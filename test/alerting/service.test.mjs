// The delivery service (lib/alerting/service.mjs; delivery spec §5.5) with a fake clock, the
// real history Store, a memory control store (wrapStore) and a real webhook receiver on
// 127.0.0.1: legacy status, probes, Uptime Goblin's notices, send-time rechecks, the start work of D16,
// D26 and D27, signing, test emails, refusals, Retry, the history list and the audit hook.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { randomBytes, createPrivateKey } from 'node:crypto';
import { Store } from '../../lib/store.mjs';
import { createAlerting, STALE_REASON, SUPERSEDED_REASON } from '../../lib/alerting/service.mjs';
import { SIGNING_HOLD_REASON } from '../../lib/alerting/signing.mjs';
import { notifySettings } from '../../lib/alerting/settings.mjs';
import { ntfySettings } from '../../lib/alerting/push-settings.mjs';
import { DeliveryError } from '../../lib/alerting/errors.mjs';
import { createSettings, defineSetting, memorySettingsStore } from '../../lib/settings.mjs';
import { Keyring, memoryKeyringStore } from '../../lib/keyring.mjs';
import { createMemoryOutboxStore } from '../../lib/notify/memory-store.mjs';
import { createControlOutboxStore } from '../../lib/repo/outbox.mjs';
import { deliveryUid } from '../../lib/notify/outbox.mjs';
import {
  verifyWebhookSignature,
  publicSigningKey,
  generateSigningKey,
} from '../../lib/notify/sign.mjs';
import { openControl } from '../../lib/db/control.mjs';
import { emailDefaults } from '../../lib/catalog.mjs';
import { outboxRow } from '../notify/store-contract.mjs';
import { fakeClock, quietLogger, settle } from './fake-clock.mjs';

const minute = 60 * 1000,
  hour = 60 * minute;
const full = () =>
  Object.assign(new Error('database or disk is full'), { class: 'full', code: 'SQLITE_FULL' });
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

// --- fixtures ---------------------------------------------------------------------------------

// A webhook receiver on 127.0.0.1: `answers` (status numbers or {status, headers}) in turn, then
// 200. Records {body, headers}.
async function receiver(t, answers = []) {
  const got = [];
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    got.push({ body: Buffer.concat(chunks).toString('utf8'), headers: req.headers });
    const answer = answers.length ? answers.shift() : 200;
    const { status, headers = {} } = typeof answer === 'number' ? { status: answer } : answer;
    res.writeHead(status, headers);
    res.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  return {
    got,
    answers,
    url: `http://127.0.0.1:${server.address().port}/hook`,
    kinds: () => got.map(item => `${JSON.parse(item.body).service}:${JSON.parse(item.body).kind}`),
  };
}

// A mail transport that answers from `script` (functions of the message), then accepts.
function mailer(script = []) {
  const sent = [];
  return {
    sent,
    script,
    factory: () => ({
      async sendMail(mail) {
        sent.push(mail);
        const next = script.shift();
        if (next) return next(mail);
        return { accepted: [mail.to[0].address], rejected: [] };
      },
      close() {},
    }),
  };
}
const authFails = () =>
  Promise.reject(Object.assign(new Error('Invalid login'), { code: 'EAUTH' }));

// The job runner as the service sees it, run by hand: no timers, every run is explicit.
function manualJobs() {
  const registered = new Map();
  const ctx = () => ({
    signal: new AbortController().signal,
    wait: promise => promise,
    yieldNow: async () => {},
    sleep: async () => {},
  });
  return {
    registered,
    every(name, intervalMs, fn, options = {}) {
      registered.set(name, { fn, intervalMs, options });
    },
    leaderTask(name, fn) {
      registered.set(name, { fn, continuous: true });
    },
    run: name => registered.get(name).fn(ctx()),
    async cancelAndWait(name) {
      return { cancelled: registered.delete(name), settled: true };
    },
  };
}

function history(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-service-'));
  const store = new Store(directory);
  t.after(() => {
    store.close();
    fs.rmSync(directory, { recursive: true, force: true });
  });
  let time = 1_800_000_000_000;
  const source = id => ({
    id,
    name: id.toUpperCase(),
    pollSeconds: 60,
    availabilityFailures: 1,
    availabilitySeconds: 0,
    recoverySuccesses: 1,
    recoverySeconds: 0,
    rules: [],
  });
  return {
    store,
    directory,
    setTime: value => (time = value),
    fire: (id, at) => store.evaluate(source(id), [], 'connection refused', at ?? (time += 1000)),
    recover: (id, at) => store.evaluate(source(id), [], null, at ?? (time += 1000)),
    legacy: (service, rule, at, kind = 'resolved') =>
      store.db
        .prepare('INSERT INTO events(service,time,kind,message,category,rule) VALUES(?,?,?,?,?,?)')
        .run(service, at, kind, 'from 1.4.x', 'availability', rule),
    relayedOf: uid =>
      store.db.prepare('SELECT relayed FROM events WHERE uid = ?').get(uid)?.relayed,
  };
}

function config({ email = {}, alerts = {}, services = ['plex', 'nas', 'x', 'y'] } = {}) {
  const value = {
    alerts: {
      enabled: true,
      notifyOnAlert: true,
      notifyOnRecovery: true,
      notifyAvailability: true,
      notifyMeasurements: true,
      ...alerts,
    },
    email: { ...emailDefaults(), ...email },
    services: services.map(id => ({ id, name: id.toUpperCase(), alerts: {} })),
  };
  return { value, get: id => value.services.find(service => service.id === id) };
}
const emailOn = {
  enabled: true,
  host: '192.0.2.25',
  from: 'orbit@example.test',
  to: 'dana@example.test',
  password: 'canary-smtp-password-7731',
};

// A memory store standing in for control.sqlite, whose writes (or every call) can fail.
function controlStore() {
  const inner = createMemoryOutboxStore();
  const state = { writes: false, reads: false };
  const reads = new Set([
    'candidates',
    'sending',
    'channel',
    'channelIds',
    'countActive',
    'counts',
    'nextDueAt',
    'list',
    'find',
    'batch',
    'activeKeys',
    'summary',
  ]);
  const store = { kind: 'control (memory)' };
  for (const [name, fn] of Object.entries(inner))
    if (typeof fn === 'function')
      store[name] = async (...args) => {
        if (reads.has(name) ? state.reads : state.writes) throw full();
        return fn(...args);
      };
  return { store, inner, state };
}

async function makeKeyring(key = randomBytes(32)) {
  return Keyring.open(memoryKeyringStore(), { key });
}

// The settings service over a memory store whose writes (`state.full`) and reads
// (`state.readFails`) can fail.
function settingsService(keyring, clock) {
  const rows = memorySettingsStore();
  const state = { full: false, readFails: false };
  const store = {
    get: (...args) => rows.get(...args),
    list: (...args) => rows.list(...args),
    async put(...args) {
      if (state.full) throw full();
      return rows.put(...args);
    },
  };
  // `state.race`: the next update meets another writer's change (a concurrent rotation).
  const raced = {
    async get(...args) {
      if (state.race && ++state.gets === 2) {
        state.race = false;
        const row = await rows.get(...args);
        if (row) await rows.put({ ...row, version: row.version + 1 }, { ifVersion: row.version });
      }
      return rows.get(...args);
    },
  };
  store.get = async (...args) => {
    if (state.readFails) throw Object.assign(new Error('disk I/O error'), { code: 'SQLITE_IOERR' });
    return state.race ? raced.get(...args) : rows.get(...args);
  };
  return {
    state,
    rows,
    settings: createSettings({
      store,
      definitions: [notifySettings],
      env: {},
      keyring: () => keyring,
      clock: () => clock.wall(),
    }),
  };
}

async function service(t, options = {}) {
  const clock = options.clock ?? fakeClock();
  const keyring = options.keyring ?? (await makeKeyring());
  const hist = options.hist ?? history(t);
  const control = options.control ?? controlStore();
  const settings = options.settings ?? settingsService(keyring, clock);
  const jobs = options.jobs ?? manualJobs();
  const logger = options.logger ?? quietLogger();
  const cfg = options.config ?? config(options.configOptions);
  const mail = options.mail ?? mailer();
  const events = [],
    storageErrors = [];
  const alerting = await createAlerting({
    control: { settings: settings.settings, db: { read() {}, write() {} } },
    keyring,
    history: options.wrapHistoryStore ? options.wrapHistoryStore(hist.store) : hist.store,
    config: cfg,
    jobs,
    webhook: options.webhook ?? '',
    mailTransportFactory: mail.factory,
    emailBatchMs: 1000,
    restored: options.restored ?? false,
    clock,
    rng: () => 1,
    logger,
    wrapStore: () => control.store,
    webhookUnknown: options.webhookUnknown,
    ...(options.pushAddressPolicy ? { pushAddressPolicy: options.pushAddressPolicy } : {}),
    onStorageError: error => storageErrors.push(error),
    onEvent: record => events.push(record),
  });
  t.after(() => alerting.stop({ timeoutMs: 0 }));
  if (options.start !== false) alerting.start();
  await settle();
  // Delivery as the worker does it, pass after pass, waiting for real sends between them.
  const deliver = async () => {
    for (let i = 0; i < 50; i++) {
      const { started } = await alerting.outbox.pump();
      for (let w = 0; alerting.outbox.inFlight && w < 1000; w++) await sleep(5);
      await settle();
      if (!started) return;
    }
  };
  return {
    alerting,
    clock,
    keyring,
    hist,
    control,
    settings,
    jobs,
    logger,
    config: cfg,
    mail,
    events,
    storageErrors,
    deliver,
  };
}
const channelOf = (alerting, id) => alerting.snapshot().channels.find(c => c.id === id);
const rowsOf = async inner => (await inner.list({ limit: 100 })).sort((a, b) => a.id - b.id);

// --- tests ------------------------------------------------------------------------------------

test('an alert and its recovery reach both channels, signed, with 1.4.2’s body and one digest', async t => {
  const hook = await receiver(t);
  const s = await service(t, { webhook: hook.url, configOptions: { email: emailOn } });
  const firing = s.hist.fire('plex');
  assert.deepEqual(await s.alerting.transitions(firing), { enqueued: 2, marked: 1, deferred: 0 });
  const resolved = s.hist.recover('plex');
  await s.alerting.transitions(resolved);
  await s.deliver();
  assert.deepEqual(hook.kinds(), ['plex:firing', 'plex:resolved']);
  const [request] = hook.got;
  const { publicKey } = await s.alerting.signing.publicKeys();
  assert.equal(request.headers['x-goblin-delivery'], deliveryUid(firing[0].uid, 'env-webhook'));
  assert.deepEqual(
    verifyWebhookSignature(publicKey, request.body, request.headers['x-goblin-signature'], {
      deliveryId: request.headers['x-goblin-delivery'],
      nowMs: s.clock.wall(),
    }),
    { ok: true }
  );
  assert.equal(
    request.body,
    JSON.stringify({
      source: 'orbit',
      service: 'plex',
      name: 'PLEX',
      kind: 'firing',
      category: 'availability',
      rule: '__availability',
      message: firing[0].message,
      time: firing[0].time,
    })
  );
  // Email: one digest of both, with a stable Message-ID.
  await s.clock.advance(3000);
  await s.deliver();
  assert.equal(s.mail.sent.length, 1);
  assert.match(s.mail.sent[0].messageId, /^<orbit\.g_[a-z2-7]{26}@example\.test>$/);
  assert.match(s.mail.sent[0].subject, /1 alert, 1 recovered/);
  await s.alerting.refresh();
  const snapshot = s.alerting.snapshot();
  assert.deepEqual(snapshot.totals, { waiting: 0, retrying: 0, sending: 0, paused: 0, failed: 0 });
  assert.deepEqual(
    snapshot.channels.map(channel => [channel.id, channel.state, channel.deliveredTotal]),
    [
      ['email', 'ok', 1],
      ['env-webhook', 'ok', 2],
      // ntfy and Gotify are listed whether set up or not.
      ['ntfy', 'not-configured', 0],
      ['gotify', 'not-configured', 0],
    ]
  );
  assert.equal(channelOf(s.alerting, 'env-webhook').host, '127.0.0.1');
});

test('legacy() keeps 1.4.x’s notification fields, from persisted status', async t => {
  const hook = await receiver(t, [500]);
  const s = await service(t, { webhook: hook.url, configOptions: { email: emailOn } });
  // Before anything happened: 1.4.x's start values.
  assert.deepEqual(s.alerting.legacy(), {
    configured: true,
    lastError: null,
    webhook: { configured: true, lastError: null },
    email: {
      enabled: true,
      configured: true,
      state: 'ready',
      pending: 0,
      lastAttempt: null,
      lastAccepted: null,
      lastError: null,
      failedCount: 0,
    },
  });
  await s.alerting.transitions(s.hist.fire('plex'));
  await s.deliver();
  await s.alerting.refresh();
  let legacy = s.alerting.legacy();
  assert.equal(legacy.lastError, s.clock.wall(), 'the webhook failed after its last success');
  assert.equal(legacy.webhook.lastError, legacy.lastError);
  assert.equal(legacy.email.pending, 1, 'the email row waits for its digest window');
  // The email is accepted; the webhook's retry succeeds: no error any more.
  await s.clock.advance(31000);
  await s.deliver();
  await s.alerting.refresh();
  legacy = s.alerting.legacy();
  assert.equal(legacy.lastError, null);
  assert.equal(legacy.email.state, 'accepted');
  assert.equal(legacy.email.lastAccepted, s.clock.wall());
  // Email switched off, or not set up: 1.4.x's states.
  s.config.value.email.enabled = false;
  assert.equal(s.alerting.legacy().email.state, 'disabled');
  s.config.value.email = { ...emailOn, password: '' };
  assert.equal(s.alerting.legacy().email.state, 'unconfigured');
  s.config.value.email = { ...emailOn };
  // Status unreadable: the last values stay, and available is false.
  const before = s.alerting.legacy();
  s.control.state.reads = true;
  await s.alerting.refresh();
  assert.equal(s.alerting.snapshot().available, false);
  assert.deepEqual(s.alerting.legacy(), before);
  await assert.rejects(s.alerting.deliveries({}), { code: 'delivery_status_unavailable' });
  s.control.state.reads = false;
  await s.alerting.refresh();
  assert.equal(s.alerting.snapshot().available, true);
});

test('email switched on but not set up gets no row (1.4.2 sent nothing then)', async t => {
  const hook = await receiver(t);
  const s = await service(t, {
    webhook: hook.url,
    configOptions: { email: { ...emailOn, password: '' } },
  });
  assert.deepEqual(await s.alerting.transitions(s.hist.fire('plex')), {
    enqueued: 1,
    marked: 1,
    deferred: 0,
  });
  assert.deepEqual(
    (await rowsOf(s.control.inner)).map(row => row.channelId),
    ['env-webhook']
  );
});

// ntfy's settings, saved before a start whose read of them fails (control.sqlite read errors):
// whether ntfy gets an event is then not known, so its rows wait for the read while email's are
// queued at once. Neither an alert change nor an Uptime Goblin notice is lost to ntfy (review low).
async function ntfyHeldAtStart(t, { mail } = {}) {
  const clock = fakeClock();
  const keyring = await makeKeyring();
  const settings = settingsService(keyring, clock);
  const ntfy = await receiver(t);
  settings.settings.define(ntfySettings);
  await settings.settings.update('notify', 'ntfy', {
    enabled: true,
    server: new URL(ntfy.url).origin,
    topic: 'orbit-held-topic',
    allowPlainHttp: true,
  });
  settings.state.readFails = true;
  const s = await service(t, {
    clock,
    keyring,
    settings,
    mail,
    configOptions: { email: emailOn },
    pushAddressPolicy: async () => null,
  });
  const messages = () => ntfy.got.map(item => JSON.parse(item.body).message);
  return { s, ntfy, settings, messages };
}

test('an alert relayed while the ntfy settings cannot be read waits for them; email is queued at once and once', async t => {
  const { s, settings, messages } = await ntfyHeldAtStart(t);
  assert.equal(channelOf(s.alerting, 'ntfy').state, 'not-configured');
  const firing = s.hist.fire('plex');
  await s.alerting.transitions(firing);
  assert.deepEqual(
    (await rowsOf(s.control.inner)).map(row => row.channelId),
    ['email']
  );
  // Kept unrelayed, so the relay relays it again.
  assert.equal(s.hist.relayedOf(firing[0].uid), 0);
  // Still unreadable: the relay job tries again, and still writes nothing for ntfy.
  await s.jobs.run('notify.relay');
  await settle();
  assert.equal(s.hist.relayedOf(firing[0].uid), 0);
  assert.equal((await rowsOf(s.control.inner)).length, 1);
  settings.state.readFails = false;
  await s.jobs.run('notify.relay');
  await settle();
  assert.equal(s.hist.relayedOf(firing[0].uid), 1);
  const rows = await rowsOf(s.control.inner);
  assert.deepEqual(
    rows.map(row => [row.channelId, row.eventUid]),
    [
      ['email', firing[0].uid],
      ['ntfy', firing[0].uid],
    ]
  );
  await s.clock.advance(3000);
  await s.deliver();
  assert.deepEqual(messages().length, 1);
  assert.match(messages()[0], new RegExp(firing[0].message));
  assert.equal(s.mail.sent.length, 1);
  await s.alerting.refresh();
  assert.equal(channelOf(s.alerting, 'ntfy').state, 'ok');
});

test('an alert the ntfy and Gotify settings would not get is relayed at once while they cannot be read', async t => {
  const { s } = await ntfyHeldAtStart(t);
  s.config.value.alerts.notifyOnAlert = false;
  const firing = s.hist.fire('plex');
  await s.alerting.transitions(firing);
  assert.equal(s.hist.relayedOf(firing[0].uid), 1);
  assert.equal((await rowsOf(s.control.inner)).length, 0);
});

test('an Uptime Goblin notice while the ntfy settings cannot be read reaches ntfy once they can', async t => {
  const mail = mailer([authFails]);
  const { s, settings, messages } = await ntfyHeldAtStart(t, { mail });
  const firing = s.hist.fire('plex');
  await s.alerting.transitions(firing);
  await s.clock.advance(3000);
  await s.deliver();
  await settle();
  // Email paused: its notice goes to every other channel, here only ntfy, which waits.
  assert.equal(mail.sent.length, 1);
  await s.alerting.refresh();
  assert.equal(channelOf(s.alerting, 'email').state, 'paused');
  assert.equal(messages().length, 0);
  settings.state.readFails = false;
  await s.jobs.run('notify.relay');
  await settle();
  await s.deliver();
  assert.deepEqual(
    messages().sort(),
    [
      'Email notifications are paused: Email sign-in failed. Check the sender address and Gmail app password.',
      firing[0].message,
    ].sort()
  );
  // The paused email channel got no second row of the alert, and no row of its own notice.
  assert.deepEqual(
    (await rowsOf(s.control.inner))
      .filter(row => row.channelId === 'email')
      .map(row => row.eventUid),
    [firing[0].uid]
  );
});

test('an alert held for ntfy while control.sqlite cannot be written keeps its email row in memory until it is final', async t => {
  const tryLater = () =>
    Promise.reject(Object.assign(new Error('421 Try again later'), { responseCode: 421 }));
  const mail = mailer([tryLater]);
  const { s, settings, messages } = await ntfyHeldAtStart(t, { mail });
  s.control.state.writes = true;
  const [firing] = s.hist.fire('plex');
  await s.alerting.transitions([firing]);
  const unsaved = await s.alerting.deliveries({ limit: 50 });
  assert.deepEqual(
    unsaved.deliveries.map(item => [item.channel, item.saved]),
    [['email', false]]
  );
  assert.equal(s.hist.relayedOf(firing.uid), 0);
  // The settings can be read again: ntfy's row joins email's in memory.
  settings.state.readFails = false;
  await s.jobs.run('notify.relay');
  await settle();
  await s.clock.advance(3000);
  await s.deliver();
  assert.equal(messages().length, 1);
  assert.equal(mail.sent.length, 1);
  // ntfy delivered, email waits for its retry: the alert stays unrelayed, so a restart now
  // would send email again from history.
  await s.jobs.run('notify.relay');
  await settle();
  assert.equal(s.hist.relayedOf(firing.uid), 0);
  await s.clock.advance(10 * minute);
  await s.deliver();
  assert.equal(mail.sent.length, 2);
  await s.jobs.run('notify.relay');
  await settle();
  assert.equal(s.hist.relayedOf(firing.uid), 1);
});

test('a 404 pauses the webhook; it probes every 15 minutes and resumes without Resume', async t => {
  const hook = await receiver(t, [404, 404]);
  const s = await service(t, { webhook: hook.url, configOptions: { email: emailOn } });
  await s.alerting.transitions(s.hist.fire('plex'));
  await s.alerting.transitions(s.hist.recover('plex'));
  await s.alerting.transitions(s.hist.fire('nas'));
  await s.deliver();
  assert.equal(hook.got.length, 1);
  await s.alerting.refresh();
  let webhook = channelOf(s.alerting, 'env-webhook');
  assert.equal(webhook.state, 'paused');
  assert.equal(webhook.nextAttemptAt, s.clock.wall() + 15 * minute);
  assert.equal(webhook.counts.paused, 3);
  assert.match(
    s.logger.lines.warn.join('\n'),
    /Webhook notifications are paused: The webhook answered 404\..*Uptime Goblin tries again at/
  );
  // The probe 15 minutes later is answered 404 again; the next one 200.
  await s.clock.advance(15 * minute);
  await s.deliver();
  assert.equal(hook.got.length, 2);
  assert.match(
    s.logger.lines.info.join('\n'),
    /Trying Webhook notifications again with one notification/
  );
  await s.clock.advance(15 * minute);
  await s.deliver();
  assert.deepEqual(hook.kinds(), [
    'plex:firing',
    'plex:firing',
    'plex:firing',
    'plex:resolved',
    'nas:firing',
  ]);
  await s.alerting.refresh();
  webhook = channelOf(s.alerting, 'env-webhook');
  assert.deepEqual([webhook.state, webhook.pausedSince], ['ok', null]);
  // Email was told once that the webhook paused, and once that it works again.
  await s.clock.advance(3000);
  await s.deliver();
  const mails = s.mail.sent.map(mail => mail.text).join('\n');
  const count = text => mails.split(text).length - 1;
  assert.equal(count('Webhook notifications are paused: The webhook answered 404.'), 1);
  assert.equal(count('Webhook notifications are working again.'), 1);
  assert.match(s.mail.sent.at(-1).subject, /Recovered · Uptime Goblin health · Uptime Goblin/);
});

test('the dashboard counts the email rows waiting to retry apart from newer ones waiting for their digest (A44)', async t => {
  const refused = () =>
    Promise.reject(
      Object.assign(new Error('connect ECONNREFUSED 192.0.2.25:465'), { code: 'ECONNREFUSED' })
    );
  const mail = mailer([refused]);
  const s = await service(t, { mail, configOptions: { email: emailOn } });
  await s.alerting.transitions(s.hist.fire('plex'));
  await s.clock.advance(3000);
  await s.deliver();
  assert.equal(mail.sent.length, 1);
  // Two newer alerts wait for a digest of their own, which goes long before Plex's retry.
  await s.alerting.transitions(s.hist.fire('nas'));
  await s.alerting.transitions(s.hist.fire('x'));
  await s.alerting.refresh();
  const email = channelOf(s.alerting, 'email');
  assert.deepEqual([email.state, email.counts.retrying, email.counts.waiting], ['retrying', 1, 2]);
  const { dashboardNotifications } = await import('../../lib/alerting/view.mjs');
  const dashboard = dashboardNotifications(s.alerting.legacy(), s.alerting.snapshot()).email;
  // `waiting` keeps counting every row not yet sent; `retrying` is the one the next attempt
  // time is about.
  assert.deepEqual(
    [dashboard.channelState, dashboard.waiting, dashboard.retrying, dashboard.nextAttemptAt],
    ['retrying', 3, 1, email.nextAttemptAt]
  );
});

test('EAUTH pauses email until a fix: no probe by time, one at a start, Resume releases it', async t => {
  const hook = await receiver(t);
  const mail = mailer([authFails, authFails]);
  const s = await service(t, { webhook: hook.url, mail, configOptions: { email: emailOn } });
  await s.alerting.transitions(s.hist.fire('plex'));
  await s.clock.advance(3000);
  await s.deliver();
  assert.equal(mail.sent.length, 1);
  await s.alerting.refresh();
  assert.deepEqual(
    [channelOf(s.alerting, 'email').state, channelOf(s.alerting, 'email').nextAttemptAt],
    ['paused', null]
  );
  for (let i = 0; i < 6; i++) {
    await s.clock.advance(15 * minute);
    await s.deliver();
  }
  assert.equal(mail.sent.length, 1, 'never by time');
  // The webhook got exactly one notice that email paused.
  assert.deepEqual(
    hook.got
      .map(item => JSON.parse(item.body))
      .filter(body => body.service === 'orbit')
      .map(b => b.message),
    [
      'Email notifications are paused: Email sign-in failed. Check the sender address and Gmail app password.',
    ]
  );
  // A restart: the next process probes once (here refused again: still paused).
  const again = await service(t, {
    webhook: hook.url,
    mail,
    clock: s.clock,
    keyring: s.keyring,
    hist: s.hist,
    control: s.control,
    settings: s.settings,
    configOptions: { email: emailOn },
  });
  await again.deliver();
  assert.equal(mail.sent.length, 2);
  await again.alerting.refresh();
  assert.equal(channelOf(again.alerting, 'email').state, 'paused');
  // Resume (the credentials were fixed): the held digest goes, and the webhook hears it works.
  const resumed = await again.alerting.resume('email', { actor: { login: 'dana' } });
  assert.equal(resumed.released, 1);
  assert.equal(resumed.channel.state, 'ok');
  await again.deliver();
  assert.equal(mail.sent.length, 3);
  assert.match(again.logger.lines.info.join('\n'), /Email notifications were resumed by dana\./);
  // The webhook heard once that email paused and once that it works again.
  assert.deepEqual(
    hook.got
      .map(item => JSON.parse(item.body))
      .filter(body => body.service === 'orbit')
      .map(body => [body.kind, body.rule]),
    [
      ['firing', '__channel_email'],
      ['resolved', '__channel_email'],
    ]
  );
  const record = again.events.find(event => event.action === 'channel.resume');
  assert.deepEqual([record.actor, record.target, record.detail.released], ['dana', 'email', 1]);
  // Resume of a channel that is not paused releases nothing; an unknown one is refused.
  assert.equal((await again.alerting.resume('email')).released, 0);
  await assert.rejects(again.alerting.resume('slack'), { code: 'channel_unknown', status: 404 });
});

test('a start probe resumes a paused webhook whose receiver was fixed while Uptime Goblin was stopped', async t => {
  const hook = await receiver(t, [401]);
  const first = await service(t, { webhook: hook.url });
  await first.alerting.transitions(first.hist.fire('plex'));
  await first.deliver();
  await first.alerting.stop({ timeoutMs: 0 });
  // The receiver is fixed meanwhile; the next start probes once and everything goes.
  const second = await service(t, {
    webhook: hook.url,
    clock: first.clock,
    keyring: first.keyring,
    hist: first.hist,
    control: first.control,
    settings: first.settings,
  });
  await second.deliver();
  assert.deepEqual(hook.kinds(), ['plex:firing', 'plex:firing']);
  await second.alerting.refresh();
  assert.equal(channelOf(second.alerting, 'env-webhook').state, 'ok');
});

// Review round 4: a channel paused by one run and switched off before the next (email switched
// off under 1.4.x during a rollback, GOBLIN_WEBHOOK_URL removed at a restart) can send nothing, so
// no probe ended its pause and the other channel's receiver showed "… notifications are paused"
// firing for good; the same change made in a running Uptime Goblin sends "… working again". Now the
// start ends such a pause as a settings save does, also after D16's stale marking.
test('a channel switched off while Uptime Goblin was stopped leaves its pause at the next start, and the other channel hears it once', async t => {
  const noticesAt = hook =>
    hook.got
      .map(item => JSON.parse(item.body))
      .filter(body => body.service === 'orbit')
      .map(body => [body.kind, body.rule, body.message]);
  const pausedEmail = [
    'firing',
    '__channel_email',
    'Email notifications are paused: Email sign-in failed. Check the sender address and Gmail app password.',
  ];
  for (const restored of [false, true]) {
    const hook = await receiver(t);
    const mail = mailer([authFails]);
    const s = await service(t, { webhook: hook.url, mail, configOptions: { email: emailOn } });
    await s.alerting.transitions(s.hist.fire('plex'));
    await s.clock.advance(3000);
    await s.deliver();
    await s.alerting.refresh();
    assert.equal(channelOf(s.alerting, 'email').state, 'paused');
    assert.deepEqual(noticesAt(hook), [pausedEmail]);
    await s.alerting.stop({ timeoutMs: 0 });
    // Email is switched off while Uptime Goblin is stopped (1.4.x's settings, or config.json edited).
    // Restored data: D16's first try fails, so its stale marking comes after the start's first
    // work; a notice queued before it would be marked as never to be sent.
    const restart = ({ discardFails = false } = {}) =>
      service(t, {
        webhook: hook.url,
        mail,
        restored,
        clock: s.clock,
        keyring: s.keyring,
        hist: s.hist,
        control: s.control,
        settings: s.settings,
        configOptions: { email: { ...emailOn, enabled: false } },
        wrapHistoryStore: store => ({
          unrelayedEvents: options => store.unrelayedEvents(options),
          markRelayed: uids => store.markRelayed(uids),
          legacyEventsAfter: (time, options) => store.legacyEventsAfter(time, options),
          discardUnrelayed() {
            if (discardFails) {
              discardFails = false;
              throw full();
            }
            return store.discardUnrelayed();
          },
        }),
      });
    const again = await restart({ discardFails: restored });
    await again.jobs.run('notify.relay');
    await settle();
    await again.deliver();
    assert.deepEqual(
      noticesAt(hook),
      [pausedEmail, ['resolved', '__channel_email', 'Email notifications are working again.']],
      restored ? 'after D16 marked the old rows stale' : 'a restart'
    );
    assert.equal(mail.sent.length, 1, 'nothing more is emailed');
    const status = await s.control.inner.channel('email');
    assert.deepEqual([status.state, status.pausedSince], ['ok', null]);
    const held = (await rowsOf(s.control.inner)).find(row => row.channelId === 'email');
    assert.equal(held.state, restored ? 'stale' : 'skipped', held.lastError);
    await again.alerting.stop({ timeoutMs: 0 });
    // The next start has no pause to end: nothing more.
    const third = await restart();
    await third.deliver();
    assert.equal(noticesAt(hook).length, 2);
    await third.alerting.stop({ timeoutMs: 0 });
  }

  // The webhook paused by a 404, then GOBLIN_WEBHOOK_URL removed at a restart: email hears it.
  {
    const hook = await receiver(t, [404]);
    const mail = mailer();
    const s = await service(t, { webhook: hook.url, mail, configOptions: { email: emailOn } });
    await s.alerting.transitions(s.hist.fire('plex'));
    for (let i = 0; i < 3; i++) {
      await s.clock.advance(3000);
      await s.deliver();
    }
    const mailed = () => mail.sent.map(item => item.text ?? '').join('\n---\n');
    assert.match(mailed(), /Webhook notifications are paused: /);
    assert.doesNotMatch(mailed(), /Webhook notifications are working again/);
    await s.alerting.stop({ timeoutMs: 0 });
    const again = await service(t, {
      webhook: '',
      mail,
      clock: s.clock,
      keyring: s.keyring,
      hist: s.hist,
      control: s.control,
      settings: s.settings,
      configOptions: { email: emailOn },
    });
    for (let i = 0; i < 3; i++) {
      await again.clock.advance(3000);
      await again.deliver();
    }
    assert.equal(mailed().match(/Webhook notifications are working again\./g)?.length, 1);
    const status = await s.control.inner.channel('env-webhook');
    assert.deepEqual([status.state, status.pausedSince], ['ok', null]);
    assert.equal(hook.got.length, 1, 'nothing is sent to the removed webhook');
  }

  // Email switched on but incomplete keeps its pause: its start probe pauses it again with that
  // cause (as a save of such settings would), and no "working again" is sent.
  {
    const hook = await receiver(t);
    const mail = mailer([authFails]);
    const s = await service(t, { webhook: hook.url, mail, configOptions: { email: emailOn } });
    await s.alerting.transitions(s.hist.fire('plex'));
    await s.clock.advance(3000);
    await s.deliver();
    await s.alerting.stop({ timeoutMs: 0 });
    const again = await service(t, {
      webhook: hook.url,
      mail,
      clock: s.clock,
      keyring: s.keyring,
      hist: s.hist,
      control: s.control,
      settings: s.settings,
      configOptions: { email: { ...emailOn, password: '' } },
    });
    await again.deliver();
    assert.deepEqual(noticesAt(hook), [pausedEmail]);
    const status = await s.control.inner.channel('email');
    assert.equal(status.state, 'paused');
    assert.match(status.pausedReason, /^Email is not set up/);
  }
});

// T8's double failure: the reserve did not free enough, and control.sqlite takes no writes. Space
// returns: the service's probe (every 10 s while not saving) saves again.
async function spaceReturns(s) {
  s.control.state.writes = false;
  await s.clock.advance(11 * 1000);
  await s.alerting.refresh();
  assert.equal(s.alerting.snapshot().saving, true);
}
const servicesOf = async inner =>
  (await rowsOf(inner)).map(row => `${row.event.service}:${row.state}`);

test('a Resume, a probe or a start probe that meets an unwritable control database never strands the held alerts', async t => {
  // Before, the resume's status change outlived the release it could not write: the rows stayed
  // held on a channel that looked fine (Resume did nothing, Retry said "paused", no probe came)
  // until they expired; a probe left an open circuit that nothing probed again.
  for (const how of ['Resume', 'probe', 'start probe']) {
    const hook = await receiver(t, [404]);
    let s = await service(t, { webhook: hook.url });
    await s.alerting.transitions(s.hist.fire('plex'));
    await s.deliver();
    await s.alerting.transitions(s.hist.fire('nas'));
    await s.deliver();
    assert.deepEqual(await servicesOf(s.control.inner), ['plex:held', 'nas:held'], how);
    // control.sqlite stops taking writes; the receiver is fixed meanwhile (it answers 200).
    s.control.state.writes = true;
    if (how === 'Resume') {
      const resumed = await s.alerting.resume('env-webhook', { actor: { login: 'dana' } });
      // The resume stands: the admin's decision is kept (in memory), the rows go once they can.
      assert.deepEqual([resumed.channel.state, resumed.channel.counts.paused], ['ok', 2], how);
    } else if (how === 'probe') {
      await s.clock.advance(15 * minute);
      await s.deliver();
      await s.alerting.refresh();
      // The probe could not release its rows: the channel stays paused and due.
      const webhook = channelOf(s.alerting, 'env-webhook');
      assert.equal(webhook.state, 'paused', how);
      assert.ok(webhook.nextAttemptAt <= s.clock.wall(), how);
    } else {
      await s.alerting.stop({ timeoutMs: 0 });
      s = await service(t, {
        webhook: hook.url,
        clock: s.clock,
        keyring: s.keyring,
        hist: s.hist,
        control: s.control,
        settings: s.settings,
      });
      s.control.state.writes = true;
      await s.deliver();
    }
    for (let i = 0; i < 6; i++) {
      await s.clock.advance(10 * minute);
      await s.deliver();
    }
    assert.deepEqual(await servicesOf(s.control.inner), ['plex:held', 'nas:held'], how);
    assert.equal(hook.got.length, 1, `${how}: nothing could be released while full`);
    await spaceReturns(s);
    await s.deliver();
    assert.deepEqual(hook.kinds(), ['plex:firing', 'plex:firing', 'nas:firing'], how);
    assert.deepEqual(await servicesOf(s.control.inner), ['plex:delivered', 'nas:delivered'], how);
    await s.alerting.refresh();
    assert.deepEqual(
      [
        channelOf(s.alerting, 'env-webhook').state,
        channelOf(s.alerting, 'env-webhook').counts.paused,
      ],
      ['ok', 0],
      how
    );
    assert.match(s.logger.lines.error.join('\n'), /Held notifications could not be released yet/);
  }
});

test('an accepted test email while control.sqlite takes no writes resumes email; its held alerts go once space returns', async t => {
  const mail = mailer([authFails]);
  const s = await service(t, { mail, configOptions: { email: emailOn } });
  await s.alerting.transitions(s.hist.fire('plex'));
  await s.clock.advance(3000);
  await s.deliver();
  await s.alerting.transitions(s.hist.fire('nas'));
  await s.clock.advance(3000);
  await s.deliver();
  assert.deepEqual(await servicesOf(s.control.inner), ['plex:held', 'nas:held']);
  s.control.state.writes = true;
  await s.alerting.recordTest({ accepted: true });
  assert.equal(channelOf(s.alerting, 'email').state, 'ok');
  for (let i = 0; i < 6; i++) {
    await s.clock.advance(10 * minute);
    await s.deliver();
  }
  assert.equal(mail.sent.length, 1, 'nothing could be released while full');
  await spaceReturns(s);
  await s.deliver();
  await s.clock.advance(3000);
  await s.deliver();
  assert.deepEqual(await servicesOf(s.control.inner), ['plex:delivered', 'nas:delivered']);
  // The plex digest again (its Message-ID kept), then nas: in order.
  assert.equal(mail.sent.length, 3);
  assert.equal(mail.sent[1].messageId, mail.sent[0].messageId);
  assert.match(mail.sent[1].text, /PLEX/);
  assert.match(mail.sent[2].text, /NAS/);
});

test('Resume releases the held alerts of a channel that is not paused; so does the next pass', async t => {
  // Only the bulk release fails, once: the status write goes through. Before, the channel read
  // "working" with its two alerts held, and a second Resume answered "nothing to resume".
  for (const second of ['Resume', 'pass']) {
    const hook = await receiver(t, [404]);
    const s = await service(t, { webhook: hook.url });
    await s.alerting.transitions(s.hist.fire('plex'));
    await s.deliver();
    await s.alerting.transitions(s.hist.fire('nas'));
    await s.deliver();
    const release = s.control.store.release;
    s.control.store.release = async () => {
      s.control.store.release = release;
      throw full();
    };
    const first = await s.alerting.resume('env-webhook', { actor: { login: 'dana' } });
    assert.deepEqual(
      [first.released, first.channel.state, first.channel.counts.paused],
      [0, 'ok', 2]
    );
    if (second === 'Resume') {
      const again = await s.alerting.resume('env-webhook', { actor: { login: 'dana' } });
      assert.deepEqual([again.released, again.channel.counts.paused], [2, 0]);
      assert.equal(
        s.events.filter(event => event.action === 'channel.resume').at(-1).detail.released,
        2
      );
    }
    await s.deliver();
    assert.deepEqual(hook.kinds(), ['plex:firing', 'plex:firing', 'nas:firing'], second);
    assert.deepEqual(
      await servicesOf(s.control.inner),
      ['plex:delivered', 'nas:delivered'],
      second
    );
  }
});

test('a full disk sends one notice and one recovery to every channel', async t => {
  const hook = await receiver(t);
  const s = await service(t, { webhook: hook.url });
  const since = s.clock.wall();
  s.alerting.diskChanged({ full: true, since });
  s.alerting.diskChanged({ full: true, since });
  await s.alerting.flush({ timeoutMs: 5000 });
  s.alerting.diskChanged({ full: false, since: null });
  s.alerting.diskChanged({ full: false, since: null });
  await s.alerting.flush({ timeoutMs: 5000 });
  const bodies = hook.got.map(item => JSON.parse(item.body));
  assert.deepEqual(
    bodies.map(body => [body.kind, body.rule, body.message]),
    [
      [
        'firing',
        '__disk',
        "The Uptime Goblin host's disk is full: settings cannot be saved and readings are paused until space is freed. Alerts are still sent.",
      ],
      ['resolved', '__disk', "The Uptime Goblin host's disk has free space again."],
    ]
  );
});

test('rechecks: a held firing is cancelled when its source is deleted, skipped when alerts are off', async t => {
  const hook = await receiver(t, [401]);
  const s = await service(t, { webhook: hook.url });
  await s.alerting.transitions(s.hist.fire('plex'));
  await s.alerting.transitions(s.hist.fire('nas'));
  await s.alerting.transitions(s.hist.fire('x'));
  await s.deliver();
  // plex is deleted while its firing is held: cancelled, never sent.
  s.config.value.services = s.config.value.services.filter(service => service.id !== 'plex');
  await s.hist.store.forget('plex');
  assert.deepEqual(await s.alerting.forgetSource('plex'), { cancelled: 1 });
  // nas's alerts are switched off while its firing waits: skipped at the next attempt.
  s.config.get('nas').alerts = { notifyAvailability: false };
  // x is deleted from the config without forgetSource (a race): the recheck skips it.
  s.config.value.services = s.config.value.services.filter(service => service.id !== 'x');
  await s.alerting.resume('env-webhook');
  await s.deliver();
  assert.equal(hook.got.length, 1, 'only the first 401');
  const rows = await rowsOf(s.control.inner);
  assert.deepEqual(
    rows.map(row => [row.event.service, row.state, row.lastError]),
    [
      ['plex', 'cancelled', 'Not sent: the source was deleted.'],
      ['nas', 'skipped', 'Not sent: alerts of this kind were switched off after it was queued.'],
      ['x', 'skipped', 'Not sent: the source was deleted.'],
    ]
  );
  // The rechecks did not touch the channel's health.
  await s.alerting.refresh();
  assert.equal(channelOf(s.alerting, 'env-webhook').deliveredTotal, 0);
});

test('A57: a channel whose retrying notifications all ended unsent says Working, never Retrying or a past wait', async t => {
  const { dashboardNotifications } = await import('../../lib/alerting/view.mjs');
  const shown = async s => {
    await s.alerting.refresh();
    const channel = channelOf(s.alerting, 'env-webhook'),
      dashboard = dashboardNotifications(s.alerting.legacy(), s.alerting.snapshot());
    return {
      state: channel.state,
      nextAttemptAt: channel.nextAttemptAt,
      counts: channel.counts,
      dashboard: dashboard.channels.find(c => c.id === 'env-webhook').state,
    };
  };
  const none = { waiting: 0, retrying: 0, sending: 0, paused: 0, failed: 0 };
  const health = s => s.control.inner.channel('env-webhook');

  // Retrying: the receiver answers 500, then plex's alerts are switched off while its firing
  // waits to retry. The recheck skips it unsent, and the health stays as the 500 left it.
  const hook = await receiver(t, [500]);
  const s = await service(t, { webhook: hook.url });
  await s.alerting.transitions(s.hist.fire('plex'));
  await s.deliver();
  assert.equal(hook.got.length, 1);
  assert.equal((await shown(s)).state, 'retrying');
  s.config.get('plex').alerts = { notifyAvailability: false };
  await s.clock.advance(hour);
  await s.deliver();
  assert.equal(hook.got.length, 1, 'the skipped retry was not sent');
  assert.equal((await health(s)).state, 'retrying');
  assert.deepEqual(await shown(s), {
    state: 'ok',
    nextAttemptAt: null,
    counts: none,
    dashboard: 'ok',
  });

  // Circuit open: five failures in a row open it; the sources are then deleted, so every row
  // is cancelled. While the wait lasts it is said (a new alert would wait for it too); once it
  // is over, no time in the past is shown.
  const down = await receiver(t, Array(5).fill(500));
  const c = await service(t, { webhook: down.url });
  for (const id of ['plex', 'nas', 'x', 'y']) await c.alerting.transitions(c.hist.fire(id));
  await c.alerting.enqueueDirect(
    {
      service: 'plex',
      name: 'PLEX',
      kind: 'firing',
      category: 'threshold',
      rule: 'cpu',
      message: 'CPU is above 80%',
      time: c.clock.wall(),
    },
    'test:cpu'
  );
  await c.deliver();
  assert.equal(down.got.length, 5);
  const open = await health(c);
  assert.equal(open.state, 'circuit-open');
  assert.ok(open.nextSendAt > c.clock.wall());
  assert.equal((await shown(c)).state, 'circuit-open');
  for (const id of ['plex', 'nas', 'x', 'y']) {
    c.config.value.services = c.config.value.services.filter(service => service.id !== id);
    await c.hist.store.forget(id);
    await c.alerting.forgetSource(id);
  }
  assert.deepEqual(
    (await rowsOf(c.control.inner)).map(row => row.state),
    Array(5).fill('cancelled')
  );
  assert.deepEqual(await shown(c), {
    state: 'circuit-open',
    nextAttemptAt: open.nextSendAt,
    counts: none,
    dashboard: 'circuit-open',
  });
  await c.clock.advance(open.nextSendAt - c.clock.wall() + 1);
  assert.equal((await health(c)).state, 'circuit-open');
  assert.deepEqual(await shown(c), {
    state: 'ok',
    nextAttemptAt: null,
    counts: none,
    dashboard: 'ok',
  });
});

test('D26: a waiting row whose alert 1.4.x changed later is superseded at start; others are sent', async t => {
  const hook = await receiver(t);
  const hist = history(t);
  const control = controlStore();
  const clock = fakeClock();
  const T = clock.wall();
  // Rows left waiting by a 1.5 run before a rollback.
  await control.inner.insert([
    outboxRow({
      eventUid: 'e_plexfiringxxxxxxxxxxxxxxxx',
      orderKey: 'plex\n__availability',
      createdAt: T - 30 * minute,
      event: {
        service: 'plex',
        name: 'PLEX',
        kind: 'firing',
        category: 'availability',
        rule: '__availability',
        message: 'down',
        time: T - 30 * minute,
      },
      attempts: 2,
      nextAt: T - minute,
    }),
    outboxRow({
      eventUid: 'e_nasfiringxxxxxxxxxxxxxxxxx',
      orderKey: 'nas\n__availability',
      createdAt: T - 20 * minute,
      event: {
        service: 'nas',
        name: 'NAS',
        kind: 'firing',
        category: 'availability',
        rule: '__availability',
        message: 'down',
        time: T - 20 * minute,
      },
    }),
  ]);
  // 1.4.x then handled a later change of plex (its own recovery), and an older one of nas.
  hist.legacy('plex', '__availability', T - 10 * minute);
  hist.legacy('nas', '__availability', T - 25 * minute, 'firing');
  const s = await service(t, { webhook: hook.url, hist, control, clock });
  await s.deliver();
  assert.deepEqual(hook.kinds(), ['nas:firing']);
  const rows = await rowsOf(control.inner);
  assert.deepEqual(
    rows.map(row => [row.event.service, row.state, row.lastError]),
    [
      ['plex', 'superseded', SUPERSEDED_REASON],
      ['nas', 'delivered', null],
    ]
  );
  assert.equal(
    s.logger.lines.warn.filter(line => /handled a later change of their alerts/.test(line)).length,
    1
  );
  const listed = await s.alerting.deliveries({ filter: 'all' });
  const plex = listed.deliveries.find(item => item.alert.service === 'plex');
  assert.deepEqual([plex.status, plex.lastError], ['replaced', SUPERSEDED_REASON]);
});

test('D16: restored data never sends what waited before; history events are not sent either', async t => {
  const hook = await receiver(t);
  const hist = history(t);
  const control = controlStore();
  await control.inner.insert([outboxRow({ eventUid: 'e_oldxxxxxxxxxxxxxxxxxxxxxxx' })]);
  const unrelayed = hist.fire('plex');
  const s = await service(t, { webhook: hook.url, hist, control, restored: true });
  await s.jobs.run('notify.relay');
  await s.deliver();
  assert.equal(hook.got.length, 0);
  const [row] = await rowsOf(control.inner);
  assert.deepEqual([row.state, row.lastError], ['stale', STALE_REASON]);
  assert.equal(hist.relayedOf(unrelayed[0].uid), 1);
  assert.match(
    s.logger.lines.warn.join('\n'),
    /1 notifications and 1 alert changes from before Uptime Goblin's control database became a different file were not sent/
  );
  // New alerts are sent as usual.
  await s.alerting.transitions(s.hist.fire('nas'));
  await s.deliver();
  assert.deepEqual(hook.kinds(), ['nas:firing']);
});

test('D27: a start on a full disk succeeds, sends nothing old until it can record what not to send, then catches up', async t => {
  const hook = await receiver(t);
  const hist = history(t);
  const control = controlStore();
  const clock = fakeClock();
  const T = clock.wall();
  await control.inner.insert([
    outboxRow({
      eventUid: 'e_plexfiringxxxxxxxxxxxxxxxx',
      orderKey: 'plex\n__availability',
      createdAt: T - 30 * minute,
      event: {
        service: 'plex',
        name: 'PLEX',
        kind: 'firing',
        category: 'availability',
        rule: '__availability',
        message: 'down',
        time: T - 30 * minute,
      },
    }),
    outboxRow({
      eventUid: 'e_nasfiringxxxxxxxxxxxxxxxxx',
      orderKey: 'nas\n__availability',
      createdAt: T - 20 * minute,
      event: {
        service: 'nas',
        name: 'NAS',
        kind: 'firing',
        category: 'availability',
        rule: '__availability',
        message: 'down',
        time: T - 20 * minute,
      },
    }),
  ]);
  hist.legacy('plex', '__availability', T - 10 * minute);
  control.state.writes = true;
  const keyring = await makeKeyring();
  const settings = settingsService(keyring, clock);
  settings.state.full = true;
  const s = await service(t, { webhook: hook.url, hist, control, clock, keyring, settings });
  // It started; the signing key could not be saved; the roll-forward is pending.
  assert.equal(s.alerting.signing.describe().saved, false);
  assert.match(
    s.logger.lines.error.join('\n'),
    /could not be saved \(the disk is full\); the webhook holds its alerts/
  );
  assert.match(
    s.logger.lines.error.join('\n'),
    /Notifications wait until Uptime Goblin can record which old notifications must not be sent \(the disk is full\)/
  );
  assert.ok(s.storageErrors.length > 0);
  assert.equal(s.jobs.registered.has('notify.delivery'), false, 'nothing is sent meanwhile');
  assert.equal(await s.alerting.flush({ timeoutMs: 1000 }), true);
  assert.equal(hook.got.length, 0);
  // Still full at the next relay run: still waiting.
  await s.jobs.run('notify.relay');
  assert.equal(s.jobs.registered.has('notify.delivery'), false);
  // Space is back: the next run records the roll-forward, saves the key, and delivery starts.
  control.state.writes = false;
  settings.state.full = false;
  await s.jobs.run('notify.relay');
  assert.equal(s.jobs.registered.has('notify.delivery'), true);
  assert.equal(s.alerting.signing.describe().saved, true);
  await s.deliver();
  assert.deepEqual(hook.kinds(), ['nas:firing']);
  assert.ok(hook.got[0].headers['x-goblin-signature'], 'signed once the key is saved');
});

// Rows a 1.5 process was sending when it was killed (left 'sending' with its lease): plex's,
// whose recovery 1.4.x then sent after a rollback, and nas's, which 1.4.x never touched.
async function killedWhileSending(control, hist, T) {
  const event = (service, time) => ({
    service,
    name: service.toUpperCase(),
    kind: 'firing',
    category: 'availability',
    rule: '__availability',
    message: 'down',
    time,
  });
  const { inserted } = await control.inner.insert([
    outboxRow({
      eventUid: 'e_plexfiringxxxxxxxxxxxxxxxx',
      orderKey: 'plex\n__availability',
      createdAt: T - 30 * minute,
      event: event('plex', T - 30 * minute),
    }),
    outboxRow({
      eventUid: 'e_nasfiringxxxxxxxxxxxxxxxxx',
      orderKey: 'nas\n__availability',
      createdAt: T - 20 * minute,
      event: event('nas', T - 20 * minute),
    }),
  ]);
  for (const [row, at] of [
    [inserted[0], T - 30 * minute],
    [inserted[1], T - 20 * minute],
  ])
    await control.inner.claim([row.id], {
      owner: 'o_killed',
      epoch: 1,
      now: at,
      leaseUntil: at + minute,
    });
  hist.legacy('plex', '__availability', T - 10 * minute);
}

test('D26 covers a row an earlier run left sending: 1.4.x’s later recovery supersedes it; another is resent once', async t => {
  const hook = await receiver(t);
  const hist = history(t);
  const control = controlStore();
  const clock = fakeClock();
  const T = clock.wall();
  await killedWhileSending(control, hist, T);
  const s = await service(t, { webhook: hook.url, hist, control, clock });
  assert.equal(s.jobs.registered.has('notify.delivery'), true);
  const [plex, nas] = await rowsOf(control.inner);
  // Resolved as "acceptance unknown" first, then superseded: never sent after 1.4.x's recovery.
  assert.deepEqual(
    [plex.state, plex.lastError, plex.attempts, plex.unknowns],
    ['superseded', SUPERSEDED_REASON, 1, 1]
  );
  assert.deepEqual([nas.state, nas.unknowns, nas.nextAt], ['queued', 1, T + 2 * minute]);
  assert.equal(
    s.logger.lines.warn.filter(line => /1 notifications were not sent: Orbit 1\.4\.x/.test(line))
      .length,
    1
  );
  // The worker's own first pass finds nothing left to resolve; nas goes once, 2 minutes on.
  assert.equal(await s.alerting.outbox.recover({ foreign: true }), 0);
  await s.deliver();
  assert.deepEqual(hook.kinds(), []);
  await clock.advance(3 * minute);
  await s.deliver();
  await clock.advance(10 * minute);
  await s.deliver();
  assert.deepEqual(hook.kinds(), ['nas:firing']);
  assert.equal(hook.got[0].headers['x-goblin-delivery'], nas.uid);
});

test('D26 for a row an earlier run left sending waits while its resolution cannot be written', async t => {
  const hook = await receiver(t);
  const hist = history(t);
  const control = controlStore();
  const clock = fakeClock();
  const T = clock.wall();
  await killedWhileSending(control, hist, T);
  control.state.writes = true;
  const s = await service(t, { webhook: hook.url, hist, control, clock });
  // The resolution is kept in memory: the rows are still 'sending' in the control database, so
  // nothing may be sent yet.
  assert.deepEqual(
    (await rowsOf(control.inner)).map(row => row.state),
    ['sending', 'sending']
  );
  assert.equal(s.jobs.registered.has('notify.delivery'), false, 'nothing is sent meanwhile');
  assert.match(
    s.logger.lines.error.join('\n'),
    /Notifications wait until Uptime Goblin can record which old notifications must not be sent \(a notification an earlier run was sending is not resolved yet/
  );
  await s.jobs.run('notify.relay');
  assert.equal(s.jobs.registered.has('notify.delivery'), false);
  assert.equal(await s.alerting.flush({ timeoutMs: 1000 }), true);
  assert.equal(hook.got.length, 0);
  // Space is back: the resolution is written, then the check runs over it.
  control.state.writes = false;
  await s.jobs.run('notify.relay');
  assert.equal(s.jobs.registered.has('notify.delivery'), true);
  assert.deepEqual(
    (await rowsOf(control.inner)).map(row => [row.event.service, row.state]),
    [
      ['plex', 'superseded'],
      ['nas', 'queued'],
    ]
  );
  await clock.advance(3 * minute);
  await s.deliver();
  assert.deepEqual(hook.kinds(), ['nas:firing']);
});

// A63 (an independent review of 9a7d6e5): the check read only the 1,000 alerts 1.4.x changed last, so a
// waiting firing whose recovery 1.4.x sent before 1,000 changes of other alerts was sent after
// that recovery, and the receiver showed plex down for good. 999 is the control that passed
// then; 1,000 and 2,500 failed. Every change here fits the supported 200 sources and 30 rules.
for (const unrelated of [999, 1000, 2500])
  test(`D26 over the real control database: a firing whose recovery 1.4.x sent before ${unrelated} changes of other alerts is superseded`, async t => {
    const hook = await receiver(t);
    const hist = history(t);
    const clock = fakeClock();
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-d26-control-'));
    const db = openControl(directory, { env: {} });
    t.after(() => {
      db.close();
      fs.rmSync(directory, { recursive: true, force: true });
    });
    await db.migrate();
    const store = createControlOutboxStore({ db: db.db });
    const T = clock.wall() - 10 * 1000;
    const firing = outboxRow({
      eventUid: 'e_plexfiringxxxxxxxxxxxxxxxx',
      orderKey: 'plex\n__availability',
      createdAt: T,
      event: {
        service: 'plex',
        name: 'PLEX',
        kind: 'firing',
        category: 'availability',
        rule: '__availability',
        message: 'down',
        time: T,
      },
    });
    await store.insert([firing]);
    // 1.4.x sent plex's recovery, then handled changes of `unrelated` other alerts.
    hist.legacy('plex', '__availability', T + 1);
    for (let i = 0; i < unrelated; i++)
      hist.legacy(`s${i % 200}`, `r${Math.floor(i / 200)}`, T + 2 + i);
    const s = await service(t, {
      webhook: hook.url,
      hist,
      clock,
      control: { store, inner: store },
    });
    assert.equal(s.jobs.registered.has('notify.delivery'), true);
    await s.deliver();
    const row = await store.find(firing.uid);
    assert.deepEqual([row.state, row.lastError], ['superseded', SUPERSEDED_REASON]);
    assert.deepEqual(hook.kinds(), [], 'nothing is sent after 1.4.x’s recovery');
  });

test('D26 checks every waiting alert: 1,200 waiting firings over pages of rows and statements of keys', async t => {
  const hist = history(t);
  const control = controlStore();
  const clock = fakeClock();
  const T = clock.wall() - hour;
  // 200 sources × 6 rules, oldest first (ids in that order); then one more row for the oldest
  // alert on email, and one whose rule 1.4.x wrote as NULL (its order key ends in '').
  const keys = Array.from({ length: 1200 }, (_, i) => [`s${i % 200}`, `r${Math.floor(i / 200)}`]);
  const row = ([service, rule], i, channelId = 'env-webhook') =>
    outboxRow({
      eventUid: `e_${service}_${rule}`,
      channelId,
      orderKey: `${service}\n${rule}`,
      createdAt: T + i * 1000,
      event: { service, kind: 'firing', category: 'availability', rule, message: 'down', time: T },
    });
  const rows = keys.map((key, i) => row(key, i));
  rows.push(row(keys[0], 0, 'email'), row(['n0', ''], 1200));
  for (let start = 0; start < rows.length; start += 200)
    await control.inner.insert(rows.slice(start, start + 200));
  // 1.4.x changed four alerts after their rows (on the last, a middle and the first page of
  // rows; their keys in the first, a middle and a late statement of 200), and the NULL-rule
  // one; and one before its row, which does not supersede it.
  const later = [0, 100, 450, 1199];
  for (const i of later) hist.legacy(...keys[i], T + i * 1000 + 500);
  hist.legacy('n0', null, T + 1200 * 1000 + 500);
  hist.legacy(...keys[700], T + 700 * 1000 - 500);
  const s = await service(t, { hist, control, clock });
  assert.equal(s.jobs.registered.has('notify.delivery'), true);
  const superseded = await control.inner.list({ states: ['superseded'], limit: 100 });
  assert.deepEqual(
    superseded.map(item => `${item.channelId} ${item.orderKey.replace('\n', '/')}`).sort(),
    [
      'email s0/r0',
      'env-webhook n0/',
      'env-webhook s0/r0',
      'env-webhook s100/r0',
      'env-webhook s50/r2',
      'env-webhook s199/r5',
    ].sort()
  );
  assert.ok(superseded.every(item => item.lastError === SUPERSEDED_REASON));
  assert.equal(await control.inner.countActive(), rows.length - 6);
  assert.match(s.logger.lines.warn.join('\n'), /6 notifications were not sent: Orbit 1\.4\.x/);
});

// A webhook receiver on 127.0.0.1 that answers 200 after `delayMs`.
async function slowReceiver(t, delayMs) {
  const got = [];
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    got.push({ body: Buffer.concat(chunks).toString('utf8'), headers: req.headers });
    setTimeout(() => {
      res.writeHead(200);
      res.end();
    }, delayMs);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  return {
    got,
    url: `http://127.0.0.1:${server.address().port}/hook`,
    kinds: () => got.map(item => `${JSON.parse(item.body).service}:${JSON.parse(item.body).kind}`),
  };
}

test('a recovery is sent from memory while the firing’s delivered result waits to be written (D15, D23)', async t => {
  const hook = await slowReceiver(t, 300);
  const s = await service(t, { webhook: hook.url });
  await s.alerting.transitions(s.hist.fire('plex'));
  // The firing is in flight when control.sqlite stops taking writes (reads still work).
  assert.equal((await s.alerting.outbox.pump()).started, 1);
  for (let w = 0; hook.got.length < 1 && w < 400; w++) await sleep(5);
  s.control.state.writes = true;
  for (let w = 0; s.alerting.outbox.inFlight && w < 1000; w++) await sleep(5);
  await settle();
  assert.deepEqual(
    (await rowsOf(s.control.inner)).map(row => row.state),
    ['sending']
  );
  // plex recovers: its row goes to memory and is sent, not held back behind the firing.
  await s.alerting.transitions(s.hist.recover('plex'));
  await s.clock.advance(minute);
  await s.deliver();
  assert.deepEqual(hook.kinds(), ['plex:firing', 'plex:resolved']);
  // The history and the status show the firing as delivered (its result is kept in memory).
  const listed = await s.alerting.deliveries({ limit: 10 });
  assert.deepEqual(
    listed.deliveries.map(item => [item.kind, item.status, item.saved]),
    [
      ['resolved', 'delivered', false],
      ['firing', 'delivered', true],
    ]
  );
  await s.alerting.refresh();
  assert.equal(channelOf(s.alerting, 'env-webhook').counts.sending, 0);
  // A day later, with the disk still full: nothing expired, nothing sent again.
  for (let i = 0; i < 25; i++) {
    await s.clock.advance(60 * minute);
    await s.deliver();
  }
  assert.deepEqual(hook.kinds(), ['plex:firing', 'plex:resolved']);
  // Space is back: both are saved as delivered.
  s.control.state.writes = false;
  await s.clock.advance(10000);
  await s.alerting.refresh();
  assert.deepEqual(
    (await rowsOf(s.control.inner)).map(row => [row.kind, row.state]),
    [
      ['firing', 'delivered'],
      ['resolved', 'delivered'],
    ]
  );
});

test('once Uptime Goblin saves again, rows delivered from memory are saved: nothing unsaved, newest first', async t => {
  const hook = await receiver(t);
  const s = await service(t, { webhook: hook.url });
  s.control.state.writes = true;
  await s.alerting.transitions(s.hist.fire('plex'));
  await s.deliver();
  assert.equal((await s.alerting.deliveries({ limit: 50 })).unsaved, 1);
  s.control.state.writes = false;
  await s.clock.advance(10000);
  await s.alerting.refresh();
  assert.equal(s.alerting.snapshot().saving, true);
  // An hour later, nas fires and recovers (saved as usual).
  await s.clock.advance(60 * minute);
  await s.alerting.transitions(s.hist.fire('nas'));
  await s.alerting.transitions(s.hist.recover('nas'));
  await s.deliver();
  const page = await s.alerting.deliveries({ limit: 50 });
  assert.equal(page.unsaved, 0);
  assert.deepEqual(
    page.deliveries.map(item => [item.alert.service, item.kind, item.status, item.saved]),
    [
      ['nas', 'resolved', 'delivered', true],
      ['nas', 'firing', 'delivered', true],
      ['plex', 'firing', 'delivered', true],
    ]
  );
  assert.deepEqual(hook.kinds(), ['plex:firing', 'nas:firing', 'nas:resolved']);
  // plex's event, delivered from memory, is marked relayed once its row is final and saved.
  await s.jobs.run('notify.relay');
  assert.equal(
    s.hist.store.db.prepare('SELECT COUNT(*) AS n FROM events WHERE relayed = 0').get().n,
    0
  );
});

test('D27: while the signing key cannot be saved, the webhook holds with zero POST until a current key is saved', async t => {
  const hook = await receiver(t);
  const clock = fakeClock();
  const keyring = await makeKeyring();
  const settings = settingsService(keyring, clock);
  settings.state.full = true;
  const s = await service(t, { webhook: hook.url, clock, keyring, settings });
  await s.alerting.transitions(s.hist.fire('plex'));
  await s.deliver();
  assert.equal(hook.got.length, 0);
  assert.equal(channelOf(s.alerting, 'env-webhook').state, 'paused');
  assert.deepEqual(s.alerting.snapshot().signing, {
    configured: true,
    saved: false,
    createdAt: null,
    previousUntil: null,
  });
  await assert.rejects(s.alerting.signing.publicKeys(), {
    code: 'signing_unavailable',
    status: 503,
  });
});

// Writes `values` into notify/envWebhook as a pre-release build did (schema 1, the key fields
// sealed whatever they hold).
async function earlierBuildDoc(settings, keyring, clock, values) {
  const earlier = createSettings({
    store: settings.rows,
    definitions: [
      defineSetting({
        component: 'notify',
        key: 'envWebhook',
        schema: 1,
        fields: {
          signingSecret: { secret: true, validate: value => value },
          previousSigningSecret: { secret: true, validate: value => value },
          previousUntil: { default: null, validate: value => value },
          createdAt: { default: null, validate: value => value },
        },
      }),
    ],
    env: {},
    keyring: () => keyring,
    clock: () => clock.wall(),
  });
  await earlier.update('notify', 'envWebhook', values, { ifVersion: 0, by: 'orbit' });
}

// Review SIGN-1: a 1.5 pre-release build that already signed with Ed25519 kept the key in
// signingSecret. A start that cannot save it moved to signingKey (a full disk) signs with it all
// the same, as the checkpoint did: before, the webhook went out unsigned, and a receiver that
// verifies refused it.
test('review SIGN-1: a retired key never signs; successful replacement stays held until explicit Resume', async t => {
  const hook = await receiver(t);
  const clock = fakeClock();
  const keyring = await makeKeyring();
  const settings = settingsService(keyring, clock);
  const key = generateSigningKey();
  await earlierBuildDoc(settings, keyring, clock, {
    signingSecret: key,
    createdAt: clock.wall() - hour,
  });
  settings.state.full = true;
  const s = await service(t, { webhook: hook.url, clock, keyring, settings });
  await s.alerting.transitions(s.hist.fire('plex'));
  await s.deliver();
  assert.equal(hook.got.length, 0);
  assert.deepEqual(s.alerting.snapshot().signing, {
    configured: true,
    saved: false,
    createdAt: null,
    previousUntil: null,
  });
  await assert.rejects(s.alerting.signing.publicKeys(), { code: 'signing_unavailable' });
  assert.equal((await settings.settings.get('notify', 'envWebhook')).schema, 1);
  // The relay job's next pass moves it once writes work again; the same key signs.
  settings.state.full = false;
  await s.jobs.run('notify.relay');
  const doc = await settings.settings.get('notify', 'envWebhook');
  assert.deepEqual(
    [doc.schema, doc.value.signingKey, doc.value.signingSecret, doc.value.heldSince],
    [2, doc.value.signingKey, null, clock.wall()]
  );
  assert.notEqual(doc.value.signingKey, key);
  await s.deliver();
  assert.equal(hook.got.length, 0);
  await s.alerting.resume('env-webhook', { actor: 'admin' });
  await s.deliver();
  await s.alerting.transitions(s.hist.recover('plex'));
  await s.deliver();
  assert.equal(hook.got.length, 2);
  assert.equal(
    verifyWebhookSignature(
      publicSigningKey(doc.value.signingKey).publicKey,
      hook.got[1].body,
      hook.got[1].headers['x-goblin-signature'],
      { deliveryId: hook.got[1].headers['x-goblin-delivery'], nowMs: clock.wall() }
    ).ok,
    true
  );
});

// G4.1: the signing start work runs without a webhook too, where it only removes the HMAC
// secrets of an earlier pre-release build (lib/alerting/signing.mjs). It never stops the start,
// and the relay job tries again every 10 s while it cannot write.
test('a start without a webhook removes a pre-release HMAC signing secret, makes no key, and tries again while it cannot write', async t => {
  const clock = fakeClock();
  const keyring = await makeKeyring();
  const settings = settingsService(keyring, clock);
  const hmac = 'c0ffee'.repeat(10) + 'beef';
  // What a pre-release build saved: its HMAC secrets, sealed.
  const earlier = createSettings({
    store: settings.rows,
    definitions: [
      defineSetting({
        component: 'notify',
        key: 'envWebhook',
        schema: 1,
        fields: {
          signingSecret: { secret: true, validate: value => value },
          previousSigningSecret: { secret: true, validate: value => value },
          previousUntil: { default: null, validate: value => value },
          createdAt: { default: null, validate: value => value },
        },
      }),
    ],
    env: {},
    keyring: () => keyring,
    clock: () => clock.wall(),
  });
  await earlier.update(
    'notify',
    'envWebhook',
    {
      signingSecret: hmac,
      previousSigningSecret: 'f00d'.repeat(16),
      previousUntil: clock.wall() + 24 * hour,
      createdAt: clock.wall(),
    },
    { ifVersion: 0, by: 'orbit' }
  );
  const stored = async () => (await settings.settings.get('notify', 'envWebhook')).value;
  // The disk is full at the start: Uptime Goblin finds the secrets but cannot remove them. They stay,
  // one line says why, and Uptime Goblin starts.
  settings.state.full = true;
  const s = await service(t, { clock, keyring, settings });
  const lines = level => s.logger.lines[level].filter(line => line.includes('HMAC'));
  assert.deepEqual(lines('error'), [
    'Uptime Goblin could not remove the HMAC signing secret of a pre-release build from its settings (the disk is full); it tries again every 10 seconds.',
  ]);
  assert.deepEqual(lines('warn'), []);
  assert.equal((await stored()).signingSecret, hmac);
  // The relay job's next pass removes both, and makes no key.
  settings.state.full = false;
  await s.jobs.run('notify.relay');
  assert.deepEqual(await stored(), {
    signingKey: null,
    previousSigningKey: null,
    previousUntil: null,
    createdAt: null,
    heldSince: null,
    signingSecret: null,
    previousSigningSecret: null,
  });
  assert.deepEqual(lines('warn'), [
    "Uptime Goblin removed the alert webhook's HMAC signing secret (from a pre-release build); GOBLIN_WEBHOOK_URL is not set, so it made no signing key in its place.",
  ]);
  assert.equal(s.alerting.signing.describe(), null);
  assert.ok(!s.events.some(event => event.action === 'signing.created'));
  // Later passes leave the document alone.
  const { version } = await settings.settings.get('notify', 'envWebhook');
  await s.jobs.run('notify.relay');
  assert.equal((await settings.settings.get('notify', 'envWebhook')).version, version);
  assert.deepEqual([lines('error').length, lines('warn').length], [1, 1]);
});

// A start without a webhook reads the settings even where no pre-release build ever ran. A read
// that fails is said as such, with its own cause: not a full disk unless it is one.
test('a start without a webhook whose settings cannot be read says so with the cause, and later finds nothing to remove', async t => {
  const clock = fakeClock();
  const keyring = await makeKeyring();
  const settings = settingsService(keyring, clock);
  settings.state.readFails = true;
  const s = await service(t, { clock, keyring, settings });
  const lines = level => s.logger.lines[level].filter(line => line.includes('HMAC'));
  assert.deepEqual(lines('error'), [
    'Uptime Goblin could not read its settings to look for an HMAC signing secret of a pre-release build (disk I/O error); it tries again every 10 seconds.',
  ]);
  settings.state.readFails = false;
  await s.jobs.run('notify.relay');
  await s.jobs.run('notify.relay');
  assert.deepEqual([lines('error').length, lines('warn').length], [1, 0]);
  assert.equal((await settings.settings.get('notify', 'envWebhook')).version, 0);
  assert.equal(s.alerting.signing.describe(), null);
});

// Builds before schema 2 kept the Ed25519 key in signingSecret, which earlier pre-release builds
// take for their HMAC secret. A start without a webhook moves it out too; on a full disk it says
// so and the relay job tries again every 10 s.
test('a start without a webhook clears retired Ed25519 authority, and retries while it cannot write', async t => {
  const clock = fakeClock();
  const keyring = await makeKeyring();
  const settings = settingsService(keyring, clock);
  const key = generateSigningKey();
  const earlier = createSettings({
    store: settings.rows,
    definitions: [
      defineSetting({
        component: 'notify',
        key: 'envWebhook',
        schema: 1,
        fields: {
          signingSecret: { secret: true, validate: value => value },
          previousSigningSecret: { secret: true, validate: value => value },
          previousUntil: { default: null, validate: value => value },
          createdAt: { default: null, validate: value => value },
        },
      }),
    ],
    env: {},
    keyring: () => keyring,
    clock: () => clock.wall(),
  });
  await earlier.update(
    'notify',
    'envWebhook',
    { signingSecret: key, createdAt: clock.wall() },
    { ifVersion: 0, by: 'orbit' }
  );
  settings.state.full = true;
  const s = await service(t, { clock, keyring, settings });
  const lines = level => s.logger.lines[level].filter(line => /signing|HMAC/.test(line));
  assert.deepEqual(lines('error'), [
    "Uptime Goblin could not save the webhook's signing settings in the form that pre-release builds cannot read (the disk is full); it tries again every 10 seconds.",
  ]);
  assert.equal((await settings.settings.get('notify', 'envWebhook')).schema, 1);
  settings.state.full = false;
  await s.jobs.run('notify.relay');
  const doc = await settings.settings.get('notify', 'envWebhook');
  assert.deepEqual(
    [doc.schema, doc.value.signingKey, doc.value.signingSecret, doc.value.createdAt],
    [2, null, null, null]
  );
  assert.deepEqual([lines('error').length, lines('warn').length], [1, 0]);
  // Later passes leave the document alone.
  await s.jobs.run('notify.relay');
  assert.equal((await settings.settings.get('notify', 'envWebhook')).version, doc.version);
  assert.equal(s.alerting.signing.describe(), null);
});

test('signing: a key pair created once, its public key read, replaced with a 24-hour overlap, replaced when unreadable', async t => {
  const hook = await receiver(t);
  const clock = fakeClock();
  const keyring = await makeKeyring();
  const settings = settingsService(keyring, clock);
  const s = await service(t, { webhook: hook.url, clock, keyring, settings });
  assert.match(
    s.logger.lines.warn.join('\n'),
    /Uptime Goblin created a new signing key for the alert webhook; receivers that check X-Goblin-Signature need its public key/
  );
  const shown = await s.alerting.signing.publicKeys();
  assert.equal(shown.algorithm, 'Ed25519');
  assert.match(shown.publicKey, /^-----BEGIN PUBLIC KEY-----\n/);
  assert.deepEqual(
    [shown.createdAt, shown.previousUntil, shown.previous],
    [clock.wall(), null, null]
  );
  // Reading the public key is neither logged nor recorded.
  assert.doesNotMatch(s.logger.lines.warn.join('\n'), /was shown/);
  assert.ok(!s.events.some(event => /reveal|publicKey/.test(event.action)));
  // Sealed at rest: the stored document never holds the private key's text.
  const [row] = await settings.rows.list('notify');
  const privateKey = (await settings.settings.get('notify', 'envWebhook')).value.signingKey;
  assert.match(privateKey, /^-----BEGIN PRIVATE KEY-----\n/);
  assert.equal(publicSigningKey(privateKey).keyId, shown.keyId);
  assert.ok(!row.value.includes(privateKey.split('\n')[1]));
  // A second start reuses it.
  const second = await service(t, { webhook: hook.url, clock, keyring, settings, start: false });
  assert.equal((await second.alerting.signing.publicKeys()).keyId, shown.keyId);
  // Rotation: the new key signs with the old one beside it for 24 hours.
  await clock.advance(1000);
  const rotated = await s.alerting.signing.rotate({ actor: { login: 'dana' } });
  assert.deepEqual(rotated, { createdAt: clock.wall(), previousUntil: clock.wall() + 24 * hour });
  const next = await s.alerting.signing.publicKeys();
  assert.notEqual(next.keyId, shown.keyId);
  assert.equal(next.previousUntil, clock.wall() + 24 * hour);
  assert.equal(next.previous.keyId, shown.keyId);
  await s.alerting.transitions(s.hist.fire('plex'));
  await s.deliver();
  const [request] = hook.got;
  for (const { publicKey } of [shown, next])
    assert.deepEqual(
      verifyWebhookSignature(publicKey, request.body, request.headers['x-goblin-signature'], {
        deliveryId: request.headers['x-goblin-delivery'],
        nowMs: clock.wall(),
      }),
      { ok: true }
    );
  // After 24 hours only the new one signs.
  await clock.advance(24 * hour + 1);
  await s.alerting.transitions(s.hist.recover('plex'));
  await s.deliver();
  assert.equal(hook.got[1].headers['x-goblin-signature'].split(',').length, 2);
  assert.equal(s.alerting.signing.describe().previousUntil, null);
  // A concurrent rotation loses the compare-and-swap.
  Object.assign(settings.state, { race: true, gets: 0 });
  await assert.rejects(s.alerting.signing.rotate({ actor: 'dana' }), {
    code: 'signing_conflict',
    status: 409,
  });
  // Another key (after goblin-admin key reset): the sealed private key no longer opens; the next
  // start replaces the pair and says receivers need the new public key.
  const otherKey = await makeKeyring();
  const otherSettings = createSettings({
    store: settings.rows,
    definitions: [notifySettings],
    env: {},
    keyring: () => otherKey,
    clock: () => clock.wall(),
  });
  const replaced = await service(t, {
    webhook: hook.url,
    clock,
    keyring: otherKey,
    settings: { settings: otherSettings, rows: settings.rows, state: {} },
    start: false,
  });
  assert.match(
    replaced.logger.lines.warn.join('\n'),
    /created a new signing key.*The previous key could not be opened with the current encryption key/
  );
  assert.notEqual((await replaced.alerting.signing.publicKeys()).keyId, next.keyId);
  // Without a webhook there is nothing to sign.
  const none = await service(t, { start: false });
  assert.equal(none.alerting.signing.describe(), null);
  await assert.rejects(none.alerting.signing.publicKeys(), {
    code: 'webhook_not_configured',
    status: 404,
  });
  await assert.rejects(none.alerting.signing.rotate({ actor: 'dana' }), {
    code: 'webhook_not_configured',
  });
});

test('the public key is read as often as asked, together too; a read that cannot open the key is signing_unavailable', async t => {
  const hook = await receiver(t);
  const clock = fakeClock();
  const keyring = await makeKeyring();
  const settings = settingsService(keyring, clock);
  // The disk was full at start, so there is no key yet: nothing to read.
  settings.state.full = true;
  const s = await service(t, { webhook: hook.url, clock, keyring, settings });
  const read = () => s.alerting.signing.publicKeys();
  for (let n = 0; n < 3; n++)
    await assert.rejects(read(), { code: 'signing_unavailable', status: 503, retryAfter: 60 });
  settings.state.full = false;
  await s.jobs.run('notify.relay');
  assert.equal(s.alerting.signing.describe().saved, true);
  // The settings document cannot be read: signing_unavailable, together and one by one.
  settings.state.readFails = true;
  const together = await Promise.allSettled(Array.from({ length: 6 }, read));
  assert.deepEqual(
    together.map(result => result.reason?.code),
    Array(6).fill('signing_unavailable')
  );
  settings.state.readFails = false;
  // No limit: 30 at once all answer the same public key.
  const answers = await Promise.all(Array.from({ length: 30 }, read));
  assert.equal(new Set(answers.map(answer => answer.keyId)).size, 1);
  assert.equal(new Set(answers.map(answer => answer.publicKey)).size, 1);
  assert.ok(!s.events.some(event => event.action === 'signing.reveal'));
});

// Review F2: a pre-release build's receiver checks `v1` (its HMAC secret) and refuses the v1a
// requests of this release; a 400 or 422 ended each alert as Failed, and giving the receiver the
// public key later sent none of them again. A start that makes a key pair in place of signing
// material (here an HMAC secret) holds the webhook: paused with SIGNING_HOLD_REASON, never probed,
// nothing signed or sent, until an admin's Resume. A first key pair is not held.
async function prereleaseHmacDoc(settings, keyring, clock) {
  const earlier = createSettings({
    store: settings.rows,
    definitions: [
      defineSetting({
        component: 'notify',
        key: 'envWebhook',
        schema: 1,
        fields: {
          signingSecret: { secret: true, validate: value => value },
          previousSigningSecret: { secret: true, validate: value => value },
          previousUntil: { default: null, validate: value => value },
          createdAt: { default: null, validate: value => value },
        },
      }),
    ],
    env: {},
    keyring: () => keyring,
    clock: () => clock.wall(),
  });
  await earlier.update(
    'notify',
    'envWebhook',
    { signingSecret: 'c0ffee'.repeat(10) + 'beef', createdAt: clock.wall() - hour },
    { ifVersion: 0, by: 'orbit' }
  );
}

test('review F2: a start that replaces a pre-release HMAC secret holds the webhook until Resume: nothing reaches a receiver that still checks v1, no start probe, then the held alert goes signed', async t => {
  // The receiver refuses whatever it gets until it has the new public key.
  const hook = await receiver(t);
  hook.answers.push(422, 422, 422, 422);
  const clock = fakeClock();
  const keyring = await makeKeyring();
  const settings = settingsService(keyring, clock);
  await prereleaseHmacDoc(settings, keyring, clock);
  const s = await service(t, {
    webhook: hook.url,
    clock,
    keyring,
    settings,
    configOptions: { email: emailOn },
  });
  const created = (await settings.settings.get('notify', 'envWebhook')).value;
  assert.match(created.signingKey, /^-----BEGIN PRIVATE KEY-----\n/);
  assert.deepEqual([created.signingSecret, created.heldSince], [null, clock.wall()]);
  await s.alerting.refresh();
  let webhook = channelOf(s.alerting, 'env-webhook');
  assert.deepEqual(
    [webhook.state, webhook.pausedReason, webhook.nextAttemptAt],
    ['paused', SIGNING_HOLD_REASON, null]
  );
  assert.ok(
    s.logger.lines.warn.includes(`Webhook notifications are paused: ${SIGNING_HOLD_REASON}`)
  );
  // An alert waits: the receiver is never asked, so nothing is refused or Failed.
  const plex = s.hist.fire('plex');
  await s.alerting.transitions(plex);
  await clock.advance(3000);
  await s.deliver();
  assert.equal(hook.got.length, 0);
  const uid = deliveryUid(plex[0].uid, 'env-webhook');
  const held = async control => (await rowsOf(control.inner)).find(row => row.uid === uid);
  assert.deepEqual([(await held(s.control)).state, (await held(s.control)).attempts], ['held', 0]);
  await s.alerting.refresh();
  assert.equal(channelOf(s.alerting, 'env-webhook').counts.paused, 1);
  // Email says why, as for any pause.
  assert.ok(
    s.mail.sent.some(mail =>
      mail.text.includes(`Webhook notifications are paused: ${SIGNING_HOLD_REASON}`)
    )
  );
  // A restart sends no probe: the receiver is still not asked.
  await s.alerting.stop({ timeoutMs: 0 });
  const again = await service(t, {
    webhook: hook.url,
    clock,
    keyring,
    settings,
    hist: s.hist,
    control: s.control,
    mail: s.mail,
    configOptions: { email: emailOn },
  });
  await again.deliver();
  assert.equal(hook.got.length, 0);
  await again.alerting.refresh();
  webhook = channelOf(again.alerting, 'env-webhook');
  assert.deepEqual([webhook.state, webhook.pausedReason], ['paused', SIGNING_HOLD_REASON]);
  // The public key is read while held (the same key: the restart made none) and given to the
  // receiver, which now accepts; Resume ends the hold and sends what waited, signed with it.
  const shown = await again.alerting.signing.publicKeys();
  assert.equal(shown.keyId, publicSigningKey(created.signingKey).keyId);
  hook.answers.length = 0;
  const resumed = await again.alerting.resume('env-webhook', { actor: 'admin' });
  assert.deepEqual([resumed.released, resumed.channel.state], [1, 'ok']);
  assert.equal((await settings.settings.get('notify', 'envWebhook')).value.heldSince, null);
  await again.deliver();
  assert.deepEqual(hook.kinds(), ['plex:firing']);
  const [request] = hook.got;
  assert.deepEqual(
    verifyWebhookSignature(shown.publicKey, request.body, request.headers['x-goblin-signature'], {
      deliveryId: request.headers['x-goblin-delivery'],
      nowMs: clock.wall(),
    }),
    { ok: true }
  );
  assert.equal((await held(again.control)).state, 'delivered');
  // The next start holds nothing.
  const third = await service(t, {
    webhook: hook.url,
    clock,
    keyring,
    settings,
    hist: s.hist,
    control: s.control,
    mail: s.mail,
    configOptions: { email: emailOn },
  });
  await third.alerting.refresh();
  assert.equal(channelOf(third.alerting, 'env-webhook').state, 'ok');
});

test('review F2: a first key pair is not held; a key the encryption key no longer opens is replaced held', async t => {
  const hook = await receiver(t);
  const clock = fakeClock();
  const keyring = await makeKeyring();
  const settings = settingsService(keyring, clock);
  const s = await service(t, { webhook: hook.url, clock, keyring, settings });
  assert.equal((await settings.settings.get('notify', 'envWebhook')).value.heldSince, null);
  await s.alerting.transitions(s.hist.fire('plex'));
  await s.deliver();
  assert.equal(hook.got.length, 1);
  await s.alerting.stop({ timeoutMs: 0 });
  // After goblin-admin key reset: the sealed key no longer opens, so receivers that hold its
  // public key would refuse the new one.
  const otherKey = await makeKeyring();
  const otherSettings = createSettings({
    store: settings.rows,
    definitions: [notifySettings],
    env: {},
    keyring: () => otherKey,
    clock: () => clock.wall(),
  });
  const reset = await service(t, {
    webhook: hook.url,
    clock,
    keyring: otherKey,
    hist: s.hist,
    control: s.control,
    settings: { settings: otherSettings, rows: settings.rows, state: {} },
  });
  await reset.alerting.transitions(reset.hist.recover('plex'));
  await reset.deliver();
  assert.equal(hook.got.length, 1);
  await reset.alerting.refresh();
  assert.equal(channelOf(reset.alerting, 'env-webhook').pausedReason, SIGNING_HOLD_REASON);
  assert.equal(
    (await otherSettings.get('notify', 'envWebhook')).value.heldSince,
    clock.wall(),
    'saved with the new key'
  );
});

test('review F2: while the new key cannot be saved the held webhook sends nothing, not even unsigned; a Resume that cannot end the hold leaves it held', async t => {
  const hook = await receiver(t);
  const clock = fakeClock();
  const keyring = await makeKeyring();
  const settings = settingsService(keyring, clock);
  await prereleaseHmacDoc(settings, keyring, clock);
  settings.state.full = true;
  const s = await service(t, { webhook: hook.url, clock, keyring, settings });
  assert.ok(
    s.logger.lines.error.includes(
      'The new webhook signing key could not be saved (the disk is full); the webhook holds its alerts meanwhile, and Uptime Goblin tries again every 10 seconds.'
    )
  );
  await s.alerting.transitions(s.hist.fire('plex'));
  await s.deliver();
  assert.equal(hook.got.length, 0, 'not sent unsigned');
  await s.alerting.refresh();
  assert.equal(channelOf(s.alerting, 'env-webhook').pausedReason, SIGNING_HOLD_REASON);
  // Saved at the relay job's next pass, with the hold.
  settings.state.full = false;
  await s.jobs.run('notify.relay');
  const doc = await settings.settings.get('notify', 'envWebhook');
  assert.deepEqual(
    [doc.value.signingSecret, doc.value.heldSince, s.alerting.signing.describe().saved],
    [null, clock.wall(), true]
  );
  await s.deliver();
  assert.equal(hook.got.length, 0);
  // A pause ended by something else meanwhile (a send in flight that answered, say) still sends
  // nothing: the next send pauses the webhook again with the reason.
  await s.alerting.outbox.resume('env-webhook');
  await s.deliver();
  assert.equal(hook.got.length, 0);
  await s.alerting.refresh();
  assert.deepEqual(
    [channelOf(s.alerting, 'env-webhook').state, channelOf(s.alerting, 'env-webhook').pausedReason],
    ['paused', SIGNING_HOLD_REASON]
  );
  // Resume while the settings cannot be written, or after another change of the signing key
  // was saved meanwhile: refused, still held, still paused.
  settings.state.full = true;
  await assert.rejects(s.alerting.resume('env-webhook', { actor: 'admin' }), {
    code: 'storage_full',
    status: 503,
  });
  settings.state.full = false;
  Object.assign(settings.state, { race: true, gets: 0 });
  await assert.rejects(s.alerting.resume('env-webhook', { actor: 'admin' }), {
    code: 'signing_conflict',
    status: 409,
  });
  settings.state.race = false;
  await s.alerting.refresh();
  assert.equal(channelOf(s.alerting, 'env-webhook').state, 'paused');
  assert.notEqual((await settings.settings.get('notify', 'envWebhook')).value.heldSince, null);
  await s.deliver();
  assert.equal(hook.got.length, 0);
  // Resumed: the held alert goes, signed with the new key.
  assert.equal((await s.alerting.resume('env-webhook', { actor: 'admin' })).released, 1);
  await s.deliver();
  assert.equal(hook.got.length, 1);
  assert.match(hook.got[0].headers['x-goblin-signature'], /^t=\d+,v1a=[0-9a-f]{16}:[0-9a-f]{128}$/);
});

// Review SEC-1: while the start could not save the new key yet, the hold is only in memory.
// Resume used to forget it and release the held alerts unsigned; Replace signing key used to
// save the new key without the hold, so a restart sent them signed with a key receivers did not
// have (a 422 ended each as Failed).
test('review SEC-1: Resume before the new key is saved is refused, the hold stays and nothing goes unsigned', async t => {
  const hook = await receiver(t);
  const clock = fakeClock();
  const keyring = await makeKeyring();
  const settings = settingsService(keyring, clock);
  await prereleaseHmacDoc(settings, keyring, clock);
  settings.state.full = true;
  const s = await service(t, { webhook: hook.url, clock, keyring, settings });
  await s.alerting.transitions(s.hist.fire('plex'));
  await s.deliver();
  assert.equal(hook.got.length, 0);
  // Refused while the key write fails, and once writes work again before the relay job's next
  // pass saved the key: there is no public key to give receivers yet.
  for (const full of [true, false]) {
    settings.state.full = full;
    await assert.rejects(s.alerting.resume('env-webhook', { actor: 'admin' }), {
      code: 'signing_unavailable',
      status: 503,
    });
    await s.deliver();
    assert.equal(hook.got.length, 0, 'nothing sent, signed or not');
    await s.alerting.refresh();
    const webhook = channelOf(s.alerting, 'env-webhook');
    assert.deepEqual([webhook.state, webhook.pausedReason], ['paused', SIGNING_HOLD_REASON]);
  }
  assert.equal((await settings.settings.get('notify', 'envWebhook')).value.heldSince, null);
  // The relay job saves the key pair with the hold; the public key is shown, Resume sends signed.
  await s.jobs.run('notify.relay');
  const shown = await s.alerting.signing.publicKeys();
  assert.equal((await settings.settings.get('notify', 'envWebhook')).value.heldSince, clock.wall());
  assert.equal((await s.alerting.resume('env-webhook', { actor: 'admin' })).released, 1);
  await s.deliver();
  assert.equal(hook.got.length, 1);
  const [request] = hook.got;
  assert.deepEqual(
    verifyWebhookSignature(shown.publicKey, request.body, request.headers['x-goblin-signature'], {
      deliveryId: request.headers['x-goblin-delivery'],
      nowMs: clock.wall(),
    }),
    { ok: true }
  );
});

test('review SEC-1: Replace signing key before the new key is saved keeps the hold across a restart', async t => {
  // A receiver that still checks the pre-release HMAC secret refuses the new key's requests.
  const hook = await receiver(t);
  hook.answers.push(422, 422, 422);
  const clock = fakeClock();
  const keyring = await makeKeyring();
  const settings = settingsService(keyring, clock);
  await prereleaseHmacDoc(settings, keyring, clock);
  settings.state.full = true;
  const s = await service(t, { webhook: hook.url, clock, keyring, settings });
  settings.state.full = false;
  await s.alerting.signing.rotate({ actor: 'admin' });
  const rotated = (await settings.settings.get('notify', 'envWebhook')).value;
  assert.deepEqual([rotated.signingSecret, rotated.heldSince], [null, clock.wall()]);
  await s.alerting.stop({ timeoutMs: 0 });
  const again = await service(t, { webhook: hook.url, clock, keyring, settings });
  const plex = again.hist.fire('plex');
  await again.alerting.transitions(plex);
  await again.deliver();
  assert.equal(hook.got.length, 0, 'held: the receiver is not asked');
  await again.alerting.refresh();
  const webhook = channelOf(again.alerting, 'env-webhook');
  assert.deepEqual(
    [webhook.state, webhook.pausedReason, webhook.counts.failed],
    ['paused', SIGNING_HOLD_REASON, 0]
  );
  // Given the public key, the receiver accepts; Resume sends the held alert, signed.
  hook.answers.length = 0;
  assert.equal((await again.alerting.resume('env-webhook', { actor: 'admin' })).released, 1);
  await again.deliver();
  assert.deepEqual(hook.kinds(), ['plex:firing']);
  assert.equal(
    (await rowsOf(again.control.inner)).find(
      row => row.uid === deliveryUid(plex[0].uid, 'env-webhook')
    ).state,
    'delivered'
  );
});

// Review SIGN-2: the start could not read its settings, so it knew of no hold for the pre-release
// HMAC secret there, and an admin replaced the signing key before its next try. The replacement
// keeps no key, so it saves the hold as the start would have: the webhook waits for Resume
// (before, it sent with a key the receiver did not have, and a 422 ended the alert as Failed).
test('review SIGN-2: Replace signing key while the start could not read its settings holds the webhook for a replaced HMAC secret', async t => {
  const hook = await receiver(t);
  hook.answers.push(422, 422, 422);
  const clock = fakeClock();
  const keyring = await makeKeyring();
  const settings = settingsService(keyring, clock);
  await prereleaseHmacDoc(settings, keyring, clock);
  settings.state.readFails = true;
  const s = await service(t, { webhook: hook.url, clock, keyring, settings });
  settings.state.readFails = false;
  await s.alerting.signing.rotate({ actor: 'admin' });
  const rotated = (await settings.settings.get('notify', 'envWebhook')).value;
  assert.deepEqual([rotated.signingSecret, rotated.heldSince], [null, clock.wall()]);
  await s.jobs.run('notify.relay');
  const plex = s.hist.fire('plex');
  await s.alerting.transitions(plex);
  await s.deliver();
  assert.equal(hook.got.length, 0, 'held: the receiver is not asked');
  await s.alerting.refresh();
  const webhook = channelOf(s.alerting, 'env-webhook');
  assert.deepEqual(
    [webhook.state, webhook.pausedReason, webhook.counts.failed],
    ['paused', SIGNING_HOLD_REASON, 0]
  );
  // Given the public key, the receiver accepts; Resume sends the held alert, signed with it.
  const shown = await s.alerting.signing.publicKeys();
  hook.answers.length = 0;
  assert.equal((await s.alerting.resume('env-webhook', { actor: 'admin' })).released, 1);
  await s.deliver();
  assert.deepEqual(hook.kinds(), ['plex:firing']);
  const [request] = hook.got;
  assert.equal(
    verifyWebhookSignature(shown.publicKey, request.body, request.headers['x-goblin-signature'], {
      deliveryId: request.headers['x-goblin-delivery'],
      nowMs: clock.wall(),
    }).ok,
    true
  );
});

// Writes `values` into notify/envWebhook as a newer release might (schema 3): read-only here.
async function newerBuildDoc(settings, keyring, clock, values) {
  const newer = createSettings({
    store: settings.rows,
    definitions: [
      defineSetting({
        component: 'notify',
        key: 'envWebhook',
        schema: 3,
        fields: {
          signingKey: { secret: true, validate: value => value },
          previousSigningKey: { secret: true, validate: value => value },
          previousUntil: { default: null, validate: value => value },
          createdAt: { default: null, validate: value => value },
          heldSince: { default: null, validate: value => value },
          signingKeyV3: { secret: true, validate: value => value },
        },
      }),
    ],
    env: {},
    keyring: () => keyring,
    clock: () => clock.wall(),
  });
  const { version } = await settings.settings.get('notify', 'envWebhook');
  await newer.update('notify', 'envWebhook', values, { ifVersion: version, by: 'orbit' });
}

// A rollback preserves newer immutable holds; missing authority never permits unsigned
// delivery. A usable unheld key remains available without changing the saved document.

test('review SIGN-3: newer settings preserve immutable holds and block missing-key delivery', async t => {
  await t.test('no key this release can use', async s => {
    const hook = await receiver(s);
    const clock = fakeClock();
    const keyring = await makeKeyring();
    const settings = settingsService(keyring, clock);
    // A newer release moved the key to a field of its own, and held the webhook.
    await settings.settings.update(
      'notify',
      'envWebhook',
      { signingKey: generateSigningKey(), createdAt: clock.wall() },
      { ifVersion: 0, by: 'orbit' }
    );
    await newerBuildDoc(settings, keyring, clock, {
      signingKey: null,
      signingKeyV3: generateSigningKey(),
      heldSince: clock.wall(),
    });
    const s1 = await service(s, { webhook: hook.url, clock, keyring, settings });
    await s1.alerting.transitions(s1.hist.fire('plex'));
    await s1.deliver();
    assert.deepEqual(hook.kinds(), []);
    await assert.rejects(s1.alerting.resume('env-webhook', { actor: 'admin' }), {
      code: 'signing_compatibility',
      status: 409,
    });
    await s1.alerting.refresh();
    assert.equal(channelOf(s1.alerting, 'env-webhook').state, 'paused');
    assert.equal(s1.alerting.snapshot().signing.saved, false);
    assert.ok(
      s1.logger.lines.error.some(line =>
        /^The new webhook signing key could not be saved \(.*newer Uptime Goblin.*\); the webhook holds its alerts meanwhile, and Uptime Goblin tries again every 10 seconds\.$/.test(
          line
        )
      )
    );
  });
  await t.test("that release's key and hold", async s => {
    const hook = await receiver(s);
    const clock = fakeClock();
    const keyring = await makeKeyring();
    const settings = settingsService(keyring, clock);
    // This release replaced a pre-release HMAC secret and held the webhook; an alert waits.
    await prereleaseHmacDoc(settings, keyring, clock);
    const first = await service(s, { webhook: hook.url, clock, keyring, settings });
    await first.alerting.transitions(first.hist.fire('plex'));
    await first.deliver();
    assert.equal(hook.got.length, 0);
    await first.alerting.stop({ timeoutMs: 0 });
    // A newer release ran on the data and saved the settings in its form, key and hold as they
    // were; then this release runs again.
    const { signingKey, heldSince } = (await settings.settings.get('notify', 'envWebhook')).value;
    await newerBuildDoc(settings, keyring, clock, { signingKey, heldSince });
    const again = await service(s, {
      webhook: hook.url,
      clock,
      keyring,
      settings,
      hist: first.hist,
      control: first.control,
    });
    await again.deliver();
    assert.deepEqual(hook.kinds(), []);
    await assert.rejects(again.alerting.resume('env-webhook', { actor: 'admin' }), {
      code: 'signing_compatibility',
      status: 409,
    });
    await again.alerting.refresh();
    assert.equal(channelOf(again.alerting, 'env-webhook').state, 'paused');
    // The newer release's settings are as it left them.
    const doc = await settings.settings.get('notify', 'envWebhook');
    assert.deepEqual([doc.readOnly, doc.value.heldSince], [true, heldSince]);
  });
});

test('test emails: recorded best-effort; an accepted one resumes a paused email channel', async t => {
  const mail = mailer([authFails]);
  const s = await service(t, { mail, configOptions: { email: emailOn } });
  await s.alerting.transitions(s.hist.fire('plex'));
  await s.clock.advance(3000);
  await s.deliver();
  await s.alerting.refresh();
  assert.equal(channelOf(s.alerting, 'email').state, 'paused');
  assert.equal(s.alerting.emailSending(), false);
  await s.alerting.recordTest({ accepted: false, message: 'Email sign-in failed.' });
  assert.equal(channelOf(s.alerting, 'email').state, 'paused');
  assert.equal(channelOf(s.alerting, 'email').failedTotal, 2);
  await s.alerting.recordTest({ accepted: true });
  assert.equal(channelOf(s.alerting, 'email').state, 'ok');
  await s.deliver();
  assert.equal(s.mail.sent.length, 2);
  // A status write that fails (disk full) never rejects.
  s.control.state.writes = true;
  await s.alerting.recordTest({ accepted: true });
  s.control.state.writes = false;
});

test('saving email settings clears the last error and the refusal streak; three refusals are "refusing"', async t => {
  const refuse = () =>
    Promise.reject(Object.assign(new Error('quota'), { code: 'EMESSAGE', responseCode: 550 }));
  const mail = mailer([refuse, refuse, refuse]);
  const s = await service(t, { mail, configOptions: { email: emailOn } });
  for (const id of ['plex', 'nas', 'x']) {
    await s.alerting.transitions(s.hist.fire(id));
    await s.clock.advance(3000);
    await s.deliver();
  }
  await s.alerting.refresh();
  let email = channelOf(s.alerting, 'email');
  assert.deepEqual(
    [email.state, email.consecutiveRefusals, email.counts.failed],
    ['refusing', 3, 3]
  );
  assert.equal(s.alerting.legacy().email.state, 'error');
  assert.deepEqual(s.alerting.snapshot().totals.failed, 3);
  await s.alerting.emailChanged();
  email = channelOf(s.alerting, 'email');
  assert.deepEqual([email.state, email.consecutiveRefusals, email.lastError], ['ok', 0, null]);
  // One accepted message also ends "refusing"; failed counts only since the last success.
  const again = mailer([refuse, refuse, refuse]);
  const t2 = await service(t, { mail: again, configOptions: { email: emailOn } });
  for (const id of ['plex', 'nas', 'x', 'y']) {
    await t2.alerting.transitions(t2.hist.fire(id));
    await t2.clock.advance(3000);
    await t2.deliver();
  }
  await t2.alerting.refresh();
  email = channelOf(t2.alerting, 'email');
  assert.deepEqual([email.state, email.consecutiveRefusals, email.counts.failed], ['ok', 0, 0]);
  assert.equal(email.failedSince, email.lastSuccess);
});

test('failed counts the last 24 hours at most', async t => {
  const hook = await receiver(t, [400]);
  const s = await service(t, { webhook: hook.url });
  await s.alerting.transitions(s.hist.fire('plex'));
  await s.deliver();
  await s.alerting.refresh();
  assert.equal(s.alerting.snapshot().totals.failed, 1);
  await s.clock.advance(24 * hour + 1);
  await s.alerting.refresh();
  assert.equal(s.alerting.snapshot().totals.failed, 0);
  // Still listed in the history (30 days).
  assert.equal((await s.alerting.deliveries({ filter: 'problems' })).deliveries.length, 1);
});

test('Retry: refusals as DeliveryErrors, a failed row retried, an outdated one refused', async t => {
  const hook = await receiver(t, [400, 401]);
  const s = await service(t, { webhook: hook.url });
  const firing = s.hist.fire('plex');
  await s.alerting.transitions(firing);
  await s.deliver();
  const uid = deliveryUid(firing[0].uid, 'env-webhook');
  await assert.rejects(s.alerting.retry('d_aaaaaaaaaaaaaaaaaaaaaaaaaa'), {
    status: 404,
    code: 'delivery_not_found',
  });
  // The next alert pauses the channel (401): a retry is refused with the channel's reason.
  await s.alerting.transitions(s.hist.fire('nas'));
  await s.deliver();
  await assert.rejects(s.alerting.retry(uid), {
    status: 409,
    code: 'channel_paused',
    message:
      'Webhook notifications are paused: The webhook answered 401. Check GOBLIN_WEBHOOK_URL and the receiver; queued alerts wait until it is fixed. Resume the channel to send them.',
  });
  await s.alerting.resume('env-webhook');
  await s.deliver();
  // Retry the failed firing.
  const retried = await s.alerting.retry(uid, { actor: { login: 'dana' } });
  assert.equal(retried.retried, 1);
  assert.deepEqual([retried.delivery.status, retried.delivery.retryable], ['retrying', true]);
  await s.deliver();
  assert.equal(hook.got.filter(item => item.headers['x-goblin-delivery'] === uid).length, 2);
  await assert.rejects(s.alerting.retry(uid), {
    code: 'delivery_not_retryable',
    message: 'Only failed notifications and notifications waiting to retry can be retried.',
  });
  // A failed firing whose recovery was delivered meanwhile: out of order, refused.
  hook.answers.push(400);
  const second = s.hist.fire('x');
  await s.alerting.transitions(second);
  await s.deliver();
  await s.alerting.transitions(s.hist.recover('x'));
  await s.deliver();
  await assert.rejects(s.alerting.retry(deliveryUid(second[0].uid, 'env-webhook')), {
    code: 'delivery_outdated',
  });
  const listed = (await s.alerting.deliveries({})).deliveries.find(
    item => item.uid === deliveryUid(second[0].uid, 'env-webhook')
  );
  assert.deepEqual([listed.status, listed.retryable], ['failed', false]);
  const audit = s.events.filter(event => event.action === 'delivery.retry');
  assert.deepEqual(
    audit.map(event => event.outcome),
    ['refused', 'refused', 'ok', 'refused', 'refused']
  );
});

test('Retry is neither offered nor taken on a channel that is not set up: email switched off, the webhook removed at a restart (A45)', async t => {
  const hook = await receiver(t, [500, 400]);
  const recipientRefused = () =>
    Promise.reject(
      Object.assign(new Error('550 5.1.1 Recipient refused'), {
        code: 'EENVELOPE',
        command: 'RCPT TO',
        responseCode: 550,
      })
    );
  const mail = mailer([recipientRefused]);
  const s = await service(t, { webhook: hook.url, mail, configOptions: { email: emailOn } });
  const plex = s.hist.fire('plex'),
    nas = s.hist.fire('nas');
  await s.alerting.transitions(plex);
  await s.deliver();
  await s.alerting.transitions(nas);
  await s.deliver();
  await s.clock.advance(3000);
  await s.deliver();
  const uid = (event, channel) => deliveryUid(event[0].uid, channel);
  const listed = async () =>
    Object.fromEntries(
      (await s.alerting.deliveries({})).deliveries.map(item => [
        `${item.alert.service}:${item.channel}`,
        `${item.status}:${item.retryable}`,
      ])
    );
  // Both channels set up: the webhook's retry and failure, and the failed digest, offer Retry.
  assert.deepEqual(await listed(), {
    'plex:env-webhook': 'retrying:true',
    'nas:env-webhook': 'failed:true',
    'plex:email': 'failed:true',
    'nas:email': 'failed:true',
  });
  // Email switched off: a retried email would only be skipped when sent.
  s.config.value.email.enabled = false;
  assert.equal((await listed())['plex:email'], 'failed:false');
  await assert.rejects(s.alerting.retry(uid(plex, 'email')), {
    status: 409,
    code: 'channel_not_set_up',
    message:
      'Email alerts are switched off, so Uptime Goblin cannot send this notification: switch them on under Configure → Email.',
  });
  s.config.value.email = { ...emailOn, password: '' };
  await assert.rejects(s.alerting.retry(uid(plex, 'email')), {
    status: 409,
    code: 'channel_not_set_up',
    message:
      'Email is not set up, so Uptime Goblin cannot send this notification: complete the email settings under Configure → Email.',
  });
  s.config.value.email = { ...emailOn };
  await s.alerting.stop({ timeoutMs: 0 });

  // A restart without GOBLIN_WEBHOOK_URL: the webhook is not set up, and its rows stay as they
  // were rather than being "sent again" only to be skipped.
  const again = await service(t, {
    webhook: '',
    mail,
    clock: s.clock,
    keyring: s.keyring,
    hist: s.hist,
    control: s.control,
    settings: s.settings,
    configOptions: { email: emailOn },
  });
  await again.alerting.refresh();
  assert.equal(channelOf(again.alerting, 'env-webhook').state, 'not-configured');
  const rows = (await again.alerting.deliveries({ channel: 'env-webhook' })).deliveries;
  assert.deepEqual(
    rows.map(item => [item.alert.service, item.status, item.retryable]),
    [
      ['nas', 'failed', false],
      ['plex', 'retrying', false],
    ]
  );
  for (const event of [plex, nas])
    await assert.rejects(again.alerting.retry(uid(event, 'env-webhook')), {
      status: 409,
      code: 'channel_not_set_up',
      message:
        'Webhook is not set up, so Uptime Goblin cannot send this notification: set GOBLIN_WEBHOOK_URL on the Uptime Goblin server and restart Uptime Goblin.',
    });
  const after = (await again.alerting.deliveries({ channel: 'env-webhook' })).deliveries;
  assert.deepEqual(
    after.map(item => [item.status, item.attempts]),
    rows.map(item => [item.status, item.attempts]),
    'nothing was requeued'
  );
  // Email is set up again: its failed rows can be retried.
  assert.equal((await again.alerting.retry(uid(plex, 'email'))).retried, 2);
  assert.deepEqual(
    again.events.filter(event => event.action === 'delivery.retry').map(event => event.outcome),
    ['refused', 'refused', 'ok']
  );
});

test('alerts the backlog cap refused are in the Status per channel and in the dashboard’s attention for 24 hours (A46)', async t => {
  const hook = await receiver(t);
  const s = await service(t, { webhook: hook.url });
  const event = i => ({
    eventUid: `cap-${i}`,
    channelId: 'env-webhook',
    kind: 'firing',
    orderKey: `s${i}\n__availability`,
    event: { service: `s${i}`, name: `S${i}`, kind: 'firing', message: 'Source is unavailable' },
  });
  // 10,000 notifications wait (the cap); 3 more alerts are refused.
  const first = await s.alerting.outbox.enqueue(Array.from({ length: 10000 }, (_, i) => event(i)));
  assert.equal(first.dropped, 0);
  const at = s.clock.wall();
  const refused = await s.alerting.outbox.enqueue([10000, 10001, 10002].map(event));
  assert.equal(refused.dropped, 3);
  await s.alerting.refresh();
  const { dashboardNotifications } = await import('../../lib/alerting/view.mjs');
  const status = s.alerting.snapshot();
  assert.equal(status.notQueued, 3);
  assert.deepEqual(
    status.channels.map(c => [c.id, c.notQueued, c.notQueuedAt]),
    [
      ['email', 0, null],
      ['env-webhook', 3, at],
      ['ntfy', 0, null],
      ['gotify', 0, null],
    ]
  );
  let dashboard = dashboardNotifications(s.alerting.legacy(), status);
  assert.deepEqual(dashboard.attention.notQueued, ['env-webhook']);
  assert.deepEqual(
    dashboard.channels.map(c => [c.id, c.notQueued, c.notQueuedAt]),
    [
      ['email', 0, null],
      ['env-webhook', 3, at],
      ['ntfy', 0, null],
      ['gotify', 0, null],
    ]
  );
  // Past 24 hours the banner goes; the count since this start stays.
  await s.clock.advance(24 * hour + minute);
  await s.alerting.refresh();
  dashboard = dashboardNotifications(s.alerting.legacy(), s.alerting.snapshot());
  assert.deepEqual(dashboard.attention.notQueued, []);
  assert.equal(dashboard.channels[1].notQueued, 3);
});

test('the history: filters, newest first, cursor paging, memory rows first and unsaved', async t => {
  const hook = await receiver(t, [500]);
  const s = await service(t, { webhook: hook.url, configOptions: { email: emailOn } });
  for (const id of ['plex', 'nas', 'x']) await s.alerting.transitions(s.hist.fire(id));
  await s.deliver();
  const all = await s.alerting.deliveries({ limit: 2 });
  assert.equal(all.deliveries.length, 2);
  assert.equal(all.unsaved, 0);
  assert.match(all.nextCursor, /^[1-9][0-9]*$/);
  const next = await s.alerting.deliveries({ limit: 2, cursor: all.nextCursor });
  assert.ok(next.deliveries.every(item => item.saved));
  const ids = [...all.deliveries, ...next.deliveries].map(item => item.uid);
  assert.equal(new Set(ids).size, ids.length);
  const problems = await s.alerting.deliveries({ filter: 'problems' });
  assert.deepEqual(
    problems.deliveries.map(item => [item.channel, item.status]),
    [['env-webhook', 'retrying']]
  );
  const active = await s.alerting.deliveries({ filter: 'active', channel: 'email' });
  assert.ok(active.deliveries.every(item => item.channel === 'email' && item.status === 'waiting'));
  assert.equal(active.deliveries.length, 3);
  // Rows kept in memory (control.sqlite full) come first, unsaved.
  s.control.state.writes = true;
  await s.alerting.transitions(s.hist.fire('y'));
  const degraded = await s.alerting.deliveries({ limit: 50 });
  assert.equal(degraded.unsaved, 2);
  assert.deepEqual(
    degraded.deliveries.slice(0, 2).map(item => [item.alert.service, item.saved]),
    [
      ['y', false],
      ['y', false],
    ]
  );
  // Invalid queries. (m:<n> names a row kept in memory, A30: m:1 is a valid cursor.)
  for (const query of [
    { filter: 'nope' },
    { channel: 'slack' },
    { cursor: 'm:0' },
    { cursor: 'm:' },
    { cursor: 'm:01' },
    { cursor: 'x' },
    { limit: 0 },
    { limit: 101 },
  ])
    await assert.rejects(s.alerting.deliveries(query), { code: 'invalid_request', status: 400 });
});

test('the history pages through every row kept in memory, then the saved ones, never more than `limit` rows a page (A30)', async t => {
  const hook = await receiver(t);
  const s = await service(t, { webhook: hook.url });
  const notice = n => ({
    service: 'plex',
    name: `Flood ${n}`,
    kind: 'firing',
    category: 'threshold',
    rule: `f-${n}`,
    message: 'CPU is above 80%',
    time: s.clock.wall(),
  });
  // 30 saved rows, then 61 kept in memory (control.sqlite refuses writes). Nothing is sent.
  for (let n = 1; n <= 30; n++) await s.alerting.enqueueDirect(notice(n), `test:f-${n}`);
  s.control.state.writes = true;
  for (let n = 31; n <= 91; n++) await s.alerting.enqueueDirect(notice(n), `test:f-${n}`);
  const pagesOf = async options => {
    const pages = [];
    let cursor = null;
    for (let i = 0; i < 100; i++) {
      const page = await s.alerting.deliveries({ ...options, ...(cursor ? { cursor } : {}) });
      pages.push(page);
      cursor = page.nextCursor;
      if (!cursor) break;
    }
    return pages;
  };
  const newestFirst = Array.from({ length: 91 }, (_, i) => `Flood ${91 - i}`);
  const names = pages => pages.flatMap(page => page.deliveries.map(item => item.alert.name));
  // Pages of 50: the memory rows first, all of them, then the saved rows filling the page.
  let pages = await pagesOf({ limit: 50 });
  assert.deepEqual(
    pages.map(page => [page.deliveries.length, page.deliveries.filter(d => !d.saved).length]),
    [
      [50, 50],
      [41, 11],
    ]
  );
  assert.match(pages[0].nextCursor, /^m:[1-9][0-9]*$/);
  assert.equal(pages.at(-1).nextCursor, null);
  assert.ok(pages.every(page => page.unsaved === 61));
  assert.deepEqual(names(pages), newestFirst);
  // Pages of 5: never more than 5 rows; memory cursors, then row ids; every row once.
  pages = await pagesOf({ limit: 5 });
  assert.ok(pages.every(page => page.deliveries.length <= 5));
  assert.equal(pages.length, 19);
  assert.match(pages[11].nextCursor, /^m:/);
  assert.match(pages[12].nextCursor, /^[1-9][0-9]*$/);
  assert.deepEqual(names(pages), newestFirst);
  // Memory rows that end exactly at a page's end: the next page is the saved rows.
  pages = await pagesOf({ limit: 61 });
  assert.deepEqual(
    pages.map(page => page.deliveries.length),
    [61, 30]
  );
  assert.deepEqual(names(pages), newestFirst);
  // A filter none of them matches: an empty page without a cursor, `unsaved` still all of them.
  const delivered = await s.alerting.deliveries({ filter: 'delivered' });
  assert.deepEqual(
    [delivered.deliveries.length, delivered.nextCursor, delivered.unsaved],
    [0, null, 61]
  );
  // Only memory rows and nothing saved after them: no cursor once they end.
  const memoryOnly = await pagesOf({ limit: 50, channel: 'env-webhook', filter: 'active' });
  assert.deepEqual(names(memoryOnly), newestFirst);
});

test('an email waiting for its digest says when the digest goes, by the outbox rule, never its creation time (A31)', async t => {
  // emailBatchMs is 1000 here: a digest goes once its newest row is 1 s old, or its oldest 3 s.
  const s = await service(t, { configOptions: { email: emailOn } });
  const waiting = async () =>
    (await s.alerting.deliveries({ channel: 'email' })).deliveries
      .filter(item => item.status === 'waiting')
      .map(item => [item.alert.service, item.createdAt, item.nextAttemptAt]);
  // Each alert stamped now (a row is created at its event's time).
  const start = s.clock.wall();
  await s.alerting.transitions(s.hist.fire('plex', s.clock.wall()));
  await s.clock.advance(400);
  await s.alerting.transitions(s.hist.fire('nas', s.clock.wall()));
  // Both go 1 s after the newest: start + 1400, after now (start + 400).
  assert.deepEqual(await waiting(), [
    ['nas', start + 400, start + 1400],
    ['plex', start, start + 1400],
  ]);
  // Alerts that keep coming: at most 3 s after the oldest.
  await s.clock.advance(1500);
  await s.alerting.transitions(s.hist.fire('x', s.clock.wall()));
  await s.clock.advance(900);
  await s.alerting.transitions(s.hist.fire('y', s.clock.wall()));
  const now = s.clock.wall();
  assert.equal(now, start + 2800);
  assert.deepEqual(
    (await waiting()).map(([service, , next]) => [service, next]),
    [
      ['y', start + 3000],
      ['x', start + 3000],
      ['nas', start + 3000],
      ['plex', start + 3000],
    ]
  );
  // Due: it goes at the next pass, so now; then it is sent, as one email.
  await s.clock.advance(200);
  assert.ok((await waiting()).every(([, , next]) => next === s.clock.wall()));
  await s.deliver();
  assert.equal(s.mail.sent.length, 1);
  assert.deepEqual(await waiting(), []);
});

test('not being saved: the status says so, probe() ends it within 10 s of space returning', async t => {
  const hook = await receiver(t);
  const s = await service(t, { webhook: hook.url });
  s.control.state.writes = true;
  await s.alerting.transitions(s.hist.fire('plex'));
  await s.deliver();
  assert.equal(hook.got.length, 1, 'delivered from memory');
  await s.alerting.refresh();
  let status = s.alerting.snapshot();
  assert.equal(status.saving, false);
  assert.equal(status.unsavedSince, s.clock.wall());
  assert.match(status.unsavedReason, /cannot write its control database/);
  assert.equal(s.alerting.legacy().configured, true);
  s.control.state.writes = false;
  // Within 10 s of the last probe: not tried yet.
  await s.alerting.refresh();
  assert.equal(s.alerting.snapshot().saving, false);
  await s.clock.advance(10000);
  await s.alerting.refresh();
  status = s.alerting.snapshot();
  assert.deepEqual([status.saving, status.unsavedSince], [true, null]);
  assert.ok(s.events.some(event => event.action === 'notifications.unsaved'));
  assert.ok(s.events.some(event => event.action === 'notifications.saved'));
});

test('refresh() after completions runs at most once a second', async t => {
  const hook = await receiver(t);
  const s = await service(t, { webhook: hook.url });
  let reads = 0;
  const summary = s.control.store.summary;
  s.control.store.summary = async (...args) => {
    reads++;
    return summary(...args);
  };
  for (const id of ['plex', 'nas', 'x', 'y']) await s.alerting.transitions(s.hist.fire(id));
  await s.deliver();
  await s.clock.advance(999);
  const early = reads;
  await s.clock.advance(1000);
  assert.ok(reads - early <= 1, `${reads - early} reads`);
  assert.ok(reads <= 3, `${reads} reads for 8 changes`);
  assert.equal(s.alerting.snapshot().channels[1].deliveredTotal, 4);
});

test('an invalid GOBLIN_WEBHOOK_URL or a refused IP literal pauses the webhook at start', async t => {
  for (const [webhook, reason] of [
    ['http://169.254.169.254/latest', /link-local, multicast or reserved/],
    ['http://[64:ff9b::a9fe:a9fe]/', /link-local, multicast or reserved/],
    // The whole text: safeReason() turned "or https://." into "or [url]" (docs audit 1.5).
    ['ftp://example.test/hook', /^GOBLIN_WEBHOOK_URL must be an http: or https: address\.$/],
  ]) {
    const s = await service(t, { webhook });
    await s.alerting.refresh();
    const channel = channelOf(s.alerting, 'env-webhook');
    assert.equal(channel.state, 'paused', webhook);
    assert.match(channel.pausedReason, reason);
    assert.equal(channel.nextAttemptAt, null);
    assert.match(s.logger.lines.warn.join('\n'), /GOBLIN_WEBHOOK_URL cannot be used/);
    assert.ok(!s.logger.lines.warn.join('\n').includes('latest'), 'the URL is never logged');
  }
});

test('GOBLIN_WEBHOOK_URL: plain http: to another computer is said at start (never its token); an overlong URL pauses the webhook', async t => {
  const token = 'SYNTHETIC-WEBHOOK-TOKEN';
  for (const [webhook, warned] of [
    [`http://192.0.2.10/hook?token=${token}`, '192.0.2.10'],
    [`http://chat.example/hooks/${token}`, 'chat.example'],
    [`http://[2001:db8::7]/hook/${token}`, '2001:db8::7'],
    [`https://chat.example/hooks/${token}`, null],
    [`http://127.0.0.1:9/hook/${token}`, null],
    [`http://localhost:9/hook/${token}`, null],
    [`http://[::1]:9/hook/${token}`, null],
  ]) {
    const s = await service(t, { webhook });
    const warnings = s.logger.lines.warn.join('\n');
    assert.ok(!warnings.includes(token), 'the URL is never logged');
    if (warned)
      assert.ok(
        warnings.includes(
          `GOBLIN_WEBHOOK_URL uses plain HTTP to ${warned}: the address (with any token in it), each notification and its signature cross the network unencrypted. Use an https:// address.`
        ),
        `${webhook}: ${warnings}`
      );
    else assert.doesNotMatch(warnings, /plain HTTP/, webhook);
  }
  const s = await service(t, { webhook: `https://chat.example/${'a'.repeat(2048)}` });
  await s.alerting.refresh();
  const channel = channelOf(s.alerting, 'env-webhook');
  assert.equal(channel.state, 'paused');
  assert.equal(channel.pausedReason, 'GOBLIN_WEBHOOK_URL is longer than 2048 characters.');
});

test('stop() cancels the jobs, then stops the outbox; nothing is registered before start()', async t => {
  const s = await service(t, { start: false });
  assert.deepEqual([...s.jobs.registered.keys()], []);
  s.alerting.start();
  await settle();
  assert.deepEqual([...s.jobs.registered.keys()].sort(), [
    'notify.delivery',
    'notify.prune',
    'notify.relay',
  ]);
  assert.equal(s.jobs.registered.get('notify.relay').intervalMs, 10000);
  assert.equal(s.jobs.registered.get('notify.prune').intervalMs, hour);
  assert.deepEqual(await s.alerting.stop({ timeoutMs: 0 }), { cancelled: 0, unsettled: 0 });
  assert.deepEqual([...s.jobs.registered.keys()], []);
});

test('the audit hook and the log never carry a secret, a URL or a key', async t => {
  const canary = 'canary-url-token-5521';
  const hook = await receiver(t, [401]);
  const s = await service(t, {
    webhook: `${hook.url}?token=${canary}`,
    configOptions: { email: emailOn },
  });
  await s.alerting.transitions(s.hist.fire('plex'));
  await s.deliver();
  const before = (await s.settings.settings.get('notify', 'envWebhook')).value.signingKey;
  await s.alerting.signing.publicKeys();
  await s.alerting.signing.rotate({ actor: { login: 'dana' } });
  const after = (await s.settings.settings.get('notify', 'envWebhook')).value.signingKey;
  await s.alerting.resume('env-webhook', { actor: { login: 'dana' } });
  await s.alerting.refresh();
  const everything = JSON.stringify({
    events: s.events,
    log: s.logger.lines,
    snapshot: s.alerting.snapshot(),
    legacy: s.alerting.legacy(),
    deliveries: await s.alerting.deliveries({}),
    rows: await rowsOf(s.control.inner),
  });
  // The private keys, as PEM, as the PEM's body and as the raw seed (base64url, base64, hex).
  const privateForms = [before, after].flatMap(key => {
    const seed = createPrivateKey(key).export({ format: 'jwk' }).d;
    return [
      key,
      key.split('\n')[1],
      seed,
      Buffer.from(seed, 'base64url').toString('base64'),
      Buffer.from(seed, 'base64url').toString('hex'),
    ];
  });
  for (const value of [
    canary,
    ...privateForms,
    emailOn.password,
    s.keyring.describe?.()?.kid ?? 'no-kid',
  ])
    if (value !== 'no-kid') assert.ok(!everything.includes(value), value);
  assert.ok(s.events.some(event => event.action === 'signing.rotate' && event.actor === 'dana'));
});

test('over the real control database: delivered, saved, and listed after a restart', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-service-control-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const clock = fakeClock();
  const keyring = await makeKeyring();
  const open = async () => {
    const control = openControl(directory, {
      env: {},
      clock: () => clock.wall(),
      settingsDefinitions: [notifySettings],
      keyring,
    });
    await control.migrate();
    return control;
  };
  const hook = await receiver(t, [500]);
  const hist = history(t);
  const control = await open();
  const jobs = manualJobs();
  const alerting = await createAlerting({
    control,
    keyring,
    history: hist.store,
    config: config(),
    jobs,
    webhook: hook.url,
    clock,
    rng: () => 1,
    logger: quietLogger(),
  });
  alerting.start();
  await settle();
  await alerting.transitions(hist.fire('plex'));
  await alerting.outbox.pump();
  for (let w = 0; alerting.outbox.inFlight && w < 1000; w++) await sleep(5);
  await alerting.stop({ timeoutMs: 0 });
  control.close();
  // A new process on the same files: the retrying row is sent, signed with the saved key.
  const reopened = await open();
  t.after(() => reopened.close());
  const again = await createAlerting({
    control: reopened,
    keyring,
    history: hist.store,
    config: config(),
    jobs: manualJobs(),
    webhook: hook.url,
    clock,
    rng: () => 1,
    logger: quietLogger(),
  });
  again.start();
  await settle();
  await clock.advance(31000);
  await again.outbox.pump();
  for (let w = 0; again.outbox.inFlight && w < 1000; w++) await sleep(5);
  assert.deepEqual(hook.kinds(), ['plex:firing', 'plex:firing']);
  assert.equal(hook.got[0].headers['x-goblin-delivery'], hook.got[1].headers['x-goblin-delivery']);
  const listed = await again.deliveries({});
  assert.deepEqual(
    listed.deliveries.map(item => [item.status, item.attempts, item.saved]),
    [['delivered', 2, true]]
  );
  await again.stop({ timeoutMs: 0 });
});

// Amendment A40: the disk and history notices pair a firing with its recovery under one since,
// and control.sqlite's meta keeps the open episode across a stop. Before, the episode lived in
// memory only: space freed while Uptime Goblin was stopped never sent the recovery (a receiver keyed by
// service and rule showed the disk full for good), a firing still retrying at the stop was sent
// after the start with nothing behind it, and a start on a disk still full began a second one.
test('the disk and history notices outlive a stop: one recovery once space was freed, no second episode while still full, a waiting firing followed by its recovery (A40)', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-service-episodes-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const clock = fakeClock();
  const keyring = await makeKeyring();
  const hist = history(t);
  const hook = await receiver(t);
  const failing = { set: false };
  // One process of the service on control.sqlite; meta.set fails while `failing.set` holds.
  const run = async () => {
    const control = openControl(directory, {
      env: {},
      clock: () => clock.wall(),
      settingsDefinitions: [notifySettings],
      keyring,
    });
    await control.migrate();
    const meta = {
      ...control.meta,
      async set(...args) {
        if (failing.set) throw full();
        return control.meta.set(...args);
      },
    };
    const jobs = manualJobs();
    const alerting = await createAlerting({
      control: { settings: control.settings, db: control.db, meta },
      keyring,
      history: hist.store,
      config: config(),
      jobs,
      webhook: hook.url,
      clock,
      rng: () => 1,
      logger: quietLogger(),
    });
    alerting.start();
    await settle();
    let stopped = false;
    const stop = async () => {
      if (stopped) return;
      stopped = true;
      await alerting.stop({ timeoutMs: 0 });
      control.close();
    };
    t.after(stop);
    const send = async () => {
      await alerting.flush({ timeoutMs: 5000 });
      await alerting.flush({ timeoutMs: 5000 });
    };
    return { alerting, control, jobs, stop, send };
  };
  // [kind, rule, the delivery id names this since] of each request, from `from` on.
  const got = (from = 0) =>
    hook.got.slice(from).map(item => {
      const body = JSON.parse(item.body);
      return [body.kind, body.rule, item.headers['x-goblin-delivery']];
    });
  const id = (name, since, kind) => deliveryUid(`sys:${name}:${since}:${kind}`, 'env-webhook');

  // The disk fills, the notice goes out, Uptime Goblin stops; space is freed while it is stopped.
  let p = await run();
  const t1 = clock.wall();
  p.alerting.diskChanged({ full: true, since: t1 });
  await p.send();
  assert.deepEqual(got(), [['firing', '__disk', id('disk', t1, 'firing')]]);
  await p.stop();
  // The next start, on a disk with space (server.mjs tells the guard's state once it started).
  p = await run();
  p.alerting.diskChanged({ full: false, since: null });
  await p.send();
  assert.deepEqual(got(1), [['resolved', '__disk', id('disk', t1, 'resolved')]]);
  await p.stop();
  // And once only: the start after that has nothing open.
  p = await run();
  p.alerting.diskChanged({ full: false, since: null });
  await p.send();
  assert.equal(hook.got.length, 2);

  // A start on a disk still full keeps the episode: no second firing, and its own recovery.
  await clock.advance(minute);
  const t2 = clock.wall();
  p.alerting.diskChanged({ full: true, since: t2 });
  await p.send();
  await p.stop();
  await clock.advance(minute);
  p = await run();
  p.alerting.diskChanged({ full: true, since: clock.wall() });
  await p.send();
  assert.deepEqual(got(2), [['firing', '__disk', id('disk', t2, 'firing')]], 'no second firing');
  p.alerting.diskChanged({ full: false, since: null });
  await p.send();
  assert.deepEqual(got(3), [['resolved', '__disk', id('disk', t2, 'resolved')]]);
  await p.stop();

  // A firing still retrying at the stop (the receiver answered 500) is followed by its recovery.
  hook.answers.push(500);
  await clock.advance(minute);
  p = await run();
  const t3 = clock.wall();
  p.alerting.diskChanged({ full: true, since: t3 });
  await p.send();
  assert.equal(hook.got.length, 5, 'one attempt, answered 500');
  await p.stop();
  p = await run();
  p.alerting.diskChanged({ full: false, since: null });
  await clock.advance(31000);
  await p.send();
  assert.deepEqual(got(5), [
    ['firing', '__disk', id('disk', t3, 'firing')],
    ['resolved', '__disk', id('disk', t3, 'resolved')],
  ]);

  // A recovery queued whose end could not be written (a stop, or a write refused): the next
  // start finds its rows and treats the episode as ended, so a full disk then is a new episode.
  await clock.advance(minute);
  const t4 = clock.wall();
  p.alerting.diskChanged({ full: true, since: t4 });
  await p.send();
  failing.set = true;
  p.alerting.diskChanged({ full: false, since: null });
  await p.send();
  failing.set = false;
  assert.equal(await p.control.meta.get('notice_disk_since'), String(t4), 'the end not written');
  await p.stop();
  await clock.advance(minute);
  p = await run();
  const t5 = clock.wall();
  p.alerting.diskChanged({ full: true, since: t5 });
  await p.send();
  assert.deepEqual(got(7), [
    ['firing', '__disk', id('disk', t4, 'firing')],
    ['resolved', '__disk', id('disk', t4, 'resolved')],
    ['firing', '__disk', id('disk', t5, 'firing')],
  ]);
  // A since whose write failed is written by the next notify.relay run.
  p.alerting.diskChanged({ full: false, since: null });
  await p.send();
  await clock.advance(minute);
  failing.set = true;
  const t6 = clock.wall();
  p.alerting.diskChanged({ full: true, since: t6 });
  await p.send();
  assert.equal(await p.control.meta.get('notice_disk_since'), '');
  failing.set = false;
  await p.jobs.run('notify.relay');
  await settle();
  assert.equal(await p.control.meta.get('notice_disk_since'), String(t6));
  await p.stop();

  // The history notice: an outage announced before a stop is carried into the next run, which
  // ends it with the same since (server.mjs decides when writes work again).
  p = await run();
  assert.equal(p.alerting.storageCarried(), null);
  const s1 = clock.wall();
  p.alerting.storageChanged({ failing: true, since: s1 });
  await p.send();
  await p.stop();
  p = await run();
  assert.equal(p.alerting.storageCarried(), s1);
  const before = hook.got.length;
  p.alerting.storageChanged({ failing: false });
  assert.equal(p.alerting.storageCarried(), null, 'reported once this run');
  await p.send();
  assert.deepEqual(got(before), [['resolved', '__storage', id('storage', s1, 'resolved')]]);
  assert.equal(
    JSON.parse(hook.got.at(-1).body).message,
    'Uptime Goblin can write its history database again.'
  );
});

test('every answer has exactly the shape of test/contract/notifications-bodies.json', async t => {
  const bodies = JSON.parse(
    fs.readFileSync(new URL('../contract/notifications-bodies.json', import.meta.url), 'utf8')
  );
  const keys = value => Object.keys(value).sort();
  const hook = await receiver(t, [422, 401]);
  const s = await service(t, { webhook: hook.url, configOptions: { email: emailOn } });
  const firing = s.hist.fire('plex');
  await s.alerting.transitions(firing);
  await s.deliver();
  await s.alerting.refresh();
  const status = s.alerting.snapshot();
  assert.deepEqual(keys(status), keys(bodies.answers.status));
  for (const [index, channel] of status.channels.entries())
    assert.deepEqual(keys(channel), keys(bodies.answers.status.channels[index]), channel.id);
  assert.deepEqual(keys(status.signing), keys(bodies.answers.status.signing));
  const page = await s.alerting.deliveries({});
  assert.deepEqual(keys(page), keys(bodies.answers.deliveries));
  for (const item of page.deliveries)
    assert.deepEqual(keys(item), keys(bodies.answers.deliveries.deliveries[0]));
  const retried = await s.alerting.retry(deliveryUid(firing[0].uid, 'env-webhook'));
  assert.deepEqual(keys(retried), keys(bodies.answers.retry));
  assert.deepEqual(keys(retried.delivery), keys(bodies.answers.retry.delivery));
  await s.deliver();
  const resumed = await s.alerting.resume('env-webhook');
  assert.deepEqual(keys(resumed), keys(bodies.answers.resume));
  assert.deepEqual(keys(resumed.channel), keys(bodies.answers.resume.channel));
  assert.deepEqual(keys(await s.alerting.signing.publicKeys()), keys(bodies.answers.publicKey));
  assert.deepEqual(keys(await s.alerting.signing.rotate()), keys(bodies.answers.rotate));
  assert.deepEqual(
    keys((await s.alerting.signing.publicKeys()).previous),
    keys(bodies.answers.publicKey.previous)
  );
  const { dashboardNotifications } = await import('../../lib/alerting/view.mjs');
  const dashboard = dashboardNotifications(s.alerting.legacy(), s.alerting.snapshot());
  const expected = bodies.answers.dashboard.notifications;
  assert.deepEqual(keys(dashboard), keys(expected));
  assert.deepEqual(keys(dashboard.email), keys(expected.email));
  assert.deepEqual(keys(dashboard.attention), keys(expected.attention));
  assert.deepEqual(keys(dashboard.channels[0]), keys(expected.channels[0]));
});

// D24 and A45: Retry must not say a notification is being sent again when the send-time recheck
// would only skip it. A failed notification whose source was deleted, or whose kind of alert was
// switched off since, is neither offered Retry nor requeued by one.
test('Retry is neither offered nor taken for a notification the send-time recheck would skip: its source deleted, its alerts switched off', async t => {
  const hook = await receiver(t, [400, 400]);
  const s = await service(t, { webhook: hook.url });
  const plex = s.hist.fire('plex'),
    nas = s.hist.fire('nas');
  await s.alerting.transitions(plex);
  await s.deliver();
  await s.alerting.transitions(nas);
  await s.deliver();
  const uid = event => deliveryUid(event[0].uid, 'env-webhook');
  const listed = async event =>
    (await s.alerting.deliveries({})).deliveries.find(item => item.uid === uid(event));
  for (const event of [plex, nas])
    assert.deepEqual(
      [(await listed(event)).status, (await listed(event)).retryable],
      ['failed', true]
    );
  // plex is deleted, as DELETE /api/services/:id does it (its failed row is left as it is).
  s.config.value.services = s.config.value.services.filter(source => source.id !== 'plex');
  await s.alerting.forgetSource('plex');
  assert.equal((await listed(plex)).retryable, false);
  await assert.rejects(s.alerting.retry(uid(plex), { actor: { login: 'dana' } }), {
    status: 409,
    code: 'delivery_not_retryable',
    message: 'The source of this notification was deleted, so Uptime Goblin does not send it.',
  });
  // Connection alerts switched off: nas's failed firing would be skipped as well.
  s.config.value.alerts.notifyAvailability = false;
  assert.equal((await listed(nas)).retryable, false);
  await assert.rejects(s.alerting.retry(uid(nas)), {
    status: 409,
    code: 'delivery_not_retryable',
    message:
      'Alerts of this kind are switched off, so Uptime Goblin does not send this notification.',
  });
  // Neither was requeued, nor sent again.
  await s.deliver();
  assert.equal(hook.got.length, 2);
  assert.deepEqual([(await listed(plex)).status, (await listed(nas)).status], ['failed', 'failed']);
  assert.deepEqual(
    s.events
      .filter(event => event.action === 'delivery.retry')
      .map(event => [event.outcome, event.detail]),
    [
      ['refused', { reason: 'not_sent' }],
      ['refused', { reason: 'not_sent' }],
    ]
  );
  // Switched on again, nas is offered Retry and sent.
  s.config.value.alerts.notifyAvailability = true;
  assert.equal((await listed(nas)).retryable, true);
  assert.equal((await s.alerting.retry(uid(nas))).retried, 1);
  await s.deliver();
  assert.equal(hook.got.length, 3);
});

// An email digest is sent, and retried, as one email: Retry refuses the whole of it when one of
// its notifications would be skipped. The history then offers Retry for none of them, and the
// refusal of the other one says why (its own source still exists).
test('a failed email digest with one source deleted offers Retry for neither notification, and says why', async t => {
  const recipientRefused = () =>
    Promise.reject(
      Object.assign(new Error('550 5.1.1 Recipient refused'), {
        code: 'EENVELOPE',
        command: 'RCPT TO',
        responseCode: 550,
      })
    );
  const mail = mailer([recipientRefused]);
  const s = await service(t, { mail, configOptions: { email: emailOn } });
  const plex = s.hist.fire('plex'),
    nas = s.hist.fire('nas');
  await s.alerting.transitions(plex);
  await s.deliver();
  await s.alerting.transitions(nas);
  await s.deliver();
  await s.clock.advance(3000);
  await s.deliver();
  assert.equal(mail.sent.length, 1, 'one digest of both, refused');
  const uid = event => deliveryUid(event[0].uid, 'email');
  const listed = async () =>
    Object.fromEntries(
      (await s.alerting.deliveries({})).deliveries
        .filter(item => item.channel === 'email')
        .map(item => [item.alert.service, [item.status, item.retryable]])
    );
  assert.deepEqual(await listed(), { plex: ['failed', true], nas: ['failed', true] });
  // plex is deleted, as DELETE /api/services/:id does it.
  s.config.value.services = s.config.value.services.filter(source => source.id !== 'plex');
  await s.alerting.forgetSource('plex');
  // Retry was still offered for nas, and refused, blaming nas's source, which exists.
  assert.deepEqual(await listed(), { plex: ['failed', false], nas: ['failed', false] });
  await assert.rejects(s.alerting.retry(uid(nas), { actor: { login: 'dana' } }), {
    status: 409,
    code: 'delivery_not_retryable',
    message:
      'This notification was sent in one email with another whose source was deleted, so Uptime Goblin does not send that email again.',
  });
  await assert.rejects(s.alerting.retry(uid(plex), { actor: { login: 'dana' } }), {
    status: 409,
    message: 'The source of this notification was deleted, so Uptime Goblin does not send it.',
  });
  // A reason of the notification's own comes first: its alerts switched off as well.
  s.config.value.alerts.notifyAvailability = false;
  await assert.rejects(s.alerting.retry(uid(nas), { actor: { login: 'dana' } }), {
    status: 409,
    message:
      'Alerts of this kind are switched off, so Uptime Goblin does not send this notification.',
  });
  await s.clock.advance(3000);
  await s.deliver();
  assert.equal(mail.sent.length, 1, 'nothing was sent again');
});

// The other refusals Retry gives a digest member for another notification of its email name
// that one too: the member's own alert may have no later notification, and the member may well
// be waiting to retry.
test('a digest member refused for another notification of its email says so: a later notification of the other alert, the other one cancelled', async t => {
  const uid = event => deliveryUid(event[0].uid, 'email');
  const listed = async s =>
    (await s.alerting.deliveries({})).deliveries
      .filter(item => item.channel === 'email')
      .map(item => [item.alert.service, item.kind, item.status, item.retryable]);
  const refused = (s, event) => s.alerting.retry(uid(event), { actor: { login: 'dana' } });
  // 1. plex recovers after the failed digest of plex and nas, and its recovery is delivered: a
  // resend of the digest would bring plex's firing after it. nas has no later notification.
  const recipientRefused = () =>
    Promise.reject(
      Object.assign(new Error('550 5.1.1 Recipient refused'), {
        code: 'EENVELOPE',
        command: 'RCPT TO',
        responseCode: 550,
      })
    );
  const mail = mailer([recipientRefused]);
  const s = await service(t, { mail, configOptions: { email: emailOn } });
  const plex = s.hist.fire('plex'),
    nas = s.hist.fire('nas');
  await s.alerting.transitions(plex);
  await s.deliver();
  await s.alerting.transitions(nas);
  await s.deliver();
  await s.clock.advance(3000);
  await s.deliver();
  await s.alerting.transitions(s.hist.recover('plex'));
  await s.deliver();
  await s.clock.advance(3000);
  await s.deliver();
  assert.equal(mail.sent.length, 2, 'the digest, refused, then the recovery, accepted');
  assert.deepEqual(await listed(s), [
    ['plex', 'resolved', 'delivered', false],
    ['nas', 'firing', 'failed', false],
    ['plex', 'firing', 'failed', false],
  ]);
  await assert.rejects(refused(s, nas), {
    status: 409,
    code: 'delivery_outdated',
    message:
      'This notification was sent in one email with another whose alert already had a later notification delivered or being sent on this channel, so sending that email again would arrive out of order.',
  });
  await assert.rejects(refused(s, plex), {
    status: 409,
    code: 'delivery_outdated',
    message:
      'A later notification for the same alert was already delivered or is being sent on this channel, so sending this one now would arrive out of order.',
  });

  // 2. A digest waiting to retry (the server asked to try later), whose plex notification was
  // cancelled when plex was deleted: nas waits to retry, but Retry would requeue the email as a
  // whole, the cancelled one included.
  const tryLater = () =>
    Promise.reject(Object.assign(new Error('421 Try again later'), { responseCode: 421 }));
  const later = mailer([tryLater]);
  const r = await service(t, { mail: later, configOptions: { email: emailOn } });
  const plex2 = r.hist.fire('plex'),
    nas2 = r.hist.fire('nas');
  await r.alerting.transitions(plex2);
  await r.deliver();
  await r.alerting.transitions(nas2);
  await r.deliver();
  await r.clock.advance(3000);
  await r.deliver();
  assert.equal(later.sent.length, 1, 'one digest of both, to be tried later');
  r.config.value.services = r.config.value.services.filter(source => source.id !== 'plex');
  await r.alerting.forgetSource('plex');
  const states = Object.fromEntries(
    (await listed(r)).map(([service, , status, retryable]) => [service, [status, retryable]])
  );
  assert.equal(states.nas[0], 'retrying');
  assert.notEqual(states.plex[0], 'retrying', 'plex was cancelled');
  assert.equal(states.nas[1], false, 'Retry is not offered for nas');
  await assert.rejects(refused(r, nas2), {
    status: 409,
    code: 'delivery_not_retryable',
    message:
      'This notification was sent in one email with another that cannot be retried now, so Retry cannot send that email again.',
  });
  await assert.rejects(refused(r, plex2), {
    status: 409,
    code: 'delivery_not_retryable',
    message: 'Only failed notifications and notifications waiting to retry can be retried.',
  });
});

// Delivery spec A62 starts once Retry or Resume has acted. Before that, the route's re-check of
// its session (`check`) runs right before the requeue and the release, after every read: a
// session that ended during the reads changes nothing, and its error is passed on as it is.
test('Retry and Resume run the route’s session check right before they act: one that ended during their reads changes nothing', async t => {
  const hook = await receiver(t, [400, 401]);
  const s = await service(t, { webhook: hook.url });
  const plex = s.hist.fire('plex');
  await s.alerting.transitions(plex);
  await s.deliver();
  const uid = deliveryUid(plex[0].uid, 'env-webhook');
  const ended = Object.assign(new Error('The session ended.'), { code: 'session_expired' });
  let signedIn = true;
  const check = () => {
    if (!signedIn) throw ended;
  };
  // The next call of the control store's `name` waits; the session ends meanwhile.
  const endDuring = name => {
    const original = s.control.store[name];
    let release;
    const held = new Promise(resolve => (release = resolve));
    s.control.store[name] = async (...args) => {
      s.control.store[name] = original;
      await held;
      return original(...args);
    };
    return () => {
      signedIn = false;
      release();
    };
  };
  const row = async () => (await rowsOf(s.control.inner)).find(item => item.uid === uid);

  // Retry: the row is read, the session ends, nothing is requeued.
  let end = endDuring('find');
  const retrying = s.alerting.retry(uid, { actor: 'dana', check });
  end();
  await assert.rejects(retrying, error => error === ended);
  assert.equal((await row()).state, 'dead');
  await s.deliver();
  assert.equal(hook.got.length, 1, 'not sent again');
  assert.equal(
    s.events.some(event => event.action === 'delivery.retry' && event.outcome === 'ok'),
    false
  );

  // Resume: the next alert pauses the webhook (401); its session ends while the channel is
  // read, and the channel stays paused with its notification held.
  signedIn = true;
  await s.alerting.transitions(s.hist.fire('nas'));
  await s.deliver();
  await s.alerting.refresh();
  assert.equal(channelOf(s.alerting, 'env-webhook').state, 'paused');
  const held = async () =>
    (await rowsOf(s.control.inner)).filter(item => item.state === 'held').length;
  const heldBefore = await held();
  assert.ok(heldBefore >= 1, 'the paused webhook holds the notification');
  end = endDuring('channel');
  const resuming = s.alerting.resume('env-webhook', { actor: 'dana', check });
  end();
  await assert.rejects(resuming, error => error === ended);
  await s.alerting.refresh();
  assert.equal(channelOf(s.alerting, 'env-webhook').state, 'paused');
  assert.equal(await held(), heldBefore);
  assert.equal(
    s.events.some(event => event.action === 'channel.resume'),
    false
  );

  // Signed in, both act.
  signedIn = true;
  assert.equal((await s.alerting.resume('env-webhook', { check })).released, heldBefore);
  await s.deliver();
  assert.equal((await s.alerting.retry(uid, { check })).retried, 1);
});

test('security F02/F06: newer unheld current authority continues through a refused rotation', async t => {
  const hook = await receiver(t),
    clock = fakeClock(),
    keyring = await makeKeyring();
  const settings = settingsService(keyring, clock),
    key = generateSigningKey();
  await newerBuildDoc(settings, keyring, clock, {
    signingKey: key,
    createdAt: clock.wall(),
    heldSince: null,
  });
  const s = await service(t, { webhook: hook.url, clock, keyring, settings });
  await s.alerting.transitions(s.hist.fire('plex'));
  await s.deliver();
  assert.deepEqual(hook.kinds(), ['plex:firing']);
  const before = await settings.settings.get('notify', 'envWebhook');
  await assert.rejects(s.alerting.signing.rotate({ actor: 'admin' }), {
    code: 'signing_compatibility',
    status: 409,
  });
  assert.deepEqual(await settings.settings.get('notify', 'envWebhook'), before);
  await s.alerting.transitions(s.hist.recover('plex'));
  await s.deliver();
  assert.deepEqual(hook.kinds(), ['plex:firing', 'plex:resolved']);
  for (const request of hook.got)
    assert.equal(
      verifyWebhookSignature(
        publicSigningKey(key).publicKey,
        request.body,
        request.headers['x-goblin-signature'],
        { deliveryId: request.headers['x-goblin-delivery'], nowMs: clock.wall() }
      ).ok,
      true
    );
});

test('security D04: service Resume cannot clear a pause installed after its observation', async t => {
  const hook = await receiver(t),
    s = await service(t, { webhook: hook.url });
  await s.alerting.outbox.pause('env-webhook', 'Initial receiver refusal');
  await s.alerting.transitions(s.hist.fire('plex'));
  const heldBefore = (await rowsOf(s.control.inner)).filter(row => row.state === 'held').length;
  assert.ok(heldBefore > 0);
  const read = s.control.store.channel;
  let observed, release;
  const seen = new Promise(resolve => {
    observed = resolve;
  });
  const barrier = new Promise(resolve => {
    release = resolve;
  });
  s.control.store.channel = async (...args) => {
    s.control.store.channel = read;
    const status = await read(...args);
    observed();
    await barrier;
    return status;
  };
  const resuming = s.alerting.resume('env-webhook', { actor: 'dana' });
  await seen;
  await s.alerting.outbox.pause('env-webhook', 'New receiver credentials required');
  release();
  assert.equal((await resuming).released, 0);
  assert.equal(
    (await s.control.inner.channel('env-webhook')).pausedReason,
    'New receiver credentials required'
  );
  assert.equal(
    (await rowsOf(s.control.inner)).filter(row => row.state === 'held').length,
    heldBefore
  );
  assert.equal(
    s.events.some(event => event.action === 'channel.resume'),
    false
  );
  assert.equal(hook.got.length, 0);
});

test(
  'security R2-01: signing-pause installation rechecks a newer pause and the current hold',
  { timeout: 10000 },
  async t => {
    for (const newerPause of [true, false]) {
      await t.test(
        newerPause ? 'preserves another pause' : 'does not install an ended hold',
        async t => {
          const hook = await receiver(t),
            clock = fakeClock(),
            keyring = await makeKeyring();
          const settings = settingsService(keyring, clock);
          await prereleaseHmacDoc(settings, keyring, clock);
          settings.state.readFails = true;
          const s = await service(t, { webhook: hook.url, clock, keyring, settings });
          // Expose the startup retry's not-paused observation without permitting delivery.
          await s.alerting.outbox.resume('env-webhook');
          await s.alerting.transitions(s.hist.fire('plex'));
          settings.state.readFails = false;
          const entered = Promise.withResolvers(),
            gate = Promise.withResolvers();
          const pauseChannel = s.alerting.outbox.pause;
          s.alerting.outbox.pause = async (...args) => {
            if (args[1] === SIGNING_HOLD_REASON) {
              entered.resolve();
              await gate.promise;
            }
            return pauseChannel(...args);
          };
          t.after(() => gate.resolve());
          const retrying = s.jobs.run('notify.relay');
          await entered.promise;
          const held = await settings.settings.get('notify', 'envWebhook');
          assert.notEqual(held.value.heldSince, null);
          if (newerPause) await pauseChannel('env-webhook', 'Independent receiver refusal');
          else {
            // Another authorized settings writer ends the hold; publicKeys adopts it.
            await settings.settings.update(
              'notify',
              'envWebhook',
              { heldSince: null },
              { ifVersion: held.version }
            );
            await s.alerting.signing.publicKeys();
          }
          gate.resolve();
          await retrying;
          const status = await s.control.inner.channel('env-webhook');
          assert.deepEqual(
            [status.state, status.pausedReason],
            newerPause ? ['paused', 'Independent receiver refusal'] : ['ok', null]
          );
          const rows = (await rowsOf(s.control.inner)).filter(
            row => row.channelId === 'env-webhook'
          );
          assert.ok(rows.length > 0);
          assert.ok(rows.every(row => row.state === (newerPause ? 'held' : 'queued')));
          assert.equal(
            s.events.some(event => event.action === 'channel.resume'),
            false
          );
          assert.equal(hook.got.length, 0);
        }
      );
    }
  }
);
