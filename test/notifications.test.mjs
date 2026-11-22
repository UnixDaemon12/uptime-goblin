// Durable alert delivery through a real Uptime Goblin (createApp), delivery spec §8.1 H and §8.2: both
// built-in channels end to end (X-Goblin-Delivery, the signature, 1.4.2's body, the digest's
// Message-ID), retries and order per alert, pauses and their probes, Resume, Retry, deleted
// sources and switched-off alerts, a failing history, restart continuity, the V1 regression,
// the webhook address policy, the key out of the environment, restored data and a canary.
// The webhook receiver and the mail transport are fixtures of this file: nothing leaves
// 127.0.0.1, and SMTP host names resolve to a documentation address without DNS.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { createPrivateKey, createPublicKey, randomBytes, verify } from 'node:crypto';
import { spawn } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';
import { createApp } from '../server.mjs';
import { configureDestinations } from '../lib/destinations.mjs';
import { emailDefaults } from '../lib/catalog.mjs';
import { acquireLock } from '../lib/db/lock.mjs';
import { createSnapshot, restoreSnapshot } from '../lib/db/snapshot.mjs';
import { freePortSync } from './helpers/net.mjs';
import { platformTest } from './helpers/platform.mjs';

configureDestinations({ lookup: async () => [{ address: '192.0.2.1' }] });

const serverFile = fileURLToPath(new URL('../server.mjs', import.meta.url));
const release = JSON.parse(
  fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')
).version;
// Throwaway values for these data directories only.
const password = 'notifications-test-password';
const mailPassword = 'notifications-mail-canary-0001';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function until(condition, { timeoutMs = 15000, what = 'the condition' } = {}) {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const value = await condition();
    if (value) return value;
    if (Date.now() > end) assert.fail(`${what} was not reached within ${timeoutMs} ms`);
    await sleep(10);
  }
}

function temporary(t, prefix = 'orbit-notifications-') {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

/**
 * A webhook receiver on 127.0.0.1 recording {body, headers, receivedAt} per request.
 * `respond(request, n)` returns a status, {status, headers, afterMs}, or 'hold' (the body is
 * read, the answer waits until release()).
 */
async function receiver(t, respond = () => 200, { path: route = '/hook' } = {}) {
  const requests = [],
    held = new Set(),
    sockets = new Set();
  const server = http.createServer(async (req, res) => {
    let body = '';
    req.setEncoding('utf8');
    for await (const chunk of req) body += chunk;
    const request = { body, headers: req.headers, receivedAt: Date.now(), url: req.url };
    requests.push(request);
    const answer = await respond(request, requests.length);
    if (answer === 'hold') {
      held.add(res);
      return;
    }
    const {
      status = 200,
      headers = {},
      afterMs = 0,
    } = typeof answer === 'number' ? { status: answer } : (answer ?? {});
    if (afterMs) await sleep(afterMs);
    request.answered = status;
    if (!res.destroyed) {
      res.writeHead(status, headers);
      res.end();
    }
  });
  server.on('connection', socket => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => {
    for (const socket of sockets) socket.destroy();
    return new Promise(resolve => server.close(resolve));
  });
  return {
    url: `http://127.0.0.1:${server.address().port}${route}`,
    requests,
    bodies: () => requests.map(request => JSON.parse(request.body)),
    deliveries: () => requests.map(request => request.headers['x-goblin-delivery']),
    release(status = 200) {
      for (const res of held) {
        if (!res.destroyed) {
          res.writeHead(status);
          res.end();
        }
      }
      held.clear();
    },
  };
}

/** A mail transport recording each message; `fail(message)` returns an error to throw. */
function mailbox({ fail = () => null } = {}) {
  const messages = [],
    attempts = [];
  return {
    messages,
    attempts,
    factory: () => ({
      async sendMail(message) {
        attempts.push(message);
        const error = fail(message, attempts.length);
        if (error === 'hang') return new Promise(() => {});
        if (error) throw error;
        messages.push(message);
        return { accepted: ['recipient@example.test'], rejected: [] };
      },
      close() {},
    }),
  };
}

const emailSettings = (extra = {}) => ({
  ...emailDefaults(),
  enabled: true,
  from: 'sender@example.test',
  to: 'recipient@example.test',
  password: mailPassword,
  host: 'smtp.example.test',
  ...extra,
});

// Fast delivery for tests: the worker looks every 20 ms and retries after 100 ms.
const fast = { pollMs: 20, rng: () => 1, policy: { baseMs: 100, capMs: 100 } };

/**
 * A running Uptime Goblin on a temporary (or given) directory: the scheduler off, sources failing or
 * reporting as `down` says, email set up when `mail` is given. Resolves {app, call, down,
 * fire(id), recover(id), directory, base}.
 */
async function start(
  t,
  {
    directory = temporary(t),
    webhook = '',
    mail = null,
    delivery = {},
    sources = ['plex', 'sonarr', 'radarr'],
    ...options
  } = {}
) {
  const down = new Set();
  const app = await createApp({
    directory,
    host: '127.0.0.1',
    port: 0,
    password,
    allowedHosts: '',
    trustProxy: '',
    startScheduler: false,
    webhook,
    emailBatchMs: 60000,
    mailTransportFactory:
      mail?.factory ??
      (() => {
        throw new Error('Unexpected mail attempt');
      }),
    collector: async service => {
      if (down.has(service.id)) throw new Error(`${service.id} is down`);
      return [{ key: 'up', label: 'Up', value: 1, unit: '' }];
    },
    ...options,
    delivery: { ...fast, ...delivery, policy: { ...fast.policy, ...delivery.policy } },
  });
  const { port } = await app.listen();
  // Also after a test that closed it (close() is idempotent) or failed before it could.
  t.after(() => app.close());
  const base = `http://127.0.0.1:${port}`;
  const call = async (route, method = 'GET', body, headers = {}) => {
    const res = await fetch(base + route, {
      method,
      headers: {
        Authorization: 'Basic ' + Buffer.from('admin:' + password).toString('base64'),
        'Content-Type': 'application/json',
        'X-Goblin-Request': '1',
        ...headers,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    let value = text;
    try {
      value = JSON.parse(text);
    } catch {}
    return { status: res.status, headers: res.headers, body: value };
  };
  // One failed or successful collection changes the alert at once.
  app.config.updateGlobal({
    monitoring: {
      availabilityFailures: 1,
      availabilitySeconds: 0,
      retryCount: 0,
      recoverySuccesses: 1,
      recoverySeconds: 0,
    },
    ...(mail ? { email: emailSettings() } : {}),
  });
  for (const id of sources)
    if (!app.config.get(id)?.apiUrl)
      app.config.update(id, { apiUrl: `https://${id}.example.test`, apiKey: 'fixture-key' });
  const fire = async id => {
    down.add(id);
    await app.poll(app.config.get(id));
  };
  const recover = async id => {
    down.delete(id);
    await app.poll(app.config.get(id));
  };
  return { app, call, down, fire, recover, directory, base, port };
}

/**
 * A clock for the delivery service ({now, wall, setTimeout, clearTimeout}, as lib/jobs.mjs's
 * systemClock): time moves only through advance(ms), which runs every timer due on the way, in
 * order, letting I/O and promises settle between them.
 */
function fakeClock(start = Date.now()) {
  let elapsed = 0,
    sequence = 0;
  const timers = new Map();
  return {
    now: () => elapsed,
    wall: () => start + elapsed,
    setTimeout(fn, ms) {
      const id = ++sequence;
      timers.set(id, { at: elapsed + Math.max(0, Number(ms) || 0), fn });
      return id;
    },
    clearTimeout: id => void timers.delete(id),
    async advance(ms) {
      const target = elapsed + ms;
      for (;;) {
        let next = null;
        for (const [id, timer] of timers)
          if (timer.at <= target && (!next || timer.at < next.timer.at)) next = { id, timer };
        if (!next) break;
        timers.delete(next.id);
        elapsed = Math.max(elapsed, next.timer.at);
        next.timer.fn();
        await sleep(5);
      }
      elapsed = target;
      await sleep(5);
    },
  };
}

// The answers' contract (test/contract/notifications-bodies.json): keys and kinds of an answer
// follow its example ("<ms>" a time or null, "<uid>" a delivery id, "<id>" a row id).
const contract = JSON.parse(
  fs.readFileSync(new URL('./contract/notifications-bodies.json', import.meta.url), 'utf8')
).answers;
function sameShape(actual, expected, where = 'body') {
  if (expected === '<ms>')
    return assert.ok(actual === null || Number.isSafeInteger(actual), `${where}: ${actual}`);
  if (expected === '<uid>') return assert.match(actual, /^d_[a-z2-7]{26}$/, where);
  if (expected === '<id>')
    return assert.ok(actual === null || /^[1-9][0-9]*$/.test(actual), `${where}: ${actual}`);
  if (expected === '<keyId>') return assert.match(actual, /^[0-9a-f]{16}$/, where);
  if (expected === '<publicKey>')
    return assert.match(
      actual,
      /^-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/]{59}=\n-----END PUBLIC KEY-----\n$/,
      where
    );
  if (expected === '<publicKeyRaw>') return assert.match(actual, /^[A-Za-z0-9+/]{43}=$/, where);
  if (Array.isArray(expected)) {
    assert.ok(Array.isArray(actual), `${where}: a list`);
    if (expected.length)
      for (const [i, item] of actual.entries()) sameShape(item, expected[0], `${where}[${i}]`);
    return;
  }
  if (expected && typeof expected === 'object') {
    if (actual === null) return;
    assert.deepEqual(Object.keys(actual).sort(), Object.keys(expected).sort(), where);
    for (const key of Object.keys(expected))
      sameShape(actual[key], expected[key], `${where}.${key}`);
    return;
  }
  if (expected === null) return;
  assert.ok(actual === null || typeof actual === typeof expected, `${where}: ${typeof actual}`);
}

// X-Goblin-Signature as a receiver reads it: its t, its v1a values ({keyId, signature}) and
// anything else it carries.
function signatureParts(header) {
  const parts = String(header ?? '').split(',');
  const t = parts.find(part => part.startsWith('t='))?.slice(2);
  const v1a = parts
    .filter(part => part.startsWith('v1a='))
    .map(part => /^v1a=([0-9a-f]{16}):([0-9a-f]{128})$/.exec(part))
    .map(match => ({ keyId: match?.[1], signature: match?.[2] }));
  return { t, v1a, other: parts.filter(part => !/^(t|v1a)=/.test(part)) };
}
// 1.4.2's exact request body for a history event of `service` and `kind` (field order kept).
function legacyBody(app, service, kind) {
  const event = app.store.events().find(e => e.service === service && e.kind === kind);
  assert.ok(event, `${service} ${kind} event`);
  return JSON.stringify({
    source: 'orbit',
    service: event.service,
    name: app.config.get(event.service)?.name ?? event.name,
    kind: event.kind,
    category: event.category,
    rule: event.rule,
    message: event.message,
    time: event.time,
  });
}
const deliveries = async (call, query = '') =>
  (await call(`/api/notifications/deliveries${query}`)).body.deliveries;
const channelOf = async (call, id) =>
  (await call('/api/notifications')).body.channels.find(channel => channel.id === id);

test('an alert and its recovery reach both channels once, signed, with 1.4.2’s body and one digest', async t => {
  const hook = await receiver(t);
  const mail = mailbox();
  const { app, call, fire, recover } = await start(t, { webhook: hook.url, mail });
  await fire('plex');
  await recover('plex');
  await app.flushNotifications();
  await until(() => hook.requests.length === 2, { what: 'both webhook requests' });

  // The body is byte for byte what 1.4.2 sent, in the order the alert changed.
  assert.deepEqual(
    hook.requests.map(request => request.body),
    [legacyBody(app, 'plex', 'firing'), legacyBody(app, 'plex', 'resolved')]
  );
  // The receiver's public key, from Uptime Goblin's public-key route (any signed-in admin, or a script
  // while legacy Basic is on, as here).
  const keys = await call('/api/notifications/webhook/public-key');
  assert.equal(keys.status, 200);
  assert.equal(keys.body.algorithm, 'Ed25519');
  assert.deepEqual([keys.body.previous, keys.body.previousUntil], [null, null]);
  const pem = createPublicKey(keys.body.publicKey);
  const raw = createPublicKey({
    key: {
      kty: 'OKP',
      crv: 'Ed25519',
      x: Buffer.from(keys.body.publicKeyRaw, 'base64').toString('base64url'),
    },
    format: 'jwk',
  });
  assert.ok(pem.equals(raw), 'the PEM and the raw bytes are the same key');
  const ids = new Set();
  for (const request of hook.requests) {
    const delivery = request.headers['x-goblin-delivery'];
    assert.match(delivery, /^d_[a-z2-7]{26}$/);
    ids.add(delivery);
    assert.equal(request.headers['content-type'], 'application/json');
    assert.equal(request.headers['user-agent'], 'Uptime-Goblin');
    // The names from before the rename to Uptime Goblin, with the same values (1.5 and 1.6).
    assert.equal(request.headers['x-orbit-delivery'], delivery);
    assert.equal(request.headers['x-orbit-signature'], request.headers['x-goblin-signature']);
    // The signature is Ed25519 over the delivery id, the time and the body, made with the key
    // the header names: node:crypto verifies it with the route's public key.
    const { t: time, v1a, other } = signatureParts(request.headers['x-goblin-signature']);
    assert.match(time, /^\d{10}$/);
    assert.deepEqual(other, [], 'no HMAC v1 or anything else');
    assert.equal(v1a.length, 1);
    assert.equal(v1a[0].keyId, keys.body.keyId);
    const signature = Buffer.from(v1a[0].signature, 'hex');
    const signed = data => Buffer.from(`${data}.${time}.${request.body}`);
    assert.equal(verify(null, signed(delivery), keys.body.publicKey, signature), true);
    assert.equal(verify(null, signed(delivery), raw, signature), true);
    // Replayed under another delivery id, or with a changed body, it does not verify.
    assert.equal(verify(null, signed(`d_${'z'.repeat(26)}`), pem, signature), false);
    assert.equal(
      verify(null, Buffer.from(`${delivery}.${time}.${request.body} `), pem, signature),
      false
    );
  }
  assert.equal(ids.size, 2, 'one delivery id per notification');

  // Email: one digest with both, its Message-ID the batch id at the sender's domain.
  assert.equal(mail.messages.length, 1);
  assert.match(mail.messages[0].messageId, /^<orbit\.g_[a-z2-7]{26}@example\.test>$/);
  assert.match(mail.messages[0].text, /Plex/);
  // Every delivery is recorded as delivered, and the status says so.
  const rows = await deliveries(call);
  assert.equal(rows.length, 4);
  assert.deepEqual(new Set(rows.map(row => row.status)), new Set(['delivered']));
  assert.equal(new Set(rows.filter(r => r.channel === 'email').map(r => r.batch)).size, 1);
  // Newest first, a page at a time: following nextCursor lists every row once.
  const paged = [];
  let cursor = null;
  for (let page = 0; page < 5; page++) {
    const answer = (
      await call(`/api/notifications/deliveries?limit=2${cursor ? `&cursor=${cursor}` : ''}`)
    ).body;
    paged.push(...answer.deliveries.map(row => row.uid));
    cursor = answer.nextCursor;
    if (!cursor) break;
    assert.match(cursor, /^[1-9][0-9]*$/);
  }
  assert.deepEqual(
    paged,
    rows.map(row => row.uid)
  );
  assert.equal(
    (await call('/api/notifications/deliveries?filter=active')).body.deliveries.length,
    0
  );
  const status = (await call('/api/notifications')).body;
  assert.equal(status.available, true);
  // The real service's answers have the contract's shapes.
  sameShape(status, contract.status, 'status');
  sameShape((await call('/api/notifications/deliveries')).body, contract.deliveries, 'page');
  sameShape(
    (await call('/api/dashboard')).body.notifications,
    contract.dashboard.notifications,
    'dashboard'
  );
  assert.deepEqual(
    status.channels.map(channel => [channel.id, channel.state, channel.deliveredTotal]),
    [
      // One email message (a digest of both), two webhook requests.
      ['email', 'ok', 1],
      ['env-webhook', 'ok', 2],
      // ntfy and Gotify are listed, not set up.
      ['ntfy', 'not-configured', 0],
      ['gotify', 'not-configured', 0],
    ]
  );
  // The dashboard's 1.4.x fields follow the persisted status.
  const legacy = (await call('/api/dashboard')).body.notifications;
  assert.equal(legacy.configured, true);
  assert.equal(legacy.lastError, null);
  assert.equal(legacy.email.state, 'accepted');
  assert.equal(legacy.available, true);
});

test('a webhook answering 500, 500, 200 delivers on the third attempt; the recovery waits behind it', async t => {
  const hook = await receiver(t, (request, n) => (n <= 2 ? 500 : 200));
  const { app, call, fire, recover } = await start(t, { webhook: hook.url });
  await fire('plex');
  await recover('plex');
  await until(() => hook.requests.length >= 4, { what: 'the retries and the recovery' });
  await sleep(300);
  assert.deepEqual(
    hook.bodies().map(body => body.kind),
    ['firing', 'firing', 'firing', 'resolved']
  );
  const ids = hook.deliveries();
  assert.equal(new Set(ids.slice(0, 3)).size, 1, 'every attempt carries the same delivery id');
  assert.notEqual(ids[3], ids[0]);
  // The recovery was not sent before its alert was delivered.
  assert.ok(hook.requests[3].receivedAt >= hook.requests[2].receivedAt);
  const firing = (await deliveries(call)).find(row => row.kind === 'firing');
  assert.equal(firing.status, 'delivered');
  assert.equal(firing.attempts, 3);
  assert.equal(firing.lastStatus, 200);
});

test('401 pauses the webhook and holds its alerts, email is told, and Resume sends them in order', async t => {
  let answer = 401;
  const hook = await receiver(t, () => answer);
  const mail = mailbox();
  const { app, call, fire, recover } = await start(t, {
    webhook: hook.url,
    mail,
    // No probe during this test: only Resume may end the pause.
    delivery: { policy: { circuitCapMs: 60 * 60 * 1000 } },
  });
  const warn = t.mock.method(console, 'warn', () => {});
  await fire('plex');
  await until(async () => (await channelOf(call, 'env-webhook')).state === 'paused', {
    what: 'the webhook pause',
  });
  await recover('plex');
  const webhook = await channelOf(call, 'env-webhook');
  assert.match(webhook.pausedReason, /401/);
  assert.equal(typeof webhook.pausedSince, 'number');
  // The dashboard's banner fields.
  const dashboard = (await call('/api/dashboard')).body.notifications;
  assert.deepEqual(dashboard.attention.paused, ['env-webhook']);
  assert.deepEqual(
    dashboard.channels.find(channel => channel.id === 'env-webhook').state,
    'paused'
  );
  const held = (await deliveries(call, '?channel=env-webhook')).map(row => [row.kind, row.status]);
  assert.deepEqual(held, [
    ['resolved', 'paused'],
    ['firing', 'paused'],
  ]);
  assert.equal(hook.requests.length, 1, 'one request, answered 401');
  // The pause is told to the other channel, once.
  answer = 200;
  await app.flushNotifications();
  const pauseNotices = (await deliveries(call, '?channel=email')).filter(
    row => row.alert.rule === '__channel_env-webhook'
  );
  assert.deepEqual(
    pauseNotices.map(row => [row.kind, row.status]),
    [['firing', 'delivered']]
  );
  assert.match(
    mail.messages.map(message => message.text).join('\n'),
    /Webhook notifications are paused/
  );
  assert.equal(hook.requests.length, 1, 'still held: nothing is sent while paused');
  // Resume: the held alerts go out in the order the alert changed, then the recovery notice.
  const resumed = await call('/api/notifications/channels/env-webhook/resume', 'POST', {});
  assert.equal(resumed.status, 200);
  assert.equal(resumed.body.released, 2);
  await until(() => hook.requests.length === 3, { what: 'the released alerts' });
  assert.deepEqual(
    hook.bodies().map(body => body.kind),
    ['firing', 'firing', 'resolved']
  );
  await app.flushNotifications();
  const notices = (await deliveries(call, '?channel=email')).filter(
    row => row.alert.rule === '__channel_env-webhook'
  );
  assert.deepEqual(notices.map(row => row.kind).sort(), ['firing', 'resolved']);
  assert.match(
    mail.messages.map(message => message.text).join('\n'),
    /Webhook notifications are working again/
  );
  assert.equal((await channelOf(call, 'env-webhook')).state, 'ok');
  assert.ok(warn.mock.calls.length >= 1, 'the pause was logged');
});

// Review round 3: an Uptime Goblin notice sent alone carried the explanation of its category, and every
// 'system' notice got the history-storage one: the email saying that the webhook paused told
// the admin that readings were not saved and to free disk space, and "working again" that Uptime Goblin was
// saving readings again.
test('the emails saying that the webhook paused and works again, each sent alone, say nothing of readings or disk space', async t => {
  let answer = 503;
  const hook = await receiver(t, () => answer);
  const mail = mailbox();
  const { app, call, fire } = await start(t, {
    webhook: hook.url,
    mail,
    // No probe during this test: only Resume may end the pause.
    delivery: { policy: { circuitCapMs: 60 * 60 * 1000 } },
  });
  t.mock.method(console, 'warn', () => {});
  t.mock.method(console, 'info', () => {});
  // Plex's alert email goes out first, alone; the webhook answers 503, so it retries.
  await fire('plex');
  await app.flushNotifications();
  await until(() => mail.messages.length === 1 && hook.requests.length >= 1, {
    what: "Plex's email and the first webhook request",
  });
  // The retry is answered 404: the webhook pauses, and the email that says so goes out alone.
  answer = 404;
  await until(async () => (await channelOf(call, 'env-webhook')).state === 'paused', {
    what: 'the webhook pause',
  });
  await app.flushNotifications();
  await until(() => mail.messages.length === 2, { what: 'the pause email' });
  const paused = mail.messages[1];
  assert.equal(paused.subject, '[Uptime Goblin] Alert · Uptime Goblin health · Uptime Goblin');
  assert.match(paused.text, /^Alert — Uptime Goblin\n\nWebhook notifications are paused: .*404/);
  assert.match(
    paused.text,
    /\n\nIts notifications are held until it works again \(each for at most 24 hours\); this channel keeps sending\. Configure → Notifications in Uptime Goblin says why; once the cause is fixed, Resume there sends them\.\n\n/
  );
  // Resume with the receiver fixed: the email that it works again goes out alone too.
  answer = 200;
  const resumed = await call('/api/notifications/channels/env-webhook/resume', 'POST', {});
  assert.equal(resumed.status, 200);
  await until(() => hook.requests.some(request => request.answered === 200), {
    what: 'the held alert',
  });
  await app.flushNotifications();
  await until(() => mail.messages.length === 3, { what: 'the email that it works again' });
  const working = mail.messages[2];
  assert.equal(working.subject, '[Uptime Goblin] Recovered · Uptime Goblin health · Uptime Goblin');
  assert.match(
    working.text,
    /^Recovered — Uptime Goblin\n\nWebhook notifications are working again\.\n\nTime: /
  );
  for (const message of [paused, working]) {
    assert.doesNotMatch(message.text, /readings|disk space/);
    assert.doesNotMatch(message.html, /readings|disk space/);
  }
  // Both were the channel notices, each in an email of its own.
  const notices = (await deliveries(call, '?channel=email')).filter(
    row => row.alert.rule === '__channel_env-webhook'
  );
  assert.deepEqual(notices.map(row => row.kind).sort(), ['firing', 'resolved']);
});

test('a webhook answering 404 resumes by itself once a probe is accepted, without Resume', async t => {
  let answer = 404;
  const hook = await receiver(t, () => answer);
  const { app, call, fire } = await start(t, {
    webhook: hook.url,
    // The 15-minute probe of a transient pause, shortened.
    delivery: { policy: { circuitCapMs: 400 } },
  });
  t.mock.method(console, 'warn', () => {});
  t.mock.method(console, 'info', () => {});
  await fire('plex');
  await until(async () => (await channelOf(call, 'env-webhook')).state === 'paused', {
    what: 'the webhook pause',
  });
  const paused = await channelOf(call, 'env-webhook');
  assert.equal(typeof paused.nextAttemptAt, 'number', 'a transient pause names its next probe');
  await fire('sonarr');
  answer = 200;
  await until(() => hook.requests.filter(request => request.answered === 200).length === 2, {
    what: 'the probe and the rest',
  });
  // Plex's alert was refused, and so was each probe that came before the receiver was fixed:
  // how many did depends on how long this test took to fix it, so a busy machine sees more. Each
  // probe reached the receiver at least 400 ms after the request before it (a busy machine only
  // adds to that); the first probe accepted carried Plex's held alert, and Sonarr's followed.
  const answers = hook.requests.map(request => [
    JSON.parse(request.body).service,
    request.answered,
  ]);
  const fixed = answers.findIndex(([, status]) => status === 200);
  assert.ok(fixed >= 1, JSON.stringify(answers));
  assert.deepEqual(answers.slice(0, fixed), Array(fixed).fill(['plex', 404]));
  assert.deepEqual(answers.slice(fixed), [
    ['plex', 200],
    ['sonarr', 200],
  ]);
  const gaps = hook.requests
    .slice(1, fixed + 1)
    .map((request, i) => request.receivedAt - hook.requests[i].receivedAt);
  assert.ok(
    gaps.every(gap => gap >= 400),
    `probes ${gaps} ms after the request before`
  );
  const resumed = await channelOf(call, 'env-webhook');
  assert.equal(resumed.state, 'ok');
  assert.equal(resumed.pausedSince, null);
  assert.equal(app.config.get('plex').name, 'Plex');
});

test('a refused email sign-in pauses email; saving settings or an accepted test email resumes it', async t => {
  let refusing = true;
  const mail = mailbox({
    fail: message =>
      refusing && !/test/i.test(message.subject ?? '')
        ? Object.assign(new Error('535 authentication failed'), { code: 'EAUTH' })
        : null,
  });
  const { app, call, fire } = await start(t, { mail });
  t.mock.method(console, 'warn', () => {});
  await fire('plex');
  await app.flushNotifications();
  await until(async () => (await channelOf(call, 'email')).state === 'paused', {
    what: 'the email pause',
  });
  assert.equal((await call('/api/dashboard')).body.notifications.email.state, 'error');
  // Saving corrected settings resumes it, and the held alert is sent.
  refusing = false;
  const saved = await call('/api/settings', 'PATCH', {
    email: emailSettings({ password: 'notifications-new-app-password' }),
  });
  assert.equal(saved.status, 200);
  await app.flushNotifications();
  await until(() => mail.messages.length === 1, { what: 'the held email' });
  assert.equal((await channelOf(call, 'email')).state, 'ok');
  // Paused again; this time an accepted test email resumes it.
  refusing = true;
  await fire('sonarr');
  await app.flushNotifications();
  await until(async () => (await channelOf(call, 'email')).state === 'paused', {
    what: 'the second pause',
  });
  refusing = false;
  const tested = await call('/api/email/test', 'POST', {});
  assert.equal(tested.status, 200, JSON.stringify(tested.body));
  await app.flushNotifications();
  await until(
    () => mail.messages.filter(message => /Sonarr/.test(message.text ?? '')).length === 1,
    { what: 'the email held by the second pause' }
  );
  assert.equal((await channelOf(call, 'email')).state, 'ok');
});

test('a test email is refused only while the email channel is sending, not while alerts wait to retry', async t => {
  // D13: "busy" is a send in flight on the email channel (or a test pending), no longer "any
  // message waiting", so a webhook alert retrying never blocks the test the admin uses to check a fix.
  const hook = await receiver(t, () => 500);
  let hangAlerts = false;
  const mail = mailbox({
    fail: message => (hangAlerts && !/test/i.test(message.subject ?? '') ? 'hang' : null),
  });
  let mono = 1e6;
  const { app, call, fire } = await start(t, {
    webhook: hook.url,
    mail,
    emailTimeoutMs: 1500,
    monotonic: () => mono,
    delivery: { policy: { baseMs: 60000, capMs: 60000 } },
  });
  t.mock.method(console, 'warn', () => {});
  await fire('plex');
  await until(async () => (await deliveries(call, '?channel=env-webhook'))[0]?.attempts === 1);
  const waiting = await deliveries(call, '?channel=email');
  assert.equal(waiting[0].status, 'waiting', 'the email waits in its quiet window');
  const first = await call('/api/email/test', 'POST', {});
  assert.equal(first.status, 200, JSON.stringify(first.body));
  // An alert email in flight (the mail server never answers): a test is refused meanwhile.
  hangAlerts = true;
  mono += 61000;
  const flushed = app.flushNotifications();
  await until(() => app.alerting.emailSending(), { what: 'an email in flight' });
  const busy = await call('/api/email/test', 'POST', {});
  assert.equal(busy.status, 429);
  assert.ok(Number(busy.headers.get('retry-after')) >= 1);
  await flushed;
  hangAlerts = false;
  await until(() => !app.alerting.emailSending());
  const again = await call('/api/email/test', 'POST', {});
  assert.equal(again.status, 200, JSON.stringify(again.body));
});

test('Retry sends a failed notification again, and refuses what it must', async t => {
  let mode = 'refuse-firing';
  const hook = await receiver(t, request => {
    if (mode === 'hold') return 'hold';
    if (mode === 'pause') return 401;
    return mode === 'refuse-firing' && JSON.parse(request.body).kind === 'firing' ? 422 : 200;
  });
  const mail = mailbox();
  const { app, call, fire, recover } = await start(t, {
    webhook: hook.url,
    mail,
    delivery: { policy: { circuitCapMs: 60 * 60 * 1000 } },
  });
  t.mock.method(console, 'warn', () => {});
  const retry = uid => call(`/api/notifications/deliveries/${uid}/retry`, 'POST', {});
  const webhookRow = async (service, kind) =>
    (await deliveries(call, '?channel=env-webhook')).find(
      row => row.alert.service === service && row.kind === kind
    );

  // A refused (dead) firing; its recovery is then delivered, so retrying it is out of order.
  await fire('plex');
  await until(async () => (await webhookRow('plex', 'firing'))?.status === 'failed');
  const failed = await webhookRow('plex', 'firing');
  assert.equal(failed.retryable, true);
  assert.equal(failed.lastStatus, 422);
  await recover('plex');
  await until(async () => (await webhookRow('plex', 'resolved'))?.status === 'delivered');
  const outdated = await retry(failed.uid);
  assert.equal(outdated.status, 409);
  assert.equal(outdated.body.code, 'delivery_outdated');

  // A failed firing with nothing after it is sent again.
  await fire('sonarr');
  await until(async () => (await webhookRow('sonarr', 'firing'))?.status === 'failed');
  mode = 'accept';
  const sonarr = await webhookRow('sonarr', 'firing');
  const retried = await retry(sonarr.uid);
  assert.equal(retried.status, 200, JSON.stringify(retried.body));
  assert.equal(retried.body.retried, 1);
  assert.equal(retried.body.delivery.uid, sonarr.uid);
  await until(async () => (await webhookRow('sonarr', 'firing'))?.status === 'delivered');
  assert.equal(
    hook.requests.filter(request => request.headers['x-goblin-delivery'] === sonarr.uid).length,
    2
  );
  // A delivered notification is finished.
  const finished = await retry(sonarr.uid);
  assert.equal(finished.status, 409);
  assert.equal(finished.body.code, 'delivery_not_retryable');
  assert.match(finished.body.error, /^Only failed notifications/);
  // An email waiting in its quiet window has not had its first attempt.
  const waiting = (await deliveries(call, '?channel=email')).find(row => row.status === 'waiting');
  assert.ok(waiting, 'an email row in its window');
  const early = await retry(waiting.uid);
  assert.equal(early.status, 409);
  assert.match(early.body.error, /not had its first attempt/);
  // A row being sent.
  mode = 'hold';
  await fire('radarr');
  await until(() => hook.requests.some(request => JSON.parse(request.body).service === 'radarr'));
  const sending = await webhookRow('radarr', 'firing');
  assert.equal(sending.status, 'sending');
  const busy = await retry(sending.uid);
  assert.equal(busy.status, 409);
  assert.match(busy.body.error, /being sent right now/);
  hook.release(401);
  // A paused channel's held row: Resume first.
  mode = 'pause';
  await until(async () => (await channelOf(call, 'env-webhook')).state === 'paused');
  const heldRow = await webhookRow('radarr', 'firing');
  assert.equal(heldRow.status, 'paused');
  const paused = await retry(heldRow.uid);
  assert.equal(paused.status, 409);
  assert.equal(paused.body.code, 'channel_paused');
  assert.match(paused.body.error, /^Webhook notifications are paused: .*Resume the channel/);
  // An id that is not (or no longer) in the history.
  const missing = await retry('d_' + 'q'.repeat(26));
  assert.equal(missing.status, 404);
  assert.equal(missing.body.code, 'delivery_not_found');
  await app.flushNotifications();
});

test('Problems pages list what retries behind 105 newer notifications waiting at an open circuit, and a cursor only while older rows match', async t => {
  const hook = await receiver(t, () => 500);
  // A failed send waits a minute, and 5 failures open the circuit for a minute: the first 5
  // notifications retry, and every one queued after them waits for its first attempt.
  const { app, call } = await start(t, {
    webhook: hook.url,
    delivery: { policy: { baseMs: 60000, capMs: 60000 } },
  });
  for (let n = 1; n <= 110; n++)
    await app.alerting.enqueueDirect(
      {
        service: 'plex',
        name: `Flood ${n}`,
        kind: 'firing',
        category: 'threshold',
        rule: `flood-${n}`,
        message: 'CPU is above 80%',
        time: Date.now(),
      },
      `test:flood-${n}`
    );
  const status = await until(
    async () => {
      const body = (await call('/api/notifications')).body;
      return body.totals.retrying === 5 && body.totals.waiting === 105 && body;
    },
    { what: '5 notifications retrying and 105 waiting' }
  );
  assert.equal(status.channels.find(c => c.id === 'env-webhook').state, 'circuit-open');
  const page = async query => (await call(`/api/notifications/deliveries?${query}`)).body;
  // Needs attention's read (100) and the history's (50): the 5 that retry, and nothing older.
  for (const limit of [100, 50, 5]) {
    const problems = await page(`filter=problems&limit=${limit}`);
    assert.deepEqual(
      problems.deliveries.map(row => row.status),
      Array(5).fill('retrying'),
      `limit ${limit}`
    );
    assert.ok(problems.deliveries.every(row => row.retryable));
    assert.equal(problems.nextCursor, null, `limit ${limit}`);
  }
  // Pages of 2 follow the cursor to the end, and the last one has none.
  const paged = [];
  let cursor = null;
  for (let n = 0; n < 5; n++) {
    const answer = await page(`filter=problems&limit=2${cursor ? `&cursor=${cursor}` : ''}`);
    paged.push(answer.deliveries.length);
    cursor = answer.nextCursor;
    if (!cursor) break;
  }
  assert.deepEqual(paged, [2, 2, 1]);
  // A history of exactly two pages: the second, full, says there is nothing older.
  const first = await page('limit=55');
  assert.equal(first.deliveries.length, 55);
  assert.match(first.nextCursor, /^[1-9][0-9]*$/);
  const second = await page(`limit=55&cursor=${first.nextCursor}`);
  assert.equal(second.deliveries.length, 55);
  assert.equal(second.nextCursor, null);
  // The other filters are unchanged: waiting rows are active.
  const active = await page('filter=active&limit=100');
  assert.equal(active.deliveries.length, 100);
  assert.ok(active.nextCursor);
  assert.equal(active.deliveries.filter(row => row.status === 'waiting').length, 100);
});

test('a deleted source’s held alert is cancelled, and one whose alerts were switched off is skipped', async t => {
  let answer = 401;
  const hook = await receiver(t, () => answer);
  const { app, call, fire } = await start(t, {
    webhook: hook.url,
    delivery: { policy: { circuitCapMs: 60 * 60 * 1000, baseMs: 300, capMs: 300 } },
  });
  t.mock.method(console, 'warn', () => {});
  await fire('plex');
  await until(async () => (await channelOf(call, 'env-webhook')).state === 'paused');
  assert.equal((await call('/api/services/plex', 'DELETE')).status, 200);
  const cancelled = (await deliveries(call)).find(row => row.alert.service === 'plex');
  assert.equal(cancelled.state, 'cancelled');
  assert.equal(cancelled.status, 'not-sent');
  assert.equal(cancelled.lastError, 'Not sent: the source was deleted.');
  answer = 200;
  assert.equal(
    (await call('/api/notifications/channels/env-webhook/resume', 'POST', {})).status,
    200
  );
  await app.flushNotifications();
  await sleep(200);
  assert.equal(hook.requests.length, 1, 'nothing was sent for the deleted source');

  // A firing retrying when alerts of its kind are switched off is skipped at its next attempt.
  answer = 500;
  await fire('sonarr');
  await until(async () =>
    (await deliveries(call)).some(row => row.alert.service === 'sonarr' && row.attempts === 1)
  );
  const off = await call('/api/settings', 'PATCH', { alerts: { notifyOnAlert: false } });
  assert.equal(off.status, 200);
  answer = 200;
  await until(
    async () =>
      (await deliveries(call)).find(row => row.alert.service === 'sonarr')?.status === 'skipped',
    { what: 'the skipped firing' }
  );
  const skipped = (await deliveries(call)).find(row => row.alert.service === 'sonarr');
  assert.equal(
    skipped.lastError,
    'Not sent: alerts of this kind were switched off after it was queued.'
  );
  assert.equal(hook.requests.filter(request => request.answered === 200).length, 0);
});

test('with history failing on evaluation, each fallback event and the storage notice go out once', async t => {
  const hook = await receiver(t);
  const mail = mailbox();
  const { app, call, fire } = await start(t, { webhook: hook.url, mail });
  const errors = t.mock.method(console, 'error', () => {});
  app.store.evaluate = () => {
    throw Object.assign(new Error('database or disk is full'), { code: 'SQLITE_FULL' });
  };
  for (let i = 0; i < 3; i++) for (const id of ['plex', 'sonarr']) await fire(id);
  await app.flushNotifications();
  await until(() => hook.requests.length === 3, { what: 'two fallback events and the notice' });
  await sleep(200);
  const bodies = hook.bodies();
  assert.deepEqual(bodies.map(body => [body.service, body.rule, body.kind]).sort(), [
    ['orbit', '__storage', 'firing'],
    ['plex', '__availability', 'firing'],
    ['sonarr', '__availability', 'firing'],
  ]);
  assert.equal(new Set(hook.deliveries()).size, 3);
  // Email has each once as well (one digest).
  const email = await deliveries(call, '?channel=email');
  assert.deepEqual(email.map(row => `${row.alert.service}:${row.alert.rule}`).sort(), [
    'orbit:__storage',
    'plex:__availability',
    'sonarr:__availability',
  ]);
  assert.equal(mail.messages.length, 1);
  assert.ok(errors.mock.calls.length > 0);
});

test('restart continuity: retrying, in-flight and digest rows survive close() and createApp()', async t => {
  // One data directory, two releases of the same process: what was waiting at close() is sent
  // after createApp() without any request to Uptime Goblin's API (delivery spec §8.2 item 1).
  let mode = 'fail-firing';
  const hook = await receiver(t, request => {
    const { service } = JSON.parse(request.body);
    if (mode === 'accept') return 200;
    if (service === 'radarr') return 'hold';
    return 500;
  });
  const mail = mailbox();
  const unknown = { resendAfterMs: 2000, maxResends: 1 };
  const directory = temporary(t);
  const first = await start(t, {
    directory,
    webhook: hook.url,
    mail,
    emailTimeoutMs: 1000,
    delivery: { webhookUnknown: unknown, policy: { baseMs: 400, capMs: 400 } },
  });
  t.mock.method(console, 'warn', () => {});
  t.mock.method(console, 'error', () => {});
  // (a) retrying: the receiver answers 500.
  await first.fire('plex');
  await until(() => hook.requests.length === 1);
  // (d) in flight at close(): the receiver holds the request and never answers.
  await first.fire('radarr');
  await until(() => hook.requests.some(request => JSON.parse(request.body).service === 'radarr'));
  // (c) the email digest window is open (60 s quiet): close() sends it.
  assert.equal(mail.messages.length, 0);
  const started = Date.now();
  await first.app.close();
  assert.ok(Date.now() - started < 31000, 'the stop keeps its budget');
  assert.equal(mail.messages.length, 1, 'the digest went out at close()');
  const emailsBefore = mail.messages.length;
  const radarrId = hook.requests.find(request => JSON.parse(request.body).service === 'radarr')
    .headers['x-goblin-delivery'];
  const plexId = hook.requests[0].headers['x-goblin-delivery'];

  mode = 'accept';
  const second = await start(t, {
    directory,
    webhook: hook.url,
    mail,
    delivery: { webhookUnknown: unknown, policy: { baseMs: 400, capMs: 400 } },
  });
  // (a) delivered once; (d) resent once, with the same delivery id, after its resend delay.
  await until(
    () =>
      hook.requests.filter(r => r.answered === 200 && r.headers['x-goblin-delivery'] === plexId)
        .length === 1 &&
      hook.requests.filter(r => r.answered === 200 && r.headers['x-goblin-delivery'] === radarrId)
        .length === 1,
    { what: 'the retrying and the unconfirmed notification', timeoutMs: 20000 }
  );
  await sleep(500);
  const radarrRequests = hook.requests.filter(
    request => request.headers['x-goblin-delivery'] === radarrId
  );
  assert.equal(radarrRequests.length, 2, 'the unconfirmed request was sent once more');
  assert.ok(radarrRequests[1].receivedAt - radarrRequests[0].receivedAt >= 2000);
  assert.equal(
    hook.requests.filter(request => request.headers['x-goblin-delivery'] === plexId).length,
    2,
    'one 500 before the restart, one 200 after'
  );
  // (c) no email after the restart: the digest was sent once, before it.
  await second.app.flushNotifications();
  assert.equal(mail.messages.length, emailsBefore);
  const rows = await deliveries(second.call, '?channel=env-webhook');
  assert.deepEqual(new Set(rows.map(row => row.status)), new Set(['delivered']));
});

test('restart continuity: a paused webhook fixed while Uptime Goblin was stopped is probed at start', async t => {
  let answer = 401;
  const hook = await receiver(t, () => answer);
  const directory = temporary(t);
  const first = await start(t, {
    directory,
    webhook: hook.url,
    delivery: { policy: { circuitCapMs: 60 * 60 * 1000 } },
  });
  t.mock.method(console, 'warn', () => {});
  t.mock.method(console, 'info', () => {});
  await first.fire('plex');
  await until(async () => (await channelOf(first.call, 'env-webhook')).state === 'paused');
  await first.app.close();
  // (b) The receiver is fixed while Uptime Goblin is stopped; no Resume is pressed after the start.
  answer = 200;
  const second = await start(t, {
    directory,
    webhook: hook.url,
    delivery: { policy: { circuitCapMs: 60 * 60 * 1000 } },
  });
  await until(() => hook.requests.filter(request => request.answered === 200).length === 1, {
    what: 'the start probe',
  });
  await sleep(300);
  assert.equal(hook.requests.length, 2, 'the 401, then the probe accepted once');
  assert.equal(hook.deliveries()[0], hook.deliveries()[1]);
  assert.equal((await channelOf(second.call, 'env-webhook')).state, 'ok');
});

test('V1: an event id SQLite reuses after a source is deleted is still relayed, exactly once', async t => {
  // x (plex) and y (sonarr) fire and are delivered; y's history mark fails while y exists, so
  // its uid is still pending when y is deleted; z (radarr) then fires, its event reuses y's id,
  // and its fast-path enqueue fails once, so only the sweep can relay it (delivery spec §8.1 H).
  // Marking by id (the pending id now names z) or a sweep cursor kept across passes (a sweep
  // already passed that id) would lose z.
  const hook = await receiver(t);
  let pendingMark = null,
    failInsertOf = 'radarr';
  const busy = () =>
    Object.assign(new Error('database is locked'), { code: 'SQLITE_BUSY', class: 'retry' });
  const wrapHistory = history => ({
    ...history,
    async markRelayed(uids) {
      if (pendingMark && uids.includes(pendingMark)) throw busy();
      return history.markRelayed(uids);
    },
  });
  // The control adapter with z's first insert refused (not a storage error: no memory copy).
  const wrapStore = store =>
    new Proxy(store, {
      get(target, property) {
        if (property === 'insert')
          return async rows => {
            if (failInsertOf && rows.some(row => row.event?.service === failInsertOf)) {
              failInsertOf = null;
              throw busy();
            }
            return target.insert(rows);
          };
        const value = target[property];
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
  const { app, call, fire, directory } = await start(t, {
    webhook: hook.url,
    delivery: { wrapHistory, wrapStore },
  });
  t.mock.method(console, 'error', () => {});
  t.mock.method(console, 'warn', () => {});
  // History's rows as the relay sees them (events() keeps 1.4.x's columns, without uid).
  const historyUids = where => {
    const db = new DatabaseSync(path.join(directory, 'history.sqlite'), { readOnly: true });
    try {
      return db
        .prepare(`SELECT uid FROM events WHERE ${where} ORDER BY id`)
        .all()
        .map(row => row.uid);
    } finally {
      db.close();
    }
  };
  const unrelayedUids = () => historyUids('relayed = 0');
  await fire('plex');
  // y's uid is pending from the moment store.evaluate() wrote it.
  const evaluate = app.store.evaluate.bind(app.store);
  app.store.evaluate = (...args) => {
    const events = evaluate(...args);
    for (const event of events) if (event.service === 'sonarr') pendingMark = event.uid;
    return events;
  };
  await fire('sonarr');
  app.store.evaluate = evaluate;
  await app.flushNotifications();
  await until(() => hook.requests.length === 2, { what: 'x and y delivered' });
  // A sweep passes over y's row, still unmarked, before y is deleted.
  await app.jobs.runNow('notify.relay');
  assert.deepEqual(unrelayedUids(), [pendingMark], "only y's uid is pending");
  const yEvent = app.store.events().find(event => event.service === 'sonarr');
  assert.equal(
    yEvent.id,
    Math.max(...app.store.events().map(event => event.id)),
    "y's event holds the highest id"
  );
  // y is deleted (its events with it); SQLite gives y's id to the next event.
  assert.equal((await call('/api/services/sonarr', 'DELETE')).status, 200);
  await fire('radarr');
  const zEvent = app.store.events().find(event => event.service === 'radarr');
  assert.equal(zEvent.id, yEvent.id, "z's event reuses y's id");
  assert.equal(failInsertOf, null, "z's fast-path enqueue failed once");
  const [zUid] = historyUids("service = 'radarr'");
  assert.match(zUid, /^e_[a-z2-7]{26}$/);
  assert.deepEqual(unrelayedUids(), [zUid]);
  // Only the sweep can relay z now; later sweeps relay nothing more.
  await app.jobs.runNow('notify.relay');
  await app.flushNotifications();
  await until(() => hook.bodies().some(body => body.service === 'radarr'), {
    what: "z's firing",
  });
  await app.jobs.runNow('notify.relay');
  await app.flushNotifications();
  await sleep(200);
  assert.deepEqual(
    hook.bodies().map(body => body.service),
    ['plex', 'sonarr', 'radarr']
  );
  assert.deepEqual(unrelayedUids(), []);
});

test('the webhook address policy: link-local, NAT64-embedded and rebinding addresses pause it', async t => {
  t.mock.method(console, 'warn', () => {});
  t.mock.method(console, 'error', () => {});
  const cases = [
    ['http://169.254.169.254/latest/meta-data/', {}],
    ['http://[64:ff9b::a9fe:a9fe]/hook', {}],
    // A host name that resolves to the metadata address at connect time (the lookup seam).
    [
      'http://metadata.example.test/hook',
      {
        lookup: (hostname, options, callback) =>
          process.nextTick(callback, null, [{ address: '169.254.169.254', family: 4 }]),
      },
    ],
  ];
  for (const [webhook, delivery] of cases) {
    const { app, call, fire } = await start(t, { webhook, delivery });
    await fire('plex');
    await until(async () => (await channelOf(call, 'env-webhook')).state === 'paused', {
      what: `the pause for ${webhook}`,
    });
    const channel = await channelOf(call, 'env-webhook');
    assert.match(channel.pausedReason, /link-local, multicast or reserved/, webhook);
    const row = (await deliveries(call, '?channel=env-webhook'))[0];
    assert.equal(row.status, 'paused', webhook);
    assert.equal(row.sentAt, null, webhook);
    // The host name is shown; the URL itself never is.
    const answer = JSON.stringify((await call('/api/notifications')).body);
    assert.equal(answer.includes(webhook), false);
    assert.equal(answer.includes('/latest/meta-data'), false);
    await app.close();
  }
  // Loopback and http: still work (1.4.2 allowed them).
  const hook = await receiver(t);
  const { fire } = await start(t, { webhook: hook.url });
  await fire('plex');
  await until(() => hook.requests.length === 1);
});

// Linux only (/proc): registered there alone (test/platform-manifest.json).
platformTest(
  import.meta.url,
  'notifications.proc-environ',
  'on Linux the key from GOBLIN_SECRET_KEY_FILE never enters /proc/<pid>/environ; GOBLIN_SECRET_KEY does',
  {},
  async t => {
    const key = randomBytes(32).toString('hex');
    const keyFile = path.join(temporary(t), 'secret.key');
    fs.writeFileSync(keyFile, key + '\n', { mode: 0o600 });
    const environOf = async env => {
      const directory = temporary(t);
      const child = spawn(process.execPath, [serverFile], {
        cwd: path.dirname(serverFile),
        env: {
          PATH: process.env.PATH,
          HOST: '127.0.0.1',
          PORT: freePortSync(),
          GOBLIN_DATA_DIR: directory,
          GOBLIN_PASSWORD: password,
          ...env,
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      t.after(() => child.kill('SIGKILL'));
      let output = '';
      child.stdout.on('data', chunk => (output += chunk));
      child.stderr.on('data', chunk => (output += chunk));
      await until(() => /Uptime Goblin is ready/.test(output), {
        what: 'the start',
        timeoutMs: 30000,
      });
      const environ = fs.readFileSync(`/proc/${child.pid}/environ`);
      child.kill('SIGTERM');
      await new Promise(resolve => child.once('exit', resolve));
      return { environ, output };
    };
    const fromFile = await environOf({ GOBLIN_SECRET_KEY_FILE: keyFile });
    assert.equal(fromFile.environ.includes(Buffer.from(key)), false);
    assert.match(fromFile.output, /Encryption key: GOBLIN_SECRET_KEY_FILE \(/);
    // The documented limit: the variable is removed from process.env, not from /proc.
    const fromEnv = await environOf({ GOBLIN_SECRET_KEY: key });
    assert.equal(fromEnv.environ.includes(Buffer.from(key)), true);
    assert.match(fromEnv.output, /Encryption key: GOBLIN_SECRET_KEY · fingerprint [0-9a-f]{16}/);
    assert.match(fromEnv.output, /\/proc\/<pid>\/environ still shows/);
    assert.equal(fromEnv.output.includes(key), false, 'the key is never printed');
  }
);

test('restored data never sends what waited before: rows become stale, events are marked', async t => {
  let answer = 500;
  const hook = await receiver(t, () => answer);
  const directory = temporary(t);
  const first = await start(t, { directory, webhook: hook.url });
  t.mock.method(console, 'warn', () => {});
  await first.fire('plex');
  await until(() => hook.requests.length >= 1);
  // Without history.sqlite: a restore keeps history as it is, so the event below stays.
  const snapshot = await createSnapshot(directory, { reason: 'manual', release, history: false });
  await first.app.close();
  // An alert change history still has to relay (written while stopped, relayed = 0).
  const history = new DatabaseSync(path.join(directory, 'history.sqlite'));
  history
    .prepare(
      'INSERT INTO events(service, time, kind, message, category, rule, since, uid, relayed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)'
    )
    .run(
      'sonarr',
      Date.now(),
      'firing',
      'Source is unavailable',
      'availability',
      '__availability',
      Date.now(),
      'e_' + 'r'.repeat(26)
    );
  history.close();
  const lock = acquireLock(directory);
  try {
    await restoreSnapshot(directory, snapshot.id, { lock, release });
  } finally {
    lock.release();
  }
  answer = 200;
  const before = hook.requests.length;
  const second = await start(t, { directory, webhook: hook.url });
  await second.app.flushNotifications();
  await sleep(500);
  assert.equal(hook.requests.length, before, 'nothing old was sent');
  const row = (await deliveries(second.call)).find(r => r.alert.service === 'plex');
  assert.equal(row.state, 'stale');
  assert.equal(row.status, 'not-sent');
  assert.match(row.lastError, /different file than before/);
  const check = new DatabaseSync(path.join(directory, 'history.sqlite'), { readOnly: true });
  try {
    assert.equal(
      check.prepare('SELECT relayed FROM events WHERE uid = ?').get('e_' + 'r'.repeat(26)).relayed,
      1
    );
  } finally {
    check.close();
  }
});

test('a canary secret never appears in an answer, the outbox, the log or the audit records', async t => {
  const canary = {
    mail: mailPassword,
    token: 'webhook-token-canary-0002',
    key: randomBytes(32).toString('hex'),
  };
  const hook = await receiver(t, () => 200, { path: `/hook?token=${canary.token}` });
  const mail = mailbox();
  const output = [];
  for (const level of ['log', 'info', 'warn', 'error'])
    t.mock.method(console, level, (...args) => output.push(args.join(' ')));
  const events = [];
  process.env.GOBLIN_SECRET_KEY = canary.key;
  t.after(() => delete process.env.GOBLIN_SECRET_KEY);
  const { app, call, fire, recover, directory } = await start(t, {
    webhook: hook.url,
    mail,
    delivery: { onEvent: record => events.push(record) },
  });
  assert.equal(process.env.GOBLIN_SECRET_KEY, undefined, 'the key left the environment');
  await fire('plex');
  await recover('plex');
  await app.flushNotifications();
  await until(() => hook.requests.length === 2);
  // The private signing keys (the first and the one the rotation makes): as PEM, its body and
  // the raw seed in base64, base64url and hex.
  const privateKey = async () =>
    (await app.control.settings.get('notify', 'envWebhook')).value.signingKey;
  const first = await privateKey();
  assert.equal(
    (await call('/api/notifications/webhook/signing-secret', 'POST', {})).status,
    200,
    'a rotation'
  );
  const second = await privateKey();
  const keyForms = {};
  for (const [name, key] of Object.entries({ first, second })) {
    assert.match(key, /^-----BEGIN PRIVATE KEY-----\n/);
    const seed = Buffer.from(createPrivateKey(key).export({ format: 'jwk' }).d, 'base64url');
    Object.assign(keyForms, {
      [`${name}Pem`]: key,
      [`${name}Body`]: key.split('\n')[1],
      [`${name}SeedBase64`]: seed.toString('base64'),
      [`${name}SeedBase64url`]: seed.toString('base64url'),
      [`${name}SeedHex`]: seed.toString('hex'),
    });
  }
  const answers = [];
  for (const route of [
    '/api/dashboard',
    '/api/system',
    '/api/notifications',
    '/api/notifications/deliveries',
    '/api/notifications/deliveries?filter=delivered',
    '/api/notifications/webhook/public-key',
  ])
    answers.push(JSON.stringify((await call(route)).body));
  // The audit log (audit spec §9.3): its list and export answers, and every row it keeps.
  for (const route of ['/api/audit?limit=500', '/api/audit?outcome=attempt&limit=500'])
    answers.push(JSON.stringify((await call(route)).body));
  answers.push(JSON.stringify((await call('/api/audit/export?format=ndjson')).body));
  const control = new DatabaseSync(path.join(directory, 'control.sqlite'), { readOnly: true });
  let outbox, auditLog;
  try {
    outbox = JSON.stringify(control.prepare('SELECT * FROM alerting_outbox').all());
    outbox += JSON.stringify(control.prepare('SELECT * FROM alerting_channel_status').all());
    auditLog = ['audit_log', 'audit_inbox', 'audit_checkpoints', 'audit_head', 'meta']
      .map(table => JSON.stringify(control.prepare(`SELECT * FROM ${table}`).all()))
      .join('\n');
  } finally {
    control.close();
  }
  // The audit's lines (mirror, checkpoints, audit.unwritten) are in `output`: they go to the
  // console like every other log line.
  const places = {
    answers: answers.join('\n'),
    outbox,
    log: output.join('\n'),
    audit: JSON.stringify(events),
    auditLog,
  };
  for (const [where, text] of Object.entries(places))
    for (const [name, value] of Object.entries({ ...canary, ...keyForms }))
      assert.equal(text.includes(value), false, `${name} in ${where}`);
  assert.doesNotMatch(places.answers, /PRIVATE KEY/);
  assert.match(places.answers, /PUBLIC KEY/, 'the public-key answer was searched');
  // Not even the URL's host and port beyond the host name.
  assert.equal(places.answers.includes(hook.url), false);
  assert.ok(
    events.some(record => record.action === 'signing.rotate'),
    'the rotation is audited'
  );
});

test('30 public-key reads at once as the first Basic requests after start all answer the same key; the reveal route is gone', async t => {
  // Concurrent legacy-Basic requests share one password check and resume together. The public
  // key is public material, so nothing limits or logs reading it.
  const output = [];
  for (const level of ['log', 'info', 'warn', 'error'])
    t.mock.method(console, level, (...args) => output.push(args.join(' ')));
  const hook = await receiver(t);
  const { call } = await start(t, { webhook: hook.url });
  const route = '/api/notifications/webhook/public-key';
  const answers = await Promise.all(Array.from({ length: 30 }, () => call(route)));
  assert.deepEqual(
    answers.map(answer => answer.status),
    Array(30).fill(200)
  );
  assert.equal(new Set(answers.map(answer => answer.body.keyId)).size, 1);
  assert.equal(new Set(answers.map(answer => answer.body.publicKey)).size, 1);
  assert.equal(output.filter(line => /was shown/.test(line)).length, 0);
  // The reveal of the pre-release builds answers as any unknown route does.
  const unknown = await call('/api/notifications/webhook/no-such-route', 'POST', {});
  for (const method of ['POST', 'GET']) {
    const gone = await call(
      '/api/notifications/webhook/signing-secret/reveal',
      method,
      method === 'POST' ? {} : undefined
    );
    assert.deepEqual([gone.status, gone.body], [unknown.status, unknown.body], method);
  }
  assert.equal(unknown.status, 404);
});

test('an email the mail server never confirms is sent once more, 5 minutes after the next start, with its Message-ID', async t => {
  // The email part of delivery spec §8.2 item 2, in process on a fake clock: the message is
  // handed over and never confirmed (the 300 ms deadline ends it as "unknown"), Uptime Goblin stops,
  // starts again, and only after 5 more minutes is the same batch sent again.
  const clock = fakeClock();
  let hang = true;
  const mail = mailbox({ fail: () => (hang ? 'hang' : null) });
  const directory = temporary(t);
  t.mock.method(console, 'warn', () => {});
  t.mock.method(console, 'error', () => {});
  const first = await start(t, {
    directory,
    mail,
    emailTimeoutMs: 300,
    // The worker's idle look every 5 s of fake time, so advancing minutes runs few timers.
    delivery: { clock, pollMs: 5000 },
  });
  await first.fire('plex');
  await first.app.flushNotifications();
  assert.equal(mail.attempts.length, 1);
  assert.equal(mail.messages.length, 0);
  const [{ messageId }] = mail.attempts;
  assert.match(messageId, /^<orbit\.g_[a-z2-7]{26}@example\.test>$/);
  await first.app.close();
  hang = false;
  const second = await start(t, {
    directory,
    mail,
    emailTimeoutMs: 300,
    delivery: { clock, pollMs: 5000 },
  });
  await sleep(300);
  await clock.advance(60 * 1000);
  assert.equal(mail.attempts.length, 1, 'not sent again at once');
  await clock.advance(5 * 60 * 1000);
  await until(() => mail.messages.length === 1, { what: 'the resend' });
  assert.equal(mail.attempts.length, 2);
  assert.equal(mail.messages[0].messageId, messageId, 'the same Message-ID');
  await clock.advance(30 * 60 * 1000);
  await sleep(100);
  assert.equal(mail.attempts.length, 2, 'once only');
  const [row] = await deliveries(second.call, '?channel=email');
  assert.equal(row.status, 'delivered');
});

test('an idle Uptime Goblin writes nothing to control.sqlite but each job’s first status (D21, D20)', async t => {
  // Acceptance check 10 in short: with nothing to deliver the worker, the relay sweep and the
  // storage guard only read; job status is written when it changes or every 5 minutes, so in
  // 25 s each job that ran writes its status once. Every write goes through control.db.write.
  const hook = await receiver(t);
  const { app } = await start(t, { webhook: hook.url, delivery: { pollMs: 5000 } });
  await sleep(1000);
  const writes = [];
  const write = app.control.db.write.bind(app.control.db);
  app.control.db.write = (fn, options) => {
    writes.push(new Error('write').stack.split('\n').slice(2, 6).join(' | '));
    return write(fn, options);
  };
  await sleep(25000);
  const names = app.jobs
    .status()
    .filter(job => job.runs > 0)
    .map(job => job.name);
  assert.ok(names.includes('storage.guard') && names.includes('notify.relay'), names.join(','));
  assert.ok(
    writes.length <= names.length,
    `${writes.length} writes for ${names.length} jobs that ran:\n${writes.join('\n')}`
  );
  assert.equal(hook.requests.length, 0);
});

test('SIGKILL while a webhook request is in flight: the next start resends it once, after 2 minutes', async t => {
  // Real processes (delivery spec §8.2 item 2): no seam shortens the resend delay.
  let hold = true;
  const hook = await receiver(t, () => (hold ? 'hold' : 200));
  const directory = temporary(t);
  const env = {
    PATH: process.env.PATH,
    HOST: '127.0.0.1',
    PORT: freePortSync(),
    GOBLIN_DATA_DIR: directory,
    GOBLIN_PASSWORD: password,
    GOBLIN_WEBHOOK_URL: hook.url,
    // The test drives the API as a script (Basic), which a new directory turns off (G2).
    GOBLIN_LEGACY_BASIC: '1',
  };
  const spawnOrbit = () => {
    const child = spawn(process.execPath, [serverFile], {
      cwd: path.dirname(serverFile),
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    t.after(() => child.kill('SIGKILL'));
    const state = { output: '', child };
    child.stdout.on('data', chunk => (state.output += chunk));
    child.stderr.on('data', chunk => (state.output += chunk));
    return state;
  };
  const basicHeaders = {
    Authorization: 'Basic ' + Buffer.from('admin:' + password).toString('base64'),
    'Content-Type': 'application/json',
    'X-Goblin-Request': '1',
  };
  const first = spawnOrbit();
  await until(() => /Uptime Goblin is ready at (\S+)/.test(first.output), {
    what: 'the first start',
    timeoutMs: 30000,
  });
  const url = /Uptime Goblin is ready at (\S+)/.exec(first.output)[1];
  // A source that cannot be reached fires at its first collection.
  const settings = await fetch(`${url}/api/settings`, {
    method: 'PATCH',
    headers: basicHeaders,
    body: JSON.stringify({
      monitoring: { availabilityFailures: 1, availabilitySeconds: 0, retryCount: 0 },
    }),
  });
  assert.equal(settings.status, 200);
  const source = await fetch(`${url}/api/services/linux`, {
    method: 'PATCH',
    headers: basicHeaders,
    body: JSON.stringify({ apiUrl: 'http://192.0.2.1:9' }),
  });
  assert.equal(source.status, 200);
  await fetch(`${url}/api/refresh`, { method: 'POST', headers: basicHeaders, body: '{}' });
  await until(() => hook.requests.length === 1, { what: 'the held request', timeoutMs: 60000 });
  first.child.kill('SIGKILL');
  await new Promise(resolve => first.child.once('exit', resolve));
  hold = false;
  const delivery = hook.requests[0].headers['x-goblin-delivery'];
  const second = spawnOrbit();
  await until(() => /Uptime Goblin is ready/.test(second.output), {
    what: 'the second start',
    timeoutMs: 30000,
  });
  const startedAt = Date.now();
  await until(() => hook.requests.length === 2, {
    what: 'the resend',
    timeoutMs: 150000,
  });
  const after = (hook.requests[1].receivedAt - startedAt) / 1000;
  assert.ok(after >= 115 && after <= 140, `resent ${after} s after the start`);
  assert.equal(hook.requests[1].headers['x-goblin-delivery'], delivery);
  await sleep(40000);
  assert.equal(hook.requests.length, 2, 'no third request');
  second.child.kill('SIGTERM');
  await new Promise(resolve => second.child.once('exit', resolve));
});
