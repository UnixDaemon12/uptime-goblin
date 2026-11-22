// Durable delivery across upgrades and rollbacks (delivery spec §9.1), with real processes:
// 1.4.2 (from test/fixtures), 1.4.3 (tag v1.4.3) and the sessions milestone (1.5.0-dev.0, from
// the private history, test/upgrade/history.mjs) against the working tree (WT),
// on one data directory, with a webhook receiver W and an implicit-TLS SMTP server S whose
// throwaway certificate every release trusts through NODE_EXTRA_CA_CERTS. Email digests are
// flushed by a clean stop (SIGTERM), so no test waits for a 60 s window. Skips like the other
// upgrade suites unless TEST_REQUIRE=fixtures (and, for the releases from the private history,
// TEST_REQUIRE=history).
//
//   U1/U2  1.4.2 / 1.4.3 → WT: nothing old is sent; the next recovery is signed and sent once.
//   U3     sessions milestone → WT: the outbox step migrates; the session survives.
//   R1/R2  WT with a failing receiver and a refused email → 1.4.3 / 1.4.2: they send nothing of
//          WT's and leave control.sqlite alone, and send their own alerts.
//   F1/F2  after R1 → WT: the waiting firing goes once, the held email through the start probe;
//          a row past its expiry ends expired without a request.
//   F3     a recovery 1.4.3 sent supersedes WT's old firing.
//   F4     WT pauses email, 1.4.3 switches email off, WT again: W hears once that email works
//          again (no probe could end that pause), and the email channel ends ok.
//   K1     SIGKILL during a send: the same delivery id once more after D30's 2 minutes.
//   K1+F3  SIGKILL during a send, then 1.4.3 sends the recovery: WT's firing, left 'sending', is
//          superseded at the next start and never sent after that recovery.
//   K1e    SIGKILL during an SMTP send: the same Message-ID once more after 5 minutes, and
//          nothing recorded as sent before the kill (email or webhook) is sent again.
//   P1     WT → restore-snapshot of the pinned pre-upgrade snapshot → 1.4.3 → WT: the waiting
//          notification is gone with control.sqlite, and the signing key is a new one.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { DatabaseSync } from 'node:sqlite';
import { installRelease, installTag, skipWithoutFixtures, skipWithoutTag } from './fixtures.mjs';
import {
  endpoint,
  login,
  readHistory,
  sessionRequest,
  start,
  temporary,
  waitFor,
  workingTree,
} from './harness.mjs';
import { webhookReceiver } from '../helpers/webhook-receiver.mjs';
import { smtpServer } from '../helpers/smtp.mjs';
import { verifyWebhookSignature } from '../../lib/notify/sign.mjs';
import { listSnapshots } from '../../lib/db/snapshot.mjs';

const working = JSON.parse(fs.readFileSync(path.join(workingTree, 'package.json'), 'utf8')).version;
const sender = 'orbit@example.test';
const orbitMessageId = /^<orbit\.g_[a-z2-7]{26}@example\.test>$/;
const deliveryId = /^d_[a-z2-7]{26}$/;

// A release fixture is named by its version alone; a milestone's version has a pre-release part.
const fixture = release => /^\d+\.\d+\.\d+$/.test(release);
/** A release's app directory: '1.4.2' from the fixtures, 'v1.4.3' or a milestone from the history. */
function install(t, release) {
  const directory = path.join(temporary(t, 'orbit-delivery-app-'), 'app');
  return fixture(release) ? installRelease(release, directory) : installTag(release, directory);
}
const skipFor = (t, release) =>
  fixture(release) ? skipWithoutFixtures(t) : skipWithoutTag(t, release);
// The sessions milestone, by its version (the private history gives its commit).
const sessions = '1.5.0-dev.0';

// What a release's settings validation knows (older releases refuse unknown keys).
const supports = (app, key) =>
  fs.readFileSync(path.join(app, 'lib/config.mjs'), 'utf8').includes(`'${key}'`);

/**
 * A test world: one data directory, W, S and a source endpoint whose health the test sets per
 * path (`health[name] = false` answers 503). `env(extra)` is what every release starts with.
 */
async function world(t, { respond, authFails = false } = {}) {
  const directory = temporary(t, 'orbit-delivery-'),
    data = path.join(directory, 'data');
  const health = {};
  const site = await endpoint(t, pathname =>
    health[pathname.slice(1)] === false ? [503, 'down'] : 'ok'
  );
  const hook = await webhookReceiver(t, { respond: (request, n) => respond?.(request, n) ?? 200 });
  // `hold`: S reads a whole message and never answers it (a send Orbit cannot confirm).
  const smtpState = { authFails, hold: false };
  const smtp = await smtpServer(t, {
    authFails: (user, pass) =>
      typeof smtpState.authFails === 'function'
        ? smtpState.authFails(user, pass)
        : smtpState.authFails,
    holdAfterData: message => smtpState.hold === true || smtpState.hold === message.messageId,
  });
  const env = (extra = {}) => ({
    ORBIT_WEBHOOK_URL: hook.url,
    NODE_EXTRA_CA_CERTS: smtp.caFile,
    ...extra,
  });
  return { directory, data, health, site, hook, smtp, smtpState, env };
}

/** Settings every release accepts: alert at the first failure, recover at the first success. */
async function configure(running, app, { smtp, email = true, password = 'first-app-password' }) {
  const monitoring = { availabilityFailures: 1, availabilitySeconds: 0, timeoutSeconds: 5 };
  for (const [key, value] of [
    ['retryCount', 0],
    ['recoverySuccesses', 1],
    ['recoverySeconds', 0],
  ])
    if (supports(app, key)) monitoring[key] = value;
  const body = { monitoring };
  if (email)
    body.email = {
      enabled: true,
      host: '127.0.0.1',
      port: smtp.port,
      secure: true,
      from: sender,
      to: 'dana@example.test',
      password,
    };
  const response = await running.request('PATCH', '/api/settings', { body });
  assert.equal(response.status, 200, response.text);
}
async function addSource(running, w, name) {
  w.health[name] ??= true;
  const response = await running.request('POST', '/api/services', {
    body: { type: 'http', name, group: 'Delivery', apiUrl: `${w.site}/${name}`, pollSeconds: 15 },
  });
  assert.equal(response.status, 201, response.text);
  return response.json.service.id;
}
// Polls now (coalesced to one in 5 s by every release), then waits for the alert state.
async function settle(running, check, what) {
  await waitFor(
    async () => {
      await running.request('POST', '/api/refresh');
      const dashboard = await running.dashboard();
      return check(dashboard);
    },
    what,
    60000
  );
}
const firing = id => dashboard => dashboard.alerts.some(alert => alert.service === id);
const resolved = id => dashboard => !dashboard.alerts.some(alert => alert.service === id);

const bodiesFor = (hook, id) =>
  hook.requests
    .map(request => ({ ...request, json: JSON.parse(request.body) }))
    .filter(request => request.json.service === id);
const signed = request => typeof request.headers['x-orbit-delivery'] === 'string';
const orbitMail = message => orbitMessageId.test(message.messageId ?? '');

/** Every control.sqlite* file's SHA-256 (what a release that must not touch it leaves alone). */
function controlHashes(data) {
  return Object.fromEntries(
    fs
      .readdirSync(data)
      .filter(name => name.startsWith('control.sqlite'))
      .map(name => [
        name,
        createHash('sha256')
          .update(fs.readFileSync(path.join(data, name)))
          .digest('hex'),
      ])
  );
}
/** Reads control.sqlite after Orbit stopped. */
function readControl(data, query, ...params) {
  const db = new DatabaseSync(path.join(data, 'control.sqlite'), { readOnly: true });
  try {
    return db.prepare(query).all(...params);
  } finally {
    db.close();
  }
}
/** history.sqlite's `events` columns and indexes (name and SQL), read after Orbit stopped. */
function eventsSchema(data) {
  const db = new DatabaseSync(path.join(data, 'history.sqlite'), { readOnly: true });
  try {
    return {
      columns: db
        .prepare('PRAGMA table_info(events)')
        .all()
        .map(column => column.name),
      indexes: db
        .prepare("SELECT name, sql FROM sqlite_master WHERE type = 'index' AND tbl_name = 'events'")
        .all()
        .map(index => ({ name: index.name, sql: index.sql })),
    };
  } finally {
    db.close();
  }
}
const outboxRows = data =>
  readControl(data, 'SELECT * FROM alerting_outbox ORDER BY id').map(row => ({
    ...row,
    event: JSON.parse(row.event),
  }));

/** The webhook's public signing key, PEM (a session, as the web app asks for it). */
async function publicKey(running) {
  const cookie = await login(running.port);
  const read = await sessionRequest(running.port, 'GET', '/api/notifications/webhook/public-key', {
    cookie,
  });
  assert.equal(read.status, 200, read.text);
  return { publicKey: read.json.publicKey, cookie };
}
async function deliveries(running, cookie) {
  const answer = await sessionRequest(
    running.port,
    'GET',
    '/api/notifications/deliveries?filter=all&limit=100',
    { cookie }
  );
  assert.equal(answer.status, 200, answer.text);
  return answer.json.deliveries;
}

describe('durable delivery across upgrades and rollbacks', { concurrency: 4 }, () => {
  for (const [row, release] of [
    ['U1', '1.4.2'],
    ['U2', 'v1.4.3'],
  ])
    it(`${row}: ${release} → WT sends nothing old; the next recovery is signed and sent once`, async t => {
      if (skipFor(t, release)) return;
      const w = await world(t);
      const app = install(t, release);
      // 1. The old release: a source fails, the firing goes to W at once and to S at its stop.
      const old = await start(t, { app, data: w.data, env: w.env() });
      await configure(old, app, { smtp: w.smtp });
      const x = await addSource(old, w, 'x');
      w.health.x = false;
      await settle(old, firing(x), `${release} to fire`);
      await waitFor(() => bodiesFor(w.hook, x).length === 1, 'the old firing at W');
      assert.equal((await old.stop()).code, 0, old.output());
      assert.equal(w.smtp.messages.length, 1, 'the old release flushed its email at its stop');
      assert.ok(!orbitMail(w.smtp.messages[0]));
      const before = {
        config: fs.readFileSync(path.join(w.data, 'config.json')),
        auth: fs.existsSync(path.join(w.data, 'auth.json'))
          ? fs.readFileSync(path.join(w.data, 'auth.json'))
          : null,
        events: readHistory(w.data).events,
        schema: eventsSchema(w.data),
        requests: w.hook.requests.length,
        mails: w.smtp.sessions.length,
      };

      // 2. WT on the same data: nothing during its start, nor 5 s after.
      const current = await start(t, { app: workingTree, data: w.data, env: w.env() });
      await delay(5000);
      assert.equal(w.hook.requests.length, before.requests, 'no webhook request at the start');
      assert.equal(w.smtp.sessions.length, before.mails, 'no SMTP connection at the start');
      assert.match(current.output(), /secret\.key is inside the data directory/);
      assert.match(
        current.output(),
        /^Encryption key: a new .*secret\.key \(generated now\) · fingerprint [0-9a-f]{16}$/m
      );
      assert.ok(fs.existsSync(path.join(w.data, 'secret.key')));
      // The recovery: one resolved, signed over its delivery id, the time and the body.
      w.health.x = true;
      await settle(current, resolved(x), 'WT to resolve');
      await waitFor(
        () => bodiesFor(w.hook, x).some(request => request.json.kind === 'resolved'),
        'the resolved at W'
      );
      await delay(2000);
      const sent = bodiesFor(w.hook, x).slice(1);
      assert.equal(sent.length, 1, 'exactly one request from WT');
      const [recovery] = sent;
      assert.equal(recovery.json.kind, 'resolved');
      assert.deepEqual(Object.keys(recovery.json), [
        'source',
        'service',
        'name',
        'kind',
        'category',
        'rule',
        'message',
        'time',
      ]);
      const id = recovery.headers['x-orbit-delivery'];
      assert.match(id, deliveryId);
      const { publicKey: key } = await publicKey(current);
      assert.deepEqual(
        verifyWebhookSignature(key, recovery.body, recovery.headers['x-orbit-signature'], {
          deliveryId: id,
          nowMs: recovery.receivedAt,
        }),
        { ok: true }
      );
      assert.equal(
        verifyWebhookSignature(key, recovery.body, recovery.headers['x-orbit-signature'], {
          deliveryId: 'd_aaaaaaaaaaaaaaaaaaaaaaaaaa',
          nowMs: recovery.receivedAt,
        }).ok,
        false
      );
      // One email at WT's stop, with Orbit's Message-ID.
      assert.equal((await current.stop()).code, 0, current.output());
      const mails = w.smtp.messages.slice(1);
      assert.equal(mails.length, 1, 'one digest at the stop');
      assert.match(mails[0].messageId, orbitMessageId);
      // The old release's rows were never relayed or rewritten; its files are as they were.
      const events = readHistory(w.data).events;
      for (const event of before.events) {
        const now = events.find(item => item.id === event.id);
        assert.deepEqual([now.uid, now.relayed], [null, null], `event ${event.id}`);
      }
      assert.deepEqual(fs.readFileSync(path.join(w.data, 'config.json')), before.config);
      if (before.auth)
        assert.deepEqual(fs.readFileSync(path.join(w.data, 'auth.json')), before.auth);
      const tables = readControl(w.data, "SELECT name FROM sqlite_master WHERE type='table'").map(
        item => item.name
      );
      assert.ok(tables.includes('alerting_outbox') && tables.includes('alerting_channel_status'));
      assert.equal(readControl(w.data, 'SELECT kid FROM keyring').length, 4);
      assert.ok(outboxRows(w.data).every(item => item.state === 'delivered'));
      // What WT adds to the history 1.4.3 left, as the upgrade notes say: three columns and a
      // partial index on events, nothing else (they once said 1.5 did not change it).
      if (release === 'v1.4.3') {
        const schema = eventsSchema(w.data);
        assert.deepEqual(
          schema.columns.filter(name => !before.schema.columns.includes(name)),
          ['since', 'uid', 'relayed']
        );
        assert.deepEqual(
          schema.indexes.filter(
            index => !before.schema.indexes.some(earlier => earlier.name === index.name)
          ),
          [
            {
              name: 'events_unrelayed',
              sql: 'CREATE INDEX events_unrelayed ON events(id) WHERE relayed = 0',
            },
          ]
        );
        const notes = fs.readFileSync(path.join(workingTree, 'docs/installation.md'), 'utf8');
        assert.match(
          notes,
          /1\.5 only adds to `history\.sqlite`: three columns and a partial index on its `events` table/
        );
      }
    });

  it('U3: the sessions milestone → WT migrates the outbox step; the session cookie still works', async t => {
    if (skipFor(t, sessions)) return;
    const w = await world(t);
    const app = install(t, sessions);
    const milestone = await start(t, { app, data: w.data, env: w.env() });
    const cookie = await login(milestone.port);
    assert.equal(
      (await sessionRequest(milestone.port, 'GET', '/api/session', { cookie })).status,
      200
    );
    await configure(milestone, app, { smtp: w.smtp, email: false });
    const x = await addSource(milestone, w, 'x');
    assert.equal((await milestone.stop()).code, 0, milestone.output());
    assert.equal(readControl(w.data, 'SELECT kid FROM keyring').length, 0, 'no keyring yet (D2)');

    const current = await start(t, {
      app: workingTree,
      data: w.data,
      env: w.env(),
      port: milestone.port,
    });
    const applied = readControl(w.data, 'SELECT id FROM schema_migrations').map(item => item.id);
    assert.ok(applied.includes('alerting-001-outbox'), applied.join(', '));
    const snapshot = listSnapshots(w.data).find(item => item.release === working);
    assert.deepEqual(
      [snapshot?.reason, snapshot?.fromRelease],
      ['pre-upgrade', '1.5.0-dev.0'],
      'a pre-upgrade snapshot of the milestone data'
    );
    assert.equal(
      (await sessionRequest(current.port, 'GET', '/api/session', { cookie })).status,
      200,
      'the session survives'
    );
    w.health.x = false;
    await settle(current, firing(x), 'WT to fire');
    await waitFor(() => bodiesFor(w.hook, x).length === 1, 'the firing at W');
    assert.match(bodiesFor(w.hook, x)[0].headers['x-orbit-delivery'], deliveryId);
    assert.equal((await current.stop()).code, 0, current.output());
    assert.equal(readControl(w.data, 'SELECT kid FROM keyring').length, 4, 'the keyring');
  });

  // R1/R2, and F1/F2 after R1: WT with W answering 500 and S refusing sign-in, then a rollback.
  for (const [row, release, forward] of [
    ['R1', 'v1.4.3', true],
    ['R2', '1.4.2', false],
  ])
    it(`${row}: WT → ${release} sends nothing of WT's${forward ? ', then F1/F2: WT again sends the waiting firing once and the held email through its start probe' : ''}`, async t => {
      if (skipFor(t, release)) return;
      const state = { webhook: 500 };
      const w = await world(t, { respond: () => state.webhook, authFails: true });
      // WT first (a new install), with a failing receiver and a refused email sign-in.
      const current = await start(t, { app: workingTree, data: w.data, env: w.env() });
      await configure(current, workingTree, { smtp: w.smtp });
      const x = await addSource(current, w, 'x'),
        z = await addSource(current, w, 'z');
      w.health.x = w.health.z = false;
      await settle(
        current,
        dashboard => firing(x)(dashboard) && firing(z)(dashboard),
        'WT to fire'
      );
      await waitFor(
        () => bodiesFor(w.hook, x).length >= 1 && bodiesFor(w.hook, z).length >= 1,
        'the first attempts at W'
      );
      // The stop flushes the email digest: its sign-in is refused and the email channel pauses.
      assert.equal((await current.stop()).code, 0, current.output());
      assert.ok(w.smtp.sessions.length >= 1, 'WT tried email at its stop');
      assert.equal(w.smtp.messages.length, 0);
      const waiting = outboxRows(w.data);
      const alerts = waiting.filter(item => item.event.service !== 'orbit');
      assert.deepEqual(alerts.map(item => [item.channel_id, item.state]).sort(), [
        ['email', 'held'],
        ['email', 'held'],
        ['env-webhook', 'queued'],
        ['env-webhook', 'queued'],
      ]);
      // The pause notice (D28) waits on the other channel, the failing webhook.
      const notices = waiting.filter(item => item.event.service === 'orbit');
      assert.deepEqual(
        notices.map(item => [item.channel_id, item.state, item.kind, item.event.rule]),
        [['env-webhook', 'queued', 'firing', '__channel_email']]
      );
      const control = controlHashes(w.data);

      // The rollback: W and S healthy for it; it starts, answers Basic, and sends only its own.
      state.webhook = 200;
      w.smtpState.authFails = false;
      const requestsBefore = w.hook.requests.length,
        mailsBefore = w.smtp.messages.length;
      const app = install(t, release);
      const old = await start(t, { app, data: w.data, env: w.env() });
      assert.equal((await old.request('GET', '/api/dashboard')).status, 200);
      const y = await addSource(old, w, 'y');
      w.health.y = false;
      await settle(old, firing(y), `${release} to fire`);
      await waitFor(() => bodiesFor(w.hook, y).length === 1, `${release}'s own firing at W`);
      if (forward) {
        // F1: the email password is changed under 1.4.3 (the new one is the one S accepts).
        const changed = await old.request('PATCH', '/api/settings', {
          body: { email: { password: 'second-app-password' } },
        });
        assert.equal(changed.status, 200, changed.text);
      }
      assert.equal((await old.stop()).code, 0, old.output());
      const during = w.hook.requests.slice(requestsBefore);
      assert.ok(
        during.every(request => !signed(request)),
        'no WT request while rolled back'
      );
      assert.ok(
        during.every(request => JSON.parse(request.body).service === y),
        'only its own alerts'
      );
      const mails = w.smtp.messages.slice(mailsBefore);
      assert.equal(mails.length, 1, `${release} emailed its own alert at its stop`);
      assert.ok(!orbitMail(mails[0]));
      assert.deepEqual(controlHashes(w.data), control, `${release} left control.sqlite alone`);
      if (!forward) return;

      // F2: one waiting row has passed its expiry while Orbit was stopped.
      const expiring = waiting.find(
        item => item.channel_id === 'env-webhook' && item.event.service === z
      );
      const db = new DatabaseSync(path.join(w.data, 'control.sqlite'));
      db.prepare('UPDATE alerting_outbox SET expires_at = ? WHERE id = ?').run(
        Date.now() - 1000,
        expiring.id
      );
      db.close();
      w.smtpState.authFails = (user, pass) => pass !== 'second-app-password';
      const forwardRequests = w.hook.requests.length,
        forwardMails = w.smtp.messages.length;
      const again = await start(t, { app: workingTree, data: w.data, env: w.env() });
      // X's waiting firing reaches W once; nothing for Z (expired) and nothing of Y's again.
      await waitFor(
        () =>
          w.hook.requests
            .slice(forwardRequests)
            .some(request => JSON.parse(request.body).service === x),
        "X's waiting firing at W"
      );
      // The held email goes through the start probe, signed in with the new password; the
      // pause notice waiting for the webhook goes too, followed by its recovery (D28).
      await waitFor(() => w.smtp.messages.length > forwardMails, 'the held email at S', 60000);
      const noticeKinds = () =>
        w.hook.requests
          .slice(forwardRequests)
          .map(request => JSON.parse(request.body))
          .filter(body => body.service === 'orbit')
          .map(body => body.kind);
      await waitFor(
        () => noticeKinds().join() === 'firing,resolved',
        'the pause notice and its recovery at W',
        60000
      );
      await delay(3000);
      assert.deepEqual(noticeKinds(), ['firing', 'resolved']);
      const resent = w.hook.requests
        .slice(forwardRequests)
        .filter(request => JSON.parse(request.body).service !== 'orbit');
      assert.equal(resent.length, 1, resent.map(request => request.body).join('\n'));
      assert.equal(
        resent[0].headers['x-orbit-delivery'],
        waiting.find(item => item.channel_id === 'env-webhook' && item.event.service === x).uid
      );
      const probe = w.smtp.messages.slice(forwardMails);
      assert.equal(probe.length, 1);
      assert.match(probe[0].messageId, orbitMessageId);
      assert.ok(w.smtp.sessions.some(session => session.auth?.pass === 'second-app-password'));
      const { cookie } = await publicKey(again);
      const listed = await deliveries(again, cookie);
      const expired = listed.find(item => item.uid === expiring.uid);
      assert.equal(expired?.status, 'expired');
      assert.equal((await again.stop()).code, 0, again.output());
      const rows = outboxRows(w.data);
      for (const item of rows.filter(item => item.uid !== expiring.uid))
        assert.equal(item.state, 'delivered', `${item.channel_id} ${item.event.service}`);
      assert.deepEqual(
        [
          rows.find(item => item.uid === expiring.uid).state,
          rows.find(item => item.uid === expiring.uid).dead_reason,
        ],
        ['dead', 'expired']
      );
      assert.ok(
        !w.hook.requests
          .slice(forwardRequests)
          .some(request => JSON.parse(request.body).service === y),
        "Y's events, written by 1.4.3, are not sent again"
      );
    });

  it('F3: a recovery 1.4.3 sent supersedes the firing WT still had waiting', async t => {
    if (skipFor(t, 'v1.4.3')) return;
    const state = { webhook: 500 };
    const w = await world(t, { respond: () => state.webhook });
    const current = await start(t, { app: workingTree, data: w.data, env: w.env() });
    await configure(current, workingTree, { smtp: w.smtp, email: false });
    const x = await addSource(current, w, 'x');
    w.health.x = false;
    await settle(current, firing(x), 'WT to fire');
    await waitFor(() => bodiesFor(w.hook, x).length >= 1, 'the first attempt at W');
    assert.equal((await current.stop()).code, 0, current.output());
    const [waiting] = outboxRows(w.data);
    assert.equal(waiting.state, 'queued');
    // 1.4.3, with W healthy: X recovers, and 1.4.3 sends its own resolved.
    state.webhook = 200;
    const app = install(t, 'v1.4.3');
    const old = await start(t, { app, data: w.data, env: w.env() });
    w.health.x = true;
    await settle(old, resolved(x), '1.4.3 to resolve');
    await waitFor(
      () => bodiesFor(w.hook, x).some(request => request.json.kind === 'resolved'),
      "1.4.3's resolved at W"
    );
    assert.equal((await old.stop()).code, 0, old.output());
    const requests = w.hook.requests.length;
    // WT again: the old firing is superseded, unsent.
    const again = await start(t, { app: workingTree, data: w.data, env: w.env() });
    await delay(5000);
    assert.equal(w.hook.requests.length, requests, 'nothing from WT for X');
    assert.match(
      again.output(),
      /1 notifications? (were|was) not sent: Orbit 1\.4\.x handled a later change of their alerts/
    );
    const { cookie } = await publicKey(again);
    const replaced = (await deliveries(again, cookie)).find(item => item.uid === waiting.uid);
    assert.equal(replaced?.status, 'replaced');
    assert.equal(replaced.lastError, 'Not sent: Orbit 1.4.x handled a later change of this alert.');
    assert.equal(bodiesFor(w.hook, x).at(-1).json.kind, 'resolved', "W's last body is 1.4.3's");
    assert.ok(!signed(bodiesFor(w.hook, x).at(-1)));
    assert.equal((await again.stop()).code, 0, again.output());
    assert.equal(outboxRows(w.data)[0].state, 'superseded');
  });

  // Review round 4: email switched off under 1.4.x during a rollback can send nothing, so no
  // probe ended WT's pause; W kept "Email notifications are paused" firing for good, while the
  // same change made in WT itself sends "Email notifications are working again.".
  it('F4: WT pauses email, 1.4.3 switches email off, WT again: W hears once that email works again', async t => {
    if (skipFor(t, 'v1.4.3')) return;
    const w = await world(t, { authFails: true });
    const emailNotices = () =>
      w.hook.requests
        .map(request => JSON.parse(request.body))
        .filter(body => body.service === 'orbit' && body.rule === '__channel_email')
        .map(body => [body.kind, body.message]);
    const current = await start(t, { app: workingTree, data: w.data, env: w.env() });
    await configure(current, workingTree, { smtp: w.smtp });
    const x = await addSource(current, w, 'x');
    w.health.x = false;
    await settle(current, firing(x), 'WT to fire');
    await waitFor(() => bodiesFor(w.hook, x).length === 1, "X's firing at W");
    // The stop flushes the email digest: its sign-in is refused, email pauses, and W hears it.
    assert.equal((await current.stop()).code, 0, current.output());
    assert.deepEqual(emailNotices(), [
      [
        'firing',
        'Email notifications are paused: Email sign-in failed. Check the sender address and Gmail app password.',
      ],
    ]);
    // The rollback: 1.4.3 switches email off.
    const app = install(t, 'v1.4.3');
    const old = await start(t, { app, data: w.data, env: w.env() });
    const off = await old.request('PATCH', '/api/settings', {
      body: { email: { enabled: false } },
    });
    assert.equal(off.status, 200, off.text);
    assert.equal((await old.stop()).code, 0, old.output());
    const mails = w.smtp.messages.length;
    // WT again: the pause ends at the start, as a settings save in WT ends it; W hears it once.
    const again = await start(t, { app: workingTree, data: w.data, env: w.env() });
    await waitFor(() => emailNotices().length === 2, 'the end of the email pause at W', 60000);
    await delay(5000);
    assert.deepEqual(emailNotices().at(-1), ['resolved', 'Email notifications are working again.']);
    assert.equal(emailNotices().length, 2);
    assert.equal(bodiesFor(w.hook, x).length, 1, 'nothing of X again');
    assert.equal(w.smtp.messages.length, mails, 'no email while it is switched off');
    assert.equal((await again.stop()).code, 0, again.output());
    assert.deepEqual(
      readControl(
        w.data,
        "SELECT state, paused_since FROM alerting_channel_status WHERE channel_id = 'email'"
      ).map(row => [row.state, row.paused_since]),
      [['ok', null]]
    );
    const held = outboxRows(w.data).filter(
      item => item.channel_id === 'email' && item.event.service === x
    );
    assert.deepEqual(
      held.map(item => [item.state, item.last_error]),
      [['skipped', 'Email alerts are switched off.']]
    );
  });

  it(
    'K1: killed during a send, the same delivery id goes once more after 2 minutes',
    { timeout: 400000 },
    async t => {
      if (skipWithoutFixtures(t)) return;
      const state = { hold: true };
      const w = await world(t, { respond: () => (state.hold ? 'hold' : 200) });
      const current = await start(t, { app: workingTree, data: w.data, env: w.env() });
      await configure(current, workingTree, { smtp: w.smtp, email: false });
      const x = await addSource(current, w, 'x');
      w.health.x = false;
      await settle(current, firing(x), 'WT to fire');
      const [first] = await w.hook.waitFor(1, { timeoutMs: 60000 });
      const id = first.headers['x-orbit-delivery'];
      assert.match(id, deliveryId);
      await current.kill();
      state.hold = false;
      w.hook.release(200);
      const spawned = Date.now();
      const again = await start(t, { app: workingTree, data: w.data, env: w.env() });
      const ready = Date.now();
      const [, second] = await w.hook.waitFor(2, { timeoutMs: 180000 });
      assert.equal(second.headers['x-orbit-delivery'], id, 'the same delivery id');
      assert.ok(
        second.receivedAt - spawned >= 115000,
        `${second.receivedAt - spawned} ms after the restart`
      );
      assert.ok(
        second.receivedAt - ready <= 140000,
        `${second.receivedAt - ready} ms after the start line`
      );
      await delay(40000);
      assert.equal(w.hook.requests.length, 2, 'no third request');
      assert.equal((await again.stop()).code, 0, again.output());
      assert.equal(outboxRows(w.data)[0].state, 'delivered');
    }
  );

  it(
    "K1+F3: killed during a send, then 1.4.3 sends the recovery: WT's firing is never sent after it",
    { timeout: 420000 },
    async t => {
      if (skipFor(t, 'v1.4.3')) return;
      const state = { hold: true };
      const w = await world(t, { respond: () => (state.hold ? 'hold' : 200) });
      const current = await start(t, { app: workingTree, data: w.data, env: w.env() });
      await configure(current, workingTree, { smtp: w.smtp, email: false });
      const x = await addSource(current, w, 'x');
      w.health.x = false;
      await settle(current, firing(x), 'WT to fire');
      const [first] = await w.hook.waitFor(1, { timeoutMs: 60000 });
      assert.match(first.headers['x-orbit-delivery'], deliveryId);
      await current.kill();
      state.hold = false;
      w.hook.release(200);
      const [left] = outboxRows(w.data);
      assert.equal(left.state, 'sending', 'killed during the send');
      // Rollback: 1.4.3 recovers x and sends its own resolved.
      const app = install(t, 'v1.4.3');
      const old = await start(t, { app, data: w.data, env: w.env() });
      w.health.x = true;
      await settle(old, resolved(x), '1.4.3 to resolve');
      await waitFor(
        () => bodiesFor(w.hook, x).some(request => request.json.kind === 'resolved'),
        "1.4.3's resolved at W"
      );
      assert.equal((await old.stop()).code, 0, old.output());
      const requests = w.hook.requests.length;
      // WT again: the firing it was sending is resolved as unknown, then superseded at once.
      const again = await start(t, { app: workingTree, data: w.data, env: w.env() });
      const ready = Date.now();
      await waitFor(
        () =>
          /1 notifications? (were|was) not sent: Orbit 1\.4\.x handled a later change of their alerts/.test(
            again.output()
          ),
        'the roll-forward line'
      );
      const { cookie } = await publicKey(again);
      const replaced = (await deliveries(again, cookie)).find(item => item.uid === left.uid);
      assert.deepEqual(
        [replaced?.status, replaced?.lastError],
        ['replaced', 'Not sent: Orbit 1.4.x handled a later change of this alert.']
      );
      // Past D30's 2-minute resend of an unconfirmed request: still nothing from WT for x.
      await delay(Math.max(0, ready + 145000 - Date.now()));
      assert.equal(w.hook.requests.length, requests, 'nothing from WT after 1.4.3’s recovery');
      assert.equal(bodiesFor(w.hook, x).at(-1).json.kind, 'resolved', "W's last body is 1.4.3's");
      assert.equal((await again.stop()).code, 0, again.output());
      const [row] = outboxRows(w.data);
      assert.deepEqual([row.uid, row.state, row.unknowns], [left.uid, 'superseded', 1]);
    }
  );

  it(
    'K1e: killed during an SMTP send, the same Message-ID goes once more after 5 minutes; nothing recorded as sent goes again',
    { timeout: 660000 },
    async t => {
      if (skipWithoutFixtures(t)) return;
      const w = await world(t);
      // 1. x fires: W accepts it at once, and its email goes at the clean stop. Both are
      //    recorded as sent.
      const first = await start(t, { app: workingTree, data: w.data, env: w.env() });
      await configure(first, workingTree, { smtp: w.smtp });
      const x = await addSource(first, w, 'x'),
        z = await addSource(first, w, 'z');
      w.health.x = false;
      await settle(first, firing(x), 'WT to fire x');
      await waitFor(() => bodiesFor(w.hook, x).length === 1, "x's firing at W");
      assert.equal((await first.stop()).code, 0, first.output());
      assert.equal(w.smtp.messages.length, 1, "x's email at the clean stop");
      const [accepted] = w.smtp.messages;
      assert.match(accepted.messageId, orbitMessageId);
      const sent = outboxRows(w.data);
      assert.deepEqual(sent.map(row => [row.channel_id, row.state]).sort(), [
        ['email', 'delivered'],
        ['env-webhook', 'delivered'],
      ]);

      // 2. z fires: W accepts it at once; its email goes when the digest's 60 s quiet window
      //    closes, and S reads the whole message and never answers. Orbit is killed meanwhile.
      w.smtpState.hold = true;
      const second = await start(t, { app: workingTree, data: w.data, env: w.env() });
      w.health.z = false;
      await settle(second, firing(z), 'WT to fire z');
      await waitFor(() => bodiesFor(w.hook, z).length === 1, "z's firing at W");
      await waitFor(() => w.smtp.held === 1, "z's email held by S", 150000);
      const held = w.smtp.messages[1];
      assert.match(held.messageId, orbitMessageId);
      assert.notEqual(held.messageId, accepted.messageId);
      await second.kill();

      // 3. The next start: S answers again. The unconfirmed email goes once more, with the same
      //    Message-ID, 5 minutes later (the email channel's rule for "acceptance unknown").
      w.smtpState.hold = false;
      const spawned = Date.now();
      const again = await start(t, { app: workingTree, data: w.data, env: w.env() });
      const ready = Date.now();
      await waitFor(() => w.smtp.messages.length >= 3, 'the unconfirmed email again', 420000);
      const resent = w.smtp.messages[2];
      assert.equal(resent.messageId, held.messageId, 'the same Message-ID');
      assert.ok(
        resent.receivedAt - spawned >= 290000,
        `${resent.receivedAt - spawned} ms after the restart`
      );
      assert.ok(
        resent.receivedAt - ready <= 340000,
        `${resent.receivedAt - ready} ms after the start line`
      );
      await delay(30000);
      assert.equal(w.smtp.messages.length, 3, 'no third email');
      assert.equal(
        w.smtp.messages.filter(message => message.messageId === accepted.messageId).length,
        1,
        "x's email, recorded as sent, is not sent again"
      );
      assert.equal(bodiesFor(w.hook, x).length, 1, "x's webhook request is not sent again");
      assert.equal(bodiesFor(w.hook, z).length, 1, "z's webhook request is not sent again");
      assert.equal((await again.stop()).code, 0, again.output());
      assert.equal(w.smtp.messages.length, 3, 'nothing more at the clean stop');
      const rows = outboxRows(w.data);
      for (const row of rows) assert.equal(row.state, 'delivered', `${row.channel_id} ${row.uid}`);
      for (const before of sent) {
        const after = rows.find(row => row.uid === before.uid);
        assert.deepEqual(
          [after.attempts, after.sent_at, after.updated_at],
          [before.attempts, before.sent_at, before.updated_at],
          `${before.channel_id} ${before.uid} unchanged`
        );
      }
      const unconfirmed = rows.find(row => row.channel_id === 'email' && row.event.service === z);
      assert.equal(`<orbit.${unconfirmed.digest_key}@example.test>`, held.messageId);
      assert.equal(unconfirmed.unknowns, 1, 'one resend for the unknown outcome');
    }
  );

  // Delivery spec A25 (review round 2). To go back to the data of before the upgrade, the
  // rollback docs restore the pinned pre-upgrade snapshot. It was taken before 1.5 created
  // control.sqlite, so the restore removes that file, and with it the waiting notifications and
  // the sealed signing key: those are neither sent nor listed after upgrading again, and the
  // next start makes a new key pair, which a receiver checking with the old public key rejects. The docs
  // had promised the waiting ones would be sent and said to turn the check back on.
  it('P1: WT → restore the pinned snapshot → 1.4.3 → WT: the waiting notification is gone, the signing key is new, and the restore says both', async t => {
    if (skipFor(t, 'v1.4.3')) return;
    const state = { webhook: 200 };
    const w = await world(t, { respond: () => state.webhook });
    const app = install(t, 'v1.4.3');
    const old = await start(t, { app, data: w.data, env: w.env() });
    await configure(old, app, { smtp: w.smtp, email: false });
    const x = await addSource(old, w, 'x');
    assert.equal((await old.stop()).code, 0, old.output());
    // WT with W answering 500: x fires, and its notification waits.
    state.webhook = 500;
    const current = await start(t, { app: workingTree, data: w.data, env: w.env() });
    w.health.x = false;
    await settle(current, firing(x), 'WT to fire');
    await waitFor(() => bodiesFor(w.hook, x).length >= 1, 'the first attempt at W');
    const { publicKey: before } = await publicKey(current);
    assert.equal((await current.stop()).code, 0, current.output());
    const waiting = outboxRows(w.data).filter(row => row.event.service === x);
    assert.ok(
      waiting.some(row => row.state === 'queued' && row.kind === 'firing'),
      JSON.stringify(waiting)
    );
    // The documented restore, with the 1.5 code: it says what goes with control.sqlite.
    const pinned = listSnapshots(w.data).find(item => item.pinned);
    const restored = spawnSync(
      process.execPath,
      [
        path.join(workingTree, 'lib/cli/orbit-admin.mjs'),
        'restore-snapshot',
        pinned.id,
        '--data-dir',
        w.data,
      ],
      { env: { PATH: process.env.PATH }, encoding: 'utf8' }
    );
    assert.equal(restored.status, 0, restored.stdout + restored.stderr);
    assert.match(restored.stdout, /^Removed \(absent in the snapshot\): control\.sqlite\.$/m);
    assert.match(
      restored.stdout,
      /^control\.sqlite held Uptime Goblin 1\.5's audit log, its sessions, its waiting notifications, its delivery history and the webhook signing key\. The audit log starts again, empty, at the next start, and Check integrity will list no restore: the old log is kept only in the pre-restore snapshot named below\. Those notifications will not be sent\. With a webhook set, Uptime Goblin 1\.5 makes a new signing key when it next starts\./m
    );
    // 1.4.3 runs: x recovers, and it sends its own, unsigned resolved.
    state.webhook = 200;
    const rolledBack = await start(t, { app, data: w.data, env: w.env() });
    w.health.x = true;
    await settle(rolledBack, resolved(x), '1.4.3 to resolve');
    await waitFor(
      () => bodiesFor(w.hook, x).some(request => request.json.kind === 'resolved'),
      "1.4.3's resolved at W"
    );
    assert.equal((await rolledBack.stop()).code, 0, rolledBack.output());
    // WT again: a new key, said at the start; the waiting firing is neither sent nor listed.
    const requests = w.hook.requests.length;
    const again = await start(t, { app: workingTree, data: w.data, env: w.env() });
    await delay(5000);
    assert.match(
      again.output(),
      /Uptime Goblin created a new signing key for the alert webhook; receivers that check X-Goblin-Signature need its public key/
    );
    assert.equal(w.hook.requests.length, requests, 'nothing sent at the start');
    const { publicKey: after, cookie } = await publicKey(again);
    assert.notEqual(after, before);
    assert.deepEqual(await deliveries(again, cookie), [], 'nothing listed, not even as not sent');
    // The next firing: signed with the new key only.
    w.health.x = false;
    await settle(again, firing(x), 'WT to fire again');
    await waitFor(() => w.hook.requests.length > requests, 'the next firing at W');
    const [next] = w.hook.requests.slice(requests);
    assert.equal(JSON.parse(next.body).kind, 'firing');
    const options = { deliveryId: next.headers['x-orbit-delivery'], nowMs: next.receivedAt };
    assert.deepEqual(
      verifyWebhookSignature(before, next.body, next.headers['x-orbit-signature'], options),
      { ok: false, reason: 'mismatch' },
      'a receiver still holding the old public key rejects it'
    );
    assert.deepEqual(
      verifyWebhookSignature(after, next.body, next.headers['x-orbit-signature'], options),
      { ok: true }
    );
    assert.equal((await again.stop()).code, 0, again.output());
    const uids = new Set(waiting.map(row => row.uid));
    assert.ok(!outboxRows(w.data).some(row => uids.has(row.uid)), 'no row of before');
  });
});
