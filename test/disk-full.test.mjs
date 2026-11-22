// The disk-full gate T8 (delivery spec D14, §8.2): with the disk of the data directory full,
// sign-in and alert delivery keep working, configuration writes answer 503 storage_full with a
// banner, readings pause, a start on a full disk succeeds, and everything recovers once space is
// freed.
//
// Part A runs everywhere, in process: a fake statfs makes the storage guard see a full disk, and
// Uptime Goblin's own control connection (app.control.db.pragma, §4.7) makes control.sqlite full.
// Part B runs on a real size-limited file system: the driver at the end of this file runs this
// file in the Dockerfile's pinned node:24-bookworm-slim image on a 96 MiB tmpfs (Docker; required
// with TEST_REQUIRE=docker), with TEST_T8_DIR naming that tmpfs and TEST_T8_RUN a one-time code.
// Part B's tests are registered only on such a tmpfs, which test/helpers/t8.mjs checks (of the
// code only its form: the driver checks that the run reported its code); a host run has no part
// B test at all (not even a skip), and a TEST_T8_DIR that fails those checks gives one failing
// test and fills nothing. The driver is registered only where TEST_T8_DIR is unset. Each of these
// is a platform test (test/helpers/platform.mjs, test/platform-manifest.json): the three inside
// the container on the `container` platform, the driver and the host check on Linux and macOS.
// The driver takes its pinned image per Node runtime from the manifest, records which runtime
// ran the evidence inside, and checks that run with the coverage check as well.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';
import { createApp } from '../server.mjs';
import { configureDestinations } from '../lib/destinations.mjs';
import { emailDefaults } from '../lib/catalog.mjs';
import { RESERVE_BYTES, RESERVE_FILE } from '../lib/storage-guard.mjs';
import { deliveryUid } from '../lib/notify/outbox.mjs';
import { LoginThrottle } from '../lib/throttle.mjs';
import { signIn, sessionCall, browserHeaders } from './helpers/session.mjs';
import {
  t8Environment,
  t8Fill,
  t8Images,
  t8InnerProblems,
  t8Names,
  t8RunLine,
} from './helpers/t8.mjs';
import {
  platformManifest,
  platformTest,
  recordSettings,
  writePlatformRecord,
} from './helpers/platform.mjs';
import {
  checkCoverage,
  parseManifest,
  readRecords,
  sha256,
} from '../scripts/check-platform-coverage.mjs';

configureDestinations({ lookup: async () => [{ address: '192.0.2.1' }] });

const repository = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
// Throwaway values for these data directories only.
const password = 'disk-full-test-password';
const MiB = 2 ** 20;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
async function until(condition, { timeoutMs = 15000, what = 'the condition' } = {}) {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const value = await condition();
    if (value) return value;
    if (Date.now() > end) assert.fail(`${what} was not reached within ${timeoutMs} ms`);
    await sleep(20);
  }
}

/**
 * A webhook receiver on 127.0.0.1 recording {body, headers, status} per request; it answers
 * `hook.status` (200 unless a test changes it).
 */
async function receiver(t) {
  const requests = [],
    sockets = new Set();
  const hook = { status: 200 };
  const server = http.createServer(async (req, res) => {
    let body = '';
    req.setEncoding('utf8');
    for await (const chunk of req) body += chunk;
    const status = hook.status;
    requests.push({ body, headers: req.headers, status });
    res.statusCode = status;
    res.end();
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
  return Object.assign(hook, {
    url: `http://127.0.0.1:${server.address().port}/hook`,
    requests,
    bodies: () => requests.map(request => JSON.parse(request.body)),
  });
}

function mailbox() {
  const messages = [];
  return {
    messages,
    factory: () => ({
      async sendMail(message) {
        messages.push(message);
        return { accepted: ['recipient@example.test'], rejected: [] };
      },
      close() {},
    }),
  };
}

const emailSettings = {
  ...emailDefaults(),
  enabled: true,
  from: 'sender@example.test',
  to: 'recipient@example.test',
  password: 'disk-full-mail-fixture',
  host: 'smtp.example.test',
};
const fastFailure = {
  availabilityFailures: 1,
  availabilitySeconds: 0,
  retryCount: 0,
  recoverySuccesses: 1,
  recoverySeconds: 0,
};

// The outbox store methods that write; a wrapped store fails them as a full disk does.
const writes = new Set([
  'insert',
  'claim',
  'complete',
  'unclaim',
  'expire',
  'hold',
  'release',
  'supersede',
  'requeue',
  'stale',
  'cancel',
  'shiftExpiry',
  'clampTimes',
  'setChannel',
  'prune',
]);
const full = () =>
  Object.assign(new Error('database or disk is full'), { code: 'SQLITE_FULL', class: 'full' });
function failingWrites(state) {
  return store =>
    new Proxy(store, {
      get(target, property) {
        const value = target[property];
        if (typeof value !== 'function') return value;
        if (writes.has(property) && state.failing)
          return async () => {
            throw full();
          };
        return value.bind(target);
      },
    });
}

/**
 * Uptime Goblin on `directory` with the sources `down` names failing, a webhook receiver and a mail
 * transport (and `monotonic`, Uptime Goblin's monotonic clock, `audit`, the audit's seams,
 * `loginThrottle` and `identityOptions`, when given). Resolves {app, base, script(route, method,
 * body)} (a Basic caller).
 */
async function start(
  t,
  {
    directory,
    hook,
    mail,
    down,
    storageGuard,
    delivery = {},
    monotonic,
    audit,
    loginThrottle,
    identityOptions,
  }
) {
  const app = await createApp({
    ...(monotonic ? { monotonic } : {}),
    ...(audit ? { audit } : {}),
    ...(loginThrottle ? { loginThrottle } : {}),
    ...(identityOptions ? { identityOptions } : {}),
    directory,
    host: '127.0.0.1',
    port: 0,
    password,
    allowedHosts: '',
    trustProxy: '',
    startScheduler: false,
    webhook: hook.url,
    mailTransportFactory: mail.factory,
    emailBatchMs: 60000,
    collector: async service => {
      if (down.has(service.id)) throw new Error(`${service.id} is down`);
      const many = service.id === 'proxmox' ? 200 : 1;
      return Array.from({ length: many }, (_, i) => ({
        key: `m${i}`,
        label: `Metric ${i}`,
        value: i,
        unit: '',
      }));
    },
    storageGuard,
    delivery: { pollMs: 20, rng: () => 1, policy: { baseMs: 100, capMs: 100 }, ...delivery },
  });
  const { port } = await app.listen();
  // Also after a test that closed it (close() is idempotent) or failed before it could.
  t.after(() => app.close());
  const base = `http://127.0.0.1:${port}`;
  const script = async (route, method = 'GET', body) => {
    const res = await fetch(base + route, {
      method,
      headers: {
        Authorization: 'Basic ' + Buffer.from('admin:' + password).toString('base64'),
        'Content-Type': 'application/json',
        'X-Goblin-Request': '1',
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
  return { app, base, script };
}

const readings = (directory, service) => {
  const db = new DatabaseSync(path.join(directory, 'history.sqlite'), { readOnly: true });
  try {
    return db.prepare('SELECT count(*) AS n FROM readings WHERE service = ?').get(service).n;
  } finally {
    db.close();
  }
};
const unrelayed = (directory, service) => {
  const db = new DatabaseSync(path.join(directory, 'history.sqlite'), { readOnly: true });
  try {
    return db
      .prepare('SELECT count(*) AS n FROM events WHERE service = ? AND relayed = 0')
      .get(service).n;
  } finally {
    db.close();
  }
};

test('T8 part A: a full disk refuses settings, keeps sign-in and delivery, restarts, and recovers', async t => {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-t8a-')));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const hook = await receiver(t);
  const mail = mailbox();
  const down = new Set();
  // The disk as statfs shows it: `available` bytes while the reserve exists, 8 MiB more once
  // the guard has deleted it (as a real file system frees its blocks).
  let available = 2 ** 30;
  const reserve = path.join(directory, RESERVE_FILE);
  const statfs = () => ({
    type: 0,
    bsize: 1,
    blocks: 2 ** 40,
    bfree: available,
    bavail: available + (fs.existsSync(reserve) ? 0 : RESERVE_BYTES),
    files: 1000,
    ffree: 1000,
  });
  const output = [];
  for (const level of ['warn', 'error', 'info'])
    t.mock.method(console, level, (...args) => output.push(args.join(' ')));
  const storageGuard = { statfs, checkMs: 50 };
  const outboxFull = { failing: false };
  const first = await start(t, {
    directory,
    hook,
    mail,
    down,
    storageGuard,
    delivery: { wrapStore: failingWrites(outboxFull) },
  });
  const { app } = first;
  assert.equal(fs.statSync(reserve).size, RESERVE_BYTES, 'the reserve is held');
  app.config.updateGlobal({ monitoring: fastFailure, email: emailSettings });
  for (const id of ['plex', 'sonarr', 'radarr', 'proxmox'])
    app.config.update(id, { apiUrl: `https://${id}.example.test`, apiKey: 'fixture-key' });
  const a = await signIn(first.base, password);
  const sessionA = sessionCall(first.base, a.cookie);
  const configBefore = fs.readFileSync(path.join(directory, 'config.json'));

  // The disk fills: the guard releases its reserve, the space comes back, and Uptime Goblin says so.
  available = 1 * MiB;
  await until(async () => (await sessionA('/api/dashboard')).body.disk?.full === true, {
    what: 'the full state',
  });
  const banner = (await sessionA('/api/dashboard')).body.disk;
  assert.equal(banner.reserveReleased, true);
  assert.equal(banner.freed, true);
  assert.equal(fs.existsSync(reserve), false);
  // Settings and the signing key's rotation are configuration writes: 503 with Retry-After.
  const refused = await sessionA('/api/settings', 'PATCH', { title: 'Changed while full' });
  assert.equal(refused.status, 503);
  assert.equal(refused.body.code, 'storage_full');
  assert.equal(refused.headers.get('retry-after'), '60');
  const rotation = await sessionA('/api/notifications/webhook/signing-secret', 'POST', {});
  assert.equal(rotation.status, 503);
  assert.equal(rotation.body.code, 'storage_full');
  assert.deepEqual(fs.readFileSync(path.join(directory, 'config.json')), configBefore);
  // The disk notice reaches the receiver.
  await app.flushNotifications();
  await until(() => hook.bodies().some(body => body.rule === '__disk' && body.kind === 'firing'), {
    what: 'the disk notice',
  });
  // Sign-in and an existing session keep working.
  const b = await signIn(first.base, password);
  assert.equal((await sessionCall(first.base, b.cookie)('/api/session')).status, 200);
  assert.equal((await sessionA('/api/dashboard')).status, 200);
  // Readings pause quietly: no reading, no history error line, no storage notice.
  const before = readings(directory, 'proxmox');
  await app.poll(app.config.get('proxmox'));
  assert.equal(readings(directory, 'proxmox'), before);
  // An alert is still delivered, through control.sqlite (saving).
  down.add('plex');
  await app.poll(app.config.get('plex'));
  await app.flushNotifications();
  await until(() => hook.bodies().some(body => body.service === 'plex'), { what: 'plex' });
  assert.equal((await sessionA('/api/notifications')).body.saving, true);

  // control.sqlite full too: a page limit on Uptime Goblin's own connection (§4.7) fills it for every
  // write that needs a new page (sessions, job status), and the outbox's writes fail as a full
  // disk makes them fail. (Under a page limit an in-place update still fits, so the outbox's
  // own probe would succeed and end "not saving" at once; on a real full disk it cannot, which
  // part B shows.) The next alert change is kept in memory and still delivered.
  const [{ page_count: pages }] = app.control.db.pragma('page_count');
  app.control.db.pragma(`max_page_count=${pages}`);
  outboxFull.failing = true;
  const webhookRows = async () =>
    (await sessionA('/api/notifications/deliveries?channel=env-webhook&limit=100')).body.deliveries;
  down.add('sonarr');
  await app.poll(app.config.get('sonarr'));
  const unsavedRow = await until(
    async () => (await webhookRows()).find(row => row.saved === false),
    { what: 'the alert change kept in memory' }
  );
  assert.equal(unsavedRow.alert.service, 'sonarr');
  await until(
    async () =>
      (await webhookRows()).find(row => row.uid === unsavedRow.uid)?.status === 'delivered',
    { what: 'the delivery from memory' }
  );
  assert.ok(
    hook.requests.some(request => request.headers['x-goblin-delivery'] === unsavedRow.uid),
    'the receiver got it'
  );
  const status = await until(async () => {
    const answer = (await sessionA('/api/notifications')).body;
    return answer.saving === false ? answer : null;
  });
  assert.equal(typeof status.unsavedSince, 'number');
  assert.ok((await sessionA('/api/notifications/deliveries')).body.unsaved >= 1);
  // Its email row still waits in its quiet window, so its history event is not final: it stays
  // relayed = 0, and a restart would send it again (D15).
  assert.ok(unrelayed(directory, 'sonarr') >= 1, 'its history event waits until it is final');
  const dashboard = (await sessionA('/api/dashboard')).body;
  assert.equal(dashboard.notifications.saving, false);
  assert.equal(dashboard.disk.full, true);
  assert.ok(!output.some(line => /History database write failed/.test(line)));
  assert.ok(!hook.bodies().some(body => body.rule === '__storage'), 'no history notice');
  await app.close();

  // A restart while full: the start succeeds although every outbox write fails, delivers from
  // memory, and shows both banners (D27).
  const outbox = { failing: true };
  const second = await start(t, {
    directory,
    hook,
    mail,
    down,
    storageGuard,
    delivery: { wrapStore: failingWrites(outbox) },
  });
  const sessionA2 = sessionCall(second.base, a.cookie);
  assert.equal((await sessionA2('/api/session')).status, 200, 'session A survived the restart');
  down.add('radarr');
  await second.app.poll(second.app.config.get('radarr'));
  await second.app.flushNotifications();
  await until(() => hook.bodies().some(body => body.service === 'radarr'), { what: 'radarr' });
  const restarted = (await sessionA2('/api/dashboard')).body;
  assert.equal(restarted.disk.full, true);
  await until(async () => (await sessionA2('/api/notifications')).body.saving === false, {
    what: 'not saving after the restart',
  });

  // Space again: the guard recreates its reserve, settings save, the notice recovers, and the
  // outbox saves again (probe()).
  outbox.failing = false;
  available = 2 ** 30;
  await until(async () => (await sessionA2('/api/dashboard')).body.disk === null, {
    what: 'the disk back',
  });
  assert.equal(fs.statSync(reserve).size, RESERVE_BYTES, 'the reserve is held again');
  const saved = await sessionA2('/api/settings', 'PATCH', { title: 'Saved again' });
  assert.equal(saved.status, 200);
  await until(async () => (await sessionA2('/api/notifications')).body.saving === true, {
    what: 'saving again',
    timeoutMs: 30000,
  });
  await second.app.flushNotifications();
  await until(
    () => hook.bodies().some(body => body.rule === '__disk' && body.kind === 'resolved'),
    { what: 'the disk recovery notice' }
  );
});

test('T8 part A: a history write that failed just before the guard saw the full disk is not resolved while readings are paused', async t => {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-t8n-')));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const hook = await receiver(t);
  let available = 2 ** 30,
    later = 0;
  const reserve = path.join(directory, RESERVE_FILE);
  const statfs = () => ({
    type: 0,
    bsize: 1,
    blocks: 2 ** 40,
    bfree: available,
    bavail: available + (fs.existsSync(reserve) ? 0 : RESERVE_BYTES),
    files: 1000,
    ffree: 1000,
  });
  for (const level of ['warn', 'error', 'info']) t.mock.method(console, level, () => {});
  const { app } = await start(t, {
    directory,
    hook,
    mail: mailbox(),
    down: new Set(),
    storageGuard: { statfs, checkMs: 50 },
    monotonic: () => performance.now() + later,
  });
  app.config.update('plex', { apiUrl: 'https://plex.example.test', apiKey: 'fixture-key' });
  const plex = () => app.config.get('plex');
  const notices = () =>
    hook
      .bodies()
      .filter(body => body.rule === '__storage')
      .map(body => body.kind);
  // The disk fills faster than the guard's 10 s check: a history write fails first.
  const record = app.store.record.bind(app.store);
  app.store.record = () => {
    throw Object.assign(new Error('database or disk is full'), {
      errcode: 13,
      errstr: 'database or disk is full',
    });
  };
  await app.poll(plex());
  app.store.record = record;
  await app.flushNotifications();
  await until(() => notices().includes('firing'), { what: 'the history notice' });
  // Then the guard sees the full disk and pauses readings. Six minutes of polls write nothing.
  available = 1 * MiB;
  await until(() => app.guard.state().full, { what: 'the full state' });
  const before = readings(directory, 'plex');
  later += 6 * 60 * 1000;
  for (let i = 0; i < 4; i++) await app.poll(plex());
  await app.flushNotifications();
  await sleep(200);
  await app.flushNotifications();
  assert.equal(readings(directory, 'plex'), before, 'readings are paused');
  // Before, each paused poll counted as a history write: "Uptime Goblin can write its history database
  // again." went out while the disk was still full and no reading had been saved.
  assert.deepEqual(notices(), ['firing']);
  // Space again: readings are saved, and three of them (five minutes after the failure) end it.
  available = 2 ** 30;
  await until(() => !app.guard.state().full, { what: 'the disk back' });
  for (let i = 0; i < 3; i++) await app.poll(plex());
  assert.ok(readings(directory, 'plex') > before, 'readings are saved again');
  await app.flushNotifications();
  await until(() => notices().length === 2, { what: 'the history recovery notice' });
  assert.deepEqual(notices(), ['firing', 'resolved']);
});

// The notices Uptime Goblin sent about itself that the receiver got ([kind, status, delivery id]), the
// delivery id of a notice of the episode that began at `since`, and the firing bodies of a rule.
const noticesOf = (hook, rule) =>
  hook.requests
    .map(request => ({ ...JSON.parse(request.body), request }))
    .filter(body => body.rule === rule)
    .map(body => [body.kind, body.request.status, body.request.headers['x-goblin-delivery']]);
const noticeId = (name, since, kind) => deliveryUid(`sys:${name}:${since}:${kind}`, 'env-webhook');
const firings = (hook, rule) =>
  hook.bodies().filter(body => body.rule === rule && body.kind === 'firing');

// Amendment A40 (review round 3): the disk notice's episode lived in the delivery service's
// memory, and a start announced only a disk full at that moment. Space freed while Uptime Goblin was
// stopped (a restart after a clean-up, a reboot, a rollback to 1.4.3 and an upgrade again) never
// sent "The Uptime Goblin host's disk has free space again.", a firing still retrying at the stop was
// sent after the start with no recovery behind it, and a start on a disk still full sent a
// second firing under a new since.
test('T8 part A: the disk notice outlives a stop: space freed meanwhile sends its recovery once, a start on a disk still full sends no second firing, and a firing still retrying is followed by its recovery', async t => {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-t8r-')));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const hook = await receiver(t);
  let available = 2 ** 30;
  const reserve = path.join(directory, RESERVE_FILE);
  const statfs = () => ({
    type: 0,
    bsize: 1,
    blocks: 2 ** 40,
    bfree: available,
    bavail: available + (fs.existsSync(reserve) ? 0 : RESERVE_BYTES),
    files: 1000,
    ffree: 1000,
  });
  for (const level of ['warn', 'error', 'info']) t.mock.method(console, level, () => {});
  const run = async () =>
    (
      await start(t, {
        directory,
        hook,
        mail: mailbox(),
        down: new Set(),
        storageGuard: { statfs, checkMs: 50 },
      })
    ).app;
  const disk = () => noticesOf(hook, '__disk');
  const quiet = async app => {
    for (let i = 0; i < 3; i++) {
      await app.flushNotifications();
      await sleep(150);
    }
  };

  // The disk fills and the notice is delivered; Uptime Goblin stops, and space is freed meanwhile.
  let app = await run();
  available = 1 * MiB;
  await until(() => disk().length === 1, { what: 'the disk notice' });
  const [first] = firings(hook, '__disk');
  await app.close();
  available = 2 ** 30;
  app = await run();
  await until(() => disk().length === 2, { what: 'the recovery after the start' });
  assert.deepEqual(disk(), [
    ['firing', 200, noticeId('disk', first.time, 'firing')],
    ['resolved', 200, noticeId('disk', first.time, 'resolved')],
  ]);
  assert.equal(app.guard.banner(), null, 'the disk has space');
  await app.close();
  // Once: the start after that has nothing open.
  app = await run();
  await quiet(app);
  assert.equal(disk().length, 2);

  // A start on a disk still full keeps the episode (no second firing); freeing space ends it.
  available = 1 * MiB;
  await until(() => disk().length === 3, { what: 'the second episode' });
  const second = firings(hook, '__disk').at(-1);
  // Other writers take the space the released reserve freed too: the disk is still full at the
  // next start.
  available = 1 * MiB - RESERVE_BYTES;
  await app.close();
  app = await run();
  assert.equal(app.guard.state().full, true);
  await quiet(app);
  assert.equal(disk().length, 3, 'no second firing');
  available = 2 ** 30;
  await until(() => disk().length === 4, { what: 'the second recovery' });
  assert.deepEqual(disk().slice(2), [
    ['firing', 200, noticeId('disk', second.time, 'firing')],
    ['resolved', 200, noticeId('disk', second.time, 'resolved')],
  ]);
  await app.close();

  // A firing still retrying at the stop (the receiver answering 500) is sent after the start,
  // on a disk with space again, and its recovery follows it.
  hook.status = 500;
  app = await run();
  available = 1 * MiB;
  await until(() => disk().length > 4, { what: 'a refused attempt' });
  await app.close();
  const third = firings(hook, '__disk').at(-1);
  const refused = disk().length;
  hook.status = 200;
  available = 2 ** 30;
  app = await run();
  await until(() => disk().length === refused + 2, { what: 'the firing and its recovery' });
  assert.deepEqual(disk().slice(refused), [
    ['firing', 200, noticeId('disk', third.time, 'firing')],
    ['resolved', 200, noticeId('disk', third.time, 'resolved')],
  ]);
  assert.deepEqual(
    disk()
      .slice(4, refused)
      .map(([kind, status]) => [kind, status]),
    Array.from({ length: refused - 4 }, () => ['firing', 500])
  );
});

// The history notice the same way: "Uptime Goblin can write its history database again." is sent by the
// run whose writes work again, under the since of the outage an earlier run announced, and the
// dashboard does not show that outage meanwhile (no write of this run failed).
test('T8 part A: the history notice outlives a stop: writes that work after the start end the outage with its own since', async t => {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-t8s-')));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const hook = await receiver(t);
  let later = 0;
  for (const level of ['warn', 'error', 'info']) t.mock.method(console, level, () => {});
  const run = () =>
    start(t, {
      directory,
      hook,
      mail: mailbox(),
      down: new Set(),
      monotonic: () => performance.now() + later,
    });
  const storage = () => noticesOf(hook, '__storage');
  let { app, script } = await run();
  app.config.update('plex', { apiUrl: 'https://plex.example.test', apiKey: 'fixture-key' });
  const plex = () => app.config.get('plex');
  const record = app.store.record.bind(app.store);
  app.store.record = () => {
    throw Object.assign(new Error('database or disk is full'), {
      errcode: 13,
      errstr: 'database or disk is full',
    });
  };
  await app.poll(plex());
  app.store.record = record;
  await app.flushNotifications();
  await until(() => storage().length === 1, { what: 'the history notice' });
  assert.equal((await script('/api/dashboard')).body.storage.code, '13');
  const [outage] = firings(hook, '__storage');
  await app.close();

  ({ app, script } = await run());
  // Carried, not shown: this run has not failed a write.
  assert.equal((await script('/api/dashboard')).body.storage, null);
  assert.equal((await script('/api/system')).body.data.writeFailure, null);
  await app.poll(plex());
  later += 6 * 60 * 1000;
  for (let i = 0; i < 3; i++) await app.poll(plex());
  await app.flushNotifications();
  await until(() => storage().length === 2, { what: 'the history recovery notice' });
  assert.deepEqual(storage(), [
    ['firing', 200, noticeId('storage', outage.time, 'firing')],
    ['resolved', 200, noticeId('storage', outage.time, 'resolved')],
  ]);
  await app.close();
  // Once.
  ({ app } = await run());
  for (let i = 0; i < 4; i++) await app.poll(plex());
  await app.flushNotifications();
  await sleep(200);
  await app.flushNotifications();
  assert.equal(storage().length, 2);
});

// ---------------------------------------------------------------------------------------------
// The audit under T8 (audit spec D7, §9.3).

function auditRows(directory) {
  const db = new DatabaseSync(path.join(directory, 'control.sqlite'), { readOnly: true });
  try {
    return db
      .prepare('SELECT * FROM audit_log ORDER BY seq')
      .all()
      .map(row => ({ ...row, detail: row.detail === null ? null : JSON.parse(row.detail) }));
  } finally {
    db.close();
  }
}

test('T8 part A (audit): while full, sign-in and Retry are recorded, configuration writes refused without a row, refusals only counted, operations on stderr; a full restart recovers its rows', async t => {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-t8audit-')));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const hook = await receiver(t);
  hook.status = 422;
  const mail = mailbox();
  const down = new Set();
  let available = 2 ** 30;
  const reserve = path.join(directory, RESERVE_FILE);
  const statfs = () => ({
    type: 0,
    bsize: 1,
    blocks: 2 ** 40,
    bfree: available,
    bavail: available + (fs.existsSync(reserve) ? 0 : RESERVE_BYTES),
    files: 1000,
    ffree: 1000,
  });
  const output = [];
  for (const level of ['log', 'warn', 'error', 'info'])
    t.mock.method(console, level, (...args) => output.push(args.join(' ')));
  // One audit window, which ends while Uptime Goblin runs: the audit's clock stays a second before
  // 13:00 until the disk is back, then moves past it (the aggregation's timer finds the window
  // still open each time it fires until then). The refusals are about the audit, not the
  // lockout.
  let now = Date.UTC(2026, 9, 3, 12, 59, 59);
  const loginThrottle = new LoginThrottle({ freeAttempts: 1000, globalFailures: 1000 });
  const storageGuard = { statfs, checkMs: 50 };
  const first = await start(t, {
    directory,
    hook,
    mail,
    down,
    storageGuard,
    audit: { clock: () => now },
    loginThrottle,
  });
  const { app } = first;
  app.config.updateGlobal({ monitoring: fastFailure, email: emailSettings });
  app.config.update('plex', { apiUrl: 'https://plex.example.test', apiKey: 'fixture-key' });
  const sessionA = sessionCall(first.base, (await signIn(first.base, password)).cookie);
  down.add('plex');
  await app.poll(app.config.get('plex'));
  await app.flushNotifications();
  const failed = await until(async () =>
    (await sessionA('/api/notifications/deliveries?channel=env-webhook')).body.deliveries.find(
      row => row.status === 'failed'
    )
  );
  hook.status = 200;

  // The disk fills.
  available = 1 * MiB;
  await until(async () => (await sessionA('/api/dashboard')).body.disk?.full === true, {
    what: 'the full state',
  });
  const rowsAt = auditRows(directory).length;
  const added = () => auditRows(directory).slice(rowsAt);
  // A sign-in on the released reserve writes its row with its session.
  const b = await signIn(first.base, password);
  assert.ok(b.cookie);
  assert.deepEqual(
    added().map(row => [row.action, row.outcome]),
    [['session.login', 'ok']]
  );
  // Configuration writes and the rotation: refused before their attempt, no row.
  assert.equal(
    (await sessionA('/api/settings', 'PATCH', { title: 'Full' })).body.code,
    'storage_full'
  );
  assert.equal(
    (await sessionA('/api/notifications/webhook/signing-secret', 'POST', {})).body.code,
    'storage_full'
  );
  assert.equal(added().length, 1, 'no row for a refused write');
  // Retry: an attempt and its result on the reserve.
  const retried = await sessionA(`/api/notifications/deliveries/${failed.uid}/retry`, 'POST', {});
  assert.equal(retried.status, 200, JSON.stringify(retried.body));
  assert.deepEqual(
    added()
      .filter(row => row.action === 'delivery.retry')
      .map(row => row.outcome),
    ['attempt', 'ok']
  );
  // 50 refused sign-ins with different names: only counted while full.
  const count = added().length;
  for (let i = 0; i < 50; i++)
    assert.equal(
      (
        await fetch(new URL('/api/auth/login', first.base), {
          method: 'POST',
          headers: browserHeaders(first.base),
          body: JSON.stringify({ login: `someone-${i}`, password: 'wrong-password-0001' }),
        })
      ).status,
      401
    );
  assert.equal(added().length, count, 'no row for the refusals while full');
  // A source test (its collection runs under a test id, so it connects): answered, its row on
  // stderr only.
  assert.equal(
    (await sessionA('/api/test-service', 'POST', { serviceId: 'plex', settings: {} })).status,
    200
  );
  assert.equal(added().length, count);
  assert.ok(
    output.some(
      line =>
        line.startsWith('{"orbit":"audit.unwritten"') &&
        JSON.parse(line).row?.action === 'source.test'
    )
  );
  // Space again, then the window's end: while Uptime Goblin runs, one summary at the window's end
  // holds the 50 refusals.
  available = 2 ** 30;
  await until(async () => (await sessionA('/api/dashboard')).body.disk === null, {
    what: 'the disk back',
  });
  now = Date.UTC(2026, 9, 3, 13, 0, 30);
  const summaries = await until(
    () => {
      const found = auditRows(directory).filter(
        row => row.action === 'session.login' && row.outcome === 'failed'
      );
      return found.length ? found : null;
    },
    { what: "the window's summary" }
  );
  assert.equal(summaries.length, 1);
  assert.equal(summaries[0].time, Date.UTC(2026, 9, 3, 13), "at the window's end");
  assert.equal(summaries[0].count, 50);
  assert.equal(summaries[0].detail.codes.invalid_credentials, 50);
  await app.close();

  // A restart while full with every audit write failing: it starts; the next start, once
  // writes work, writes the start rows.
  const file = path.join(directory, 'config.json');
  const edited = JSON.parse(fs.readFileSync(file, 'utf8'));
  edited.title = 'Edited while stopped';
  fs.writeFileSync(file, JSON.stringify(edited, null, 2));
  available = 1 * MiB;
  const before = auditRows(directory).length;
  const failing = (db, purpose) =>
    purpose === 'read'
      ? db
      : new Proxy(db, {
          get(target, property) {
            const value = target[property];
            if (property === 'write') return () => Promise.reject(full());
            return typeof value === 'function' ? value.bind(target) : value;
          },
        });
  const second = await start(t, {
    directory,
    hook,
    mail,
    down,
    storageGuard,
    audit: { wrapDb: failing },
  });
  assert.equal((await second.script('/api/dashboard')).status, 200);
  await second.app.close();
  assert.equal(auditRows(directory).length, before);
  available = 2 ** 30;
  const third = await start(t, { directory, hook, mail, down, storageGuard });
  await third.app.close();
  const recovered = auditRows(directory)
    .slice(before)
    .map(row => row.action);
  assert.ok(recovered.includes('config.changed-outside'), JSON.stringify(recovered));
  assert.ok(recovered.includes('system.start'));
});

// ---------------------------------------------------------------------------------------------
// Part B: a real size-limited file system (TEST_T8_DIR).

// null in a host run; inside the driver's container, its checked tmpfs (test/helpers/t8.mjs).
// platformTest registers the environment test on the `container` platform only: where
// TEST_T8_DIR is set, valid or not.
const environment = t8Environment();
platformTest(import.meta.url, 't8.environment', t8Names.environment, {}, t => {
  assert.ok(environment?.ok, environment?.reason ?? 'TEST_T8_DIR is not set');
  t.diagnostic(t8RunLine(environment));
});
// The directory part B fills, and what registers its tests: only on that tmpfs. Elsewhere part B
// and the measurements are absent, which the coverage check refuses in the container run.
const t8 = environment?.ok ? environment.dir : null;
const partBTest = t8 ? platformTest : () => {};

// Fills the tmpfs from a new, empty folder `folder` (t8Fill checks everything again first).
const fillDisk = folder => t8Fill(folder, { expected: environment.run });
const freeBytes = directory => {
  const s = fs.statfsSync(directory);
  return Number(s.bavail) * Number(s.bsize);
};
// Measurement only: the bytes each file of `directory` holds on disk, and which grew since
// `before` (where a step's space went).
const allocated = directory =>
  Object.fromEntries(
    fs
      .readdirSync(directory, { withFileTypes: true })
      .filter(entry => entry.isFile())
      .map(entry => [entry.name, fs.statSync(path.join(directory, entry.name)).blocks * 512])
  );
const grown = (before, after) =>
  Object.fromEntries(
    Object.entries(after)
      .filter(([name, bytes]) => bytes !== (before[name] ?? 0))
      .map(([name, bytes]) => [name, bytes - (before[name] ?? 0)])
  );

partBTest(
  import.meta.url,
  't8.part-b',
  t8Names.partB,
  // 4c's thousand refused sign-ins each cost a password derivation.
  { timeout: 480000 },
  async t => {
    const directory = path.join(t8, 'data');
    fs.mkdirSync(directory, { recursive: true });
    // Each fill writes its file into a folder of its own, made now while there is space and
    // empty until its fill.
    const fillers = [path.join(t8, 'fill-1'), path.join(t8, 'fill-2')];
    for (const folder of fillers) fs.mkdirSync(folder);
    t.after(() => {
      for (const folder of fillers) fs.rmSync(folder, { recursive: true, force: true });
    });
    const hook = await receiver(t);
    const mail = mailbox();
    const down = new Set();
    const storageGuard = { checkMs: 200 };
    const output = [];
    for (const level of ['warn', 'error'])
      t.mock.method(console, level, (...args) => output.push(args.join(' ')));
    // Step 4c's refusals are about the disk, not the lockout.
    const loginThrottle = new LoginThrottle({ freeAttempts: 100000, globalFailures: 100000 });
    // Sessions A and B, step 4b's 20 sign-ins, 4c's and step 8's: more than the 20 a user keeps,
    // and session A, the least recently seen, must not be the one evicted.
    const identityOptions = { limits: { maxSessions: 32 } };
    const first = await start(t, {
      directory,
      hook,
      mail,
      down,
      storageGuard,
      loginThrottle,
      identityOptions,
    });
    const { app } = first;
    // 1. Session A; email and failing sources set up while there is space.
    const a = await signIn(first.base, password);
    const sessionA = sessionCall(first.base, a.cookie);
    assert.equal(
      (await sessionA('/api/settings', 'PATCH', { monitoring: fastFailure, email: emailSettings }))
        .status,
      200
    );
    for (const id of ['plex', 'sonarr', 'radarr', 'proxmox'])
      assert.equal(
        (
          await sessionA(`/api/services/${id}`, 'PATCH', {
            apiUrl: `https://${id}.example.test`,
            apiKey: 'fixture-key',
          })
        ).status,
        200,
        id
      );
    const configBefore = fs.readFileSync(path.join(directory, 'config.json'));
    // 2. Fill, after truncating control.sqlite's WAL (every later write needs new space).
    app.control.db.pragma('wal_checkpoint(TRUNCATE)');
    fillDisk(fillers[0]);
    // 3. The guard releases its reserve, and the file system freed the space.
    await until(
      async () => {
        const disk = (await sessionA('/api/dashboard')).body.disk;
        return disk?.full && disk.reserveReleased && disk.freed;
      },
      { what: 'the full state with the reserve released' }
    );
    // 3b. Readings while full (measured): 20 polls of a 200-reading source.
    const freeBefore = freeBytes(t8);
    for (let i = 0; i < 20; i++) await app.poll(app.config.get('proxmox'));
    const fell = freeBefore - freeBytes(t8);
    t.diagnostic(`free space fell by ${fell} bytes over 20 polls while full`);
    assert.ok(fell <= 256 * 1024, `free space fell by ${fell} bytes`);
    // 4. Sign-in still works; both sessions read. Its audit row shares its unit (checked after
    // the recovery, step 9).
    const signedInFrom = Date.now();
    const b = await signIn(first.base, password);
    const signedInTo = Date.now();
    assert.equal((await sessionCall(first.base, b.cookie)('/api/session')).status, 200);
    assert.equal((await sessionA('/api/dashboard')).status, 200);
    // 4b. Measured, not gating: what a sign-in with its audit row takes of the released reserve.
    const beforeSignIns = freeBytes(t8),
      filesBeforeSignIns = allocated(directory);
    for (let i = 0; i < 20; i++) await signIn(first.base, password);
    t.diagnostic(
      `20 sign-ins on the released reserve took ${beforeSignIns - freeBytes(t8)} bytes (${Math.round((beforeSignIns - freeBytes(t8)) / 20)} a sign-in, its audit row included); by file: ${JSON.stringify(grown(filesBeforeSignIns, allocated(directory)))}`
    );
    // 4c. Gating: a thousand refused sign-ins with different names write nothing while full (they
    // are only counted, audit spec D7, D9), and a sign-in still works after them.
    const beforeRefusals = freeBytes(t8),
      filesBeforeRefusals = allocated(directory),
      rowsBeforeRefusals = auditRows(directory).length,
      jobsBeforeRefusals = await app.control.jobs.list();
    for (let i = 0; i < 1000; i++) {
      const refused = await fetch(new URL('/api/auth/login', first.base), {
        method: 'POST',
        headers: browserHeaders(first.base),
        body: JSON.stringify({ login: `guess-${i}`, password: 'wrong-password-0001' }),
      });
      assert.equal(refused.status, 401, `refusal ${i}`);
    }
    // Where 4c's bytes went, if any: Uptime Goblin's job status rows (lib/jobs.mjs records each job's
    // status when its outcome changes or every 5 minutes, refusals or not), never an audit row.
    const jobsWritten = (await app.control.jobs.list())
      .filter(
        row =>
          !jobsBeforeRefusals.some(
            old => old.name === row.name && old.updated_at === row.updated_at
          )
      )
      .map(row => row.name);
    t.diagnostic(
      `free space before and after 1,000 refused sign-ins: ${beforeRefusals} and ${freeBytes(t8)} bytes; by file: ${JSON.stringify(grown(filesBeforeRefusals, allocated(directory)))}; audit rows added: ${auditRows(directory).length - rowsBeforeRefusals}; job status rows written meanwhile: ${JSON.stringify(jobsWritten)}`
    );
    assert.equal(auditRows(directory).length, rowsBeforeRefusals, 'the refusals wrote no row');
    const refusedRows = await first.script('/api/audit?action=session.login&outcome=failed');
    assert.equal(refusedRows.status, 200);
    assert.deepEqual(refusedRows.body.entries, [], 'no row for a refusal while full');
    assert.ok(await signIn(first.base, password));
    // 5. Configuration writes answer 503 with a banner; config.json is unchanged.
    const refused = await sessionA('/api/settings', 'PATCH', { title: 'Changed while full' });
    assert.equal(refused.status, 503);
    assert.equal(refused.body.code, 'storage_full');
    assert.ok(refused.headers.get('retry-after'));
    assert.deepEqual(fs.readFileSync(path.join(directory, 'config.json')), configBefore);
    assert.equal((await sessionA('/api/dashboard')).body.disk.full, true);
    // 6. Alerts are still delivered, saved in control.sqlite.
    down.add('plex');
    await app.poll(app.config.get('plex'));
    await app.flushNotifications();
    await until(() => hook.bodies().some(body => body.service === 'plex'), { what: 'plex' });
    await until(() => mail.messages.some(message => /Plex/.test(message.text ?? '')), {
      what: 'the email',
    });
    assert.equal((await sessionA('/api/notifications')).body.saving, true);
    // 7. Fill again (taking the released reserve): the next alert goes out from memory.
    app.control.db.pragma('wal_checkpoint(TRUNCATE)');
    fillDisk(fillers[1]);
    down.add('sonarr');
    await app.poll(app.config.get('sonarr'));
    await app.flushNotifications();
    await until(() => hook.bodies().some(body => body.service === 'sonarr'), { what: 'sonarr' });
    await until(async () => (await sessionA('/api/notifications')).body.saving === false, {
      what: 'not saving',
    });
    const listed = (await sessionA('/api/notifications/deliveries')).body.deliveries;
    assert.ok(listed.some(row => row.alert.service === 'sonarr' && row.saved === false));
    await app.close();
    // 8. A restart while both fillers stay.
    const second = await start(t, { directory, hook, mail, down, storageGuard, identityOptions });
    const sessionA2 = sessionCall(second.base, a.cookie);
    assert.equal((await sessionA2('/api/dashboard')).status, 200, 'session A after the restart');
    const attempt = await fetch(new URL('/api/auth/login', second.base), {
      method: 'POST',
      headers: browserHeaders(second.base),
      body: JSON.stringify({ login: 'admin', password }),
    });
    t.diagnostic(`a new sign-in after the restart while full answered ${attempt.status}`);
    assert.ok([200, 503].includes(attempt.status));
    down.add('radarr');
    await second.app.poll(second.app.config.get('radarr'));
    await second.app.flushNotifications();
    await until(() => hook.bodies().some(body => body.service === 'radarr'), { what: 'radarr' });
    const restarted = (await sessionA2('/api/dashboard')).body;
    assert.equal(restarted.disk.full, true);
    const perDelivery = new Map();
    for (const request of hook.requests) {
      const id = request.headers['x-goblin-delivery'];
      perDelivery.set(id, (perDelivery.get(id) ?? 0) + 1);
    }
    t.diagnostic(`requests per delivery id: ${JSON.stringify([...perDelivery.values()])}`);
    assert.ok([...perDelivery.values()].every(count => count <= 2));
    // 9. Space again: within 2 s (plus the check interval) the guard leaves full.
    for (const folder of fillers) fs.rmSync(folder, { recursive: true, force: true });
    await until(async () => (await sessionA2('/api/dashboard')).body.disk === null, {
      what: 'the disk back',
      timeoutMs: 2500,
    });
    assert.equal(fs.statSync(path.join(directory, RESERVE_FILE)).size, RESERVE_BYTES);
    // Step 4's sign-in has its session.login row.
    const logins = (await sessionA2('/api/audit?action=session.login&outcome=ok&limit=500')).body
      .entries;
    assert.ok(
      logins.some(entry => entry.time >= signedInFrom && entry.time <= signedInTo),
      JSON.stringify(logins.map(entry => entry.time))
    );
    assert.equal((await sessionA2('/api/settings', 'PATCH', { title: 'Saved' })).status, 200);
    await until(async () => (await sessionA2('/api/notifications')).body.saving === true, {
      what: 'saving again',
      timeoutMs: 30000,
    });
    await second.app.close();
    const third = await start(t, { directory, hook, mail, down, storageGuard, identityOptions });
    const saved = (await third.script('/api/notifications/deliveries')).body.deliveries;
    assert.ok(saved.some(row => row.alert.service === 'plex' && row.saved === true));
  }
);

partBTest(
  import.meta.url,
  't8.measurements',
  t8Names.measurements,
  // Its diagnostics are the record: it asserts nothing about the answers it measures.
  { timeout: 240000 },
  async t => {
    const output = [];
    for (const level of ['warn', 'error'])
      t.mock.method(console, level, (...args) => output.push(args.join(' ')));
    for (const [name, options] of [
      ['WAL left at its high-water size', { truncate: false, reserveBytes: undefined }],
      ['no reserve, WAL truncated', { truncate: true, reserveBytes: 0 }],
    ]) {
      const base = path.join(t8, `measure-${options.reserveBytes ?? 'r'}-${options.truncate}`);
      const directory = path.join(base, 'data');
      fs.mkdirSync(directory, { recursive: true });
      const filler = path.join(base, 'fill');
      fs.mkdirSync(filler);
      const hook = await receiver(t);
      const down = new Set();
      const { app, base: url } = await start(t, {
        directory,
        hook,
        mail: mailbox(),
        down,
        storageGuard: {
          checkMs: 200,
          ...(options.reserveBytes === undefined ? {} : { reserveBytes: options.reserveBytes }),
        },
      });
      const a = await signIn(url, password);
      // 3,000 small control writes grow the WAL to its high-water size (probe P5).
      if (!options.truncate)
        for (let i = 0; i < 3000; i++)
          await app.control.jobs.record({ name: `t8-measure-${i % 50}`, runs: i });
      else app.control.db.pragma('wal_checkpoint(TRUNCATE)');
      fillDisk(filler);
      await sleep(600);
      const answer = await fetch(new URL('/api/auth/login', url), {
        method: 'POST',
        headers: browserHeaders(url),
        body: JSON.stringify({ login: 'admin', password }),
      });
      const read = await sessionCall(url, a.cookie)('/api/dashboard');
      t.diagnostic(
        `${name}: a new sign-in answered ${answer.status}; session A read ${read.status}`
      );
      fs.rmSync(filler, { recursive: true, force: true });
      await app.close();
      fs.rmSync(base, { recursive: true, force: true });
    }
  }
);

// ---------------------------------------------------------------------------------------------
// The driver: part B in a pinned Node image on a 96 MiB tmpfs. Each driver is a registration line
// below, runDriver(t, runtime) under the entry that runs.t8-container.images[runtime].driver in
// test/platform-manifest.json names: today one, for Node 24 (t8.driver.node24). The manifest alone
// registers nothing: a Node 26 driver needs an approved pinned image in images.26, its own driver
// entry and its own line here, and the T8 helper test below fails while an image has no line. It
// is registered, with the test below it, only on a host (platforms darwin and linux): inside its
// container both are absent, and a TEST_T8_DIR set on a host fails the environment test above
// instead. It runs when TEST_REQUIRE lists docker (its prerequisite `docker`), and fails then
// without Docker. Node 26 has no approved image yet, so it has no driver, and the coverage check
// of a host run reports the missing Node 26 evidence by name.

const docker = (...args) => spawnSync('docker', args, { encoding: 'utf8', timeout: 900000 });
// Finite memory, CPU and process limits, as every container the tests start has
// (test/docker-limits.test.mjs checks that). The 96 MiB tmpfs is memory, and counts against the
// 1 GiB: part B measured a peak of 276 MiB with it, and 18 processes.
const limits = ['--memory=1g', '--cpus=2', '--pids-limit=256'];

/**
 * Runs part B in the pinned image of Node `runtime` and checks the run inside: its exit status,
 * t8InnerProblems() (with the runtime its environment test reports), and the coverage check of
 * the t8-container run on that runtime, over the TAP and the records it wrote. The evidence (the
 * inner TAP and records) goes to TEST_PLATFORM_RECORDS when the gate set it, with a `container`
 * record naming the runtime, image, code and inner Node version; otherwise to a folder removed
 * after the test.
 */
function runDriver(t, runtime) {
  const { manifest, sha256: manifestSha256 } = platformManifest();
  const configured = manifest.runs['t8-container'].images[runtime];
  assert.ok(configured, `test/platform-manifest.json names no pinned image for Node ${runtime}`);
  const image = configured.image;
  // Node 24's is the Dockerfile's base image, by digest: --pull=never runs that image as it is.
  if (runtime === '24')
    assert.equal(
      image,
      /^FROM (node:24-bookworm-slim@sha256:[0-9a-f]{64})$/m.exec(
        fs.readFileSync(path.join(repository, 'Dockerfile'), 'utf8')
      )?.[1],
      "the Node 24 image is the Dockerfile's base image"
    );
  const copy = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-t8-tree-')));
  t.after(() => fs.rmSync(copy, { recursive: true, force: true }));
  for (const entry of [
    'server.mjs',
    'package.json',
    'Dockerfile',
    'lib',
    'public',
    'docs',
    'test',
    'scripts',
  ])
    fs.cpSync(path.join(repository, entry), path.join(copy, entry), { recursive: true });
  // The worktree's node_modules may be a symbolic link: the container gets a real copy.
  fs.cpSync(
    fs.realpathSync(path.join(repository, 'node_modules')),
    path.join(copy, 'node_modules'),
    {
      recursive: true,
      dereference: true,
    }
  );
  fs.chmodSync(copy, 0o755);
  // This run's one-time code: the run inside reports it and puts it in its records, so the
  // output read below is this run's.
  const code = randomBytes(32).toString('hex');
  // Where the evidence goes: beside the host's own records in a gate run, else a folder of its own.
  const settings = recordSettings();
  const evidence = fs.realpathSync(
    fs.mkdtempSync(path.join(settings?.directory ?? os.tmpdir(), `t8-container-${runtime}-`))
  );
  if (!settings) t.after(() => fs.rmSync(evidence, { recursive: true, force: true }));
  const inner = path.join(evidence, 'records');
  fs.mkdirSync(inner);
  // The container's user (node, uid 1000) writes its records there; closed again after the run.
  fs.chmodSync(inner, 0o777);
  const run = docker(
    'run',
    ...limits,
    '--rm',
    '--pull=never',
    '--network',
    'none',
    '--user',
    'node',
    '-e',
    'HOME=/tmp',
    '--tmpfs',
    '/t8:rw,size=96m,mode=1777',
    '-v',
    `${copy}:/src:ro`,
    '-v',
    `${inner}:/records`,
    '-w',
    '/src',
    '-e',
    'TEST_T8_DIR=/t8',
    '-e',
    `TEST_T8_RUN=${code}`,
    '-e',
    'TEST_PLATFORM_RECORDS=/records',
    '-e',
    `TEST_PLATFORM_RUN=${code}`,
    image,
    'node',
    '--test',
    '--test-reporter=tap',
    '--test-timeout=300000',
    '--import',
    './test/setup.mjs',
    'test/disk-full.test.mjs'
  );
  fs.chmodSync(inner, 0o700);
  fs.writeFileSync(path.join(evidence, 'inner.tap'), run.stdout ?? '', { mode: 0o600 });
  const output = `${run.stdout}${run.stderr}`;
  t.diagnostic(
    output
      .split('\n')
      .filter(line => /^\s*# /.test(line))
      .join('\n')
  );
  // For the record: the image, this run's code, the Node version inside, and the totals and
  // results of the run inside.
  const id = docker('image', 'inspect', '--format', '{{.Id}}', image).stdout.trim();
  const inside = (run.stdout ?? '').split('\n');
  const totals = inside
    .filter(line => /^# (tests|pass|fail|cancelled|skipped|todo) \d+$/.test(line))
    .map(line => line.slice(2))
    .join(', ');
  const read = readRecords(inner, { containers: false });
  // The Node version the environment test inside recorded; v0.0.0 when it recorded none, which
  // the coverage check of the host run then refuses as the wrong runtime.
  const node =
    read.records.find(record => record.kind === 'result' && record.id === 't8.environment')?.node ??
    'v0.0.0';
  t.diagnostic(
    `T8 driver: Node ${runtime} image ${image} (${id}); one-time code ${code}; inside: Node ${node}; ${totals}`
  );
  const results = inside.filter(line => /^(?:not )?ok \d+ - /.test(line));
  t.diagnostic(`T8 driver: the results inside:\n${results.join('\n')}`);
  const coverage = checkCoverage({
    manifest,
    manifestSha256,
    runId: 't8-container',
    runtime,
    tap: run.stdout ?? '',
    records: read.records,
    nonce: code,
    files: ['test/disk-full.test.mjs'],
  });
  assert.match(id, /^sha256:[0-9a-f]{64}$/, `docker image inspect ${image}`);
  // Which runtime produced this evidence, for the coverage check of the host run.
  writePlatformRecord({
    kind: 'container',
    id: configured.driver,
    runtime,
    image,
    imageId: id,
    code,
    node,
    evidence: path.basename(evidence),
    tapSha256: sha256(run.stdout ?? ''),
    recordsSha256: read.digest,
  });
  assert.equal(run.status, 0, output);
  // The run inside, by exact test name: the environment test, part B and the measurements each
  // passed once at the top level, nothing skipped or todo, this run's code and runtime reported,
  // and its records cover the container run's contract.
  assert.deepEqual(t8InnerProblems(run.stdout, code, runtime), [], output);
  assert.deepEqual([...read.problems, ...coverage.problems], [], output);
}

platformTest(import.meta.url, 't8.driver.node24', t8Names.driver, { timeout: 900000 }, t =>
  runDriver(t, '24')
);

// A TEST_T8_DIR that is not an empty 96 MiB tmpfs: here an empty folder this test cannot write
// to, so that even a part B registered by mistake could not fill it. The run of this file with
// it has the environment test, failing with the reason, and no other T8 test: nothing is written.
platformTest(
  import.meta.url,
  't8.host-regression',
  'T8: a TEST_T8_DIR that is not an empty 96 MiB tmpfs fails one test and fills nothing',
  { timeout: 120000 },
  t => {
    const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-t8-wrong-')));
    fs.chmodSync(dir, 0o555);
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    // A runner of its own (not this one's child), without this run's TEST_ variables.
    const env = Object.fromEntries(
      Object.entries(process.env).filter(
        ([name]) => !name.startsWith('TEST_') && name !== 'NODE_TEST_CONTEXT'
      )
    );
    const run = spawnSync(
      process.execPath,
      [
        '--test',
        '--test-reporter=tap',
        '--test-name-pattern=^T8 (environment|part B|measurements)',
        '--import',
        './test/setup.mjs',
        'test/disk-full.test.mjs',
      ],
      {
        cwd: repository,
        encoding: 'utf8',
        timeout: 100000,
        env: { ...env, TEST_T8_DIR: dir, TEST_T8_RUN: randomBytes(32).toString('hex') },
      }
    );
    const output = run.stdout + run.stderr;
    assert.equal(run.status, 1, output);
    assert.deepEqual(
      run.stdout.split('\n').filter(line => /^\s*(?:not )?ok \d+ - /.test(line)),
      [`not ok 1 - ${t8Names.environment}`],
      output
    );
    // The reason: two parts of it that read the same however the TAP reporter quotes it.
    for (const text of [`TEST_T8_DIR=${dir} is not the T8 driver`, 'so it is not registered.'])
      assert.ok(run.stdout.includes(text), output);
    assert.deepEqual(fs.readdirSync(dir), [], 'nothing was written there');
  }
);

test('T8 helpers: part B registers only on an empty 96 MiB tmpfs on Linux, not as root, with a code of the one-time code’s form', () => {
  const code = 'a'.repeat(64);
  const tmpfs = { type: 0x01021994, bsize: 4096, blocks: 24576, bfree: 24576 };
  const touched = [];
  const probe = (answers = {}) => ({
    platform: () => 'linux',
    uid: () => 1000,
    version: () => 'v24.21.0',
    readdir: directory => (touched.push(directory), []),
    statfs: directory => (touched.push(directory), tmpfs),
    ...answers,
  });
  const env = { TEST_T8_DIR: '/t8', TEST_T8_RUN: code };
  assert.equal(t8Environment({}, probe()), null, 'a host run: no part B test at all');
  assert.equal(t8Environment({ TEST_T8_DIR: '', TEST_T8_RUN: code }, probe()), null);
  assert.deepEqual(t8Environment(env, probe()), {
    ok: true,
    dir: '/t8',
    run: code,
    bytes: 96 * MiB,
    node: 'v24.21.0',
    uid: 1000,
  });
  // The diagnostic names the Node version and user that produced the evidence.
  assert.equal(
    t8RunLine(t8Environment(env, probe())),
    `T8 run ${code}: /t8 is an empty tmpfs of 100663296 bytes; node v24.21.0, uid 1000`
  );
  // Only the code's form is checked here: any code of that form passes, and the driver, which
  // knows its code, rejects a run that reports another (the next test).
  assert.equal(t8Environment({ ...env, TEST_T8_RUN: 'f'.repeat(64) }, probe()).ok, true);
  const refused = (answers, environmentVariables = env) => {
    touched.length = 0;
    const result = t8Environment(environmentVariables, probe(answers));
    assert.equal(result.ok, false);
    assert.ok(
      result.reason.startsWith(
        `TEST_T8_DIR=${environmentVariables.TEST_T8_DIR} is not the T8 driver's container tmpfs: `
      ),
      result.reason
    );
    return result.reason;
  };
  // Refused before anything there is read.
  assert.match(refused({ platform: () => 'darwin' }), /this is darwin, not Linux/);
  assert.deepEqual(touched, []);
  assert.match(refused({ uid: () => 0 }), /runs as root/);
  for (const run of [undefined, '', 'A'.repeat(64), 'a'.repeat(63), `${code}\n`, `${code}0`])
    assert.match(refused({}, { ...env, TEST_T8_RUN: run }), /TEST_T8_RUN is not a one-time code/);
  assert.match(refused({}, { ...env, TEST_T8_DIR: 't8' }), /not an absolute path/);
  assert.deepEqual(touched, []);
  // What is there.
  assert.match(refused({ readdir: () => ['filler-1'] }), /it is not empty/);
  const missing = Object.assign(new Error('gone'), { code: 'ENOENT' });
  assert.match(
    refused({
      readdir: () => {
        throw missing;
      },
    }),
    /cannot be read \(ENOENT\)/
  );
  assert.match(
    refused({ statfs: () => ({ ...tmpfs, type: 0xef53 }) }),
    /not on a tmpfs \(file system type 0xef53\)/
  );
  assert.match(
    refused({ statfs: () => ({ ...tmpfs, blocks: 2 * 24576, bfree: 2 * 24576 }) }),
    /holds 201326592 bytes, not 100663296/
  );
  assert.match(refused({ statfs: () => ({ ...tmpfs, bfree: 24575 }) }), /already holds data/);
});

test('T8 helpers: the driver accepts only a whole passing run inside, with its three tests and this run’s code', () => {
  const code = 'b'.repeat(64);
  const { environment: env, partB, measurements, driver } = t8Names;
  const passing = [
    'TAP version 13',
    '# Subtest: T8 part A: a full disk refuses settings',
    'ok 1 - T8 part A: a full disk refuses settings',
    `# Subtest: ${env}`,
    `ok 2 - ${env}`,
    '  ---',
    '  duration_ms: 1.5',
    '  ...',
    `# T8 run ${code}: /t8 is an empty tmpfs of 100663296 bytes`,
    `# Subtest: ${partB}`,
    `ok 3 - ${partB}`,
    `# Subtest: ${measurements}`,
    `ok 4 - ${measurements}`,
    '# WAL left at its high-water size: a new sign-in answered 200; session A read 200',
    '1..4',
    '# tests 4',
    '# suites 0',
    '# pass 4',
    '# fail 0',
    '# cancelled 0',
    '# skipped 0',
    '# todo 0',
    '# duration_ms 140000.5',
  ].join('\n');
  assert.deepEqual(t8InnerProblems(passing, code), []);
  const problems = (from, to, run = code) => {
    assert.ok(passing.includes(from), from);
    const found = t8InnerProblems(passing.replace(from, to), run);
    assert.notDeepEqual(found, [], to);
    return found.join('\n');
  };
  // Part B left out of the run, with totals that agree, or reported as a subtest.
  const withoutPartB = passing
    .replace(`# Subtest: ${partB}\nok 3 - ${partB}\n`, '')
    .replace(`ok 4 - ${measurements}`, `ok 3 - ${measurements}`)
    .replace('1..4', '1..3')
    .replace('# tests 4', '# tests 3')
    .replace('# pass 4', '# pass 3');
  assert.deepEqual(t8InnerProblems(withoutPartB, code), [`0 result lines for "${partB}", not one`]);
  assert.match(problems(`ok 3 - ${partB}`, `    ok 1 - ${partB}`), /did not pass at the top level/);
  // A skip, a todo or a failure inside, even with totals that agree.
  for (const [directive, total] of [
    ['SKIP no tmpfs', 'skipped'],
    ['TODO later', 'todo'],
  ]) {
    const tap = passing
      .replace(`ok 3 - ${partB}`, `ok 3 - ${partB} # ${directive}`)
      .replace('# pass 4', '# pass 3')
      .replace(`# ${total} 0`, `# ${total} 1`);
    const found = t8InnerProblems(tap, code).join('\n');
    assert.match(found, new RegExp(`has 1 ${total}`));
    assert.match(found, /did not pass at the top level/);
    assert.match(found, /passed 3 of 4 tests/);
  }
  assert.match(problems(`\nok 3 - ${partB}\n`, `\nnot ok 3 - ${partB}\n`), /did not pass/);
  assert.match(problems('# fail 0', '# fail 1'), /has 1 fail/);
  assert.match(problems('# cancelled 0', '# cancelled 1'), /has 1 cancelled/);
  // Totals: each exactly once.
  assert.match(problems('# tests 4\n', ''), /0 "# tests" lines/);
  assert.match(problems('# todo 0', '# todo 0\n# todo 0'), /2 "# todo" lines/);
  // Another run's code, none, or two.
  assert.match(problems('', '', 'c'.repeat(64)), /not this run's c{64}/);
  assert.match(problems(`# T8 run ${code}: `, '# T8 ran: '), /code nowhere/);
  assert.match(
    problems(`# T8 run ${code}: `, `# T8 run ${'d'.repeat(64)}: x\n# T8 run ${code}: `),
    /code d{64}, b{64}/
  );
  // The driver itself registered inside (skipped, as it was before).
  assert.match(
    problems('1..4', `ok 5 - ${driver} # SKIP this is the run inside the container\n1..4`),
    /the driver itself is named/
  );
});

test('T8 helpers: the driver refuses a run inside whose Node is not the runtime of its image', () => {
  const code = 'e'.repeat(64);
  const { environment: env, partB, measurements } = t8Names;
  const inside = node =>
    [
      `ok 1 - ${env}`,
      `# T8 run ${code}: /t8 is an empty tmpfs of 100663296 bytes${node === null ? '' : `; node ${node}, uid 1000`}`,
      `ok 2 - ${partB}`,
      `ok 3 - ${measurements}`,
      '1..3',
      '# tests 3',
      '# suites 0',
      '# pass 3',
      '# fail 0',
      '# cancelled 0',
      '# skipped 0',
      '# todo 0',
    ].join('\n');
  assert.deepEqual(t8InnerProblems(inside('v24.21.0'), code, '24'), []);
  assert.deepEqual(t8InnerProblems(inside('v26.5.1'), code, '26'), []);
  // A Node 24 run reported under a Node 26 image, the other way round, and no version at all.
  for (const [node, runtime] of [
    ['v24.21.0', '26'],
    ['v26.5.1', '24'],
    ['v2.4.0', '24'],
    [null, '24'],
  ])
    assert.match(
      t8InnerProblems(inside(node), code, runtime).join('\n'),
      new RegExp(`reported Node ${node ?? 'nowhere'}, not Node ${runtime}, the image's runtime`),
      `${node} under ${runtime}`
    );
  // Without a runtime (the earlier callers) the version is not judged.
  assert.deepEqual(t8InnerProblems(inside(null), code), []);
});

// The maintainer (2026-10-11, item 6): before any filler operation, the bounded file system, the
// dedicated empty folder, a user other than root and the driver's code are checked, and a setup
// that fails creates no filler file. Here the system is a stand-in whose open() and write() only
// record their calls, so nothing is ever written, whatever the checks say.
test('T8 helpers: a filler file is made only in an empty folder inside TEST_T8_DIR on its 96 MiB tmpfs, on Linux, not as root, under the code checked at registration', () => {
  const code = 'f'.repeat(64);
  const env = { TEST_T8_DIR: '/t8', TEST_T8_RUN: code };
  const tmpfs = { type: 0x01021994, bsize: 4096, blocks: 24576, bfree: 20000 };
  let opened, writes;
  const probe = (answers = {}) => {
    opened = [];
    writes = 0;
    return {
      platform: () => 'linux',
      uid: () => 1000,
      lstat: () => ({ isDirectory: () => true, dev: 7 }),
      stat: () => ({ dev: 7 }),
      realpath: file => file,
      readdir: () => [],
      statfs: () => tmpfs,
      open: (file, flags, mode) => (opened.push({ file, flags, mode }), 99),
      write: (fd, bytes) => {
        if (++writes > 3) throw Object.assign(new Error('full'), { code: 'ENOSPC' });
        return bytes.length;
      },
      close: () => {},
      ...answers,
    };
  };
  // Every check passes: one file, opened exclusively without following a link, filled until
  // ENOSPC (three whole chunks; no partial chunk fits after it).
  assert.equal(t8Fill('/t8/fill-1', { env, expected: code, probe: probe() }), 3 * MiB);
  const { O_WRONLY, O_CREAT, O_EXCL, O_NOFOLLOW } = fs.constants;
  assert.deepEqual(opened, [
    { file: '/t8/fill-1/filler', flags: O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode: 0o600 },
  ]);
  const refused = (answers, why, options = {}) => {
    assert.throws(
      () =>
        t8Fill(options.folder ?? '/t8/fill-1', {
          env: options.env ?? env,
          expected: options.expected ?? code,
          probe: probe(answers),
        }),
      error => {
        assert.match(error.message, why);
        assert.match(error.message, /Nothing was written\.$/);
        return true;
      }
    );
    assert.deepEqual(opened, [], `nothing opened: ${why}`);
  };
  refused({ platform: () => 'darwin' }, /this is darwin, not Linux/);
  refused({ uid: () => 0 }, /runs as root/);
  refused({}, /TEST_T8_RUN is not the code checked/, { expected: 'a'.repeat(64) });
  refused({}, /TEST_T8_RUN is not the code checked/, { env: { ...env, TEST_T8_RUN: undefined } });
  refused({}, /TEST_T8_RUN is not the code checked/, {
    env: { ...env, TEST_T8_RUN: 'F'.repeat(64) },
    expected: 'F'.repeat(64),
  });
  refused({}, /not an absolute path/, { env: { ...env, TEST_T8_DIR: 't8' } });
  refused({}, /not an absolute path/, { folder: 'fill-1' });
  refused(
    { lstat: () => ({ isDirectory: () => false, dev: 7 }) },
    /not a folder \(or it is a link\)/
  );
  refused(
    { realpath: file => (file === '/t8' ? '/t8' : '/elsewhere/fill-1') },
    /not a folder inside TEST_T8_DIR/
  );
  refused({}, /not a folder inside TEST_T8_DIR/, { folder: '/t8' });
  refused({ stat: () => ({ dev: 8 }) }, /not on the file system of TEST_T8_DIR/);
  refused({ readdir: () => ['filler'] }, /it is not empty/);
  refused(
    { statfs: () => ({ ...tmpfs, type: 0xef53 }) },
    /not on a tmpfs \(file system type 0xef53\)/
  );
  refused(
    { statfs: () => ({ ...tmpfs, blocks: 2 * 24576 }) },
    /holds 201326592 bytes, not 100663296/
  );
  // The real system, but for open() and write(): this host's temporary folder is refused (not
  // Linux here, or not the driver's tmpfs and code there), and stays empty.
  const real = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-t8-fill-')));
  const folder = path.join(real, 'fill');
  fs.mkdirSync(folder);
  try {
    assert.throws(
      () =>
        t8Fill(folder, {
          env: { TEST_T8_DIR: real, TEST_T8_RUN: code },
          expected: code,
          probe: {
            platform: () => process.platform,
            uid: () => process.getuid?.(),
            lstat: file => fs.lstatSync(file),
            stat: file => fs.statSync(file),
            realpath: file => fs.realpathSync(file),
            readdir: file => fs.readdirSync(file),
            statfs: file => fs.statfsSync(file),
            open: (file, flags, mode) => (opened.push({ file, flags, mode }), 99),
            write: () => assert.fail('nothing is written here'),
            close: () => {},
          },
        }),
      /T8 will not fill .*Nothing was written\.$/
    );
    assert.deepEqual(fs.readdirSync(folder), []);
  } finally {
    fs.rmSync(real, { recursive: true, force: true });
  }
});

test('T8 helpers: each runtime’s pinned image comes from the manifest, Node 24’s is the Dockerfile’s, and Node 26 has none until one is approved', () => {
  const { manifest } = platformManifest();
  const from = /^FROM (node:24-bookworm-slim@sha256:[0-9a-f]{64})$/m.exec(
    fs.readFileSync(path.join(repository, 'Dockerfile'), 'utf8')
  )?.[1];
  assert.ok(from);
  assert.deepEqual(t8Images(manifest), [
    { runtime: '24', image: from, driver: 't8.driver.node24' },
  ]);
  assert.equal(
    manifest.runs['t8-container'].images['26'],
    null,
    'no Node 26 image is approved yet'
  );
  assert.deepEqual(manifest.runs['t8-container'].runtimes, ['24', '26'], 'both are still required');
  // A fixture only: a synthetic Node 26 reference (never configured, never pulled) with its
  // driver entry is accepted and gives a second driver; a tag without a digest, another major or
  // an image without a driver entry is refused.
  const fixture = structuredClone(manifest);
  const node26 = `node:26-bookworm-slim@sha256:${'26'.repeat(32)}`;
  fixture.runs['t8-container'].images['26'] = { image: node26, driver: 't8.driver.node26' };
  fixture.entries.push({
    ...manifest.entries.find(entry => entry.id === 't8.driver.node24'),
    id: 't8.driver.node26',
    name: ['T8 part B passes in node:26-bookworm-slim on a size-limited tmpfs'],
  });
  const parsed = parseManifest(JSON.stringify(fixture));
  assert.deepEqual(parsed.problems, []);
  assert.deepEqual(
    t8Images(parsed.manifest).map(item => [item.runtime, item.image, item.driver]),
    [
      ['24', from, 't8.driver.node24'],
      ['26', node26, 't8.driver.node26'],
    ]
  );
  for (const [image, why] of [
    ['node:26-bookworm-slim', /images\.26\.image is not node:26… pinned by its sha256 digest/],
    [`node:24-bookworm-slim@sha256:${'26'.repeat(32)}`, /images\.26\.image is not node:26…/],
    [`node:26@sha256:${'2'.repeat(63)}`, /images\.26\.image is not node:26…/],
  ]) {
    const wrong = structuredClone(fixture);
    wrong.runs['t8-container'].images['26'].image = image;
    assert.match(parseManifest(JSON.stringify(wrong)).problems.join('\n'), why, image);
  }
  const orphan = structuredClone(fixture);
  orphan.entries = orphan.entries.filter(entry => entry.id !== 't8.driver.node26');
  assert.match(
    parseManifest(JSON.stringify(orphan)).problems.join('\n'),
    /images\.26\.driver "t8\.driver\.node26" is not an entry/
  );
  // verify-1: the manifest alone registers no driver. Each runtime with an image needs its own
  // registration line in this file, runDriver(t, runtime) under that image's driver entry; while
  // one is missing this test fails (and the contract test fails for an entry bound nowhere).
  const registered = [
    ...fs
      .readFileSync(fileURLToPath(import.meta.url), 'utf8')
      .matchAll(
        /platformTest\(\s*import\.meta\.url,\s*'([a-z0-9.-]+)',[^;]*?runDriver\(t, '(\d+)'\)\s*\);/g
      ),
  ].map(match => [match[1], match[2]]);
  const wanted = images => images.map(item => [item.driver, item.runtime]);
  assert.deepEqual(registered, wanted(t8Images(manifest)));
  assert.notDeepEqual(registered, wanted(t8Images(parsed.manifest)));
});
