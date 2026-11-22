import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { spawnSync } from 'node:child_process';
import { Store, periods } from '../lib/store.mjs';
import { ConfigStore } from '../lib/config.mjs';
import { historyWindow } from '../lib/series/shape.mjs';
// The HTTP server is never imported: these tests use lib/store.mjs directly (and, for the
// synthetic dataset, the configuration store it writes with).
function temporary(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-store-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}
function open(t) {
  const directory = temporary(t),
    store = new Store(directory);
  t.after(() => store.close());
  return { directory, store };
}
const measurements = value => [{ key: 'cpu', label: 'CPU', value, unit: '%' }];
// About 11 KB of JSON per reading, so a few hundred pages hold only a few dozen readings.
const large = Array.from({ length: 200 }, (_, i) => ({
  key: `guest_${i}`,
  label: `Guest ${i} CPU`,
  value: i,
  unit: '%',
}));
const source = { id: 'linux', name: 'Linux', rules: [] };
const pragma = (store, name) => store.db.prepare(`PRAGMA ${name}`).get()[name];
// Caps the database at its current size plus `extra` pages, standing in for a full disk.
// Writes re-read free space, so the disk is simulated too: a 64 MiB filesystem (which keeps
// its 64 MiB minimum reserve) whose free space shrinks as the database grows towards
// `space.limit` pages. Raising the limit frees space on the host.
function quota(t, store, extra) {
  const size = pragma(store, 'page_size'),
    blocks = 2 ** 26 / size,
    space = { limit: pragma(store, 'page_count') + extra };
  t.mock.method(fs, 'statfsSync', () => ({
    bsize: size,
    frsize: size,
    blocks,
    bavail: blocks + Math.max(0, space.limit - pragma(store, 'page_count')),
  }));
  store.db.exec(`PRAGMA max_page_count=${space.limit}`);
  return space;
}
const oldest = store => store.db.prepare('SELECT MIN(time) AS time FROM readings').get().time;
const bytes = file => (fs.existsSync(file) ? fs.statSync(file).size : 0);
// A history of `count` readings without the covering index, as 1.4.1 left it. Returns its
// directory and what building the index adds to the database, measured and rolled back.
function older(t, count, error = null) {
  const directory = temporary(t),
    store = new Store(directory),
    insert = store.db.prepare(
      'INSERT INTO readings(service,time,ok,metrics,error) VALUES (?,?,?,?,?)'
    ),
    now = Date.now();
  store.db.exec('DROP INDEX readings_history; BEGIN');
  for (let n = 0; n < count; n++)
    insert.run(`s${n % 20}`, now - n * 1000, error ? 0 : 1, '[]', error);
  store.db.exec('COMMIT; BEGIN');
  const before = pragma(store, 'page_count');
  store.db.exec('CREATE INDEX readings_history ON readings(service,time,ok,error)');
  const index = (pragma(store, 'page_count') - before) * pragma(store, 'page_size');
  store.db.exec('ROLLBACK; PRAGMA wal_checkpoint(TRUNCATE)');
  store.close();
  return { directory, index };
}
// A filesystem that holds only the history database and its WAL, with `free` bytes left
// above its 64 MiB reserve. Raising `space.total` frees space on the host. `space.lowest` is
// the least space left above the reserve at a checkpoint, which holds the whole WAL until
// the database has grown to take it. `space.builds` counts attempts to build the index.
function disk(t, directory, free) {
  const file = path.join(directory, 'history.sqlite'),
    used = () => bytes(file) + bytes(`${file}-wal`),
    space = {
      total: 2 ** 26 + used() + Math.round(free),
      spare: () => space.total - used() - 2 ** 26,
      lowest: Infinity,
      builds: 0,
    },
    exec = DatabaseSync.prototype.exec;
  t.mock.method(fs, 'statfsSync', () => ({
    bsize: 4096,
    frsize: 4096,
    blocks: Math.floor(space.total / 4096),
    bavail: Math.max(0, Math.floor((space.total - used()) / 4096)),
  }));
  t.mock.method(DatabaseSync.prototype, 'exec', function (sql) {
    const wal = bytes(`${file}-wal`);
    if (sql.startsWith('CREATE INDEX readings_history')) space.builds++;
    try {
      return exec.call(this, sql);
    } finally {
      if (sql.includes('wal_checkpoint'))
        space.lowest = Math.min(space.lowest, space.total - 2 ** 26 - bytes(file) - wal);
    }
  });
  return space;
}
const indexed = store =>
  Boolean(store.db.prepare("SELECT 1 FROM sqlite_master WHERE name='readings_history'").get());

test('a caller-supplied collection cycle keeps alert counts through queueing, not long silences', t => {
  const { store } = open(t),
    now = Date.now(),
    // Longer than (60 s poll + 90 s timeout) * 3, like a queue of many slow failing sources.
    backlog = 500000,
    queued = { ...source, staleAfterMs: 3 * backlog };
  assert.deepEqual(store.evaluate(queued, [], 'Failed', now), []);
  assert.equal(store.evaluate(queued, [], 'Failed', now + backlog)[0]?.kind, 'firing');
  assert.deepEqual(store.evaluate(queued, [], null, now + 2 * backlog), []);
  assert.equal(store.evaluate(queued, [], null, now + 3 * backlog)[0]?.kind, 'resolved');
  // A silence longer than the allowance (restart, suspend, storage outage) still resets.
  assert.deepEqual(store.evaluate(queued, [], 'Failed', now + 4 * backlog), []);
  assert.deepEqual(store.evaluate(queued, [], 'Failed', now + 8 * backlog), []);
  assert.deepEqual(store.alerts(), []);
  // Without an allowance, the default (poll + timeout) * 3 applies.
  assert.deepEqual(store.evaluate(source, [], 'Failed', now + 9 * backlog), []);
  assert.deepEqual(store.evaluate(source, [], 'Failed', now + 10 * backlog), []);
  assert.deepEqual(store.alerts(), []);
});

test('a rule key holding half a surrogate pair fires on the reading collectors make whole', t => {
  const { store } = open(t),
    now = Date.now();
  // A hand-edited config.json (or a 1.4.x save) can hold such a key; collectors send the reading
  // key made whole (U+FFFD). The key was bound as U+FFFD but compared as it was: its pending row
  // never matched again, and the rule never fired.
  const service = {
    id: 'svc',
    name: 'n',
    pollSeconds: 60,
    rules: [
      { key: 'disk\ud800', operator: 'gt', threshold: 1, forSeconds: 60 },
      // Another key that is the same once whole: one rule, the first.
      { key: 'disk\udbff', operator: 'gt', threshold: 99, forSeconds: 0 },
    ],
  };
  for (const reading of ['disk\ufffd', 'disk\ud800']) {
    store.db.exec('DELETE FROM alerts');
    const kinds = [];
    for (let i = 0; i < 3; i++)
      kinds.push(
        ...store
          .evaluate(service, [{ key: reading, label: 'Disk', value: 5 }], null, now + i * 60000)
          .map(event => event.kind)
      );
    assert.deepEqual(kinds, ['firing'], JSON.stringify(reading));
    assert.deepEqual(
      store.db
        .prepare("SELECT rule, state FROM alerts WHERE service = 'svc'")
        .all()
        .map(row => [row.rule, row.state]),
      [['disk\ufffd', 'firing']]
    );
  }
});

test('history gaps allow for collection time and queueing, and report the threshold', t => {
  const { store } = open(t),
    now = Date.now();
  // A 15 s interval whose collection plus queue wait spaces readings 50 s apart.
  for (let n = 71; n >= 0; n--) store.record('b', measurements(n), null, now - n * 50000);
  const history = store.history('b', '1h', now, 15);
  assert.equal(history.maxGapMs, (15 + 90) * 3000);
  assert.equal(history.points.length, 72);
  assert.equal(history.points.filter(p => p.gapBefore).length, 0);
  const tight = store.history('b', '1h', now, 15, 1);
  assert.equal(tight.maxGapMs, 48000);
  assert.ok(tight.points.slice(1).every(p => p.gapBefore));
});

test('history periods ignore Object.prototype keys', t => {
  const { store } = open(t),
    now = Date.now();
  assert.ok(Object.isFrozen(periods));
  assert.deepEqual(Object.keys(periods), ['1h', '6h', '24h', '7d', '30d']);
  for (const key of ['constructor', '__proto__', 'toString', 'hasOwnProperty', 'valueOf']) {
    assert.equal(Object.hasOwn(periods, key), false);
    assert.equal(periods[key], undefined);
    assert.equal(store.history('a', key, now).from, now - periods['24h']);
  }
});

test('a full history database recycles its oldest readings so recording continues', t => {
  const { store } = open(t),
    start = Date.now() - 86400000,
    last = start + 399 * 60000,
    event = store.db.prepare('INSERT INTO events(service,time,kind,message) VALUES(?,?,?,?)');
  event.run('linux', start - 1, 'firing', 'Older than any reading');
  event.run('linux', last, 'firing', 'Recent');
  quota(t, store, 300);
  for (let n = 0; n < 400; n++) store.record('linux', large, null, start + n * 60000);
  const { samples } = store.stats(),
    first = oldest(store);
  assert.ok(samples > 0 && samples < 400, `${samples} readings kept`);
  assert.ok(first > start);
  assert.equal(
    store.db.prepare('SELECT COUNT(*) AS count FROM readings WHERE time>=?').get(first).count,
    samples,
    'only the oldest readings were dropped'
  );
  assert.equal(store.latest('linux').lastSuccess, last);
  assert.deepEqual(
    store.events().map(e => e.message),
    ['Recent']
  );
  store.markGap('linux', last + 60000);
  assert.equal(store.history('linux', '24h', last + 60000).points.at(-1).ok, false);
});

test('history stays below the free disk space and follows it on each prune', async t => {
  // A 64 MiB filesystem keeps its 64 MiB minimum reserve, so the spare is `free` pages, less
  // what the database has grown since it was opened.
  const disk = { blocks: 16384, free: 300, grown: () => 0 };
  t.mock.method(fs, 'statfsSync', () => ({
    bsize: 4096,
    frsize: 4096,
    blocks: disk.blocks,
    bavail: disk.blocks + disk.free - disk.grown(),
  }));
  const { store } = open(t),
    start = Date.now() - 86400000,
    initial = pragma(store, 'page_count');
  disk.grown = () => pragma(store, 'page_count') - initial;
  assert.equal(pragma(store, 'page_size'), 4096);
  assert.equal(pragma(store, 'max_page_count'), initial + 300);
  for (let n = 0; n < 400; n++) store.record('linux', large, null, start + n * 60000);
  assert.ok(pragma(store, 'page_count') <= initial + 300);
  assert.ok(store.stats().samples < 400);
  assert.equal(store.latest('linux').lastSuccess, start + 399 * 60000);
  // Space freed elsewhere raises the cap at the next prune; a filesystem that reports no
  // size leaves the last cap in place.
  disk.free = 1000;
  await store.prune(30);
  const cap = pragma(store, 'max_page_count');
  assert.equal(cap, initial + 1000);
  disk.blocks = 0;
  await store.prune(30);
  assert.equal(pragma(store, 'max_page_count'), cap);
});

test('space freed on the host is used at once, instead of recycling history until a prune', t => {
  const { store } = open(t),
    now = Date.now(),
    space = quota(t, store, 60);
  for (let n = 0; n < 40; n++) store.record('linux', large, null, now - (40 - n) * 60000);
  const kept = store.stats().samples,
    first = oldest(store);
  assert.ok(kept < 40, 'the disk filled up and history was recycled');
  space.limit += 2000;
  for (let n = 0; n < 5; n++) store.record('linux', large, null, now + n * 60000);
  assert.equal(store.stats().samples, kept + 5);
  assert.equal(oldest(store), first, 'no more history was recycled');
});

test('writes follow space that other programs use, without waiting for a prune', t => {
  const clock = { now: 0 };
  t.mock.method(performance, 'now', () => clock.now);
  const { store } = open(t),
    now = Date.now(),
    space = quota(t, store, 5000);
  space.limit -= 4000;
  store.record('linux', measurements(1), null, now);
  assert.equal(pragma(store, 'max_page_count'), space.limit + 4000, 'checked once a minute');
  clock.now += 60000;
  store.record('linux', measurements(2), null, now + 60000);
  assert.equal(pragma(store, 'max_page_count'), space.limit);
});

test('alert evaluation recycles history when a full database has no room for alert state', t => {
  const { store } = open(t),
    now = Date.now(),
    insert = store.db.prepare('INSERT INTO readings(service,time,ok,metrics) VALUES (?,?,1,?)');
  quota(t, store, 100);
  let n = 0;
  // Large readings first, then small ones to use up the last partly free pages.
  for (const metrics of [JSON.stringify(large), '[]'])
    assert.throws(() => {
      for (;;) insert.run('linux', now - 86400000 + n++, metrics);
    }, /full/);
  // A long label makes the alert row need new pages.
  const metric = [{ key: 'cpu', label: 'CPU '.repeat(2000), value: 95, unit: '%' }],
    s = { ...source, rules: [{ key: 'cpu', operator: 'gt', threshold: 90, forSeconds: 0 }] };
  assert.deepEqual(store.evaluate(s, metric, null, now), []);
  assert.equal(store.evaluate(s, metric, null, now + 1000)[0]?.kind, 'firing');
  assert.equal(store.alerts().length, 1);
  assert.equal(store.events().length, 1);
});

test('a write that does not fit even after recycling reports SQLITE_FULL and rolls back', t => {
  const { store } = open(t),
    now = Date.now();
  quota(t, store, 0);
  assert.throws(() => store.record('linux', large, null, now), { errcode: 13 });
  assert.equal(store.stats().samples, 0);
  assert.equal(store.latest('linux').lastAttempt, null);
  store.db.exec('PRAGMA max_page_count=1073741823');
  store.record('linux', large, null, now);
  assert.equal(store.stats().samples, 1);
});

test('pruning deletes in short transactions, so it needs little free disk space', async t => {
  const { directory, store } = open(t),
    now = Date.now(),
    metrics = JSON.stringify(large.slice(0, 8)),
    insert = store.db.prepare('INSERT INTO readings(service,time,ok,metrics) VALUES (?,?,1,?)'),
    event = store.db.prepare('INSERT INTO events(service,time,kind,message) VALUES(?,?,?,?)');
  store.db.exec('BEGIN');
  for (let n = 0; n < 20000; n++) insert.run(`s${n % 20}`, now - 3 * 86400000 + n * 1000, metrics);
  for (let n = 0; n < 100; n++) insert.run('s0', now - n * 1000, metrics);
  for (let n = 0; n < 2500; n++) event.run('s0', now - 2 * 86400000 + n, 'firing', 'Old');
  event.run('s0', now, 'firing', 'Recent');
  store.db.exec('COMMIT');
  store.db.exec('PRAGMA wal_checkpoint(TRUNCATE); PRAGMA wal_autocheckpoint=50');
  await store.prune(1, now);
  const wal = fs.statSync(path.join(directory, 'history.sqlite-wal')).size;
  assert.ok(wal < 2e6, `the WAL grew to ${wal} bytes`);
  assert.equal(store.stats().samples, 100);
  assert.deepEqual(
    store.events().map(e => e.message),
    ['Recent']
  );
});

test('a large prune lets collection run between chunks, and stops quietly on shutdown', async t => {
  const directory = temporary(t),
    store = new Store(directory),
    now = Date.now(),
    insert = store.db.prepare('INSERT INTO readings(service,time,ok,metrics) VALUES (?,?,1,?)'),
    old = () => {
      store.db.exec('BEGIN');
      for (let n = 0; n < 5000; n++) insert.run('old', now - 3 * 86400000 + n, '[]');
      store.db.exec('COMMIT');
    };
  old();
  const pruning = store.prune(1, now);
  assert.ok(store.stats().samples > 1000, 'only the first chunk ran before yielding');
  store.record('linux', measurements(1), null, now);
  assert.deepEqual(store.evaluate(source, measurements(1), null, now), []);
  await pruning;
  assert.equal(store.stats().samples, 1);
  old();
  const stopped = store.prune(1, now);
  store.close();
  await stopped;
});
test('a write that cannot fit even after recycling does not keep eating history', t => {
  const { store } = open(t),
    now = Date.now();
  for (let n = 0; n < 60; n++) store.record('linux', large, null, now - (60 - n) * 1000);
  quota(t, store, 0);
  // Far larger than one recycled chunk can free.
  const huge = Array.from({ length: 5000 }, (_, i) => ({
    key: `k${i}`,
    label: 'x'.repeat(200),
    value: i,
    unit: '%',
  }));
  assert.throws(() => store.record('linux', huge, null, now), /full/);
  const after = store.stats().samples;
  // Alternate with alert evaluation, as each poll does, so no other commit resets anything.
  for (let i = 1; i <= 5; i++) {
    assert.throws(() => store.record('linux', huge, null, now + i), /full/);
    store.evaluate(source, measurements(1), null, now + i);
  }
  assert.equal(store.stats().samples, after);
});

test('forgetting a source works in chunks and removes its readings, alerts and events', async t => {
  const { store } = open(t),
    now = Date.now(),
    s = {
      ...source,
      id: 'big',
      availabilityFailures: 1,
      availabilitySeconds: 0,
      recoverySuccesses: 1,
      recoverySeconds: 0,
    };
  for (let n = 0; n < 2500; n++) store.record('big', measurements(n), n % 7 ? null : 'x', now + n);
  store.record('other', measurements(1), null, now);
  assert.equal(store.evaluate(s, [], 'Refused', now + 3000)[0].kind, 'firing');
  const forgetting = store.forget('big');
  assert.ok(store.stats().samples > 1000, 'only the first chunk ran before yielding');
  // A poll that finishes during the deletion leaves nothing behind either.
  store.record('big', measurements(1), null, now + 4000);
  await forgetting;
  assert.equal(store.latest('big').lastAttempt, null);
  assert.equal(store.stats().samples, 1);
  assert.deepEqual(store.alerts(), []);
  assert.deepEqual(store.events(), []);
  // IDs are reused (type-N): a new source must not recover from the old one's outage.
  assert.deepEqual(store.evaluate(s, measurements(1), null, now + 5000), []);
  assert.deepEqual(store.events(), []);
});

test('history reads only a covering index, which older databases gain on open', t => {
  const directory = temporary(t),
    plan = store =>
      store.db
        .prepare(
          'EXPLAIN QUERY PLAN SELECT time,ok,error FROM readings WHERE service=? AND time>=? AND time<=? ORDER BY time'
        )
        .all('a', 0, 1)
        .map(row => row.detail)
        .join('; '),
    first = new Store(directory);
  // Without it, each reading costs one random table page: seconds for a cold 30-day chart.
  assert.match(plan(first), /COVERING INDEX readings_history/);
  first.db.exec('DROP INDEX readings_history');
  first.record('a', measurements(1), null, Date.now());
  first.close();
  // A full disk must not stop Uptime Goblin from starting; the next start builds the index.
  const exec = DatabaseSync.prototype.exec;
  const mock = t.mock.method(DatabaseSync.prototype, 'exec', function (sql) {
    if (sql.startsWith('CREATE INDEX readings_history'))
      throw Object.assign(new Error('database or disk is full'), { errcode: 13 });
    return exec.call(this, sql);
  });
  const degraded = new Store(directory);
  assert.doesNotMatch(plan(degraded), /COVERING/);
  assert.equal(degraded.history('a', '1h').points.length, 1);
  degraded.close();
  mock.mock.restore();
  const reopened = new Store(directory);
  t.after(() => reopened.close());
  assert.match(plan(reopened), /COVERING INDEX readings_history/);
});

test('a history at its disk budget starts and records without the index, built once there is room', t => {
  const { directory, index } = older(t, 20000),
    wal = path.join(directory, 'history.sqlite-wal'),
    // Free space is down to the reserve, as when history has filled its budget.
    space = disk(t, directory, 0),
    now = Date.now();
  const full = new Store(directory);
  assert.equal(indexed(full), false);
  assert.equal(space.builds, 0, 'a build that cannot fit is not attempted');
  assert.equal(space.spare(), 0, 'the reserve is untouched');
  full.record('s0', measurements(1), null, now + 1000);
  assert.equal(full.history('s0', '1h', now + 1000).points.at(-1).time, now + 1000);
  full.close();
  // The operator frees space: the next start builds the index and checkpoints it.
  space.total += 2 ** 26;
  const reopened = new Store(directory);
  t.after(() => reopened.close());
  assert.equal(indexed(reopened), true);
  assert.equal(bytes(wal), 0);
  assert.ok(space.lowest >= 2 ** 26 - 3 * index, `${space.lowest} bytes left at the checkpoint`);
});

test('the history index is only committed when its checkpoint fits above the reserve', t => {
  // Long errors make the index far larger than an estimate from the number of readings.
  const { directory, index } = older(t, 10000, 'Connection refused '.repeat(30)),
    file = path.join(directory, 'history.sqlite'),
    size = bytes(file),
    space = disk(t, directory, 0),
    base = space.total;
  assert.ok(index > 4e6, `an index of ${index} bytes spills out of the page cache`);
  // With less room than the index, the build runs out of space and must not leave the pages
  // it spilled in the WAL. With room for the index but not for its checkpoint as well, it
  // must not commit: the checkpoint would fill the disk.
  for (const room of [0.6, 1.5]) {
    space.total = base + Math.round(room * index);
    const store = new Store(directory);
    assert.equal(space.builds, 1, `${room} × the index size`);
    assert.equal(indexed(store), false, `${room} × the index size`);
    assert.equal(bytes(`${file}-wal`), 0, `${room} × the index size`);
    assert.ok(space.lowest >= 0, `${room} × the index size: ${space.lowest} bytes left`);
    store.close();
    assert.equal(bytes(file), size);
    space.builds = 0;
  }
  space.total = base + Math.round(2.5 * index);
  const store = new Store(directory);
  t.after(() => store.close());
  assert.equal(indexed(store), true);
  assert.equal(bytes(`${file}-wal`), 0);
  assert.ok(space.lowest >= 0, `${space.lowest} bytes left at the checkpoint`);
  assert.ok(space.spare() >= index, `${space.spare()} bytes left above the reserve`);
});

test('failed readings keep their reason, and availability alerts say why and for how long', t => {
  const { store } = open(t),
    now = Date.now(),
    s = {
      ...source,
      availabilityFailures: 1,
      availabilitySeconds: 0,
      recoverySuccesses: 1,
      recoverySeconds: 0,
    };
  store.record('linux', [], 'Connection timed out. Check network access.', now);
  const fired = store.evaluate(s, [], 'Connection timed out. Check network access.', now);
  assert.equal(
    fired[0].message,
    'Source is unavailable: Connection timed out. Check network access.'
  );
  store.record('linux', measurements(1), null, now + 600000);
  const resolved = store.evaluate(s, measurements(1), null, now + 600000);
  assert.equal(resolved[0].message, 'Connection restored after 10 min');
  const failure = store.history('linux', '1h', now + 600000, 60).points.find(p => !p.ok);
  assert.equal(failure.error, 'Connection timed out. Check network access.');
});

test('record() stores a non-string error as text and cuts a long one, in readings and latest alike', t => {
  const { store } = open(t),
    now = Date.now();
  const stored = id =>
    store.db
      .prepare(
        'SELECT r.error AS reading, l.error AS latest FROM readings r JOIN latest l ON l.service = r.service WHERE r.service = ?'
      )
      .get(id);
  // An Error object failed the whole record (latest.error was bound as given), readings too.
  assert.equal(store.record('object', [], new Error('synthetic failure'), now), true);
  assert.deepEqual(
    { ...stored('object') },
    {
      reading: 'Error: synthetic failure',
      latest: 'Error: synthetic failure',
    }
  );
  // Megabytes of reason were stored whole; history keeps 300 characters, cut between characters.
  store.record('huge', [], 'SYNTHETIC '.repeat(200_000), now);
  assert.deepEqual(
    { ...stored('huge') },
    {
      reading: 'SYNTHETIC '.repeat(30),
      latest: 'SYNTHETIC '.repeat(30),
    }
  );
  store.record('pairs', [], '😀'.repeat(400) + '\u0000', now);
  assert.equal(stored('pairs').reading, '😀'.repeat(300));
  assert.equal(store.latest('pairs').error, '😀'.repeat(300));
  // A reason that fits is kept exactly as before.
  store.record('short', [], 'Connection timed out. Check network access.', now);
  assert.equal(stored('short').latest, 'Connection timed out. Check network access.');
});

test('the Store keeps its connection private: server code holding it has no raw SQL', t => {
  const directory = temporary(t);
  const module = new URL('../lib/store.mjs', import.meta.url).href;
  // Without test/setup.mjs, as the server runs: routes hold the Store, and store.db was a
  // DatabaseSync any of them could hand SQL text to.
  const child = spawnSync(
    process.execPath,
    [
      '--input-type=module',
      '-e',
      `import assert from 'node:assert/strict';
       const { Store } = await import(${JSON.stringify(module)});
       const store = new Store(process.argv[1]);
       assert.throws(() => store.db, /keeps its connection to itself/);
       assert.ok(!Object.keys(store).includes('db'));
       store.record('a', [{ key: 'cpu', label: 'CPU', value: 1, unit: '%' }], null, 1);
       assert.equal(store.latest('a').metrics[0].value, 1);
       store.close();`,
      directory,
    ],
    { encoding: 'utf8', timeout: 10000 }
  );
  assert.equal(child.status, 0, child.stderr);
  // Tests opt in (test/setup.mjs); the connection runs with trusted_schema off.
  const { store } = open(t);
  assert.equal(store.db.prepare('PRAGMA trusted_schema').get().trusted_schema, 0);
});

test('older databases gain the reading error column without losing history', t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-store-migrate-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const first = new Store(directory);
  first.db.exec('DROP INDEX readings_history; ALTER TABLE readings DROP COLUMN error');
  first.db
    .prepare('INSERT INTO readings(service,time,ok,metrics) VALUES (?,?,1,?)')
    .run('old', Date.now(), JSON.stringify(measurements(3)));
  first.close();
  const reopened = new Store(directory);
  t.after(() => reopened.close());
  assert.equal(reopened.stats().samples, 1);
  reopened.record('old', [], 'Refused', Date.now() + 1);
  assert.ok(reopened.db.prepare('SELECT error FROM readings WHERE ok=0').get().error === 'Refused');
});

test('recovery reports the outage up to the first healthy reading, and pauses are gaps', t => {
  const { store } = open(t),
    now = Date.now(),
    s = {
      ...source,
      availabilityFailures: 1,
      availabilitySeconds: 0,
      recoverySuccesses: 2,
      recoverySeconds: 600,
      staleAfterMs: 3600000,
    };
  store.evaluate(s, [], 'Refused', now);
  store.evaluate(s, measurements(1), null, now + 4 * 60000);
  const resolved = store.evaluate(s, measurements(1), null, now + 14 * 60000);
  assert.equal(resolved[0].message, 'Connection restored after 4 min');
  store.markGap('paused', now);
  store.record('paused', [], 'Refused', now + 60000);
  const points = store.history('paused', '1h', now + 120000, 60).points;
  assert.deepEqual(
    points.map(p => [p.ok, p.gap ?? false, p.error ?? null]),
    [
      [false, true, null],
      [false, false, 'Refused'],
    ]
  );
});

test('a pause in the same history bucket does not hide the failure before it, or after it', t => {
  const { store } = open(t),
    now = Date.now(),
    width = periods['24h'] / 300,
    // Starts of two 24h buckets (288 s wide).
    b = now - periods['24h'] + 100 * width,
    c = b + 50 * width;
  store.record('a', measurements(1), null, b + 5000);
  store.record('a', [], 'Rejected credentials (HTTP 401)', b + 65000);
  store.record('a', [], 'Rejected credentials (HTTP 401)', b + 125000);
  store.markGap('a', b + 185000);
  store.markGap('a', c + 5000);
  store.record('a', [], 'Connection refused', c + 65000);
  assert.deepEqual(
    store.history('a', '24h', now).points.map(p => [p.time, p.ok, p.gap ?? false, p.error]),
    [
      [b + 5000, true, false, undefined],
      [b + 125000, false, false, 'Rejected credentials (HTTP 401)'],
      [b + 185000, false, true, null],
      [c + 5000, false, true, null],
      [c + 65000, false, false, 'Connection refused'],
    ]
  );
});

test('a silence is marked on the first point after it, even when that point is a failure', t => {
  const { store } = open(t),
    now = Date.now(),
    minute = 60000,
    points = (id, period) =>
      store.history(id, period, now).points.map(p => [p.time, p.ok, p.gapBefore]);
  for (const [id, period] of [
    ['a', '24h'],
    ['b', '30d'],
  ]) {
    // The start of a bucket: 145 min wide in the 30d range (whole 5-minute summary slots, from a
    // slot boundary), 288 s in the 24h range.
    const window = historyWindow(period, now),
      b = window.from + 100 * window.width;
    for (let n = 0; n <= 20; n++) store.record(id, measurements(n), null, b + n * minute);
    // 2 hours without readings (Uptime Goblin stopped), then a failure and a recovery.
    store.record(id, [], 'Refused', b + 140 * minute);
    store.record(id, measurements(1), null, b + 145 * minute);
    store.record(id, measurements(2), null, b + 146 * minute);
    const history = points(id, period),
      failure = history.find(([time]) => time === b + 140 * minute);
    assert.deepEqual(failure, [b + 140 * minute, false, true], period);
    if (period === '30d')
      // The bucket [readings][silence][failure] must not mark the silence before its sample.
      assert.deepEqual(history, [
        [b + 20 * minute, true, false],
        [b + 140 * minute, false, true],
        [b + 146 * minute, true, false],
      ]);
  }
});

test('a history index that cannot be built never stops Uptime Goblin from starting', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-index-damaged-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  let store = new Store(dir);
  const now = Date.now();
  for (let n = 0; n < 20000; n++) store.record('s' + (n % 7), [], 'x'.repeat(40), now - n * 1000);
  store.db.exec('DROP INDEX readings_history');
  store.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
  // A leaf page of the readings table, from the middle of it.
  const leaves = store.db
      .prepare(
        "SELECT pageno FROM dbstat WHERE name='readings' AND pagetype='leaf' ORDER BY pageno"
      )
      .all(),
    { page_size: size } = store.db.prepare('PRAGMA page_size').get();
  store.close();
  const file = path.join(dir, 'history.sqlite'),
    bytes = fs.readFileSync(file),
    offset = (leaves[Math.floor(leaves.length / 2)].pageno - 1) * size;
  bytes.fill(0xff, offset, offset + size);
  fs.writeFileSync(file, bytes);
  const errors = [];
  t.mock.method(console, 'error', (...args) => errors.push(args.join(' ')));
  store = new Store(dir);
  t.after(() => store.close());
  assert.ok(errors.some(line => /History index could not be built/.test(line)));
  store.record('new', [{ key: 'cpu', label: 'CPU', value: 1, unit: '%' }], null, now);
  assert.equal(store.latest('new').metrics[0].value, 1);
});

test('the history index is sorted in the data directory, and the setting is reset afterwards', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "orbit-index-temp-'quote-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const store = new Store(dir);
  t.after(() => store.close());
  assert.ok(
    store.db.prepare("SELECT 1 FROM sqlite_master WHERE name='readings_history'").get(),
    'the index is built, even with a quote in the data directory path'
  );
  // The setting is process-wide in SQLite; nothing else may inherit it.
  // An unset directory returns no row.
  assert.equal(
    store.db.prepare('PRAGMA temp_store_directory').get()?.temp_store_directory ?? '',
    ''
  );
});

// Collector notes (1.4.3): latest_notes keeps the notes of each source's latest successful
// collection, beside `latest` rather than in it, so 1.4.2 can still read `latest`.
const capped = (omitted = 3) => [
  { code: 'measurements_capped', message: `Left out ${omitted}.`, omitted },
];
const noteRows = store => store.db.prepare('SELECT * FROM latest_notes ORDER BY service').all();

test('notes follow the latest successful collection, survive failures and clear when gone', t => {
  const { store } = open(t),
    now = Date.now();
  assert.deepEqual(store.latest('a').notes, []);
  store.record('a', measurements(1), null, now, capped());
  assert.deepEqual(store.latest('a').notes, capped());
  // A failure keeps showing the last successful readings, so their notes stay too.
  store.record('a', [], 'Refused', now + 1000, capped(9));
  assert.equal(store.latest('a').lastSuccess, now);
  assert.deepEqual(store.latest('a').notes, capped());
  // Newer notes replace older ones; a success without notes removes the row.
  store.record('a', measurements(2), null, now + 2000, capped(7));
  assert.deepEqual(store.latest('a').notes, capped(7));
  assert.equal(noteRows(store)[0].time, now + 2000);
  store.record('a', measurements(3), null, now + 3000);
  assert.deepEqual(store.latest('a').notes, []);
  assert.deepEqual(noteRows(store), []);
  // Sources without notes never write the table.
  for (let n = 0; n < 5; n++) store.record('b', measurements(n), null, now + n);
  assert.deepEqual(noteRows(store), []);
});

test('notes default to the ones a collector attached to its readings', t => {
  const { store } = open(t),
    now = Date.now(),
    readings = Object.defineProperty(measurements(1), 'notes', { value: capped(4) });
  store.record('a', readings, null, now);
  assert.deepEqual(store.latest('a').notes, capped(4));
  // Explicit notes win over the attached ones, and the stored readings never include them.
  store.record('a', readings, null, now + 1, []);
  assert.deepEqual(store.latest('a').notes, []);
  assert.deepEqual(store.latest('a').metrics, measurements(1));
});

test('stored notes are bounded: 8 per source, one per code, 200 characters, known shape', t => {
  const { store } = open(t),
    now = Date.now(),
    many = Array.from({ length: 12 }, (_, i) => ({ code: `code_${i}`, message: `Note ${i}` }));
  store.record('a', measurements(1), null, now, [
    { code: 'long', message: 'x'.repeat(500), omitted: 2.5 },
    { code: 'long', message: 'duplicate code' },
    { code: 'Bad Code', message: 'refused' },
    { code: 'blank', message: '   ' },
    { code: 'object', message: { toString: () => 'refused' } },
    null,
    'text',
    ...many,
  ]);
  const notes = store.latest('a').notes;
  assert.equal(notes.length, 8);
  assert.deepEqual(notes[0], { code: 'long', message: 'x'.repeat(199) + '…' });
  assert.deepEqual(
    notes.slice(1).map(n => n.code),
    many.slice(0, 7).map(n => n.code)
  );
  // Not an array: nothing is stored.
  store.record('b', measurements(1), null, now, { code: 'x', message: 'y' });
  assert.deepEqual(store.latest('b').notes, []);
  // A damaged row cannot break the dashboard.
  store.db.prepare("UPDATE latest_notes SET notes='{' WHERE service='a'").run();
  assert.deepEqual(store.latest('a').notes, []);
});

test('notes older than the last success are hidden, as after running 1.4.2 in between', t => {
  const { store } = open(t),
    now = Date.now();
  store.record('a', measurements(1), null, now, capped());
  // 1.4.2 records a success with exactly this statement, and knows nothing of latest_notes.
  store.db
    .prepare(
      'INSERT INTO latest VALUES (?,?,?,?,NULL) ON CONFLICT(service) DO UPDATE SET attempted=excluded.attempted,success=excluded.success,metrics=excluded.metrics,error=NULL'
    )
    .run('a', now + 1000, now + 1000, JSON.stringify(measurements(2)));
  assert.deepEqual(store.latest('a').notes, []);
  assert.equal(noteRows(store).length, 1, 'the stale row stays until the next success');
  store.record('a', measurements(3), null, now + 2000, capped(5));
  assert.deepEqual(store.latest('a').notes, capped(5));
});

test('forgetting a source removes its notes, and older databases gain the notes table', async t => {
  const directory = temporary(t),
    store = new Store(directory),
    now = Date.now();
  store.record('gone', measurements(1), null, now, capped());
  store.record('kept', measurements(1), null, now, capped(2));
  await store.forget('gone');
  assert.deepEqual(
    noteRows(store).map(r => r.service),
    ['kept']
  );
  // A 1.4.2 database has no latest_notes table: opening it adds one and keeps the rest.
  store.db.exec('DROP TABLE latest_notes');
  store.close();
  const reopened = new Store(directory);
  t.after(() => reopened.close());
  assert.equal(reopened.latest('kept').lastSuccess, now);
  assert.deepEqual(reopened.latest('kept').notes, []);
  reopened.record('kept', measurements(2), null, now + 1, capped(6));
  assert.deepEqual(reopened.latest('kept').notes, capped(6));
});

test('history can be limited to selected measurements, in the same shape', t => {
  const { store } = open(t),
    now = Date.now(),
    readings = n => [
      { key: 'cpu', label: 'CPU', value: n, unit: '%' },
      { key: 'memory', label: 'Memory', value: n * 2, unit: '%' },
      { key: 'disk', label: 'Disk', value: n * 3, unit: '%' },
    ];
  for (let n = 10; n >= 1; n--) store.record('a', readings(n), null, now - n * 60000);
  store.record('a', [], 'Refused', now - 30000);
  store.markGap('a', now - 20000);
  const all = store.history('a', '1h', now);
  const only = store.history('a', '1h', now, 60, 90, { metrics: ['memory', 'unknown', 'cpu'] });
  assert.deepEqual(Object.keys(only), Object.keys(all));
  assert.equal(only.totalSamples, all.totalSamples);
  assert.equal(only.points.length, all.points.length);
  for (const [i, point] of only.points.entries()) {
    const full = all.points[i];
    assert.deepEqual(
      { ...point, metrics: undefined },
      { ...full, metrics: undefined },
      'only the readings inside each point change'
    );
    assert.deepEqual(
      point.metrics,
      full.metrics.filter(m => m.key === 'cpu' || m.key === 'memory')
    );
  }
  assert.ok(only.points.some(p => p.metrics.length === 2));
  // No list, an empty list or no options: every measurement.
  assert.deepEqual(store.history('a', '1h', now, 60, 90, { metrics: [] }), all);
  assert.deepEqual(store.history('a', '1h', now, 60, 90, {}), all);
  assert.deepEqual(store.history('a', '1h', now, 60, 90, null), all);
  // Keys the source never reported match nothing.
  assert.ok(
    store
      .history('a', '1h', now, 60, 90, { metrics: ['unknown', '__proto__'] })
      .points.every(p => p.metrics.length === 0)
  );
});

test('the synthetic benchmark dataset opens in Uptime Goblin with realistic readings, and is reproducible', async t => {
  const { generate } = await import('../scripts/gen-dataset.mjs');
  const end = Date.UTC(2026, 8, 1),
    options = { sources: 12, days: 0.25, interval: 300, end, seed: 7 },
    out = temporary(t),
    again = temporary(t);
  const result = generate({ out, ...options });
  generate({ out: again, ...options });
  assert.equal(result.sources, 12);
  // 72 five-minute polls in six hours, less a two-hour pause, per source.
  assert.ok(result.readings > 12 * 40 && result.readings <= 12 * 73, String(result.readings));
  const config = new ConfigStore(out);
  assert.equal(config.value.services.length, 12);
  assert.equal(config.value.pollSeconds, 300);
  assert.ok(config.value.services.every(s => s.apiUrl.includes('.example.test')));
  const store = new Store(out),
    copy = new Store(again);
  t.after(() => {
    store.close();
    copy.close();
  });
  const all = s => s.db.prepare('SELECT * FROM readings ORDER BY service,time').all();
  assert.deepEqual(all(copy), all(store), 'the same arguments give the same readings');
  // Proxmox carries per-guest detail, as the collector records it.
  const proxmox = store.latest('proxmox-1');
  assert.equal(proxmox.metrics.length, 161);
  assert.deepEqual(Object.keys(proxmox.metrics[0]), ['key', 'label', 'value', 'unit']);
  const chart = store.history('proxmox-1', '24h', end, 300, 90, { metrics: ['cpu'] });
  assert.ok(chart.points.some(p => p.ok && p.metrics.length === 1));
  assert.ok(
    chart.points.some(p => p.gap),
    'the maintenance pause is a gap'
  );
  assert.deepEqual(
    store.latest('radarr-1').notes.map(n => n.code),
    ['arr_library_too_large']
  );
  assert.equal(store.alerts().length, 1);
  assert.ok(store.events().some(e => e.kind === 'firing'));
  // An existing data directory is never overwritten by accident, and 1.4 holds 200 sources.
  assert.throws(() => generate({ out, ...options }), /not empty/);
  assert.throws(() => generate({ out: temporary(t), ...options, sources: 201 }), /1-200/);
});

// 1.5 #7 hot paths: prepared statements are compiled once, and latest() can be cached.
test('statements are compiled once per text, not on every call', t => {
  const { store } = open(t),
    now = Date.now(),
    prepare = t.mock.method(store.db, 'prepare'),
    rules = { ...source, rules: [{ key: 'cpu', operator: 'gt', threshold: 50, forSeconds: 0 }] },
    round = n => {
      store.record('linux', measurements(n), null, now + n * 1000, capped());
      store.record('linux', [], 'Refused', now + n * 1000 + 1);
      store.markGap('linux', now + n * 1000 + 2);
      store.evaluate(rules, measurements(n * 30), null, now + n * 1000 + 3);
      store.latest('linux');
      store.history('linux', '1h', now + n * 1000 + 4);
      store.alerts();
      store.events();
      store.stats();
    };
  // Three rounds reach every statement: the rule is pending in the second, firing in the third.
  for (let n = 1; n <= 3; n++) round(n);
  const compiled = prepare.mock.callCount();
  assert.ok(compiled > 5, String(compiled));
  for (let n = 4; n < 8; n++) round(n);
  assert.equal(prepare.mock.callCount(), compiled, 'later calls reuse the compiled statements');
  // Still correct afterwards: a reused statement is reset between calls.
  assert.equal(store.latest('linux').lastSuccess, now + 7000);
  assert.equal(store.stats().samples, 21);
});

test('cached statements follow schema changes made after they were compiled', t => {
  const { store } = open(t),
    now = Date.now();
  store.record('a', measurements(1), null, now - 1000);
  const before = store.history('a', '1h', now);
  store.db.exec('DROP INDEX readings_history');
  assert.deepEqual(store.history('a', '1h', now), before);
  store.db.exec('CREATE INDEX readings_history ON readings(service,time,ok,error)');
  store.record('a', measurements(2), null, now - 500);
  assert.equal(store.history('a', '1h', now).totalSamples, 2);
});

test('latest() is read from SQLite each time unless the cache is asked for', t => {
  const { store } = open(t),
    now = Date.now();
  store.record('a', measurements(1), null, now);
  const first = store.latest('a');
  assert.notEqual(store.latest('a'), first, 'a fresh answer each time');
  assert.equal(Object.isFrozen(first), false);
  // A write made outside the Store (as 1.4.2 would) is seen at once.
  store.db.prepare('UPDATE latest SET error=? WHERE service=?').run('Outside', 'a');
  assert.equal(store.latest('a').error, 'Outside');
});

test('the latest cache answers from memory until a write changes the source', async t => {
  const directory = temporary(t),
    store = new Store(directory, { cacheLatest: true }),
    plain = new Store(directory),
    now = Date.now();
  t.after(() => {
    store.close();
    plain.close();
  });
  const outside = value =>
    plain.db.prepare('UPDATE latest SET error=? WHERE service=?').run(value, 'a');
  // An unknown source is cached as unknown too, until something is recorded for it.
  assert.deepEqual(store.latest('a'), plain.latest('a'));
  store.record('a', measurements(1), null, now, capped());
  const cached = store.latest('a');
  assert.deepEqual(cached, plain.latest('a'));
  assert.equal(store.latest('a'), cached, 'the same object, from memory');
  // Proves it is memory: a change made on another connection is not read.
  outside('Outside');
  assert.equal(store.latest('a').error, null);
  // Shared by every caller, so it cannot be changed by one of them.
  assert.equal(Object.isFrozen(cached), true);
  assert.equal(Object.isFrozen(cached.metrics[0]), true);
  assert.equal(Object.isFrozen(cached.notes[0]), true);
  assert.throws(() => {
    cached.metrics[0].value = 99;
  }, TypeError);
  // record() drops the entry, success or failure; the next answer is read again.
  store.record('a', [], 'Refused', now + 1000);
  assert.deepEqual(store.latest('a'), plain.latest('a'));
  assert.equal(store.latest('a').error, 'Refused');
  assert.deepEqual(store.latest('a').notes, capped(), 'a failure keeps the notes');
  store.record('a', measurements(2), null, now + 2000);
  assert.deepEqual(store.latest('a'), plain.latest('a'));
  // Other sources keep their entries.
  store.record('b', measurements(3), null, now);
  const b = store.latest('b');
  store.record('a', measurements(4), null, now + 3000);
  assert.equal(store.latest('b'), b);
  // forget() drops the entry too.
  await store.forget('a');
  assert.deepEqual(store.latest('a'), {
    id: 'a',
    lastAttempt: null,
    lastSuccess: null,
    metrics: [],
    error: null,
    notes: [],
  });
});

test('a write that fails leaves the latest cache matching the database', t => {
  const directory = temporary(t),
    store = new Store(directory, { cacheLatest: true }),
    now = Date.now();
  t.after(() => store.close());
  store.record('a', measurements(1), null, now);
  assert.equal(store.latest('a').lastSuccess, now);
  const exec = t.mock.method(store.db, 'exec', function (sql) {
    if (sql === 'COMMIT') throw Object.assign(new Error('disk I/O error'), { errcode: 10 });
    return DatabaseSync.prototype.exec.call(this, sql);
  });
  assert.throws(() => store.record('a', measurements(2), null, now + 1000), /disk I\/O/);
  exec.mock.restore();
  assert.equal(store.db.isTransaction, false);
  assert.equal(store.latest('a').lastSuccess, now, 'read again: the write was rolled back');
  store.record('a', measurements(3), null, now + 2000);
  assert.equal(store.latest('a').lastSuccess, now + 2000);
});

test('cached and uncached latest() agree over any sequence of collections', t => {
  const directory = temporary(t),
    cached = new Store(directory, { cacheLatest: true }),
    plain = new Store(directory),
    now = Date.now();
  t.after(() => {
    cached.close();
    plain.close();
  });
  let seed = 7;
  const random = () => (seed = (seed * 1103515245 + 12345) % 2 ** 31) / 2 ** 31;
  for (let n = 0; n < 300; n++) {
    const id = `s${Math.floor(random() * 5)}`,
      roll = random();
    if (roll < 0.5)
      cached.record(id, measurements(n), null, now + n, roll < 0.2 ? capped(n + 1) : []);
    else if (roll < 0.8) cached.record(id, [], `Failure ${n}`, now + n);
    else cached.latest(id);
    for (const other of ['s0', 's1', 's2', 's3', 's4'])
      assert.deepEqual(cached.latest(other), plain.latest(other), `${other} after step ${n}`);
  }
});

// ---------------------------------------------------------------------------------------------
// Durable delivery (delivery spec §3.2, §4.2): the event row is the outbox record.

const failing = { ...source, availabilityFailures: 1, availabilitySeconds: 0 };
// Fires the availability alert of `id` at `time` and resolves it 2 minutes later.
function flap(store, id, time) {
  const service = { ...failing, id, name: id.toUpperCase() };
  const fired = store.evaluate(service, [], 'Refused', time);
  store.evaluate(service, measurements(1), null, time + 60000);
  const resolved = store.evaluate(service, measurements(1), null, time + 120000);
  return [...fired, ...resolved];
}
const eventRows = store =>
  store.db
    .prepare('SELECT * FROM events ORDER BY id')
    .all()
    .map(row => ({ ...row }));

test('alert changes carry a random uid and the alert since, and are written to relay (relayed 0)', t => {
  const { store } = open(t);
  const time = Date.now() - 3600000;
  const [firing, resolved] = flap(store, 'plex', time);
  for (const event of [firing, resolved]) assert.match(event.uid, /^e_[a-z2-7]{26}$/);
  assert.notEqual(firing.uid, resolved.uid);
  assert.deepEqual(
    [firing.kind, firing.since, resolved.kind, resolved.since],
    ['firing', time, 'resolved', time]
  );
  assert.deepEqual(
    eventRows(store).map(row => [row.kind, row.uid, row.since, row.relayed]),
    [
      ['firing', firing.uid, time, 0],
      ['resolved', resolved.uid, time, 0],
    ]
  );
  // The dashboard's events keep their 1.4.x columns.
  assert.deepEqual(Object.keys(store.events()[0]).sort(), [
    'category',
    'id',
    'kind',
    'message',
    'rule',
    'service',
    'time',
  ]);
  // A threshold rule's firing carries the since of its pending start.
  const cpu = {
    ...source,
    id: 'nas',
    rules: [{ key: 'cpu', operator: 'gt', threshold: 80, forSeconds: 60 }],
  };
  store.evaluate(cpu, measurements(95), null, time);
  const [late] = store.evaluate(cpu, measurements(95), null, time + 61000);
  assert.deepEqual([late.kind, late.since, late.time], ['firing', time, time + 61000]);
});

test('events written the 1.4.x way (named columns) have no uid and are never relayed', t => {
  const { store } = open(t);
  store.db
    .prepare('INSERT INTO events(service,time,kind,message,category,rule) VALUES(?,?,?,?,?,?)')
    .run('plex', Date.now(), 'firing', 'From 1.4.x', 'availability', '__availability');
  const [row] = eventRows(store);
  assert.deepEqual([row.since, row.uid, row.relayed], [null, null, null]);
  assert.deepEqual(store.unrelayedEvents(), []);
  assert.equal(store.markRelayed(['e_anything']), 0);
  assert.equal(store.discardUnrelayed(), 0);
  assert.equal(eventRows(store)[0].relayed, null, 'never rewritten');
});

test('unrelayedEvents pages the pending rows in id order; markRelayed marks by uid only', t => {
  const { store } = open(t);
  const base = Date.now() - 3600000;
  const events = [];
  for (let n = 0; n < 7; n++) events.push(...flap(store, `s${n}`, base + n * 1000));
  assert.equal(events.length, 14);
  const page1 = store.unrelayedEvents({ limit: 5 });
  assert.deepEqual(
    page1.map(row => row.uid),
    events.slice(0, 5).map(event => event.uid)
  );
  assert.deepEqual(Object.keys(page1[0]).sort(), [
    'category',
    'id',
    'kind',
    'message',
    'rule',
    'service',
    'since',
    'time',
    'uid',
  ]);
  const page2 = store.unrelayedEvents({ afterId: page1.at(-1).id, limit: 5 });
  assert.deepEqual(
    page2.map(row => row.uid),
    events.slice(5, 10).map(event => event.uid)
  );
  // At most 200 a page, whatever is asked.
  assert.equal(store.unrelayedEvents({ limit: 10000 }).length, 14);
  // Marking: by uid, only rows still pending, duplicates and unknown uids changing nothing.
  assert.equal(store.markRelayed([events[0].uid, events[0].uid, events[3].uid, 'e_unknown']), 2);
  assert.equal(store.markRelayed([events[0].uid]), 0);
  assert.equal(store.markRelayed([]), 0);
  assert.deepEqual(
    store.unrelayedEvents().map(row => row.uid),
    events.filter((_, n) => n !== 0 && n !== 3).map(event => event.uid)
  );
  // V1: the id of a deleted source's newest event is reused; marking by uid never marks the
  // new event that took it.
  const { id: newest } = store.unrelayedEvents().at(-1);
  const victim = events.at(-1);
  store.db.prepare('DELETE FROM events WHERE uid=?').run(victim.uid);
  const [reused] = flap(store, 'z', base + 100000);
  const row = store.db.prepare('SELECT id, relayed FROM events WHERE uid=?').get(reused.uid);
  assert.equal(row.id, newest, 'SQLite reused the id');
  assert.equal(store.markRelayed([victim.uid]), 0);
  assert.equal(
    store.db.prepare('SELECT relayed FROM events WHERE uid=?').get(reused.uid).relayed,
    0
  );
  // More than 200 uids: one transaction per 200.
  const many = Array.from({ length: 450 }, (_, n) => `e_${String(n).padStart(26, 'a')}`);
  assert.equal(store.markRelayed([...many, ...events.map(event => event.uid)]), 11);
});

test('markRelayed throws a failed write to the relay instead of recycling history for it', t => {
  const { store } = open(t);
  const [firing] = flap(store, 'plex', Date.now() - 60000);
  const readings = () => store.stats().samples;
  store.record('plex', measurements(5), null, Date.now() - 1000);
  const before = readings();
  // A full history (its own budget): SQLITE_FULL reaches the caller; no reading is recycled.
  store.db.exec(`PRAGMA max_page_count=${pragma(store, 'page_count')}`);
  t.mock.method(store.db, 'prepare', function (text) {
    const statement = DatabaseSync.prototype.prepare.call(this, text);
    if (!/UPDATE "events" SET "relayed"/.test(text)) return statement;
    return {
      run: () => {
        throw Object.assign(new Error('database or disk is full'), {
          code: 'ERR_SQLITE_ERROR',
          errcode: 13,
        });
      },
    };
  });
  assert.throws(() => store.markRelayed([firing.uid]), { errcode: 13 });
  t.mock.restoreAll();
  assert.equal(readings(), before);
  assert.equal(store.db.isTransaction, false, 'rolled back');
});

test('pauseReadings: record() and markGap() write nothing and throw nothing; evaluate() goes on', t => {
  const directory = temporary(t);
  let paused = true;
  const errors = t.mock.method(console, 'error', () => {});
  const store = new Store(directory, { pauseReadings: () => paused });
  t.after(() => store.close());
  const time = Date.now() - 60000;
  store.record('linux', measurements(5), null, time);
  store.record('linux', [], 'Refused', time + 1000);
  store.markGap('linux', time + 2000);
  assert.equal(store.stats().samples, 0);
  assert.equal(store.latest('linux').lastAttempt, null);
  assert.equal(errors.mock.callCount(), 0, 'nothing logged per poll');
  // Alerts are still evaluated and their changes written (to be relayed).
  const [firing] = store.evaluate(failing, [], 'Refused', time);
  assert.equal(firing.kind, 'firing');
  assert.equal(store.unrelayedEvents().length, 1);
  paused = false;
  store.record('linux', measurements(5), null, time + 3000);
  assert.equal(store.stats().samples, 1);
});

test('recycling and retention keep alert changes still to relay for 24 hours', async t => {
  const now = Date.now(),
    hour = 3600000;
  const add = store =>
    store.db.prepare(
      'INSERT INTO events(service,time,kind,message,uid,relayed) VALUES(?,?,?,?,?,?)'
    );
  // prune() with a 12-hour retention: of the events older than it, a pending one younger than
  // 24 h stays; an older pending one, a relayed one and a 1.4.x one (NULL) go.
  {
    const { store } = open(t);
    const insert = add(store);
    insert.run('a', now - 30 * hour, 'firing', 'pending, 30 h', 'e_old', 0);
    insert.run('a', now - 13 * hour, 'firing', 'pending, 13 h', 'e_young', 0);
    insert.run('a', now - 13 * hour, 'firing', 'relayed, 13 h', 'e_done', 1);
    insert.run('a', now - 13 * hour, 'firing', '1.4.x, 13 h', null, null);
    insert.run('a', now - hour / 2, 'firing', 'within retention', null, null);
    await store.prune(0.5, now);
    assert.deepEqual(
      eventRows(store).map(row => row.message),
      ['pending, 13 h', 'within retention']
    );
    // Once it is 24 h old it goes too (it was not relayed in time).
    await store.prune(0.5, now + 11 * hour + 1);
    assert.deepEqual(
      eventRows(store).map(row => row.message),
      ['within retention']
    );
  }
  // #pruneOldest() (a full history recycling itself): of the events older than the readings it
  // keeps, the same rule.
  {
    const directory = temporary(t);
    const store = new Store(directory, { clock: () => now });
    t.after(() => store.close());
    const insert = add(store);
    const start = now - 7 * hour;
    insert.run('linux', now - 30 * hour, 'firing', 'pending, 30 h', 'e_a', 0);
    insert.run('linux', start - 2000, 'firing', 'pending, 7 h', 'e_b', 0);
    insert.run('linux', start - 1000, 'firing', 'relayed, 7 h', 'e_c', 1);
    quota(t, store, 300);
    for (let n = 0; n < 400; n++) store.record('linux', large, null, start + n * 60000);
    assert.ok(store.stats().samples < 400, 'history was recycled');
    assert.ok(oldest(store) > start, 'the events are older than every reading kept');
    assert.deepEqual(
      eventRows(store).map(row => row.message),
      ['pending, 7 h']
    );
  }
});

test('legacyEventsAfter: the newest 1.4.x event after a time of each (service, rule) asked about', t => {
  const { store } = open(t);
  const insert = store.db.prepare(
    'INSERT INTO events(service,time,kind,message,category,rule) VALUES(?,?,?,?,?,?)'
  );
  insert.run('plex', 1000, 'firing', 'old', 'availability', '__availability');
  insert.run('plex', 3000, 'firing', 'new', 'availability', '__availability');
  insert.run('plex', 5000, 'resolved', 'newest', 'availability', '__availability');
  insert.run('plex', 4000, 'firing', 'cpu', 'measurement', 'cpu');
  insert.run('nas', 1500, 'firing', 'before the time', 'availability', '__availability');
  insert.run('nas', 2500, 'firing', 'not asked about', 'measurement', 'disk');
  // A 1.4.0 row without a rule: the outbox's order key writes its rule as ''.
  insert.run('old', 2600, 'firing', 'no rule', 'availability', null);
  // Rows 1.5 wrote (relayed set) are not 1.4.x's.
  store.db
    .prepare(
      'INSERT INTO events(service,time,kind,message,category,rule,uid,relayed) VALUES(?,?,?,?,?,?,?,?)'
    )
    .run('nas', 9000, 'firing', 'by 1.5', 'availability', '__availability', 'e_x', 1);
  const keys = [
    { service: 'plex', rule: '__availability' },
    { service: 'plex', rule: 'cpu' },
    { service: 'nas', rule: '__availability' },
    { service: 'old', rule: '' },
    { service: 'plex', rule: 'cpu' },
  ];
  assert.deepEqual(store.legacyEventsAfter(2000, { keys }), [
    { service: 'old', rule: null, time: 2600 },
    { service: 'plex', rule: '__availability', time: 5000 },
    { service: 'plex', rule: 'cpu', time: 4000 },
  ]);
  assert.deepEqual(store.legacyEventsAfter(2000, { keys: [{ service: 'plex', rule: 'cpu' }] }), [
    { service: 'plex', rule: 'cpu', time: 4000 },
  ]);
  assert.deepEqual(store.legacyEventsAfter(6000, { keys }), []);
  assert.deepEqual(store.legacyEventsAfter(2000), [], 'no keys, nothing to check');
  // Every key asked about is answered, however many other alerts 1.4.x changed later (A63:
  // the newest 1,000 groups were read before) and over several statements of 200 keys.
  store.db.exec('BEGIN');
  for (let i = 0; i < 2500; i++)
    insert.run(`s${i % 200}`, 10_000 + i, 'firing', 'x', 'availability', `r${Math.floor(i / 200)}`);
  store.db.exec('COMMIT');
  const many = Array.from({ length: 450 }, (_, i) => ({
    service: `s${i % 200}`,
    rule: `r${Math.floor(i / 200)}`,
  }));
  const found = store.legacyEventsAfter(2000, {
    keys: [{ service: 'plex', rule: 'cpu' }, ...many],
  });
  assert.equal(found.length, 451);
  assert.deepEqual(
    found.find(change => change.service === 'plex'),
    { service: 'plex', rule: 'cpu', time: 4000 }
  );
  assert.deepEqual(
    found.find(change => change.service === 's49' && change.rule === 'r2'),
    { service: 's49', rule: 'r2', time: 10_449 }
  );
});

test('discardUnrelayed marks every pending event relayed without sending, in chunks', t => {
  const { store } = open(t);
  const insert = store.db.prepare(
    'INSERT INTO events(service,time,kind,message,uid,relayed) VALUES(?,?,?,?,?,0)'
  );
  store.db.exec('BEGIN');
  for (let n = 0; n < 1234; n++) insert.run('a', n, 'firing', 'm', `e_${n}`);
  store.db.exec('COMMIT');
  const updates = [];
  const prepare = store.db.prepare;
  t.mock.method(store.db, 'prepare', function (text) {
    const statement = prepare.call(this, text);
    if (!/UPDATE "events" SET "relayed" = 1 WHERE "id" IN/.test(text)) return statement;
    return { run: (...args) => (updates.push(args), statement.run(...args)) };
  });
  assert.equal(store.discardUnrelayed(), 1234);
  t.mock.restoreAll();
  assert.equal(updates.length, 3, '500 + 500 + 234');
  assert.deepEqual(store.unrelayedEvents(), []);
  assert.equal(store.discardUnrelayed(), 0);
});

test('a 1.4.x history gains since, uid, relayed and the pending index on open, keeping its rows', t => {
  const directory = temporary(t);
  const old = new DatabaseSync(path.join(directory, 'history.sqlite'));
  old.exec(`CREATE TABLE events (id INTEGER PRIMARY KEY, service TEXT NOT NULL, time INTEGER NOT NULL, kind TEXT NOT NULL, message TEXT NOT NULL, category TEXT, rule TEXT);
    INSERT INTO events(service,time,kind,message,category,rule) VALUES('plex',1,'firing','kept','availability','__availability');`);
  old.close();
  const store = new Store(directory);
  t.after(() => store.close());
  const columns = store.db
    .prepare('PRAGMA table_info(events)')
    .all()
    .map(column => column.name);
  assert.deepEqual(columns.slice(-3), ['since', 'uid', 'relayed']);
  const index = store.db
    .prepare("SELECT sql FROM sqlite_master WHERE type='index' AND name='events_unrelayed'")
    .get();
  assert.match(index.sql, /ON events\(id\) WHERE relayed = 0/);
  assert.deepEqual(
    store.events().map(event => event.message),
    ['kept']
  );
  // The relay's read goes through the partial index.
  const plan = store.db
    .prepare(
      'EXPLAIN QUERY PLAN SELECT "id" FROM "events" WHERE "relayed" = 0 AND "uid" IS NOT NULL AND "id" > ? ORDER BY "id" ASC LIMIT ?'
    )
    .all(0, 200)
    .map(row => row.detail)
    .join(' ');
  assert.match(plan, /events_unrelayed/);
});

test('a pending-notification index that cannot be built (a full disk) never stops Uptime Goblin from starting', t => {
  const directory = temporary(t);
  const exec = DatabaseSync.prototype.exec;
  t.mock.method(DatabaseSync.prototype, 'exec', function (text) {
    if (/events_unrelayed/.test(text))
      throw Object.assign(new Error('database or disk is full'), {
        code: 'ERR_SQLITE_ERROR',
        errcode: 13,
      });
    return exec.call(this, text);
  });
  const errors = t.mock.method(console, 'error', () => {});
  const store = new Store(directory);
  t.after(() => store.close());
  assert.equal(errors.mock.callCount(), 1);
  assert.match(
    errors.mock.calls[0].arguments[0],
    /^The pending-notification index could not be built; Uptime Goblin builds it at a later start/
  );
  // Without it the relay still works (a scan).
  const [firing] = flap(store, 'plex', Date.now() - 60000);
  assert.deepEqual(
    store.unrelayedEvents().map(row => row.uid),
    [firing.uid, store.unrelayedEvents()[1].uid]
  );
  assert.equal(store.markRelayed([firing.uid]), 1);
  // A later start builds it.
  t.mock.restoreAll();
  const again = new Store(directory);
  t.after(() => again.close());
  assert.ok(
    again.db
      .prepare("SELECT 1 FROM sqlite_master WHERE type='index' AND name='events_unrelayed'")
      .get()
  );
});

test('a saved latest or reading row that is not a JSON list of readings reads as none, with a note; charts and the latest answer still work', t => {
  const { store } = open(t);
  const now = Date.now();
  // Hours apart: each in a chart bucket of its own.
  store.record('a', measurements(1), null, now - 3 * 3600000);
  store.record('a', measurements(2), null, now - 3600000);
  for (const [stored, what] of [
    ['garbage{', 'not JSON'],
    ['{"not":"a list"}', 'an object'],
    ['null', 'null'],
  ]) {
    store.db.prepare("UPDATE latest SET metrics = ? WHERE service = 'a'").run(stored);
    store.db
      .prepare("UPDATE readings SET metrics = ? WHERE service = 'a' AND time = ?")
      .run(stored, now - 3600000);
    const latest = store.latest('a');
    assert.deepEqual(latest.metrics, [], what);
    assert.equal(latest.notes[0]?.code, 'stored_reading_unreadable', what);
    const chart = store.history('a', '24h', now);
    assert.deepEqual(
      chart.points.map(point => point.metrics.map(m => m.value)),
      [[1], []],
      what
    );
    assert.deepEqual(store.history('a', '24h', now, 60, 90, { metrics: ['cpu'] }).points.length, 2);
  }
  // Entries of a list that are not readings are left out; the rest stay.
  store.db
    .prepare("UPDATE latest SET metrics = ? WHERE service = 'a'")
    .run(JSON.stringify([null, 5, { label: 'no key' }, ...measurements(3)]));
  assert.deepEqual(store.latest('a').metrics, measurements(3));
  assert.deepEqual(store.latest('a').notes, []);
});

test('opening history.sqlite tightens it to 0600, never the target of a symbolic link', t => {
  const directory = temporary(t);
  const target = path.join(temporary(t), 'history.sqlite');
  new DatabaseSync(target).close();
  fs.chmodSync(target, 0o644);
  fs.symlinkSync(target, path.join(directory, 'history.sqlite'));
  new Store(directory).close();
  assert.equal(fs.statSync(target).mode & 0o777, 0o644);
  const own = temporary(t);
  new DatabaseSync(path.join(own, 'history.sqlite')).close();
  fs.chmodSync(path.join(own, 'history.sqlite'), 0o644);
  new Store(own).close();
  assert.equal(fs.statSync(path.join(own, 'history.sqlite')).mode & 0o777, 0o600);
});
