// History summaries (lib/store.mjs, history_summaries): charts of 7 days or more read one row per
// source and 5-minute slot instead of every reading, and must give exactly the chart the readings
// give over the same aligned buckets, whatever was written, replaced, paused or deleted, also when
// readings were written behind the Store's back (an older release after a rollback, a restore).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { setImmediate as nextTurn } from 'node:timers/promises';
import { Store } from '../../lib/store.mjs';
import {
  GAP,
  historyWindow,
  windowFor,
  summarizeSlot,
  summarySlotMs,
} from '../../lib/series/shape.mjs';
import { temporary, seeded } from '../repo/helpers.mjs';

const day = 86400000,
  minute = 60000;
const end = Date.UTC(2026, 10, 1, 12, 3, 17, 451);
// (pollSeconds, timeoutSeconds): gapAfter from 48 s to 3 h.
const timings = [
  [15, 1],
  [60, 90],
  [300, 30],
  [3600, 90],
];
const slotOf = time => Math.floor(time / summarySlotMs) * summarySlotMs;
const cpu = value => [
  { key: 'cpu', label: 'CPU', value, unit: '%' },
  { key: 'memory', label: 'Memory', value: value / 2, unit: '%' },
];

function open(t, directory = temporary(t, 'orbit-summaries-'), options = {}) {
  const store = new Store(directory, options);
  // A test may close it early to reopen the directory.
  t.after(() => store.db.isOpen && store.close());
  return { directory, store };
}

// The summaries the readings of `service` call for, built from scratch with summarizeSlot.
function expectedSummaries(db, service) {
  const readings = db
    .prepare(
      'SELECT time, ok, error IS ? AS marker FROM readings WHERE service=? AND typeof(time)=? ORDER BY time'
    )
    .all(GAP, service, 'integer');
  const out = [];
  let previous = null;
  for (let i = 0; i < readings.length; ) {
    const slot = slotOf(readings[i].time);
    let j = i + 1;
    while (j < readings.length && slotOf(readings[j].time) === slot) j += 1;
    out.push({ service, slot, ...summarizeSlot(readings.slice(i, j), previous) });
    previous = readings[j - 1].time;
    i = j;
  }
  return out;
}
const storedSummaries = (db, service) =>
  db
    .prepare(
      'SELECT service, slot, successes, first_time, last_time, previous_time, sample_time, failure_time, marker_time, first_failure_time, sample_gap, failure_gap, marker_gap FROM history_summaries WHERE service=? ORDER BY slot'
    )
    .all(service)
    .map(row => ({ ...row }));
const sources = db =>
  db
    .prepare('SELECT DISTINCT service FROM readings ORDER BY service')
    .all()
    .map(row => row.service);
// Whether the slot holding `to` also holds a later reading (that chart comes from the readings).
const laterInSlot = (db, service, to) =>
  Boolean(
    db
      .prepare('SELECT 1 FROM readings WHERE service=? AND time>? AND time<? LIMIT 1')
      .get(service, to, slotOf(to) + summarySlotMs)
  );

// Every chart of 7, 30 and 90 days at each time in `nows`, for every timing: the summaries give
// the readings' chart (null only when the slot of `now` holds later readings), with and without
// a measurement filter, and history() serves it.
function assertCharts(store, nows, label) {
  let summarized = 0;
  for (const service of sources(store.db)) {
    assert.ok(store.summarized(service), `${label}: ${service} is summarised`);
    for (const now of nows)
      for (const [poll, timeout] of timings)
        for (const window of [
          historyWindow('7d', now, poll, timeout),
          historyWindow('30d', now, poll, timeout),
          windowFor(90 * day, now, poll, timeout),
        ])
          for (const options of [{}, { metrics: ['cpu'] }]) {
            const where = `${label}: ${service}, ${(window.to - window.from) / day} days to ${now}, gap ${window.gapAfter}`;
            const raw = store.historyOver(service, window, { ...options, path: 'raw' }),
              fast = store.historyOver(service, window, { ...options, path: 'summaries' });
            if (laterInSlot(store.db, service, window.to)) assert.equal(fast, null, where);
            else {
              assert.deepEqual(fast, raw, where);
              summarized += 1;
            }
            assert.deepEqual(store.historyOver(service, window, options), raw, where);
          }
  }
  return summarized;
}

// Writes a random history for `service` from `start` to `stop` through the Store: successes,
// failures and pause markers at intervals from 15 s to 15 min in bursts, pauses from a minute to
// three days, rewrites of earlier readings (INSERT OR REPLACE, the same time with another
// outcome), readings out of order and a few in the future. Returns the times written.
function writeHistory(store, { random, pick, int }, service, start, stop) {
  const times = [];
  const write = time => {
    const roll = random();
    if (roll < 0.75) store.record(service, cpu(int(0, 100)), null, time);
    else if (roll < 0.9) store.record(service, [], `Refused ${int(1, 4)}`, time);
    else store.markGap(service, time);
    times.push(time);
  };
  let time = start + int(0, 10 * minute),
    step = pick([15000, minute, 5 * minute, 15 * minute]),
    burst = int(5, 200);
  while (time < stop) {
    const roll = random();
    if (roll < 0.88) write(time);
    else if (roll < 0.92)
      time += pick([minute, 6 * minute, 40 * minute, 3 * 3600000, 26 * 3600000, 3 * day]);
    else if (roll < 0.96 && times.length) write(pick(times));
    else if (roll < 0.99) write(time - int(1, 20 * day));
    else write(stop + int(1, 4 * minute));
    if (--burst <= 0) {
      step = pick([15000, minute, 5 * minute, 15 * minute]);
      burst = int(5, 200);
    }
    time += step + int(-Math.floor(step / 4), Math.floor(step / 4));
  }
  return times;
}

test('summary charts equal the readings’ charts over random histories (7, 30 and 90 days)', async t => {
  let compared = 0;
  for (const seed of [11, 2026, 31337, 424242, 7, 99991]) {
    const random = seeded(seed),
      { store } = open(t);
    await store.summariesChecked();
    const start = end - 95 * day;
    writeHistory(store, random, 'linux-1', start, end);
    writeHistory(store, random, 'proxmox-1', start + random.int(0, 30) * day, end);
    // Retention drops the oldest readings (in chunks), then a source is removed and added again.
    await store.prune(random.int(70, 90), end);
    if (seed % 2) {
      await store.forget('proxmox-1');
      assert.deepEqual(storedSummaries(store.db, 'proxmox-1'), []);
      writeHistory(store, random, 'proxmox-1', end - random.int(1, 40) * day, end);
    }
    // A few more readings anywhere, and two sources writing in the same millisecond.
    writeHistory(store, random, 'linux-1', end - 2 * day, end - day);
    store.record('docker-1', cpu(1), null, end - 3 * day);
    store.record('linux-1', cpu(2), null, end - 3 * day);
    for (const service of sources(store.db))
      assert.deepEqual(
        storedSummaries(store.db, service),
        expectedSummaries(store.db, service),
        `seed ${seed}: summaries of ${service}`
      );
    compared += assertCharts(
      store,
      [end, end - random.int(1, 20 * day), end + 2 * minute, end + 3 * day],
      `seed ${seed}`
    );
  }
  assert.ok(compared > 500, `${compared} charts compared`);
});

test('chart windows of 7 days or more are whole 5-minute slots, at most 299 buckets', () => {
  for (const [period, width] of [
    ['7d', 35 * minute],
    ['30d', 145 * minute],
  ]) {
    const window = historyWindow(period, end);
    assert.equal(window.width, width);
    assert.equal(window.from % summarySlotMs, 0);
    assert.ok(end - window.from >= (period === '7d' ? 7 : 30) * day);
    assert.ok(end - window.from < (period === '7d' ? 7 : 30) * day + summarySlotMs);
    assert.ok(Math.floor((window.to - window.from) / window.width) + 1 <= 299);
  }
  assert.equal(windowFor(90 * day, end).width, 435 * minute);
  // Shorter charts are unchanged.
  assert.deepEqual(historyWindow('24h', end), {
    from: end - day,
    to: end,
    gapAfter: 450000,
    width: 288000,
  });
});

test('readings written behind the Store’s back are summarised again at the next start', async t => {
  const random = seeded(5150),
    directory = temporary(t, 'orbit-summaries-'),
    store = new Store(directory);
  await store.summariesChecked();
  writeHistory(store, random, 'linux-1', end - 40 * day, end);
  writeHistory(store, random, 'http-1', end - 10 * day, end);
  store.close();
  // An older release after a rollback (or a tool) writes and deletes readings without summaries.
  const older = new DatabaseSync(path.join(directory, 'history.sqlite'));
  const insert = older.prepare(
    'INSERT OR REPLACE INTO readings(service,time,ok,metrics,error) VALUES (?,?,?,?,?)'
  );
  older.exec('BEGIN');
  for (let n = 0; n < 3000; n++) {
    const time = end - random.int(0, 45 * day);
    if (random.random() < 0.8) insert.run('linux-1', time, 1, JSON.stringify(cpu(n % 100)), null);
    else insert.run('linux-1', time, 0, '[]', random.random() < 0.5 ? GAP : 'Older release');
  }
  for (let n = 0; n < 500; n++)
    insert.run('new-1', end - n * minute, 1, JSON.stringify(cpu(n)), null);
  older
    .prepare('DELETE FROM readings WHERE service=? AND time BETWEEN ? AND ?')
    .run('linux-1', end - 20 * day, end - 18 * day);
  older.prepare('DELETE FROM readings WHERE service=?').run('http-1');
  // A summary left over without readings, and one that is wrong.
  older
    .prepare(
      'INSERT INTO history_summaries(service,slot,successes,first_time,last_time) VALUES (?,?,?,?,?)'
    )
    .run('gone-1', slotOf(end), 1, slotOf(end), slotOf(end));
  older
    .prepare('UPDATE history_summaries SET successes=successes+7 WHERE service=?')
    .run('linux-1');
  older.exec('COMMIT');
  older.close();

  const reopened = new Store(directory);
  t.after(() => reopened.close());
  // Until the check has run, charts read the readings, and are right.
  assert.equal(reopened.summarized('linux-1'), false);
  assert.equal(
    reopened.historyOver('linux-1', historyWindow('30d', end), { path: 'summaries' }),
    null
  );
  const before = reopened.history('linux-1', '30d', end);
  assert.deepEqual(before, reopened.history('linux-1', '30d', end, 60, 90, { path: 'raw' }));
  await reopened.summariesChecked();
  for (const service of ['linux-1', 'new-1', 'http-1', 'gone-1'])
    assert.deepEqual(
      storedSummaries(reopened.db, service),
      expectedSummaries(reopened.db, service),
      service
    );
  assert.deepEqual(reopened.history('linux-1', '30d', end), before);
  assertCharts(reopened, [end, end - 5 * day], 'after the check');
});

test('a history from before 1.5 gains the summaries at its first start, checked in short steps', async t => {
  const directory = temporary(t, 'orbit-summaries-');
  // The 1.4.x schema of readings, filled by that release: 30 days of minute readings.
  const older = new DatabaseSync(path.join(directory, 'history.sqlite'));
  older.exec(
    'CREATE TABLE readings (service TEXT NOT NULL, time INTEGER NOT NULL, ok INTEGER NOT NULL, metrics TEXT NOT NULL, error TEXT, PRIMARY KEY(service,time)); BEGIN'
  );
  const insert = older.prepare('INSERT INTO readings VALUES (?,?,?,?,?)');
  for (let n = 0; n <= 30 * 1440; n++) {
    const failed = n % 47 === 1;
    insert.run(
      'linux-1',
      end - n * minute,
      failed ? 0 : 1,
      failed ? '[]' : JSON.stringify(cpu(n % 100)),
      failed ? 'Refused' : null
    );
  }
  older.exec('COMMIT');
  older.close();
  const { store } = open(t, directory);
  assert.deepEqual(storedSummaries(store.db, 'linux-1'), []);
  // The check yields to the event loop between short transactions.
  let turns = 0,
    longest = 0,
    done = false;
  const checked = store.summariesChecked().then(() => (done = true));
  for (let last = performance.now(); !done; turns += 1) {
    await nextTurn();
    longest = Math.max(longest, performance.now() - last);
    last = performance.now();
  }
  await checked;
  assert.ok(turns >= 5, `${turns} turns while the check ran`);
  assert.ok(longest < 250, `the longest step held the event loop for ${longest} ms`);
  assert.deepEqual(storedSummaries(store.db, 'linux-1'), expectedSummaries(store.db, 'linux-1'));
  assertCharts(store, [end], 'first start');
});

test('a source with readings Uptime Goblin cannot summarise is charted from its readings', async t => {
  const { store } = open(t);
  for (let n = 0; n < 100; n++) store.record('linux-1', cpu(n), null, end - n * 10 * minute);
  // A reading time that is not an integer, written by something else.
  store.db
    .prepare('INSERT INTO readings VALUES (?,?,?,?,?)')
    .run('linux-1', end - 3 * day + 0.5, 1, '[]', null);
  store.record('http-1', cpu(1), null, end);
  await store.summariesChecked();
  assert.equal(store.summarized('linux-1'), false);
  assert.equal(store.summarized('http-1'), true);
  assert.equal(store.historyOver('linux-1', historyWindow('7d', end), { path: 'summaries' }), null);
  assert.deepEqual(
    store.history('linux-1', '7d', end),
    store.history('linux-1', '7d', end, 60, 90, { path: 'raw' })
  );
  assert.ok(store.history('linux-1', '7d', end).points.length > 0);
});

test('a table of that name with other columns leaves charts on the readings, and Uptime Goblin starts', async t => {
  const directory = temporary(t, 'orbit-summaries-');
  const older = new DatabaseSync(path.join(directory, 'history.sqlite'));
  older.exec('CREATE TABLE history_summaries (service TEXT, slot INTEGER)');
  older.close();
  const errors = t.mock.method(console, 'error', () => {});
  const { store } = open(t, directory);
  assert.match(String(errors.mock.calls[0]?.arguments[0]), /History summaries are unavailable/);
  assert.equal(errors.mock.calls[0].arguments[1], 'SUMMARY_COLUMNS');
  store.record('linux-1', cpu(1), null, end - minute);
  store.record('linux-1', [], 'Refused', end);
  await store.summariesChecked();
  assert.equal(store.summarized('linux-1'), false);
  const chart = store.history('linux-1', '30d', end);
  assert.equal(chart.totalSamples, 1);
  assert.equal(chart.points.length, 2);
});

test('while prune() and forget() delete readings, charts read the readings', async t => {
  const { store } = open(t);
  await store.summariesChecked();
  for (let n = 0; n < 6000; n++) {
    store.record('linux-1', cpu(n % 100), null, end - n * 15000);
    store.record('http-1', cpu(n % 100), null, end - n * 15000);
  }
  assert.equal(store.summarized('linux-1'), true);
  const pruning = store.prune(0.5, end);
  assert.equal(store.summarized('linux-1'), false);
  await pruning;
  assert.equal(store.summarized('linux-1'), true);
  const forgetting = store.forget('http-1');
  assert.equal(store.summarized('http-1'), false);
  assert.equal(store.summarized('linux-1'), true);
  await forgetting;
  assert.deepEqual(storedSummaries(store.db, 'http-1'), []);
  assert.deepEqual(storedSummaries(store.db, 'linux-1'), expectedSummaries(store.db, 'linux-1'));
  assertCharts(store, [end], 'after prune and forget');
});

test('recycling on a full disk keeps the summaries of what is left', async t => {
  const { store } = open(t);
  await store.summariesChecked();
  // About 11 KB per reading, so a few hundred pages hold only a few dozen readings.
  const large = Array.from({ length: 200 }, (_, i) => ({
    key: `guest_${i}`,
    label: 'G',
    value: i,
    unit: '%',
  }));
  for (let n = 0; n < 50; n++) store.record('linux-1', large, null, end - (400 - n) * minute);
  const size = store.db.prepare('PRAGMA page_size').get().page_size,
    blocks = 2 ** 26 / size,
    limit = store.db.prepare('PRAGMA page_count').get().page_count + 300;
  t.mock.method(fs, 'statfsSync', () => ({
    bsize: size,
    frsize: size,
    blocks,
    bavail: blocks + Math.max(0, limit - store.db.prepare('PRAGMA page_count').get().page_count),
  }));
  store.db.exec(`PRAGMA max_page_count=${limit}`);
  for (let n = 50; n < 400; n++) {
    store.record('linux-1', large, null, end - (400 - n) * minute);
    if (n % 3 === 0) store.markGap('http-1', end - (400 - n) * minute);
  }
  const { samples } = store.stats();
  assert.ok(samples < 450, `${samples} readings kept: recycling ran`);
  for (const service of ['linux-1', 'http-1'])
    assert.deepEqual(
      storedSummaries(store.db, service),
      expectedSummaries(store.db, service),
      service
    );
  assertCharts(store, [end], 'after recycling');
});

test('recycling one of two readings of the same millisecond summarises that slot again', async t => {
  const { store } = open(t);
  await store.summariesChecked();
  const large = Array.from({ length: 200 }, (_, i) => ({
    key: `guest_${i}`,
    label: 'G',
    value: i,
    unit: '%',
  }));
  const size = store.db.prepare('PRAGMA page_size').get().page_size,
    blocks = 2 ** 26 / size,
    limit = store.db.prepare('PRAGMA page_count').get().page_count + 40;
  t.mock.method(fs, 'statfsSync', () => ({
    bsize: size,
    frsize: size,
    blocks,
    bavail: blocks + Math.max(0, limit - store.db.prepare('PRAGMA page_count').get().page_count),
  }));
  store.db.exec(`PRAGMA max_page_count=${limit}`);
  // Two sources record in the same millisecond; a full disk then recycles one reading at a time
  // (a tenth of fewer than ten), so one of the two goes while the other stays the oldest.
  const start = slotOf(end) - 4 * minute;
  store.record('linux-1', large, null, start);
  store.record('http-1', large, null, start);
  store.record('linux-1', large, null, start + 1000);
  store.record('http-1', large, null, start + 2000);
  // The writes that recycle are another source's, in a later slot.
  let recycled = 0;
  for (let n = 1; n < 40; n++) {
    const before = store.stats().samples;
    store.record('docker-1', large, null, start + 10 * minute + n * 1000);
    if (store.stats().samples <= before) recycled += 1;
    for (const service of ['linux-1', 'http-1', 'docker-1'])
      assert.deepEqual(
        storedSummaries(store.db, service),
        expectedSummaries(store.db, service),
        `${service} after ${n}`
      );
  }
  assert.ok(recycled > 0, 'recycling ran');
});

// Runs the start's check to its end, counting the event-loop turns it took and its longest step.
async function watchCheck(store) {
  let turns = 0,
    longest = 0,
    done = false;
  const checked = store.summariesChecked().then(() => (done = true));
  for (let last = performance.now(); !done; turns += 1) {
    await nextTurn();
    longest = Math.max(longest, performance.now() - last);
    last = performance.now();
  }
  await checked;
  return { turns, longest };
}

// 25 hours of readings every 15 s for two sources, through the Store.
function writeDay(store) {
  for (let n = 0; n < 6000; n++) {
    store.record('linux-1', cpu(n % 100), null, end - n * 15000);
    store.record('http-1', n % 9 ? cpu(n % 100) : [], n % 9 ? null : 'Refused', end - n * 15000);
  }
}

test('a summary read that fails leaves charts on the readings until the next start', async t => {
  const { directory, store } = open(t);
  await store.summariesChecked();
  writeDay(store);
  assert.equal(store.summarized('linux-1'), true);
  const errors = t.mock.method(console, 'error', () => {});
  // The read fails (here: the table is gone; a damaged page or an SQLite without concat_ws
  // fails the same way), and the chart comes from the readings.
  store.db.exec('ALTER TABLE history_summaries RENAME TO summaries_elsewhere');
  const window = historyWindow('7d', end);
  assert.equal(store.historyOver('linux-1', window, { path: 'summaries' }), null);
  assert.equal(store.summarized('linux-1'), false);
  assert.match(String(errors.mock.calls[0]?.arguments[0]), /History summaries stopped/);
  for (const service of ['linux-1', 'http-1'])
    for (const period of ['7d', '30d'])
      assert.deepEqual(
        store.history(service, period, end),
        store.history(service, period, end, 60, 90, { path: 'raw' }),
        `${service} ${period}`
      );
  // Readings written meanwhile get no summaries; the next start finds and writes them.
  for (let n = 1; n <= 30; n++) store.record('linux-1', cpu(n), null, end + n * minute);
  store.db.exec('ALTER TABLE summaries_elsewhere RENAME TO history_summaries');
  store.close();
  const { store: reopened } = open(t, directory);
  await reopened.summariesChecked();
  for (const service of ['linux-1', 'http-1'])
    assert.deepEqual(
      storedSummaries(reopened.db, service),
      expectedSummaries(reopened.db, service),
      service
    );
  assertCharts(reopened, [end, end + 30 * minute], 'after the failed read');
});

test('a stray reading far from the others costs the check a few steps, not one per empty stretch', async t => {
  const { directory, store } = open(t);
  await store.summariesChecked();
  writeDay(store);
  // Times a tool could write, at both ends of what a reading time may be, through its own
  // connection while Uptime Goblin runs (so the Store's close leaves no mark to trust).
  const tool = new DatabaseSync(path.join(directory, 'history.sqlite'));
  const insert = tool.prepare('INSERT INTO readings VALUES (?,?,?,?,?)');
  insert.run('linux-1', 1000, 1, JSON.stringify(cpu(1)), null);
  insert.run('linux-1', 8e15, 0, '[]', 'Refused');
  insert.run('linux-1', -8e15, 1, JSON.stringify(cpu(2)), null);
  tool.close();
  store.close();
  const { store: reopened } = open(t, directory);
  const { turns } = await watchCheck(reopened);
  assert.ok(turns < 200, `${turns} turns while the check ran`);
  assert.equal(reopened.summarized('linux-1'), true);
  assert.deepEqual(
    storedSummaries(reopened.db, 'linux-1'),
    expectedSummaries(reopened.db, 'linux-1')
  );
  assertCharts(reopened, [end], 'with stray readings');
});

test('the check of a source with many readings per slot starts with a short step', async t => {
  const directory = temporary(t, 'orbit-summaries-');
  const older = new DatabaseSync(path.join(directory, 'history.sqlite'));
  older.exec(
    'CREATE TABLE readings (service TEXT NOT NULL, time INTEGER NOT NULL, ok INTEGER NOT NULL, metrics TEXT NOT NULL, error TEXT, PRIMARY KEY(service,time)); BEGIN'
  );
  // A day of readings every second: 300 per slot.
  const insert = older.prepare('INSERT INTO readings VALUES (?,?,?,?,?)');
  for (let n = 0; n < 86400; n++)
    insert.run('fast-1', end - n * 1000, 1, JSON.stringify(cpu(n % 100)), null);
  older.exec('COMMIT');
  older.close();
  const { store } = open(t, directory);
  // Its first step covers 3 slots (about 1,000 readings), and a step at most doubles the last,
  // so the day's 289 slots take at least 7 steps (one step of a day's slots before).
  const { turns, longest } = await watchCheck(store);
  assert.ok(turns >= 7, `${turns} turns while the check ran`);
  assert.ok(longest < 250, `the longest step held the event loop for ${longest} ms`);
  assert.deepEqual(storedSummaries(store.db, 'fast-1'), expectedSummaries(store.db, 'fast-1'));
});

test('a prune that fails part way keeps the summaries of what is left', async t => {
  const { store } = open(t);
  await store.summariesChecked();
  writeDay(store);
  // Deleting readings fails once the chunks reach 18 hours ago (12 hours are to go).
  store.db.exec(
    `CREATE TRIGGER fail_prune BEFORE DELETE ON readings WHEN OLD.time >= ${end - 18 * 3600000} BEGIN SELECT RAISE(ABORT, 'injected'); END`
  );
  await assert.rejects(store.prune(0.5, end), /injected/);
  store.db.exec('DROP TRIGGER fail_prune');
  const oldest = store.db.prepare('SELECT MIN(time) AS oldest FROM readings').get().oldest;
  assert.ok(oldest > end - 25 * 3600000 && oldest < end - 18 * 3600000, 'some chunks ran');
  for (const service of ['linux-1', 'http-1']) {
    assert.equal(store.summarized(service), true, service);
    assert.deepEqual(
      storedSummaries(store.db, service),
      expectedSummaries(store.db, service),
      service
    );
  }
  assertCharts(store, [end], 'after a failed prune');
});

test('summaries a prune or forget fails to delete leave charts on the readings until the next start repairs them', async t => {
  const { directory, store } = open(t);
  await store.summariesChecked();
  writeDay(store);
  t.mock.method(console, 'error', () => {});
  const raw = (service, period) => store.history(service, period, end, 60, 90, { path: 'raw' });
  // Deleting summaries fails: prune() deletes its readings and stops the summaries.
  store.db.exec(
    "CREATE TRIGGER fail_summaries BEFORE DELETE ON history_summaries BEGIN SELECT RAISE(ABORT, 'injected'); END"
  );
  await store.prune(0.5, end);
  assert.equal(store.summarized('linux-1'), false);
  assert.ok(
    store.db.prepare('SELECT MIN(time) AS oldest FROM readings').get().oldest >= end - day / 2
  );
  assert.deepEqual(store.history('linux-1', '7d', end), raw('linux-1', '7d'));
  store.db.exec('DROP TRIGGER fail_summaries');
  store.close();
  const { store: second } = open(t, directory);
  await second.summariesChecked();
  for (const service of ['linux-1', 'http-1'])
    assert.deepEqual(storedSummaries(second.db, service), expectedSummaries(second.db, service));
  assertCharts(second, [end], 'after the failed trim');
  // forget() fails part way through the readings (the 500th delete): its charts read what is
  // left of its readings, the other source's charts keep the summaries.
  second.db.exec(
    "CREATE TABLE forget_count (n INTEGER); INSERT INTO forget_count VALUES (0); CREATE TRIGGER count_forget AFTER DELETE ON readings BEGIN UPDATE forget_count SET n = n + 1; END; CREATE TRIGGER fail_forget BEFORE DELETE ON readings WHEN (SELECT n FROM forget_count) >= 500 BEGIN SELECT RAISE(ABORT, 'injected'); END"
  );
  const before = second.db.prepare('SELECT COUNT(*) AS n FROM readings WHERE service=?');
  const had = before.get('http-1').n;
  await assert.rejects(second.forget('http-1'), /injected/);
  const left = before.get('http-1').n;
  assert.ok(left < had && left > 0, `${had - left} of ${had} readings deleted`);
  assert.equal(second.summarized('http-1'), false);
  assert.equal(second.summarized('linux-1'), true);
  for (const period of ['7d', '30d'])
    assert.deepEqual(
      second.history('http-1', period, end),
      second.history('http-1', period, end, 60, 90, { path: 'raw' })
    );
  second.db.exec('DROP TRIGGER fail_forget; DROP TRIGGER count_forget; DROP TABLE forget_count');
  second.close();
  const { store: third } = open(t, directory);
  await third.summariesChecked();
  for (const service of ['linux-1', 'http-1'])
    assert.deepEqual(storedSummaries(third.db, service), expectedSummaries(third.db, service));
  assertCharts(third, [end], 'after the failed forget');
});

// The hot path's budget: a 30-day chart of a month of minute readings. Ratio always; the absolute
// target (p95 within 10 ms) where measurement runs are asked for (TEST_REQUIRE=capacity), as wall
// time also measures the machine.
test('a 30-day chart from summaries is at least 5x faster than from readings (budget)', async t => {
  const { store } = open(t);
  const insert = store.db.prepare('INSERT INTO readings VALUES (?,?,?,?,?)');
  const metrics = n =>
    JSON.stringify(
      Array.from({ length: 8 }, (_, j) => ({ key: `metric${j}`, value: n + j, unit: 'ms' }))
    );
  store.db.exec('BEGIN');
  for (let n = 0; n <= 30 * 1440; n++) {
    const failed = n % 47 === 1;
    insert.run(
      'linux-1',
      end - n * minute,
      failed ? 0 : 1,
      failed ? '[]' : metrics(n),
      failed ? 'Unavailable' : null
    );
  }
  store.db.exec('COMMIT');
  await store.summariesChecked();
  assert.equal(store.summarized('linux-1'), true);
  const window = historyWindow('30d', end, 60, 90),
    options = { metrics: ['metric0'] };
  const measure = path => {
    const times = [];
    for (let n = 0; n < 45; n++) {
      const started = performance.now();
      const chart = store.historyOver('linux-1', window, { ...options, path });
      times.push(performance.now() - started);
      assert.ok(chart.points.length > 280);
    }
    times.splice(0, 5);
    times.sort((a, b) => a - b);
    return { p50: times[times.length >> 1], p95: times[Math.ceil(times.length * 0.95) - 1] };
  };
  assert.deepEqual(
    store.historyOver('linux-1', window, { ...options, path: 'summaries' }),
    store.historyOver('linux-1', window, { ...options, path: 'raw' })
  );
  const raw = measure('raw'),
    fast = measure('summaries');
  t.diagnostic(
    `30d chart: readings p50 ${raw.p50.toFixed(2)} ms, p95 ${raw.p95.toFixed(2)} ms; summaries p50 ${fast.p50.toFixed(2)} ms, p95 ${fast.p95.toFixed(2)} ms`
  );
  assert.ok(raw.p50 >= 5 * fast.p50, `summaries ${fast.p50} ms against readings ${raw.p50} ms`);
  if ((process.env.TEST_REQUIRE ?? '').split(',').includes('capacity'))
    assert.ok(fast.p95 <= 10, `p95 ${fast.p95} ms`);
});

// Coverage marks (history_summary_marks): a clean close marks each source whose summaries match its
// readings, and a start checks again only the sources whose readings (or summary count) changed
// since. A summary edited in place, with the readings unchanged, is outside what a mark covers, so
// it shows here which sources a start skipped.
const marks = db =>
  db
    .prepare('SELECT service, reading_count FROM history_summary_marks ORDER BY service')
    .all()
    .map(row => ({ ...row }));
const tamper = (directory, service) => {
  const tool = new DatabaseSync(path.join(directory, 'history.sqlite'));
  tool.prepare('UPDATE history_summaries SET successes=successes+7 WHERE service=?').run(service);
  tool.close();
};

test('a clean close marks every checked source', async t => {
  const { directory, store } = open(t);
  await store.summariesChecked();
  writeDay(store);
  store.close();
  assert.deepEqual(marks(open(t, directory).store.db), [
    { service: 'http-1', reading_count: 6000 },
    { service: 'linux-1', reading_count: 6000 },
  ]);
});

// close() stops fingerprinting once its time budget is spent (a stop is not held for long by a
// large history): the sources it did not reach keep their old marks, which match only while
// their readings are unchanged, so a start checks those that changed and skips the rest.
test('a close past its marking budget keeps the old marks, and a start checks what changed', async t => {
  const { directory, store } = open(t);
  await store.summariesChecked();
  writeDay(store);
  store.close();
  const { store: second } = open(t, directory, { closeMarkBudgetMs: 0 });
  await second.summariesChecked();
  second.record('linux-1', cpu(5), null, end + minute);
  second.close();
  // Nothing was fingerprinted: the marks are those of the first close.
  const check = new DatabaseSync(path.join(directory, 'history.sqlite'));
  assert.deepEqual(marks(check), [
    { service: 'http-1', reading_count: 6000 },
    { service: 'linux-1', reading_count: 6000 },
  ]);
  check.close();
  tamper(directory, 'linux-1');
  tamper(directory, 'http-1');
  const { store: third } = open(t, directory);
  await third.summariesChecked();
  // linux-1 changed after its mark, so it was checked and put right; http-1 did not, so it was
  // skipped (its tampered summary is outside what a mark covers, see above).
  assert.deepEqual(storedSummaries(third.db, 'linux-1'), expectedSummaries(third.db, 'linux-1'));
  assert.notDeepEqual(storedSummaries(third.db, 'http-1'), expectedSummaries(third.db, 'http-1'));
  third.close();
  assert.deepEqual(marks(open(t, directory).store.db), [
    { service: 'http-1', reading_count: 6000 },
    { service: 'linux-1', reading_count: 6001 },
  ]);
});

test('every kind of outside change to a marked source’s readings has it checked again', async t => {
  // Each change, made by another connection after a clean close (an older release, a tool).
  const changes = {
    'a newer reading': db =>
      db
        .prepare('INSERT INTO readings VALUES (?,?,?,?,?)')
        .run('linux-1', end + minute, 1, '[]', null),
    'an outcome replaced at the same time': db =>
      db
        .prepare('UPDATE readings SET ok=0, metrics=?, error=? WHERE service=? AND time=?')
        .run('[]', 'Older release', 'linux-1', end - 100 * 15000),
    'a failure turned into a pause marker': db =>
      db
        .prepare('UPDATE readings SET error=? WHERE service=? AND time=?')
        .run(GAP, 'http-1', end - 9 * 15000),
    'two outcomes swapped': db => {
      db.prepare('UPDATE readings SET ok=0, metrics=?, error=? WHERE service=? AND time=?').run(
        '[]',
        'Refused',
        'http-1',
        end - 10 * 15000
      );
      db.prepare('UPDATE readings SET ok=1, metrics=?, error=NULL WHERE service=? AND time=?').run(
        JSON.stringify(cpu(1)),
        'http-1',
        end - 18 * 15000
      );
    },
    'a reading moved within its slot': db =>
      db
        .prepare('UPDATE readings SET time=time+1 WHERE service=? AND time=?')
        .run('linux-1', end - 200 * 15000),
    'a reading deleted in the middle': db =>
      db
        .prepare('DELETE FROM readings WHERE service=? AND time=?')
        .run('linux-1', end - 300 * 15000),
    'the oldest readings pruned': db =>
      db.prepare('DELETE FROM readings WHERE time<?').run(end - 20 * 3600000),
    'a summary deleted': db =>
      db
        .prepare('DELETE FROM history_summaries WHERE service=? AND slot=?')
        .run('http-1', slotOf(end - 3600000)),
  };
  const { directory: marked, store } = open(t);
  await store.summariesChecked();
  writeDay(store);
  store.close();
  for (const [label, change] of Object.entries(changes)) {
    const directory = temporary(t, 'orbit-summaries-');
    fs.copyFileSync(path.join(marked, 'history.sqlite'), path.join(directory, 'history.sqlite'));
    const tool = new DatabaseSync(path.join(directory, 'history.sqlite'));
    change(tool);
    tool.close();
    // Wrong summaries for both sources, so only a check of each puts them right.
    tamper(directory, 'linux-1');
    tamper(directory, 'http-1');
    const changed = [
      'a failure turned into a pause marker',
      'two outcomes swapped',
      'a summary deleted',
    ].includes(label)
      ? ['http-1']
      : label === 'the oldest readings pruned'
        ? ['http-1', 'linux-1']
        : ['linux-1'];
    const { store: reopened } = open(t, directory);
    await reopened.summariesChecked();
    for (const service of ['http-1', 'linux-1']) {
      const right = assert.deepEqual.bind(
        null,
        storedSummaries(reopened.db, service),
        expectedSummaries(reopened.db, service),
        `${label}: ${service}`
      );
      if (changed.includes(service)) right();
      else assert.throws(right, assert.AssertionError, `${label}: ${service} was skipped`);
    }
    reopened.close();
  }
});

test('without a clean close, or after another connection wrote, a start checks every source', async t => {
  // A crash: the readings written since the last clean close no longer match its marks.
  {
    const { directory, store } = open(t);
    await store.summariesChecked();
    writeDay(store);
    store.close();
    const { store: running } = open(t, directory);
    await running.summariesChecked();
    running.record('linux-1', cpu(5), null, end + minute);
    running.record('http-1', cpu(6), null, end + minute);
    running.db.close();
    tamper(directory, 'linux-1');
    tamper(directory, 'http-1');
    const { store: reopened } = open(t, directory);
    await reopened.summariesChecked();
    for (const service of ['http-1', 'linux-1'])
      assert.deepEqual(
        storedSummaries(reopened.db, service),
        expectedSummaries(reopened.db, service),
        `after a crash: ${service}`
      );
  }
  // Another connection wrote while the Store ran (after its check): the close keeps no mark.
  {
    const { directory, store } = open(t);
    await store.summariesChecked();
    writeDay(store);
    store.close();
    const { store: running } = open(t, directory);
    await running.summariesChecked();
    const tool = new DatabaseSync(path.join(directory, 'history.sqlite'));
    tool
      .prepare('INSERT INTO readings VALUES (?,?,?,?,?)')
      .run('http-1', end - 7, 0, '[]', 'Written by a tool');
    tool.close();
    running.close();
    const check = new DatabaseSync(path.join(directory, 'history.sqlite'));
    assert.deepEqual(
      check.prepare('SELECT COUNT(*) AS found FROM history_summary_marks').get().found,
      0
    );
    check.close();
    const { store: reopened } = open(t, directory);
    await reopened.summariesChecked();
    for (const service of ['http-1', 'linux-1'])
      assert.deepEqual(
        storedSummaries(reopened.db, service),
        expectedSummaries(reopened.db, service),
        `after another connection: ${service}`
      );
  }
});

test('a removed source loses its mark, and a marks table with other columns only costs time', async t => {
  {
    const { directory, store } = open(t);
    await store.summariesChecked();
    writeDay(store);
    await store.forget('http-1');
    store.close();
    const { store: reopened } = open(t, directory);
    assert.deepEqual(marks(reopened.db), [{ service: 'linux-1', reading_count: 6000 }]);
  }
  {
    const directory = temporary(t, 'orbit-summaries-');
    const older = new DatabaseSync(path.join(directory, 'history.sqlite'));
    older.exec('CREATE TABLE history_summary_marks (service TEXT, note TEXT)');
    older.close();
    const errors = t.mock.method(console, 'error', () => {});
    const { store } = open(t, directory);
    assert.match(
      String(errors.mock.calls[0]?.arguments[0]),
      /History summary marks are unavailable/
    );
    assert.equal(errors.mock.calls[0].arguments[1], 'SUMMARY_MARK_COLUMNS');
    await store.summariesChecked();
    writeDay(store);
    assert.equal(store.summarized('linux-1'), true);
    store.close();
    tamper(directory, 'linux-1');
    const { store: reopened } = open(t, directory);
    await reopened.summariesChecked();
    assert.deepEqual(
      storedSummaries(reopened.db, 'linux-1'),
      expectedSummaries(reopened.db, 'linux-1')
    );
  }
});

test('a summary read that fails for a passing reason sends only that chart to the readings', async t => {
  const { store } = open(t);
  await store.summariesChecked();
  writeDay(store);
  const errors = t.mock.method(console, 'error', () => {});
  const window = historyWindow('7d', end);
  const raw = store.historyOver('linux-1', window, { path: 'raw' });
  // SQLITE_BUSY, then SQLITE_IOERR_READ (extended code), each once: the summary read parses
  // its first bucket with JSON.parse, which fails here as the statement would.
  for (const errcode of [5, 266]) {
    t.mock.method(
      JSON,
      'parse',
      () => {
        throw Object.assign(new Error('passing failure'), { errcode });
      },
      { times: 1 }
    );
    assert.deepEqual(store.historyOver('linux-1', window), raw);
    assert.equal(store.summarized('linux-1'), true, `after errcode ${errcode}`);
    assert.deepEqual(store.historyOver('linux-1', window, { path: 'summaries' }), raw);
  }
  assert.match(String(errors.mock.calls[0]?.arguments[0]), /A history summary read failed/);
  // The same failure three reads in a row is not passing: the summaries stop until a start.
  const failing = t.mock.method(JSON, 'parse', () => {
    throw Object.assign(new Error('database is locked'), { errcode: 6 });
  });
  for (let n = 1; n <= 3; n++) {
    assert.equal(store.historyOver('linux-1', window, { path: 'summaries' }), null);
    assert.equal(store.summarized('linux-1'), n < 3, `after ${n} failures`);
  }
  failing.mock.restore();
  assert.deepEqual(store.historyOver('linux-1', window), raw);
});
