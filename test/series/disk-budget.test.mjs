// The history disk budget (lib/series/disk-budget.mjs): the Store's 1.4.2 policy as a module of
// its own, so the v1 series store's connection is capped the same way. The Store's own budget
// tests (test/store.test.mjs) run through this module too.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { Store } from '../../lib/store.mjs';
import registry from '../../lib/db/registry.mjs';
import { createSqliteDialect } from '../../lib/db/dialect/sqlite.mjs';
import {
  createDiskBudget,
  reserveBytes,
  spareBytes,
  refreshMs,
} from '../../lib/series/disk-budget.mjs';
import { createSeriesStoreV1 } from '../../lib/series/v1.mjs';
import { createEvents } from '../../lib/repo/state/events.mjs';
import { temporary, rows } from '../repo/helpers.mjs';

const MiB = 2 ** 20,
  GiB = 2 ** 30;
const base = Date.UTC(2026, 8, 1, 12);
// About 11 KB of JSON per reading, so a few hundred pages hold only a few dozen readings.
const large = Array.from({ length: 200 }, (_, i) => ({
  key: `guest_${i}`,
  label: `Guest ${i} CPU`,
  value: i,
  unit: '%',
}));

// A connection's pages as a Db would hand them to its budget (see the report: lib/db/sqlite.mjs
// is asked for the same three functions), here over a plain node:sqlite connection.
const pagesOf = db => ({
  get: name => db.prepare(`PRAGMA ${name}`).get()[name],
  setMax: pages => db.exec(`PRAGMA max_page_count=${pages}`),
  checkpoint: () => db.exec('PRAGMA wal_checkpoint(PASSIVE)'),
});

/**
 * The Db of lib/db/sqlite.mjs reduced to what the v1 series store uses, over a connection this
 * test can cap: write() runs BEGIN IMMEDIATE … COMMIT, read() BEGIN … COMMIT, a callback that
 * returns a promise is rolled back, and SQLite errors carry their class. `pages` is the
 * connection's page accounting for its disk budget.
 */
function pagedDb(file) {
  const raw = new DatabaseSync(file),
    dialect = createSqliteDialect({ identifiers: registry.identifiers });
  raw.exec('PRAGMA journal_mode=WAL; PRAGMA busy_timeout=250');
  const cache = new Map();
  const statement = query => {
    const { text, params } = dialect.render(query);
    if (!cache.has(text)) cache.set(text, raw.prepare(text));
    return [cache.get(text), params];
  };
  const tx = {
    dialect,
    run(query) {
      const [prepared, params] = statement(query),
        result = prepared.run(...params);
      return { changes: Number(result.changes), lastInsertRowid: Number(result.lastInsertRowid) };
    },
    get(query) {
      const [prepared, params] = statement(query);
      return prepared.get(...params);
    },
    all(query) {
      const [prepared, params] = statement(query);
      return prepared.all(...params);
    },
  };
  const unit = (kind, fn) => {
    raw.exec(kind === 'write' ? 'BEGIN IMMEDIATE' : 'BEGIN');
    try {
      const result = fn(tx);
      if (typeof result?.then === 'function') throw new Error('asynchronous callback');
      raw.exec('COMMIT');
      return result;
    } catch (error) {
      if (raw.isTransaction) raw.exec('ROLLBACK');
      if (error?.code === 'ERR_SQLITE_ERROR') error.class = dialect.classify(error);
      throw error;
    }
  };
  return {
    dialect,
    raw,
    pages: pagesOf(raw),
    read: async fn => unit('read', fn),
    write: async fn => unit('write', fn),
    close: () => raw.close(),
  };
}

// A filesystem of `blocks` 4 KiB blocks (64 MiB keeps its 64 MiB minimum reserve) with `free`
// blocks above the reserve, less what the watched databases have grown since `watch`.
function filesystem(t) {
  const disk = { blocks: 16384, free: 300, grown: () => 0, calls: 0 };
  t.mock.method(fs, 'statfsSync', () => {
    disk.calls++;
    return {
      bsize: 4096,
      frsize: 4096,
      blocks: disk.blocks,
      bavail: disk.blocks + disk.free - disk.grown(),
    };
  });
  return disk;
}

test('the reserve is 5 % of the filesystem, at least 64 MiB and at most 1 GiB', t => {
  assert.equal(reserveBytes(0), 64 * MiB);
  assert.equal(reserveBytes(GiB), 64 * MiB);
  assert.equal(reserveBytes(4 * GiB), 0.05 * 4 * GiB);
  assert.equal(reserveBytes(100 * GiB), GiB);
  assert.equal(refreshMs, 60000);
  // Space above the reserve, in bytes; nothing when the filesystem reports no size.
  const directory = temporary(t),
    reply = { bsize: 512, frsize: 4096, blocks: 262144, bavail: 20000 };
  t.mock.method(fs, 'statfsSync', () => {
    if (reply.fail) throw Object.assign(new Error('gone'), { code: 'ENOENT' });
    return reply;
  });
  // 1 GiB filesystem: the reserve is 64 MiB (16,384 blocks of 4 KiB, frsize before bsize).
  assert.equal(spareBytes(directory), (20000 - 16384) * 4096);
  reply.bavail = 100;
  assert.equal(spareBytes(directory), 0, 'never negative');
  reply.frsize = 0;
  reply.bavail = 20000 * 8;
  assert.equal(spareBytes(directory), (20000 - 16384) * 4096, 'bsize when frsize is 0');
  reply.blocks = 0;
  assert.equal(spareBytes(directory), undefined);
  reply.blocks = 262144;
  reply.fail = true;
  assert.equal(spareBytes(directory), undefined);
});

test('a budget caps its connection at the free space and follows it', t => {
  const disk = filesystem(t),
    directory = temporary(t),
    raw = new DatabaseSync(path.join(directory, 'history.sqlite'));
  t.after(() => raw.close());
  raw.exec('CREATE TABLE t (v TEXT)');
  const pages = pagesOf(raw),
    clock = { now: 0 },
    checkpoints = [];
  const budget = createDiskBudget({
    directory,
    pages: { ...pages, checkpoint: () => checkpoints.push(clock.now) },
    clock: () => clock.now,
  });
  const initial = pages.get('page_count');
  disk.grown = () => pages.get('page_count') - initial;
  assert.equal(budget.refresh(), false, 'a cap below the default maximum did not grow');
  assert.equal(pages.get('max_page_count'), initial + 300);
  assert.equal(budget.spare(), 300 * 4096);
  assert.equal(budget.room(300 * 4096), true);
  assert.equal(budget.room(300 * 4096 + 1), false);
  // SQLite refuses to grow the file past the cap.
  assert.throws(() => {
    for (let n = 0; n < 1000; n++) raw.prepare('INSERT INTO t VALUES (?)').run('x'.repeat(40000));
  }, /full/);
  assert.ok(pages.get('page_count') <= initial + 300);
  // Space freed on the host: grow() raises the cap and says so; the same space again does not.
  disk.free += 100;
  assert.equal(budget.grow(), true);
  assert.equal(pages.get('max_page_count'), initial + 400);
  assert.equal(budget.grow(), false);
  // beforeWrite() refreshes once `every` (a minute) has passed since the last refresh.
  disk.free -= 50;
  budget.beforeWrite();
  assert.equal(pages.get('max_page_count'), initial + 400, 'refreshed less than a minute ago');
  clock.now += 60000;
  budget.beforeWrite();
  assert.equal(pages.get('max_page_count'), initial + 350);
  // afterDelete() checkpoints, then refreshes at once; a failing checkpoint changes nothing.
  disk.free += 10;
  budget.afterDelete();
  assert.deepEqual(checkpoints, [60000]);
  assert.equal(pages.get('max_page_count'), initial + 360);
  const failing = createDiskBudget({
    directory,
    pages: {
      ...pages,
      checkpoint() {
        throw new Error('database is locked');
      },
    },
  });
  disk.free += 10;
  failing.afterDelete();
  assert.equal(pages.get('max_page_count'), initial + 370);
  createDiskBudget({ directory, pages: { get: pages.get, setMax: pages.setMax } }).afterDelete();
  // A filesystem that reports no size leaves the last cap in place.
  disk.blocks = 0;
  assert.equal(budget.refresh(), false);
  assert.equal(pages.get('max_page_count'), initial + 370);
  assert.equal(budget.room(GiB), true, 'an unknown size cannot be budgeted');
  assert.equal(Object.isFrozen(budget), true);
  assert.throws(() => createDiskBudget({ pages }), TypeError);
  assert.throws(() => createDiskBudget({ directory, pages: { get: pages.get } }), TypeError);
});

test('the v1 series store on a budgeted connection keeps history below the free space', async t => {
  const disk = filesystem(t),
    directory = temporary(t);
  new Store(directory).close();
  const db = pagedDb(path.join(directory, 'history.sqlite'));
  t.after(() => db.close());
  const initial = db.pages.get('page_count');
  disk.grown = () => db.pages.get('page_count') - initial;
  const budget = createDiskBudget({ directory, pages: db.pages });
  budget.refresh();
  assert.equal(db.pages.get('max_page_count'), initial + 300);
  const events = createEvents({ db });
  const series = createSeriesStoreV1({
    db,
    budget,
    recycled: (tx, oldest) => events.tx.deleteBefore(tx, oldest),
  });
  const start = base - 86400000;
  await events.append([{ service: 'linux', time: start - 1, kind: 'firing', message: 'old' }]);
  for (let n = 0; n < 400; n++)
    assert.deepEqual(
      await series.append({ service: 'linux', time: start + n * 60000, metrics: large }),
      { written: 1, rejected: [] }
    );
  // The disk filled up and history was recycled: always the oldest, with older events.
  assert.ok(db.pages.get('page_count') <= initial + 300);
  const { samples } = await series.stats();
  assert.ok(samples < 400, String(samples));
  const [latest] = await series.latest(['linux']);
  assert.equal(latest.lastSuccess, start + 399 * 60000);
  const times = db.raw.prepare('SELECT time FROM readings ORDER BY time').all();
  assert.equal(times.at(-1).time, start + 399 * 60000);
  assert.equal(times.length, samples);
  assert.equal(times[0].time, start + (400 - samples) * 60000, 'a contiguous newest history');
  assert.equal(await events.count(), 0);
  // Space freed elsewhere: the next retention run (or a full write) raises the cap.
  disk.free = 1000;
  await series.applyRetention({ retentionDays: 30, now: start + 400 * 60000 });
  assert.equal(db.pages.get('max_page_count'), initial + 1000);
  for (let n = 400; n < 405; n++)
    await series.append({ service: 'linux', time: start + n * 60000, metrics: large });
  assert.equal((await series.stats()).samples, samples + 5, 'nothing more recycled');
});

test('the Store and the v1 series store recycle the same history under the same budget', async t => {
  const disk = filesystem(t),
    legacyDirectory = temporary(t),
    directory = temporary(t);
  new Store(directory).close();
  const db = pagedDb(path.join(directory, 'history.sqlite'));
  t.after(() => db.close());
  // Each database sees a filesystem with 300 pages to spare above its size when opened.
  const start = db.pages.get('page_count');
  disk.grown = () => db.pages.get('page_count') - start;
  const budget = createDiskBudget({ directory, pages: db.pages });
  budget.refresh();
  const series = createSeriesStoreV1({ db, budget });
  const readings = [];
  for (let n = 0; n < 300; n++)
    readings.push({
      service: `s${n % 3}`,
      time: base + n * 60000,
      ...(n % 7 === 3 ? { error: 'Refused' } : { metrics: n % 2 ? large : large.slice(0, 100) }),
    });
  for (const reading of readings) await series.append(reading);
  const recycled = (await series.stats()).samples;
  assert.ok(recycled < readings.length, 'the budget was reached');
  // The Store, from the same starting size and with the same free space.
  disk.grown = () => 0;
  const legacy = new Store(legacyDirectory);
  t.after(() => legacy.close());
  const legacyPages = pagesOf(legacy.db),
    legacyStart = legacyPages.get('page_count');
  assert.equal(legacyStart, start);
  disk.grown = () => legacyPages.get('page_count') - legacyStart;
  for (const { service, time, metrics, error } of readings)
    legacy.record(service, metrics ?? [], error ?? null, time);
  for (const [table, order] of [
    ['readings', 'service,time'],
    ['latest', 'service'],
    ['latest_notes', 'service'],
  ])
    assert.deepEqual(rows(db.raw, table, order), rows(legacy.db, table, order), table);
});
