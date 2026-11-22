// SeriesStore v1 (1.5 #5b): the series seam over the 1.x tables gives exactly the answers
// lib/store.mjs gives, and keeps its full-disk, retention and erasure behaviour.
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { Store } from '../../lib/store.mjs';
import { openSqlite } from '../../lib/db/sqlite.mjs';
import { createSeriesStoreV1 } from '../../lib/series/v1.mjs';
import { openSeriesStore, assertSeriesStore, SERIES_METHODS } from '../../lib/series/store.mjs';
import { placeStores } from '../../lib/repo/stores.mjs';
import { createUnitRunner } from '../../lib/repo/unit.mjs';
import { RepoError } from '../../lib/repo/errors.mjs';
import { sql, id } from '../../lib/db/sql.mjs';
import { postgres } from '../../lib/db/dialect/postgres.mjs';
import {
  temporary,
  openHistory,
  measurements,
  capped,
  seeded,
  rows,
  faultyDb,
} from '../repo/helpers.mjs';

const base = Date.UTC(2026, 8, 1, 12);
const tables = [
  ['readings', 'service,time'],
  ['latest', 'service'],
  ['latest_notes', 'service'],
];

// Two data directories: the legacy Store writes one, the v1 series store the other (through
// lib/db/sqlite.mjs). `view` is a Store on the v1 directory, used only to read its raw rows.
function twins(t) {
  const legacyDirectory = temporary(t),
    legacy = new Store(legacyDirectory);
  const { history, store: view } = openHistory(t);
  t.after(() => legacy.close());
  return { legacy, view, history, series: createSeriesStoreV1({ db: history }) };
}
const readings = (value, random) => {
  const list = measurements(value, [
    { key: 'memory', label: 'Memory', value: value * 2, unit: '%' },
  ]);
  if (random() < 0.2) list.push({ key: 'odd', label: 'Odd', value: NaN, unit: '' });
  if (random() < 0.1)
    list.push({ key: 'labelled', label: 'L', value: 1, unit: '', labels: { disk: 'sda' } });
  return list;
};

test('v1 writes and reads exactly what the Store does, over a random sequence', async t => {
  const { legacy, view, series } = twins(t),
    { random, pick, int } = seeded(20260929),
    sources = ['linux-1', 'proxmox-1', 'docker-1', 'http-1'];
  let now = base;
  const compare = async step => {
    for (const [table, order] of tables)
      assert.deepEqual(
        rows(view.db, table, order),
        rows(legacy.db, table, order),
        `${table} @${step}`
      );
    assert.deepEqual(
      await series.latest(sources),
      sources.map(id => legacy.latest(id)),
      `latest @${step}`
    );
    const service = pick(sources),
      period = pick(['1h', '6h', '24h', '7d', 'bogus']),
      pollSeconds = pick([0, 15, 60, 300]),
      metrics = pick([undefined, [], ['cpu'], ['memory', 'missing']]);
    assert.deepEqual(
      await series.query({ service, period, now, pollSeconds, timeoutSeconds: 90, metrics }),
      legacy.history(service, period, now, pollSeconds, 90, { metrics }),
      `history of ${service} ${period} @${step}`
    );
    assert.deepEqual(await series.stats(), { samples: legacy.stats().samples });
  };
  for (let step = 0; step < 400; step++) {
    // Mostly forward, sometimes the same millisecond again (a replaced reading).
    now += random() < 0.05 ? 0 : int(1, 900) * 1000;
    const service = pick(sources),
      roll = random();
    if (roll < 0.45) {
      const list = readings(step, random),
        notes = random() < 0.3 ? capped(int(1, 9)) : random() < 0.2 ? [] : undefined;
      if (random() < 0.2) Object.defineProperty(list, 'notes', { value: capped(42) });
      legacy.record(service, list, null, now, notes);
      assert.deepEqual(await series.append({ service, time: now, metrics: list, notes }), {
        written: 1,
        rejected: [],
      });
    } else if (roll < 0.75) {
      const error = pick(['Refused', 'Timed out after 12 s', 'HTTP 503']);
      legacy.record(service, [], error, now);
      await series.append({ service, time: now, error });
    } else if (roll < 0.85) {
      legacy.markGap(service, now);
      await series.markGap(service, now);
    } else if (roll < 0.93) {
      const days = pick([0.01, 0.1, 1]);
      await legacy.prune(days, now);
      await series.applyRetention({ retentionDays: days, now });
    } else {
      await legacy.forget(service);
      await series.eraseTarget(service);
    }
    if (step % 7 === 0 || step > 390) await compare(step);
  }
});

test('v1 reads a realistic history exactly as the Store reads it', async t => {
  const { generate } = await import('../../scripts/gen-dataset.mjs');
  const directory = temporary(t),
    end = Date.UTC(2026, 8, 1);
  const result = generate({ out: directory, sources: 12, days: 0.5, interval: 300, end, seed: 3 });
  assert.ok(result.readings > 100);
  const store = new Store(directory),
    db = openSqlite(path.join(directory, 'history.sqlite'));
  t.after(() => {
    db.close();
    store.close();
  });
  const series = createSeriesStoreV1({ db }),
    ids = store.db
      .prepare('SELECT DISTINCT service FROM readings ORDER BY service')
      .all()
      .map(r => r.service);
  assert.ok(ids.length >= 12);
  assert.deepEqual(
    await series.latest(ids),
    ids.map(id => store.latest(id))
  );
  for (const id of ids)
    for (const period of ['1h', '6h', '24h', '7d', '30d'])
      for (const metrics of [undefined, ['cpu']])
        assert.deepEqual(
          await series.query({ service: id, period, now: end, pollSeconds: 300, metrics }),
          store.history(id, period, end, 300, 90, { metrics }),
          `${id} ${period}`
        );
  // The Store's writes and v1's are interchangeable on one database (a fresh series store: the
  // one above cached every answer, and the Store writes behind its back).
  const again = createSeriesStoreV1({ db });
  store.record(ids[0], measurements(1), null, end + 1000, capped());
  assert.deepEqual((await again.latest(ids[0]))[0], store.latest(ids[0]));
  await again.append({ service: ids[1], time: end + 2000, metrics: measurements(2) });
  assert.deepEqual(store.latest(ids[1]), (await again.latest([ids[1]]))[0]);
  assert.deepEqual(
    await again.query({ service: ids[1], period: '1h', now: end + 3000, pollSeconds: 300 }),
    store.history(ids[1], '1h', end + 3000, 300)
  );
});

test('latest answers are cached, frozen and dropped by every write to the source', async t => {
  const { history, store } = openHistory(t),
    db = faultyDb(history),
    series = createSeriesStoreV1({ db });
  await series.append({ service: 'a', time: base, metrics: measurements(1), notes: capped() });
  const [first] = await series.latest(['a']);
  assert.equal(series.cachedLatest('a'), first);
  assert.equal(Object.isFrozen(first), true);
  assert.equal(Object.isFrozen(first.metrics[0]), true);
  assert.throws(() => {
    first.notes.push({});
  }, TypeError);
  // From memory: a write made behind its back is not seen...
  store.db.prepare("UPDATE latest SET error='outside' WHERE service='a'").run();
  assert.equal((await series.latest('a'))[0], first);
  // ...until the store itself writes the source.
  await series.append({ service: 'a', time: base + 1000, error: 'Refused' });
  assert.equal(series.cachedLatest('a'), undefined);
  const [failed] = await series.latest('a');
  assert.equal(failed.error, 'Refused');
  assert.deepEqual(failed.notes, capped(), 'a failure keeps the notes of the last success');
  // A pause marker is a reading, not a latest change, but still re-reads (cheaply).
  await series.markGap('a', base + 2000);
  assert.deepEqual((await series.latest('a'))[0], store.latest('a'));
  await series.eraseTarget('a');
  assert.deepEqual((await series.latest('a'))[0], store.latest('a'));
  assert.equal(store.latest('a').lastAttempt, null);
  // Unknown and odd IDs answer like the Store, and many IDs are read in one call.
  const ids = Array.from({ length: 1200 }, (_, n) => `s${n}`);
  const answers = await series.latest([...ids, 'a', 'a']);
  assert.equal(answers.length, 1202);
  assert.deepEqual(answers[1201], store.latest('a'));
  assert.equal(await series.preload(), 0);
});

test('a latest() read that overlaps a write never caches what it read before the write', async t => {
  const { history } = openHistory(t),
    db = faultyDb(history),
    series = createSeriesStoreV1({ db });
  await series.append({ service: 'a', time: base, metrics: measurements(1) });
  let release;
  db.beforeRead = () => new Promise(resolve => (release = resolve));
  const reading = series.latest('a');
  await new Promise(resolve => setImmediate(resolve));
  db.beforeRead = null;
  // The read waits; meanwhile a newer collection is written.
  await series.append({ service: 'a', time: base + 1000, metrics: measurements(2) });
  release();
  const [answer] = await reading;
  assert.equal(answer.lastSuccess, base + 1000, 'the read ran after the write');
  assert.equal((await series.latest('a'))[0].lastSuccess, base + 1000);
  // A write to another source while a read waits: the answer is returned but not cached, as
  // the read cannot tell which rows it saw.
  await series.append({ service: 'a', time: base + 2000, metrics: measurements(3) });
  let resume;
  db.beforeRead = async () => {
    await new Promise(resolve => (resume = resolve));
  };
  const slow = series.latest('a');
  await new Promise(resolve => setImmediate(resolve));
  db.beforeRead = null;
  await series.append({ service: 'b', time: base, metrics: measurements(3) });
  resume();
  await slow;
  assert.equal(series.cachedLatest('a'), undefined, 'a write happened meanwhile: not cached');
});

test('a full disk uses freed space first, then recycles the oldest history with its events', async t => {
  const { history, store } = openHistory(t),
    db = faultyDb(history);
  let grown = 0,
    grow = false,
    refreshed = 0;
  const budget = {
    beforeWrite: () => refreshed++,
    grow: () => (grown++, grow),
  };
  const recycledAt = [];
  const series = createSeriesStoreV1({
    db,
    budget,
    recycled: (tx, oldest) => {
      recycledAt.push(oldest);
      return tx.run(db.dialect.deleteFrom('events', sql`${id('time')} < ${oldest}`)).changes;
    },
  });
  for (let n = 0; n < 30; n++)
    await series.append({ service: 's', time: base + n * 1000, metrics: measurements(n) });
  const event = store.db.prepare('INSERT INTO events(service,time,kind,message) VALUES(?,?,?,?)');
  for (let n = 0; n < 10; n++) event.run('s', base + n * 1000 - 1, 'firing', `old ${n}`);
  const count = table => store.db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n;
  // Space freed on the host: the cap grows and the same write is tried again.
  grow = true;
  db.script(['full']);
  await series.append({ service: 's', time: base + 40000, metrics: measurements(40) });
  assert.equal(grown, 1);
  assert.equal(count('readings'), 31, 'nothing recycled');
  assert.equal(count('events'), 10);
  // No space to find: the oldest tenth of the readings goes, with the events before them.
  grow = false;
  db.script(['full']);
  await series.append({ service: 's', time: base + 41000, metrics: measurements(41) });
  assert.equal(count('readings'), 31 - 4 + 1);
  assert.equal(recycledAt.at(-1), base + 4000);
  assert.equal(count('events'), 10 - 5);
  assert.equal(store.latest('s').lastSuccess, base + 41000);
  assert.ok(refreshed >= 3);
  // A write that still does not fit fails, and the readings it recycled come back.
  db.script(['full', { class: 'full', after: true }]);
  await assert.rejects(
    series.append({ service: 's', time: base + 42000, metrics: measurements(42) }),
    error => error instanceof RepoError && error.class === 'full' && error.unit === 'ingest.append'
  );
  assert.equal(count('readings'), 28);
  assert.equal(count('events'), 5);
  // Other failures are not recycled over.
  db.script(['unavailable']);
  await assert.rejects(
    series.append({ service: 's', time: base + 43000, metrics: measurements(43) }),
    { class: 'unavailable' }
  );
  assert.equal(count('readings'), 28);
});

test('a full database with nothing left to recycle reports full and writes nothing', async t => {
  const { history, store } = openHistory(t),
    db = faultyDb(history),
    series = createSeriesStoreV1({ db });
  db.script(['full']);
  await assert.rejects(series.append({ service: 's', time: base, metrics: measurements(1) }), {
    name: 'RepoError',
    class: 'full',
  });
  assert.equal(store.stats().samples, 0);
});

test('readings no engine can store are rejected alone; the rest of the batch is written', async t => {
  const { history, store } = openHistory(t),
    db = faultyDb(history),
    series = createSeriesStoreV1({ db });
  // Refused before any write: a missing ID, a fractional time, readings that are not a list.
  const result = await series.append([
    { service: 'a', time: base, metrics: measurements(1) },
    { service: '', time: base, metrics: measurements(1) },
    { service: 'b', time: base + 0.5, metrics: measurements(1) },
    { service: 'c', time: base, metrics: { cpu: 1 } },
    null,
    { service: 'd', time: base, error: 'Refused' },
  ]);
  assert.equal(result.written, 2);
  assert.deepEqual(
    result.rejected.map(r => [r.index, r.error.class]),
    [
      [1, 'poison'],
      [2, 'poison'],
      [3, 'poison'],
      [4, 'poison'],
    ]
  );
  assert.equal(store.stats().samples, 2);
  // A value the database refuses splits the batch: each reading alone, never retried.
  db.script(['poison', null, 'poison', null]);
  const split = await series.append([
    { service: 'x', time: base, metrics: measurements(1) },
    { service: 'y', time: base, metrics: measurements(2) },
    { service: 'z', time: base, metrics: measurements(3) },
  ]);
  assert.equal(split.written, 2);
  assert.deepEqual(
    split.rejected.map(r => r.index),
    [1]
  );
  assert.equal(store.latest('y').lastAttempt, null);
  assert.equal(store.latest('z').lastSuccess, base);
  // One reading that the database refuses is reported the same way.
  db.script(['poison']);
  assert.deepEqual(
    (await series.append({ service: 'w', time: base, metrics: measurements(1) })).rejected.map(
      r => r.error.class
    ),
    ['poison']
  );
});

test('a reading’s error is cut to 300 characters at the seam, as the Store keeps it; an ID no engine can store is poison', async t => {
  const { legacy, view, series } = twins(t);
  const huge = 'SYNTHETIC '.repeat(512 * 1024); // 5 MiB
  const cases = [
    ['huge', huge],
    // A cut inside a pair keeps whole characters; NUL and half a pair are made storable.
    ['pairs', '😀'.repeat(400)],
    ['dirty', 'a\u0000b\ud800c'],
    ['object', new Error('synthetic failure')],
  ];
  for (const [service, error] of cases) {
    legacy.record(service, [], error, base);
    assert.deepEqual(
      await series.append({ service, time: base, error }),
      { written: 1, rejected: [] },
      service
    );
  }
  const stored = store =>
    store.db
      .prepare('SELECT service, error FROM readings ORDER BY service')
      .all()
      .map(row => ({ ...row }));
  const kept = stored(view);
  assert.deepEqual(kept, stored(legacy), 'v1 stores what the Store stores');
  const by = Object.fromEntries(kept.map(row => [row.service, row.error]));
  assert.equal(by.huge, huge.slice(0, 300));
  assert.equal(by.pairs, '😀'.repeat(300));
  assert.equal(by.dirty, 'ab�c');
  assert.equal(by.object, 'Error: synthetic failure');
  for (const [service] of cases)
    assert.equal((await series.latest([service]))[0].error, by[service], service);
  // A source ID with half a pair was stored as U+FFFD, another ID than the one asked for.
  const refused = await series.append([
    { service: 's\ud800', time: base, metrics: measurements(1) },
    { service: 's\u0000', time: base, metrics: measurements(1) },
    { service: 'fine', time: base, metrics: measurements(1) },
  ]);
  assert.equal(refused.written, 1);
  assert.deepEqual(
    refused.rejected.map(r => [r.index, r.error.class]),
    [
      [0, 'poison'],
      [1, 'poison'],
    ]
  );
  assert.equal(
    view.db.prepare("SELECT count(*) AS n FROM readings WHERE service LIKE 's%'").get().n,
    0
  );
});

test('retention and erasure delete in short chunks and stop when asked or closed', async t => {
  const { history, store } = openHistory(t);
  const series = createSeriesStoreV1({ db: history });
  const insert = store.db.prepare('INSERT INTO readings(service,time,ok,metrics) VALUES (?,?,1,?)');
  store.db.exec('BEGIN');
  for (let n = 0; n < 2500; n++) insert.run(n % 2 ? 'a' : 'b', base - n * 1000, '[]');
  store.db.exec('COMMIT');
  let writes = 0;
  const counting = { ...history, dialect: history.dialect, read: history.read.bind(history) };
  counting.write = (fn, options) => (writes++, history.write(fn, options));
  const chunked = createSeriesStoreV1({ db: counting });
  const removed = await chunked.applyRetention({ retentionDays: 1000 / 86400000, now: base });
  assert.equal(removed, 2498);
  assert.ok(writes > 3, `${writes} chunks`);
  assert.equal(store.stats().samples, 2);
  // An aborted erase stops between chunks and leaves the rest for later.
  store.db.exec('BEGIN');
  for (let n = 0; n < 2500; n++) insert.run('c', base - n * 1000, '[]');
  store.db.exec('COMMIT');
  const controller = new AbortController();
  controller.abort();
  await series.eraseTarget('c', { signal: controller.signal });
  assert.equal(
    store.db.prepare("SELECT COUNT(*) AS n FROM readings WHERE service='c'").get().n,
    2500
  );
  await series.eraseTarget('c');
  assert.equal(store.db.prepare("SELECT COUNT(*) AS n FROM readings WHERE service='c'").get().n, 0);
  // A database closed meanwhile (shutdown) ends the work quietly.
  const directory = temporary(t),
    other = new Store(directory);
  other.close();
  const closing = openSqlite(path.join(directory, 'history.sqlite'));
  const closed = createSeriesStoreV1({ db: closing });
  await closed.append({ service: 'q', time: base, metrics: measurements(1) });
  closing.close();
  assert.equal(await closed.applyRetention({ retentionDays: 1, now: base + 2 * 86400000 }), 0);
  await closed.eraseTarget('q');
  await assert.rejects(closed.stats(), { class: 'unavailable' });
  await assert.rejects(closed.applyRetention({}), { class: 'fatal' });
});

test('appends and retention run as named units of work when given a runner', async t => {
  const { stores } = openHistory(t),
    units = createUnitRunner(stores),
    series = createSeriesStoreV1({ db: stores.series, units });
  await series.append({ service: 'a', time: base, metrics: measurements(1) });
  await series.markGap('a', base + 1);
  await series.applyRetention({ retentionDays: 1, now: base });
  await series.eraseTarget('a');
  const stats = units.stats();
  assert.equal(stats['ingest.append'].runs, 2);
  assert.ok(stats['series.retention'].runs >= 2);
});

test('the series seam: one interface, SQLite keeps v1, later stores are refused until they ship', async t => {
  const { history } = openHistory(t);
  const series = openSeriesStore({ db: history });
  assert.equal(assertSeriesStore(series), series);
  assert.deepEqual(
    SERIES_METHODS.filter(name => typeof series[name] !== 'function'),
    []
  );
  assert.throws(() => assertSeriesStore({ append() {} }), /no latest, query/);
  await assert.rejects(series.compact(), { class: 'unavailable' });
  await assert.rejects(series.materialize(), { class: 'unavailable' });
  assert.throws(() => openSeriesStore({ engine: 'postgres', db: history }), {
    class: 'unavailable',
  });
  assert.throws(() => openSeriesStore({ db: history, version: 'v2' }), { class: 'unavailable' });
  assert.throws(() => createSeriesStoreV1({ db: history, dialect: postgres }), {
    class: 'unavailable',
  });
  assert.throws(() => createSeriesStoreV1({}), { class: 'fatal' });
  assert.deepEqual(series.tables, ['readings', 'latest', 'latest_notes']);
  // The seam is placed on the series class of the stores.
  const { stores } = openHistory(t);
  assert.equal(
    placeStores({ databases: { control: stores.control, history: stores.series } }).series,
    stores.series
  );
});
