// SeriesStore v1 (roadmap §10.4, 1.5 #5b): the series seam over the 1.x tables of
// history.sqlite, `readings`, `latest` (its values) and `latest_notes`, which stay exactly as
// lib/store.mjs created them (invariant 1). Every answer has the shape lib/store.mjs gives
// (both build it with lib/series/shape.mjs), so moving a caller from the Store to this seam
// changes nothing it can see. Differences, all invisible to callers:
// - rows are written with UPSERT, never INSERT OR REPLACE (invariant 4);
// - a source's history is erased here and its alert state by lib/repo/state (two units of work
//   instead of the Store's one transaction; each is idempotent);
// - events are recycled on a full disk through the `recycled` hook (lib/repo/state), in the
//   same transaction as the readings, as the Store does.
//
// - it neither reads nor writes lib/store.mjs's 5-minute summaries (history_summaries): its
//   charts read the readings, over the same windows (7 days or more: buckets of whole slots, from
//   shape.mjs historyWindow), which the summaries give exactly; readings appended here are
//   summarised by the Store's check at its next start, like any written behind its back.
//
// SQLite only in 1.5: PostgreSQL's v1 (jsonb, 1.7) and SQL Server's (JSON text, 1.8) add their
// own history query. compact() and materialize() belong to later stores (v2 in 2.1; rollups in
// 1.6) and are refused.
import { sql, id, list } from '../db/sql.mjs';
import { sqlite } from '../db/dialect/sqlite.mjs';
import { RepoError, classOf, toRepoError } from '../repo/errors.mjs';
import { drainChunks, chunkRows as chunk } from '../repo/chunks.mjs';
import {
  GAP,
  cleanNotes,
  latestFromRow,
  emptyLatest,
  historyWindow,
  historyFromBuckets,
  storedError,
} from './shape.mjs';

// Sources per latest() statement (each binds one parameter).
const latestBatch = 500;

const T = Object.freeze({
  readings: id('readings'),
  latest: id('latest'),
  notes: id('latest_notes'),
  service: id('service'),
  time: id('time'),
  ok: id('ok'),
  metrics: id('metrics'),
  error: id('error'),
  attempted: id('attempted'),
  success: id('success'),
  notesColumn: id('notes'),
});

// Cached answers are shared by every caller, so none may change one for the others.
function deepFreeze(value) {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const key of Object.keys(value)) deepFreeze(value[key]);
  }
  return value;
}

/**
 * A reading to append: {service, time, metrics, error = null, notes = metrics.notes} as
 * Store.record() takes them, or {service, time, gap: true} for a pause marker (markGap).
 * Returns the normalised row or throws RepoError('poison').
 */
function reading(input, index) {
  const where = `reading ${index + 1}`;
  if (!input || typeof input !== 'object')
    throw new RepoError('poison', `${where} is not an object`);
  const { service, time } = input;
  if (typeof service !== 'string' || !service)
    throw new RepoError('poison', `${where} has no source ID`);
  if (!Number.isSafeInteger(time)) throw new RepoError('poison', `${where} has no integer time`);
  if (input.gap) return { service, time, gap: true };
  const error = input.error ?? null,
    ok = error === null,
    metrics = ok ? (input.metrics ?? []) : [];
  if (!Array.isArray(metrics)) throw new RepoError('poison', `${where} has no list of readings`);
  return {
    service,
    time,
    ok,
    metrics,
    error: ok ? null : storedError(error),
    // Only a success replaces the notes (see Store.record).
    notes: ok ? cleanNotes(input.notes === undefined ? input.metrics?.notes : input.notes) : [],
  };
}

/**
 * Opens the v1 series store on `db` (the Db holding the series tables: history.sqlite).
 * Options:
 *   dialect   the dialect whose helpers build statements (default db.dialect, else SQLite);
 *   budget    {beforeWrite(), grow() -> boolean, afterDelete()} from whoever owns the
 *             connection's disk budget (lib/store.mjs caps history.sqlite below free space);
 *             grow() says whether freed host space raised the cap;
 *   recycled  (tx, oldest) -> rows deleted: the state tables' part of recycling on a full disk
 *             (events older than the oldest reading left), run in the same transaction;
 *   units     a unit runner (lib/repo/unit.mjs) whose series store is `db`: writes then run as
 *             the units ingest.append and series.retention.
 */
export function createSeriesStoreV1({
  db,
  dialect = db?.dialect ?? sqlite,
  budget,
  recycled,
  units,
} = {}) {
  if (typeof db?.read !== 'function' || typeof db?.write !== 'function')
    throw new RepoError('fatal', 'The v1 series store needs a Db');
  if (dialect.name !== 'sqlite')
    throw new RepoError('unavailable', `The v1 series store on ${dialect.name} arrives in 1.7`);
  const d = dialect;
  // Writes run as units of work when a runner is given (its series store must be this db).
  const run = (unit, fn) => (units ? units.run(unit, fn) : db.write(fn));
  // Source ID → latest() answer. Every write drops the entries it touches before it runs and
  // bumps the generation, so a read that started before a write never caches what it read.
  const cache = new Map();
  let generation = 0;
  const forget = services => {
    generation++;
    for (const service of services) cache.delete(service);
  };
  const orderByTime = () => d.orderBy(['time', 'asc', 'not null']);

  function write(tx, row) {
    if (row.gap) {
      // A marker is a failed reading whose error is '__gap' (see shape.mjs).
      tx.run(
        d.upsert(
          'readings',
          ['service', 'time'],
          ['service', 'time', 'ok', 'metrics', 'error'],
          [[row.service, row.time, 0, '[]', GAP]]
        )
      );
      return;
    }
    if (row.ok && row.notes.length)
      tx.run(
        d.upsert(
          'latest_notes',
          ['service'],
          ['service', 'time', 'notes'],
          [[row.service, row.time, sql.json(row.notes)]]
        )
      );
    else if (row.ok) tx.run(d.deleteFrom('latest_notes', sql`${T.service} = ${row.service}`));
    tx.run(
      d.upsert(
        'readings',
        ['service', 'time'],
        ['service', 'time', 'ok', 'metrics', 'error'],
        [[row.service, row.time, row.ok ? 1 : 0, sql.json(row.metrics), row.error]]
      )
    );
    if (row.ok)
      tx.run(
        d.upsert(
          'latest',
          ['service'],
          ['service', 'attempted', 'success', 'metrics', 'error'],
          [[row.service, row.time, row.time, sql.json(row.metrics), null]]
        )
      );
    else
      tx.run(
        d.upsert(
          'latest',
          ['service'],
          ['service', 'attempted', 'metrics', 'error'],
          [[row.service, row.time, '[]', row.error]],
          { update: ['attempted', 'error'] }
        )
      );
  }

  // Drops at most one chunk (and at most a tenth) of the oldest readings, plus (through the
  // `recycled` hook) events older than the history that remains. Returns the rows deleted.
  function recycleOldest(tx) {
    const { count } = tx.get(sql`SELECT COUNT(*) AS count FROM ${T.readings}`);
    const readings = count
      ? tx.run(
          d.deleteFrom(
            'readings',
            sql`(${T.service}, ${T.time}) IN (SELECT ${T.service}, ${T.time} FROM ${T.readings} ${orderByTime()} ${d.limit(Math.min(chunk, Math.ceil(count / 10)))})`
          )
        ).changes
      : 0;
    const { oldest } = tx.get(sql`SELECT MIN(${T.time}) AS oldest FROM ${T.readings}`);
    const others = oldest === null || !recycled ? 0 : recycled(tx, oldest);
    return readings + others;
  }

  // Store.#write's policy on a full disk: use space freed on the host first, then recycle the
  // oldest history and retry in the same transaction, so a write that can never fit does not
  // erode history (the recycled rows come back when it fails).
  async function writeRows(rows) {
    budget?.beforeWrite?.();
    const apply = tx => {
      for (const row of rows) write(tx, row);
      return rows.length;
    };
    let failure;
    try {
      return await run('ingest.append', apply);
    } catch (error) {
      if (classOf(error, d) !== 'full') throw error;
      failure = error;
    }
    if (budget?.grow?.())
      try {
        return await run('ingest.append', apply);
      } catch (error) {
        if (classOf(error, d) !== 'full') throw error;
        failure = error;
      }
    return await run('ingest.append', tx => {
      if (!recycleOldest(tx)) throw failure;
      return apply(tx);
    });
  }

  const retention = { write: fn => run('series.retention', fn), dialect: d };
  const drain = (statement, signal) => drainChunks(retention, statement, { signal, dialect: d });

  const fail = (error, unit) => toRepoError(error, { unit, store: 'series', dialect: d });

  return Object.freeze({
    version: 'v1',
    tables: Object.freeze(['readings', 'latest', 'latest_notes']),
    /**
     * Appends readings (one collection each, as Store.record(), or {service, time, gap: true}
     * as Store.markGap()) in one transaction. A batch with a value no engine can store is
     * split: the good readings are written and the bad ones returned as `rejected`
     * ({index, error}) and never retried. Returns {written, rejected}.
     */
    async append(batch) {
      const items = Array.isArray(batch) ? batch : [batch];
      const rows = [],
        rejected = [];
      items.forEach((input, index) => {
        try {
          rows.push({ index, row: reading(input, index) });
        } catch (error) {
          rejected.push({ index, error: fail(error, 'ingest.append') });
        }
      });
      if (!rows.length) return { written: 0, rejected };
      const services = rows.map(({ row }) => row.service);
      forget(services);
      try {
        return { written: await writeRows(rows.map(({ row }) => row)), rejected };
      } catch (error) {
        const failure = fail(error, 'ingest.append');
        if (failure.class !== 'poison') throw failure;
        if (rows.length === 1) {
          rejected.push({ index: rows[0].index, error: failure });
          rejected.sort((a, b) => a.index - b.index);
          return { written: 0, rejected };
        }
        // Split: each reading alone, so one bad value costs only its own row.
        let written = 0;
        for (const { index, row } of rows)
          try {
            written += await writeRows([row]);
          } catch (single) {
            const reason = fail(single, 'ingest.append');
            if (reason.class !== 'poison') throw reason;
            rejected.push({ index, error: reason });
          }
        rejected.sort((a, b) => a.index - b.index);
        return { written, rejected };
      } finally {
        // Again once written: a latest() that read while the write waited must not keep it.
        forget(services);
      }
    },
    /** Store.markGap(): a pause, resume or reconfigure marker. */
    markGap(service, time = Date.now()) {
      return this.append({ service, time, gap: true });
    },
    /**
     * The latest readings of each source, as Store.latest() gives them, in the order asked.
     * Answers are cached (and frozen) until an append or erase changes the source.
     */
    async latest(services) {
      const ids = Array.isArray(services) ? services : [services],
        answers = new Map();
      for (const service of ids) if (cache.has(service)) answers.set(service, cache.get(service));
      const missing = [...new Set(ids.filter(service => !answers.has(service)))];
      if (missing.length) {
        const seen = generation,
          keys = missing.filter(service => typeof service === 'string'),
          rows = new Map();
        try {
          if (keys.length)
            await db.read(tx => {
              for (let start = 0; start < keys.length; start += latestBatch)
                for (const row of tx.all(
                  sql`SELECT ${id('l', 'service')} AS service, ${id('l', 'attempted')} AS attempted, ${id('l', 'success')} AS success, ${id('l', 'metrics')} AS metrics, ${id('l', 'error')} AS error, ${id('n', 'time')} AS notes_time, ${id('n', 'notes')} AS notes FROM ${T.latest} l LEFT JOIN ${T.notes} n ON ${id('n', 'service')} = ${id('l', 'service')} WHERE ${id('l', 'service')} IN ${list(keys.slice(start, start + latestBatch))}`
                ))
                  rows.set(row.service, row);
            });
        } catch (error) {
          throw fail(error);
        }
        for (const service of missing) {
          const value = deepFreeze(
            typeof service === 'string'
              ? latestFromRow(service, rows.get(service))
              : emptyLatest(service)
          );
          answers.set(service, value);
          // Only when no write happened meanwhile; otherwise the next call reads it again.
          if (seen === generation && typeof service === 'string') cache.set(service, value);
        }
      }
      return ids.map(service => answers.get(service));
    },
    /** The cached latest() answer of a source, or undefined when it is not cached. */
    cachedLatest(service) {
      return cache.get(service);
    },
    /** Loads every source's latest() answer into the cache (at start). */
    async preload() {
      let rows;
      try {
        rows = await db.read(tx => tx.all(sql`SELECT ${T.service} AS service FROM ${T.latest}`));
      } catch (error) {
        throw fail(error);
      }
      if (rows.length) await this.latest(rows.map(row => row.service));
      return rows.length;
    },
    /**
     * A chart, as Store.history(): q = {service, period, now, pollSeconds, timeoutSeconds,
     * metrics}. At most 301 buckets whatever the retention (historyWindow).
     */
    async query(q = {}) {
      const { service, period = '24h', now = Date.now(), pollSeconds = 60 } = q;
      const window = historyWindow(period, now, pollSeconds, q.timeoutSeconds ?? 90);
      try {
        const rows = await db.read(tx =>
          tx.all(
            sql`WITH ordered AS (SELECT ${T.time}, ${T.ok}, ${T.ok} = 0 AND ${T.error} IS ${GAP} AS marker, LAG(${T.time}) OVER (${orderByTime()}) AS previous FROM ${T.readings} WHERE ${T.service} = ${service} AND ${T.time} >= ${window.from} AND ${T.time} <= ${now}), buckets AS (SELECT MAX(CASE WHEN ${T.ok} = 1 THEN ${T.time} END) AS sample_time, MAX(CASE WHEN ${T.ok} = 0 AND NOT marker THEN ${T.time} END) AS failure_time, MAX(CASE WHEN marker THEN ${T.time} END) AS marker_time, MIN(CASE WHEN ${T.ok} = 0 THEN ${T.time} END) AS first_failure_time, SUM(${T.ok}) AS count, GROUP_CONCAT(CASE WHEN ${T.time} - previous > ${window.gapAfter} THEN ${T.time} END) AS gaps FROM ordered GROUP BY CAST((${T.time} - ${window.from}) / ${window.width} AS INTEGER)) SELECT b.*, ${id('r', 'metrics')} AS metrics, ${id('f', 'error')} AS failure_error FROM buckets b LEFT JOIN ${T.readings} r ON ${id('r', 'service')} = ${service} AND ${id('r', 'time')} = b.sample_time LEFT JOIN ${T.readings} f ON ${id('f', 'service')} = ${service} AND ${id('f', 'time')} = b.failure_time`
          )
        );
        return historyFromBuckets(rows, window, { metrics: q.metrics });
      } catch (error) {
        throw fail(error);
      }
    },
    /** Readings stored in total (the Store's stats().samples). */
    async stats() {
      try {
        const { count } = await db.read(tx =>
          tx.get(sql`SELECT COUNT(*) AS count FROM ${T.readings}`)
        );
        return { samples: count };
      } catch (error) {
        throw fail(error);
      }
    },
    /**
     * Deletes readings older than the profile's retention in short chunks (Store.prune's
     * readings half). profile = {retentionDays, now}; `signal` stops it between chunks.
     * Returns the rows deleted.
     */
    async applyRetention({ retentionDays, now = Date.now(), signal } = {}) {
      if (!Number.isFinite(retentionDays) || retentionDays <= 0)
        throw new RepoError('fatal', 'applyRetention needs retentionDays');
      const before = now - retentionDays * 86400000;
      try {
        const deleted = await drain(
          limit =>
            d.deleteFrom(
              'readings',
              sql`(${T.service}, ${T.time}) IN (SELECT ${T.service}, ${T.time} FROM ${T.readings} WHERE ${T.time} < ${before} ${orderByTime()} ${d.limit(limit)})`
            ),
          signal
        );
        budget?.afterDelete?.();
        return deleted;
      } catch (error) {
        throw fail(error, 'series.retention');
      }
    },
    /**
     * Erases a source's series (Store.forget's series half): its readings in short chunks,
     * then its latest row and notes, and anything recorded meanwhile, in one transaction.
     */
    async eraseTarget(service, { signal } = {}) {
      forget([service]);
      try {
        await drain(
          limit =>
            d.deleteFrom(
              'readings',
              sql`${T.service} = ${service} AND ${T.time} IN (SELECT ${T.time} FROM ${T.readings} WHERE ${T.service} = ${service} ${orderByTime()} ${d.limit(limit)})`
            ),
          signal
        );
        if (signal?.aborted) return;
        await run('series.retention', tx => {
          for (const table of ['latest', 'latest_notes', 'readings'])
            tx.run(d.deleteFrom(table, sql`${T.service} = ${service}`));
        });
      } catch (error) {
        if (classOf(error, d) === 'unavailable') return;
        throw fail(error, 'series.retention');
      } finally {
        forget([service]);
      }
    },
    async compact() {
      throw new RepoError('unavailable', 'Series compaction arrives with series store v2 (2.1)');
    },
    async materialize() {
      throw new RepoError('unavailable', 'Rollups arrive in 1.6');
    },
  });
}
