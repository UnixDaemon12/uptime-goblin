// The `events` table (1.x, history.sqlite; class state): alert transitions and Uptime Goblin's own
// system events, as lib/store.mjs writes them. Only lib/repo/state touches it. The table is
// never altered here (invariant 1); the columns 1.5 adds for durable delivery (since, uid,
// relayed) are added by lib/store.mjs's additive loop and stay nullable (invariant 2). An event
// with a uid is written with relayed = 0 (the relay copies it to the outbox); one without, as
// 1.4.x wrote it, with relayed NULL, so it is never relayed.
import { sql, id } from '../../db/sql.mjs';
import { sqlite } from '../../db/dialect/sqlite.mjs';
import { RepoError, toRepoError } from '../errors.mjs';
import { drainChunks, chunkRows } from '../chunks.mjs';

const columns = Object.freeze([
  'service',
  'time',
  'kind',
  'message',
  'category',
  'rule',
  'since',
  'uid',
  'relayed',
]);
// An alert change still to relay (relayed = 0) is kept this long whatever the retention or the
// history budget, as lib/store.mjs keeps it, so it is not lost before the relay has copied it.
export const unrelayedKeepMs = 24 * 3600 * 1000;
// What Store.events() lists: the 1.x columns, so the dashboard's events keep their shape.
const listed = Object.freeze(['id', 'service', 'time', 'kind', 'message', 'category', 'rule']);
const T = Object.freeze({
  events: id('events'),
  id: id('id'),
  service: id('service'),
  time: id('time'),
  relayed: id('relayed'),
});

// The most an event may hold: a source ID as configuration allows it, the evaluator's own kinds,
// and a message well above the longest it writes (a label and a 300-character reason). The
// 1.x table has no CHECK, so these are the only bounds on what one row can take.
export const eventLimits = Object.freeze({ service: 80, kind: 32, message: 1000 });

/**
 * An event to insert: {service, time, kind, message, category?, rule?, since?, uid?}, or
 * poison. relayed is 0 when the event has a uid (1.5 alert changes), else NULL. The message can
 * quote a source's own error text, so it is cleaned rather than refused: an unpaired surrogate
 * becomes U+FFFD (what SQLite stored for it before) and a NUL is removed.
 */
function eventRow(event, index) {
  const where = `event ${index + 1}`;
  if (!event || typeof event !== 'object')
    throw new RepoError('poison', `${where} is not an object`);
  for (const key of ['service', 'kind', 'message'])
    if (typeof event[key] !== 'string') throw new RepoError('poison', `${where} has no ${key}`);
  const message = event.message.toWellFormed().replaceAll('\u0000', '');
  for (const [key, value] of [
    ['service', event.service],
    ['kind', event.kind],
    ['message', message],
  ])
    if (!value.length || value.length > eventLimits[key])
      throw new RepoError(
        'poison',
        `${where} has a ${key} of ${value.length} characters (1 to ${eventLimits[key]})`
      );
  if (!Number.isSafeInteger(event.time)) throw new RepoError('poison', `${where} has no time`);
  if (event.since !== undefined && event.since !== null && !Number.isSafeInteger(event.since))
    throw new RepoError('poison', `${where} has an invalid since`);
  if (
    event.uid !== undefined &&
    event.uid !== null &&
    (typeof event.uid !== 'string' || !event.uid)
  )
    throw new RepoError('poison', `${where} has an invalid uid`);
  const uid = event.uid ?? null;
  return [
    event.service,
    event.time,
    event.kind,
    message,
    event.category ?? null,
    event.rule ?? null,
    event.since ?? null,
    uid,
    uid === null ? null : 0,
  ];
}

/**
 * The events repository on `db` (the Db of the state tables). Reads are async; `tx` holds the
 * helpers a unit of work uses inside its transaction.
 */
export function createEvents({ db, dialect = db?.dialect ?? sqlite, units } = {}) {
  if (typeof db?.read !== 'function')
    throw new RepoError('fatal', 'The events repository needs a Db');
  const d = dialect;
  // Writes run as units of work when a runner is given (its state store must be this db).
  const run = (unit, fn) => (units ? units.run(unit, fn) : db.write(fn));
  const retention = { write: fn => run('state.retention', fn), dialect: d };
  const fail = (error, unit) => toRepoError(error, { unit, store: 'state', dialect: d });
  const newestFirst = () => d.orderBy(['time', 'desc', 'not null'], ['id', 'desc', 'not null']);
  // Rows a deletion by age may take: not an unrelayed alert change younger than 24 h.
  const deletable = now =>
    sql`(${T.relayed} IS NULL OR ${T.relayed} <> 0 OR ${T.time} <= ${now - unrelayedKeepMs})`;
  const tx = Object.freeze({
    /** Inserts events in order (ids ascending, as the Store's one-by-one inserts give). */
    insert(transaction, events) {
      const rows = events.map(eventRow);
      for (const row of rows) transaction.run(d.insert('events', columns, [row]));
      return rows.length;
    },
    /**
     * Deletes up to `limit` events older than `time` (recycling on a full disk), except
     * unrelayed alert changes younger than 24 h before `now`.
     */
    deleteBefore(transaction, time, limit = chunkRows, now = Date.now()) {
      return transaction.run(
        d.deleteFrom(
          'events',
          sql`${T.id} IN (SELECT ${T.id} FROM ${T.events} WHERE ${T.time} < ${time} AND ${deletable(now)} ${d.orderBy(['time', 'asc', 'not null'])} ${d.limit(limit)})`
        )
      ).changes;
    },
    /** Deletes a source's events. */
    deleteService(transaction, service) {
      return transaction.run(d.deleteFrom('events', sql`${T.service} = ${service}`)).changes;
    },
  });
  return Object.freeze({
    tables: Object.freeze(['events']),
    tx,
    /** The newest events first, as Store.events() lists them (50 by default). */
    async recent(limit = 50) {
      try {
        return await db.read(transaction =>
          transaction.all(
            sql`SELECT ${sql.ids(listed)} FROM ${T.events} ${newestFirst()} ${d.limit(limit)}`
          )
        );
      } catch (error) {
        throw fail(error);
      }
    },
    async count() {
      try {
        return (
          await db.read(transaction =>
            transaction.get(sql`SELECT COUNT(*) AS count FROM ${T.events}`)
          )
        ).count;
      } catch (error) {
        throw fail(error);
      }
    },
    /** Inserts events in one transaction (Uptime Goblin's own system events). */
    async append(events) {
      try {
        return await run('state.transition', transaction => tx.insert(transaction, events));
      } catch (error) {
        throw fail(error, 'state.transition');
      }
    },
    /**
     * Deletes events older than the retention, in short chunks (Store.prune's events half),
     * except unrelayed alert changes younger than 24 h.
     */
    async applyRetention({ retentionDays, now = Date.now(), signal } = {}) {
      if (!Number.isFinite(retentionDays) || retentionDays <= 0)
        throw new RepoError('fatal', 'applyRetention needs retentionDays');
      const before = now - retentionDays * 86400000;
      try {
        return await drainChunks(
          retention,
          limit =>
            d.deleteFrom(
              'events',
              sql`${T.id} IN (SELECT ${T.id} FROM ${T.events} WHERE ${T.time} < ${before} AND ${deletable(now)} ${d.orderBy(['time', 'asc', 'not null'])} ${d.limit(limit)})`
            ),
          { signal, dialect: d }
        );
      } catch (error) {
        throw fail(error, 'state.retention');
      }
    },
    /** Deletes a source's events in short chunks, then any written meanwhile. */
    async eraseTarget(service, { signal } = {}) {
      try {
        await drainChunks(
          retention,
          limit =>
            d.deleteFrom(
              'events',
              sql`${T.id} IN (SELECT ${T.id} FROM ${T.events} WHERE ${T.service} = ${service} ${d.orderBy(['id', 'asc', 'not null'])} ${d.limit(limit)})`
            ),
          { signal, dialect: d }
        );
        if (!signal?.aborted)
          await run('state.retention', transaction => tx.deleteService(transaction, service));
      } catch (error) {
        const failure = fail(error, 'state.retention');
        if (failure.class !== 'unavailable') throw failure;
      }
    },
  });
}
