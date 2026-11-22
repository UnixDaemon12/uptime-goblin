// The `alerts` table (1.x, history.sqlite; class state): one row per source and rule while
// the rule is pending or firing. Only lib/repo/state touches it. Rows are written with UPSERT
// of the 1.x columns, never INSERT OR REPLACE (invariant 4), so columns a later release adds
// survive an update made here.
//
// The evaluator (1.5 #8) stays pure: transition() hands it the source's current rows and
// applies what it returns, the next rows and the events, in one unit of work. Until #8 moves
// evaluation out of lib/store.mjs, Store.evaluate() remains the writer in production.
import { sql, id } from '../../db/sql.mjs';
import { sqlite } from '../../db/dialect/sqlite.mjs';
import { RepoError, toRepoError } from '../errors.mjs';

export const alertColumns = Object.freeze([
  'service',
  'rule',
  'state',
  'since',
  'count',
  'message',
  'updated',
  'recovery_since',
  'recovery_count',
]);
const T = Object.freeze({
  alerts: id('alerts'),
  service: id('service'),
  rule: id('rule'),
  state: id('state'),
});

// Columns an evaluator may leave out: no recovery in progress.
const optional = Object.freeze({ recovery_since: null, recovery_count: 0 });
/** An alert row with every 1.x column, in column order; poison when a value is missing. */
function alertRow(row) {
  if (!row || typeof row !== 'object')
    throw new RepoError('poison', 'An alert row is not an object');
  const values = alertColumns.map(column =>
    row[column] === undefined ? optional[column] : row[column]
  );
  for (const [index, column] of alertColumns.entries())
    if (values[index] === undefined)
      throw new RepoError(
        'poison',
        `The alert row for ${row.service}/${row.rule} has no ${column}`
      );
  if (!['pending', 'firing'].includes(row.state))
    throw new RepoError('poison', `Unknown alert state ${JSON.stringify(row.state)}`);
  return values;
}
const same = (a, b) => alertColumns.every(column => (a[column] ?? null) === (b[column] ?? null));

/**
 * The alerts repository on `db` (the Db of the state tables). `events` is the events
 * repository (transition() inserts events in the same transaction); `units` a unit runner
 * whose state store is this `db` (optional: without one, writes go to db.write directly).
 */
export function createAlerts({ db, dialect = db?.dialect ?? sqlite, events, units } = {}) {
  if (typeof db?.read !== 'function')
    throw new RepoError('fatal', 'The alerts repository needs a Db');
  const d = dialect;
  const fail = (error, unit) => toRepoError(error, { unit, store: 'state', dialect: d });
  const run = async (unit, fn) => {
    try {
      return units ? await units.run(unit, fn) : await db.write(fn);
    } catch (error) {
      throw fail(error, unit);
    }
  };
  const ofService = service => sql`${T.service} = ${service}`;
  // One rule's row. A rule that is not text is a caller's mistake, refused: falling back to the
  // source's condition would delete or reset every rule of the source. clearService() is the one
  // way to change them all.
  const ofRule = (service, rule) => {
    if (typeof rule !== 'string')
      throw new RepoError('fatal', 'An alert rule is needed: use clearService() for every rule');
    return sql`${ofService(service)} AND ${T.rule} = ${rule}`;
  };
  const tx = Object.freeze({
    /** The source's rows, as `SELECT *` returns them. */
    rows: (transaction, service) =>
      transaction.all(sql`SELECT * FROM ${T.alerts} WHERE ${ofService(service)}`),
    /** Inserts or replaces the values of one row (all 1.x columns). */
    put(transaction, row) {
      transaction.run(d.upsert('alerts', ['service', 'rule'], alertColumns, [alertRow(row)]));
    },
    remove: (transaction, service, rule) =>
      transaction.run(d.deleteFrom('alerts', ofRule(service, rule))).changes,
    /**
     * Forgets progress towards recovery. `time`, when given, is also the row's `updated`
     * (as evaluation does); a configuration change leaves `updated` alone.
     */
    resetRecovery: (transaction, service, rule, time) =>
      transaction.run(
        d.update(
          'alerts',
          time === undefined
            ? { recovery_since: null, recovery_count: 0 }
            : { recovery_since: null, recovery_count: 0, updated: time },
          ofRule(service, rule)
        )
      ).changes,
    clearService: (transaction, service) =>
      transaction.run(d.deleteFrom('alerts', ofService(service))).changes,
    clearAll: transaction => transaction.run(d.deleteFrom('alerts', sql`1 = 1`)).changes,
  });
  return Object.freeze({
    tables: Object.freeze(['alerts']),
    tx,
    /** Firing alerts, newest first, as Store.alerts() lists them. */
    async firing() {
      try {
        return await db.read(transaction =>
          transaction.all(
            sql`SELECT ${T.service}, ${T.rule}, ${id('since')}, ${id('message')}, ${id('updated')} FROM ${T.alerts} WHERE ${T.state} = ${'firing'} ${d.orderBy(['since', 'desc', 'not null'])}`
          )
        );
      } catch (error) {
        throw fail(error);
      }
    },
    /** How many alerts are firing (Store.stats().activeAlerts). */
    async countFiring() {
      try {
        return (
          await db.read(transaction =>
            transaction.get(
              sql`SELECT COUNT(*) AS count FROM ${T.alerts} WHERE ${T.state} = ${'firing'}`
            )
          )
        ).count;
      } catch (error) {
        throw fail(error);
      }
    },
    /** A source's rows (pending and firing). */
    async forService(service) {
      try {
        return await db.read(transaction => tx.rows(transaction, service));
      } catch (error) {
        throw fail(error);
      }
    },
    /**
     * One evaluation as a unit of work: `evaluate(rows)` gets the source's current rows (copies)
     * and returns {alerts: the source's next rows, events: transitions to record}. Rows it
     * leaves out are deleted, changed rows are upserted, and the events are inserted, all in
     * one transaction. `evaluate` must be synchronous. Returns the events.
     */
    async transition(service, evaluate) {
      if (typeof evaluate !== 'function')
        throw new RepoError('fatal', 'transition() needs an evaluator');
      // It runs inside the transaction (SQLite guard): synchronous, and pure, since the Db may
      // run it again after a busy database.
      if (evaluate.constructor?.name === 'AsyncFunction')
        throw new RepoError(
          'fatal',
          'An evaluator runs inside the transaction; it cannot be async',
          {
            unit: 'state.transition',
          }
        );
      return run('state.transition', transaction => {
        const current = tx.rows(transaction, service);
        const result = evaluate(current.map(row => ({ ...row })));
        if (typeof result?.then === 'function') {
          Promise.resolve(result).catch(() => {});
          throw new RepoError('fatal', 'An evaluator returned a promise; nothing was written');
        }
        if (!result || !Array.isArray(result.alerts) || !Array.isArray(result.events ?? []))
          throw new RepoError('fatal', 'An evaluator returns {alerts, events}');
        const next = new Map();
        for (const row of result.alerts) {
          if (row?.service !== service)
            throw new RepoError(
              'fatal',
              `An evaluation of ${service} returned a row of another source`
            );
          next.set(row.rule, row);
        }
        for (const row of current)
          if (!next.has(row.rule)) tx.remove(transaction, service, row.rule);
        const byRule = new Map(current.map(row => [row.rule, row]));
        for (const row of next.values())
          if (!byRule.has(row.rule) || !same(byRule.get(row.rule), row)) tx.put(transaction, row);
        const recorded = result.events ?? [];
        if (recorded.length) {
          if (!events) throw new RepoError('fatal', 'transition() needs the events repository');
          events.tx.insert(transaction, recorded);
        }
        return recorded;
      });
    },
    /** Store.reconcileRules(): resets alert state of rules whose definition changed. */
    async reconcileRules(service, oldRules, newRules) {
      return run('state.change', transaction => {
        for (const previous of oldRules) {
          const next = newRules.find(rule => rule.key === previous.key);
          if (
            !next ||
            ['operator', 'threshold', 'forSeconds'].some(key => next[key] !== previous[key])
          )
            tx.remove(transaction, service, previous.key);
          else if ((next.recoveryThreshold ?? null) !== (previous.recoveryThreshold ?? null))
            tx.resetRecovery(transaction, service, previous.key);
        }
      });
    },
    /** Store.clearAlerts(): a source's alert state (paused, reconfigured or removed). */
    async clear(service) {
      return run('state.change', transaction => tx.clearService(transaction, service));
    },
    /** Store.clearAllAlerts(): every source's alert state (alerts switched off). */
    async clearAll() {
      return run('state.change', transaction => tx.clearAll(transaction));
    },
  });
}
