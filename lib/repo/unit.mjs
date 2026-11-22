// Named units of work (roadmap §10.4 "Transactions"). A unit owns exactly one transaction on
// the database of one store class: the repositories and ingest never open transactions of
// their own, and no transaction spans two databases (invariant 6). Each unit is idempotent by
// its key, so a retry or a replay after a crash cannot apply it twice.
//
// SQLite runs a unit's callback inside BEGIN IMMEDIATE on the one write connection, so the
// callback must finish synchronously: a callback that awaits would hold the transaction open
// across other work, or run its later statements outside it. The runner refuses async
// callbacks before touching the database, and fails (rolling back) any callback that returns
// a promise; lib/db/sqlite.mjs's own guard does the same underneath (the "SQLite guard").
import { RepoError, toRepoError } from './errors.mjs';
import { STORE_CLASSES } from './stores.mjs';

/**
 * The units of this release and the ones already named for later releases (which the runner
 * refuses until their release). `key` says what makes a unit idempotent.
 */
export const UNITS = Object.freeze({
  'ingest.append': Object.freeze({
    store: 'series',
    since: '1.5.0',
    key: '(source, time) of each reading',
    about: 'Readings, latest values and collector notes of collections (lib/series)',
  }),
  'state.transition': Object.freeze({
    store: 'state',
    since: '1.5.0',
    key: '(source, rule) alert rows; events carry their time',
    about: "Alert state and events of one evaluation (single-node form of 2.2's consumer.commit)",
  }),
  'state.change': Object.freeze({
    store: 'state',
    since: '1.5.0',
    key: 'the source or rule being reset',
    about: 'Alert state reset by a configuration change (rules edited, a source paused)',
  }),
  'series.retention': Object.freeze({
    store: 'series',
    since: '1.5.0',
    key: 'rows older than the cutoff; each chunk commits alone',
    about: 'One chunk of retention or erasure deletes in the series tables',
  }),
  'state.retention': Object.freeze({
    store: 'state',
    since: '1.5.0',
    key: 'rows older than the cutoff; each chunk commits alone',
    about: 'One chunk of retention or erasure deletes in the state tables',
  }),
  'config.applyChange': Object.freeze({
    store: 'control',
    since: '1.5.0',
    key: 'the configuration revision',
    about: 'A configuration change with its config_ext rows (wave 2, #18)',
  }),
  'outbox.claim': Object.freeze({
    store: 'control',
    since: '1.5.0',
    key: 'the outbox row and its attempt',
    about: 'Claiming outbox rows for delivery (lib/notify, #15)',
  }),
  'compaction.window': Object.freeze({
    store: 'series',
    since: '2.1.0',
    key: '(shard, window)',
    about: 'Series store v2 compaction (server databases only)',
  }),
  'consumer.commit': Object.freeze({
    store: 'control',
    since: '2.2.0',
    key: '(shard, cursor)',
    about: 'Shard consumer commit (cluster mode only)',
  }),
});

const available = spec => spec.since.startsWith('1.');
const isAsync = fn => fn?.constructor?.name === 'AsyncFunction';
const isThenable = value =>
  value !== null &&
  (typeof value === 'object' || typeof value === 'function') &&
  typeof value.then === 'function';

/**
 * Runs units of work on the store classes placed by placeStores().
 *   const units = createUnitRunner(stores);
 *   await units.run('ingest.append', tx => { …synchronous statements… }, {key});
 *   await units.read('state', tx => tx.all(query));
 * Every failure is a RepoError naming the unit. `stats()` counts runs and failures per unit.
 */
export function createUnitRunner(stores, { units = UNITS, clock = () => performance.now() } = {}) {
  for (const name of STORE_CLASSES)
    if (typeof stores?.[name]?.write !== 'function')
      throw new RepoError('fatal', `The ${name} store has no database`);
  const counters = new Map();
  const count = (name, started, error) => {
    let entry = counters.get(name);
    if (!entry)
      counters.set(name, (entry = { runs: 0, failures: 0, lastMs: 0, maxMs: 0, classes: {} }));
    const took = clock() - started;
    entry.runs++;
    entry.lastMs = took;
    entry.maxMs = Math.max(entry.maxMs, took);
    if (error) {
      entry.failures++;
      entry.classes[error.class] = (entry.classes[error.class] ?? 0) + 1;
    }
  };
  function spec(name) {
    const found = Object.hasOwn(units, name) ? units[name] : null;
    if (!found) throw new RepoError('fatal', `Unknown unit of work ${JSON.stringify(name)}`);
    if (!available(found))
      throw new RepoError('unavailable', `The ${name} unit arrives in ${found.since}`, {
        unit: name,
      });
    return found;
  }
  return Object.freeze({
    units,
    /**
     * Runs `fn(tx)` as one transaction of the unit's store class and returns its result.
     * `options.retries` is passed to the Db (default 3; only `retry`-class errors are retried).
     */
    async run(name, fn, options = {}) {
      const unit = spec(name),
        store = unit.store,
        started = clock();
      try {
        if (typeof fn !== 'function')
          throw new RepoError('fatal', `${name} needs a callback`, { unit: name });
        if (isAsync(fn))
          throw new RepoError(
            'fatal',
            `${name}: a unit of work runs synchronously inside its transaction; its callback cannot be async`,
            { unit: name }
          );
        const result = await stores[store].write(
          tx => {
            const value = fn(tx);
            if (isThenable(value)) {
              // Its rejection, if any, is this error's business, not an unhandled rejection.
              Promise.resolve(value).catch(() => {});
              throw new RepoError(
                'fatal',
                `${name}: the callback returned a promise; the transaction was rolled back`,
                { unit: name }
              );
            }
            return value;
          },
          { retries: options.retries ?? 3 }
        );
        count(name, started);
        return result;
      } catch (error) {
        const failure = toRepoError(error, { unit: name, store, dialect: stores[store].dialect });
        count(name, started, failure);
        throw failure;
      }
    },
    /** Runs `fn(tx)` in a read transaction of a store class. */
    async read(storeClass, fn) {
      if (!STORE_CLASSES.includes(storeClass))
        throw new RepoError('fatal', `Unknown store class ${JSON.stringify(storeClass)}`);
      try {
        return await stores[storeClass].read(fn);
      } catch (error) {
        throw toRepoError(error, { store: storeClass, dialect: stores[storeClass].dialect });
      }
    },
    /** {unit: {runs, failures, lastMs, maxMs, classes: {class: count}}} */
    stats() {
      const out = {};
      for (const [name, entry] of counters) out[name] = { ...entry, classes: { ...entry.classes } };
      return out;
    },
  });
}
