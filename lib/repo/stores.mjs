// Store classes (roadmap §10.4, layer 3): every table belongs to one class, and the class
// decides which database holds it in each deployment mode.
//
//   class    holds                                      SQLite (single)          one server database
//   control  config (2.0), identity, audit, settings,    control.sqlite           that database
//            keyring, outbox, incidents, …
//   state    status, alert state, transitions, SLA       history.sqlite for the   that database
//            facts                                       1.x tables; SLA facts in
//                                                        control.sqlite (1.7)
//   series   readings, latest values, rollups            history.sqlite           that database
//
// In a cluster (2.2) control and state live in the control database and series in the shard
// databases; that placement arrives with the cluster store and is refused here until then.
// Repositories never open databases: they are handed the Db of their class (or of their table)
// by placeStores(), so the same repository code runs in every mode.
import defaultRegistry from '../db/registry.mjs';
import { RepoError } from './errors.mjs';

export const STORE_CLASSES = Object.freeze(['control', 'state', 'series']);
export const ENGINES = Object.freeze(['sqlite', 'postgres', 'mssql']);

const isDb = db => Boolean(db) && typeof db.read === 'function' && typeof db.write === 'function';

/**
 * Places the store classes on the open databases.
 *   SQLite:           placeStores({databases: {control, history}})
 *   one server db:    placeStores({engine: 'postgres', databases: {main}})
 * Returns {engine, mode, control, state, series, forTable(name), classOf(name), databases}.
 * `forTable` follows the registry's `db` for SQLite, so a state table registered in the
 * control database (SLA facts, 1.7) is found there; `state` is the database of the 1.x state
 * tables (history.sqlite).
 */
export function placeStores({
  engine = 'sqlite',
  mode = 'single',
  databases = {},
  registry = defaultRegistry,
} = {}) {
  if (!ENGINES.includes(engine))
    throw new RepoError('fatal', `Unknown database engine ${JSON.stringify(engine)}`);
  if (mode === 'cluster')
    throw new RepoError('unavailable', 'Cluster placement arrives with the cluster store (2.2)');
  if (mode !== 'single') throw new RepoError('fatal', `Unknown mode ${JSON.stringify(mode)}`);
  let byDatabase;
  if (engine === 'sqlite') {
    for (const name of ['control', 'history'])
      if (!isDb(databases[name]))
        throw new RepoError('fatal', `SQLite mode needs the ${name} database`);
    byDatabase = { control: databases.control, history: databases.history };
  } else {
    if (!isDb(databases.main))
      throw new RepoError('fatal', `${engine} mode needs its database as databases.main`);
    byDatabase = { control: databases.main, history: databases.main };
  }
  const classes = {
    control: byDatabase.control,
    state: byDatabase.history,
    series: byDatabase.history,
  };
  const table = name => {
    if (!registry.has(name)) throw new RepoError('fatal', `${name} is not a registered table`);
    return registry.table(name);
  };
  return Object.freeze({
    engine,
    mode,
    ...classes,
    /** The class a registered table belongs to. */
    classOf: name => table(name).class,
    /** The Db holding a registered table in this mode. */
    forTable(name) {
      const entry = table(name);
      if (!entry.modes.includes(mode))
        throw new RepoError('fatal', `${name} does not exist in ${mode} mode`);
      if (entry.db === '*') throw new RepoError('fatal', `${name} exists in every database`);
      return byDatabase[entry.db];
    },
    /** Each open database once (for closing, health and backups). */
    databases: Object.freeze([...new Set(Object.values(byDatabase))]),
  });
}
