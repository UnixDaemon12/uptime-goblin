// Shared set-up for the repository and series-store tests: a data directory whose
// history.sqlite has the 1.x schema (created by lib/store.mjs, as in production), opened as a
// Db through lib/db/sqlite.mjs.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Store } from '../../lib/store.mjs';
import { openSqlite } from '../../lib/db/sqlite.mjs';
import { placeStores } from '../../lib/repo/stores.mjs';
import { alertColumns } from '../../lib/repo/state/alerts.mjs';

export function temporary(t, prefix = 'orbit-repo-') {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

/**
 * A data directory with history.sqlite (1.x schema) and control.sqlite, open as Dbs.
 * Returns {directory, store (the legacy Store on the same history file, or null), history,
 * control, stores}. Everything is closed after the test.
 */
export function openHistory(t, { keepStore = true, dbOptions = {} } = {}) {
  const directory = temporary(t);
  let store = new Store(directory);
  if (!keepStore) {
    store.close();
    store = null;
  }
  const history = openSqlite(path.join(directory, 'history.sqlite'), dbOptions),
    control = openSqlite(path.join(directory, 'control.sqlite'), dbOptions);
  t.after(() => {
    history.close();
    control.close();
    store?.close();
  });
  return {
    directory,
    store,
    history,
    control,
    stores: placeStores({ databases: { control, history } }),
  };
}

export const measurements = (value, extra = []) => [
  { key: 'cpu', label: 'CPU', value, unit: '%' },
  ...extra,
];
export const capped = (omitted = 3) => [
  { code: 'measurements_capped', message: `Left out ${omitted}.`, omitted },
];

/** A small deterministic generator, so a failing sequence can be replayed. */
export function seeded(seed = 1) {
  let state = seed >>> 0 || 1;
  const random = () => {
    state = (Math.imul(state, 1103515245) + 12345) >>> 0;
    return state / 2 ** 32;
  };
  return {
    random,
    pick: list => list[Math.floor(random() * list.length)],
    int: (low, high) => low + Math.floor(random() * (high - low + 1)),
  };
}

/** Every row of a table in a fixed order (for comparing two databases). */
export const rows = (database, table, order) =>
  database.prepare(`SELECT * FROM ${table} ORDER BY ${order}`).all();

/**
 * A Db wrapper whose write() fails on demand. `script(list)` queues outcomes for the next
 * writes, one per write: null lets it through; a class name fails it before its callback runs;
 * {class, after: true} runs the callback inside the real transaction, then fails it (so it is
 * rolled back). `reads` can delay read() to let other work run in between.
 */
export function faultyDb(db) {
  const pending = [];
  const wrapper = {
    dialect: db.dialect,
    writes: 0,
    beforeRead: null,
    async read(fn, options) {
      if (wrapper.beforeRead) await wrapper.beforeRead();
      return db.read(fn, options);
    },
    write(fn, options) {
      wrapper.writes++;
      const fault = pending.shift();
      if (!fault) return db.write(fn, options);
      const errorClass = typeof fault === 'string' ? fault : fault.class;
      const error = Object.assign(new Error(`injected ${errorClass}`), { class: errorClass });
      if (!fault.after) return Promise.reject(error);
      return db.write(tx => {
        fn(tx);
        throw error;
      }, options);
    },
    script(outcomes) {
      pending.push(...outcomes);
      return wrapper;
    },
    get pending() {
      return pending.length;
    },
  };
  return wrapper;
}

/**
 * An event as the events table stores it (the fields Store.evaluate() transitions carry): since
 * 1.5 also the alert's since and the event's random uid, which the events repository writes with
 * relayed = 0, as Store.evaluate() does.
 */
export const eventOf = e => ({
  service: e.service,
  time: e.time,
  kind: e.kind,
  message: e.message,
  category: e.category,
  rule: e.rule,
  since: e.since,
  uid: e.uid,
});
/** An event without its uid (random per write, so two databases never share it). */
export const withoutUid = ({ uid, ...rest }) => rest;

/**
 * 1.4.2's Store.evaluate() as a pure function of a source's alert rows, for driving
 * alerts.transition() and as the reference of the evaluator differential (roadmap §10.7 gate):
 *   legacyEvaluator(t)(service, metrics, error, time)(rows) -> {alerts, events}
 * A scratch Store holding only the given rows evaluates; its rows afterwards are the next state.
 */
export function legacyEvaluator(t) {
  const scratch = new Store(temporary(t, 'orbit-evaluator-'));
  t.after(() => scratch.close());
  const insert = scratch.db.prepare(
    `INSERT INTO alerts(${alertColumns.join(',')}) VALUES (${alertColumns.map(() => '?').join(',')})`
  );
  return (service, metrics, error, time) => current => {
    scratch.db.exec('DELETE FROM alerts');
    for (const row of current) insert.run(...alertColumns.map(column => row[column]));
    const transitions = scratch.evaluate(service, metrics, error, time);
    return {
      alerts: scratch.db.prepare('SELECT * FROM alerts WHERE service=?').all(service.id),
      events: transitions.map(eventOf),
    };
  };
}
