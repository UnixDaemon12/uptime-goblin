// The async repository seam (1.5 #5): error classes, store classes and units of work over
// lib/db/sqlite.mjs, including the SQLite guard as the repositories meet it.
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { sql, id } from '../../lib/db/sql.mjs';
import { sqlite } from '../../lib/db/dialect/sqlite.mjs';
import { openSqlite } from '../../lib/db/sqlite.mjs';
import {
  RepoError,
  ERROR_CLASSES,
  classOf,
  toRepoError,
  statusFor,
} from '../../lib/repo/errors.mjs';
import { placeStores, STORE_CLASSES } from '../../lib/repo/stores.mjs';
import { createUnitRunner, UNITS } from '../../lib/repo/unit.mjs';
import { openHistory } from './helpers.mjs';

const event = (n, time = 1000 + n) =>
  sqlite.insert(
    'events',
    ['id', 'service', 'time', 'kind', 'message'],
    [[n, 'a', time, 'firing', `event ${n}`]]
  );
const eventCount = tx => tx.get(sql`SELECT COUNT(*) AS count FROM ${id('events')}`).count;

test('repository errors carry one of the dialect classes, whatever raised them', () => {
  assert.deepEqual(Object.keys(statusFor).sort(), [...ERROR_CLASSES].sort());
  const plain = new RepoError('bogus', 'x');
  assert.equal(plain.class, 'fatal');
  assert.equal(plain.status, 500);
  assert.equal(new RepoError('full', 'x').transient, true);
  assert.equal(new RepoError('poison', 'x').transient, false);
  assert.equal(new RepoError('unique', 'x').status, 409);
  // Errors from a Db or lib/db/sql.mjs carry their class; raw driver errors are classified.
  assert.equal(classOf({ class: 'timeout' }), 'timeout');
  assert.equal(classOf({ class: 'nonsense' }), 'fatal');
  const raw = new DatabaseSync(':memory:');
  raw.exec('CREATE TABLE t (k INTEGER PRIMARY KEY)');
  raw.exec('INSERT INTO t VALUES (1)');
  let duplicate;
  try {
    raw.exec('INSERT INTO t VALUES (1)');
  } catch (error) {
    duplicate = error;
  }
  raw.close();
  assert.equal(classOf(duplicate, sqlite), 'unique');
  assert.equal(classOf(duplicate), 'fatal', 'without a dialect nothing is guessed');
  assert.equal(classOf(Object.assign(new Error('x'), { code: 'ENOSPC' }), sqlite), 'full');
  // toRepoError names the unit and store and keeps the cause.
  const wrapped = toRepoError(duplicate, { unit: 'state.transition', dialect: sqlite });
  assert.ok(wrapped instanceof RepoError);
  assert.equal(wrapped.class, 'unique');
  assert.equal(wrapped.unit, 'state.transition');
  assert.equal(wrapped.cause, duplicate);
  assert.match(wrapped.message, /already exists in state\.transition: .*UNIQUE/);
  assert.equal(toRepoError(wrapped, { unit: 'other' }), wrapped, 'already complete');
  const placed = toRepoError(wrapped, { store: 'state' });
  assert.equal(placed.store, 'state');
  assert.equal(placed.unit, 'state.transition');
  assert.equal(placed.class, 'unique');
  assert.equal(toRepoError('text').class, 'fatal');
});

test('store classes are placed per mode: control and history in SQLite, one database otherwise', t => {
  const { control, history, stores } = openHistory(t, { keepStore: false });
  assert.deepEqual(STORE_CLASSES, ['control', 'state', 'series']);
  assert.equal(stores.control, control);
  assert.equal(stores.state, history);
  assert.equal(stores.series, history);
  assert.deepEqual(stores.databases, [control, history]);
  // Tables follow the registry's database.
  assert.equal(stores.forTable('readings'), history);
  assert.equal(stores.forTable('alerts'), history);
  assert.equal(stores.forTable('settings'), control);
  assert.equal(stores.classOf('readings'), 'series');
  assert.equal(stores.classOf('events'), 'state');
  assert.equal(stores.classOf('settings'), 'control');
  assert.throws(() => stores.forTable('nope'), { class: 'fatal' });
  assert.throws(() => stores.forTable('schema_migrations'), /every database/);
  assert.equal(Object.isFrozen(stores), true);
  // One server database holds every class.
  const server = placeStores({ engine: 'postgres', databases: { main: history } });
  assert.equal(server.control, history);
  assert.equal(server.series, history);
  assert.equal(server.forTable('settings'), history);
  assert.deepEqual(server.databases, [history]);
  // Refusals.
  assert.throws(() => placeStores({ databases: { control } }), /history database/);
  assert.throws(() => placeStores({ engine: 'mssql', databases: {} }), /databases\.main/);
  assert.throws(() => placeStores({ engine: 'oracle' }), { class: 'fatal' });
  assert.throws(() => placeStores({ mode: 'cluster', databases: { control, history } }), {
    class: 'unavailable',
  });
  assert.throws(() => placeStores({ mode: 'solo', databases: { control, history } }), {
    class: 'fatal',
  });
});

test('a unit of work commits one synchronous transaction on its store class', async t => {
  const { stores, history } = openHistory(t, { keepStore: true });
  const calls = [];
  const spy = {
    ...stores,
    state: {
      dialect: history.dialect,
      read: (fn, options) => history.read(fn, options),
      write: (fn, options) => (calls.push(options), history.write(fn, options)),
    },
  };
  const units = createUnitRunner(spy);
  assert.equal(await units.run('state.transition', tx => (tx.run(event(1)), eventCount(tx))), 1);
  assert.deepEqual(calls, [{ retries: 3 }], 'the Db retries busy databases itself');
  await units.run('state.transition', tx => tx.run(event(2)), { retries: 0 });
  assert.deepEqual(calls.at(-1), { retries: 0 });
  assert.equal(await units.read('state', eventCount), 2);
  const stats = units.stats();
  assert.equal(stats['state.transition'].runs, 2);
  assert.equal(stats['state.transition'].failures, 0);
  assert.equal(typeof stats['state.transition'].maxMs, 'number');
  // Every unit named for 1.5 names a store class; later ones are refused until their release.
  for (const [name, unit] of Object.entries(UNITS))
    assert.ok(STORE_CLASSES.includes(unit.store), name);
  await assert.rejects(
    units.run('consumer.commit', () => 1),
    {
      class: 'unavailable',
      message: /2\.2\.0/,
    }
  );
  await assert.rejects(
    units.run('compaction.window', () => 1),
    { class: 'unavailable' }
  );
  await assert.rejects(
    units.run('no.such', () => 1),
    { class: 'fatal' }
  );
  await assert.rejects(
    units.run('__proto__', () => 1),
    { class: 'fatal' }
  );
  await assert.rejects(units.run('state.transition'), { class: 'fatal' });
  await assert.rejects(units.read('nowhere', eventCount), { class: 'fatal' });
  assert.throws(() => createUnitRunner({ control: stores.control }), /state store/);
});

test('the SQLite guard: a unit whose callback awaits is refused or rolled back', async t => {
  const { stores } = openHistory(t);
  let touched = 0;
  const counting = {
    ...stores,
    state: {
      dialect: stores.state.dialect,
      read: (fn, options) => stores.state.read(fn, options),
      write: (fn, options) => (touched++, stores.state.write(fn, options)),
    },
  };
  const units = createUnitRunner(counting);
  // Declared async: refused before the database is touched.
  await assert.rejects(
    units.run('state.transition', async tx => tx.run(event(1))),
    error =>
      error instanceof RepoError && error.class === 'fatal' && /cannot be async/.test(error.message)
  );
  assert.equal(touched, 0);
  // Returns a promise after writing: everything it did is rolled back.
  let late;
  await assert.rejects(
    units.run('state.transition', tx => {
      tx.run(event(2));
      late = Promise.resolve().then(() => tx.run(event(3)));
      return late;
    }),
    error =>
      error.class === 'fatal' && error.unit === 'state.transition' && /promise/.test(error.message)
  );
  // The work it tried after the transaction ended is refused too, and nothing was written.
  await assert.rejects(late, /finished/);
  assert.equal(await units.read('state', eventCount), 0);
  const stats = units.stats()['state.transition'];
  assert.equal(stats.failures, 2);
  assert.equal(stats.classes.fatal, 2);
});

test('failures roll a unit back and arrive classified; busy databases are retried', async t => {
  const { directory, stores } = openHistory(t);
  const units = createUnitRunner(stores);
  await units.run('state.transition', tx => tx.run(event(1)));
  // A duplicate key: the whole unit is rolled back, class unique.
  await assert.rejects(
    units.run('state.transition', tx => {
      tx.run(event(2));
      tx.run(event(1));
    }),
    error => error instanceof RepoError && error.class === 'unique' && error.store === 'state'
  );
  assert.equal(await units.read('state', eventCount), 1);
  // An error the callback throws keeps its class.
  await assert.rejects(
    units.run('state.transition', tx => {
      tx.run(event(3));
      throw new RepoError('poison', 'bad reading');
    }),
    { class: 'poison', message: 'bad reading' }
  );
  assert.equal(await units.read('state', eventCount), 1);
  // Another connection holds the write lock: the Db waits at most its busy timeout, then
  // retries asynchronously; the unit succeeds once the lock is gone.
  const file = path.join(directory, 'history.sqlite'),
    quick = openSqlite(file, { busyTimeoutMs: 5, retryDelayMs: 5 }),
    other = new DatabaseSync(file);
  t.after(() => {
    quick.close();
    other.close();
  });
  const busy = createUnitRunner({ ...stores, state: quick });
  other.exec('BEGIN IMMEDIATE');
  const waiting = busy.run('state.transition', tx => tx.run(event(4)));
  setTimeout(() => other.exec('COMMIT'), 12);
  await waiting;
  assert.equal(await busy.read('state', eventCount), 2);
  // Still locked after every retry: class retry, nothing written.
  other.exec('BEGIN IMMEDIATE');
  await assert.rejects(
    busy.run('state.transition', tx => tx.run(event(5))),
    error => error.class === 'retry' && error.unit === 'state.transition'
  );
  other.exec('ROLLBACK');
  assert.equal(await busy.read('state', eventCount), 2);
  // A closed database is unavailable.
  quick.close();
  await assert.rejects(
    busy.run('state.transition', tx => tx.run(event(6))),
    {
      class: 'unavailable',
    }
  );
});
