// The SQLite driver loader: the only Uptime Goblin module besides lib/store.mjs (whose 1.x connection
// predates it) that imports node:sqlite. It gives a SQLite file the `Db` interface of roadmap
// §10.4 so repositories run unchanged on every engine:
//
//   const db = openSqlite(file, {registry});
//   const count = await db.write(tx => tx.run(sql`UPDATE …`).changes);
//   const rows = await db.read(tx => tx.all(sql`SELECT …`));
//
// - write(fn) runs fn inside BEGIN IMMEDIATE … COMMIT and read(fn) inside BEGIN … COMMIT. `fn`
//   gets a transaction object whose run/get/all/iterate take sql`…` queries (lib/db/sql.mjs),
//   rendered by the SQLite dialect with the registry's identifier allowlist.
// - The SQLite guard: fn must finish synchronously. If it returns a promise (it awaited, or it
//   is async), everything it did is rolled back and the call throws a GuardError; the
//   transaction object refuses every later use. That enforces "no SQLite transaction spans an
//   await" at run time.
// - busy_timeout is at most 250 ms (it blocks the event loop while it waits). A unit that meets
//   SQLITE_BUSY (class `retry`) is rolled back and run again after an asynchronous, jittered
//   delay, at most `retries` times (default 3). fn may therefore run more than once: keep its
//   effects outside the database until the returned promise resolves.
// - Every error from SQLite carries `class` (dialect.classify): retry, unique, fenced, full,
//   unavailable, timeout, poison or fatal. Errors fn throws itself pass through unchanged.
// - tx.onCommit(cb), in a write unit, defers an effect that must happen once and only if the
//   unit committed (a line printed, in-memory state): cb runs after COMMIT, when no unit is
//   current (so it may start another), in registration order. An attempt that rolls back, or
//   is run again after a retry, drops what it registered (audit spec D4).
//
// The lock and snapshot primitives at the end (holdExclusive, backupDatabase, quickCheck,
// integrityCheck) are here so no other module needs node:sqlite; lib/db/lock.mjs and
// lib/db/snapshot.mjs use them.
import { DatabaseSync, backup as sqliteBackup } from 'node:sqlite';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { setTimeout as sleep } from 'node:timers/promises';
import { Query, chunkRows, sql } from './sql.mjs';
import { createSqliteDialect } from './dialect/sqlite.mjs';
import defaultRegistry from './registry.mjs';
import { assertDatabaseFiles, printable, tightenMode } from '../saved-data.mjs';

/** The most a SQLite call may block the event loop waiting for another connection's lock. */
export const maxBusyTimeoutMs = 250;
/**
 * The most rows one bulkInsert() call takes. Its write unit is synchronous, so the batch size
 * bounds how long it blocks the event loop; callers split larger inputs into several calls.
 */
export const maxBulkInsertRows = 5000;
const statementCacheSize = 256;
const sqliteReadonly = 8; // SQLITE_READONLY
// The pragmas Db#pragma() accepts (a test seam): read or cap the page count, and checkpoint.
const allowedPragma =
  /^(max_page_count(=\d{1,12})?|page_count|wal_checkpoint\((PASSIVE|TRUNCATE)\))$/;

/** A misuse of a Db: an awaiting callback, a finished transaction, nesting, a closed Db. */
export class GuardError extends Error {
  constructor(message, errorClass = 'fatal') {
    super(message);
    this.name = 'GuardError';
    this.code = 'GOBLIN_SQLITE_GUARD';
    this.class = errorClass;
  }
}

const immutableUrl = file => {
  const url = pathToFileURL(path.resolve(file));
  url.searchParams.set('immutable', '1');
  return url;
};
// node:sqlite opens a path given as a string with URI names on: one starting 'file:' (a relative
// GOBLIN_DATA_DIR such as file:X) opened another file than the one fs checked, locked and
// chmodded, and honoured query parameters such as mode=memory or nolock=1. An absolute path is
// never read as a URI, so every open, check and chmod here acts on the resolved path.
const sqlitePath = file => path.resolve(file);
// The shapes of additive DDL that ddl() runs: what the schema DSL's renderTable() writes (a
// table with its column list, an index on a table's columns) and ALTER TABLE … ADD COLUMN. Not
// any CREATE: CREATE TABLE … AS SELECT copies rows into a table the registry does not know, and a
// view, a trigger, a virtual or a temporary table is a schema object no drift check lists.
const ddlName = '(?:"[a-z_][a-z0-9_]*"|[a-z_][a-z0-9_]*)';
const additiveDdl = [
  new RegExp(
    `^\\s*CREATE\\s+TABLE\\s+${ddlName}\\s*\\([\\s\\S]*\\)(?:\\s*(?:STRICT|WITHOUT\\s+ROWID)(?:\\s*,\\s*(?:STRICT|WITHOUT\\s+ROWID))?)?\\s*;?\\s*$`,
    'i'
  ),
  new RegExp(`^\\s*CREATE\\s+(?:UNIQUE\\s+)?INDEX\\s+${ddlName}\\s+ON\\s+${ddlName}\\s*\\(`, 'i'),
  new RegExp(
    `^\\s*ALTER\\s+TABLE\\s+${ddlName}\\s+ADD\\s+(?:COLUMN\\s+)?(?!CONSTRAINT\\b)${ddlName}\\s`,
    'i'
  ),
];
const isAdditiveDdl = statement =>
  typeof statement === 'string' &&
  !/;\s*\S/.test(statement) &&
  additiveDdl.some(shape => shape.test(statement));
const isThenable = value =>
  value !== null &&
  (typeof value === 'object' || typeof value === 'function') &&
  typeof value.then === 'function';
const fromSqlite = error =>
  error?.code === 'ERR_SQLITE_ERROR' ||
  ['ERR_OUT_OF_RANGE', 'ERR_INVALID_ARG_VALUE', 'ERR_INVALID_STATE'].includes(error?.code);

// A commit callback's failure is not the caller's: its unit committed, so the caller must see
// success. It is reported once, by code or name only (an error message may quote a value), and
// a promise it returns is not awaited, though its rejection is reported the same way.
const commitFailed = error =>
  console.error(`A commit callback failed: ${error?.code ?? error?.name ?? typeof error}`);
function committed(callback) {
  try {
    const result = callback();
    if (isThenable(result)) Promise.resolve(result).catch(commitFailed);
  } catch (error) {
    commitFailed(error);
  }
}

class Transaction {
  #db;
  #kind;
  #active = true;
  #commits = [];
  // Runs one statement ddl() accepted on the connection. Handed in by the Db, which keeps its
  // connection private: a public method for it would run any text for whoever holds the Db.
  #runDdl;
  constructor(db, kind, runDdl) {
    this.#db = db;
    this.#kind = kind;
    this.#runDdl = runDdl;
  }
  /**
   * Registers fn to run once this write unit committed (see the header). Only a write unit can
   * commit something worth reporting; a read() unit refuses, so a misplaced call shows at once.
   */
  onCommit(fn) {
    if (!this.#active)
      throw new GuardError(
        'This transaction has finished; a Db callback must do all its work synchronously.'
      );
    if (this.#kind !== 'write') throw new GuardError('onCommit needs a write unit');
    if (typeof fn !== 'function') throw new TypeError('onCommit needs a function');
    this.#commits.push(fn);
  }
  /** @internal The functions registered by this attempt, in order. */
  get commits() {
    return this.#commits;
  }
  get kind() {
    return this.#kind;
  }
  /** The Db's dialect, for its statement builders (insert, upsert, update, limit, orderBy…). */
  get dialect() {
    return this.#db.dialect;
  }
  get active() {
    return this.#active;
  }
  end() {
    this.#active = false;
  }
  #statement(query, writing) {
    if (!this.#active)
      throw new GuardError(
        'This transaction has finished; a Db callback must do all its work synchronously.'
      );
    if (writing && this.#kind !== 'write')
      throw new GuardError('A read() unit cannot write; use write().');
    return this.#db.prepare(query);
  }
  /** Executes a statement: {changes, lastInsertRowid} (numbers). */
  run(query) {
    const { statement, params } = this.#statement(query, true);
    const result = statement.run(...params);
    return { changes: Number(result.changes), lastInsertRowid: Number(result.lastInsertRowid) };
  }
  /** The first row, or undefined. */
  get(query) {
    const { statement, params } = this.#statement(query, false);
    return statement.get(...params);
  }
  /** Every row. */
  all(query) {
    const { statement, params } = this.#statement(query, false);
    return statement.all(...params);
  }
  /** Rows one at a time; the iteration must also finish before the callback returns. */
  *iterate(query) {
    const { statement, params } = this.#statement(query, false);
    const rows = statement.iterate(...params);
    try {
      for (const row of rows) {
        if (!this.#active) throw new GuardError('This transaction has finished.');
        yield row;
      }
    } finally {
      // Resets the statement even when a step failed (for-of only does so for a failing body);
      // a statement left running keeps the unit's ROLLBACK and PRAGMAs from taking effect.
      rows.return?.();
    }
  }
  /**
   * Runs additive DDL in this write unit; only migrations use it. Accepted: CREATE TABLE and
   * CREATE [UNIQUE] INDEX as the schema DSL's renderTable(dialect, table) writes them, and ALTER
   * TABLE … ADD COLUMN, the one change an expand step may make to an existing table (new `events`
   * columns, nullable: invariant 2). Anything that drops, renames, rewrites or copies rows, and
   * any view, trigger, virtual or temporary table, is refused (see additiveDdl).
   */
  ddl(statements) {
    if (!this.#active) throw new GuardError('This transaction has finished.');
    if (this.#kind !== 'write') throw new GuardError('DDL needs a write() unit.');
    for (const statement of [statements].flat()) {
      if (!isAdditiveDdl(statement))
        throw new GuardError(
          'ddl() takes one additive statement at a time: a create, or a new column'
        );
      this.#runDdl(statement);
    }
  }
}

/**
 * A SQLite database behind the Db interface. Construct with openSqlite(); the connection is
 * opened at once and stays open until close().
 */
class SqliteDb {
  #db;
  // The dialect that renders every statement this connection prepares. Private, with a getter:
  // repositories hold the Db, and one that could replace it (db.dialect = { render }) would
  // have any text prepared for a sql`…` query.
  #dialect;
  #statements = new Map();
  #current = null;
  #closed = false;
  #sleep;
  constructor(file, options) {
    const {
      registry,
      readOnly,
      busyTimeoutMs,
      retries,
      retryDelayMs,
      clock,
      synchronous,
      create,
      sleep: wait,
    } = options;
    if (!Number.isInteger(busyTimeoutMs) || busyTimeoutMs < 0 || busyTimeoutMs > maxBusyTimeoutMs)
      throw new RangeError(`busyTimeoutMs must be 0 to ${maxBusyTimeoutMs}`);
    if (!Number.isInteger(retries) || retries < 0 || retries > 10)
      throw new RangeError('retries must be 0 to 10');
    file = sqlitePath(file);
    // SQLite opens what is there: a FIFO would hold a read-only (immutable) open until something
    // writes to it, and fail a read-write one as a disk error that a restart cannot cure; so
    // would one in place of its journal, which a read-only open checks too; and a symbolic link
    // to nothing would have a new database created through it. Each is a refusal
    // (UnusableFileError, exit 78) before SQLite opens anything.
    assertDatabaseFiles(file);
    const exists = fs.existsSync(file);
    if (!exists && (readOnly || !create))
      throw Object.assign(new Error(`${file} does not exist`), {
        code: 'ENOENT',
        class: 'unavailable',
      });
    if (!readOnly) fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
    // A read-only connection to a database no one has open (no -wal file beside it) is opened
    // immutable. Otherwise SQLite creates -wal and -shm files and leaves them behind, owned by
    // whoever read (root, for `goblin-admin status`), and a read must not change the data
    // directory (a refusal leaves it byte-identical, T11). Immutable reads assume no writer
    // appears meanwhile: true under goblin.lock; for a report taken while Uptime Goblin starts, a
    // query may fail and is simply run again.
    this.immutable = readOnly && !fs.existsSync(`${file}-wal`);
    this.file = file;
    this.readOnly = readOnly;
    this.name = 'sqlite';
    this.registry = registry;
    this.identifiers = registry?.identifiers ?? null;
    this.#dialect = createSqliteDialect({ identifiers: this.identifiers ?? undefined, clock });
    this.retries = retries;
    this.retryDelayMs = retryDelayMs;
    this.clock = clock;
    this.#sleep = wait;
    try {
      this.#db = new DatabaseSync(this.immutable ? immutableUrl(file) : file, { readOnly });
      // Connection settings are engine statements, not queries: they are fixed text here.
      this.#db.exec(`PRAGMA busy_timeout=${busyTimeoutMs}`);
      if (!readOnly) {
        // Not through a symbolic link: its target is not Uptime Goblin's to change.
        tightenMode(file, 0o600);
        this.#db.exec('PRAGMA journal_mode=WAL');
        this.#db.exec(`PRAGMA synchronous=${synchronous === 'NORMAL' ? 'NORMAL' : 'FULL'}`);
      }
      this.#db.exec('PRAGMA foreign_keys=ON');
      // A trigger or view in the file (planted, or carried in by a restore) may use only the
      // functions and tables SQLite marks innocuous: not the pragma_* tables, which read the
      // schema and the files the connection has open. Uptime Goblin's own schema uses none other
      // (length, json_valid in its CHECKs).
      this.#db.exec('PRAGMA trusted_schema=OFF');
    } catch (error) {
      try {
        this.#db?.close();
      } catch {}
      throw this.#classified(error);
    }
  }

  /** The dialect this connection renders statements with (frozen; it cannot be replaced). */
  get dialect() {
    return this.#dialect;
  }
  /** True while a unit of work runs on this connection. */
  get inTransaction() {
    return this.#current !== null;
  }
  get closed() {
    return this.#closed;
  }

  /** @internal Renders a query and returns its cached statement and parameters. */
  prepare(query) {
    if (!(query instanceof Query))
      throw new GuardError('Statements must be sql`…` queries (lib/db/sql.mjs)');
    const { text, params } = this.#dialect.render(query);
    let statement = this.#statements.get(text);
    if (statement) {
      // Most recently used last, so the oldest entry is the first one evicted.
      this.#statements.delete(text);
    } else {
      statement = this.#db.prepare(text);
      if (this.#statements.size >= statementCacheSize)
        this.#statements.delete(this.#statements.keys().next().value);
    }
    this.#statements.set(text, statement);
    return { statement, params };
  }

  #classified(error) {
    if (fromSqlite(error) && typeof error.class !== 'string' && Object.isExtensible(error))
      error.class = this.#dialect.classify(error);
    return error;
  }

  // One attempt of a unit: BEGIN, fn, COMMIT, all synchronous. Rolls back on any failure.
  #unit(kind, fn) {
    if (this.#closed) throw new GuardError('The database is closed.', 'unavailable');
    if (this.#current)
      throw new GuardError(
        'A unit of work is already running on this database; units cannot be nested.'
      );
    const tx = new Transaction(this, kind, statement => this.#db.exec(statement));
    let began = false,
      queryOnly = false;
    this.#current = tx;
    try {
      // A read unit cannot change the database through any accessor: get(), all() and iterate()
      // can run an UPDATE … RETURNING as well as run() can. SQLite's query_only refuses every
      // write for the unit (SQLITE_READONLY), which is reported as the GuardError below.
      if (kind === 'read' && !this.readOnly) {
        this.#db.exec('PRAGMA query_only=ON');
        queryOnly = true;
      }
      const begin = kind === 'write' ? 'BEGIN IMMEDIATE' : 'BEGIN';
      this.#db.exec(begin);
      began = true;
      const result = fn(tx);
      if (isThenable(result)) {
        // The callback went on after this point; nothing it did may commit.
        Promise.resolve(result).catch(() => {});
        throw new GuardError(
          `The callback of ${kind}() returned a promise. A SQLite transaction must finish synchronously, so it was rolled back.`
        );
      }
      this.#db.exec('COMMIT');
      // The commit callbacks go back with the result: #run calls them once this unit is no
      // longer current. A failed attempt never gets here, so its list is dropped with it.
      return { result, commits: tx.commits };
    } catch (error) {
      if (began && this.#db.isTransaction)
        try {
          this.#db.exec('ROLLBACK');
        } catch {}
      if (kind === 'read' && error?.errcode === sqliteReadonly)
        throw new GuardError('A read() unit cannot write; use write().');
      throw this.#classified(error);
    } finally {
      tx.end();
      this.#current = null;
      // If query_only cannot be switched off, the connection stays unable to write: every later
      // write fails (SQLITE_READONLY) rather than a read ever writing.
      if (queryOnly)
        try {
          this.#db.exec('PRAGMA query_only=OFF');
        } catch {}
    }
  }

  async #run(kind, fn, retries) {
    if (typeof fn !== 'function') throw new TypeError(`${kind}() needs a callback`);
    for (let attempt = 0; ; attempt += 1) {
      let done;
      try {
        done = this.#unit(kind, fn);
      } catch (error) {
        if (error?.class !== 'retry' || attempt >= retries || error instanceof GuardError)
          throw error;
        // Jittered, growing waits: 1×, 2×, 4× the base, each between half and the full step.
        const step = this.retryDelayMs * 2 ** attempt;
        await this.#sleep(step / 2 + Math.random() * (step / 2));
        if (this.#closed) throw error;
        continue;
      }
      // Committed: #current is null again, so a callback may start another unit.
      for (const callback of done.commits) committed(callback);
      return done.result;
    }
  }

  /** Runs fn(tx) in a read transaction (one consistent snapshot). */
  read(fn, { retries = this.retries } = {}) {
    return this.#run('read', fn, retries);
  }
  /**
   * Runs fn(tx) in BEGIN IMMEDIATE … COMMIT. `fence` (lease references) is for server
   * databases; in SQLite mode goblin.lock stands in for it, so it must be empty.
   */
  write(fn, { retries = this.retries, fence } = {}) {
    if (this.readOnly) return Promise.reject(new GuardError('This database was opened read-only.'));
    if (fence?.length)
      return Promise.reject(
        new GuardError('SQLite mode has no leases to fence; goblin.lock stands in for them.')
      );
    return this.#run('write', fn, retries);
  }

  /**
   * Inserts rows given column by column (`columnBatch[i]` holds the values of `columns[i]`) in
   * one write unit, in statements of at most the dialect's parameter limit. onConflict
   * 'ignore' skips rows whose key exists (in the table or earlier in the batch); 'error' fails
   * the whole batch with class `unique`. Resolves to the number of rows inserted.
   */
  async bulkInsert(table, columns, columnBatch, { onConflict = 'error' } = {}) {
    if (!['ignore', 'error'].includes(onConflict))
      throw new GuardError("onConflict must be 'ignore' or 'error'");
    if (!Array.isArray(columns) || !columns.length || !Array.isArray(columnBatch))
      throw new GuardError('bulkInsert needs columns and one value array per column');
    if (columnBatch.length !== columns.length || columnBatch.some(values => !Array.isArray(values)))
      throw new GuardError('bulkInsert needs one value array per column');
    const count = columnBatch[0].length;
    if (columnBatch.some(values => values.length !== count))
      throw new GuardError('bulkInsert: every column needs the same number of values');
    if (count > maxBulkInsertRows)
      throw new GuardError(
        `bulkInsert takes at most ${maxBulkInsertRows} rows per call (got ${count}); split the batch`
      );
    if (!count) return 0;
    const rows = Array.from({ length: count }, (_, row) => columnBatch.map(values => values[row]));
    const statements = chunkRows(rows, columns.length, this.#dialect.caps.maxParams).map(chunk =>
      onConflict === 'ignore'
        ? this.#dialect.insertIgnore(table, columns, chunk)
        : this.#dialect.insert(table, columns, chunk)
    );
    return this.write(tx => statements.reduce((sum, query) => sum + tx.run(query).changes, 0));
  }

  /** The database clock in epoch milliseconds: in SQLite mode, the process clock. */
  async now() {
    return this.clock();
  }

  /**
   * A test seam on this connection (nothing in Uptime Goblin calls it): runs `PRAGMA <text>` outside any
   * unit and returns its rows. Only page-count limits and checkpoints are accepted, so a test can
   * make Uptime Goblin's own control.sqlite full (a page limit belongs to a connection, so no other
   * connection can do it) and empty its WAL before filling the disk. Errors carry their class.
   */
  pragma(text) {
    if (typeof text !== 'string' || !allowedPragma.test(text))
      throw new GuardError(`pragma(): ${JSON.stringify(text)} is not an allowed pragma`);
    if (this.#closed) throw new GuardError('The database is closed.', 'unavailable');
    if (this.#current)
      throw new GuardError('pragma() cannot run inside a unit of work on the same database.');
    try {
      return this.#db.prepare(`PRAGMA ${text}`).all();
    } catch (error) {
      throw this.#classified(error);
    }
  }

  /**
   * Names of the tables, indexes, triggers and views in this database (for registry drift
   * checks), and `others`: every other row of its catalog, as {type, name} (see catalogKind).
   * Uptime Goblin declares no triggers or views: one found here was put there by something else, and a
   * trigger runs under Uptime Goblin's own writes, so check-data reports them and the others too.
   */
  catalog() {
    return this.read(tx => {
      const rows = tx.all(sql`SELECT type, name, sql FROM sqlite_master`);
      const named = kind =>
        rows
          .filter(row => catalogKind(row) === kind)
          .map(row => row.name)
          .sort();
      return {
        tables: named('table'),
        indexes: named('index'),
        triggers: named('trigger'),
        views: named('view'),
        others: rows
          .filter(row => catalogKind(row) === null)
          .map(({ type, name }) => ({ type, name }))
          .sort((a, b) =>
            String(a.name) < String(b.name) ? -1 : +(String(a.name) > String(b.name))
          ),
      };
    });
  }

  /** Closes the connection. A unit still running refuses (its callback is synchronous). */
  close() {
    if (this.#closed) return;
    if (this.#current) throw new GuardError('Cannot close the database inside a unit of work.');
    this.#closed = true;
    this.#statements.clear();
    this.#db.close();
  }
}

/**
 * Opens (creating it unless `readOnly` or `create: false`) the SQLite database `file` as a Db.
 * A read-only Db never adds files beside the database (see `immutable` above).
 * Options: registry (identifier allowlist; default lib/db/registry.mjs), readOnly,
 * busyTimeoutMs (≤ 250), retries (3), retryDelayMs (20), synchronous ('FULL' | 'NORMAL'),
 * clock (epoch ms, for now() and dialect.clockMs()), sleep (tests).
 */
export function openSqlite(
  file,
  {
    registry = defaultRegistry,
    readOnly = false,
    create = true,
    busyTimeoutMs = maxBusyTimeoutMs,
    retries = 3,
    retryDelayMs = 20,
    synchronous = 'FULL',
    clock = Date.now,
    sleep: wait = ms => sleep(ms),
  } = {}
) {
  return new SqliteDb(file, {
    registry,
    readOnly,
    create,
    busyTimeoutMs,
    retries,
    retryDelayMs,
    synchronous,
    clock,
    sleep: wait,
  });
}

// ---------------------------------------------------------------------------------------------
// Primitives for lib/db/lock.mjs and lib/db/snapshot.mjs.

/**
 * Takes an exclusive, process-lifetime lock on the SQLite file `file` (created if missing): the
 * operating system releases it when the process exits, however it exits. Returns {release()},
 * or throws an error with `busy: true` when another connection (in this process or another)
 * holds it. Never open, read or copy a held lock file with fs in the same process: closing any
 * descriptor of it drops POSIX locks.
 */
export function holdExclusive(file) {
  let db;
  try {
    db = new DatabaseSync(sqlitePath(file));
    db.exec('PRAGMA busy_timeout=0');
    db.exec('PRAGMA locking_mode=EXCLUSIVE');
    // An in-memory journal: holding the lock leaves no journal file beside it.
    db.exec('PRAGMA journal_mode=MEMORY');
    db.exec('BEGIN EXCLUSIVE');
  } catch (error) {
    try {
      db?.close();
    } catch {}
    if (error?.errcode === 5 || error?.errcode === 6) error.busy = true;
    throw error;
  }
  let held = true;
  return {
    file,
    release() {
      if (!held) return;
      held = false;
      try {
        db.exec('ROLLBACK');
      } finally {
        db.close();
      }
    },
    get held() {
      return held;
    },
  };
}

/**
 * Copies the SQLite database `source` to `destination` with SQLite's online backup (a
 * consistent copy even while another connection writes, WAL included). The copy is switched
 * to a rollback journal, so it is one self-contained file that opening read-only never adds
 * -wal/-shm files to (Uptime Goblin switches it back to WAL when it opens a restored copy). The source
 * is opened read-write but query-only: a read-only connection would leave -wal/-shm files
 * behind it. Resolves to the number of pages copied.
 */
export async function backupDatabase(source, destination) {
  assertDatabaseFiles(source);
  if (!fs.existsSync(source))
    throw Object.assign(new Error(`${source} does not exist`), { code: 'ENOENT' });
  const db = new DatabaseSync(sqlitePath(source));
  let pages;
  try {
    db.exec(`PRAGMA busy_timeout=${maxBusyTimeoutMs}`);
    db.exec('PRAGMA query_only=1');
    // node:sqlite settles the backup's promise without running the microtask queue, so the
    // await below would resume only when some other event wakes the loop (a pending timer can
    // hold it for seconds). A short interval during the copy provides that event.
    const wake = setInterval(() => {}, 5);
    try {
      // Resolved, as every path given to node:sqlite: 'file:X/…' would be read as a URI, and the
      // copy written to another file than the one the caller then checks and chmods.
      pages = await sqliteBackup(db, sqlitePath(destination));
    } finally {
      clearInterval(wake);
    }
  } finally {
    db.close();
  }
  const copy = new DatabaseSync(sqlitePath(destination));
  try {
    copy.exec('PRAGMA journal_mode=DELETE');
  } finally {
    copy.close();
  }
  return pages;
}

/**
 * What a row of a database's catalog (sqlite_master: type, name, sql) is: 'table', 'index',
 * 'trigger' or 'view', or null for any other row. SQLite builds each object from the row's SQL
 * and compares its type without regard to case and only up to a NUL, so a trigger whose row says
 * 'TRIGGER' (or 'trigger' and a NUL) runs inside Uptime Goblin's writes like any other: a catalog that
 * matched the type exactly listed nothing. Fail closed: a row is a table or an index only as
 * SQLite writes one (that type exactly, and the CREATE statement SQLite writes for it, or no SQL
 * for the index of a PRIMARY KEY or UNIQUE constraint). Any other row, another type or SQL that
 * SQLite does not write for its type (a virtual table, say), is null: plantedObjects() names it.
 */
export function catalogKind({ type, sql: definition }) {
  if (type === 'trigger' || type === 'view') return type;
  if (type === 'table')
    return typeof definition === 'string' && /^CREATE TABLE /.test(definition) ? type : null;
  if (type === 'index')
    return definition === null ||
      (typeof definition === 'string' && /^CREATE (?:UNIQUE )?INDEX /.test(definition))
      ? type
      : null;
  return null;
}

/**
 * The triggers and views of a database's catalog (SqliteDb#catalog()), as "trigger <name>" and
 * "view <name>", and its other rows (catalogKind) as 'catalog entry <name> of type "<type>"',
 * each name printable and cut: Uptime Goblin creates none in its databases, so each was put there by
 * something else (a hand edit, a crafted restore), and a trigger runs inside Uptime Goblin's own writes,
 * where it could undo a sign-out or rewrite a password.
 */
export const plantedObjects = ({ triggers = [], views = [], others = [] }) => [
  ...triggers.map(name => `trigger ${printable(name, 100)}`),
  ...views.map(name => `view ${printable(name, 100)}`),
  ...others.map(
    ({ type, name }) =>
      `catalog entry ${printable(name, 100)} of type ${printable(typeof type === 'string' ? JSON.stringify(type) : String(type), 40)}`
  ),
];

/**
 * Why the database file `file` cannot be read, or null when it can. Only its main file is read
 * (immutable=1: no lock, and its -wal and -shm are left alone): a file whose header is damaged,
 * opened the usual way, fails, and closing it deletes its WAL. A restore checks a live database
 * with this before settling it, and moves one that cannot be read aside as it is.
 */
export function databaseProblem(file) {
  let db;
  try {
    assertDatabaseFiles(file);
    db = new DatabaseSync(immutableUrl(file), { readOnly: true });
    db.prepare('SELECT count(*) FROM sqlite_master').get();
    return null;
  } catch (error) {
    return error?.message || String(error);
  } finally {
    db?.close();
  }
}

/**
 * Folds a closed database's WAL into its main file and switches it to a rollback journal, so
 * the file alone is the whole database and can be renamed. Only while nothing else has it
 * open (offline, under goblin.lock).
 */
export function settleDatabase(file) {
  assertDatabaseFiles(file);
  const db = new DatabaseSync(sqlitePath(file));
  try {
    db.exec(`PRAGMA busy_timeout=${maxBusyTimeoutMs}`);
    db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    db.exec('PRAGMA journal_mode=DELETE');
  } finally {
    db.close();
  }
}

/**
 * SQLite's quick_check of a database file: 'ok', or the problems it found. Meant for
 * snapshot copies (rollback journal), which a read-only open leaves untouched.
 */
export function quickCheck(file) {
  assertDatabaseFiles(file);
  const db = new DatabaseSync(sqlitePath(file), { readOnly: true });
  try {
    const rows = db.prepare('PRAGMA quick_check').all();
    const found = rows.map(row => Object.values(row)[0]);
    return found.length === 1 && found[0] === 'ok' ? 'ok' : found.join('; ');
  } finally {
    db.close();
  }
}

/**
 * SQLite's integrity_check of a database file, at most the first 100 problems: 'ok', or the
 * problems it found. Unlike quick_check it also checks that every index holds exactly the rows
 * of its table, so a copy whose index disagrees with its table (which quick_check passes) is
 * refused. It reads every index entry: on a synthetic history.sqlite of 1.7M readings (2.7 GiB)
 * it took about 1.9 s against quick_check's 0.8 s and the backup's 2.9 s (warm cache, SSD).
 * Meant for snapshot copies, as quickCheck.
 */
export function integrityCheck(file) {
  assertDatabaseFiles(file);
  const db = new DatabaseSync(sqlitePath(file), { readOnly: true });
  try {
    const rows = db.prepare('PRAGMA integrity_check=100').all();
    const found = rows.map(row => Object.values(row)[0]);
    return found.length === 1 && found[0] === 'ok' ? 'ok' : found.join('; ');
  } finally {
    db.close();
  }
}
