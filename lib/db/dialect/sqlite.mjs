// The SQLite dialect: the only engine Uptime Goblin executes in 1.5 (lib/db/sqlite.mjs runs what this
// renders). Pure functions only; this module never imports node:sqlite.
//
// Contract (roadmap §10.4): `?` placeholders; ON CONFLICT for upsert and insert-ignore;
// RETURNING; the clock is the process clock (bound as a value); one process, so claims and fences
// need no lock clause (goblin.lock stands in); times are INTEGER milliseconds, JSON is TEXT,
// doubles are REAL and bytes are BLOB. New tables are STRICT, so a value of the wrong type is
// refused as it would be by PostgreSQL or SQL Server.
import { fragment } from '../sql.mjs';
import { createDialect, classifier } from './base.mjs';

const quote = name => `"${name.replaceAll('"', '""')}"`;
const tagged = (strings, values = []) => fragment(strings, values, 'sqlite');

/**
 * SQLite result codes (extended first, then primary = code & 0xff) and their error classes.
 * https://sqlite.org/rescode.html
 */
export const SQLITE_CODES = Object.freeze({
  extended: Object.freeze({
    1555: 'unique', // SQLITE_CONSTRAINT_PRIMARYKEY
    2067: 'unique', // SQLITE_CONSTRAINT_UNIQUE
    2579: 'unique', // SQLITE_CONSTRAINT_ROWID
    275: 'poison', // SQLITE_CONSTRAINT_CHECK
    787: 'poison', // SQLITE_CONSTRAINT_FOREIGNKEY
    1299: 'poison', // SQLITE_CONSTRAINT_NOTNULL
    3091: 'poison', // SQLITE_CONSTRAINT_DATATYPE (STRICT tables)
    1032: 'unavailable', // SQLITE_READONLY_DBMOVED
    517: 'retry', // SQLITE_BUSY_SNAPSHOT
    261: 'retry', // SQLITE_BUSY_RECOVERY
  }),
  primary: Object.freeze({
    1: 'fatal', // SQLITE_ERROR (syntax, missing table, too many variables)
    2: 'fatal', // SQLITE_INTERNAL
    3: 'fatal', // SQLITE_PERM
    4: 'fatal', // SQLITE_ABORT
    5: 'retry', // SQLITE_BUSY
    6: 'retry', // SQLITE_LOCKED
    7: 'unavailable', // SQLITE_NOMEM
    8: 'fatal', // SQLITE_READONLY
    9: 'timeout', // SQLITE_INTERRUPT
    10: 'unavailable', // SQLITE_IOERR
    11: 'fatal', // SQLITE_CORRUPT
    12: 'fatal', // SQLITE_NOTFOUND
    13: 'full', // SQLITE_FULL
    14: 'unavailable', // SQLITE_CANTOPEN
    15: 'retry', // SQLITE_PROTOCOL
    17: 'retry', // SQLITE_SCHEMA
    18: 'poison', // SQLITE_TOOBIG
    19: 'poison', // SQLITE_CONSTRAINT (any other constraint)
    20: 'poison', // SQLITE_MISMATCH
    21: 'fatal', // SQLITE_MISUSE
    22: 'fatal', // SQLITE_NOLFS
    23: 'fatal', // SQLITE_AUTH
    25: 'fatal', // SQLITE_RANGE
    26: 'fatal', // SQLITE_NOTADB
  }),
});
// Node's own errors around node:sqlite (binding and reading values, a closed database).
const NODE_CODES = Object.freeze({
  ERR_OUT_OF_RANGE: 'poison', // an INTEGER outside the safe range read without readBigInts
  ERR_INVALID_ARG_VALUE: 'poison', // a BigInt too large to bind
  ERR_INVALID_ARG_TYPE: 'fatal', // a value node:sqlite cannot bind at all
});

const classify = classifier([
  error => {
    if (error?.code !== 'ERR_SQLITE_ERROR' || !Number.isInteger(error.errcode)) return null;
    return (
      SQLITE_CODES.extended[error.errcode] ?? SQLITE_CODES.primary[error.errcode & 0xff] ?? 'fatal'
    );
  },
  error => NODE_CODES[error?.code] ?? null,
  // A closed database (shutting down) is unavailable; other invalid states are bugs.
  error =>
    error?.code === 'ERR_INVALID_STATE'
      ? /not open|closed|finalized/i.test(error.message ?? '')
        ? 'unavailable'
        : 'fatal'
      : null,
]);

// DDL rules for the schema DSL (schema.mjs).
const ddl = Object.freeze({
  singleOnly: true,
  quote,
  tableName: quote,
  idColumn: 'INTEGER PRIMARY KEY AUTOINCREMENT',
  idIsKey: true,
  keyCollation: 'COLLATE BINARY',
  boolean: value => (value ? '1' : '0'),
  type: column =>
    ({
      text: 'TEXT',
      bigint: 'INTEGER',
      double: 'REAL',
      bool: 'INTEGER',
      bytes: 'BLOB',
      json: 'TEXT',
    })[column.type],
  checks(name, column) {
    if (column.type === 'text' && column.max) return [`length(${name}) <= ${column.max}`];
    if (column.type === 'bool') return [`${name} IN (0, 1)`];
    if (column.type === 'json') return [`json_valid(${name})`];
    return [];
  },
  primaryKey: (name, columns) => `CONSTRAINT ${quote(name)} PRIMARY KEY (${columns.join(', ')})`,
  createTable: (name, lines, spec) =>
    `CREATE TABLE ${name} (\n  ${lines.join(',\n  ')}\n) STRICT${spec.withoutRowid ? ', WITHOUT ROWID' : ''}`,
  createIndex: ({ name, unique, table, keys, where }) =>
    `CREATE ${unique ? 'UNIQUE ' : ''}INDEX ${quote(name)} ON ${table} (${keys})${where ? ` WHERE ${where}` : ''}`,
});

// Catalog queries (base.mjs): the main database's own tables and indexes; SQLite's internal
// ones (sqlite_sequence, sqlite_autoindex_*) are left out.
const internal = `name NOT LIKE 'sqlite\\_%' ESCAPE '\\'`;
const catalog = Object.freeze({
  tables: () =>
    tagged([`SELECT name FROM sqlite_master WHERE type = 'table' AND ${internal} ORDER BY name`]),
  tableExists: name =>
    tagged(["SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = ", ''], [name]),
  columns: name => tagged(['SELECT name FROM pragma_table_info(', ') ORDER BY cid'], [name]),
  indexes: () =>
    tagged([
      `SELECT name, tbl_name AS "table" FROM sqlite_master WHERE type = 'index' AND ${internal} ORDER BY name`,
    ]),
});

/**
 * A SQLite dialect. Options: `identifiers` (the registry's names; every id() must be one) and
 * `clock` (returns epoch milliseconds; default Date.now) for clockMs().
 */
export function createSqliteDialect({ identifiers, clock = Date.now } = {}) {
  return createDialect({
    name: 'sqlite',
    executable: true,
    identifiers,
    caps: {
      cluster: false,
      partitions: false,
      skipLocked: false,
      onlineIndex: true,
      txDdl: true,
      bulkLoad: false,
      dbClock: false,
    },
    quote,
    placeholder: () => '?',
    bind: value => ({ value: typeof value === 'boolean' ? (value ? 1 : 0) : value }),
    json: placeholder => placeholder,
    returning: 'suffix',
    clock: () => tagged(['', ''], [clock()]),
    limit: (state, n, offset) =>
      offset ? `LIMIT ${state.bind(n)} OFFSET ${state.bind(offset)}` : `LIMIT ${state.bind(n)}`,
    orderTerm: (expression, desc, nulls) =>
      tagged(
        [
          '',
          ` ${desc ? 'DESC' : 'ASC'}${nulls === 'not null' ? '' : ` NULLS ${nulls.toUpperCase()}`}`,
        ],
        [expression]
      ),
    locks: { share: { hint: '', tail: '' }, claim: { hint: '', tail: '' } },
    classify,
    catalog,
    ddl,
  });
}

/** The default SQLite dialect (no registry check, process clock). */
export const sqlite = createSqliteDialect();
