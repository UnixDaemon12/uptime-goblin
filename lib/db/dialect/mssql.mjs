// The SQL Server dialect: a render-only skeleton in 1.5 (overrides 1.6–1.8, preview 2.0,
// supported 2.1). Nothing executes it in 1.5 and no driver is installed; lib/db/mssql.mjs (the
// driver-pack loader) will be the only importer of `tedious`. Reach it only through
// `loadDialect('mssql')` (a dynamic import): SQLite mode must never resolve it.
//
// Contract (roadmap §10.4 and review items R40–R50): `@pN` placeholders with strings bound as
// VarChar (never NVARCHAR, which turns index seeks into scans); upsert is UPDATE … WITH (UPDLOCK,
// SERIALIZABLE) then INSERT, never MERGE, keys sorted; duplicates are ignored by a unique index
// WITH (IGNORE_DUP_KEY = ON); OUTPUT inserted.* instead of RETURNING; claims use
// WITH (UPDLOCK, READPAST, ROWLOCK) and fences WITH (HOLDLOCK, ROWLOCK); the clock is
// DATEDIFF_BIG(millisecond, '1970-01-01', SYSUTCDATETIME()); NULL ordering is emulated (T-SQL has
// no NULLS FIRST/LAST); OFFSET … FETCH needs an ORDER BY; text(n) is varchar(4n) in a _UTF8
// database, key text uses Latin1_General_100_BIN2_UTF8; JSON is varchar(max) checked by ISJSON;
// doubles are float (never real); schema `orbit`.
import { fragment, SqlError, sql, id, join } from '../sql.mjs';
import { createDialect, classifier } from './base.mjs';

const quote = name => `[${name.replaceAll(']', ']]')}]`;
const tagged = (strings, values = []) => fragment(strings, values, 'mssql');

/** SQL Server error numbers and tedious error codes → error class. */
export const MSSQL_CODES = Object.freeze({
  numbers: Object.freeze({
    1205: 'retry', // chosen as deadlock victim
    1222: 'retry', // lock request time out period exceeded
    3960: 'retry', // snapshot isolation update conflict
    3961: 'retry', // snapshot isolation: object changed by DDL
    // Azure SQL transient errors (retried with jitter)
    4060: 'retry',
    4221: 'retry',
    10928: 'retry',
    10929: 'retry',
    40143: 'retry',
    40197: 'retry',
    40501: 'retry',
    40540: 'retry',
    40613: 'retry',
    42108: 'retry',
    42109: 'retry',
    49918: 'retry',
    49919: 'retry',
    49920: 'retry',
    2601: 'unique', // duplicate key row in a unique index
    2627: 'unique', // unique or primary key constraint violation
    1101: 'full', // could not allocate a page (filegroup full)
    1105: 'full', // could not allocate space (filegroup full)
    9002: 'full', // transaction log full
    515: 'poison', // cannot insert NULL
    547: 'poison', // foreign key or check constraint
    2628: 'poison', // string or binary data would be truncated
    8152: 'poison', // string or binary data would be truncated (older form)
    8115: 'poison', // arithmetic overflow
    245: 'poison', // conversion failed
    8114: 'poison', // error converting data type
    8023: 'poison', // invalid float parameter value (NaN or Infinity in the RPC)
    13609: 'poison', // JSON text is not properly formatted
    701: 'unavailable', // insufficient system memory
    976: 'unavailable', // availability group database not accessible
    978: 'unavailable', // AG secondary without read intent
    983: 'unavailable', // AG database role is resolving
    3906: 'unavailable', // database is read-only
    64: 'unavailable', // connection lost
    233: 'unavailable', // no process on the other end of the pipe
    10053: 'unavailable',
    10054: 'unavailable',
    10060: 'unavailable',
    [-2]: 'timeout', // client timeout
    18456: 'fatal', // login failed
    102: 'fatal', // syntax error
    207: 'fatal', // invalid column name
    208: 'fatal', // invalid object name
    229: 'fatal', // permission denied
  }),
  codes: Object.freeze({
    ETIMEOUT: 'timeout',
    ECANCEL: 'timeout',
    ESOCKET: 'unavailable',
    ECLOSE: 'unavailable',
    ENOTOPEN: 'unavailable',
    ECONNRESET: 'unavailable',
    ECONNREFUSED: 'unavailable',
    EINSTLOOKUP: 'unavailable',
    ELOGIN: 'fatal',
    EINVALIDSTATE: 'fatal',
  }),
});

const classify = classifier([
  error => (Number.isInteger(error?.number) ? (MSSQL_CODES.numbers[error.number] ?? null) : null),
  error => MSSQL_CODES.codes[error?.code] ?? null,
]);

// tedious needs a type for each parameter. Strings are VarChar (R40); a NULL is typed VarChar
// here, so a NULL for a varbinary column needs an explicit type once statements execute (1.6).
function bind(value) {
  if (value === null) return { value, type: 'VarChar' };
  if (typeof value === 'string') return { value, type: 'VarChar' };
  if (typeof value === 'boolean') return { value, type: 'Bit' };
  if (typeof value === 'bigint') return { value: value.toString(), type: 'BigInt' };
  if (typeof value === 'number')
    return { value, type: Number.isSafeInteger(value) ? 'BigInt' : 'Float' };
  if (value instanceof Uint8Array) return { value, type: 'VarBinary' };
  throw new SqlError('fatal', 'SQL Server cannot bind this value');
}

// T-SQL has no NULLS FIRST/LAST: NULL sorts first ascending and last descending, so the other two
// orders add a CASE key in front.
function orderTerm(expression, desc, nulls) {
  const direction = tagged([` ${desc ? 'DESC' : 'ASC'}`]);
  const native = nulls === 'not null' || (desc ? nulls === 'last' : nulls === 'first');
  if (native) return sql`${expression}${direction}`;
  const [whenNull, otherwise] = desc ? ['0', '1'] : ['1', '0'];
  return sql`${tagged([`CASE WHEN `])}${expression}${tagged([` IS NULL THEN ${whenNull} ELSE ${otherwise} END, `])}${expression}${direction}`;
}

function limit(state, n, offset) {
  if (!state.seen.has('orderBy'))
    throw new SqlError('fatal', 'SQL Server needs orderBy() before limit() (OFFSET … FETCH)');
  return `OFFSET ${state.bind(offset)} ROWS FETCH NEXT ${state.bind(n)} ROWS ONLY`;
}

const serializable = tagged([' WITH (UPDLOCK, SERIALIZABLE)']);

// Upsert without MERGE: per row, sorted by key, UPDATE under a key-range lock, then INSERT when
// nothing was updated. One batch, one round trip.
function upsert({ table, names, keyNames, update, rows, options, returning }) {
  const output = options.returning ? sql` ${returning(options.returning)}` : sql``;
  const statements = rows.map(row => {
    const valueOf = column => row[names.indexOf(column)];
    const where = join(
      keyNames.map(key => sql`${id(key)} = ${valueOf(key)}`),
      sql` AND `
    );
    const insert = sql`INSERT INTO ${table} (${join(names.map(name => id(name)))})${output} VALUES (${join(row)})`;
    if (!update.length)
      return sql`IF NOT EXISTS (SELECT 1 FROM ${table}${serializable} WHERE ${where}) ${insert};`;
    const set = join(update.map(column => sql`${id(column)} = ${valueOf(column)}`));
    return sql`UPDATE ${table}${serializable} SET ${set}${output} WHERE ${where};
IF @@ROWCOUNT = 0 ${insert};`;
  });
  return join(statements, sql`\n`);
}

function ddl(schema) {
  const tableName = name => `${quote(schema)}.${quote(name)}`;
  const ignore = flag => (flag ? ' WITH (IGNORE_DUP_KEY = ON)' : '');
  return Object.freeze({
    singleOnly: false,
    quote,
    tableName,
    idColumn: 'bigint IDENTITY(1,1) NOT NULL',
    idIsKey: false,
    keyCollation: 'COLLATE Latin1_General_100_BIN2_UTF8',
    boolean: value => (value ? '1' : '0'),
    type: column =>
      column.type === 'text'
        ? column.max
          ? `varchar(${column.max * 4})`
          : 'varchar(max)'
        : {
            bigint: 'bigint',
            double: 'float',
            bool: 'bit',
            bytes: 'varbinary(max)',
            json: 'varchar(max)',
          }[column.type],
    checks(name, column) {
      // LEN() ignores trailing spaces, so they are counted by replacing them one for one first:
      // text(n) is n characters on every engine, spaces included.
      if (column.type === 'text' && column.max)
        return [`LEN(REPLACE(${name}, ' ', '.')) <= ${column.max}`];
      if (column.type === 'json') return [`ISJSON(${name}) = 1`];
      return [];
    },
    primaryKey: (name, columns, key) =>
      `CONSTRAINT ${quote(name)} PRIMARY KEY CLUSTERED (${columns.join(', ')})${ignore(key.ignoreDuplicates)}`,
    createTable: (name, lines, spec) =>
      `CREATE TABLE ${name} (\n  ${lines.join(',\n  ')}\n)${
        spec.partition
          ? ` ON ${quote(`${spec.name}_ps`)} (${quote(spec.partition.column)}) /* ${spec.partition.interval} ranges: the partition manager */`
          : ''
      }`,
    createIndex: ({ name, unique, table, keys, where, ignoreDuplicates }) =>
      `CREATE ${unique ? 'UNIQUE ' : ''}NONCLUSTERED INDEX ${quote(name)} ON ${table} (${keys})${where ? ` WHERE ${where}` : ''}${ignore(ignoreDuplicates)}`,
  });
}

// Catalog queries (base.mjs) over sys.*, for the dialect's schema (bound as a value). A heap's
// row in sys.indexes has no name and is left out.
const schemaTables = 'FROM sys.tables AS t WHERE t.schema_id = SCHEMA_ID(';
function catalog(schema) {
  return Object.freeze({
    tables: () => tagged([`SELECT t.name AS name ${schemaTables}`, ') ORDER BY t.name'], [schema]),
    tableExists: name =>
      tagged([`SELECT 1 AS present ${schemaTables}`, ') AND t.name = ', ''], [schema, name]),
    columns: name =>
      tagged(
        [
          'SELECT c.name AS name FROM sys.columns AS c JOIN sys.tables AS t ON t.object_id = c.object_id WHERE t.schema_id = SCHEMA_ID(',
          ') AND t.name = ',
          ' ORDER BY c.column_id',
        ],
        [schema, name]
      ),
    indexes: () =>
      tagged(
        [
          'SELECT i.name AS name, t.name AS [table] FROM sys.indexes AS i JOIN sys.tables AS t ON t.object_id = i.object_id WHERE t.schema_id = SCHEMA_ID(',
          ') AND i.name IS NOT NULL ORDER BY i.name',
        ],
        [schema]
      ),
  });
}

/**
 * A SQL Server dialect (render only in 1.5). Options: `identifiers` (the registry's names) and
 * `schema` (default `orbit`; DDL is schema-qualified, statements rely on the login's default
 * schema being `orbit`).
 */
export function createMssqlDialect({ identifiers, schema = 'orbit' } = {}) {
  return createDialect({
    name: 'mssql',
    executable: false,
    identifiers,
    caps: {
      cluster: true,
      partitions: true,
      skipLocked: true,
      onlineIndex: false, // Standard edition has no online index builds
      txDdl: true,
      bulkLoad: true,
      dbClock: true,
    },
    types: true,
    quote,
    placeholder: n => `@p${n}`,
    bind,
    json: placeholder => placeholder,
    returning: 'output',
    sortKeys: true,
    clock: () => tagged([`DATEDIFF_BIG(millisecond, '1970-01-01', SYSUTCDATETIME())`]),
    limit,
    orderTerm,
    locks: {
      share: { hint: 'WITH (HOLDLOCK, ROWLOCK)', tail: '' },
      claim: { hint: 'WITH (UPDLOCK, READPAST, ROWLOCK)', tail: '' },
    },
    insertIgnore: ({ table, columns, rows, options, insert }) =>
      insert(table, columns, rows, options),
    upsert,
    classify,
    catalog: catalog(schema),
    ddl: ddl(schema),
  });
}

export const mssql = createMssqlDialect();
