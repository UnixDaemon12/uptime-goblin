// The one way Uptime Goblin code builds SQL (roadmap §10.4). A statement is a `Query`: trusted text parts
// written in source code, plus values that are bound as parameters, identifiers quoted by the
// dialect, and dialect fragments. Nothing here knows an engine; `dialect.render(query)` turns a
// Query into `{text, params}` for SQLite, PostgreSQL or SQL Server.
//
//   import { sql, id } from '../db/sql.mjs';
//   const q = sql`SELECT ${id('value')} FROM ${id('meta')} WHERE ${id('key')} = ${name}`;
//   const { text, params } = dialect.render(q); // SQLite: SELECT "value" FROM "meta" WHERE "key" = ?
//
// Rules that `scripts/sql-lint.mjs` enforces around this module:
// - SQL text is written only inside sql`…` templates (and the dialect helpers); values are never
//   spliced into text, identifiers only arrive through id(), and portable helpers replace
//   engine-specific syntax (limit, ORDER BY with NULL ordering, RETURNING, upsert, the clock).
// - The values bound here follow the conformance rules shared by every engine: NaN and ±Infinity
//   become NULL, −0 becomes 0, BigInts must fit in 64 bits, and a statement binds at most 2,000
//   parameters.

/** Error classes a dialect's classify() returns (§10.4). Only `retry` is retried inside a unit. */
export const ERROR_CLASSES = Object.freeze([
  'retry',
  'unique',
  'fenced',
  'full',
  'unavailable',
  'timeout',
  'poison',
  'fatal',
]);

/** Most parameters one statement may bind on any engine (SQL Server's hard limit is 2,100). */
export const MAX_PARAMS = 2000;

/**
 * An error raised while building, rendering or binding a statement. `class` is one of
 * ERROR_CLASSES: `poison` for a value no engine may store (the row is rejected, the batch is
 * split), `fatal` for a programming error (a bad identifier, too many parameters).
 */
export class SqlError extends Error {
  constructor(errorClass, message, details) {
    super(message);
    this.name = 'SqlError';
    this.code = 'GOBLIN_SQL';
    this.class = ERROR_CLASSES.includes(errorClass) ? errorClass : 'fatal';
    if (details) this.details = details;
  }
}

// Identifiers are lower case so that every engine, including SQL Server with a binary (_BIN2)
// database collation, resolves them the same way; 63 characters is PostgreSQL's limit.
const identifierPattern = /^[a-z_][a-z0-9_]{0,62}$/;

// The classes below are exported for `instanceof` checks, so any module holding one of their
// values can reach its constructor (`sql``.constructor`, `id('a').constructor`). Only this module
// may construct them: each constructor needs this module-private token, so text built at run time
// cannot become a Query, an Identifier that skipped id()'s check, or a Directive the dialect
// writes out verbatim.
const issued = Symbol('lib/db/sql.mjs');
function mustBeIssued(token, what) {
  if (token !== issued)
    throw new SqlError(
      'fatal',
      `${what} values are built by sql\`…\`, id() and the dialect helpers, never constructed`
    );
}

/** A table or column name, quoted by the dialect at render time. Create it with id(). */
export class Identifier {
  /** @internal Use id(). */
  constructor(token, parts) {
    mustBeIssued(token, 'Identifier');
    this.parts = Object.freeze(parts);
    Object.freeze(this);
  }
  /** The name the registry must know: a column's own name, or the table's name. */
  get name() {
    return this.parts[this.parts.length - 1];
  }
}

/**
 * A fragment only a dialect can write (placeholders it numbers itself, a lock hint, a limit).
 * Dialect helpers create these with directive(); application code never does. `emit(state)`
 * returns the text and may bind values through `state.bind(value)`.
 */
export class Directive {
  /** @internal Use directive(). */
  constructor(token, dialect, kind, emit) {
    mustBeIssued(token, 'Directive');
    this.dialect = dialect;
    this.kind = kind;
    this.emit = emit;
    Object.freeze(this);
  }
}

/**
 * @internal For lib/db/dialect/* only (scripts/sql-lint.mjs refuses it elsewhere): a Directive of
 * `dialect`. Its text is written verbatim when that dialect renders it, so it always names its
 * dialect (another one refuses to render it) and is written by code, never from data.
 */
export function directive(dialect, kind, emit) {
  if (typeof dialect !== 'string' || !dialect)
    throw new SqlError('fatal', 'directive(): a directive belongs to a dialect');
  if (typeof kind !== 'string' || typeof emit !== 'function')
    throw new SqlError('fatal', 'directive(): needs a kind and an emit function');
  return new Directive(issued, dialect, kind, emit);
}

/** A JSON document bound as one parameter (text in SQLite and SQL Server, jsonb in PostgreSQL). */
export class JsonValue {
  constructor(value) {
    const text = JSON.stringify(value, (key, item) =>
      typeof item === 'bigint' ? item.toString() : item
    );
    if (text === undefined) throw new SqlError('poison', 'sql.json(): the value is not JSON');
    this.text = text;
    Object.freeze(this);
  }
}

// What the engine makes for a tagged template literal (ECMA-262 GetTemplateObject): a frozen
// array of strings whose `raw` is a frozen array of the same length, held in a read-only,
// non-enumerable, non-configurable property. A run-time array dressed up with Object.freeze()
// and Object.assign() fails this. No shape check can tell a carefully forged object from a
// literal, so scripts/sql-lint.mjs also refuses every use of `sql` other than as a tag.
function isTemplate(strings) {
  if (!Array.isArray(strings) || !Object.isFrozen(strings)) return false;
  const raw = Object.getOwnPropertyDescriptor(strings, 'raw');
  return (
    raw !== undefined &&
    !raw.enumerable &&
    !raw.writable &&
    !raw.configurable &&
    Array.isArray(raw.value) &&
    Object.isFrozen(raw.value) &&
    raw.value.length === strings.length &&
    strings.every(part => typeof part === 'string')
  );
}

function checkValue(value, index) {
  if (value === undefined)
    throw new SqlError('fatal', `sql: value ${index + 1} is undefined; bind null for NULL`);
  if (typeof value === 'function' || typeof value === 'symbol')
    throw new SqlError('fatal', `sql: value ${index + 1} is a ${typeof value}`);
}

/** An immutable statement or fragment. Build it with sql`…`; render it with a dialect. */
export class Query {
  /** @internal Use sql`…` or a dialect helper. */
  constructor(token, strings, values, dialect = null) {
    mustBeIssued(token, 'Query');
    if (strings.length !== values.length + 1)
      throw new SqlError('fatal', 'sql: a query needs one more text part than values');
    this.strings = Object.freeze([...strings]);
    this.values = Object.freeze([...values]);
    this.dialect = dialect;
    Object.freeze(this);
  }
  /** True when the query has no text and no values. */
  get isEmpty() {
    return this.values.length === 0 && this.strings[0] === '';
  }
}

// Joins text parts and values, splicing nested queries in place. A query built from one
// dialect's helpers carries that dialect's name, and mixing two dialects is refused.
function compose(strings, values) {
  const parts = [strings[0]],
    flat = [];
  let dialect = null;
  const adopt = name => {
    if (!name) return;
    if (dialect && dialect !== name)
      throw new SqlError('fatal', `sql: a ${dialect} fragment cannot be combined with ${name}`);
    dialect = name;
  };
  values.forEach((value, index) => {
    checkValue(value, index);
    if (value instanceof Query) {
      adopt(value.dialect);
      parts[parts.length - 1] += value.strings[0];
      for (let i = 0; i < value.values.length; i += 1) {
        flat.push(value.values[i]);
        parts.push(value.strings[i + 1]);
      }
      parts[parts.length - 1] += strings[index + 1];
      return;
    }
    if (value instanceof Directive) adopt(value.dialect);
    flat.push(value);
    parts.push(strings[index + 1]);
  });
  return new Query(issued, parts, flat, dialect);
}

/**
 * @internal For lib/db/dialect/* only (scripts/sql-lint.mjs refuses it elsewhere): a fragment of
 * engine-specific text, tagged with its dialect so another dialect refuses to render it.
 */
export function fragment(strings, values, dialect) {
  // Its text is written as given, so it always names the dialect that wrote it.
  if (typeof dialect !== 'string' || !dialect)
    throw new SqlError('fatal', 'fragment(): a fragment belongs to a dialect');
  if (!Array.isArray(strings) || !strings.every(part => typeof part === 'string'))
    throw new SqlError('fatal', 'fragment(): text parts are strings');
  const query = compose(strings, values ?? []);
  if (query.dialect && query.dialect !== dialect)
    throw new SqlError(
      'fatal',
      `sql: a ${query.dialect} fragment cannot be combined with ${dialect}`
    );
  return new Query(issued, query.strings, query.values, dialect);
}

/**
 * The SQL template tag. Interpolated values become bound parameters, except a Query (spliced in),
 * an id() (quoted) and a sql.json() document. Only a template literal is accepted (isTemplate()),
 * and scripts/sql-lint.mjs refuses any use of `sql` but as a tag, so a string built at run time
 * never becomes SQL text.
 */
export function sql(strings, ...values) {
  if (!isTemplate(strings))
    throw new SqlError('fatal', 'sql must be used as a template tag: sql`SELECT …`');
  return compose(strings, values);
}

/**
 * A quoted identifier. `id('meta')` is a table or column; `id('l', 'service')` is a column
 * qualified by a table alias (only the last part is checked against the registry).
 */
export function id(...parts) {
  if (!parts.length) throw new SqlError('fatal', 'id() needs a name');
  for (const part of parts)
    if (typeof part !== 'string' || !identifierPattern.test(part))
      throw new SqlError(
        'fatal',
        `id(): ${JSON.stringify(part)} is not a valid identifier (lower case letters, digits and _; at most 63)`
      );
  return new Identifier(issued, parts);
}

/** True for a name id() accepts. */
export const isIdentifier = name => typeof name === 'string' && identifierPattern.test(name);

/** `"a", "b", "c"`: a column list. Names are strings or id() values. */
export function ids(names) {
  if (!Array.isArray(names) || !names.length) throw new SqlError('fatal', 'ids() needs names');
  return join(names.map(name => (name instanceof Identifier ? name : id(name))));
}

/** Joins fragments or values with a separator fragment (default `, `). */
export function join(items, separator = sql`, `) {
  if (!Array.isArray(items)) throw new SqlError('fatal', 'join() needs an array');
  if (!(separator instanceof Query)) throw new SqlError('fatal', 'join(): separator is not sql');
  const strings = [''],
    values = [];
  items.forEach((item, index) => {
    if (index) {
      values.push(separator);
      strings.push('');
    }
    values.push(item);
    strings.push('');
  });
  return compose(strings, values);
}

/** `(?, ?, ?)` for `IN` lists and row constructors. An empty list is refused (`IN ()` is invalid). */
export function list(values) {
  if (!Array.isArray(values) || !values.length)
    throw new SqlError('fatal', 'list() needs at least one value');
  return sql`(${join(values)})`;
}

/** A JSON document parameter. Compare stored JSON by parsed value, never by bytes. */
export const json = value => new JsonValue(value);

/** The empty fragment, for optional clauses. */
export const empty = sql``;

sql.id = id;
sql.ids = ids;
sql.join = join;
sql.list = list;
sql.json = json;
sql.empty = empty;

// ---------------------------------------------------------------------------------------------
// Value conformance (§10.4 "Text rules" and "Floats"). These run the same way on every engine,
// so SQLite behaves like the servers that will follow it.

/** NaN and ±Infinity become null (absent) and −0 becomes 0; other values are returned as is. */
export function canonicalFloat(value) {
  if (typeof value !== 'number') return value;
  if (!Number.isFinite(value)) return null;
  return Object.is(value, -0) ? 0 : value;
}

const INT64_MIN = -(2n ** 63n),
  INT64_MAX = 2n ** 63n - 1n;

/** Checks a BigInt parameter fits a 64-bit integer column. */
export function checkBigint(value) {
  if (value < INT64_MIN || value > INT64_MAX)
    throw new SqlError('poison', `the integer ${value} does not fit in 64 bits`);
  return value;
}

/**
 * A BIGINT read from a driver (PostgreSQL and tedious return strings, node:sqlite may return a
 * BigInt) as a Number, refusing anything that is not a safe integer. `null` stays null.
 */
export function toSafeNumber(value) {
  if (value === null || value === undefined) return null;
  let number;
  if (typeof value === 'number') number = value;
  else if (typeof value === 'bigint') number = Number(value);
  else if (typeof value === 'string' && /^-?\d{1,20}$/.test(value)) number = Number(value);
  else throw new SqlError('poison', `expected an integer, got ${typeof value}`);
  if (
    !Number.isSafeInteger(number) ||
    (typeof value !== 'number' && BigInt(number) !== BigInt(value))
  )
    throw new SqlError('poison', `the integer ${value} is outside the safe range`);
  return number;
}

/**
 * A SQL Server `rowversion` read from tedious (an 8-byte Buffer, big-endian) as an unsigned
 * BigInt, for ordered-log cursors (1.9). It can exceed 2^53, so it never becomes a Number.
 */
export function fromRowversion(value) {
  if (!(value instanceof Uint8Array) || value.length !== 8)
    throw new SqlError('poison', 'a rowversion is exactly 8 bytes');
  let result = 0n;
  for (const byte of value) result = (result << 8n) | BigInt(byte);
  return result;
}

/** UTF-8 length in bytes. */
export const utf8Bytes = text => Buffer.byteLength(text, 'utf8');

const loneSurrogate = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** Number of Unicode code points (what `text(n)` counts). */
export function codePoints(text) {
  let count = 0;
  for (const _ of text) count += 1;
  return count;
}

/**
 * Why `value` cannot be stored in a `text(max)` column, or null. Text must be a string of at most
 * `max` code points (so at most 4 × max UTF-8 bytes: SQL Server stores text(n) as varchar(4n)),
 * without NUL (PostgreSQL rejects it) or unpaired surrogates (not encodable as UTF-8).
 */
export function textProblem(value, max) {
  if (typeof value !== 'string') return 'is not text';
  if (value.includes('\0')) return 'contains a NUL character';
  if (loneSurrogate.test(value)) return 'contains an unpaired surrogate';
  if (max !== undefined && value.length > max && codePoints(value) > max)
    return `is longer than ${max} characters`;
  return null;
}

/**
 * Key text (ids, names used in keys and unique indexes). Besides textProblem(), trailing spaces
 * are refused: SQL Server compares 'a' and 'a ' as equal even under a binary collation, so such
 * keys would collide there but not in SQLite or PostgreSQL. APIs normalise with
 * normalizeKeyText() before storing. Returns the value; throws SqlError('poison').
 */
export function keyText(value, max) {
  const problem = textProblem(value, max) ?? (/ $/.test(value) ? 'ends with a space' : null);
  if (problem) throw new SqlError('poison', `key text ${problem}`);
  return value;
}

/** What an API does to key text before it reaches the database: trailing spaces removed. */
export const normalizeKeyText = value => value.replace(/ +$/, '');

/** Splits rows so each statement binds at most `maxParams` values (`columns` per row). */
export function chunkRows(rows, columns, maxParams = MAX_PARAMS) {
  if (!Number.isInteger(columns) || columns < 1 || columns > maxParams)
    throw new SqlError('fatal', `chunkRows(): ${columns} columns cannot fit ${maxParams} params`);
  const size = Math.floor(maxParams / columns),
    chunks = [];
  for (let start = 0; start < rows.length; start += size)
    chunks.push(rows.slice(start, start + size));
  return chunks;
}
