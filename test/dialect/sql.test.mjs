// The sql template tag and the value rules every engine shares (lib/db/sql.mjs, roadmap §10.4).
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  sql,
  id,
  ids,
  join,
  list,
  json,
  empty,
  Query,
  Identifier,
  Directive,
  directive,
  JsonValue,
  SqlError,
  ERROR_CLASSES,
  MAX_PARAMS,
  canonicalFloat,
  checkBigint,
  toSafeNumber,
  fromRowversion,
  textProblem,
  keyText,
  normalizeKeyText,
  codePoints,
  utf8Bytes,
  chunkRows,
  fragment,
} from '../../lib/db/sql.mjs';

const fails = (fn, errorClass, pattern) =>
  assert.throws(fn, error => {
    assert.ok(error instanceof SqlError, `expected SqlError, got ${error}`);
    assert.equal(error.class, errorClass);
    assert.equal(error.code, 'GOBLIN_SQL');
    if (pattern) assert.match(error.message, pattern);
    return true;
  });

test('sql`…` keeps text and values apart and splices nested queries', () => {
  const where = sql`${id('service')} = ${'a'} AND ${id('time')} > ${5}`;
  const query = sql`SELECT ${id('value')} FROM ${id('readings')} WHERE ${where}`;
  assert.ok(query instanceof Query);
  assert.ok(
    Object.isFrozen(query) && Object.isFrozen(query.strings) && Object.isFrozen(query.values)
  );
  assert.deepEqual(query.strings, ['SELECT ', ' FROM ', ' WHERE ', ' = ', ' AND ', ' > ', '']);
  assert.equal(query.values.length, 6);
  assert.ok(query.values[0] instanceof Identifier);
  assert.deepEqual(query.values[3], 'a');
  assert.equal(query.values[5], 5);
  assert.equal(query.dialect, null, 'a portable query has no dialect');
  assert.ok(empty.isEmpty && sql``.isEmpty && !sql`x`.isEmpty);
});

test('sql refuses anything but a real template literal, and undefined values', () => {
  fails(() => sql(['SELECT 1']), 'fatal', /template tag/);
  // Arrays built at run time and dressed as a template literal: frozen, with raw (enumerable,
  // not frozen, or of another length), or with a part that is not a string.
  const text = "SELECT * FROM meta WHERE key = 'x' OR '1'='1'";
  const forgeries = [
    Object.freeze(Object.assign([text], { raw: [text] })),
    Object.freeze(Object.assign([text], { raw: Object.freeze([text]) })),
    Object.freeze(Object.defineProperty([text], 'raw', { value: [text] })),
    Object.freeze(Object.defineProperty([text], 'raw', { value: Object.freeze([text, '']) })),
    Object.freeze(Object.defineProperty([1], 'raw', { value: Object.freeze(['1']) })),
  ];
  for (const forged of forgeries) fails(() => sql(forged), 'fatal', /template tag/);
  // Template literals of any shape pass, including a nested and a value-only one.
  assert.ok(sql`${1}` instanceof Query && sql`` instanceof Query);
  // The lint refuses every other use of sql (scripts/sql-lint.mjs): a carefully forged object
  // (all properties as the engine makes them) cannot be told from a literal at run time.
  fails(() => sql`SELECT ${undefined}`, 'fatal', /undefined; bind null/);
  fails(() => sql`SELECT ${() => 1}`, 'fatal', /function/);
  fails(() => sql`SELECT ${Symbol('x')}`, 'fatal', /symbol/);
});

test('a Query, Identifier or Directive cannot be constructed outside sql`…`, id() and the dialect helpers', () => {
  const text = 'DELETE FROM "meta"';
  // Every way a module holding a value reaches the classes: the export, .constructor and the
  // prototype. Each refuses to construct, whatever arguments it is given.
  const Q = sql``.constructor,
    I = id('meta').constructor,
    D = directive('sqlite', 'limit', () => '').constructor;
  assert.equal(Q, Query);
  assert.equal(Object.getPrototypeOf(sql``).constructor, Query);
  for (const attempt of [
    () => new Query([text], []),
    () => new Q([text], []),
    () => new Q(Symbol('lib/db/sql.mjs'), [text], []),
    () => new I(['password']),
    () => new Identifier(['x"; DROP TABLE "meta" --']),
    () => new D('sqlite', 'x', () => text),
    () => new Directive(null, 'x', () => text),
  ])
    fails(attempt, 'fatal', /never constructed/);
  // A directive always belongs to a dialect, so another dialect (or none) never writes its text.
  fails(() => directive(null, 'x', () => text), 'fatal', /belongs to a dialect/);
  fails(() => directive('', 'x', () => text), 'fatal', /belongs to a dialect/);
  fails(() => directive('sqlite', 'x', text), 'fatal', /emit function/);
  fails(() => fragment([text], [], null), 'fatal', /belongs to a dialect/);
  fails(() => fragment([1], [], 'sqlite'), 'fatal', /text parts are strings/);
  assert.ok(directive('sqlite', 'limit', () => '') instanceof Directive);
});

test('id() accepts lower-case names only, and qualified alias.column', () => {
  assert.deepEqual(id('meta').parts, ['meta']);
  assert.deepEqual(id('l', 'service').parts, ['l', 'service']);
  assert.equal(id('l', 'service').name, 'service');
  for (const bad of ['', 'Meta', 'a-b', 'a b', '1a', 'x'.repeat(64), 'a"b', 'a;drop', null, 7])
    fails(() => id(bad), 'fatal', /not a valid identifier/);
  fails(() => id(), 'fatal');
  assert.equal(ids(['a', id('b')]).values.length, 2);
  fails(() => ids([]), 'fatal');
});

test('join and list build comma lists; an empty IN list is refused', () => {
  const joined = join([1, 2, 3]);
  assert.deepEqual(joined.strings, ['', ', ', ', ', '']);
  assert.deepEqual(joined.values, [1, 2, 3]);
  assert.deepEqual(join([1, 2], sql` OR `).strings, ['', ' OR ', '']);
  assert.deepEqual(list(['a']).strings, ['(', ')']);
  fails(() => list([]), 'fatal', /at least one/);
  fails(() => join('ab'), 'fatal');
  fails(() => join([1], ', '), 'fatal', /separator/);
  assert.deepEqual(join([]).strings, ['']);
});

test('fragments of two dialects cannot be combined', () => {
  const a = fragment(['LIMIT 1'], [], 'sqlite');
  const b = fragment(['OFFSET 0 ROWS'], [], 'mssql');
  assert.equal(sql`SELECT 1 ${a}`.dialect, 'sqlite');
  fails(() => sql`SELECT 1 ${a} ${b}`, 'fatal', /cannot be combined/);
  fails(() => fragment(['x ', ''], [a], 'mssql'), 'fatal', /cannot be combined/);
});

test('sql.json binds one canonical JSON text; functions and undefined are refused', () => {
  const value = json({ b: 1, a: [1, 2n], n: NaN });
  assert.ok(value instanceof JsonValue);
  assert.equal(value.text, '{"b":1,"a":[1,"2"],"n":null}');
  fails(() => json(undefined), 'poison');
  fails(() => json(() => 1), 'poison');
  assert.equal(sql.json, json);
});

test('floats are canonical everywhere: NaN and ±Infinity are absent, −0 is 0', () => {
  assert.equal(canonicalFloat(NaN), null);
  assert.equal(canonicalFloat(Infinity), null);
  assert.equal(canonicalFloat(-Infinity), null);
  assert.ok(Object.is(canonicalFloat(-0), 0));
  assert.equal(canonicalFloat(1.5), 1.5);
  assert.equal(canonicalFloat('x'), 'x');
});

test('BIGINTs are range-checked in both directions', () => {
  assert.equal(checkBigint(2n ** 63n - 1n), 2n ** 63n - 1n);
  assert.equal(checkBigint(-(2n ** 63n)), -(2n ** 63n));
  fails(() => checkBigint(2n ** 63n), 'poison', /64 bits/);
  fails(() => checkBigint(-(2n ** 63n) - 1n), 'poison');
  // Drivers return BIGINT as strings (postgres, tedious) or BigInt (node:sqlite readBigInts).
  assert.equal(toSafeNumber('9007199254740991'), Number.MAX_SAFE_INTEGER);
  assert.equal(toSafeNumber(-12n), -12);
  assert.equal(toSafeNumber(42), 42);
  assert.equal(toSafeNumber(null), null);
  assert.equal(toSafeNumber(undefined), null);
  for (const bad of ['9007199254740993', 9007199254740993n, 1.5, '1e3', 'abc', {}, NaN])
    fails(() => toSafeNumber(bad), 'poison');
});

test('SQL Server rowversions become unsigned BigInts; anything but 8 bytes is refused', () => {
  assert.equal(fromRowversion(Buffer.from('00000000000007d1', 'hex')), 2001n);
  assert.equal(fromRowversion(new Uint8Array(8).fill(0xff)), 2n ** 64n - 1n, 'beyond 2^53');
  assert.equal(fromRowversion(new Uint8Array(8)), 0n);
  const a = fromRowversion(Buffer.from('0000000000010000', 'hex'));
  const b = fromRowversion(Buffer.from('00000000000000ff', 'hex'));
  assert.ok(a > b, 'byte order is big-endian, as SQL Server compares them');
  for (const bad of [Buffer.alloc(7), Buffer.alloc(9), '0x01', 12, null, [0, 0, 0, 0, 0, 0, 0, 1]])
    fails(() => fromRowversion(bad), 'poison', /8 bytes/);
});

test('text(n) counts code points, refuses NUL and unpaired surrogates', () => {
  assert.equal(codePoints('a😀b'), 3);
  assert.equal(utf8Bytes('a😀b'), 6);
  assert.equal(textProblem('a😀b', 3), null);
  assert.equal(textProblem('a😀bc', 3), 'is longer than 3 characters');
  assert.equal(textProblem('a\0b', 10), 'contains a NUL character');
  assert.equal(textProblem('a\uD800b', 10), 'contains an unpaired surrogate');
  assert.equal(textProblem('\uDC00', 10), 'contains an unpaired surrogate');
  assert.equal(textProblem(5, 10), 'is not text');
  assert.equal(textProblem('x'.repeat(5000)), null, 'unbounded text');
});

test('key text refuses trailing spaces (SQL Server pads them); APIs normalise first', () => {
  assert.equal(keyText('web-1', 64), 'web-1');
  fails(() => keyText('web-1 ', 64), 'poison', /ends with a space/);
  fails(() => keyText('x'.repeat(65), 64), 'poison', /longer than 64/);
  fails(() => keyText('a\0', 64), 'poison', /NUL/);
  assert.equal(keyText(' leading', 64), ' leading', 'only trailing spaces compare equal');
  assert.equal(normalizeKeyText('web-1   '), 'web-1');
  assert.equal(normalizeKeyText('web-1\t'), 'web-1\t', 'tabs are not padding');
});

test('chunkRows keeps each statement within the parameter limit', () => {
  assert.equal(MAX_PARAMS, 2000);
  const rows = Array.from({ length: 1001 }, (_, i) => [i, i]);
  const chunks = chunkRows(rows, 2);
  assert.deepEqual(
    chunks.map(chunk => chunk.length),
    [1000, 1]
  );
  assert.deepEqual(chunkRows(rows, 3, 9).at(-1), [
    [999, 999],
    [1000, 1000],
  ]);
  assert.deepEqual(chunkRows([], 2), []);
  fails(() => chunkRows(rows, 0), 'fatal');
  fails(() => chunkRows(rows, 2001), 'fatal');
});

test('the error classes are the eight of §10.4', () => {
  assert.deepEqual(ERROR_CLASSES, [
    'retry',
    'unique',
    'fenced',
    'full',
    'unavailable',
    'timeout',
    'poison',
    'fatal',
  ]);
  assert.equal(new SqlError('nonsense', 'x').class, 'fatal');
  assert.deepEqual(new SqlError('poison', 'x', { row: 3 }).details, { row: 3 });
});
