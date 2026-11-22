// The portable schema DSL (lib/db/dialect/schema.mjs): validation rules, and SQLite DDL that
// really runs and enforces the same limits the server engines will.
import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import {
  table,
  id,
  text,
  bigint,
  double,
  bool,
  bytes,
  json,
  renderTable,
  renderSchema,
  requiredDialects,
  identifiersOf,
  KEY_BYTES,
  MAX_TEXT,
  CLASSES,
  MODES,
} from '../../lib/db/dialect/schema.mjs';
import { sqlite } from '../../lib/db/dialect/sqlite.mjs';
import { loadDialect } from '../../lib/db/dialect/index.mjs';
import { referenceTables } from './fixtures/reference-schema.mjs';

const invalid = (options, pattern, name = 't') =>
  assert.throws(
    () => table(name, options),
    error => error.class === 'fatal' && pattern.test(error.message)
  );

test('types, nullability, defaults and key markers', () => {
  assert.equal(text(10).max, 10);
  assert.equal(text().max, null);
  assert.equal(bigint().isNullable, false);
  assert.equal(bigint().nullable().isNullable, true);
  assert.equal(bool().default(false).defaultValue, false);
  assert.equal(text(5).asKey().isKey, true);
  assert.ok(Object.isFrozen(double()));
  assert.throws(() => text(0), /n is 1 to 2000/);
  assert.throws(() => text(MAX_TEXT + 1), /n is 1 to 2000/);
  assert.throws(() => bigint().default({}), /a default must be/);
  assert.deepEqual(CLASSES, ['control', 'state', 'series']);
  assert.deepEqual(MODES, ['single', 'cluster']);
  assert.deepEqual(KEY_BYTES, { clustered: 900, nonclustered: 1700 });
});

test('a table is validated when it is declared', () => {
  const columns = { a: text(10), b: bigint() };
  invalid({ columns, primaryKey: ['a'] }, /class must be one of/);
  invalid({ class: 'control', columns, primaryKey: ['a'], modes: [] }, /modes/);
  invalid({ class: 'control', columns, primaryKey: ['a'], modes: ['ha'] }, /modes/);
  invalid({ class: 'control', columns: {}, primaryKey: ['a'] }, /needs columns/);
  invalid(
    { class: 'control', columns: { A: bigint() }, primaryKey: ['A'] },
    /not a valid identifier/
  );
  invalid({ class: 'control', columns: { a: 'text' }, primaryKey: ['a'] }, /needs a DSL type/);
  invalid({ class: 'control', columns }, /needs a primary key/);
  invalid({ class: 'control', columns, primaryKey: ['z'] }, /unknown column z/);
  invalid(
    { class: 'control', columns: { a: text(10).nullable() }, primaryKey: ['a'] },
    /cannot be nullable/
  );
  invalid({ class: 'control', columns: { a: id(), b: id() } }, /at most one id/);
  invalid(
    { class: 'control', columns: { a: id(), b: bigint() }, primaryKey: ['a', 'b'] },
    /whole primary key/
  );
  invalid(
    { class: 'control', columns: { a: json() }, primaryKey: ['a'] },
    /cannot be part of a key/
  );
  invalid(
    { class: 'control', columns: { a: text() }, primaryKey: ['a'] },
    /cannot be part of a key/
  );
  // SQL Server key limits, counted as 4 bytes per character (varchar(4n) under UTF-8).
  invalid(
    { class: 'control', columns: { a: text(226) }, primaryKey: ['a'] },
    /may need 904 bytes; SQL Server allows 900/
  );
  assert.ok(table('t', { class: 'control', columns: { a: text(225) }, primaryKey: ['a'] }));
  invalid(
    {
      class: 'control',
      columns: { a: bigint(), b: text(500) },
      primaryKey: ['a'],
      indexes: [{ columns: ['b'] }],
    },
    /1700/
  );
  invalid(
    { class: 'control', columns, primaryKey: ['a'], indexes: [{ columns: [['b', 'up']] }] },
    /direction/
  );
  invalid(
    { class: 'control', columns, primaryKey: ['a'], indexes: [{ columns: [] }] },
    /needs columns/
  );
  invalid(
    {
      class: 'control',
      columns,
      primaryKey: ['a'],
      indexes: [
        { name: 'x', columns: ['b'] },
        { name: 'x', columns: ['a'] },
      ],
    },
    /used twice/
  );
  invalid(
    {
      class: 'control',
      columns,
      primaryKey: ['a'],
      indexes: [{ columns: ['b'], where: [['b', 'like', 1]] }],
    },
    /operator/
  );
  invalid(
    {
      class: 'control',
      columns,
      primaryKey: ['a'],
      indexes: [{ columns: ['b'], where: [['b', '=']] }],
    },
    /literal value/
  );
  invalid(
    {
      class: 'control',
      columns,
      primaryKey: ['a'],
      indexes: [{ columns: ['b'], where: [['q', 'is null']] }],
    },
    /unknown column q/
  );
  invalid(
    { class: 'series', columns, primaryKey: ['a'], partition: { column: 'b', interval: 'day' } },
    /every key must include/
  );
  invalid(
    {
      class: 'series',
      columns,
      primaryKey: ['a', 'b'],
      partition: { column: 'a', interval: 'day' },
    },
    /must be a bigint/
  );
  invalid(
    {
      class: 'series',
      columns,
      primaryKey: ['a', 'b'],
      partition: { column: 'b', interval: 'week' },
    },
    /interval/
  );
  invalid({ class: 'control', columns: { a: id() }, withoutRowid: true }, /withoutRowid/);
  invalid({ class: 'control', columns, primaryKey: ['a'] }, /not a valid identifier/, 'Bad');
});

test('text in any key is compared in binary; declared tables are frozen', () => {
  const t = table('t', {
    class: 'control',
    columns: { a: text(10), b: text(10), c: text(10) },
    primaryKey: ['a'],
    indexes: [{ columns: ['b'] }],
  });
  assert.equal(t.columns.a.isKey, true);
  assert.equal(t.columns.b.isKey, true);
  assert.equal(t.columns.c.isKey, false);
  assert.ok(Object.isFrozen(t) && Object.isFrozen(t.columns) && Object.isFrozen(t.indexes));
  assert.equal(t.indexes[0].name, 't_b_idx');
  assert.deepEqual([...identifiersOf([t])].sort(), ['a', 'b', 'c', 't']);
});

test('steps need every dialect their table exists in (§10.5 lint)', () => {
  assert.deepEqual(requiredDialects(['single', 'cluster']), ['sqlite', 'postgres', 'mssql']);
  assert.deepEqual(requiredDialects(['single']), ['sqlite', 'postgres', 'mssql']);
  assert.deepEqual(requiredDialects(['cluster']), ['postgres', 'mssql']);
});

test('SQLite DDL runs and enforces types, lengths, booleans and JSON like the servers', () => {
  const db = new DatabaseSync(':memory:');
  try {
    const statements = referenceTables
      .filter(t => t.modes.includes('single'))
      .flatMap(t => renderTable(sqlite, t));
    for (const statement of statements) db.exec(statement);
    const insert = (values = {}) => {
      const row = {
        dedupe_key: 'd1',
        channel: 'mail',
        next_at: 1,
        payload: '{"a":1}',
        ...values,
      };
      const columns = Object.keys(row);
      db.prepare(
        `INSERT INTO ref_outbox (${columns.join(', ')}) VALUES (${columns.map(() => '?').join(', ')})`
      ).run(...Object.values(row));
    };
    insert();
    const row = db.prepare('SELECT * FROM ref_outbox').get();
    assert.equal(row.id, 1);
    assert.equal(row.state, 'pending');
    assert.equal(row.attempts, 0);
    assert.equal(row.enabled, 1);
    assert.throws(() => insert({ dedupe_key: 'd1' }), /UNIQUE/);
    assert.throws(() => insert({ dedupe_key: 'x'.repeat(129) }), /CHECK/);
    assert.doesNotThrow(
      () => insert({ dedupe_key: '😀'.repeat(128) }),
      'text(n) counts characters, not bytes'
    );
    assert.throws(() => insert({ dedupe_key: 'd2', payload: '{bad' }), /CHECK/);
    assert.throws(() => insert({ dedupe_key: 'd3', enabled: 2 }), /CHECK/);
    assert.throws(
      () => insert({ dedupe_key: 'd4', next_at: 'soon' }),
      /cannot store TEXT value in INTEGER/
    );
    assert.throws(() => insert({ dedupe_key: 'd5', next_at: null }), /NOT NULL/);
    // AUTOINCREMENT: a deleted highest id is never handed out again (the V1 regression class).
    insert({ dedupe_key: 'd6' });
    const last = db.prepare('SELECT MAX(id) AS id FROM ref_outbox').get().id;
    db.prepare('DELETE FROM ref_outbox WHERE id = ?').run(last);
    insert({ dedupe_key: 'd7' });
    assert.equal(db.prepare('SELECT MAX(id) AS id FROM ref_outbox').get().id, last + 1);
    const plan = db
      .prepare(
        "EXPLAIN QUERY PLAN SELECT id FROM ref_outbox WHERE state = 'pending' ORDER BY next_at DESC"
      )
      .all();
    assert.ok(
      plan.some(step => /ref_outbox_due/.test(step.detail)),
      'the partial index serves the due query'
    );
    const withoutRowid = db
      .prepare("SELECT sql FROM sqlite_master WHERE name = 'ref_rollup'")
      .get().sql;
    assert.match(withoutRowid, /STRICT, WITHOUT ROWID$/);
  } finally {
    db.close();
  }
});

test('cluster-only tables never exist in SQLite mode', async () => {
  const head = referenceTables.find(t => t.name === 'ref_head');
  assert.throws(() => renderTable(sqlite, head), /cluster-only and never exists in sqlite/);
  assert.doesNotMatch(renderSchema(sqlite, referenceTables), /ref_head/);
  const pg = await loadDialect('postgres');
  assert.match(renderSchema(pg, referenceTables), /CREATE TABLE "orbit"."ref_head"/);
  assert.throws(() => renderTable({ name: 'x' }, head), /no DDL rules/);
});
