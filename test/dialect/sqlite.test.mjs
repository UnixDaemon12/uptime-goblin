// The SQLite dialect (lib/db/dialect/sqlite.mjs): every helper's output runs on a real
// node:sqlite database, and classify() is checked against errors SQLite really raises.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { sql, id, list, json, SqlError, MAX_PARAMS, fragment } from '../../lib/db/sql.mjs';
import { createSqliteDialect, sqlite, SQLITE_CODES } from '../../lib/db/dialect/sqlite.mjs';
import { loadDialect, dialectFor, DIALECTS } from '../../lib/db/dialect/index.mjs';
import registry from '../../lib/db/registry.mjs';
import {
  table,
  text,
  bigint,
  double,
  bool,
  json as jsonType,
  id as idType,
  renderTable,
} from '../../lib/db/dialect/schema.mjs';

const d = createSqliteDialect({ clock: () => 1_700_000_000_000 });

function database(t) {
  const db = new DatabaseSync(':memory:');
  t.after(() => db.close());
  const items = table('items', {
    class: 'control',
    columns: {
      k: text(32),
      v: double().nullable(),
      n: bigint().default(0),
      flag: bool().default(false),
      doc: jsonType().nullable(),
      note: text().nullable(),
    },
    primaryKey: ['k'],
  });
  for (const statement of renderTable(d, items)) db.exec(statement);
  return db;
}
const run = (db, query) => {
  const { text: statement, params } = d.render(query);
  return db.prepare(statement).run(...params);
};
const all = (db, query) => {
  const { text: statement, params } = d.render(query);
  return db
    .prepare(statement)
    .all(...params)
    .map(row => ({ ...row }));
};

test('render uses ? placeholders, "quoted" identifiers and bound values', () => {
  const rendered = sqlite.render(
    sql`SELECT ${id('value')}, ${id('l', 'rule')} FROM ${id('meta')} l WHERE ${id('key')} IN ${list(['a', 'b'])} AND ${id('n')} = ${7}`
  );
  assert.deepEqual(rendered, {
    text: 'SELECT "value", "l"."rule" FROM "meta" l WHERE "key" IN (?, ?) AND "n" = ?',
    params: ['a', 'b', 7],
  });
  assert.equal(sqlite.name, 'sqlite');
  assert.equal(sqlite.executable, true);
  assert.equal(sqlite.caps.maxParams, MAX_PARAMS);
  assert.equal(sqlite.id('meta'), '"meta"');
  assert.equal(sqlite.id(id('l', 'rule')), '"l"."rule"');
});

test('values are canonical: NaN/±Infinity bind NULL, −0 binds 0, booleans bind 1/0', t => {
  const db = database(t);
  run(
    db,
    d.insert(
      'items',
      ['k', 'v', 'flag'],
      [
        ['nan', NaN, true],
        ['inf', -Infinity, false],
        ['zero', -0, true],
      ]
    )
  );
  const rows = all(
    db,
    sql`SELECT ${id('k')}, ${id('v')}, ${id('flag')} FROM ${id('items')} ${d.orderBy(['k', 'asc', 'not null'])}`
  );
  assert.deepEqual(rows, [
    { k: 'inf', v: null, flag: 0 },
    { k: 'nan', v: null, flag: 1 },
    { k: 'zero', v: 0, flag: 1 },
  ]);
  assert.ok(Object.is(rows[2].v, 0));
  assert.throws(() => d.render(sql`SELECT ${new Date()}`), /epoch milliseconds/);
  assert.throws(() => d.render(sql`SELECT ${{ a: 1 }}`), /sql.json/);
  assert.throws(
    () => d.render(sql`SELECT ${2n ** 64n}`),
    error => error.class === 'poison'
  );
  assert.deepEqual(d.render(sql`SELECT ${2n ** 62n}`).params, [2n ** 62n]);
  assert.equal(d.bindValue(true), 1);
  assert.equal(d.bindValue(NaN), null);
});

test('a string with a NUL or an unpaired surrogate is refused as poison at bind, never stored', t => {
  const db = database(t);
  const poison = (value, pattern) =>
    assert.throws(
      () => run(db, d.insert('items', ['k', 'note'], [['row', value]])),
      error =>
        error instanceof SqlError &&
        error.class === 'poison' &&
        pattern.test(error.message) &&
        // The refusal names the problem, never the value.
        !error.message.includes('SYNTHETIC')
    );
  // SQLite's length() stops at a NUL, so a text(32) CHECK let any amount through after one.
  poison('a\u0000' + 'SYNTHETIC'.repeat(2000), /NUL character/);
  // node:sqlite stored U+FFFD for each of these, so different keys became one row.
  for (const lone of ['SYNTHETIC\ud800', 'SYNTHETIC\udbff', '\udc00SYNTHETIC', 'a\ud800b'])
    poison(lone, /unpaired surrogate/);
  assert.throws(() => d.render(sql`SELECT ${'k\ud800'}`), /unpaired surrogate/);
  assert.throws(() => d.bindValue('a\u0000b'), /NUL character/);
  assert.deepEqual(all(db, sql`SELECT ${id('k')} FROM ${id('items')}`), []);
  // Well-formed text binds as given: pairs, U+FFFD itself, other control characters.
  run(db, d.insert('items', ['k', 'note'], [['pair', 'a😀b�\u0001']]));
  assert.deepEqual(all(db, sql`SELECT ${id('note')} FROM ${id('items')}`), [
    { note: 'a😀b�\u0001' },
  ]);
});

test('builders refuse a column the table does not have, RETURNING included', () => {
  const registered = createSqliteDialect({ identifiers: registry.identifiers });
  // A dialect hands out no sql function: every transaction holds a dialect, and the function
  // could be called with an array built at run time.
  assert.equal(registered.sql, undefined);
  assert.equal(sqlite.sql, undefined);
  const where = sql`${id('key')} = ${'k'}`;
  // Columns of another registered table: render() alone accepts any registered name.
  for (const build of [
    () => registered.insert('meta', ['key', 'value', 'login'], [['k', 'v', 'x']]),
    () => registered.insertIgnore('meta', ['key', 'login'], [['k', 'x']]),
    () => registered.upsert('meta', ['key'], ['key', 'password'], [['k', 'x']]),
    () => registered.update('meta', { password: 'x' }, where),
    () => registered.deleteFrom('meta', where, { returning: ['password'] }),
    () => registered.update('meta', { value: 'x' }, where, { returning: ['login'] }),
  ])
    assert.throws(build, /is not a column of meta/);
  // RETURNING goes through id(): an unregistered column is refused at render, as id() is.
  assert.throws(
    () => sqlite.render(sqlite.insert('t', ['a'], [[1]], { returning: ['a"; DROP'] })),
    /not a valid identifier/
  );
  assert.throws(
    () =>
      createSqliteDialect({ identifiers: new Set(['meta', 'key', 'value']) }).render(
        sql`UPDATE ${id('meta')} SET ${id('value')} = ${'x'} ${sqlite.returning(['not_registered_col'])}`
      ),
    /not_registered_col is not in the table registry/
  );
  // The table's own columns render as before.
  assert.equal(
    registered.render(
      registered.update('meta', { value: 'x' }, where, { returning: ['key', 'value'] })
    ).text,
    'UPDATE "meta" SET "value" = ? WHERE "key" = ? RETURNING "key", "value"'
  );
});

test('upsert inserts, updates by key, keeps the last duplicate and can return rows', t => {
  const db = database(t);
  run(db, d.upsert('items', ['k'], ['k', 'v', 'n'], [{ k: 'a', v: 1, n: 1 }]));
  const returned = all(
    db,
    d.upsert(
      'items',
      ['k'],
      ['k', 'v', 'n'],
      [
        { k: 'a', v: 2, n: 5 },
        { k: 'b', v: 3, n: 6 },
        { k: 'a', v: 4, n: 7 }, // the same key twice: the last row wins, before the database sees it
      ],
      { returning: ['k', 'n'] }
    )
  );
  assert.deepEqual(
    returned.sort((x, y) => (x.k < y.k ? -1 : 1)),
    [
      { k: 'a', n: 7 },
      { k: 'b', n: 6 },
    ]
  );
  // update: only the named columns change.
  run(db, d.upsert('items', ['k'], ['k', 'v', 'n'], [['a', 9, 100]], { update: ['v'] }));
  assert.deepEqual(
    all(db, sql`SELECT ${id('v')}, ${id('n')} FROM ${id('items')} WHERE ${id('k')} = ${'a'}`),
    [{ v: 9, n: 7 }]
  );
  // update: [] keeps existing rows (insert if absent).
  run(
    db,
    d.upsert(
      'items',
      ['k'],
      ['k', 'v'],
      [
        ['a', 0],
        ['c', 1],
      ],
      { update: [] }
    )
  );
  assert.deepEqual(
    all(
      db,
      sql`SELECT ${id('k')}, ${id('v')} FROM ${id('items')} ${d.orderBy(['k', 'asc', 'not null'])}`
    ),
    [
      { k: 'a', v: 9 },
      { k: 'b', v: 3 },
      { k: 'c', v: 1 },
    ]
  );
  assert.throws(
    () => d.upsert('items', ['k'], ['k', 'v'], [['a', 1]], { update: ['k'] }),
    /cannot update k/
  );
  assert.throws(() => d.upsert('items', ['x'], ['k'], [['a']]), /key column x/);
});

test('insertIgnore skips existing keys; insert, update and delete return rows', t => {
  const db = database(t);
  run(db, d.insert('items', ['k', 'n'], [['a', 1]]));
  const inserted = all(
    db,
    d.insertIgnore(
      'items',
      ['k', 'n'],
      [
        ['a', 2],
        ['b', 3],
      ],
      { returning: ['k'] }
    )
  );
  assert.deepEqual(inserted, [{ k: 'b' }]);
  assert.deepEqual(
    all(db, d.insertIgnore('items', ['k', 'n'], [['b', 9]], { conflict: ['k'], returning: ['k'] })),
    []
  );
  assert.deepEqual(all(db, d.insert('items', ['k', 'n'], { k: 'c', n: 4 }, { returning: ['n'] })), [
    { n: 4 },
  ]);
  assert.deepEqual(
    all(
      db,
      d.update('items', { n: sql`${id('n')} + ${10}`, v: 1.5 }, sql`${id('k')} = ${'c'}`, {
        returning: ['n', 'v'],
      })
    ),
    [{ n: 14, v: 1.5 }]
  );
  assert.deepEqual(
    all(db, d.deleteFrom('items', sql`${id('k')} IN ${list(['a', 'b'])}`, { returning: ['k'] }))
      .length,
    2
  );
  assert.throws(() => d.update('items', {}, sql`1 = 1`), /columns to set/);
  assert.throws(() => d.update('items', { n: 1 }, sql``), /WHERE/);
  assert.throws(() => d.deleteFrom('items', sql``), /WHERE/);
  assert.throws(() => d.insert('items', ['k', 'n'], [['a']]), /1 values for 2 columns/);
  assert.throws(() => d.insert('items', ['k', 'n'], [{ k: 'a' }]), /no value for n/);
  assert.throws(() => d.insert('items', ['k'], []), /at least one row/);
  assert.throws(() => d.insert('items', [], [[]]), /column list/);
});

test('orderBy states NULL ordering and limit binds its bounds', t => {
  const db = database(t);
  run(
    db,
    d.insert(
      'items',
      ['k', 'v'],
      [
        ['a', 2],
        ['b', null],
        ['c', 1],
        ['d', null],
      ]
    )
  );
  const keys = query =>
    all(db, query)
      .map(row => row.k)
      .join('');
  const base = order => sql`SELECT ${id('k')} FROM ${id('items')} ${order}`;
  assert.equal(keys(base(d.orderBy(['v', 'asc', 'last'], ['k', 'asc', 'not null']))), 'cabd');
  assert.equal(keys(base(d.orderBy(['v', 'asc', 'first'], ['k', 'asc', 'not null']))), 'bdca');
  assert.equal(keys(base(d.orderBy(['v', 'desc', 'last'], ['k', 'desc', 'not null']))), 'acdb');
  assert.equal(keys(base(d.orderBy(['v', 'desc', 'first'], ['k', 'desc', 'not null']))), 'dbac');
  assert.equal(keys(sql`${base(d.orderBy(['k', 'asc', 'not null']))} ${d.limit(2, 1)}`), 'bc');
  assert.equal(d.render(d.limit(5)).text, 'LIMIT ?');
  assert.deepEqual(d.render(sql`${d.orderBy([sql`${id('v')} * ${2}`, 'desc', 'last'])}`), {
    text: 'ORDER BY "v" * ? DESC NULLS LAST',
    params: [2],
  });
  for (const bad of [0, -1, 1.5, NaN, '3']) assert.throws(() => d.limit(bad), /positive integer/);
  assert.throws(() => d.limit(1, -1), /non-negative/);
  assert.throws(() => d.orderBy(['k', 'asc']), /\[column, direction, nulls\]/);
  assert.throws(() => d.orderBy(['k', 'up', 'last']), /direction/);
  assert.throws(() => d.orderBy(['k', 'asc', 'nowhere']), /nulls/);
  assert.throws(() => d.orderBy(), /at least one/);
});

test('the clock is the process clock, bound as a value; claims and fences need no lock text', t => {
  const db = database(t);
  run(db, d.insert('items', ['k', 'n'], [['a', 1]]));
  run(db, d.update('items', { n: d.clockMs() }, sql`${id('k')} = ${'a'}`));
  assert.deepEqual(all(db, sql`SELECT ${id('n')} FROM ${id('items')}`), [{ n: 1_700_000_000_000 }]);
  assert.equal(d.nowMs, d.clockMs);
  const before = Date.now();
  const [now] = sqlite.render(sqlite.clockMs()).params;
  assert.ok(now >= before && now <= Date.now());
  for (const lock of [d.claim(), d.forShare()]) {
    assert.deepEqual(d.render(sql`SELECT 1 FROM ${lock.table('items')}${lock.tail}`), {
      text: 'SELECT 1 FROM "items"',
      params: [],
    });
  }
  assert.equal(d.caps.dbClock, false);
  assert.equal(d.caps.cluster, false);
});

test('catalog queries list tables, columns and indexes, leaving out SQLite internals', t => {
  const db = database(t);
  const logs = table('logs', {
    class: 'control',
    columns: { id: idType(), at: bigint(), note: text(32).nullable() },
    indexes: [{ name: 'logs_at', columns: ['at'] }],
  });
  for (const statement of renderTable(d, logs)) db.exec(statement);
  run(db, d.insert('logs', ['at'], [[1]])); // AUTOINCREMENT creates sqlite_sequence
  db.exec('CREATE TABLE plain (x)'); // a table made outside the DSL is listed too
  assert.ok(all(db, sql`SELECT name FROM sqlite_master WHERE name = ${'sqlite_sequence'}`).length);

  assert.deepEqual(all(db, d.catalog.tables()), [
    { name: 'items' },
    { name: 'logs' },
    { name: 'plain' },
  ]);
  assert.deepEqual(all(db, d.catalog.tableExists('logs')), [{ present: 1 }]);
  assert.deepEqual(all(db, d.catalog.tableExists('nothing')), []);
  assert.deepEqual(all(db, d.catalog.tableExists('logs_at')), [], 'an index is not a table');
  assert.deepEqual(
    all(db, d.catalog.columns('items')).map(row => row.name),
    ['k', 'v', 'n', 'flag', 'doc', 'note'],
    'in column order'
  );
  assert.deepEqual(all(db, d.catalog.columns('nothing')), []);
  // The text primary key of items has an internal sqlite_autoindex_*; only named indexes show.
  assert.deepEqual(all(db, d.catalog.indexes()), [{ name: 'logs_at', table: 'logs' }]);
  assert.deepEqual(d.render(d.catalog.tableExists('x')).params, ['x'], 'names are bound');
  assert.throws(() => d.catalog.columns(''), /a table name/);
  assert.throws(() => d.catalog.tableExists(null), /a table name/);
});

test('with the registry, every id() must be registered', () => {
  const registered = createSqliteDialect({ identifiers: new Set(['meta', 'key', 'value']) });
  assert.equal(
    registered.render(
      sql`SELECT ${id('value')} FROM ${id('meta')} m WHERE ${id('m', 'key')} = ${1}`
    ).text,
    'SELECT "value" FROM "meta" m WHERE "m"."key" = ?'
  );
  assert.throws(
    () => registered.render(sql`SELECT ${id('secret')} FROM ${id('meta')}`),
    /secret is not in the table registry/
  );
  assert.equal(registered.id('meta'), '"meta"');
  assert.equal(registered.id(id('m', 'key')), '"m"."key"', 'an alias is not a registered name');
  assert.throws(() => registered.id('secret'), /secret is not in the table registry/);
  // A render option overrides the dialect's own list; functions and arrays work too.
  assert.throws(() => sqlite.render(sql`SELECT ${id('x')}`, { identifiers: ['y'] }), /x is not in/);
  assert.equal(
    sqlite.render(sql`SELECT ${id('x')}`, { identifiers: name => name === 'x' }).text,
    'SELECT "x"'
  );
  assert.throws(() => sqlite.render(sql`SELECT 1`, { identifiers: 5 }), /identifiers must be/);
});

test('a statement binds at most 2,000 parameters', () => {
  const values = Array.from({ length: MAX_PARAMS }, (_, i) => i);
  assert.equal(sqlite.render(sql`SELECT ${list(values)}`).params.length, MAX_PARAMS);
  assert.throws(
    () => sqlite.render(sql`SELECT ${list([...values, 1])}`),
    error =>
      error instanceof SqlError && error.class === 'fatal' && /2001 parameters/.test(error.message)
  );
});

test('fragments of another dialect are refused at render time', async () => {
  const mssql = await loadDialect('mssql');
  assert.throws(
    () => sqlite.render(sql`SELECT 1 ${mssql.limit(1)}`),
    /mssql fragment cannot be rendered as sqlite/
  );
  assert.throws(() => sqlite.render(fragment(['x'], [], 'postgres')), /postgres fragment/);
  assert.throws(() => sqlite.render('SELECT 1'), /needs a sql/);
});

test('json documents bind as text', t => {
  const db = database(t);
  run(db, d.insert('items', ['k', 'doc'], [['a', json({ x: [1, 2] })]]));
  assert.deepEqual(JSON.parse(all(db, sql`SELECT ${id('doc')} FROM ${id('items')}`)[0].doc), {
    x: [1, 2],
  });
});

// ---------------------------------------------------------------------------------------------
// classify() against real SQLite errors.

const errorOf = fn => {
  try {
    fn();
  } catch (error) {
    return error;
  }
  assert.fail('expected an error');
};

test('classify: constraint errors are unique or poison', t => {
  const db = database(t);
  run(db, d.insert('items', ['k'], [['a']]));
  const insert =
    (k, extra = {}) =>
    () => {
      const columns = ['k', ...Object.keys(extra)];
      const { text: statement, params } = d.render(d.insert('items', columns, [{ k, ...extra }]));
      db.prepare(statement).run(...params);
    };
  assert.equal(sqlite.classify(errorOf(insert('a'))), 'unique'); // PRIMARY KEY (1555)
  db.exec('CREATE UNIQUE INDEX items_n ON items (n) WHERE n > 100');
  run(db, d.insert('items', ['k', 'n'], [['u', 101]]));
  assert.equal(sqlite.classify(errorOf(insert('u2', { n: 101 }))), 'unique'); // UNIQUE (2067)
  assert.equal(sqlite.classify(errorOf(insert('b', { v: 'text' }))), 'poison'); // STRICT DATATYPE (3091)
  assert.equal(sqlite.classify(errorOf(insert('x'.repeat(33)))), 'poison'); // CHECK length (275)
  assert.equal(sqlite.classify(errorOf(insert('c', { flag: 2 }))), 'poison'); // CHECK bool
  assert.equal(sqlite.classify(errorOf(insert('d', { doc: '{not json' }))), 'poison'); // CHECK json_valid
  assert.equal(
    sqlite.classify(
      errorOf(() => db.prepare('INSERT INTO items (k, n) VALUES (?, NULL)').run('e'))
    ),
    'poison'
  ); // NOT NULL (1299)
  assert.equal(sqlite.classify(errorOf(() => db.prepare('SELEC 1'))), 'fatal');
  assert.equal(sqlite.classify(errorOf(() => db.prepare('SELECT * FROM missing'))), 'fatal');
});

test('classify: busy is retry, full is full, a non-database is fatal, read-only is fatal', t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-dialect-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const file = path.join(directory, 'busy.sqlite');
  const a = new DatabaseSync(file);
  const b = new DatabaseSync(file);
  t.after(() => {
    a.close();
    b.close();
  });
  a.exec('PRAGMA journal_mode=WAL; CREATE TABLE x (a INTEGER)');
  b.exec('PRAGMA busy_timeout=0');
  a.exec('BEGIN IMMEDIATE');
  const busy = errorOf(() => b.exec('BEGIN IMMEDIATE'));
  a.exec('ROLLBACK');
  assert.equal(busy.errcode & 0xff, 5);
  assert.equal(sqlite.classify(busy), 'retry');

  const small = new DatabaseSync(':memory:');
  t.after(() => small.close());
  small.exec('CREATE TABLE y (a TEXT); PRAGMA max_page_count=3');
  const full = errorOf(() => {
    for (let i = 0; i < 100; i += 1)
      small.prepare('INSERT INTO y VALUES (?)').run('x'.repeat(1000));
  });
  assert.equal(sqlite.classify(full), 'full');

  const garbage = path.join(directory, 'garbage.sqlite');
  fs.writeFileSync(garbage, 'not a database '.repeat(40));
  const notDb = errorOf(() => {
    const c = new DatabaseSync(garbage);
    try {
      c.prepare('SELECT * FROM sqlite_master').all();
    } finally {
      c.close();
    }
  });
  assert.equal(sqlite.classify(notDb), 'fatal');

  const readOnly = new DatabaseSync(file, { readOnly: true });
  t.after(() => readOnly.close());
  assert.equal(sqlite.classify(errorOf(() => readOnly.exec('INSERT INTO x VALUES (1)'))), 'fatal');

  const closed = new DatabaseSync(':memory:');
  closed.close();
  assert.equal(sqlite.classify(errorOf(() => closed.exec('SELECT 1'))), 'unavailable');
});

test('classify: node:sqlite value errors, aborts, disk-full and pre-classified errors', () => {
  const db = new DatabaseSync(':memory:');
  try {
    const unsafe = errorOf(() => db.prepare('SELECT 9007199254740993 AS v').get());
    assert.equal(unsafe.code, 'ERR_OUT_OF_RANGE');
    assert.equal(sqlite.classify(unsafe), 'poison');
    assert.equal(sqlite.classify(errorOf(() => db.prepare('SELECT ?').get(2n ** 70n))), 'poison');
    assert.equal(sqlite.classify(errorOf(() => db.prepare('SELECT ?').get(Symbol('x')))), 'fatal');
    assert.equal(sqlite.classify(errorOf(() => db.prepare('SELECT ?').get([1]))), 'fatal');
  } finally {
    db.close();
  }
  assert.equal(sqlite.classify(Object.assign(new Error('x'), { name: 'AbortError' })), 'timeout');
  assert.equal(sqlite.classify(new DOMException('late', 'TimeoutError')), 'timeout');
  assert.equal(sqlite.classify(Object.assign(new Error('x'), { code: 'ENOSPC' })), 'full');
  assert.equal(
    sqlite.classify(Object.assign(new Error('lease lost'), { class: 'fenced' })),
    'fenced'
  );
  assert.equal(sqlite.classify(new SqlError('poison', 'bad row')), 'poison');
  assert.equal(sqlite.classify(new TypeError('bug')), 'fatal');
  assert.equal(sqlite.classify(undefined), 'fatal');
  // The table maps extended codes first, then primary codes.
  const fake = errcode => Object.assign(new Error('x'), { code: 'ERR_SQLITE_ERROR', errcode });
  assert.equal(sqlite.classify(fake(517)), 'retry'); // BUSY_SNAPSHOT
  assert.equal(sqlite.classify(fake(6)), 'retry'); // LOCKED
  assert.equal(sqlite.classify(fake(9)), 'timeout'); // INTERRUPT
  assert.equal(sqlite.classify(fake(10 | (3 << 8))), 'unavailable'); // IOERR_WRITE
  assert.equal(sqlite.classify(fake(14)), 'unavailable'); // CANTOPEN
  assert.equal(sqlite.classify(fake(11)), 'fatal'); // CORRUPT
  assert.equal(sqlite.classify(fake(1032)), 'unavailable'); // READONLY_DBMOVED
  assert.equal(sqlite.classify(fake(999)), 'fatal');
  assert.equal(SQLITE_CODES.primary[13], 'full');
});

test('dialects are chosen by URL; server dialects load only on demand', async () => {
  assert.deepEqual(DIALECTS, ['sqlite', 'postgres', 'mssql']);
  assert.equal(dialectFor('/var/lib/uptime-goblin/control.sqlite'), 'sqlite');
  assert.equal(dialectFor('file:///var/lib/uptime-goblin/control.sqlite'), 'sqlite');
  assert.equal(dialectFor('postgres://orbit@db/orbit'), 'postgres');
  assert.equal(dialectFor('postgresql://orbit@db/orbit'), 'postgres');
  assert.equal(dialectFor('mssql://orbit@db/orbit'), 'mssql');
  assert.equal(dialectFor('sqlserver://db'), 'mssql');
  assert.throws(() => dialectFor('mysql://db'), /unsupported/);
  assert.equal((await loadDialect('sqlite')).name, 'sqlite');
  assert.equal((await loadDialect('postgres')).executable, false);
  assert.equal((await loadDialect('mssql', { schema: 'x' })).name, 'mssql');
  await assert.rejects(loadDialect('oracle'), /unknown dialect/);
});
