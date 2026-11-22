// The PostgreSQL and SQL Server dialects are render-only skeletons in 1.5: their output is pinned
// here statement by statement (the §10.4 contract table), and their classify tables are checked
// with the error shapes the `postgres` and `tedious` drivers produce. Neither driver is installed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { sql, id, list, json } from '../../lib/db/sql.mjs';
import { loadDialect } from '../../lib/db/dialect/index.mjs';
import { POSTGRES_CODES } from '../../lib/db/dialect/postgres.mjs';
import { MSSQL_CODES } from '../../lib/db/dialect/mssql.mjs';

const pg = await loadDialect('postgres');
const ms = await loadDialect('mssql');

test('placeholders and quoting: $n for PostgreSQL, @pN and [brackets] for SQL Server', () => {
  const query = sql`SELECT ${id('rule')}, ${id('a', 'key')} FROM ${id('alerts')} a WHERE ${id('service')} IN ${list(['x', 'y'])} AND ${id('count')} > ${2}`;
  assert.deepEqual(pg.render(query), {
    text: 'SELECT "rule", "a"."key" FROM "alerts" a WHERE "service" IN ($1, $2) AND "count" > $3',
    params: ['x', 'y', 2],
  });
  assert.deepEqual(ms.render(query), {
    text: 'SELECT [rule], [a].[key] FROM [alerts] a WHERE [service] IN (@p1, @p2) AND [count] > @p3',
    params: ['x', 'y', 2],
    types: ['VarChar', 'VarChar', 'BigInt'],
  });
  assert.equal(pg.executable, false);
  assert.equal(ms.executable, false);
});

test('SQL Server binds strings as VarChar (never NVARCHAR), and types every parameter', () => {
  const { params, types } = ms.render(
    sql`SELECT ${'é'}, ${1}, ${1.5}, ${NaN}, ${true}, ${null}, ${12n}, ${new Uint8Array([1])}, ${-0}`
  );
  assert.deepEqual(types, [
    'VarChar',
    'BigInt',
    'Float',
    'VarChar',
    'Bit',
    'VarChar',
    'BigInt',
    'VarBinary',
    'BigInt',
  ]);
  assert.deepEqual(params.slice(0, 7), ['é', 1, 1.5, null, true, null, '12']);
  assert.ok(Object.is(params[8], 0), 'SQL Server rejects no float here: -0 is 0 and NaN is NULL');
  assert.deepEqual(pg.render(sql`SELECT ${NaN}, ${Infinity}, ${-0}`).params, [null, null, 0]);
});

test('upsert: ON CONFLICT on PostgreSQL; UPDLOCK/SERIALIZABLE then INSERT on SQL Server, keys sorted', () => {
  const rows = [
    { component: 'b', key: 'k', value: 1 },
    { component: 'a', key: 'k', value: 2 },
    { component: 'b', key: 'k', value: 3 }, // duplicate key: last wins
  ];
  const upsert = dialect =>
    dialect.render(
      dialect.upsert('settings', ['component', 'key'], ['component', 'key', 'value'], rows)
    );
  assert.deepEqual(upsert(pg), {
    text: 'INSERT INTO "settings" ("component", "key", "value") VALUES ($1, $2, $3), ($4, $5, $6) ON CONFLICT ("component", "key") DO UPDATE SET "value" = excluded."value"',
    params: ['a', 'k', 2, 'b', 'k', 3],
  });
  const mssql = upsert(ms);
  assert.equal(
    mssql.text,
    [
      'UPDATE [settings] WITH (UPDLOCK, SERIALIZABLE) SET [value] = @p1 WHERE [component] = @p2 AND [key] = @p3;',
      'IF @@ROWCOUNT = 0 INSERT INTO [settings] ([component], [key], [value]) VALUES (@p4, @p5, @p6);',
      'UPDATE [settings] WITH (UPDLOCK, SERIALIZABLE) SET [value] = @p7 WHERE [component] = @p8 AND [key] = @p9;',
      'IF @@ROWCOUNT = 0 INSERT INTO [settings] ([component], [key], [value]) VALUES (@p10, @p11, @p12);',
    ].join('\n')
  );
  assert.deepEqual(mssql.params, [2, 'a', 'k', 'a', 'k', 2, 3, 'b', 'k', 'b', 'k', 3]);
  assert.doesNotMatch(mssql.text, /MERGE/);
  // Keys are sorted even without duplicates, so concurrent writers lock them in one order.
  for (const dialect of [pg, ms])
    assert.deepEqual(
      dialect
        .render(
          dialect.upsert(
            'meta',
            ['key'],
            ['key', 'value'],
            [
              ['z', 1],
              ['a', 2],
            ]
          )
        )
        .params.filter(value => typeof value === 'string'),
      dialect === pg ? ['a', 'z'] : ['a', 'a', 'z', 'z']
    );
  const keepExisting = ms.render(
    ms.upsert('meta', ['key'], ['key', 'value'], [['k', 'v']], { update: [] })
  );
  assert.equal(
    keepExisting.text,
    'IF NOT EXISTS (SELECT 1 FROM [meta] WITH (UPDLOCK, SERIALIZABLE) WHERE [key] = @p1) INSERT INTO [meta] ([key], [value]) VALUES (@p2, @p3);'
  );
  assert.equal(
    pg.render(pg.upsert('meta', ['key'], ['key', 'value'], [['k', 'v']], { update: [] })).text,
    'INSERT INTO "meta" ("key", "value") VALUES ($1, $2) ON CONFLICT ("key") DO NOTHING'
  );
});

test('returning: RETURNING on PostgreSQL, OUTPUT inserted/deleted in place on SQL Server', () => {
  const where = sql`${id('id')} = ${1}`;
  assert.equal(
    pg.render(pg.insert('outbox', ['state'], [['pending']], { returning: ['id'] })).text,
    'INSERT INTO "outbox" ("state") VALUES ($1) RETURNING "id"'
  );
  assert.equal(
    ms.render(ms.insert('outbox', ['state'], [['pending']], { returning: ['id'] })).text,
    'INSERT INTO [outbox] ([state]) OUTPUT inserted.[id] VALUES (@p1)'
  );
  assert.equal(
    ms.render(ms.update('outbox', { state: 'sent' }, where, { returning: ['id', 'state'] })).text,
    'UPDATE [outbox] SET [state] = @p1 OUTPUT inserted.[id], inserted.[state] WHERE [id] = @p2'
  );
  assert.equal(
    ms.render(ms.deleteFrom('outbox', where, { returning: ['id'] })).text,
    'DELETE FROM [outbox] OUTPUT deleted.[id] WHERE [id] = @p1'
  );
  assert.equal(
    pg.render(pg.deleteFrom('outbox', where, { returning: ['id'] })).text,
    'DELETE FROM "outbox" WHERE "id" = $1 RETURNING "id"'
  );
  assert.equal(
    ms.render(ms.upsert('meta', ['key'], ['key', 'value'], [['k', 'v']], { returning: ['value'] }))
      .text,
    'UPDATE [meta] WITH (UPDLOCK, SERIALIZABLE) SET [value] = @p1 OUTPUT inserted.[value] WHERE [key] = @p2;\nIF @@ROWCOUNT = 0 INSERT INTO [meta] ([key], [value]) OUTPUT inserted.[value] VALUES (@p3, @p4);'
  );
  assert.equal(ms.render(sql`${ms.returning(['a'], 'deleted')}`).text, 'OUTPUT deleted.[a]');
});

test('insertIgnore: ON CONFLICT DO NOTHING, or an IGNORE_DUP_KEY index on SQL Server', () => {
  assert.equal(
    pg.render(pg.insertIgnore('head', ['shard', 'slot'], [[1, 2]], { conflict: ['shard', 'slot'] }))
      .text,
    'INSERT INTO "head" ("shard", "slot") VALUES ($1, $2) ON CONFLICT ("shard", "slot") DO NOTHING'
  );
  assert.equal(
    ms.render(ms.insertIgnore('head', ['shard', 'slot'], [[1, 2]])).text,
    'INSERT INTO [head] ([shard], [slot]) VALUES (@p1, @p2)'
  );
});

test('NULL ordering: native on PostgreSQL, emulated with CASE on SQL Server', () => {
  const order = dialect =>
    dialect.render(
      dialect.orderBy(
        ['a', 'asc', 'first'],
        ['b', 'asc', 'last'],
        ['c', 'desc', 'first'],
        ['d', 'desc', 'last'],
        ['e', 'asc', 'not null']
      )
    ).text;
  assert.equal(
    order(pg),
    'ORDER BY "a" ASC NULLS FIRST, "b" ASC NULLS LAST, "c" DESC NULLS FIRST, "d" DESC NULLS LAST, "e" ASC'
  );
  assert.equal(
    order(ms),
    'ORDER BY [a] ASC, CASE WHEN [b] IS NULL THEN 1 ELSE 0 END, [b] ASC, CASE WHEN [c] IS NULL THEN 0 ELSE 1 END, [c] DESC, [d] DESC, [e] ASC'
  );
});

test('limit: LIMIT/OFFSET on PostgreSQL; OFFSET … FETCH after ORDER BY on SQL Server', () => {
  const base = dialect =>
    sql`SELECT ${id('id')} FROM ${id('t')} ${dialect.orderBy(['id', 'asc', 'not null'])} ${dialect.limit(10, 20)}`;
  assert.deepEqual(pg.render(base(pg)), {
    text: 'SELECT "id" FROM "t" ORDER BY "id" ASC LIMIT $1 OFFSET $2',
    params: [10, 20],
  });
  assert.deepEqual(
    ms.render(base(ms)).text,
    'SELECT [id] FROM [t] ORDER BY [id] ASC OFFSET @p1 ROWS FETCH NEXT @p2 ROWS ONLY'
  );
  assert.deepEqual(ms.render(base(ms)).params, [20, 10]);
  assert.throws(() => ms.render(sql`SELECT 1 ${ms.limit(1)}`), /needs orderBy\(\) before limit/);
});

test('claims and fences: SKIP LOCKED / FOR SHARE, or UPDLOCK READPAST / HOLDLOCK hints', () => {
  const select = (dialect, lock) =>
    dialect.render(
      sql`SELECT ${id('id')} FROM ${lock.table('outbox')} WHERE ${id('state')} = ${'pending'} ${dialect.orderBy(['id', 'asc', 'not null'])} ${dialect.limit(5)}${lock.tail}`
    ).text;
  assert.equal(
    select(pg, pg.claim()),
    'SELECT "id" FROM "outbox" WHERE "state" = $1 ORDER BY "id" ASC LIMIT $2 FOR UPDATE SKIP LOCKED'
  );
  assert.equal(
    select(pg, pg.forShare()),
    'SELECT "id" FROM "outbox" WHERE "state" = $1 ORDER BY "id" ASC LIMIT $2 FOR SHARE'
  );
  assert.equal(
    select(ms, ms.claim()),
    'SELECT [id] FROM [outbox] WITH (UPDLOCK, READPAST, ROWLOCK) WHERE [state] = @p1 ORDER BY [id] ASC OFFSET @p2 ROWS FETCH NEXT @p3 ROWS ONLY'
  );
  assert.match(select(ms, ms.forShare()), /FROM \[outbox\] WITH \(HOLDLOCK, ROWLOCK\) WHERE/);
});

test('the database clock is clock_timestamp() / SYSUTCDATETIME(), never now() or GETDATE()', () => {
  const pgClock = pg.render(pg.clockMs()).text;
  const msClock = ms.render(ms.clockMs()).text;
  assert.equal(pgClock, 'CAST(floor(extract(epoch FROM clock_timestamp()) * 1000) AS bigint)');
  assert.equal(msClock, "DATEDIFF_BIG(millisecond, '1970-01-01', SYSUTCDATETIME())");
  for (const text of [pgClock, msClock])
    assert.doesNotMatch(text, /\bnow\(|GETDATE|CURRENT_TIMESTAMP/i);
  assert.equal(pg.caps.dbClock, true);
  assert.equal(ms.caps.onlineIndex, false, 'Standard edition has no online index builds');
});

test('JSON binds as jsonb on PostgreSQL and as text on SQL Server', () => {
  assert.equal(pg.render(sql`SELECT ${json({ a: 1 })}`).text, 'SELECT CAST($1 AS jsonb)');
  assert.deepEqual(ms.render(sql`SELECT ${json({ a: 1 })}`), {
    text: 'SELECT @p1',
    params: ['{"a":1}'],
    types: ['VarChar'],
  });
});

test('PostgreSQL classify: SQLSTATEs, the missing-partition case and client errors', () => {
  const error = (code, message = 'x') => Object.assign(new Error(message), { code });
  const cases = {
    40001: 'retry',
    '40P01': 'retry',
    23505: 'unique',
    23502: 'poison',
    22001: 'poison', // string_data_right_truncation, by class 22
    '22P02': 'poison',
    53100: 'full',
    '55P03': 'timeout',
    57014: 'timeout',
    '57P01': 'unavailable',
    25006: 'unavailable',
    '08006': 'unavailable',
    42601: 'fatal',
    '42P01': 'fatal',
    28000: 'fatal',
    XX001: 'fatal',
    ECONNREFUSED: 'unavailable',
    EPIPE: 'unavailable', // five capitals, but a client error, not a SQLSTATE
    CONNECTION_CLOSED: 'unavailable',
    CONNECT_TIMEOUT: 'timeout',
    ETIMEDOUT: 'timeout',
  };
  for (const [code, expected] of Object.entries(cases))
    assert.equal(pg.classify(error(code)), expected, code);
  assert.equal(
    pg.classify(error('23514', 'no partition of relation "head" found for row')),
    'full'
  );
  assert.equal(pg.classify(error('23514', 'new row violates check constraint')), 'poison');
  assert.equal(pg.classify(error('ZZ999')), 'fatal');
  assert.equal(pg.classify(Object.assign(new Error('x'), { class: 'fenced' })), 'fenced');
  assert.equal(POSTGRES_CODES.exact['40P01'], 'retry');
});

test('SQL Server classify: error numbers, Azure transient codes and tedious codes', () => {
  const request = number => Object.assign(new Error('x'), { code: 'EREQUEST', number });
  const cases = {
    1205: 'retry',
    1222: 'retry',
    40613: 'retry',
    40501: 'retry',
    2627: 'unique',
    2601: 'unique',
    9002: 'full',
    1105: 'full',
    8023: 'poison', // NaN or Infinity in a float parameter (R43)
    2628: 'poison',
    515: 'poison',
    13609: 'poison',
    976: 'unavailable',
    3906: 'unavailable',
    [-2]: 'timeout',
    18456: 'fatal',
    208: 'fatal',
    50000: 'fatal',
  };
  for (const [number, expected] of Object.entries(cases))
    assert.equal(ms.classify(request(Number(number))), expected, number);
  const connection = code => Object.assign(new Error('x'), { code });
  assert.equal(ms.classify(connection('ETIMEOUT')), 'timeout');
  assert.equal(ms.classify(connection('ESOCKET')), 'unavailable');
  assert.equal(ms.classify(connection('ELOGIN')), 'fatal');
  assert.equal(ms.classify(Object.assign(new Error('x'), { name: 'AbortError' })), 'timeout');
  assert.equal(MSSQL_CODES.numbers[1205], 'retry');
});

test('server dialects write DDL into schema orbit and are selected per database', async () => {
  const other = await loadDialect('postgres', { schema: 'tenant' });
  assert.equal(other.ddl.tableName('meta'), '"tenant"."meta"');
  assert.equal(pg.ddl.tableName('meta'), '"orbit"."meta"');
  assert.equal(ms.ddl.tableName('meta'), '[orbit].[meta]');
  const registered = await loadDialect('mssql', { identifiers: new Set(['meta']) });
  assert.throws(
    () => registered.render(sql`SELECT 1 FROM ${id('other')}`),
    /not in the table registry/
  );
});

test('catalog queries read pg_catalog or sys.* for the dialect schema, never SQLite catalogs', async () => {
  assert.deepEqual(pg.render(pg.catalog.tableExists('meta')), {
    text: "SELECT 1 AS present FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1 AND c.relkind IN ('r', 'p') AND NOT c.relispartition AND c.relname = $2",
    params: ['orbit', 'meta'],
  });
  assert.deepEqual(ms.render(ms.catalog.tableExists('meta')), {
    text: 'SELECT 1 AS present FROM sys.tables AS t WHERE t.schema_id = SCHEMA_ID(@p1) AND t.name = @p2',
    params: ['orbit', 'meta'],
    types: ['VarChar', 'VarChar'],
  });
  assert.equal(
    ms.render(ms.catalog.columns('meta')).text,
    'SELECT c.name AS name FROM sys.columns AS c JOIN sys.tables AS t ON t.object_id = c.object_id WHERE t.schema_id = SCHEMA_ID(@p1) AND t.name = @p2 ORDER BY c.column_id'
  );
  assert.match(
    pg.render(pg.catalog.columns('meta')).text,
    /FROM pg_catalog\.pg_attribute a .* AND c\.relname = \$2 AND a\.attnum > 0 AND NOT a\.attisdropped ORDER BY a\.attnum$/
  );
  assert.match(pg.render(pg.catalog.tables()).text, /NOT c\.relispartition ORDER BY c\.relname$/);
  assert.match(pg.render(pg.catalog.indexes()).text, /AS "table" FROM pg_catalog\.pg_index x /);
  assert.match(ms.render(ms.catalog.indexes()).text, /AS \[table\] .* AND i\.name IS NOT NULL/);
  const tenant = await loadDialect('postgres', { schema: 'tenant' });
  assert.deepEqual(tenant.render(tenant.catalog.tables()).params, ['tenant']);
  for (const dialect of [pg, ms])
    for (const query of [
      dialect.catalog.tables(),
      dialect.catalog.tableExists('meta'),
      dialect.catalog.columns('meta'),
      dialect.catalog.indexes(),
    ])
      assert.doesNotMatch(dialect.render(query).text, /sqlite_|pragma/i);
  assert.throws(() => pg.render(ms.catalog.tables()), /mssql fragment cannot be rendered/);
});
