// The SQLite Db (lib/db/sqlite.mjs): units of work, the SQLite guard, busy retries, error
// classes, bulk inserts and the lock/snapshot primitives.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { spawnSync } from 'node:child_process';
import {
  openSqlite,
  GuardError,
  maxBusyTimeoutMs,
  maxBulkInsertRows,
  holdExclusive,
  backupDatabase,
  settleDatabase,
  quickCheck,
  catalogKind,
  plantedObjects,
} from '../../lib/db/sqlite.mjs';
import { sql, id, SqlError } from '../../lib/db/sql.mjs';
import { renderTable, text, bigint } from '../../lib/db/dialect/schema.mjs';
import { createRegistry, defineTable } from '../../lib/db/registry.mjs';
import { retryOnce } from '../helpers/retry-once.mjs';
import { temporary, mode } from './helpers.mjs';

// A registry of one test table, so these tests do not depend on the platform schema.
const items = defineTable('items', {
  component: 'test',
  lane: 'P',
  class: 'control',
  db: 'control',
  backup: 'never',
  since: '1.5.0',
  columns: { k: text(32), v: bigint(), note: text(100).nullable() },
  primaryKey: ['k'],
});
const registry = createRegistry([items]);

function open(t, options = {}) {
  const directory = temporary(t);
  const file = path.join(directory, 'test.sqlite');
  const db = openSqlite(file, { registry, ...options });
  t.after(() => db.close());
  return { db, file, directory };
}
async function withItems(t, options) {
  const opened = open(t, options);
  await opened.db.write(tx => tx.ddl(renderTable(opened.db.dialect, items)));
  return opened;
}
const insert = (k, v, note = null) =>
  sql`INSERT INTO ${id('items')} (${id('k')}, ${id('v')}, ${id('note')}) VALUES (${k}, ${v}, ${note})`;
const count = tx => tx.get(sql`SELECT COUNT(*) AS n FROM ${id('items')}`).n;

test('openSqlite creates a 0600 WAL database with FULL sync, foreign keys and a short busy timeout', async t => {
  const { db, file } = open(t);
  assert.equal(mode(file), 0o600);
  const pragmas = {
    journal_mode: sql`PRAGMA journal_mode`,
    synchronous: sql`PRAGMA synchronous`,
    foreign_keys: sql`PRAGMA foreign_keys`,
    busy_timeout: sql`PRAGMA busy_timeout`,
  };
  const pragma = name => db.read(tx => Object.values(tx.get(pragmas[name]))[0]);
  assert.equal(await pragma('journal_mode'), 'wal');
  assert.equal(await pragma('synchronous'), 2); // FULL
  assert.equal(await pragma('foreign_keys'), 1);
  assert.equal(await pragma('busy_timeout'), maxBusyTimeoutMs);
  assert.ok(maxBusyTimeoutMs <= 250);
  assert.throws(
    () => openSqlite(path.join(path.dirname(file), 'x.sqlite'), { busyTimeoutMs: 251 }),
    RangeError
  );
  // Read-only and create: false never create a file.
  const missing = path.join(path.dirname(file), 'missing.sqlite');
  assert.throws(() => openSqlite(missing, { readOnly: true }), {
    code: 'ENOENT',
    class: 'unavailable',
  });
  assert.throws(() => openSqlite(missing, { create: false }), { code: 'ENOENT' });
  assert.equal(fs.existsSync(missing), false);
});

// Repositories hold the Db: one that replaced its dialect had any text prepared for a sql`…`
// query (Db#prepare rendered with this.dialect, an ordinary writable property).
test('the dialect a Db renders with cannot be replaced', async t => {
  const { db } = await withItems(t);
  const dialect = db.dialect;
  assert.ok(Object.isFrozen(dialect));
  const forged = { ...dialect, render: () => ({ text: "SELECT 'forged' AS r", params: [] }) };
  assert.throws(() => {
    db.dialect = forged;
  }, TypeError);
  // An own property in its place does not reach the connection either.
  Object.defineProperty(db, 'dialect', { value: forged });
  assert.equal(db.dialect, forged);
  assert.deepEqual(await db.read(tx => tx.all(sql`SELECT ${id('k')} FROM ${id('items')}`)), []);
  await db.write(tx => tx.run(dialect.insert('items', ['k', 'v'], [['a', 1]])));
  assert.deepEqual(
    (await db.read(tx => tx.all(sql`SELECT ${id('k')} FROM ${id('items')}`))).map(row => ({
      ...row,
    })),
    [{ k: 'a' }]
  );
});

test('write() commits a synchronous unit and resolves to its value; read() sees one snapshot', async t => {
  const { db } = await withItems(t);
  assert.equal(await db.write(tx => tx.run(insert('a', 1)).changes), 1);
  const value = await db.write(tx => {
    tx.run(insert('b', 2));
    return count(tx);
  });
  assert.equal(value, 2);
  assert.deepEqual(
    (
      await db.read(tx =>
        tx.all(
          sql`SELECT ${id('k')} FROM ${id('items')} ${tx.dialect.orderBy(['k', 'asc', 'not null'])}`
        )
      )
    ).map(row => row.k),
    ['a', 'b']
  );
  assert.equal(
    (
      await db.read(tx =>
        tx.get(sql`SELECT ${id('v')} FROM ${id('items')} WHERE ${id('k')} = ${'b'}`)
      )
    ).v,
    2
  );
  assert.deepEqual(
    await db.read(tx => [...tx.iterate(sql`SELECT ${id('k')} FROM ${id('items')}`)].length),
    2
  );
  // A read unit cannot write.
  await assert.rejects(
    db.read(tx => tx.run(insert('c', 3))),
    GuardError
  );
  assert.equal(await db.read(count), 2);
  // Only sql`…` queries are accepted.
  await assert.rejects(
    db.read(tx => tx.all('SELECT 1')),
    GuardError
  );
});

test('the SQLite guard: a callback that awaits is rolled back and throws', async t => {
  const { db } = await withItems(t);
  await assert.rejects(
    db.write(async tx => {
      tx.run(insert('early', 1));
      await null;
      tx.run(insert('late', 2));
    }),
    error =>
      error instanceof GuardError && error.class === 'fatal' && /synchronously/.test(error.message)
  );
  assert.equal(await db.read(count), 0, 'nothing the callback did before its await committed');
  // A callback returning any thenable is refused the same way.
  await assert.rejects(
    db.write(() => ({ then() {} })),
    GuardError
  );
  await assert.rejects(
    db.read(async () => 1),
    GuardError
  );
  // The transaction object refuses every use once its unit has finished.
  let kept;
  await db.write(tx => {
    kept = tx;
  });
  assert.throws(() => kept.run(insert('x', 1)), GuardError);
  assert.throws(() => kept.get(sql`SELECT 1`), GuardError);
  // Units cannot be nested; the outer one still commits.
  let nested;
  await db.write(tx => {
    tx.run(insert('outer', 1));
    nested = db.write(inner => inner.run(insert('inner', 2)));
  });
  await assert.rejects(nested, /cannot be nested/);
  assert.deepEqual(
    (await db.read(tx => tx.all(sql`SELECT ${id('k')} FROM ${id('items')}`))).map(row => row.k),
    ['outer']
  );
  // Later units work normally.
  assert.equal(await db.write(tx => tx.run(insert('after', 3)).changes), 1);
});

test('errors carry the dialect class; errors of the callback itself pass through and roll back', async t => {
  const { db } = await withItems(t);
  await db.write(tx => tx.run(insert('a', 1)));
  await assert.rejects(
    db.write(tx => tx.run(insert('a', 2))),
    error => error.class === 'unique' && error.errcode === 1555
  );
  await assert.rejects(
    db.write(tx =>
      tx.run(sql`INSERT INTO ${id('items')} (${id('k')}, ${id('v')}) VALUES (${'b'}, ${null})`)
    ),
    { class: 'poison' }
  );
  // STRICT tables refuse a value of the wrong type, as PostgreSQL would.
  await assert.rejects(
    db.write(tx => tx.run(insert('c', 'not a number'))),
    { class: 'poison' }
  );
  // Identifiers must be registered.
  await assert.rejects(
    db.read(tx => tx.all(sql`SELECT * FROM ${id('elsewhere')}`)),
    error => error instanceof SqlError && error.class === 'fatal'
  );
  const mine = new Error('mine');
  await assert.rejects(
    db.write(tx => {
      tx.run(insert('d', 4));
      throw mine;
    }),
    error => error === mine && !('class' in error)
  );
  assert.equal(await db.read(count), 1);
});

test('SQLITE_BUSY is retried asynchronously, with a busy wait of at most 250 ms per attempt', async t => {
  const { db, file } = await withItems(t, { busyTimeoutMs: 20, retryDelayMs: 1 });
  const holder = new DatabaseSync(file);
  t.after(() => holder.close());
  holder.exec('PRAGMA busy_timeout=0');
  holder.exec('BEGIN IMMEDIATE');
  // The first attempt meets the holder's lock; the holder commits during the async wait.
  const waits = [];
  const retrying = openSqlite(file, {
    registry,
    busyTimeoutMs: 20,
    retryDelayMs: 8,
    sleep: async ms => {
      waits.push(ms);
      if (holder.isTransaction) holder.exec('COMMIT');
    },
  });
  t.after(() => retrying.close());
  let runs = 0;
  assert.equal(
    await retrying.write(tx => {
      runs += 1;
      return tx.run(insert('x', 1)).changes;
    }),
    1
  );
  assert.equal(runs, 1, 'the callback runs only once BEGIN IMMEDIATE succeeded');
  assert.equal(waits.length, 1);
  assert.ok(waits[0] >= 4 && waits[0] <= 8, `jittered wait ${waits[0]}`);

  // With the lock never released, it gives up after `retries` retries with class retry.
  holder.exec('BEGIN IMMEDIATE');
  const started = performance.now();
  const giving = openSqlite(file, { registry, busyTimeoutMs: 20, retries: 2, retryDelayMs: 1 });
  t.after(() => giving.close());
  await assert.rejects(
    giving.write(tx => tx.run(insert('y', 2))),
    error => error.class === 'retry' && (error.errcode & 0xff) === 5
  );
  const elapsed = performance.now() - started;
  assert.ok(
    elapsed >= 50 && elapsed < 1000,
    `three attempts of about 20 ms each took ${elapsed} ms`
  );
  holder.exec('ROLLBACK');
  assert.equal(await db.read(count), 1);
});

test('bulkInsert takes columns, inserts in statements of at most 2,000 parameters, all or nothing', async t => {
  const { db } = await withItems(t);
  const n = 1500; // 4,500 parameters: three statements in one unit
  const keys = Array.from({ length: n }, (_, i) => `k${i}`);
  assert.equal(
    await db.bulkInsert(
      'items',
      ['k', 'v', 'note'],
      [keys, keys.map((_, i) => i), keys.map(() => null)]
    ),
    n
  );
  assert.equal(await db.read(count), n);
  // ignore: existing keys and duplicates within the batch are skipped and not counted.
  assert.equal(
    await db.bulkInsert(
      'items',
      ['k', 'v'],
      [
        ['k0', 'new', 'new'],
        [0, 1, 2],
      ],
      { onConflict: 'ignore' }
    ),
    1
  );
  // error: one duplicate fails the whole batch.
  await assert.rejects(
    db.bulkInsert(
      'items',
      ['k', 'v'],
      [
        ['fresh', 'k1'],
        [1, 2],
      ]
    ),
    { class: 'unique' }
  );
  assert.equal(
    await db.read(
      tx => tx.get(sql`SELECT COUNT(*) AS n FROM ${id('items')} WHERE ${id('k')} = ${'fresh'}`).n
    ),
    0
  );
  assert.equal(await db.bulkInsert('items', ['k', 'v'], [[], []]), 0);
  await assert.rejects(db.bulkInsert('items', ['k', 'v'], [['a'], [1, 2]]), GuardError);
  await assert.rejects(
    db.bulkInsert('items', ['k', 'v'], [['a'], [1]], { onConflict: 'replace' }),
    GuardError
  );
});

test('bulkInsert takes at most maxBulkInsertRows rows per call, so one unit cannot block for long', async t => {
  const { db } = await withItems(t);
  const batch = n => {
    const keys = Array.from({ length: n }, (_, i) => `b${i}`);
    return [keys, keys.map((_, i) => i)];
  };
  await assert.rejects(
    db.bulkInsert('items', ['k', 'v'], batch(maxBulkInsertRows + 1)),
    error => error instanceof GuardError && /at most 5000 rows per call/.test(error.message)
  );
  assert.equal(await db.read(count), 0, 'a refused batch writes nothing');
  assert.equal(await db.bulkInsert('items', ['k', 'v'], batch(maxBulkInsertRows)), 5000);
});

test('read() cannot change the database through get(), all() or iterate(), and write() still works after', async t => {
  const { db } = await withItems(t);
  await db.write(tx => tx.run(insert('a', 1)));
  const update = sql`UPDATE ${id('items')} SET ${id('v')} = ${2} WHERE ${id('k')} = ${'a'} RETURNING ${id('v')}`;
  const attempts = {
    'get(UPDATE … RETURNING)': tx => tx.get(update),
    'all(UPDATE … RETURNING)': tx => tx.all(update),
    'iterate(UPDATE … RETURNING)': tx => [...tx.iterate(update)],
    'all(INSERT … RETURNING)': tx =>
      tx.all(
        sql`INSERT INTO ${id('items')} (${id('k')}, ${id('v')}) VALUES (${'b'}, ${3}) RETURNING ${id('k')}`
      ),
    'get(DELETE … RETURNING)': tx =>
      tx.get(sql`DELETE FROM ${id('items')} WHERE ${id('k')} = ${'a'} RETURNING ${id('k')}`),
  };
  for (const [name, fn] of Object.entries(attempts))
    await assert.rejects(
      db.read(fn),
      error => error instanceof GuardError && /read\(\) unit cannot write/.test(error.message),
      name
    );
  assert.deepEqual(
    await db.read(tx =>
      tx.all(sql`SELECT ${id('k')}, ${id('v')} FROM ${id('items')}`).map(row => ({ ...row }))
    ),
    [{ k: 'a', v: 1 }]
  );
  // The connection is writable again once the read unit ends, including after a refused one.
  assert.deepEqual({ ...(await db.write(tx => tx.get(update))) }, { v: 2 });
  assert.equal(await db.read(tx => tx.get(sql`SELECT ${id('v')} FROM ${id('items')}`).v), 2);
});

test('now() is the process clock, read-only databases refuse writes, and close() ends the Db', async t => {
  const { db, file } = await withItems(t, { clock: () => 1234 });
  assert.equal(await db.now(), 1234);
  const reader = openSqlite(file, { registry, readOnly: true });
  await assert.rejects(
    reader.write(tx => tx.run(insert('a', 1))),
    GuardError
  );
  assert.equal(await reader.read(count), 0);
  reader.close();
  reader.close(); // idempotent
  await assert.rejects(reader.read(count), error => error.class === 'unavailable');
  await assert.rejects(
    db.write(tx => tx.run(insert('a', 1)), { fence: [{}] }),
    /goblin\.lock stands in/
  );
  await assert.rejects(
    (async () => {
      let closing;
      await db.write(() => {
        closing = () => db.close();
        closing();
      });
    })(),
    /inside a unit of work/
  );
  const { tables, indexes } = await db.catalog();
  assert.deepEqual(tables, ['items']);
  assert.ok(indexes.every(name => name.startsWith('sqlite_autoindex_items')));
});

test('holdExclusive holds a lock file with no journal beside it; backups are single self-contained files', async t => {
  const directory = temporary(t);
  const lockFile = path.join(directory, 'goblin.lock');
  const lock = holdExclusive(lockFile);
  assert.throws(
    () => holdExclusive(lockFile),
    error => error.busy === true
  );
  assert.deepEqual(fs.readdirSync(directory), ['goblin.lock']);
  lock.release();
  lock.release();
  holdExclusive(lockFile).release();

  const source = path.join(directory, 'source.sqlite');
  const writer = new DatabaseSync(source);
  writer.exec('PRAGMA journal_mode=WAL; CREATE TABLE t (x); INSERT INTO t VALUES (1), (2)');
  // Rows still only in the WAL are in the copy too.
  assert.ok(fs.statSync(`${source}-wal`).size > 0);
  const copy = path.join(directory, 'copy.sqlite');
  assert.ok((await backupDatabase(source, copy)) > 0);
  writer.close();
  assert.equal(quickCheck(copy), 'ok');
  const reader = new DatabaseSync(copy, { readOnly: true });
  assert.equal(reader.prepare('PRAGMA journal_mode').get().journal_mode, 'delete');
  assert.equal(reader.prepare('SELECT COUNT(*) AS n FROM t').get().n, 2);
  reader.close();
  assert.ok(!fs.existsSync(`${copy}-wal`) && !fs.existsSync(`${copy}-shm`));
  await assert.rejects(backupDatabase(path.join(directory, 'none.sqlite'), copy), {
    code: 'ENOENT',
  });

  // settleDatabase folds a WAL into the main file.
  const again = new DatabaseSync(source);
  again.exec('PRAGMA journal_mode=WAL; INSERT INTO t VALUES (3)');
  again.close();
  settleDatabase(source);
  assert.ok(!fs.existsSync(`${source}-wal`));
  const settled = new DatabaseSync(source, { readOnly: true });
  assert.equal(settled.prepare('SELECT COUNT(*) AS n FROM t').get().n, 3);
  settled.close();
  fs.writeFileSync(
    path.join(directory, 'bad.sqlite'),
    'not a database at all, but long enough to be read '.repeat(200)
  );
  assert.throws(() => quickCheck(path.join(directory, 'bad.sqlite')));
});

test('ddl() runs additive DDL only, one statement at a time, inside a write unit', async t => {
  const { db, directory } = await withItems(t);
  await db.write(tx => tx.ddl('ALTER TABLE "items" ADD COLUMN "extra" TEXT'));
  await db.write(tx =>
    tx.ddl([
      'CREATE INDEX "items_v" ON "items" ("v")',
      'ALTER TABLE items ADD extra2 INTEGER',
      'CREATE UNIQUE INDEX "items_note" ON "items" ("note") WHERE "note" IS NOT NULL',
      'CREATE TABLE "plain" ("k" TEXT PRIMARY KEY, "v" INTEGER)',
      'CREATE TABLE "kept" (\n  "k" TEXT NOT NULL PRIMARY KEY\n) STRICT, WITHOUT ROWID',
    ])
  );
  for (const statement of [
    // Not what renderTable writes: rows copied into an unregistered table, and schema objects
    // no drift check lists (a view, a trigger, a virtual or a temporary table).
    'CREATE TABLE "copy_of_items" AS SELECT * FROM "items"',
    'CREATE TABLE copy_of_items AS SELECT * FROM items',
    'CREATE VIEW "v" AS SELECT 1',
    'CREATE TRIGGER "t" AFTER INSERT ON "items" BEGIN DELETE FROM "items"; END',
    'CREATE TEMP TABLE "t" ("x" INTEGER)',
    'CREATE TEMPORARY TABLE "t" ("x" INTEGER)',
    'CREATE VIRTUAL TABLE "f" USING fts5("x")',
    'CREATE TABLE IF NOT EXISTS "t" ("x" INTEGER)',
    'CREATE INDEX "i" ON "items" ("v"); DELETE FROM "items"',
    'ALTER TABLE "items" ADD COLUMN',
    'DROP TABLE "items"',
    'ALTER TABLE "items" DROP COLUMN "extra"',
    'ALTER TABLE "items" RENAME TO "other"',
    'ALTER TABLE "items" RENAME COLUMN "v" TO "w"',
    'ALTER TABLE "items" ADD CONSTRAINT x CHECK (1)',
    'CREATE TABLE a (x); DROP TABLE "items"',
    'DELETE FROM "items"',
    7,
  ])
    await assert.rejects(
      db.write(tx => tx.ddl(statement)),
      GuardError,
      String(statement)
    );
  await assert.rejects(
    db.read(tx => tx.ddl('CREATE TABLE b (x)')),
    /write\(\) unit/
  );
  const reader = openSqlite(path.join(directory, 'test.sqlite'), { registry, readOnly: true });
  t.after(() => reader.close());
  assert.equal(reader.immutable, false, 'a writer has it open: the WAL is shared');
  const { tables } = await db.catalog();
  assert.deepEqual(tables, ['items', 'kept', 'plain']);
  // ddl() is the only way to run text: no public method of the Db takes a statement (one did,
  // execDdl(), and it ran whatever it was given for any module holding the Db).
  assert.equal(db.execDdl, undefined);
  assert.equal(Object.getOwnPropertyNames(Object.getPrototypeOf(db)).includes('execDdl'), false);
  assert.throws(() => db.prepare('DELETE FROM "items"'), GuardError);
});

test('pragma() is a test seam for page limits and checkpoints only, on the Db connection itself', async t => {
  const { db } = open(t);
  await db.write(tx => tx.ddl(renderTable(db.dialect, items)));
  const [{ page_count: pages }] = db.pragma('page_count');
  assert.ok(pages > 0);
  // A page limit on this connection makes its own writes full (class `full`)…
  assert.deepEqual(
    db.pragma(`max_page_count=${pages}`).map(row => ({ ...row })),
    [{ max_page_count: pages }]
  );
  const fill = n =>
    db.write(tx => {
      for (let i = 0; i < 50; i++)
        tx.run(
          tx.dialect.insert('items', ['k', 'v', 'note'], [[`k${n}-${i}`, i, 'x'.repeat(100)]])
        );
    });
  let error = null;
  for (let n = 0; n < 1000 && !error; n++) error = await fill(n).catch(caught => caught);
  assert.equal(error?.class, 'full', String(error));
  assert.equal(db.pragma('max_page_count')[0].max_page_count, pages);
  // …until it is lifted.
  db.pragma('max_page_count=1000000');
  await fill('after');
  // Checkpoints, with their counters.
  const [passive] = db.pragma('wal_checkpoint(PASSIVE)');
  assert.deepEqual(Object.keys(passive).sort(), ['busy', 'checkpointed', 'log']);
  db.pragma('wal_checkpoint(TRUNCATE)');
  assert.equal(fs.statSync(`${db.file}-wal`).size, 0, 'the WAL is empty after TRUNCATE');
  // Anything else is refused, whatever it looks like.
  for (const text of [
    'journal_mode',
    'max_page_count=1; DROP TABLE items',
    'max_page_count = 5',
    'wal_checkpoint(FULL)',
    'writable_schema=1',
    'page_count;',
    '',
    null,
  ])
    assert.throws(() => db.pragma(text), GuardError, String(text));
  // Not inside a unit of work, and not after close().
  await assert.rejects(
    db.write(() => db.pragma('page_count')),
    GuardError
  );
  db.close();
  assert.throws(() => db.pragma('page_count'), { class: 'unavailable' });
});

// tx.onCommit (audit spec D4, §2.1 item 6): what a unit must do once and only after it committed
// (print a line, change memory) runs after COMMIT, with no unit current, in registration order.
test('onCommit order: callbacks run after COMMIT, in order, with no unit current, and may start a unit', async t => {
  const { db, file } = await withItems(t);
  // A second connection sees only what has committed.
  const other = openSqlite(file, { registry });
  t.after(() => other.close());
  const events = [];
  let nested = null,
    seen = null;
  const written = await db.write(tx => {
    tx.run(insert('a', 1));
    tx.onCommit(() => {
      events.push(`first: current ${db.inTransaction}`);
      // read() runs its unit synchronously when called: this is the committed state.
      seen = other.read(count);
    });
    tx.onCommit(() => {
      events.push('second');
      // A unit inside #unit would throw "units cannot be nested"; after it, this one runs.
      nested = db.write(next => next.run(insert('b', 2)));
    });
    tx.onCommit(() => events.push('third'));
    events.push('callback done');
    return 'result';
  });
  assert.equal(written, 'result');
  assert.deepEqual(events, ['callback done', 'first: current false', 'second', 'third']);
  assert.equal(await seen, 1, 'committed before the first callback ran');
  await nested;
  assert.equal(await db.read(count), 2);
  // A unit that fails never runs what it registered.
  await assert.rejects(
    db.write(tx => {
      tx.run(insert('c', 3));
      tx.onCommit(() => events.push('rolled back'));
      throw new Error('the change fails');
    }),
    /the change fails/
  );
  assert.equal(events.includes('rolled back'), false);
  assert.equal(await db.read(count), 2);
});

test('onCommit retry: an attempt run again after a retry drops what it registered', async t => {
  const { db } = await withItems(t);
  let runs = 0,
    calls = 0;
  await retryOnce(db).write(tx => {
    runs += 1;
    tx.run(insert('a', 1));
    tx.onCommit(() => (calls += 1));
  });
  assert.equal(runs, 2, 'the callback ran twice: the first attempt was rolled back');
  assert.equal(calls, 1, 'its commit callback ran once');
  assert.equal(await db.read(count), 1, 'the row was written once');
});

test('onCommit: a failing callback is reported once and never fails the unit that committed; read() refuses it', async t => {
  const { db } = await withItems(t);
  const reported = [];
  t.mock.method(console, 'error', (...args) => reported.push(args.join(' ')));
  const after = [];
  await db.write(tx => {
    tx.run(insert('a', 1));
    tx.onCommit(() => {
      throw Object.assign(new Error('a message that may quote a value'), { code: 'EXAMPLE' });
    });
    tx.onCommit(() => {
      throw new TypeError('no code');
    });
    tx.onCommit(() => Promise.reject(Object.assign(new Error('later'), { code: 'LATER' })));
    tx.onCommit(() => after.push('still ran'));
  });
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(reported, [
    'A commit callback failed: EXAMPLE',
    'A commit callback failed: TypeError',
    'A commit callback failed: LATER',
  ]);
  assert.deepEqual(after, ['still ran']);
  assert.equal(await db.read(count), 1);
  await assert.rejects(
    db.read(tx => tx.onCommit(() => {})),
    error => error instanceof GuardError && error.message === 'onCommit needs a write unit'
  );
  await assert.rejects(
    db.write(tx => tx.onCommit('not a function')),
    TypeError
  );
  // Like a statement, a registration after the callback returned is refused.
  let kept;
  await db.write(tx => (kept = tx));
  assert.throws(() => kept.onCommit(() => {}), GuardError);
});

test('a FIFO or a directory in place of a database is refused (78) before SQLite opens it, read-only included', t => {
  const sqliteModule = new URL('../../lib/db/sqlite.mjs', import.meta.url).href;
  for (const kind of ['fifo', 'directory']) {
    const file = path.join(temporary(t), 'control.sqlite');
    if (kind === 'fifo') assert.equal(spawnSync('mkfifo', [file]).status, 0);
    else fs.mkdirSync(file);
    // In a child with a deadline: a read-only (immutable) open of a FIFO waited for a writer for
    // good, and a read-write one failed as a disk error, which a restart retried for ever.
    const child = spawnSync(
      process.execPath,
      [
        '--input-type=module',
        '-e',
        `import assert from 'node:assert/strict';
         import * as sqlite from ${JSON.stringify(sqliteModule)};
         const file = process.argv[1];
         const refused = error => error.reason === 'not-file' && error.refusal === true && error.message === file + ' is not a regular file';
         assert.throws(() => sqlite.openSqlite(file, { readOnly: true }), refused);
         assert.throws(() => sqlite.openSqlite(file), refused);
         assert.throws(() => sqlite.quickCheck(file), refused);
         assert.throws(() => sqlite.settleDatabase(file), refused);
         await assert.rejects(sqlite.backupDatabase(file, file + '.copy'), refused);
         assert.equal(sqlite.databaseProblem(file), file + ' is not a regular file');`,
        file,
      ],
      { encoding: 'utf8', timeout: 5000, killSignal: 'SIGKILL' }
    );
    assert.equal(child.error, undefined, `${kind}: every call returns before the deadline`);
    assert.equal(child.status, 0, `${kind}: ${child.stderr}`);
    assert.equal(
      kind === 'fifo' ? fs.statSync(file).isFIFO() : fs.statSync(file).isDirectory(),
      true
    );
  }
});

test('a FIFO beside a database (its journal, WAL or index), or a link to nothing or a loop in its place, is refused before SQLite opens it', t => {
  const modules = {
    sqlite: new URL('../../lib/db/sqlite.mjs', import.meta.url).href,
    store: new URL('../../lib/store.mjs', import.meta.url).href,
    lock: new URL('../../lib/db/lock.mjs', import.meta.url).href,
  };
  const fifo = file => assert.equal(spawnSync('mkfifo', [file]).status, 0);
  // [what, the entry that is refused (relative to the database), make it, the refusal's text]
  const cases = [
    ...['-journal', '-wal', '-shm'].map(suffix => [
      `a FIFO ${suffix}`,
      suffix,
      fifo,
      'is not a regular file',
    ]),
    ['a -journal directory', '-journal', file => fs.mkdirSync(file), 'is not a regular file'],
    [
      'a -journal link to nothing',
      '-journal',
      file => fs.symlinkSync(`${file}.missing`, file),
      'is a symbolic link to nothing that exists',
    ],
    [
      'a database link to nothing',
      '',
      file => {
        fs.rmSync(file);
        fs.symlinkSync(path.join(path.dirname(file), 'unmounted', 'x.sqlite'), file);
      },
      'is a symbolic link to nothing that exists',
    ],
    [
      'a loop of links',
      '',
      file => {
        fs.rmSync(file);
        fs.symlinkSync(file, file);
      },
      'is not a regular file',
    ],
  ];
  for (const [what, suffix, make, problem] of cases) {
    const directory = temporary(t);
    // A real database in WAL mode, as Uptime Goblin leaves its own, so that SQLite does look beside it.
    for (const name of ['control.sqlite', 'history.sqlite', 'goblin.lock'])
      openSqlite(path.join(directory, name), { registry }).close();
    for (const name of ['control.sqlite', 'history.sqlite', 'goblin.lock'])
      make(path.join(directory, name) + suffix);
    // In a child with a deadline: an open that checked only the database itself waited for a
    // writer to the FIFO for good (holding goblin.lock at a start), or created a new database
    // through the link.
    const child = spawnSync(
      process.execPath,
      [
        '--input-type=module',
        '-e',
        `import assert from 'node:assert/strict';
         import path from 'node:path';
         import * as sqlite from ${JSON.stringify(modules.sqlite)};
         import { Store } from ${JSON.stringify(modules.store)};
         import { acquireLock } from ${JSON.stringify(modules.lock)};
         const [directory, suffix, problem] = process.argv.slice(1);
         const file = path.join(directory, 'control.sqlite');
         const message = file + suffix + ' ' + problem;
         const refused = error => error.refusal === true && error.message === message;
         assert.throws(() => sqlite.openSqlite(file, { readOnly: true }), refused);
         assert.throws(() => sqlite.openSqlite(file), refused);
         assert.throws(() => sqlite.quickCheck(file), refused);
         assert.throws(() => sqlite.settleDatabase(file), refused);
         await assert.rejects(sqlite.backupDatabase(file, file + '.copy'), refused);
         assert.equal(sqlite.databaseProblem(file), message);
         const history = path.join(directory, 'history.sqlite') + suffix + ' ' + problem;
         assert.throws(() => new Store(directory), error => error.refusal === true && error.message === history);
         assert.throws(() => acquireLock(directory), error => error.refusal === true && error.message.includes(path.join(directory, 'goblin.lock') + suffix + ' ' + problem + '. Remove it with Uptime Goblin stopped'));`,
        directory,
        suffix,
        problem,
      ],
      { encoding: 'utf8', timeout: 8000, killSignal: 'SIGKILL' }
    );
    assert.equal(child.error, undefined, `${what}: every call returns before the deadline`);
    assert.equal(child.status, 0, `${what}: ${child.stderr}`);
    // Nothing was created through a link, or in place of what was there.
    assert.ok(!fs.existsSync(path.join(directory, 'unmounted')), what);
    assert.ok(!fs.existsSync(path.join(directory, 'control.sqlite.copy')), what);
  }
});

test('a read-write open tightens the database file to 0600, never the target of a symbolic link', t => {
  const directory = temporary(t);
  const target = path.join(directory, 'elsewhere.sqlite');
  new DatabaseSync(target).close();
  fs.chmodSync(target, 0o644);
  const link = path.join(directory, 'control.sqlite');
  fs.symlinkSync(target, link);
  openSqlite(link, { registry }).close();
  assert.equal(mode(target), 0o644, 'the link was followed by SQLite, not by chmod');
  const own = path.join(directory, 'own.sqlite');
  new DatabaseSync(own).close();
  fs.chmodSync(own, 0o644);
  openSqlite(own, { registry }).close();
  assert.equal(mode(own), 0o600);
});

test('a path that looks like a SQLite URI opens that literal path, mode 0600', t => {
  const directory = temporary(t);
  fs.mkdirSync(path.join(directory, 'X'));
  const modules = {
    sqlite: new URL('../../lib/db/sqlite.mjs', import.meta.url).href,
    store: new URL('../../lib/store.mjs', import.meta.url).href,
  };
  // In a child whose working directory is `directory`, under umask 022: a relative data
  // directory 'file:X' made SQLite open X/… (created 0644) while chmod looked for file:X/….
  const child = spawnSync(
    process.execPath,
    [
      '--input-type=module',
      '-e',
      `import fs from 'node:fs';
       process.umask(0o022);
       const sqlite = await import(${JSON.stringify(modules.sqlite)});
       const { Store } = await import(${JSON.stringify(modules.store)});
       fs.mkdirSync('file:X');
       sqlite.openSqlite('file:X/control.sqlite').close();
       sqlite.openSqlite('file:X/q.sqlite?mode=memory').close();
       new Store('file:X').close();
       sqlite.holdExclusive('file:X/goblin.lock').release();
       // The snapshot helpers too: the backup wrote its copy to X/copy.sqlite (0644) and left
       // an empty database at the path the snapshot then hashed and kept.
       const { DatabaseSync } = await import('node:sqlite');
       const raw = new DatabaseSync(process.cwd() + '/file:X/control.sqlite');
       raw.exec('CREATE TABLE synthetic (x)');
       raw.close();
       await sqlite.backupDatabase('file:X/control.sqlite', 'file:X/copy.sqlite');
       sqlite.settleDatabase('file:X/copy.sqlite');
       if (sqlite.quickCheck('file:X/copy.sqlite') !== 'ok') throw new Error('quick_check');
       if (sqlite.databaseProblem('file:X/copy.sqlite') !== null) throw new Error('problem');`,
    ],
    { cwd: directory, encoding: 'utf8', timeout: 10000 }
  );
  assert.equal(child.status, 0, child.stderr);
  assert.deepEqual(fs.readdirSync(path.join(directory, 'X')), [], 'nothing opened through a URI');
  const literal = path.join(directory, 'file:X');
  for (const name of ['control.sqlite', 'history.sqlite'])
    assert.equal(mode(path.join(literal, name)), 0o600, name);
  // The copy is the database copied, at the literal path.
  const copy = new DatabaseSync(path.join(literal, 'copy.sqlite'), { readOnly: true });
  t.after(() => copy.close());
  assert.deepEqual(
    copy
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
      .all()
      .map(row => row.name),
    ['synthetic']
  );
  assert.ok(fs.statSync(path.join(literal, 'q.sqlite?mode=memory')).isFile());
  assert.ok(fs.statSync(path.join(literal, 'goblin.lock')).isFile());
});

test('connections run with trusted_schema off: a planted trigger may use only innocuous functions and tables', async t => {
  const { db, file } = await withItems(t);
  // A trigger in the file runs under Uptime Goblin's own writes. With trusted_schema on, it could read
  // the pragma tables (here the files the connection has open, copied into a row); off, only
  // what SQLite marks innocuous (Uptime Goblin's schema uses length() and json_valid(), nothing else).
  db.close();
  const raw = new DatabaseSync(file);
  raw.exec(
    'CREATE TRIGGER planted AFTER INSERT ON items BEGIN UPDATE items SET note = (SELECT group_concat(file) FROM pragma_database_list) WHERE k = new.k; END'
  );
  raw.close();
  const reopened = openSqlite(file, { registry });
  t.after(() => reopened.close());
  await assert.rejects(
    reopened.write(tx => tx.run(tx.dialect.insert('items', ['k', 'v'], [['a', 1]]))),
    /unsafe use of virtual table "pragma_database_list"/
  );
  assert.equal(
    await reopened.read(tx => tx.get(sql`SELECT count(*) AS n FROM ${id('items')}`).n),
    0
  );
});

test('catalog() names a trigger whose catalog row spells its type another way, and every row that is not a table or an index as SQLite writes one', async t => {
  const { db, file } = await withItems(t);
  db.close();
  // SQLite builds each object from its row's SQL and compares the row's type without regard to
  // case and only up to a NUL: these three triggers run inside every write to items, and a
  // catalog that matched type = 'trigger' listed none of them, so a start, check-data and a
  // snapshot's verification passed them.
  const raw = new DatabaseSync(file);
  raw.exec('CREATE TABLE seen (name TEXT)');
  for (const name of ['upper', 'mixed', 'nul'])
    raw.exec(
      `CREATE TRIGGER ${name} AFTER INSERT ON items BEGIN INSERT INTO seen VALUES ('${name}'); END`
    );
  raw.exec(
    'CREATE TABLE disguised (x); CREATE TABLE lower (x); CREATE VIRTUAL TABLE spatial USING rtree(id, a, b)'
  );
  raw.close();
  const schema = new DatabaseSync(file, { defensive: false });
  schema.exec('PRAGMA writable_schema=ON');
  for (const [name, type] of [
    ['upper', "'TRIGGER'"],
    ['mixed', "'Trigger'"],
    ['nul', "'trigger' || char(0)"],
    ['disguised', "'TABLE'"],
  ])
    schema.exec(`UPDATE sqlite_master SET type = ${type} WHERE name = '${name}'`);
  schema.exec("UPDATE sqlite_master SET sql = 'create table lower (x)' WHERE name = 'lower'");
  schema.exec('PRAGMA writable_schema=OFF');
  schema.close();
  const reopened = openSqlite(file, { registry });
  t.after(() => reopened.close());
  await reopened.write(tx => tx.run(insert('a', 1)));
  const check = new DatabaseSync(file, { readOnly: true });
  try {
    assert.deepEqual(
      check
        .prepare('SELECT name FROM seen')
        .all()
        .map(row => row.name)
        .sort(),
      ['mixed', 'nul', 'upper'],
      'each disguised trigger ran'
    );
  } finally {
    check.close();
  }
  const catalog = await reopened.catalog();
  assert.deepEqual(catalog.triggers, []);
  assert.deepEqual(catalog.views, []);
  assert.deepEqual(
    catalog.tables.filter(name => !name.startsWith('spatial_')),
    ['items', 'seen']
  );
  assert.deepEqual(catalog.others, [
    { type: 'TABLE', name: 'disguised' },
    { type: 'table', name: 'lower' },
    { type: 'Trigger', name: 'mixed' },
    { type: 'trigger\u0000', name: 'nul' },
    { type: 'table', name: 'spatial' },
    { type: 'TRIGGER', name: 'upper' },
  ]);
  assert.deepEqual(plantedObjects(catalog), [
    'catalog entry disguised of type "TABLE"',
    'catalog entry lower of type "table"',
    'catalog entry mixed of type "Trigger"',
    'catalog entry nul of type "trigger\\u0000"',
    'catalog entry spatial of type "table"',
    'catalog entry upper of type "TRIGGER"',
  ]);
  // Each kind as SQLite writes it, and nothing else.
  for (const [row, kind] of [
    [{ type: 'table', sql: 'CREATE TABLE t (x)' }, 'table'],
    [{ type: 'index', sql: 'CREATE INDEX i ON t(x)' }, 'index'],
    [{ type: 'index', sql: 'CREATE UNIQUE INDEX i ON t(x)' }, 'index'],
    [{ type: 'index', sql: null }, 'index'],
    [{ type: 'trigger', sql: 'create trigger x …' }, 'trigger'],
    [{ type: 'view', sql: 'CREATE VIEW v AS SELECT 1' }, 'view'],
    [{ type: 'table', sql: null }, null],
    [{ type: 'table', sql: 'CREATE VIRTUAL TABLE v USING rtree(id, a, b)' }, null],
    [{ type: 'table', sql: ' CREATE TABLE t (x)' }, null],
    [{ type: 'index', sql: '' }, null],
    [{ type: 'INDEX', sql: 'CREATE INDEX i ON t(x)' }, null],
    [{ type: 'VIEW', sql: 'CREATE VIEW v AS SELECT 1' }, null],
    [{ type: null, sql: 'CREATE TABLE t (x)' }, null],
    [{ type: new Uint8Array([116]), sql: 'CREATE TABLE t (x)' }, null],
  ])
    assert.equal(catalogKind(row), kind, JSON.stringify(row));
});
