// Do the platform and state repositories of 1.5 build statements every engine can take? Each
// scenario below drives one repository's operations on a render-only Db (helpers/render-db.mjs)
// for SQLite, PostgreSQL and SQL Server: every statement is rendered with the registry's
// identifier allowlist and checked for syntax only SQLite has.
//
// All three are gating. SQLite is the engine 1.5 executes; PostgreSQL and SQL Server are only
// rendered here, and a statement of these repositories that does not render on one, or names
// syntax only SQLite has, fails the test, with a diagnostic naming each such statement it
// reaches (an operation stops at its first statement that does not render). This is not the
// SQL Server contract job of roadmap §10.7, item 5c, which runs the platform DAOs on a real
// server and is non-gating (new DAOs are gated on SQL Server from 1.6; PostgreSQL arrives in
// 1.7).
import test from 'node:test';
import assert from 'node:assert/strict';
import { sql, id } from '../../lib/db/sql.mjs';
import { loadDialect, DIALECTS } from '../../lib/db/dialect/index.mjs';
import { createRenderDb, SQLITE_ONLY } from './helpers/render-db.mjs';
import { registry } from '../../lib/db/registry.mjs';
import {
  metaOps,
  createKeyringStore,
  createSettingsStore,
  createJobsStore,
} from '../../lib/db/control.mjs';
import { requireRelease } from '../../lib/db/migrate.mjs';
import { createEvents } from '../../lib/repo/state/events.mjs';
import { createAlerts } from '../../lib/repo/state/alerts.mjs';

const dialects = Object.fromEntries(
  await Promise.all(
    DIALECTS.map(async name => [
      name,
      await loadDialect(name, { identifiers: registry.identifiers }),
    ])
  )
);

// Answers that let each operation reach its later statements: a table that exists (asked of
// SQLite's catalog or through dialect.catalog), a count, an existing fence to raise.
const respond = ({ kind, text }) => {
  if (kind === 'get' && /sqlite_master|AS present/.test(text))
    return { name: 'keyring', present: 1 };
  if (kind === 'get' && /COUNT\(\*\)/.test(text)) return { count: 0 };
  if (kind === 'get' && /min_release/.test(text)) return { min_release: '1.5.0' };
  return undefined;
};

const alertRow = {
  service: 'web',
  rule: 'cpu',
  state: 'firing',
  since: 1,
  count: 2,
  message: 'CPU above 90 %',
  updated: 3,
};

/** [owner lane, module, name, run(db)]: each runs every operation of one repository. */
const scenarios = [
  [
    'P',
    'lib/db/control.mjs',
    'meta',
    db =>
      db.write(tx => {
        metaOps.get(tx, 'instance_id');
        metaOps.set(tx, 'last_version', '1.5.0', 1);
        metaOps.setIfAbsent(tx, 'credentials_ever', '1', 1);
        metaOps.bumpSessionSeq(tx, 1);
      }),
  ],
  [
    'P',
    'lib/db/control.mjs',
    'keyring',
    async db => {
      const store = createKeyringStore(db);
      await store.list();
      await store.exists();
      await store.save({
        clear: true,
        rewrap: [{ kid: 'k1', wrapped: 'w2' }],
        retire: [{ kid: 'k0', retired_at: 2 }],
        insert: [{ kid: 'k2', purpose: 'data', wrapped: 'w', created_at: 1 }],
      });
    },
  ],
  [
    'P',
    'lib/db/control.mjs',
    'settings',
    async db => {
      const store = createSettingsStore(db);
      const row = {
        component: 'alerting',
        key: 'policy',
        schema: 1,
        value: '{}',
        version: 2,
        updated_at: 1,
        updated_by: null,
      };
      await store.get('alerting', 'policy');
      await store.list();
      await store.list('alerting');
      await store.put(row, { ifVersion: 0 });
      await store.put(row, { ifVersion: 1 });
    },
  ],
  [
    'P',
    'lib/db/control.mjs',
    'jobs',
    async db => {
      const store = createJobsStore(db, () => 1);
      await store.record({ name: 'outbox.deliver', runs: 1, failures: 0, lastError: 'x' });
      await store.list();
    },
  ],
  [
    'P',
    'lib/db/migrate.mjs',
    'fences',
    db =>
      db.write(tx =>
        requireRelease(tx, {
          name: 'identity.totp',
          minRelease: '1.6.0',
          reason: 'TOTP enrolment',
          now: 1,
        })
      ),
  ],
  [
    'S',
    'lib/repo/state/events.mjs',
    'events',
    async db => {
      const events = createEvents({ db });
      await events.recent();
      await events.count();
      await events.append([{ service: 'web', time: 1, kind: 'alert', message: 'm' }]);
      await events.applyRetention({ retentionDays: 1, now: 10 * 86400000 });
      await events.eraseTarget('web');
    },
  ],
  [
    'S',
    'lib/repo/state/alerts.mjs',
    'alerts',
    async db => {
      const alerts = createAlerts({ db, events: createEvents({ db }) });
      await alerts.firing();
      await alerts.countFiring();
      await alerts.forService('web');
      await alerts.transition('web', () => ({
        alerts: [alertRow],
        events: [{ service: 'web', time: 1, kind: 'alert', message: 'm' }],
      }));
      await alerts.reconcileRules(
        'web',
        [
          { key: 'cpu', operator: '>', threshold: 90, forSeconds: 0, recoveryThreshold: 80 },
          { key: 'mem', operator: '>', threshold: 90, forSeconds: 0 },
        ],
        [{ key: 'cpu', operator: '>', threshold: 90, forSeconds: 0, recoveryThreshold: 70 }]
      );
      await alerts.clear('web');
      await alerts.clearAll();
    },
  ],
];

/** Runs each scenario on `engine`: [{owner, module, name, statements, problems}]. */
async function runAll(engine, list = scenarios) {
  const results = [];
  for (const [owner, module, name, run] of list) {
    const db = createRenderDb(dialects[engine], { respond, clock: () => 1 });
    try {
      await run(db);
    } catch (error) {
      // An operation stopped: by a statement that did not render (already recorded) or by
      // something else, which is recorded here.
      if (!db.problems.some(problem => problem.message === error.message))
        db.problems.push({ unit: null, kind: 'throw', message: error.message });
    }
    results.push({ owner, module, name, statements: db.statements, problems: db.problems });
  }
  return results;
}

/**
 * Judges one server engine's results. Every statement that does not port gets its diagnostic
 * before anything is asserted, so a scenario stopped by its first statement is named by that
 * statement; then any finding fails, then a scenario that issued no statement at all.
 */
function judge(t, engine, results) {
  const findings = results.flatMap(result =>
    result.problems.map(
      problem =>
        `lane ${result.owner} ${result.module} (${result.name}): ${problem.message}${
          problem.text ? ` in: ${problem.text}` : ''
        }`
    )
  );
  const rendered = results.reduce((sum, result) => sum + result.statements.length, 0);
  t.diagnostic(`${rendered} statements rendered for ${engine}`);
  for (const finding of findings) t.diagnostic(finding);
  assert.deepEqual(findings, [], `${findings.length} statement(s) do not port to ${engine}`);
  for (const result of results)
    assert.ok(result.statements.length >= 1, `${result.name} issued no statement`);
  assert.ok(rendered > results.length, 'the scenarios reached the database');
}

test('the render-only Db renders, records and answers like a Db, and flags what does not port', async () => {
  const ms = createRenderDb(dialects.mssql, {
    respond: ({ kind }) => (kind === 'get' ? { value: 'x' } : undefined),
  });
  const value = await ms.read(tx =>
    tx.get(sql`SELECT ${id('value')} FROM ${id('meta')} WHERE ${id('key')} = ${'k'}`)
  );
  assert.deepEqual(value, { value: 'x' });
  assert.deepEqual(ms.statements, [
    {
      unit: 'read',
      kind: 'get',
      text: 'SELECT [value] FROM [meta] WHERE [key] = @p1',
      params: ['k'],
    },
  ]);
  assert.deepEqual(await ms.write(tx => tx.run(sql`DELETE FROM ${id('meta')}`)), {
    changes: 1,
    lastInsertRowid: 1,
  });
  // limit() without orderBy() cannot render on SQL Server: recorded, and thrown as it would be.
  await assert.rejects(
    ms.read(tx => tx.all(sql`SELECT ${id('kid')} FROM ${id('keyring')} ${ms.dialect.limit(1)}`)),
    /needs orderBy\(\) before limit\(\)/
  );
  // An identifier outside the registry is refused on every engine.
  await assert.rejects(
    ms.read(tx => tx.all(sql`SELECT 1 FROM ${id('nowhere')}`)),
    /not in the table registry/
  );
  // SQLite's catalog renders, but no server has it.
  await ms.read(tx => tx.get(sql`SELECT name FROM sqlite_master WHERE type = ${'table'}`));
  assert.deepEqual(
    ms.problems.map(problem => `${problem.unit} ${problem.kind}: ${problem.message}`),
    [
      'read all: SQL Server needs orderBy() before limit() (OFFSET … FETCH)',
      'read all: nowhere is not in the table registry',
      'read get: names SQLite-only syntax',
    ]
  );
  await assert.rejects(
    ms.write(() => ms.read(() => 1)),
    /units do not nest/
  );
  const inserted = await createRenderDb(dialects.postgres).bulkInsert(
    'meta',
    ['key', 'value', 'updated_at'],
    [
      ['a', 'b'],
      ['1', '2'],
      [1, 2],
    ],
    { onConflict: 'ignore' }
  );
  assert.equal(inserted, 1, 'one statement, one (default) change');
  for (const text of ['PRAGMA user_version', 'INSERT OR IGNORE INTO t', 'SELECT unixepoch()'])
    assert.match(text, SQLITE_ONLY);
  for (const text of ['SELECT [value] FROM [meta]', 'INSERT INTO "t" ("a") VALUES ($1)'])
    assert.doesNotMatch(text, SQLITE_ONLY);
});

test('the platform and state repositories build statements SQLite takes (gating)', async () => {
  for (const result of await runAll('sqlite')) {
    assert.deepEqual(result.problems, [], `${result.module} ${result.name}`);
    assert.ok(result.statements.length >= 1, `${result.name} issued no statement`);
    for (const { text } of result.statements) assert.doesNotMatch(text, /\$\d|@p\d|\[\w+\]/);
  }
});

test('a statement that does not port is named, also when it is the first its operation issues', async () => {
  const keyring = sql`SELECT ${id('kid')} FROM ${id('keyring')}`;
  // On SQL Server: an operation stopped by its first statement (limit() without orderBy() does
  // not render there), one whose only statement renders but reads SQLite's catalog, and one whose
  // three statements port, so more statements rendered than there are operations.
  const stopped = [
    'P',
    'lib/db/control.mjs',
    'first',
    db => db.read(tx => tx.all(sql`${keyring} ${tx.dialect.limit(1)}`)),
  ];
  const catalog = [
    'S',
    'lib/repo/state/events.mjs',
    'catalog',
    db => db.read(tx => tx.get(sql`SELECT name FROM sqlite_master WHERE type = ${'table'}`)),
  ];
  const ports = [
    'P',
    'lib/db/control.mjs',
    'ports',
    db => db.read(tx => [1, 2, 3].map(() => tx.all(keyring))),
  ];
  const diagnostics = [];
  const record = { diagnostic: line => diagnostics.push(line) };
  const results = await runAll('mssql', [stopped, catalog, ports]);
  assert.throws(() => judge(record, 'mssql', results), /2 statement\(s\) do not port to mssql/);
  assert.deepEqual(diagnostics, [
    '4 statements rendered for mssql',
    'lane P lib/db/control.mjs (first): SQL Server needs orderBy() before limit() (OFFSET … FETCH)',
    'lane S lib/repo/state/events.mjs (catalog): names SQLite-only syntax in: SELECT name FROM sqlite_master WHERE type = @p1',
  ]);
  // When every statement ports, an operation that issued none still fails, by its name.
  diagnostics.length = 0;
  const silent = ['P', 'lib/db/control.mjs', 'silent', async () => {}];
  const quiet = await runAll('mssql', [silent, ports, ports]);
  assert.throws(() => judge(record, 'mssql', quiet), /silent issued no statement/);
  assert.deepEqual(diagnostics, ['6 statements rendered for mssql']);
});

for (const engine of ['postgres', 'mssql'])
  test(`the platform and state repositories build statements ${engine} takes (gating)`, async t =>
    judge(t, engine, await runAll(engine)));
