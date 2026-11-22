// The migration runner (lib/db/migrate.mjs): step rules, ordering, one unit per step, crash
// safety, refusals that write nothing, fences and background data steps.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import {
  compareReleases,
  parseRelease,
  isMajorRelease,
  validateSteps,
  orderSteps,
  defineSteps,
  createMigrator,
  requireRelease,
  RefusalError,
  MigrationError,
} from '../../lib/db/migrate.mjs';
import { openSqlite } from '../../lib/db/sqlite.mjs';
import { sql, id } from '../../lib/db/sql.mjs';
import { text, bigint } from '../../lib/db/dialect/schema.mjs';
import {
  createRegistry,
  defineTable,
  platformTables,
  legacyHistoryTables,
} from '../../lib/db/registry.mjs';
import { temporary, fingerprint } from './helpers.mjs';
import * as crash from './fixtures/crash-steps.mjs';

const testTable = (name, columns = { k: text(32), v: bigint() }) =>
  defineTable(name, {
    component: 'test',
    lane: 'P',
    class: 'control',
    db: 'control',
    backup: 'never',
    since: '1.5.0',
    columns,
    primaryKey: [Object.keys(columns)[0]],
  });
const alpha = testTable('alpha'),
  beta = testTable('beta'),
  counter = testTable('counter', { name: text(32), n: bigint() });
const registry = createRegistry([...platformTables, ...legacyHistoryTables, alpha, beta, counter]);

const step = (idText, extra = {}) => ({
  id: idText,
  component: idText.split('-')[0],
  kind: 'expand',
  db: 'control',
  up: () => {},
  ...extra,
});
const rows = (tx, table) => tx.all(sql`SELECT * FROM ${id(table)}`);
const applied = db =>
  db.read(tx => tx.all(sql`SELECT ${id('id')}, ${id('release')} FROM ${id('schema_migrations')}`));

function open(t, file) {
  const db = openSqlite(file, { registry });
  t.after(() => db.close());
  return db;
}
const baseSteps = [
  step('platform-001-fences', { up: { createTables: ['schema_fences'] } }),
  step('test-001-alpha', { up: { createTables: ['alpha'] } }),
  step('test-002-beta', { up: { createTables: ['beta'] } }),
];

test('releases compare as semantic versions; only x.0.0 is a major release', () => {
  assert.deepEqual(parseRelease('1.5.0-rc.1'), [1, 5, 0, ['rc', '1']]);
  assert.throws(() => parseRelease('1.5'), TypeError);
  const ordered = [
    '1.4.2',
    '1.4.10',
    '1.5.0-alpha',
    '1.5.0-alpha.1',
    '1.5.0-alpha.beta',
    '1.5.0-beta.2',
    '1.5.0-beta.11',
    '1.5.0-rc.1',
    '1.5.0',
    '2.0.0',
  ];
  for (let i = 1; i < ordered.length; i += 1) {
    assert.ok(compareReleases(ordered[i - 1], ordered[i]) < 0, `${ordered[i - 1]} < ${ordered[i]}`);
    assert.ok(compareReleases(ordered[i], ordered[i - 1]) > 0);
  }
  assert.equal(compareReleases('1.5.0', '1.5.0'), 0);
  assert.equal(isMajorRelease('2.0.0'), true);
  assert.equal(isMajorRelease('2.0.0-rc.1'), true);
  assert.equal(isMajorRelease('1.5.0'), false);
  assert.equal(isMajorRelease('2.0.1'), false);
});

test('validateSteps enforces ids, numbering, kinds, dialect coverage, the DAG and contract-only-in-majors', () => {
  const problems = steps => validateSteps(steps, { release: '1.5.0', registry });
  assert.deepEqual(problems(baseSteps), []);
  const cases = [
    [[step('Bad-001-x')], /must be <component>-<nnn>-<slug>/],
    [[step('test-001-a'), step('test-001-a')], /used twice/],
    [[step('test-001-a'), step('test-003-c')], /without gaps/],
    [[step('test-002-b')], /without gaps/],
    [[{ ...step('test-001-a'), component: 'other' }], /component must be test/],
    [[step('test-001-a', { kind: 'shrink' })], /kind must be/],
    [[step('test-001-a', { db: 'history' })], /db must be control\|state\|series/],
    [[step('test-001-a', { modes: ['solo'] })], /modes must be/],
    [[step('test-001-a', { after: ['test-009-nope'] })], /unknown step test-009-nope/],
    [[step('test-001-a', { kind: 'contract' })], /must name the major release that introduced it/],
    [
      [step('test-001-a', { kind: 'contract', since: '1.5.0' })],
      /cannot be introduced in 1\.5\.0, which is not a major release/,
    ],
    [
      [step('test-001-a', { kind: 'contract', since: '2.0.0' })],
      /introduced in 2\.0\.0, later than this release \(1\.5\.0\)/,
    ],
    [[step('test-001-a', { since: '2.0' })], /since must be the release that introduced the step/],
    [[step('test-001-a', { up: { sqlite() {} } })], /up has no postgres, mssql version/],
    [
      [step('test-001-a', { modes: ['cluster'], up: { postgres() {} } })],
      /up has no mssql version/,
    ],
    [
      [step('test-001-a', { up: { sqlite() {}, postgres() {}, mssql() {}, oracle() {} } })],
      /up\.oracle is not an engine/,
    ],
    [
      [step('test-001-a', { up: { createTables: ['nowhere'] } })],
      /nowhere is not a registered table/,
    ],
    [[step('test-001-a', { up: { createTables: ['readings'] } })], /hand-written 1\.x table/],
    [
      [step('test-001-a', { db: 'series', up: { createTables: ['alpha'] } })],
      /alpha is a control table, not series/,
    ],
    [
      [step('test-001-a', { kind: 'data', up: { createTables: ['alpha'] } })],
      /data step cannot create tables/,
    ],
    [[step('test-001-a', { up: 7 })], /up must be/],
    [
      [
        step('test-001-a', { after: ['other-001-b'] }),
        step('other-001-b', { after: ['test-001-a'] }),
      ],
      /form a cycle/,
    ],
    [
      [step('test-001-a', { kind: 'data' }), step('test-002-b', { after: ['test-001-a'] })],
      /an expand step cannot come after a data step/,
    ],
    // The same through numbering alone, which orderSteps() and runData() also follow.
    [
      [step('ordered-001-data', { kind: 'data' }), step('ordered-002-expand')],
      /step ordered-002-expand: an expand step cannot come after a data step/,
    ],
    [
      [
        step('ordered-001-data', { kind: 'data' }),
        step('ordered-002-more', { kind: 'data' }),
        step('ordered-003-drop', { kind: 'contract', since: '1.0.0' }),
      ],
      /step ordered-003-drop: a contract step cannot come after a data step/,
    ],
    [
      [
        step('ordered-001-data', { kind: 'data' }),
        step('other-001-x', { after: ['ordered-002-next'] }),
        step('ordered-002-next', { kind: 'data' }),
      ],
      /step other-001-x: an expand step cannot come after a data step/,
    ],
  ];
  for (const [steps, pattern] of cases)
    assert.ok(
      problems(steps).some(problem => pattern.test(problem)),
      `${pattern}: ${JSON.stringify(problems(steps))}`
    );
  // A contract step introduced in a major release stays valid in every later release that
  // carries it in its history (2.0.1 must not be blocked by the 2.0.0 step it inherited).
  const contract = step('test-001-a', { kind: 'contract', since: '2.0.0' });
  for (const release of ['2.0.0-rc.1', '2.0.0', '2.0.1', '2.1.0', '3.0.0'])
    assert.deepEqual(validateSteps([contract], { release, registry }), [], release);
  assert.deepEqual(
    validateSteps([step('test-001-a', { kind: 'contract', since: '2.0.0-rc.1' })], {
      release: '2.0.0',
      registry,
    }),
    []
  );
  assert.ok(
    validateSteps([step('test-001-a', { kind: 'contract', since: '2.0.1' })], {
      release: '2.0.1',
      registry,
    }).some(problem => /not a major release/.test(problem)),
    'a new contract step cannot appear in a patch release'
  );
  assert.throws(() => defineSteps([step('test-002-b')]), MigrationError);
  const defined = defineSteps([step('test-001-a')]);
  assert.ok(Object.isFrozen(defined[0]));
  assert.deepEqual(
    [defined[0].after, defined[0].modes, defined[0].online],
    [[], ['single', 'cluster'], true]
  );
});

test('orderSteps follows `after` and numbering, whatever order the lanes merged in', () => {
  const steps = [
    step('platform-001-base'),
    step('platform-002-more'),
    step('identity-001-users', { after: ['platform-002-more'] }),
    step('identity-002-sessions'),
    step('alerting-001-outbox', { after: ['identity-001-users'] }),
    step('ops-001-sessions'),
  ];
  const expected = orderSteps(steps).map(item => item.id);
  const position = name => expected.indexOf(name);
  assert.ok(position('platform-002-more') < position('identity-001-users'));
  assert.ok(position('identity-001-users') < position('identity-002-sessions'));
  assert.ok(position('identity-001-users') < position('alerting-001-outbox'));
  assert.ok(position('platform-001-base') < position('platform-002-more'));
  for (let round = 0; round < 20; round += 1) {
    const shuffled = [...steps].sort(() => Math.random() - 0.5);
    assert.deepEqual(
      orderSteps(shuffled).map(item => item.id),
      expected
    );
  }
});

test('migrate applies each pending step once, in its own unit, and records it with the release', async t => {
  const directory = temporary(t);
  const db = open(t, path.join(directory, 'control.sqlite'));
  const migrator = createMigrator({
    db,
    classes: ['control'],
    steps: baseSteps,
    release: '1.5.0',
    registry,
    clock: () => 7,
  });
  const before = await migrator.inspect();
  assert.deepEqual(
    before.pending.map(item => item.id),
    ['platform-001-fences', 'test-001-alpha', 'test-002-beta']
  );
  assert.equal(before.refusal, null);
  const plan = await migrator.plan();
  assert.match(plan.steps[1].ddl[0], /^CREATE TABLE "alpha"/);
  const progress = [];
  const result = await migrator.migrate({ onProgress: item => progress.push(item) });
  assert.deepEqual(result, {
    applied: ['platform-001-fences', 'test-001-alpha', 'test-002-beta'],
    pendingData: [],
  });
  assert.deepEqual(
    progress.map(item => [item.index, item.total]),
    [
      [0, 3],
      [1, 3],
      [2, 3],
    ]
  );
  assert.deepEqual(
    (await applied(db)).map(row => [row.id, row.release]),
    result.applied.map(item => [item, '1.5.0'])
  );
  assert.deepEqual(await migrator.migrate(), { applied: [], pendingData: [] });
  // A later release adds a step; only it runs.
  const next = createMigrator({
    db,
    classes: ['control'],
    steps: [
      ...baseSteps,
      step('test-003-seed', {
        after: ['test-001-alpha'],
        up: tx => tx.run(tx.dialect.insert('alpha', ['k', 'v'], [['seeded', 1]])),
      }),
    ],
    release: '1.6.0',
    registry,
  });
  assert.deepEqual((await next.migrate()).applied, ['test-003-seed']);
  assert.equal((await db.read(tx => rows(tx, 'alpha'))).length, 1);
  // Steps of other store classes or modes are not this database's.
  const other = createMigrator({
    db,
    classes: ['control'],
    steps: [
      ...baseSteps,
      step('scale-001-series', { db: 'series', up: () => assert.fail('not here') }),
      step('test-003-cluster', { modes: ['cluster'], up: { postgres() {}, mssql() {} } }),
    ],
    release: '1.5.0',
    registry,
  });
  assert.deepEqual((await other.inspect()).pending, []);
  await assert.rejects(
    createMigrator({
      db,
      classes: ['control'],
      steps: [step('test-001-a', { up: async () => {} })],
      release: '1.5.0',
      registry,
    }).migrate(),
    MigrationError
  );
});

// Wraps a Db so the transaction fails at its k-th statement (DDL, a step's own statements and
// the schema_migrations row alike), as a crash there would.
function failing(db, at) {
  let statements = 0;
  const trap = () => {
    if (statements++ === at) throw new Error(`crash at statement ${at}`);
  };
  return {
    name: db.name,
    dialect: db.dialect,
    read: fn => db.read(fn),
    write: fn =>
      db.write(tx =>
        fn({
          dialect: tx.dialect,
          get: query => tx.get(query),
          all: query => tx.all(query),
          run: query => (trap(), tx.run(query)),
          ddl: statements => (trap(), tx.ddl(statements)),
        })
      ),
  };
}

test('a crash at any statement leaves each step wholly applied or not at all, and the next run resumes', async t => {
  const steps = [
    step('platform-001-fences', { up: { createTables: ['schema_fences'] } }),
    step('test-001-alpha', {
      up(tx, context) {
        tx.ddl(context.registry && (() => [])()); // no statement: exercises empty DDL
        for (const [k, v] of [
          ['a', 1],
          ['b', 2],
          ['c', 3],
        ])
          tx.run(tx.dialect.insert('counter', ['name', 'n'], [[k, v]]));
      },
    }),
    step('test-002-beta', { up: { createTables: ['beta'] } }),
  ];
  const withCounter = [
    step('platform-001-fences', { up: { createTables: ['schema_fences', 'counter'] } }),
    ...steps.slice(1),
  ];
  let total = null;
  for (let at = 0; total === null || at < total; at += 1) {
    const directory = temporary(t);
    const db = open(t, path.join(directory, 'control.sqlite'));
    const make = target =>
      createMigrator({
        db: target,
        classes: ['control'],
        steps: withCounter,
        release: '1.5.0',
        registry,
      });
    let failed = false;
    try {
      await make(failing(db, at)).migrate();
    } catch (error) {
      failed = true;
      assert.match(error.message, /crash at statement/);
    }
    const state = await make(db).inspect();
    const done = new Set(state.applied.map(row => row.id));
    // Atomic per step: the counter rows exist exactly when test-001 is recorded.
    const counted = await db.read(tx =>
      tx.get(sql`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'counter'`)
        ? rows(tx, 'counter').length
        : null
    );
    if (done.has('test-001-alpha')) assert.equal(counted, 3);
    else assert.ok(counted === null || counted === 0, `partial step left ${counted} rows`);
    const beta = await db.read(tx =>
      Boolean(tx.get(sql`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'beta'`))
    );
    assert.equal(beta, done.has('test-002-beta'));
    await make(db).migrate();
    assert.equal((await make(db).inspect()).pending.length, 0);
    assert.equal(await db.read(tx => rows(tx, 'counter').length), 3);
    if (!failed) total = at; // the first run that met no crash counted every statement
  }
  assert.ok(total >= 6, `exercised ${total} statements`);
});

test('kill -9 during migration: every restart resumes, and each step is all or nothing', async t => {
  const directory = temporary(t);
  const script = fileURLToPath(new URL('./fixtures/crash-steps.mjs', import.meta.url));
  // Runs the migration in a child; `killAfter(ms)` kills it that long after it starts migrating.
  const run = async (file, killAfter = null) => {
    const child = spawn(process.execPath, [script, file], { stdio: ['ignore', 'pipe', 'inherit'] });
    let output = '',
      timer = null;
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', chunk => {
      output += chunk;
      if (killAfter !== null && !timer && output.includes('start'))
        timer = setTimeout(() => child.kill('SIGKILL'), killAfter);
    });
    const [code, signal] = await once(child, 'exit');
    clearTimeout(timer);
    return { code, signal, output };
  };
  // How long a whole migration takes here, so kills land inside it.
  const reference = await run(path.join(directory, 'reference.sqlite'));
  assert.equal(reference.code, 0);
  const duration = Number(/done (\d+)/.exec(reference.output)[1]);
  // A run that finishes before any kill landed (a busy machine can make the reference slower
  // than the runs) proves nothing: start again on a fresh file with a shorter kill window.
  let fresh = 0,
    file = path.join(directory, `control-${fresh}.sqlite`),
    window = Math.max(2, duration * 0.8),
    kills = 0,
    finished = false;
  for (let attempt = 0; attempt < 120 && !finished; attempt += 1) {
    const result = await run(file, Math.floor(Math.random() * window));
    if (result.signal === 'SIGKILL') kills += 1;
    else {
      assert.equal(result.code, 0);
      if (kills) finished = true;
      else {
        fresh += 1;
        file = path.join(directory, `control-${fresh}.sqlite`);
        window = Math.max(1, window / 2);
      }
    }
  }
  assert.ok(finished, 'the migration completed after the kills');
  assert.ok(kills >= 1, 'at least one run was killed mid-way');
  const db = openSqlite(file, { registry: crash.registry });
  t.after(() => db.close());
  const done = new Set(
    (await db.read(tx => tx.all(sql`SELECT ${id('id')} FROM ${id('schema_migrations')}`))).map(
      row => row.id
    )
  );
  assert.equal(done.size, crash.count);
  for (const table of crash.tables)
    assert.equal(
      await db.read(tx => tx.get(sql`SELECT COUNT(*) AS n FROM ${id(table.name)}`).n),
      crash.rowsPerStep
    );
  assert.equal(await db.read(tx => tx.get(sql`PRAGMA integrity_check`).integrity_check), 'ok');
});

test('refusals: an unknown contract step or a newer fence refuses with exit 78 and writes nothing', async t => {
  const directory = temporary(t);
  const file = path.join(directory, 'control.sqlite');
  // Data written by a future 2.0.0 with a contract step this release does not know.
  const future = [
    ...baseSteps,
    step('test-003-drop', { kind: 'contract', since: '2.0.0' }),
    step('test-004-extra'),
  ];
  let db = openSqlite(file, { registry });
  await createMigrator({
    db,
    classes: ['control'],
    steps: future,
    release: '2.0.0',
    registry,
  }).migrate();
  db.close();
  const before = fingerprint(directory);
  db = open(t, file);
  const current = createMigrator({
    db,
    classes: ['control'],
    steps: baseSteps,
    release: '1.5.0',
    registry,
    snapshotHint: 'pre-upgrade-2.0.0-x',
  });
  const state = await current.inspect();
  assert.deepEqual(
    state.unknown.map(row => row.id),
    ['test-003-drop', 'test-004-extra']
  );
  assert.ok(state.refusal instanceof RefusalError);
  assert.equal(state.refusal.exitCode, 78);
  assert.equal(state.refusal.refusal, true);
  assert.equal(state.refusal.code, 'data_newer');
  assert.match(
    state.refusal.message,
    /changed by Uptime Goblin 2\.0\.0 \(migration test-003-drop\).*Install 2\.0\.0 or newer, or restore snapshot pre-upgrade-2\.0\.0-x/
  );
  // A command the operator can run as printed: there is no goblin-admin on the PATH.
  assert.ok(
    state.refusal.message.endsWith(
      'restore snapshot pre-upgrade-2.0.0-x with Uptime Goblin stopped: sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key node /opt/uptime-goblin/lib/cli/goblin-admin.mjs restore-snapshot pre-upgrade-2.0.0-x --data-dir /var/lib/uptime-goblin (the native install; Docker Compose and other installs: docs/installation.md#goblin-admin).'
    ),
    state.refusal.message
  );
  await assert.rejects(current.migrate(), RefusalError);
  db.close();
  assert.deepEqual(fingerprint(directory), before, 'a refusal changes no byte');

  // Unknown expand steps alone are tolerated.
  const tolerant = temporary(t);
  db = open(t, path.join(tolerant, 'control.sqlite'));
  await createMigrator({
    db,
    classes: ['control'],
    steps: [...baseSteps, step('test-003-add')],
    release: '1.6.0',
    registry,
  }).migrate();
  const older = createMigrator({
    db,
    classes: ['control'],
    steps: baseSteps,
    release: '1.5.0',
    registry,
  });
  assert.equal((await older.inspect()).refusal, null);
  assert.deepEqual(
    (await older.inspect()).unknown.map(row => row.id),
    ['test-003-add']
  );

  // A fence newer than this release refuses, naming the release and the reason.
  await db.write(tx =>
    requireRelease(tx, {
      name: 'identity.totp',
      minRelease: '1.6.0',
      reason: 'TOTP enrolment exists',
      now: 5,
    })
  );
  const refused = (await older.inspect()).refusal;
  assert.equal(refused.code, 'fence');
  assert.equal(
    refused.message,
    'This data needs Uptime Goblin ≥ 1.6.0 (TOTP enrolment exists). Install 1.6.0 or newer, or restore the snapshot taken before the upgrade with Uptime Goblin stopped; to list them: sudo -u uptime-goblin node /opt/uptime-goblin/lib/cli/goblin-admin.mjs snapshots --data-dir /var/lib/uptime-goblin (the native install; Docker Compose and other installs: docs/installation.md#goblin-admin).'
  );
  assert.equal(
    (await older.inspect({ snapshotHint: 'pre-upgrade-1.6.0-y' })).refusal.message.endsWith(
      'restore snapshot pre-upgrade-1.6.0-y with Uptime Goblin stopped: sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key node /opt/uptime-goblin/lib/cli/goblin-admin.mjs restore-snapshot pre-upgrade-1.6.0-y --data-dir /var/lib/uptime-goblin (the native install; Docker Compose and other installs: docs/installation.md#goblin-admin).'
    ),
    true
  );
  assert.equal(
    (
      await createMigrator({
        db,
        classes: ['control'],
        steps: baseSteps,
        release: '1.6.0',
        registry,
      }).inspect()
    ).refusal,
    null
  );
});

test('requireRelease raises a fence only upwards, inside the caller transaction', async t => {
  const db = open(t, path.join(temporary(t), 'control.sqlite'));
  await createMigrator({
    db,
    classes: ['control'],
    steps: baseSteps,
    release: '1.5.0',
    registry,
  }).migrate();
  const raise = (minRelease, reason = 'why') =>
    db.write(tx => requireRelease(tx, { name: 'scale.sourceCap', minRelease, reason, now: 1 }));
  assert.equal(await raise('1.6.0'), true);
  assert.equal(await raise('1.5.0'), false, 'never lowered');
  assert.equal(await raise('1.6.0'), false);
  assert.equal(await raise('1.7.0', 'more'), true);
  const fences = await db.read(tx => rows(tx, 'schema_fences'));
  assert.deepEqual(
    fences.map(row => [row.name, row.min_release, row.reason]),
    [['scale.sourceCap', '1.7.0', 'more']]
  );
  // It belongs to the caller's unit: a failure after it rolls it back.
  await assert.rejects(
    db.write(tx => {
      requireRelease(tx, { name: 'identity.localLogin', minRelease: '1.7.0', reason: 'x', now: 1 });
      throw new Error('feature failed');
    })
  );
  assert.equal((await db.read(tx => rows(tx, 'schema_fences'))).length, 1);
  for (const bad of [
    { name: 'NoDot', minRelease: '1.6.0', reason: 'x', now: 1 },
    { name: 'a.b', minRelease: '1.6', reason: 'x', now: 1 },
    { name: 'a.b', minRelease: '1.6.0', reason: '', now: 1 },
    { name: 'a.b', minRelease: '1.6.0', reason: 'x' },
  ])
    await assert.rejects(
      db.write(tx => requireRelease(tx, bad)),
      TypeError
    );
});

test('data steps run in chunks with their checkpoint, stop on abort and resume', async t => {
  const db = open(t, path.join(temporary(t), 'control.sqlite'));
  const chunks = [];
  const steps = [
    step('platform-001-fences', { up: { createTables: ['schema_fences', 'counter'] } }),
    step('test-001-backfill', {
      kind: 'data',
      up(tx, context) {
        chunks.push(context.chunk);
        const row = tx.get(
          sql`SELECT ${id('n')} FROM ${id('counter')} WHERE ${id('name')} = ${'done'}`
        );
        const n = (row?.n ?? 0) + 1;
        tx.run(tx.dialect.upsert('counter', ['name'], ['name', 'n'], [['done', n]]));
        return { done: n >= 5, progress: n / 5 };
      },
    }),
  ];
  const migrator = createMigrator({ db, classes: ['control'], steps, release: '1.5.0', registry });
  const result = await migrator.migrate();
  assert.deepEqual(result, {
    applied: ['platform-001-fences'],
    pendingData: ['test-001-backfill'],
  });
  const controller = new AbortController();
  const progress = [];
  const stopped = await migrator.runData('test-001-backfill', {
    signal: controller.signal,
    onProgress: item => {
      progress.push(item.progress);
      if (item.chunk === 1) controller.abort();
    },
  });
  assert.deepEqual(stopped, { done: false, chunks: 2 });
  assert.deepEqual(progress, [0.2, 0.4]);
  assert.deepEqual(
    (await migrator.inspect()).pendingData.map(item => item.id),
    ['test-001-backfill']
  );
  assert.deepEqual(await migrator.runData('test-001-backfill'), { done: true, chunks: 3 });
  assert.equal((await db.read(tx => rows(tx, 'counter')))[0].n, 5);
  assert.deepEqual((await migrator.inspect()).pendingData, []);
  assert.deepEqual(await migrator.runData('test-001-backfill'), { done: true, chunks: 1 });
  assert.equal(chunks.length, 5);
  await assert.rejects(migrator.runData('platform-001-fences'), MigrationError);
});

test('runData refuses, writing nothing, before its prerequisites or when a refusal or fence applies', async t => {
  const file = path.join(temporary(t), 'control.sqlite');
  const db = open(t, file);
  // Each data step adds one to its own counter row per chunk and finishes after `chunks`.
  const bump = (name, chunks = 1) =>
    function up(tx) {
      const n =
        (tx.get(sql`SELECT ${id('n')} FROM ${id('counter')} WHERE ${id('name')} = ${name}`)?.n ??
          0) + 1;
      tx.run(tx.dialect.upsert('counter', ['name'], ['name', 'n'], [[name, n]]));
      return { done: n >= chunks };
    };
  const steps = [
    step('platform-001-fences', { up: { createTables: ['schema_fences', 'counter'] } }),
    step('test-001-first', { kind: 'data', up: bump('first') }),
    step('test-002-second', { kind: 'data', up: bump('second') }),
    step('other-001-late', { kind: 'data', after: ['test-001-first'], up: bump('late') }),
    step('fenced-001-long', { kind: 'data', up: bump('long', 3) }),
  ];
  const make = (release = '1.5.0') =>
    createMigrator({ db, classes: ['control'], steps, release, registry });
  await make().migrate();
  const counters = () =>
    db.read(tx => Object.fromEntries(rows(tx, 'counter').map(row => [row.name, row.n])));
  const recorded = async () => (await applied(db)).map(row => row.id).sort();

  // Out of order: the component's earlier step, or an explicit `after` step, is not applied yet.
  await assert.rejects(make().runData('test-002-second'), {
    name: 'MigrationError',
    message: 'test-002-second cannot run before test-001-first is applied',
  });
  await assert.rejects(
    make().runData('other-001-late'),
    /other-001-late cannot run before test-001-first/
  );
  assert.deepEqual(await counters(), {});
  assert.deepEqual(await recorded(), ['platform-001-fences']);
  assert.deepEqual(await make().runData('test-001-first'), { done: true, chunks: 1 });
  assert.deepEqual(await make().runData('test-002-second'), { done: true, chunks: 1 });
  assert.deepEqual(await make().runData('other-001-late'), { done: true, chunks: 1 });

  // A fence naming a newer release refuses as inspect() does, and nothing is written.
  await db.write(tx =>
    requireRelease(tx, { name: 'future.thing', minRelease: '1.6.0', reason: 'newer data', now: 1 })
  );
  await assert.rejects(make().runData('fenced-001-long'), { name: 'RefusalError', code: 'fence' });
  assert.equal((await counters()).long, undefined);
  // The same release as the fence may run.
  const second = openSqlite(file, { registry });
  t.after(() => second.close());
  // A fence raised by another connection between two chunks stops the step before the next one.
  const progress = [];
  await assert.rejects(
    make('1.6.0').runData('fenced-001-long', {
      onProgress: item => {
        progress.push(item.chunk);
        // write() runs its unit synchronously when nothing else holds the database.
        if (item.chunk === 0)
          second.write(tx =>
            requireRelease(tx, {
              name: 'future.other',
              minRelease: '1.7.0',
              reason: 'later',
              now: 2,
            })
          );
      },
    }),
    { name: 'RefusalError', code: 'fence', minRelease: '1.7.0' }
  );
  assert.deepEqual(progress, [0], 'no chunk ran after the fence appeared');
  assert.equal(
    (await counters()).long,
    1,
    'the committed first chunk stays; the step is not recorded'
  );
  assert.ok(!(await recorded()).includes('fenced-001-long'));

  // An applied contract step this release does not know refuses too.
  await db.write(tx =>
    tx.run(
      tx.dialect.insert(
        'schema_migrations',
        ['id', 'component', 'kind', 'release', 'applied_at'],
        [['zzz-001-drop', 'zzz', 'contract', '2.0.0', 3]]
      )
    )
  );
  await assert.rejects(make('1.7.0').runData('fenced-001-long'), {
    name: 'RefusalError',
    code: 'data_newer',
  });
  assert.equal((await counters()).long, 1);
});

test('createTables adopts an identical table created earlier and refuses one that drifted', async t => {
  const db = open(t, path.join(temporary(t), 'control.sqlite'));
  await db.write(tx => tx.ddl(['CREATE TABLE "alpha" ("k" TEXT PRIMARY KEY, "v" INTEGER)']));
  const migrator = createMigrator({
    db,
    classes: ['control'],
    steps: baseSteps,
    release: '1.5.0',
    registry,
  });
  assert.deepEqual(
    (await migrator.migrate()).applied,
    baseSteps.map(item => item.id)
  );
  const drifted = open(t, path.join(temporary(t), 'control.sqlite'));
  await drifted.write(tx =>
    tx.ddl(['CREATE TABLE "beta" ("k" TEXT PRIMARY KEY, "other" INTEGER)'])
  );
  await assert.rejects(
    createMigrator({
      db: drifted,
      classes: ['control'],
      steps: baseSteps,
      release: '1.5.0',
      registry,
    }).migrate(),
    /beta exists with columns k, other, not the registered k, v/
  );
});

test('a fence or contract row a damaged or crafted database holds is named in the refusal without control characters, and cut', async t => {
  const directory = temporary(t);
  const db = open(t, path.join(directory, 'control.sqlite'));
  const migrator = createMigrator({
    db,
    classes: ['control'],
    steps: baseSteps,
    release: '1.5.0',
    registry,
  });
  await migrator.migrate();
  // Rows written past requireRelease (which takes only release names): what a start prints.
  await db.write(tx =>
    tx.run(
      tx.dialect.insertIgnore(
        'schema_fences',
        ['name', 'min_release', 'reason', 'set_at'],
        [
          [
            'f',
            '9.9.9\u001b[2J',
            'x\u001b[2J\n[orbit] Uptime Goblin is ready SYNTH-FENCE' + 'R'.repeat(400),
            1,
          ],
        ]
      )
    )
  );
  const fence = (await migrator.inspect()).refusal;
  assert.equal(fence.code, 'fence');
  assert.ok(!/[\u0000-\u001f\u007f-\u009f]/.test(fence.message), JSON.stringify(fence.message));
  assert.ok(
    fence.message.startsWith(
      `This data needs Uptime Goblin ≥ 9.9.9[2J (${`x[2J[orbit] Uptime Goblin is ready SYNTH-FENCE${'R'.repeat(400)}`.slice(0, 200)}). Install 9.9.9[2J or newer`
    ),
    fence.message
  );
  assert.equal(fence.minRelease, '9.9.9\u001b[2J', 'the error keeps the value as stored');
  await db.write(tx =>
    tx.run(
      tx.dialect.insertIgnore(
        'schema_migrations',
        ['id', 'component', 'kind', 'release', 'applied_at'],
        [['test-009-x\u001b[31m', 'test', 'contract', '2.0.0\n[orbit] FORGED', 1]]
      )
    )
  );
  const contract = (await migrator.inspect()).refusal;
  assert.equal(contract.code, 'data_newer');
  assert.ok(
    !/[\u0000-\u001f\u007f-\u009f]/.test(contract.message),
    JSON.stringify(contract.message)
  );
  assert.match(
    contract.message,
    /^This data was changed by Uptime Goblin 2\.0\.0\[orbit\] FORGED \(migration test-009-x\[31m\)/
  );
});
