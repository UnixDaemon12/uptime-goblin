// The table registry (lib/db/registry.mjs): one owner per table and index, validated metadata,
// the identifier allowlist and the lists generated from it (backup, transfer, drift).
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import {
  registry,
  createRegistry,
  defineTable,
  defineLegacyTable,
  platformTables,
  identityTables,
  alertingTables,
  auditTables,
  legacyHistoryTables,
  summaryHistoryTables,
  RegistryError,
  backupKinds,
  databases,
} from '../../lib/db/registry.mjs';
import { text, bigint } from '../../lib/db/dialect/schema.mjs';
import { openControl, controlSteps } from '../../lib/db/control.mjs';
import { temporary } from './helpers.mjs';

const base = {
  component: 'test',
  lane: 'P',
  class: 'control',
  db: 'control',
  backup: 'never',
  since: '1.5.0',
  columns: { k: text(32), v: bigint() },
  primaryKey: ['k'],
};

test('defineTable validates the registry metadata of every table', () => {
  const table = defineTable('widgets', { ...base, sealed: ['v'], retention: 'widgets.prune' });
  assert.ok(Object.isFrozen(table));
  assert.deepEqual(
    [table.component, table.lane, table.db, table.backup, table.transfer, table.retention],
    ['test', 'P', 'control', 'never', null, 'widgets.prune']
  );
  assert.deepEqual(table.sealed, ['v']);
  assert.equal(table.legacy, false);
  for (const [change, pattern] of [
    [{ component: '' }, /component is required/],
    [{ lane: 'X' }, /lane must be/],
    [{ db: 'elsewhere' }, /db must be control\|history or \*/],
    [{ backup: 'sometimes' }, /backup must be/],
    [{ transfer: 1.5 }, /transfer must be an integer/],
    [{ since: '1.5' }, /since must name a release/],
    [{ shared: ['control'] }, /shared lists the other store classes/],
    [{ shared: ['nowhere'] }, /shared lists the other store classes/],
    [{ sealed: ['nope'] }, /sealed column nope is not a column/],
  ])
    assert.throws(
      () => defineTable('widgets', { ...base, ...change }),
      error => error instanceof RegistryError && pattern.test(error.message),
      JSON.stringify(change)
    );
  assert.deepEqual(backupKinds, ['always', 'never', 'history:rollups', 'history:all']);
  assert.deepEqual(databases, ['control', 'history']);
});

test('legacy tables are described, never rendered, and exist only in SQLite mode', () => {
  const legacy = defineLegacyTable('old_things', {
    component: 'test',
    lane: 'S',
    class: 'state',
    db: 'history',
    backup: 'history:all',
    since: '1.0.0',
    columns: { service: 'text', time: 'bigint' },
    primaryKey: ['service'],
    indexes: [{ name: 'old_things_time', columns: ['time'] }],
  });
  assert.equal(legacy.legacy, true);
  assert.deepEqual(legacy.modes, ['single']);
  const small = createRegistry([legacy]);
  assert.deepEqual(small.dslTables, []);
  assert.ok(small.identifiers.has('old_things_time'));
  assert.throws(
    () => defineLegacyTable('Bad Name', { ...legacy, class: 'state', columns: {}, primaryKey: [] }),
    RegistryError
  );
  assert.throws(
    () =>
      defineLegacyTable('x', {
        component: 'test',
        lane: 'S',
        class: 'nowhere',
        db: 'history',
        backup: 'never',
        since: '1.0.0',
        columns: { a: 'text' },
        primaryKey: ['a'],
      }),
    /unknown class/
  );
  assert.throws(
    () =>
      defineLegacyTable('x', {
        component: 'test',
        lane: 'S',
        class: 'state',
        db: 'history',
        backup: 'never',
        since: '1.0.0',
        columns: { a: 'text' },
        primaryKey: ['b'],
      }),
    /key column b is unknown/
  );
  // A partial index (events_unrelayed) declares its condition in the DSL's form; an index over
  // or filtered by an unknown column, or with an unknown operator, is refused.
  const partial = defineLegacyTable('old_events', {
    component: 'test',
    lane: 'S',
    class: 'state',
    db: 'history',
    backup: 'never',
    since: '1.0.0',
    columns: { id: 'bigint', relayed: 'bigint' },
    primaryKey: ['id'],
    indexes: [{ name: 'old_events_pending', columns: ['id'], where: [['relayed', '=', 0]] }],
  });
  assert.deepEqual(partial.indexes[0].where, [{ column: 'relayed', op: '=', value: 0 }]);
  assert.ok(createRegistry([partial]).identifiers.has('old_events_pending'));
  const refused = index =>
    assert.throws(
      () =>
        defineLegacyTable('old_events', {
          component: 'test',
          lane: 'S',
          class: 'state',
          db: 'history',
          backup: 'never',
          since: '1.0.0',
          columns: { id: 'bigint', relayed: 'bigint' },
          primaryKey: ['id'],
          indexes: [index],
        }),
      RegistryError
    );
  refused({ name: 'old_events_x', columns: ['nothing'] });
  refused({ name: 'old_events_x', columns: ['id'], where: [['nothing', '=', 0]] });
  refused({ name: 'old_events_x', columns: ['id'], where: [['relayed', 'like', 0]] });
  refused({ name: 'Bad Index', columns: ['id'] });
});

test('history events carry since, uid and relayed, and the partial index of rows to relay', () => {
  const events = registry.table('events');
  assert.equal(events.legacy, true);
  assert.deepEqual(Object.keys(events.columns), [
    'id',
    'service',
    'time',
    'kind',
    'message',
    'category',
    'rule',
    'since',
    'uid',
    'relayed',
  ]);
  assert.deepEqual(
    events.indexes.map(index => [index.name, index.columns.map(part => part.column), index.where]),
    [
      ['events_time', ['time'], []],
      ['events_unrelayed', ['id'], [{ column: 'relayed', op: '=', value: 0 }]],
    ]
  );
  for (const name of ['uid', 'relayed', 'events_unrelayed'])
    assert.ok(registry.identifiers.has(name), name);
});

test('no two tables, components or indexes may claim the same name', () => {
  const one = defineTable('shared_name', base);
  const two = defineTable('shared_name', { ...base, component: 'other' });
  assert.throws(() => createRegistry([one, two]), /Table shared_name is claimed by test and other/);
  const indexed = defineTable('indexed', {
    ...base,
    indexes: [{ name: 'shared_name', columns: ['v'] }],
  });
  assert.throws(() => createRegistry([one, indexed]), /index name shared_name/);
  const twin = defineTable('twin', { ...base, indexes: [{ name: 'dup_index', columns: ['v'] }] });
  const twin2 = defineTable('twin2', { ...base, indexes: [{ name: 'dup_index', columns: ['v'] }] });
  assert.throws(() => createRegistry([twin, twin2]), /dup_index/);
  // Only entries made by defineTable / defineLegacyTable are accepted.
  assert.throws(() => createRegistry([{ ...one }]), /was not made by defineTable/);
});

test('registry.identifiers cannot be extended at run time, and knows each table’s columns', () => {
  const allowlist = registry.identifiers;
  // A frozen Set still has add() and delete(): the allowlist is a read-only view instead.
  assert.equal(typeof allowlist.add, 'undefined');
  assert.equal(typeof allowlist.delete, 'undefined');
  assert.equal(typeof allowlist.clear, 'undefined');
  assert.ok(Object.isFrozen(allowlist));
  assert.throws(() => {
    allowlist.has = () => true;
  }, TypeError);
  assert.equal(allowlist.has('synthetic_evil_col'), false);
  assert.equal(allowlist.has('meta') && allowlist.has('key'), true);
  assert.ok(allowlist.size > 0 && [...allowlist].includes('meta'));
  assert.deepEqual([...allowlist.columnsOf('meta')].sort(), ['key', 'updated_at', 'value']);
  assert.ok(Object.isFrozen(allowlist.columnsOf('meta')));
  for (const name of ['not_a_table', '__proto__', 'constructor'])
    assert.equal(allowlist.columnsOf(name), null);
});

test('the release registry: lane P owns the platform tables; every name is unique and quotable', () => {
  assert.equal(
    registry.tables.length,
    platformTables.length +
      identityTables.length +
      alertingTables.length +
      auditTables.length +
      legacyHistoryTables.length +
      summaryHistoryTables.length
  );
  for (const table of platformTables) {
    assert.equal(table.component, 'platform');
    assert.equal(table.lane, 'P');
    assert.equal(table.class, 'control');
    assert.equal(table.legacy, false);
  }
  // Identity (lane I, 1.5.0): the built-in admin's tables, all in control.sqlite.
  assert.deepEqual(
    identityTables.map(table => table.name),
    ['users', 'sessions', 'identity_settings', 'displays']
  );
  for (const table of identityTables) {
    assert.equal(table.component, 'identity');
    assert.equal(table.lane, 'I');
    assert.equal(table.class, 'control');
    assert.equal(table.db, 'control');
    assert.equal(table.since, '1.5.0');
    assert.equal(table.legacy, false);
  }
  assert.equal(registry.table('sessions').retention, 'identity.prune');
  // Alerting (lane A, 1.5.0): durable delivery's outbox and channel health, in control.sqlite.
  assert.deepEqual(
    alertingTables.map(table => table.name),
    ['alerting_outbox', 'alerting_channel_status']
  );
  for (const table of alertingTables) {
    assert.equal(table.component, 'alerting');
    assert.equal(table.lane, 'A');
    assert.equal(table.class, 'control');
    assert.equal(table.db, 'control');
    assert.equal(table.since, '1.5.0');
    assert.equal(table.legacy, false);
  }
  // The audit trail (lane O, 1.5.0): four control.sqlite tables, carried by backups and
  // transfers after every other control table (audit spec D2).
  assert.deepEqual(
    auditTables.map(table => [table.name, table.transfer]),
    [
      ['audit_log', 30],
      ['audit_head', 31],
      ['audit_checkpoints', 32],
      ['audit_inbox', 33],
    ]
  );
  for (const table of auditTables) {
    assert.equal(table.component, 'audit');
    assert.equal(table.lane, 'O');
    assert.equal(table.class, 'control');
    assert.equal(table.db, 'control');
    assert.equal(table.since, '1.5.0');
    assert.equal(table.backup, 'always');
    assert.equal(table.legacy, false);
  }
  assert.equal(registry.table('audit_log').retention, 'audit.prune');
  // The 1.x history tables stay hand-written (invariant 1).
  assert.deepEqual(
    legacyHistoryTables.map(table => table.name),
    ['readings', 'latest', 'alerts', 'events', 'latest_notes']
  );
  assert.ok(legacyHistoryTables.every(table => table.legacy && table.db === 'history'));
  // 1.5's history summaries are hand-written by lib/store.mjs too, derived from the readings:
  // never backed up or transferred (a start rebuilds them).
  assert.deepEqual(
    summaryHistoryTables.map(table => [table.name, table.legacy, table.db, table.class]),
    [
      ['history_summaries', true, 'history', 'series'],
      ['history_summary_marks', true, 'history', 'series'],
    ]
  );
  for (const name of ['history_summaries', 'history_summary_marks']) {
    assert.equal(registry.table(name).backup, 'never');
    assert.equal(registry.table(name).transfer, null);
    assert.equal(registry.table(name).since, '1.5.0');
  }
  assert.deepEqual(
    registry.dslTables.map(table => table.name),
    [...platformTables, ...identityTables, ...alertingTables, ...auditTables].map(
      table => table.name
    )
  );
  for (const name of [
    'meta',
    'key',
    'value',
    'readings',
    'events_time',
    'settings_pkey',
    'users',
    'token_hash',
    'sessions_token_hash_key',
    'sessions_user_idx',
    'identity_settings_pkey',
    'alerting_outbox_uid',
    'alerting_outbox_order',
    'paused_since',
    'consecutive_refusals',
  ])
    assert.ok(registry.identifiers.has(name), name);
  assert.equal(registry.identifiers.has('audit_events'), false);
  assert.equal(registry.classOf('latest'), 'state');
  assert.equal(registry.classOf('readings'), 'series');
  assert.equal(registry.classOf('nowhere'), null);
  assert.throws(() => registry.table('nowhere'), RegistryError);
  assert.deepEqual(
    registry.forComponent('alerting').map(table => table.name),
    ['alerting_outbox', 'alerting_channel_status', 'alerts', 'events']
  );
  assert.deepEqual(
    registry.forComponent('identity').map(table => table.name),
    ['users', 'sessions', 'identity_settings', 'displays']
  );
  const controlTables =
    platformTables.length + identityTables.length + alertingTables.length + auditTables.length;
  assert.equal(registry.forClass('control').length, controlTables);
  assert.equal(registry.forMode('cluster').length, controlTables);
});

test('backup allowlists and transfer order are generated from the registry', () => {
  assert.deepEqual(registry.backupAllowlist('control'), [
    'schema_migrations',
    'schema_fences',
    'meta',
    'keyring',
    'settings',
    'users',
    'audit_log',
    'audit_head',
    'audit_checkpoints',
    'audit_inbox',
  ]);
  assert.deepEqual(registry.backupAllowlist('history'), ['schema_migrations']);
  assert.deepEqual(registry.backupAllowlist('history', 'rollups'), [
    'schema_migrations',
    'latest',
    'latest_notes',
  ]);
  assert.deepEqual(registry.backupAllowlist('history', 'all'), [
    'schema_migrations',
    'readings',
    'latest',
    'alerts',
    'events',
    'latest_notes',
  ]);
  assert.throws(() => registry.backupAllowlist('control', 'some'), /Unknown history level/);
  // jobs and idempotency keys are never backed up or transferred; nor are sessions (a restore
  // must not revive revoked ones, D15) or identity_settings (node-local, D3).
  // Nor are the delivery tables: restoring a backup must not send old alerts again.
  for (const name of [
    'jobs',
    'idempotency_keys',
    'sessions',
    'identity_settings',
    'displays',
    'alerting_outbox',
    'alerting_channel_status',
  ]) {
    assert.ok(!registry.backupAllowlist('control', 'all').includes(name), name);
    assert.ok(!registry.transferOrder('control').includes(name), name);
    assert.equal(registry.table(name).backup, 'never', name);
    assert.equal(registry.table(name).transfer, null, name);
  }
  assert.equal(registry.table('users').backup, 'always');
  assert.equal(registry.table('users').transfer, 10);
  assert.deepEqual(registry.transferOrder('control'), [
    'schema_migrations',
    'schema_fences',
    'meta',
    'keyring',
    'settings',
    'users',
    'audit_log',
    'audit_head',
    'audit_checkpoints',
    'audit_inbox',
  ]);
  assert.deepEqual(registry.transferOrder('history'), [
    'schema_migrations',
    'readings',
    'latest',
    'alerts',
    'events',
    'latest_notes',
  ]);
  assert.equal(registry.transferOrder().length, 15);
});

test('every table a migrated control database holds is registered, and none is missing (drift)', async t => {
  const directory = temporary(t);
  const control = openControl(directory, { release: '1.5.0', env: {} });
  t.after(() => control.close());
  // Every table the platform steps create is a registered control table.
  for (const step of controlSteps)
    for (const name of step.up?.createTables ?? []) assert.equal(registry.classOf(name), 'control');
  await control.migrate();
  const { tables } = await control.db.catalog();
  assert.deepEqual(registry.drift('control', tables), { unregistered: [], missing: [] });
  // Drift is reported both ways; SQLite's own tables are ignored.
  assert.deepEqual(
    registry.drift('control', [...tables.filter(name => name !== 'jobs'), 'stray', 'sqlite_stat1']),
    { unregistered: ['stray'], missing: ['jobs'] }
  );
  // A 1.4.x history database: the legacy tables are registered, schema_migrations is missing.
  assert.deepEqual(
    registry.drift('history', ['readings', 'latest', 'alerts', 'events', 'latest_notes']),
    { unregistered: [], missing: ['schema_migrations'] }
  );
  assert.ok(path.isAbsolute(control.file));
});
