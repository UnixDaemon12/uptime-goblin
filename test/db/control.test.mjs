// The control database (lib/db/control.mjs): platform steps, meta, the store adapters for the
// keyring, settings and jobs, and startControl(), the platform part of the start sequence.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import {
  openControl,
  startControl,
  inspectKeyring,
  controlSteps,
  platformSteps,
  identitySteps,
  auditSteps,
  planFromScratch,
  controlExists,
  controlFile,
  metaOps,
  packageRelease,
  createKeyringStore,
  createSettingsStore,
  createJobsStore,
  takeMigrationSnapshot,
  passwordRequiredMessage,
  createdByFile,
  createdByWarning,
  readCreatedBy,
  recordCreatedBy,
} from '../../lib/db/control.mjs';
import { acquireLock } from '../../lib/db/lock.mjs';
import { openSqlite } from '../../lib/db/sqlite.mjs';
import { requireRelease, RefusalError } from '../../lib/db/migrate.mjs';
import { listSnapshots, restoreJournal, restoreSnapshot } from '../../lib/db/snapshot.mjs';
import {
  KeyError,
  Keyring,
  keyFingerprint,
  memoryKeyringStore,
  secretKeyFile,
} from '../../lib/keyring.mjs';
import { sql, id } from '../../lib/db/sql.mjs';
import { alertingSteps } from '../../lib/alerting/tables.mjs';
import { temporary, fingerprint, mode, manualClock } from './helpers.mjs';

// The order the migrator applies the steps of a new control database (dependencies first,
// then by id): alerting's outbox step needs only the platform tables; the audit's and
// identity's both follow the instance step, and audit-001 sorts first.
const appliedOrder = [
  'platform-001-control-tables',
  'alerting-001-outbox',
  'platform-002-instance',
  'audit-001-log',
  'identity-001-builtin-admin',
  'identity-002-displays',
];
const hexKey = 'a1'.repeat(16) + 'b2'.repeat(16);
const otherKey = 'c3'.repeat(16) + 'd4'.repeat(16);
// Key sources that exist nowhere, so only the environment and the data directory count.
const noSources = directory => ({
  credentialsDirectory: path.join(directory, 'no-credentials'),
  secretsDirectory: path.join(directory, 'no-secrets'),
});
const manifestOf = (directory, snapshotId) =>
  JSON.parse(
    fs.readFileSync(path.join(directory, 'snapshots', snapshotId, 'manifest.json'), 'utf8')
  );
const locked = (t, directory) => {
  const lock = acquireLock(directory);
  t.after(() => lock.release());
  return lock;
};

test('the platform steps are valid, ordered, control-only, and plannable from scratch', () => {
  assert.deepEqual(
    controlSteps.map(step => step.id),
    [
      'platform-001-control-tables',
      'platform-002-instance',
      'identity-001-builtin-admin',
      'identity-002-displays',
      'alerting-001-outbox',
      'audit-001-log',
    ]
  );
  assert.ok(controlSteps.every(step => Object.isFrozen(step) && step.db === 'control'));
  assert.equal(
    platformSteps.length + identitySteps.length + alertingSteps.length + auditSteps.length,
    controlSteps.length
  );
  assert.notEqual(platformSteps.length, controlSteps.length);
  // The plan runs the alerting step right after the platform tables it depends on (and before
  // the instance step, by id, among the steps then ready).
  const plan = planFromScratch();
  assert.deepEqual(
    plan.map(step => step.id),
    appliedOrder
  );
  assert.equal(plan.length, 6);
  assert.equal(plan[0].ddl.length, 7, 'six tables and one index');
  assert.match(plan[0].ddl[0], /^CREATE TABLE "schema_fences"/);
  assert.deepEqual(alertingSteps[0].after, ['platform-001-control-tables']);
  assert.equal(plan[1].ddl.length, 6, 'two tables, one unique index and three indexes');
  assert.deepEqual(
    plan[1].ddl.filter(ddl => ddl.startsWith('CREATE TABLE')).map(ddl => /"(\w+)"/.exec(ddl)[1]),
    ['alerting_outbox', 'alerting_channel_status']
  );
  assert.deepEqual(plan[2].ddl, [], 'a portable data-only step has no DDL');
  // Identity's step creates its three tables after the instance step and inserts no row (the
  // u_admin row needs auth.json, GOBLIN_PASSWORD and scrypt, so identity creates it at start).
  // The audit's step (audit spec §3.2): expand only, its four tables, no row and no fence.
  assert.deepEqual(auditSteps[0].after, ['platform-002-instance']);
  assert.equal(auditSteps[0].kind, 'expand');
  assert.equal(plan[3].ddl.length, 11, 'four tables and seven indexes');
  assert.deepEqual(
    plan[3].ddl.filter(ddl => ddl.startsWith('CREATE TABLE')).map(ddl => /"(\w+)"/.exec(ddl)[1]),
    ['audit_log', 'audit_head', 'audit_checkpoints', 'audit_inbox']
  );
  assert.deepEqual(identitySteps[0].after, ['platform-002-instance']);
  assert.equal(plan[4].ddl.length, 7, 'three tables and four indexes');
  assert.deepEqual(
    plan[4].ddl.filter(ddl => ddl.startsWith('CREATE TABLE')).map(ddl => /"(\w+)"/.exec(ddl)[1]),
    ['users', 'sessions', 'identity_settings']
  );
  assert.match(packageRelease(), /^\d+\.\d+\.\d+/);
});

test('a data directory created by this release records created_by_release; its meta and history', async t => {
  const directory = path.join(temporary(t), 'data');
  const clock = manualClock();
  assert.equal(controlExists(directory), false);
  const control = openControl(directory, { release: '1.5.0', env: {}, clock });
  t.after(() => control.close());
  assert.equal(control.fresh, true);
  assert.equal(mode(directory), 0o700);
  assert.equal(mode(path.join(directory, controlFile)), 0o600);
  const before = await control.inspect();
  assert.deepEqual(
    before.pending.map(step => step.id),
    appliedOrder
  );
  const result = await control.migrate();
  assert.deepEqual(result, {
    applied: appliedOrder,
    pendingData: [],
    upgraded: true,
  });
  assert.equal(await control.meta.createdByRelease(), '1.5.0');
  assert.match(await control.meta.instanceId(), /^[0-9a-f-]{36}$/);
  assert.deepEqual(await control.meta.upgradeHistory(), [{ from: null, to: '1.5.0', at: clock() }]);
  // Migrating again changes nothing and records nothing.
  assert.deepEqual(await control.migrate(), { applied: [], pendingData: [], upgraded: false });
  assert.equal((await control.meta.upgradeHistory()).length, 1);

  // credentials_ever is one-way; session_seq counts up.
  assert.equal(await control.meta.credentialsEver(), false);
  assert.equal(await control.meta.markCredentials(), true);
  assert.equal(await control.meta.markCredentials(), false);
  assert.equal(await control.meta.credentialsEver(), true);
  assert.equal(await control.meta.sessionSeq(), 0);
  assert.equal(await control.meta.bumpSessionSeq(), 1);
  assert.equal(await control.meta.bumpSessionSeq(), 2);
  assert.equal(await control.meta.sessionSeq(), 2);
  // The tx-level operations join the caller's unit: a failure rolls the bump back.
  await assert.rejects(
    control.db.write(tx => {
      metaOps.bumpSessionSeq(tx, clock());
      throw new Error('the revocation failed');
    }),
    /revocation failed/
  );
  assert.equal(await control.meta.sessionSeq(), 2);
  await control.meta.set('config_revision_seen', 17);
  assert.equal(await control.meta.get('config_revision_seen'), '17');
  assert.equal(await control.meta.setIfAbsent('config_revision_seen', 18), false);
  const all = await control.meta.all();
  assert.equal(all.credentials_ever, '1');
  assert.equal(all.last_version, '1.5.0');
  // A later release records the upgrade.
  control.close();
  const later = openControl(directory, { release: '1.5.1', env: {}, clock });
  t.after(() => later.close());
  assert.equal(later.fresh, true, 'no 1.x data files: still counted as created by 1.5+');
  assert.equal((await later.migrate()).upgraded, true);
  assert.deepEqual(
    (await later.meta.upgradeHistory()).map(item => [item.from, item.to]),
    [
      [null, '1.5.0'],
      ['1.5.0', '1.5.1'],
    ]
  );
  // created_by_release was set once, by the release that created the directory.
  assert.equal(await later.meta.createdByRelease(), '1.5.0');
});

test('a data directory upgraded from 1.x has no created_by_release', async t => {
  const directory = temporary(t);
  fs.writeFileSync(path.join(directory, 'config.json'), '{}');
  const control = openControl(directory, { release: '1.5.0', env: {} });
  t.after(() => control.close());
  assert.equal(control.fresh, false);
  await control.migrate();
  assert.equal(await control.meta.createdByRelease(), null);
  assert.ok(await control.meta.instanceId());
  // Legacy Basic stays on for upgraded installs in 1.5 (G2), off for new ones.
  assert.equal(await control.features.enabled('legacyBasic'), true);
});

// control.sqlite can be moved aside to start over with a new one (docs/authentication.md).
// Without created-by.json the next start found config.json and history.sqlite, recorded no
// created_by_release and turned legacy Basic on for a directory 1.5 had created.
test('created-by.json: a directory 1.5 created stays one once control.sqlite is gone (G2)', async t => {
  const directory = temporary(t);
  const lock = locked(t, directory);
  const marker = path.join(directory, createdByFile);
  const options = {
    lock,
    credentialConfigured: true,
    keyring: 'existing',
    env: {},
    keySources: noSources(directory),
  };
  const first = await startControl(directory, {
    ...options,
    release: '1.5.0',
    clock: () => Date.UTC(2026, 9, 1),
  });
  assert.deepEqual(first.warnings, []);
  first.control.close();
  assert.deepEqual(JSON.parse(fs.readFileSync(marker, 'utf8')), {
    release: '1.5.0',
    createdAt: '2026-10-01T00:00:00.000Z',
  });
  assert.equal(mode(marker), 0o600);
  assert.ok(!fs.readdirSync(directory).some(name => name.endsWith('.tmp')), 'no temporary left');
  // The first start goes on to create config.json and history.sqlite (ConfigStore, Store).
  fs.writeFileSync(path.join(directory, 'config.json'), '{"services":[]}\n');
  openSqlite(path.join(directory, 'history.sqlite')).close();
  const removeControl = () => {
    for (const suffix of ['', '-wal', '-shm'])
      fs.rmSync(path.join(directory, controlFile + suffix), { force: true });
  };
  removeControl();

  const second = await startControl(directory, { ...options, release: '1.5.1' });
  assert.equal(second.control.fresh, false, 'the 1.x files exist');
  assert.equal(await second.control.meta.createdByRelease(), '1.5.0', 'from created-by.json');
  assert.equal(await second.control.features.enabled('legacyBasic'), false);
  assert.equal(JSON.parse(fs.readFileSync(marker, 'utf8')).release, '1.5.0', 'never replaced');
  second.control.close();

  // A directory created before created-by.json existed gets one at its next start, from meta.
  fs.rmSync(marker);
  const third = await startControl(directory, { ...options, release: '1.5.2' });
  third.control.close();
  assert.equal(readCreatedBy(directory, null), '1.5.0');
  removeControl();
  const fourth = await startControl(directory, { ...options, release: '1.5.2' });
  t.after(() => fourth.control.close());
  assert.equal(await fourth.control.meta.createdByRelease(), '1.5.0');
  assert.equal(await fourth.control.features.enabled('legacyBasic'), false);
});

test('created-by.json: an upgraded 1.4.x directory gets none and stays upgraded; a damaged one still counts', async t => {
  const directory = temporary(t);
  fs.writeFileSync(path.join(directory, 'config.json'), '{"services":[]}\n');
  const lock = locked(t, directory);
  const options = {
    lock,
    credentialConfigured: true,
    keyring: 'existing',
    env: {},
    keySources: noSources(directory),
  };
  const upgraded = await startControl(directory, { ...options, release: '1.5.0' });
  upgraded.control.close();
  assert.equal(fs.existsSync(path.join(directory, createdByFile)), false);
  for (const suffix of ['', '-wal', '-shm'])
    fs.rmSync(path.join(directory, controlFile + suffix), { force: true });
  const again = await startControl(directory, { ...options, release: '1.5.0' });
  assert.equal(await again.control.meta.createdByRelease(), null);
  assert.equal(await again.control.features.enabled('legacyBasic'), true);
  again.control.close();

  // readCreatedBy: what is there decides; 1.4.x never writes the file, so anything there means
  // 1.5 or later created the directory, and the fallback stands in for a release it does not name.
  const other = temporary(t);
  const file = path.join(other, createdByFile);
  assert.equal(readCreatedBy(other, '9.9.9'), null);
  assert.equal(readCreatedBy(path.join(other, 'missing'), '9.9.9'), null);
  fs.writeFileSync(file, '{"release":"1.5.0-dev.0","createdAt":"2026-10-01T00:00:00.000Z"}\n');
  assert.equal(readCreatedBy(other, '9.9.9'), '1.5.0-dev.0');
  for (const text of ['', '{', '{"release":["1.5.0"]}', '{"release":"latest"}', 'null']) {
    fs.writeFileSync(file, text);
    assert.equal(readCreatedBy(other, '9.9.9'), '9.9.9', text);
  }
  fs.writeFileSync(file, JSON.stringify({ release: '1.5.0', pad: 'x'.repeat(5000) }));
  assert.equal(readCreatedBy(other, '9.9.9'), '9.9.9', 'too large to be one: not read');
  fs.rmSync(file);
  fs.mkdirSync(file);
  assert.equal(readCreatedBy(other, '9.9.9'), '9.9.9', 'a directory');
  fs.rmdirSync(file);
  // A FIFO is never opened: reading it would block the start.
  const made = spawnSync('mkfifo', [file], { encoding: 'utf8' });
  assert.equal(made.status, 0, made.stderr);
  assert.equal(readCreatedBy(other, '9.9.9'), '9.9.9', 'a FIFO');
  assert.equal(recordCreatedBy(other, '1.5.0'), false, 'an entry there is never replaced');
  fs.rmSync(file);
  // A damaged file in a directory with 1.x data: a new control.sqlite takes this release.
  fs.writeFileSync(path.join(other, 'config.json'), '{"services":[]}\n');
  fs.writeFileSync(file, '{"release": 15');
  const control = openControl(other, { release: '1.5.3', env: {} });
  t.after(() => control.close());
  await control.migrate();
  assert.equal(await control.meta.createdByRelease(), '1.5.3');
  assert.equal(await control.features.enabled('legacyBasic'), false);
  assert.equal(fs.readFileSync(file, 'utf8'), '{"release": 15', 'openControl writes no file');
});

test('startControl starts when created-by.json cannot be written, with a warning, and writes it next time', async t => {
  const directory = temporary(t);
  const lock = locked(t, directory);
  const options = {
    lock,
    credentialConfigured: true,
    keyring: 'existing',
    env: {},
    keySources: noSources(directory),
  };
  const open = fs.openSync;
  const refuse = t.mock.method(fs, 'openSync', (file, ...rest) => {
    if (path.basename(String(file)).startsWith(`${createdByFile}.`))
      throw Object.assign(new Error('no space left on device'), { code: 'ENOSPC' });
    return open(file, ...rest);
  });
  const started = await startControl(directory, { ...options, release: '1.5.0' });
  refuse.mock.restore();
  assert.deepEqual(started.warnings, [createdByWarning('ENOSPC')]);
  assert.match(started.warnings[0], /created-by\.json.*ENOSPC.*legacy Basic for scripts on/);
  assert.equal(await started.control.meta.createdByRelease(), '1.5.0', 'the start went on');
  started.control.close();
  assert.deepEqual(fs.readdirSync(directory).sort(), [controlFile, 'goblin.lock', 'orbit.lock']);
  const again = await startControl(directory, { ...options, release: '1.5.0' });
  t.after(() => again.control.close());
  assert.deepEqual(again.warnings, []);
  assert.equal(readCreatedBy(directory, null), '1.5.0');
});

test('requireRelease through the control database: never newer than this release; pre-releases count as their release', async t => {
  const directory = temporary(t);
  const control = openControl(directory, { release: '1.6.0-rc.1', env: {} });
  t.after(() => control.close());
  await control.migrate();
  assert.equal(
    await control.db.write(tx =>
      control.requireRelease(tx, {
        name: 'identity.totp',
        minRelease: '1.6.0',
        reason: 'TOTP enrolment exists',
      })
    ),
    true
  );
  await assert.rejects(
    control.db.write(tx =>
      control.requireRelease(tx, { name: 'x.y', minRelease: '1.7.0', reason: 'too new' })
    ),
    RangeError
  );
  // The release candidate still opens its own data; 1.5.x does not.
  assert.equal((await control.inspect()).refusal, null);
  control.close();
  const older = openControl(directory, { release: '1.5.9', env: {}, readOnly: true });
  t.after(() => older.close());
  assert.equal((await older.inspect()).refusal.code, 'fence');
});

test('read-only opens never create or change files', async t => {
  const directory = temporary(t);
  assert.throws(() => openControl(directory, { readOnly: true, env: {} }), { code: 'ENOENT' });
  assert.deepEqual(fs.readdirSync(directory), []);
  const control = openControl(directory, { release: '1.5.0', env: {} });
  await control.migrate();
  control.close();
  const before = fingerprint(directory);
  const reader = openControl(directory, { readOnly: true, release: '1.5.0', env: {} });
  assert.equal(reader.db.immutable, true);
  assert.equal((await reader.meta.all()).last_version, '1.5.0');
  assert.deepEqual((await reader.inspect()).pending, []);
  await assert.rejects(reader.meta.set('x', 1), /read-only/);
  reader.close();
  assert.deepEqual(fs.readdirSync(directory), [controlFile], 'no -wal or -shm left behind');
  assert.deepEqual(fingerprint(directory), before);
  // While a writer has it open (a -wal file exists), a reader shares the WAL instead.
  const writer = openControl(directory, { release: '1.5.0', env: {} });
  t.after(() => writer.close());
  await writer.meta.set('while_open', 1);
  const live = openControl(directory, { readOnly: true, release: '1.5.0', env: {} });
  assert.equal(live.db.immutable, false);
  assert.equal(await live.meta.get('while_open'), '1');
  live.close();
});

test('the keyring store adapter: list, exists, and one atomic save of insert, rewrap, retire and clear', async t => {
  const directory = temporary(t);
  const control = openControl(directory, { release: '1.5.0', env: {} });
  t.after(() => control.close());
  const store = createKeyringStore(control.db);
  // Before the keyring table exists.
  assert.equal(await store.exists(), false);
  await control.migrate();
  assert.equal(await store.exists(), false);
  assert.equal(await control.keyringExists(), false);
  const row = (kid, purpose, extra = {}) => ({
    kid,
    purpose,
    wrapped: `w1.${kid}`,
    created_at: 1,
    ...extra,
  });
  await store.save({ insert: [row('k1', 'seal'), row('k2', 'login')] });
  assert.equal(await store.exists(), true);
  await store.save({
    rewrap: [{ kid: 'k1', wrapped: 'w1.new' }],
    retire: [{ kid: 'k2', retired_at: 5 }],
  });
  const rows = Object.fromEntries((await store.list()).map(item => [item.kid, { ...item }]));
  assert.equal(rows.k1.wrapped, 'w1.new');
  assert.equal(rows.k1.retired_at, null);
  assert.equal(rows.k2.retired_at, 5);
  // A rewrap of an unknown key fails the whole save.
  await assert.rejects(
    store.save({ insert: [row('k3', 'audit')], rewrap: [{ kid: 'nope', wrapped: 'x' }] }),
    /no key nope/
  );
  assert.equal((await store.list()).length, 2);
  // clear + insert replace the keyring in one unit (Keyring.reset).
  await store.save({ clear: true, insert: [row('k9', 'seal')] });
  assert.deepEqual(
    (await store.list()).map(item => item.kid),
    ['k9']
  );
  // The real keyring runs on it.
  const keyring = await Keyring.open(store, { key: Buffer.alloc(32, 7).fill(9, 0, 1) }).catch(
    error => error
  );
  assert.equal(keyring.code, 'key_mismatch', 'k9 was not wrapped by this key');
  await store.save({ clear: true });
  const opened = await Keyring.open(store, { key: Buffer.from(hexKey, 'hex') });
  const sealed = opened.sealText('seal', 'hello', 'test:1');
  const again = await Keyring.open(createKeyringStore(control.db), {
    key: Buffer.from(hexKey, 'hex'),
    create: false,
  });
  assert.equal(again.openText('seal', sealed, 'test:1'), 'hello');
});

test('the settings store adapter: compare-and-swap on version; secrets sealed at rest', async t => {
  const directory = temporary(t);
  const control = openControl(directory, { release: '1.5.0', env: {} });
  t.after(() => control.close());
  await control.migrate();
  const store = createSettingsStore(control.db);
  const row = (version, value) => ({
    component: 'test',
    key: 'doc',
    schema: 1,
    value: JSON.stringify(value),
    version,
    updated_at: version,
    updated_by: null,
  });
  assert.equal(await store.put(row(1, { a: 1 }), { ifVersion: 0 }), true);
  assert.equal(await store.put(row(1, { a: 2 }), { ifVersion: 0 }), false, 'exists already');
  assert.equal(await store.put(row(2, { a: 3 }), { ifVersion: 5 }), false, 'wrong version');
  assert.equal(await store.put(row(2, { a: 3 }), { ifVersion: 1 }), true);
  assert.equal(JSON.parse((await store.get('test', 'doc')).value).a, 3);
  assert.equal((await store.list('test')).length, 1);
  assert.equal((await store.list('other')).length, 0);
  assert.equal(await store.get('test', 'none'), undefined);

  // Through the settings service: the platform/features document and a secret field.
  const keyring = await Keyring.open(control.keyringStore, { key: Buffer.from(hexKey, 'hex') });
  control.attachKeyring(keyring);
  control.settings.define({
    component: 'test',
    key: 'channel',
    fields: {
      url: { default: '', validate: value => String(value) },
      token: { secret: true, validate: value => String(value) },
    },
  });
  const saved = await control.settings.update(
    'test',
    'channel',
    { url: 'https://example.test', token: 'super-secret-token' },
    { ifVersion: 0, by: 'u_admin' }
  );
  assert.deepEqual(saved.value.token, { set: true });
  const stored = await control.db.read(tx =>
    tx.get(sql`SELECT ${id('value')} FROM ${id('settings')} WHERE ${id('key')} = ${'channel'}`)
  );
  assert.doesNotMatch(stored.value, /super-secret-token/);
  assert.match(JSON.parse(stored.value).token.$sealed, /^v1\./);
  assert.equal((await control.settings.get('test', 'channel')).value.token, 'super-secret-token');
  assert.equal(
    (await control.settings.update('platform', 'features', { heartbeat: true }, { ifVersion: 0 }))
      .version,
    1
  );
  assert.equal(await control.features.enabled('heartbeat'), true);
});

test('the jobs store records lib/jobs.mjs statuses (errors as short text) and lists them', async t => {
  const directory = temporary(t);
  const control = openControl(directory, { release: '1.5.0', env: {}, clock: () => 99 });
  t.after(() => control.close());
  await control.migrate();
  const jobs = createJobsStore(control.db, () => 99);
  await jobs.record({
    name: 'session.prune',
    lastStarted: 1,
    lastFinished: 2,
    lastOk: 2,
    runs: 3,
    failures: 0,
    durationMs: 1,
  });
  await jobs.record({
    name: 'audit.prune',
    lastError: { message: 'x'.repeat(900) },
    runs: 1,
    failures: 1,
  });
  await control.jobs.record({ name: 'session.prune', runs: 4, failures: 1, lastError: 'boom' });
  const rows = await jobs.list();
  assert.deepEqual(
    rows.map(row => row.name),
    ['audit.prune', 'session.prune']
  );
  assert.equal(rows[0].last_error.length, 500);
  assert.deepEqual(
    [rows[1].runs, rows[1].failures, rows[1].last_error, rows[1].updated_at],
    [4, 1, 'boom', 99]
  );
});

test('the jobs and idempotency stores keep cut or odd text storable, never refused at bind', async t => {
  const directory = temporary(t);
  const control = openControl(directory, { release: '1.5.0', env: {}, clock: () => 99 });
  t.after(() => control.close());
  await control.migrate();
  const jobs = createJobsStore(control.db, () => 99);
  // A cut ending inside a pair, half a pair or a NUL in the text: refused at bind (poison), so
  // a job's status write failed on what its error said. They become U+FFFD or go.
  await jobs.record({
    name: 'x' + '😀'.repeat(100),
    lastError: 'y' + '😀'.repeat(300) + '\u0000',
    runs: 1,
    failures: 1,
  });
  await jobs.record({ name: 'half\ud800', lastError: { message: 'a\u0000b\udc00' } });
  assert.deepEqual(
    (await jobs.list()).map(row => [row.name, row.last_error]),
    [
      ['half\ufffd', 'ab\ufffd'],
      ['x' + '😀'.repeat(63) + '\ufffd', 'y' + '😀'.repeat(249) + '\ufffd'],
    ]
  );
  // A keyed request's route is kept for diagnosis only, cut to 256: the same applies.
  const { createIdempotencyStore } = await import('../../lib/db/control.mjs');
  const store = createIdempotencyStore(control.db, { clock: () => 99 });
  const scope = ['rev-1', 'POST', '/api/' + '😀'.repeat(200) + '\u0000', 'k'.repeat(16)].join('\n');
  await store.begin(scope, { digest: 'a'.repeat(64), leaseUntil: 1000 });
  const route = (
    await control.db.read(tx => tx.get(sql`SELECT ${id('route')} FROM ${id('idempotency_keys')}`))
  ).route;
  assert.ok(route.isWellFormed() && !route.includes('\u0000') && route.length <= 256, route);
});

// ---------------------------------------------------------------------------------------------
// startControl: the platform part of the start sequence.

test('startControl on a new data directory: generates secret.key, migrates, opens the keyring, takes no snapshot', async t => {
  const directory = temporary(t);
  const lock = locked(t, directory);
  const progress = [];
  const started = await startControl(directory, {
    lock,
    credentialConfigured: true,
    release: '1.5.0',
    env: {},
    keySources: noSources(directory),
    onProgress: item => progress.push(item),
  });
  t.after(() => started.control.close());
  assert.equal(started.key.source, 'generated');
  assert.equal(started.key.file, path.join(directory, secretKeyFile));
  assert.match(started.key.warnings[0], /inside the data directory/);
  assert.equal(mode(started.key.file), 0o600);
  assert.equal(started.snapshot, null, 'nothing to keep yet');
  assert.deepEqual(
    progress.map(item => [item.phase, item.step]),
    appliedOrder.map(step => ['migrating', step])
  );
  assert.equal(await started.control.meta.createdByRelease(), '1.5.0');
  assert.equal(started.keyring.describe().length, 4);
  assert.equal(await started.control.keyringExists(), true);
  assert.ok(!('key' in started.key) || typeof started.key.key !== 'object');
  // Settings can seal secrets straight away.
  started.control.settings.define({
    component: 'test',
    key: 'secret',
    fields: { value: { secret: true, validate: value => value } },
  });
  await started.control.settings.update('test', 'secret', { value: 's3cret' });
  assert.equal((await started.control.settings.get('test', 'secret')).value.value, 's3cret');
});

test('startControl on a 1.4.x data directory: a pinned pre-upgrade snapshot, reused after a crash, then the migration', async t => {
  const directory = temporary(t);
  fs.writeFileSync(path.join(directory, 'config.json'), '{"services":[]}\n');
  fs.writeFileSync(path.join(directory, 'auth.json'), '{"version":1}\n');
  const lock = locked(t, directory);
  const env = { GOBLIN_SECRET_KEY: hexKey };
  const started = await startControl(directory, {
    lock,
    credentialConfigured: true,
    release: '1.5.0',
    env,
    keySources: noSources(directory),
  });
  assert.equal(env.GOBLIN_SECRET_KEY, undefined, 'the key left the environment');
  assert.equal(started.key.source, 'env');
  assert.equal(fs.existsSync(path.join(directory, secretKeyFile)), false);
  const [snapshot] = listSnapshots(directory);
  assert.deepEqual(started.snapshot, { id: snapshot.id, reused: false });
  assert.equal(snapshot.reason, 'pre-upgrade');
  assert.equal(snapshot.pinned, true, 'the way back to 1.4.x is pinned');
  assert.deepEqual(snapshot.files, ['config.json', 'auth.json']);
  // There is no history.sqlite here, so nothing was left out.
  assert.deepEqual(manifestOf(directory, snapshot.id).excluded, []);
  assert.equal(await started.control.meta.createdByRelease(), null);
  started.control.close();

  // The next start of the same release has nothing pending and takes no snapshot.
  const again = await startControl(directory, {
    lock,
    credentialConfigured: true,
    release: '1.5.0',
    env: { GOBLIN_SECRET_KEY: hexKey },
    keySources: noSources(directory),
  });
  again.control.close();
  assert.equal(again.snapshot, null);
  assert.equal(listSnapshots(directory).length, 1);

  // A release with a new step snapshots once; a crash loop reuses that snapshot.
  const steps = [
    ...controlSteps,
    {
      id: 'platform-003-crash',
      component: 'platform',
      kind: 'expand',
      db: 'control',
      up() {
        throw new Error('crash in the step');
      },
    },
  ];
  for (let attempt = 0; attempt < 3; attempt += 1)
    await assert.rejects(
      startControl(directory, {
        lock,
        credentialConfigured: true,
        release: '1.5.1',
        env: { GOBLIN_SECRET_KEY: hexKey },
        keySources: noSources(directory),
        steps,
      }),
      /crash in the step/
    );
  const upgrades = listSnapshots(directory).filter(item => item.release === '1.5.1');
  assert.equal(upgrades.length, 1);
  assert.equal(upgrades[0].fromRelease, '1.5.0');
  assert.equal(upgrades[0].pinned, false);
  // `snapshot: false` (a test-only option; no production caller passes it) skips it.
  const quiet = await startControl(directory, {
    lock,
    credentialConfigured: true,
    release: '1.5.2',
    env: { GOBLIN_SECRET_KEY: hexKey },
    keySources: noSources(directory),
    snapshot: false,
    steps: [...controlSteps, { ...steps.at(-1), up() {} }],
  });
  quiet.control.close();
  assert.equal(quiet.snapshot, null);
  assert.equal(listSnapshots(directory).filter(item => item.release === '1.5.2').length, 0);
});

test('startControl refusals leave the data directory byte-identical, apart from goblin.lock and run/ (T11)', async t => {
  const directory = temporary(t);
  fs.writeFileSync(path.join(directory, 'config.json'), '{}\n');
  const lock = locked(t, directory);
  const first = await startControl(directory, {
    lock,
    credentialConfigured: true,
    release: '1.5.0',
    env: { GOBLIN_SECRET_KEY: hexKey },
    keySources: noSources(directory),
  });
  first.control.close();
  const skip = ['goblin.lock', 'orbit.lock', 'run'];
  const refused = async (options, check) => {
    const before = fingerprint(directory, skip);
    await assert.rejects(
      startControl(directory, {
        lock,
        credentialConfigured: true,
        release: '1.5.0',
        keySources: noSources(directory),
        ...options,
      }),
      check
    );
    assert.deepEqual(fingerprint(directory, skip), before, 'no byte changed');
    assert.ok(!fs.existsSync(path.join(directory, `${controlFile}-wal`)));
  };

  // The key is missing: nothing is generated.
  await refused(
    { env: {} },
    error => error instanceof KeyError && error.code === 'key_missing' && error.exitCode === 78
  );
  assert.equal(fs.existsSync(path.join(directory, secretKeyFile)), false);
  // The wrong key.
  await refused(
    { env: { GOBLIN_SECRET_KEY: otherKey } },
    error => error.code === 'key_mismatch' && error.exitCode === 78
  );
  // A previous key that opens the data is accepted, and reported for a rewrap.
  const rotated = await startControl(directory, {
    lock,
    credentialConfigured: true,
    release: '1.5.0',
    env: { GOBLIN_SECRET_KEY: otherKey, GOBLIN_SECRET_KEY_PREVIOUS: hexKey },
    keySources: noSources(directory),
  });
  assert.equal(rotated.key.needsRewrap, true);
  await rotated.keyring.rewrap();
  rotated.control.close();
  // A fence newer than this release.
  const writer = openSqlite(path.join(directory, controlFile));
  await writer.write(tx =>
    requireRelease(tx, { name: 'identity.totp', minRelease: '1.6.0', reason: 'TOTP', now: 1 })
  );
  writer.close();
  await refused(
    { env: { GOBLIN_SECRET_KEY: otherKey } },
    error =>
      error instanceof RefusalError &&
      error.exitCode === 78 &&
      /needs Uptime Goblin ≥ 1\.6\.0 \(TOTP\)/.test(error.message)
  );
  // An applied contract step this release does not know.
  const unknown = openSqlite(path.join(directory, controlFile));
  await unknown.write(tx => {
    tx.run(sql`DELETE FROM ${id('schema_fences')}`);
    tx.run(
      tx.dialect.insert(
        'schema_migrations',
        ['id', 'component', 'kind', 'release', 'applied_at'],
        [['platform-009-drop', 'platform', 'contract', '2.0.0', 1]]
      )
    );
  });
  unknown.close();
  await refused(
    { env: { GOBLIN_SECRET_KEY: otherKey } },
    error => error.code === 'data_newer' && /Uptime Goblin 2\.0\.0/.test(error.message)
  );
});

// Docs audit, keys 19: the key rotate line a key_mismatch refusal prints names the key files
// this start read, not the installer's file and a placeholder, so it runs as printed; and a
// start that needs a rewrap reports the previous key's file for the warning's line (keyLines()
// in server.mjs, test/startup.test.mjs).
test('a key_mismatch refusal and a start that needs a rewrap name the key files the start read', async t => {
  const directory = temporary(t);
  fs.writeFileSync(path.join(directory, 'config.json'), '{}\n');
  const lock = locked(t, directory);
  const keys = temporary(t, 'orbit-keys-');
  const keyFile = (name, hex) => {
    const file = path.join(keys, name);
    fs.writeFileSync(file, `${hex}\n`, { mode: 0o600 });
    return file;
  };
  const created = keyFile('created.key', hexKey),
    other = keyFile('other.key', otherKey),
    third = keyFile('third.key', 'e5'.repeat(16) + 'f6'.repeat(16));
  const start = env =>
    startControl(directory, {
      lock,
      credentialConfigured: true,
      release: '1.5.0',
      env,
      keySources: noSources(directory),
    });
  const first = await start({ GOBLIN_SECRET_KEY_FILE: created });
  first.control.close();
  let caught = null;
  await start({ GOBLIN_SECRET_KEY_FILE: other, GOBLIN_SECRET_KEY_PREVIOUS_FILE: third }).catch(
    error => (caught = error)
  );
  assert.equal(caught?.code, 'key_mismatch', String(caught));
  assert.ok(
    caught.message.includes(
      `run, with Uptime Goblin stopped: sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=${other} GOBLIN_SECRET_KEY_PREVIOUS_FILE=${third} node /opt/uptime-goblin/lib/cli/goblin-admin.mjs key rotate --data-dir /var/lib/uptime-goblin (the native install;`
    ),
    caught.message
  );
  // A key from elsewhere: the installer's file and the placeholder, as before.
  caught = null;
  await start({ GOBLIN_SECRET_KEY: otherKey }).catch(error => (caught = error));
  assert.match(
    caught.message,
    /: sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=\/etc\/uptime-goblin\/secret\.key GOBLIN_SECRET_KEY_PREVIOUS_FILE=OLD_KEY_FILE node /
  );
  // The previous key opens the data: the start goes on and names that key's file.
  const rotated = await start({
    GOBLIN_SECRET_KEY_FILE: other,
    GOBLIN_SECRET_KEY_PREVIOUS_FILE: created,
  });
  rotated.control.close();
  assert.equal(rotated.key.needsRewrap, true);
  assert.equal(rotated.key.file, other);
  assert.equal(rotated.key.previousFile, created);
});

// Review round 3: a volume that 1.5 ran on without compose.secret.yaml holds the secret.key it
// generated, also once a rollback to 1.4.3 runs on it (1.4.x ignores the file). The Compose
// recipe for 1.4.x data (a new key) then meets data sealed with that file's key: before, the
// refusal said only "Restore the key it was created with", with the native rotate command, and
// never named /app/data/secret.key, whose fingerprint the unused-key warning prints only on a
// start that succeeds. Now the refusal names it, its fingerprint, whether it opens the data,
// and, under Compose, the MOVE recipe (review of 9a7d6e5: the copy line no longer copies over an
// orbit_secret_key; A65: that recipe reads the key with a container of its own, since docker
// compose cp read it through the refused container and failed once its key file was set aside).
test('a key_mismatch refusal names a <data>/secret.key that the refused source outranked, and whether it opens the data', async t => {
  const directory = temporary(t);
  fs.writeFileSync(path.join(directory, 'config.json'), '{}\n');
  const lock = locked(t, directory);
  // 1.5 without another source: it generates <data>/secret.key and seals the data with it.
  const first = await startControl(directory, {
    lock,
    credentialConfigured: true,
    release: '1.5.0',
    env: {},
    keySources: noSources(directory),
  });
  first.control.close();
  assert.equal(first.key.source, 'generated');
  const own = path.join(directory, secretKeyFile);
  const generated = first.key.fingerprint;
  // The Compose secret of the new-key recipe.
  const secrets = temporary(t, 'orbit-secrets-');
  fs.writeFileSync(path.join(secrets, 'orbit_secret_key'), `${otherKey}\n`, { mode: 0o400 });
  const sources = { ...noSources(directory), secretsDirectory: secrets };
  const skip = ['goblin.lock', 'orbit.lock', 'run'];
  const refusal = async () => {
    const before = fingerprint(directory, skip);
    let caught = null;
    await startControl(directory, {
      lock,
      credentialConfigured: true,
      release: '1.5.0',
      env: {},
      keySources: sources,
    }).catch(error => (caught = error));
    assert.ok(caught instanceof KeyError, String(caught));
    assert.equal(caught.code, 'key_mismatch');
    assert.equal(caught.exitCode, 78);
    assert.deepEqual(fingerprint(directory, skip), before, 'no byte changed');
    return caught.message;
  };
  const refused = keyFingerprint(Buffer.from(otherKey, 'hex'));
  const message = await refusal();
  assert.ok(
    message.startsWith(
      `The encryption key (fingerprint ${refused}) does not match this data. Restore the key it was created with;`
    ),
    message
  );
  assert.ok(
    message.endsWith(
      ` ${own} (fingerprint ${generated}) opens this data: Uptime Goblin generated it there when it ran without the Compose secret (${path.join(secrets, 'orbit_secret_key')}), and a rollback to 1.4.x leaves it in place. Use that key: make the Compose secret (${path.join(secrets, 'orbit_secret_key')}) hold it (Docker Compose: the check in compose.secret.yaml prints MOVE: take that file's MOVE recipe, which puts this key in a new orbit_secret_key and keeps the current one as orbit_secret_key.unused), or remove the Compose secret (${path.join(secrets, 'orbit_secret_key')}) so that Uptime Goblin reads ${own} again.`
    ),
    message
  );
  // That file holding another key: it is named, and said not to open the data either.
  const third = 'e5'.repeat(16) + 'f6'.repeat(16);
  fs.chmodSync(own, 0o600);
  fs.writeFileSync(own, `${third}\n`);
  assert.ok(
    (await refusal()).endsWith(
      ` ${own} (fingerprint ${keyFingerprint(Buffer.from(third, 'hex'))}) is in the data directory too, but it does not open this data either.`
    )
  );
  // Without that file the refusal is as before.
  fs.rmSync(own);
  assert.ok(!(await refusal()).includes(own));
  // The same key in both places refuses as before too (nothing to add).
  fs.writeFileSync(own, `${otherKey}\n`, { mode: 0o600 });
  assert.ok(!(await refusal()).includes(`${own} (fingerprint`));
});

test('startControl needs the lock of its own data directory', async t => {
  const directory = temporary(t);
  await assert.rejects(startControl(directory, { env: {} }), /goblin\.lock/);
  const elsewhere = locked(t, temporary(t));
  await assert.rejects(startControl(directory, { lock: elsewhere, env: {} }), /goblin\.lock/);
  // The keyring of an in-memory store is refused by a key that did not create it.
  await assert.rejects(
    Keyring.check(
      memoryKeyringStore([{ kid: 'a', purpose: 'seal', wrapped: 'w1.x.y.z', created_at: 1 }]),
      {
        key: Buffer.from(hexKey, 'hex'),
      }
    ),
    { code: 'key_mismatch' }
  );
});

test("startControl with keyring 'existing' and no keyring reads, generates and removes no key (D2)", async t => {
  const directory = temporary(t);
  fs.writeFileSync(path.join(directory, 'config.json'), '{"services":[]}\n');
  const lock = locked(t, directory);
  const env = { GOBLIN_SECRET_KEY: hexKey, GOBLIN_SECRET_KEY_PREVIOUS: otherKey };
  const started = await startControl(directory, {
    lock,
    credentialConfigured: true,
    release: '1.5.0',
    env,
    keySources: noSources(directory),
    keyring: 'existing',
  });
  t.after(() => started.control.close());
  assert.equal(started.keyring, null);
  assert.equal(started.key, null);
  assert.deepEqual(
    env,
    { GOBLIN_SECRET_KEY: hexKey, GOBLIN_SECRET_KEY_PREVIOUS: otherKey },
    'the environment is not touched'
  );
  assert.equal(fs.existsSync(path.join(directory, secretKeyFile)), false, 'no secret.key');
  assert.equal(await started.control.keyringExists(), false, 'no keyring was created');
  assert.deepEqual(started.migration.applied, appliedOrder);
  // Settings without secret fields work; nothing asks for the key.
  assert.equal(await started.control.features.enabled('legacyBasic'), true, 'upgraded install');
  // The next start is the same: still no key, still no keyring.
  started.control.close();
  const again = await startControl(directory, {
    lock,
    credentialConfigured: true,
    release: '1.5.0',
    env: {},
    keySources: noSources(directory),
    keyring: 'existing',
  });
  again.control.close();
  assert.equal(again.keyring, null);
  assert.equal(fs.existsSync(path.join(directory, secretKeyFile)), false);
  await assert.rejects(
    startControl(directory, { lock, env: {}, keyring: 'sometimes' }),
    /keyring must be 'required', 'existing' or 'deferred'/
  );
});

test("startControl with keyring 'existing' still needs and checks the key once a keyring exists", async t => {
  const directory = temporary(t);
  const lock = locked(t, directory);
  // Only goblin-admin key reset (or a 'required' start) creates a keyring today.
  const first = await startControl(directory, {
    lock,
    credentialConfigured: true,
    release: '1.5.0',
    env: { GOBLIN_SECRET_KEY: hexKey },
    keySources: noSources(directory),
  });
  first.control.close();
  const skip = ['goblin.lock', 'orbit.lock', 'run'];
  const refused = async (env, check) => {
    const before = fingerprint(directory, skip);
    await assert.rejects(
      startControl(directory, {
        lock,
        credentialConfigured: true,
        release: '1.5.0',
        env,
        keySources: noSources(directory),
        keyring: 'existing',
      }),
      check
    );
    assert.deepEqual(fingerprint(directory, skip), before, 'no byte changed');
  };
  await refused(
    {},
    error => error instanceof KeyError && error.code === 'key_missing' && error.exitCode === 78
  );
  assert.equal(fs.existsSync(path.join(directory, secretKeyFile)), false, 'nothing generated');
  await refused(
    { GOBLIN_SECRET_KEY: otherKey },
    error => error instanceof KeyError && error.code === 'key_mismatch' && error.exitCode === 78
  );
  const env = { GOBLIN_SECRET_KEY: hexKey };
  const opened = await startControl(directory, {
    lock,
    credentialConfigured: true,
    release: '1.5.0',
    env,
    keySources: noSources(directory),
    keyring: 'existing',
  });
  t.after(() => opened.control.close());
  assert.equal(opened.key.source, 'env');
  assert.equal(env.GOBLIN_SECRET_KEY, undefined, 'a key that is read leaves the environment');
  assert.ok(opened.keyring);
  assert.equal(opened.keyring.describe().length, 4);
});

// ---------------------------------------------------------------------------------------------
// keyring 'deferred' (delivery spec D6): every start opens the keyring, and creates it only
// once the caller (after identity) calls createKeyring().

const keyFileIn = (t, contents = hexKey) => {
  const file = path.join(temporary(t, 'orbit-keyfile-'), 'secret.key');
  fs.writeFileSync(file, `${contents}\n`, { mode: 0o600 });
  return file;
};
const deferredStart = (directory, lock, env, extra = {}) =>
  startControl(directory, {
    lock,
    credentialConfigured: true,
    release: '1.5.0',
    env,
    keySources: noSources(directory),
    keyring: 'deferred',
    ...extra,
  });

test("startControl 'deferred' with GOBLIN_SECRET_KEY_FILE: no key file and no keyring until createKeyring()", async t => {
  const directory = temporary(t);
  fs.writeFileSync(path.join(directory, 'config.json'), '{"services":[]}\n');
  const lock = locked(t, directory);
  const file = keyFileIn(t);
  const env = { GOBLIN_SECRET_KEY_FILE: file };
  const started = await deferredStart(directory, lock, env);
  t.after(() => started.control.close());
  assert.equal(started.keyring, null);
  assert.deepEqual(started.key, {
    source: 'file',
    file,
    previousFile: null,
    fingerprint: keyFingerprint(Buffer.from(hexKey, 'hex')),
    warnings: [],
    needsRewrap: false,
    previous: null,
  });
  assert.deepEqual(env, { GOBLIN_SECRET_KEY_FILE: file }, 'only GOBLIN_SECRET_KEY* leave env');
  assert.equal(fs.existsSync(path.join(directory, secretKeyFile)), false);
  assert.equal(await started.control.keyringExists(), false, 'nothing created yet');
  assert.deepEqual(started.migration.applied, appliedOrder);
  const { keyring, key } = await started.createKeyring();
  assert.equal(key.source, 'file');
  assert.equal(key.fingerprint, keyring.fingerprint);
  assert.equal(keyring.describe().length, 4);
  assert.equal(await started.control.keyringExists(), true);
  assert.equal(fs.existsSync(path.join(directory, secretKeyFile)), false, 'never generated');
  // Settings can seal secrets now: createKeyring() gave the keyring to them.
  started.control.settings.define({
    component: 'test',
    key: 'secret',
    fields: { value: { secret: true, validate: value => value } },
  });
  await started.control.settings.update('test', 'secret', { value: 's3cret' });
  assert.equal((await started.control.settings.get('test', 'secret')).value.value, 's3cret');
  // It runs once.
  await assert.rejects(started.createKeyring(), TypeError);
  // The next start opens the keyring it made; nothing is left to create.
  started.control.close();
  const again = await deferredStart(directory, lock, { GOBLIN_SECRET_KEY_FILE: file });
  again.control.close();
  assert.ok(again.keyring);
  assert.equal(again.createKeyring, null);
  assert.doesNotThrow(() => again.discardKey());
  assert.equal(again.key.source, 'file');
});

test("startControl 'deferred' reads GOBLIN_SECRET_KEY and removes it from the environment before anything is created", async t => {
  const directory = temporary(t);
  const lock = locked(t, directory);
  const env = { GOBLIN_SECRET_KEY: hexKey, GOBLIN_SECRET_KEY_PREVIOUS: otherKey, KEEP: '1' };
  const started = await deferredStart(directory, lock, env);
  t.after(() => started.control.close());
  assert.deepEqual(env, { KEEP: '1' }, 'removed in step 2, before identity runs');
  assert.equal(started.key.source, 'env');
  assert.equal(started.key.previous, keyFingerprint(Buffer.from(otherKey, 'hex')));
  assert.equal(await started.control.keyringExists(), false);
  const { keyring, key } = await started.createKeyring();
  assert.equal(key.source, 'env');
  assert.equal(keyring.fingerprint, keyFingerprint(Buffer.from(hexKey, 'hex')));
  assert.equal(fs.existsSync(path.join(directory, secretKeyFile)), false);
});

test("startControl 'deferred' without any key source generates nothing; createKeyring() generates secret.key", async t => {
  const directory = temporary(t);
  const lock = locked(t, directory);
  const started = await deferredStart(directory, lock, {});
  t.after(() => started.control.close());
  assert.equal(started.key, null, 'no source was found');
  assert.equal(fs.existsSync(path.join(directory, secretKeyFile)), false);
  const { keyring, key } = await started.createKeyring();
  const file = path.join(directory, secretKeyFile);
  assert.deepEqual([key.source, key.file], ['generated', file]);
  assert.match(key.warnings[0], /inside the data directory/);
  assert.equal(mode(file), 0o600);
  assert.equal(keyring.fingerprint, key.fingerprint);
  assert.equal(
    keyring.fingerprint,
    keyFingerprint(Buffer.from(fs.readFileSync(file, 'utf8').trim(), 'hex'))
  );
  // From now on the data-directory key opens it.
  started.control.close();
  const again = await deferredStart(directory, lock, {});
  again.control.close();
  assert.equal(again.key.source, 'data-directory');
  assert.ok(again.keyring);
});

test("startControl 'deferred' finds the Compose secret and the systemd credential", async t => {
  const directory = temporary(t);
  const lock = locked(t, directory);
  const secrets = path.join(directory, 'no-secrets');
  fs.mkdirSync(secrets);
  fs.writeFileSync(path.join(secrets, 'orbit_secret_key'), hexKey, { mode: 0o400 });
  const started = await deferredStart(directory, lock, {});
  t.after(() => started.control.close());
  assert.deepEqual(
    [started.key.source, started.key.file],
    ['secrets', path.join(secrets, 'orbit_secret_key')]
  );
  const { key } = await started.createKeyring();
  assert.equal(key.source, 'secrets');
  assert.equal(fs.existsSync(path.join(directory, secretKeyFile)), false);
});

test("startControl 'deferred': a start abandoned before createKeyring() leaves no key file and no keyring", async t => {
  const directory = temporary(t);
  const lock = locked(t, directory);
  // Without a source: discardKey() is a no-op, and nothing was generated.
  const none = await deferredStart(directory, lock, {});
  none.discardKey();
  none.control.close();
  assert.equal(fs.existsSync(path.join(directory, secretKeyFile)), false);
  // With a source: the key kept for createKeyring() is zeroed, and createKeyring() refuses.
  const zeroed = [];
  const started = await deferredStart(directory, lock, { GOBLIN_SECRET_KEY: hexKey });
  const fill = Buffer.prototype.fill;
  t.mock.method(Buffer.prototype, 'fill', function (value, ...rest) {
    if (value === 0 && this.length === 32) zeroed.push(Buffer.from(this));
    return fill.call(this, value, ...rest);
  });
  started.discardKey();
  t.mock.restoreAll();
  assert.equal(zeroed.length, 1, 'the kept key was zeroed');
  assert.ok(zeroed[0].equals(Buffer.from(hexKey, 'hex')), 'it was the key');
  await assert.rejects(started.createKeyring(), /discarded/);
  started.discardKey();
  started.control.close();
  const opened = openControl(directory, { release: '1.5.0', env: {}, readOnly: true });
  t.after(() => opened.close());
  assert.equal(await opened.keyringExists(), false);
  assert.equal(fs.existsSync(path.join(directory, secretKeyFile)), false);
});

test("startControl 'deferred': the four key refusals leave the data directory byte-identical (T11)", async t => {
  const directory = temporary(t);
  fs.writeFileSync(path.join(directory, 'config.json'), '{}\n');
  const lock = locked(t, directory);
  const skip = ['goblin.lock', 'orbit.lock', 'run'];
  const refused = async (env, code) => {
    const before = fingerprint(directory, skip);
    await assert.rejects(deferredStart(directory, lock, env), error => {
      assert.equal(error.code, code);
      assert.equal(error.exitCode, 78);
      return true;
    });
    assert.deepEqual(fingerprint(directory, skip), before, `${code}: no byte changed`);
    assert.equal(fs.existsSync(path.join(directory, secretKeyFile)), false, code);
  };
  // Before any keyring: an invalid or unreadable key refuses before control.sqlite exists.
  await refused({ GOBLIN_SECRET_KEY: 'not a key' }, 'key_invalid');
  await refused(
    { GOBLIN_SECRET_KEY_FILE: path.join(directory, 'missing.key') },
    'key_file_unreadable'
  );
  assert.equal(controlExists(directory), false);
  // A keyring made with hexKey.
  const first = await deferredStart(directory, lock, { GOBLIN_SECRET_KEY: hexKey });
  await first.createKeyring();
  first.control.close();
  await refused({}, 'key_missing');
  await refused({ GOBLIN_SECRET_KEY: otherKey }, 'key_mismatch');
  await refused({ GOBLIN_SECRET_KEY: 'zz' }, 'key_invalid');
  await refused(
    { GOBLIN_SECRET_KEY_FILE: path.join(directory, 'missing.key') },
    'key_file_unreadable'
  );
  const ok = await deferredStart(directory, lock, { GOBLIN_SECRET_KEY: hexKey });
  ok.control.close();
  assert.ok(ok.keyring);
});

test('createKeyring() writes and fsyncs a generated key (file, then directory) before the keyring exists', async t => {
  const directory = temporary(t);
  const lock = locked(t, directory);
  const started = await deferredStart(directory, lock, {});
  t.after(() => started.control.close());
  const opened = new Map(),
    order = [],
    open = fs.openSync,
    fsync = fs.fsyncSync;
  t.mock.method(fs, 'openSync', function (file, ...rest) {
    const descriptor = open.call(fs, file, ...rest);
    opened.set(descriptor, String(file));
    return descriptor;
  });
  t.mock.method(fs, 'fsyncSync', function (descriptor) {
    order.push(opened.get(descriptor));
    return fsync.call(fs, descriptor);
  });
  const resolving = started.createKeyring();
  // Synchronously, before the keyring's write: the file and the directory were fsynced.
  assert.deepEqual(order, [path.join(directory, secretKeyFile), directory]);
  await resolving;
  assert.equal(await started.control.keyringExists(), true);
});

test('inspectKeyring reads a copy: whether it has a keyring, whether a key opens it, and fails loudly', async t => {
  const directory = temporary(t);
  const lock = locked(t, directory);
  const copyOf = name => {
    const target = path.join(temporary(t, 'orbit-copy-'), 'control.sqlite');
    for (const suffix of ['', '-wal'])
      if (fs.existsSync(path.join(directory, `${name}${suffix}`)))
        fs.copyFileSync(path.join(directory, `${name}${suffix}`), `${target}${suffix}`);
    return target;
  };
  const key = Buffer.from(hexKey, 'hex'),
    other = Buffer.from(otherKey, 'hex');
  // A control database without a keyring (the sessions milestone's).
  const before = await startControl(directory, {
    lock,
    credentialConfigured: true,
    release: '1.5.0',
    env: {},
    keySources: noSources(directory),
    keyring: 'existing',
  });
  const plain = copyOf(controlFile);
  assert.deepEqual(await inspectKeyring(plain), { keyring: false, matches: null });
  assert.deepEqual(await inspectKeyring(plain, { key }), { keyring: false, matches: null });
  before.control.close();
  // With a keyring (made with hexKey; -wal copied too, as the installer does).
  const started = await deferredStart(directory, lock, { GOBLIN_SECRET_KEY: hexKey });
  await started.createKeyring();
  const copy = copyOf(controlFile);
  started.control.close();
  const live = fingerprint(directory);
  assert.deepEqual(await inspectKeyring(copy), { keyring: true, matches: null });
  assert.deepEqual(await inspectKeyring(copy, { key }), { keyring: true, matches: true });
  assert.deepEqual(await inspectKeyring(copy, { key: other }), { keyring: true, matches: false });
  // The previous key opens it too (a key change in progress).
  assert.deepEqual(await inspectKeyring(copy, { key: other, previous: key }), {
    keyring: true,
    matches: true,
  });
  assert.deepEqual(fingerprint(directory), live, 'the live data was never opened');
  // A copy torn mid-page (taken while Uptime Goblin wrote) rejects, as does a damaged one, or none:
  // never "no keyring".
  const torn = path.join(temporary(t, 'orbit-torn-'), 'control.sqlite');
  fs.copyFileSync(copy, torn);
  if (fs.existsSync(`${copy}-wal`)) fs.copyFileSync(`${copy}-wal`, `${torn}-wal`);
  const settle = new DatabaseSync(torn);
  settle.exec('PRAGMA wal_checkpoint(TRUNCATE); PRAGMA journal_mode=DELETE');
  settle.close();
  fs.truncateSync(torn, Math.floor(fs.statSync(torn).size / 2) + 100);
  await assert.rejects(inspectKeyring(torn), error => {
    assert.ok(error.code, String(error));
    return true;
  });
  const damaged = path.join(temporary(t, 'orbit-damaged-'), 'control.sqlite');
  fs.writeFileSync(
    damaged,
    Buffer.concat([Buffer.from('SQLite format 3\0'), Buffer.alloc(200, 7)])
  );
  await assert.rejects(inspectKeyring(damaged));
  const garbage = path.join(temporary(t, 'orbit-garbage-'), 'control.sqlite');
  fs.writeFileSync(garbage, 'not a database at all, but long enough to have a header'.repeat(10));
  await assert.rejects(inspectKeyring(garbage));
  await assert.rejects(inspectKeyring(path.join(directory, 'nothing.sqlite')));
});

test('startControl refuses, reading only, every start without a password source, whatever credentials_ever says (D4)', async t => {
  const directory = temporary(t);
  const lock = locked(t, directory);
  const start = options =>
    startControl(directory, {
      lock,
      release: '1.5.0',
      env: {},
      keySources: noSources(directory),
      keyring: 'existing',
      ...options,
    });
  const skip = ['goblin.lock', 'orbit.lock', 'run'];
  const refused = async (why, options = { credentialConfigured: false }) => {
    const before = fingerprint(directory, skip);
    await assert.rejects(
      start(options),
      error =>
        error instanceof RefusalError &&
        error.code === 'password_required' &&
        error.refusal === true &&
        error.exitCode === 78 &&
        error.message === passwordRequiredMessage,
      why
    );
    assert.deepEqual(fingerprint(directory, skip), before, `${why}: no byte changed`);
    assert.ok(!fs.existsSync(path.join(directory, `${controlFile}-wal`)), `${why}: no WAL left`);
  };
  // A new directory: no control.sqlite is created (Uptime Goblin always requires a password; there is no
  // passwordless start to allow).
  await refused('a new data directory');
  assert.equal(controlExists(directory), false);
  // A directory whose control.sqlite has never recorded a credential (credentials_ever unset, as
  // an earlier 1.5 pre-release left it after a passwordless start).
  const configured = await start({ credentialConfigured: true });
  assert.equal(await configured.control.meta.credentialsEver(), false);
  configured.control.close();
  await refused('credentials_ever unset');
  // Identity sets credentials_ever when u_admin first gets a password: refused the same way.
  const marked = await start({ credentialConfigured: true });
  await marked.control.meta.markCredentials();
  marked.control.close();
  await refused('credentials_ever set');
  assert.match(passwordRequiredMessage, /^Uptime Goblin needs an admin password, and none is set/);
  // docs/authentication.md quotes the refusal word for word.
  assert.ok(
    fs
      .readFileSync(new URL('../../docs/authentication.md', import.meta.url), 'utf8')
      .includes(passwordRequiredMessage),
    'docs/authentication.md quotes passwordRequiredMessage as it is'
  );
  // With a source configured again, the start proceeds. There is no default: a start that does
  // not say is refused (the next test).
  (await start({ credentialConfigured: true })).control.close();
  await assert.rejects(start({}), /startControl needs credentialConfigured: true or false/);
});

// Review F7: credentialConfigured defaulted to true, and only an explicit false was refused, so
// a caller that left it out (none ships: server.mjs passes it, and refuses first) snapshotted,
// migrated and made keys without any password source. Now it must be true or false.
test('startControl without an explicit credentialConfigured starts nothing: no snapshot, migration or key (F7)', async t => {
  const directory = temporary(t);
  // 1.4.x data: a start would take a pinned pre-upgrade snapshot, create control.sqlite,
  // migrate it, and take the key out of the environment.
  fs.writeFileSync(path.join(directory, 'config.json'), '{"services":[]}\n');
  fs.writeFileSync(path.join(directory, 'auth.json'), '{"version":1}\n');
  const lock = locked(t, directory);
  const skip = ['goblin.lock', 'orbit.lock', 'run'];
  const before = fingerprint(directory, skip);
  const missing = Symbol('missing');
  for (const keyring of ['required', 'existing', 'deferred'])
    for (const value of [missing, undefined, null, 'true', 1, {}, []]) {
      const why = `keyring ${keyring}, credentialConfigured ${missing === value ? 'left out' : JSON.stringify(value)}`;
      const env = { GOBLIN_SECRET_KEY: hexKey };
      await assert.rejects(
        startControl(directory, {
          lock,
          release: '1.5.0',
          env,
          keySources: noSources(directory),
          keyring,
          ...(value === missing ? {} : { credentialConfigured: value }),
        }),
        error =>
          error instanceof TypeError &&
          error.message === 'startControl needs credentialConfigured: true or false',
        why
      );
      assert.equal(env.GOBLIN_SECRET_KEY, hexKey, `${why}: no key was read`);
      assert.deepEqual(fingerprint(directory, skip), before, `${why}: no byte changed`);
      assert.equal(controlExists(directory), false, `${why}: no control.sqlite`);
      assert.equal(fs.existsSync(path.join(directory, secretKeyFile)), false, why);
      assert.equal(fs.existsSync(path.join(directory, 'snapshots')), false, `${why}: no snapshot`);
    }
  // false is still the password refusal, and true still starts (snapshot, migration, key).
  await assert.rejects(
    startControl(directory, {
      lock,
      credentialConfigured: false,
      release: '1.5.0',
      env: { GOBLIN_SECRET_KEY: hexKey },
      keySources: noSources(directory),
    }),
    { code: 'password_required' }
  );
  assert.deepEqual(fingerprint(directory, skip), before, 'false: no byte changed');
  const env = { GOBLIN_SECRET_KEY: hexKey };
  const started = await startControl(directory, {
    lock,
    credentialConfigured: true,
    release: '1.5.0',
    env,
    keySources: noSources(directory),
  });
  t.after(() => started.control.close());
  assert.equal(env.GOBLIN_SECRET_KEY, undefined, 'true: the key left the environment');
  assert.equal(started.snapshot.reused, false, 'true: the pre-upgrade snapshot was taken');
  assert.equal(controlExists(directory), true);
});

test('a first start over 1.4.x data leaves history.sqlite out of its snapshot, even when it is larger than the free space (D24)', async t => {
  const directory = temporary(t);
  fs.writeFileSync(path.join(directory, 'config.json'), '{"services":[]}\n');
  fs.writeFileSync(path.join(directory, 'auth.json'), '{"version":1}\n');
  // A sparse history.sqlite whose apparent size exceeds what the filesystem has free: copying
  // it would refuse with snapshot_space.
  const space = fs.statfsSync(directory);
  const free = Number(space.bavail) * Number(space.bsize);
  const history = path.join(directory, 'history.sqlite');
  fs.writeFileSync(history, '');
  fs.truncateSync(history, free + 2 ** 30);
  assert.ok(fs.statSync(history).size > free);
  const lock = locked(t, directory);
  const started = await startControl(directory, {
    lock,
    credentialConfigured: true,
    release: '1.5.0-dev.0',
    env: {},
    keySources: noSources(directory),
    keyring: 'existing',
  });
  t.after(() => started.control.close());
  const [snapshot] = listSnapshots(directory);
  assert.deepEqual(started.snapshot, { id: snapshot.id, reused: false });
  assert.equal(snapshot.pinned, true);
  const manifest = manifestOf(directory, snapshot.id);
  assert.deepEqual(
    manifest.files.map(file => file.name),
    ['config.json', 'auth.json']
  );
  assert.deepEqual(manifest.excluded, ['history.sqlite']);
  assert.deepEqual(manifest.absent, ['control.sqlite'], 'taken before the migration creates it');
  assert.equal(fs.statSync(history).size, free + 2 ** 30, 'history.sqlite untouched');
  // The upgrade notes say what it holds: they had listed control.sqlite too, while restoring it
  // removes control.sqlite (as authentication.md says).
  const read = name => fs.readFileSync(new URL(`../../${name}`, import.meta.url), 'utf8');
  for (const name of ['docs/installation.md', 'CHANGELOG.md']) {
    const notes = read(name)
      .split('\n')
      .filter(line => line.startsWith('- **Free space:**'));
    assert.equal(notes.length, 1, name);
    assert.match(notes[0], /pinned snapshot of `config\.json` and `auth\.json`/, name);
    assert.doesNotMatch(notes[0], /`auth\.json` and `control\.sqlite`/, name);
    // 1.5 does change history.sqlite, by adding to it (lib/store.mjs; the upgrade suite's U2
    // compares the schema 1.4.3 left with WT's): the notes once said it did not (review round 2).
    assert.doesNotMatch(notes[0], /1\.5 does not change/, name);
    assert.match(
      notes[0],
      /adds (to `history\.sqlite`: )?three columns and a partial index (on|to) its `events` table, which 1\.4\.x ignores/,
      name
    );
  }
  // An explicit history snapshot of the same data still refuses for lack of space.
  await assert.rejects(
    takeMigrationSnapshot(directory, { release: '1.5.0-dev.1', history: true }),
    error => error.code === 'snapshot_space'
  );
});

test('a first start over 1.4.x data has its pinned snapshot on disk before the migration commits', async t => {
  // The way back to 1.4.x was never flushed: the copies (copyFileSync), the manifest and the
  // folder's final name, while the migration's commit is (synchronous=FULL). A power loss in the
  // writeback window could keep that commit and lose the rename, and the next start deleted
  // .staging-<id> as a dead process's leftover; or lose the data, leaving an INVALID snapshot.
  // With nothing pending any more, no start took another (r6).
  const directory = temporary(t);
  fs.writeFileSync(path.join(directory, 'config.json'), '{"services":[]}\n');
  fs.writeFileSync(path.join(directory, 'auth.json'), '{"version":1}\n');
  const lock = locked(t, directory);
  const events = [];
  const opened = new Map();
  // A temporary file by its fixed part: the manifest's is manifest.json.<uuid>.tmp.
  const short = file =>
    (path.relative(directory, String(file)) || '.').replace(
      /\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.tmp$/,
      '.tmp'
    );
  const { openSync, fsyncSync, renameSync } = fs;
  const stop = () => Object.assign(fs, { openSync, fsyncSync, renameSync });
  t.after(stop);
  fs.openSync = function (...args) {
    const handle = openSync.apply(this, args);
    opened.set(handle, short(args[0]));
    return handle;
  };
  fs.fsyncSync = function (...args) {
    events.push(`fsync ${opened.get(args[0])}`);
    return fsyncSync.apply(this, args);
  };
  fs.renameSync = function (...args) {
    events.push(`rename ${short(args[0])} -> ${short(args[1])}`);
    return renameSync.apply(this, args);
  };
  const started = await startControl(directory, {
    lock,
    credentialConfigured: true,
    release: '1.5.0-dev.0',
    env: {},
    keySources: noSources(directory),
    keyring: 'existing',
    // Called before each step's unit: the first one marks where the migration begins to commit.
    onProgress: ({ index }) => index === 0 && events.push('migrate'),
  });
  stop();
  t.after(() => started.control.close());
  assert.equal(started.migration.applied.length, controlSteps.length);
  const at = (event, from = 0) => {
    const index = events.indexOf(event, from);
    assert.notEqual(index, -1, `${event} (after #${from}) in:\n${events.join('\n')}`);
    return index;
  };
  const migrate = at('migrate');
  const { id: snapshotId } = started.snapshot;
  const root = 'snapshots';
  const staging = path.join(root, `.staging-${snapshotId}`);
  const manifest = path.join(staging, 'manifest.json');
  const final = at(`rename ${staging} -> ${path.join(root, snapshotId)}`);
  // Each copy, then the manifest (flushed before its rename), then the folder's entries, all
  // before the folder takes its final name.
  for (const name of ['config.json', 'auth.json'])
    assert.ok(at(`fsync ${path.join(staging, name)}`) < final, `${name} flushed`);
  const written = at(`rename ${manifest}.tmp -> ${manifest}`);
  assert.ok(at(`fsync ${manifest}.tmp`) < written);
  assert.ok(at(`fsync ${staging}`, written) < final, 'the folder’s entries before its name');
  // Its final name (snapshots/), and snapshots/ itself (new: an entry of the data directory),
  // before the migration.
  assert.ok(at(`fsync ${root}`, final) < migrate, 'the final name before the migration');
  assert.ok(at('fsync .', final) < migrate, 'the new snapshots/ before the migration');
  assert.equal(listSnapshots(directory).find(item => item.id === snapshotId)?.valid, true);
});

test('startControl removes snapshots/.staging-* left by a process that died, and keeps .restoring-* unless empty', async t => {
  // An empty .restoring-* folder that no journal names (a restore stopped before it set a file
  // aside, once a later restore finished its journal) holds nothing, but stayed for ever, listed
  // as an interrupted restore's; with a journal the start refuses before it removes anything.
  const directory = temporary(t);
  fs.writeFileSync(path.join(directory, 'config.json'), '{"services":[]}\n');
  const root = path.join(directory, 'snapshots');
  const staging = path.join(root, '.staging-pre-upgrade-1.5.0-20260901T000000Z');
  const restoring = path.join(root, '.restoring-pre-restore-1.5.0-20260901T000000Z');
  const empty = path.join(root, '.restoring-pre-restore-1.5.0-20260901T000001Z');
  for (const folder of [staging, restoring]) {
    fs.mkdirSync(folder, { recursive: true });
    fs.writeFileSync(path.join(folder, 'config.json'), '{}');
  }
  fs.mkdirSync(empty);
  const lock = locked(t, directory);
  // A refusal writes nothing, so leftovers stay until a start gets past the refusals.
  const configured = await startControl(directory, {
    lock,
    credentialConfigured: true,
    release: '1.5.0',
    env: {},
    keySources: noSources(directory),
    keyring: 'existing',
  });
  await configured.control.meta.markCredentials();
  configured.control.close();
  assert.equal(fs.existsSync(empty), false, 'an empty folder no journal names is gone');
  fs.mkdirSync(staging, { recursive: true });
  fs.mkdirSync(empty);
  await assert.rejects(
    startControl(directory, {
      lock,
      release: '1.5.0',
      env: {},
      keySources: noSources(directory),
      keyring: 'existing',
      credentialConfigured: false,
    }),
    { code: 'password_required' }
  );
  assert.equal(fs.existsSync(staging), true, 'a refusal removed nothing');
  assert.equal(fs.existsSync(empty), true, 'a refusal removed nothing');
  const started = await startControl(directory, {
    lock,
    credentialConfigured: true,
    release: '1.5.0',
    env: {},
    keySources: noSources(directory),
    keyring: 'existing',
  });
  started.control.close();
  assert.equal(fs.existsSync(staging), false, 'the staging leftover is gone');
  assert.equal(fs.existsSync(restoring), true, 'an interrupted restore is never touched');
  assert.equal(fs.existsSync(path.join(restoring, 'config.json')), true);
  assert.equal(fs.existsSync(empty), false, 'an empty folder no journal names is gone');
  assert.ok(!fs.readdirSync(root).some(name => name.startsWith('.staging-')));
  // With nothing pending (no snapshot to take), a leftover is still removed.
  fs.mkdirSync(staging);
  (
    await startControl(directory, {
      lock,
      credentialConfigured: true,
      release: '1.5.0',
      env: {},
      keySources: noSources(directory),
      keyring: 'existing',
    })
  ).control.close();
  assert.equal(fs.existsSync(staging), false);
});

test('startControl removes the copies a restore that a crash stopped left; a journal refuses first and keeps them', async t => {
  // A restore killed while it copied (step 1) leaves full-size copies under hidden names in the
  // data directory, history.sqlite's included, and no journal. Nothing ever removed them, so the
  // space was lost to history for good. Under the lock and with no journal, no restore uses them.
  const directory = temporary(t);
  fs.writeFileSync(path.join(directory, 'config.json'), '{"services":[]}\n');
  const copies = {
    '.config.json.restoring': 40,
    '.history.sqlite.restoring': 3000,
    '.history.sqlite.restoring-journal': 512,
  };
  for (const [name, bytes] of Object.entries(copies))
    fs.writeFileSync(path.join(directory, name), Buffer.alloc(bytes, 7));
  const lock = locked(t, directory);
  const options = {
    lock,
    credentialConfigured: true,
    release: '1.5.0',
    env: {},
    keySources: noSources(directory),
    keyring: 'existing',
  };
  // An interrupted restore's journal: the start refuses before it writes anything, so the copies
  // (that restore's) stay.
  const journal = path.join(directory, 'snapshots', restoreJournal);
  fs.mkdirSync(path.dirname(journal), { recursive: true });
  fs.writeFileSync(
    journal,
    JSON.stringify({
      snapshot: 'manual-1.5.0-20260901T000000Z',
      aside: 'pre-restore-1.5.0-20260901T000001Z',
      files: ['config.json', 'history.sqlite'],
      keepHistory: false,
    })
  );
  const before = fingerprint(directory, ['goblin.lock', 'orbit.lock']);
  await assert.rejects(startControl(directory, options), { code: 'restore_interrupted' });
  assert.deepEqual(
    fingerprint(directory, ['goblin.lock', 'orbit.lock']),
    before,
    'a refusal removed nothing'
  );
  // Without a journal the start removes them, and says which.
  fs.rmSync(journal);
  const started = await startControl(directory, options);
  started.control.close();
  for (const name of Object.keys(copies))
    assert.equal(fs.existsSync(path.join(directory, name)), false, name);
  assert.deepEqual(started.leftovers, [
    { id: '.config.json.restoring', names: ['.config.json.restoring'], bytes: 40 },
    {
      id: '.history.sqlite.restoring',
      names: ['.history.sqlite.restoring', '.history.sqlite.restoring-journal'],
      bytes: 3512,
    },
  ]);
  const again = await startControl(directory, options);
  again.control.close();
  assert.deepEqual(again.leftovers, [], 'nothing left the next time');
});

test('a stop requested during startControl stops at the next boundary and closes what it opened', async t => {
  const legacy = () => {
    const directory = temporary(t);
    fs.writeFileSync(path.join(directory, 'config.json'), '{"services":[]}\n');
    fs.writeFileSync(path.join(directory, 'auth.json'), '{"version":1}\n');
    return directory;
  };
  const reason = Object.assign(new Error('stop requested'), { name: 'AbortError' });
  // A signal that reports the abort at the n-th check, so each boundary can be reached.
  const abortAt = n => {
    let calls = 0;
    return {
      get aborted() {
        return calls >= n;
      },
      reason,
      throwIfAborted() {
        calls += 1;
        if (calls >= n) throw reason;
      },
    };
  };
  const start = (directory, lock, signal) =>
    startControl(directory, {
      lock,
      credentialConfigured: true,
      release: '1.5.0',
      env: {},
      keySources: noSources(directory),
      keyring: 'existing',
      signal,
    });

  // Aborted before the start: no snapshot, no control.sqlite.
  {
    const directory = legacy();
    const lock = locked(t, directory);
    const controller = new AbortController();
    controller.abort(reason);
    const before = fingerprint(directory, ['goblin.lock', 'orbit.lock']);
    await assert.rejects(start(directory, lock, controller.signal), error => error === reason);
    assert.deepEqual(fingerprint(directory, ['goblin.lock', 'orbit.lock']), before);
  }
  // Before the snapshot.
  {
    const directory = legacy();
    const lock = locked(t, directory);
    await assert.rejects(start(directory, lock, abortAt(1)), error => error === reason);
    assert.equal(listSnapshots(directory).length, 0);
    assert.equal(controlExists(directory), false);
  }
  // After the snapshot: it is kept, nothing is migrated, and the next start reuses it.
  {
    const directory = legacy();
    const lock = locked(t, directory);
    await assert.rejects(start(directory, lock, abortAt(2)), error => error === reason);
    const [snapshot] = listSnapshots(directory);
    assert.equal(snapshot.pinned, true);
    assert.equal(controlExists(directory), false);
    const next = await start(directory, lock, null);
    next.control.close();
    assert.deepEqual(next.snapshot, { id: snapshot.id, reused: true });
    assert.equal(listSnapshots(directory).length, 1);
  }
  // After the migration: the steps completed, the database was closed (no -wal left), and the
  // next start has nothing to do.
  {
    const directory = legacy();
    const lock = locked(t, directory);
    await assert.rejects(start(directory, lock, abortAt(3)), error => error === reason);
    assert.equal(controlExists(directory), true);
    assert.equal(fs.existsSync(path.join(directory, `${controlFile}-wal`)), false, 'closed');
    const next = await start(directory, lock, null);
    next.control.close();
    assert.deepEqual(next.migration.applied, []);
    assert.equal(next.snapshot, null);
  }
});

// ---------------------------------------------------------------------------------------------
// The idempotency store and history.sqlite migrations.

test('the idempotency store keeps keyed answers in idempotency_keys, across a restart', async t => {
  const { createIdempotency } = await import('../../lib/http/idempotency.mjs');
  const { createIdempotencyStore } = await import('../../lib/db/control.mjs');
  const directory = temporary(t);
  let now = Date.UTC(2026, 8, 1);
  const clock = () => now;
  let control = openControl(directory, { release: '1.5.0', env: {}, clock });
  await control.migrate();
  const secret = Buffer.alloc(32, 5);
  const make = () =>
    createIdempotency({
      store: createIdempotencyStore(control.db, { clock }),
      now: clock,
      secret,
      sleep: async () => {},
    });
  let runs = 0;
  const execute = async () => ({
    status: 200,
    body: JSON.stringify({ run: ++runs }),
    headers: { 'content-type': 'application/json' },
  });
  const scope = ['rev-1', 'POST', '/api/services'];
  const first = await make().run({ key: 'key-00000001', scope, body: '{"a":1}', execute });
  assert.equal(first.outcome, 'executed');
  assert.equal(first.kept, true);
  // A new process (a new Db) replays it.
  control.close();
  control = openControl(directory, { release: '1.5.0', env: {}, clock });
  t.after(() => control.close());
  const replay = await make().run({ key: 'key-00000001', scope, body: '{"a":1}', execute });
  assert.equal(replay.outcome, 'replayed');
  assert.deepEqual(replay.response, first.response);
  assert.equal(runs, 1);
  assert.equal(
    (await make().run({ key: 'key-00000001', scope, body: '{"a":2}', execute })).outcome,
    'conflict'
  );
  // Another scope with the same key is another entry.
  assert.equal(
    (await make().run({ key: 'key-00000001', scope: ['rev-2', 'POST', '/x'], body: '', execute }))
      .outcome,
    'executed'
  );
  const rows = await control.db.read(tx =>
    tx.all(
      sql`SELECT ${id('principal')}, ${id('key')}, ${id('route')}, ${id('state')} FROM ${id('idempotency_keys')}`
    )
  );
  assert.equal(rows.length, 2);
  assert.ok(rows.every(row => /^[0-9a-f]{64}$/.test(row.principal) && row.key === 'key-00000001'));
  assert.deepEqual(rows.map(row => row.route).sort(), [
    'rev-1\nPOST\n/api/services',
    'rev-2\nPOST\n/x',
  ]);
  // A refusal (503) is not kept, and a failure forgets the key.
  const refused = await make().run({
    key: 'key-00000002',
    scope,
    body: '',
    execute: async () => ({ status: 503, body: 'busy' }),
  });
  assert.equal(refused.kept, false);
  await assert.rejects(
    make().run({
      key: 'key-00000003',
      scope,
      body: '',
      execute: async () => {
        throw new Error('no');
      },
    }),
    /no/
  );
  assert.equal(
    await control.db.read(tx => tx.get(sql`SELECT COUNT(*) AS n FROM ${id('idempotency_keys')}`).n),
    2
  );
  // After ten minutes the answers are pruned.
  now += 11 * 60 * 1000;
  assert.equal(await make().prune(), 2);
});

test('the idempotency store adapter: leases, take-over after a crash, stale entries and the entry cap', async t => {
  const { createIdempotencyStore } = await import('../../lib/db/control.mjs');
  const control = openControl(temporary(t), { release: '1.5.0', env: {} });
  t.after(() => control.close());
  await control.migrate();
  const store = createIdempotencyStore(control.db, { clock: () => 1, maxEntries: 2, staleMs: 100 });
  const scope = key => `rev\nPOST\n/p\n${key}`;
  assert.deepEqual(await store.begin(scope('a'), { digest: 'd1', leaseUntil: 50 }), {
    entry: null,
  });
  assert.deepEqual(await store.begin(scope('a'), { digest: 'd2', leaseUntil: 60 }), {
    entry: { digest: 'd1', response: null, expiresAt: null, leaseUntil: 50 },
  });
  // Not before the lease ends; then once.
  assert.equal(await store.takeOver(scope('a'), { digest: 'd2', leaseUntil: 90, now: 40 }), false);
  assert.equal(await store.takeOver(scope('a'), { digest: 'd2', leaseUntil: 90, now: 50 }), true);
  assert.equal((await store.begin(scope('a'), { digest: 'x', leaseUntil: 0 })).entry.digest, 'd2');
  await store.finish(scope('a'), {
    response: { status: 201, body: 'made', headers: { a: 'b' } },
    expiresAt: 1000,
  });
  assert.deepEqual((await store.begin(scope('a'), { digest: 'x', leaseUntil: 0 })).entry, {
    digest: 'd2',
    response: { status: 201, body: 'made', headers: { a: 'b' } },
    expiresAt: 1000,
    leaseUntil: null,
  });
  assert.equal(await store.takeOver(scope('a'), { digest: 'd3', leaseUntil: 9, now: 5000 }), false);
  await store.abandon(scope('a'));
  assert.ok(
    (await store.begin(scope('a'), { digest: 'x', leaseUntil: 0 })).entry.response,
    'finished entries stay'
  );
  // A running entry whose lease ended long ago is pruned; so are the oldest beyond the cap.
  await store.begin(scope('dead'), { digest: 'd', leaseUntil: 10 });
  for (const key of ['b', 'c', 'd']) {
    await store.begin(scope(key), { digest: 'd', leaseUntil: 10 });
    await store.finish(scope(key), { response: { status: 200, body: key }, expiresAt: 10_000 });
  }
  assert.equal(await store.prune(200), 3, 'the dead lease and the two oldest answers');
  const left = await control.db.read(tx =>
    tx.all(
      sql`SELECT ${id('key')} FROM ${id('idempotency_keys')} ${tx.dialect.orderBy(['key', 'asc', 'not null'])}`
    )
  );
  assert.deepEqual(
    left.map(row => row.key),
    ['c', 'd']
  );
});

test('migrateHistory: nothing without a file or steps; refuses unknown contract steps; applies additive steps', async t => {
  const { migrateHistory, historySteps, historyFile } = await import('../../lib/db/control.mjs');
  const directory = temporary(t);
  assert.deepEqual(historySteps, []);
  assert.deepEqual(await migrateHistory(directory, { release: '1.5.0' }), {
    exists: false,
    applied: [],
    pending: [],
    pendingData: [],
  });
  assert.deepEqual(fs.readdirSync(directory), []);
  // A 1.4.x history database, as lib/store.mjs creates it.
  const file = path.join(directory, historyFile);
  const legacy = openSqlite(file);
  await legacy.write(tx =>
    tx.ddl(
      'CREATE TABLE events (id INTEGER PRIMARY KEY, service TEXT, time INTEGER, kind TEXT, message TEXT, category TEXT, rule TEXT)'
    )
  );
  legacy.close();
  const before = fingerprint(directory);
  assert.deepEqual((await migrateHistory(directory, { release: '1.5.0' })).applied, []);
  assert.deepEqual(fingerprint(directory), before, 'no steps: nothing written');
  // An additive step on events (a nullable column, invariant 2), for every engine.
  const steps = [
    {
      id: 'alerting-001-events-uid',
      component: 'alerting',
      kind: 'expand',
      db: 'state',
      up: {
        sqlite: tx => tx.ddl('ALTER TABLE "events" ADD COLUMN "uid" TEXT'),
        postgres: tx => tx.ddl('ALTER TABLE "events" ADD COLUMN "uid" text'),
        mssql: tx => tx.ddl('ALTER TABLE [events] ADD [uid] varchar(200)'),
      },
    },
  ];
  const progress = [];
  const result = await migrateHistory(directory, {
    release: '1.5.0',
    steps,
    onProgress: item => progress.push(item),
  });
  assert.deepEqual(result.applied, ['alerting-001-events-uid']);
  assert.deepEqual(
    progress.map(item => [item.database, item.step]),
    [['history', 'alerting-001-events-uid']]
  );
  const db = openSqlite(file, { readOnly: true });
  const columns = await db.read(tx => tx.all(sql`SELECT name FROM pragma_table_info(${'events'})`));
  db.close();
  assert.ok(columns.some(column => column.name === 'uid'));
  // Data from a release with a history contract step this release does not know.
  const writer = openSqlite(file);
  await writer.write(tx =>
    tx.run(
      tx.dialect.insert(
        'schema_migrations',
        ['id', 'component', 'kind', 'release', 'applied_at'],
        [['scale-001-drop', 'scale', 'contract', '2.0.0', 1]]
      )
    )
  );
  writer.close();
  const frozen = fingerprint(directory);
  await assert.rejects(migrateHistory(directory, { release: '1.5.0', steps }), {
    code: 'data_newer',
    exitCode: 78,
  });
  assert.deepEqual(fingerprint(directory), frozen);
});

test('after a restore of the pinned snapshot and changes under 1.4.x, the next upgrade snapshots the new data', async t => {
  // The way back to 1.4.x is restoring the pinned pre-upgrade snapshot. Upgrading again later
  // must save what 1.4.x wrote meanwhile (a password change, settings), not reuse the old copy:
  // otherwise restoring "the pinned snapshot" after the second upgrade would bring back the
  // first upgrade's password and settings.
  const directory = temporary(t);
  const clock = manualClock();
  const file = name => path.join(directory, name);
  fs.writeFileSync(file('config.json'), '{"services":[]}\n');
  fs.writeFileSync(file('auth.json'), '{"version":1,"p":"first"}\n');
  const lock = locked(t, directory);
  const start = async () => {
    const started = await startControl(directory, {
      lock,
      credentialConfigured: true,
      release: '1.5.0',
      env: {},
      keyring: 'existing',
      keySources: noSources(directory),
      clock,
    });
    started.control.close();
    clock.advance(60e3);
    return started.snapshot;
  };
  const first = await start();
  assert.equal(first.reused, false);
  await restoreSnapshot(directory, first.id, { lock, release: '1.5.0', clock });
  assert.equal(fs.existsSync(file('control.sqlite')), false, 'back to 1.4.x data');
  // 1.4.x changes the password and a setting.
  fs.writeFileSync(file('auth.json'), '{"version":1,"p":"seventh"}\n');
  fs.writeFileSync(file('config.json'), '{"services":[],"pollSeconds":30}\n');
  const second = await start();
  assert.equal(second.reused, false, 'the data changed since the first snapshot');
  const upgrades = listSnapshots(directory).filter(item => item.reason === 'pre-upgrade');
  assert.deepEqual(
    upgrades.map(item => [item.id, item.pinned]),
    [
      [second.id, true],
      [first.id, true],
    ],
    'the newest pinned snapshot holds what 1.4.x last wrote'
  );
  for (const name of ['auth.json', 'config.json'])
    assert.equal(
      fs.readFileSync(path.join(directory, 'snapshots', second.id, name), 'utf8'),
      fs.readFileSync(file(name), 'utf8'),
      name
    );
  // Nothing changed since (control.sqlite deleted, as a crash part way through would leave the
  // files): the snapshot is reused, so a crash loop never fills the disk.
  fs.rmSync(file('control.sqlite'));
  const again = await start();
  assert.deepEqual(again, { id: second.id, reused: true });
  assert.equal(listSnapshots(directory).filter(item => item.reason === 'pre-upgrade').length, 2);
});

test('after a code-only rollback and changes under 1.4.x, upgrading again takes no snapshot', async t => {
  // The documented rollback swaps the code only: control.sqlite stays migrated, so the next
  // start has nothing to migrate and takes no snapshot. The pinned snapshot keeps the data of
  // the first upgrade, not what 1.4.x wrote in between, and the docs must say so: restoring it
  // to go back to 1.4.x brings back the first upgrade's password and settings.
  const directory = temporary(t);
  const clock = manualClock();
  const file = name => path.join(directory, name);
  fs.writeFileSync(file('config.json'), '{"services":[]}\n');
  fs.writeFileSync(file('auth.json'), '{"version":1,"p":"first"}\n');
  const lock = locked(t, directory);
  const start = async () => {
    const started = await startControl(directory, {
      lock,
      credentialConfigured: true,
      release: '1.5.0',
      env: {},
      keyring: 'existing',
      keySources: noSources(directory),
      clock,
    });
    started.control.close();
    clock.advance(60e3);
    return started.snapshot;
  };
  const first = await start();
  assert.equal(first.reused, false);
  // 1.4.x again (control.sqlite left as it is): a new password and a setting.
  fs.writeFileSync(file('auth.json'), '{"version":1,"p":"seventh"}\n');
  fs.writeFileSync(file('config.json'), '{"services":[],"pollSeconds":45}\n');
  assert.equal(await start(), null, 'nothing to migrate, so no snapshot');
  const pinned = listSnapshots(directory).filter(item => item.pinned);
  assert.deepEqual(
    pinned.map(item => item.id),
    [first.id]
  );
  assert.equal(
    fs.readFileSync(path.join(directory, 'snapshots', first.id, 'auth.json'), 'utf8'),
    '{"version":1,"p":"first"}\n',
    'the first upgrade’s password, not what 1.4.x last wrote'
  );
  // What the docs and the code say about it.
  const read = name => fs.readFileSync(new URL(`../../${name}`, import.meta.url), 'utf8');
  for (const name of ['docs/architecture.md', 'docs/authentication.md', 'lib/db/control.mjs'])
    assert.doesNotMatch(
      read(name),
      /holds what 1\.4\.x last wrote|newest pinned one is the way back/,
      name
    );
  assert.match(
    read('docs/architecture.md'),
    /changes made under 1\.4\.x before the next upgrade \(a password, settings\) are in no snapshot/
  );
  assert.match(
    read('docs/authentication.md'),
    /the changes made under 1\.4\.x in between \(a password, settings\) are in no snapshot/
  );
});

test('a start removes the temporary files of saves a crash stopped, and logs only their names', async t => {
  const directory = temporary(t);
  const uuid = '0b9b1c55-1111-4222-8333-944455556666';
  // What a save killed between its fsync and its rename leaves: the whole file, credentials in it.
  const leftovers = [
    `config.json.${uuid}.tmp`,
    `auth.json.${uuid}.tmp`,
    `created-by.json.${uuid}.tmp`,
  ];
  for (const name of leftovers)
    fs.writeFileSync(path.join(directory, name), '{"password":"SYNTH-TMP-CANARY-3333"}', {
      mode: 0o600,
    });
  // Names a save never uses, and a directory, stay.
  const kept = ['config.json.tmp', `history.sqlite.${uuid}.tmp`, `config.json.${uuid}.bak`];
  for (const name of kept) fs.writeFileSync(path.join(directory, name), 'x');
  fs.mkdirSync(path.join(directory, `auth.json.${uuid.replace('0b9b', '1b9b')}.tmp`));
  const started = await startControl(directory, {
    lock: locked(t, directory),
    credentialConfigured: true,
    keyring: 'existing',
    env: {},
    keySources: noSources(directory),
  });
  started.control.close();
  for (const name of leftovers)
    assert.equal(fs.existsSync(path.join(directory, name)), false, name);
  for (const name of kept) assert.equal(fs.existsSync(path.join(directory, name)), true, name);
  const line = started.warnings.find(warning => warning.startsWith('Removed '));
  const tail =
    ' from the data directory: temporary files of saves that a crash or a power loss stopped before they completed. Nothing used them; they could hold credentials.';
  assert.ok(line?.endsWith(tail), started.warnings.join('\n'));
  assert.deepEqual(
    line.slice('Removed '.length, -tail.length).split(', ').sort(),
    [...leftovers].sort(),
    'named, never their contents'
  );
});

test('meta session_seq and upgrade_history a writer damaged are read safely: NaN never passes for a count', async t => {
  const directory = temporary(t);
  const clock = manualClock();
  const control = openControl(directory, { release: '1.5.0', clock });
  t.after(() => control.close());
  await control.migrate();
  assert.equal(await control.meta.sessionSeq(), 0);
  assert.equal(await control.meta.bumpSessionSeq(), 1);
  for (const damaged of ['abc', '1.5', '-3', '', ' 2', '99999999999999999999']) {
    await control.meta.set('session_seq', damaged);
    assert.equal(await control.meta.sessionSeq(), null, JSON.stringify(damaged));
    // A bump writes a value no count reached: every reader sees a change.
    assert.equal(await control.meta.bumpSessionSeq(), clock(), JSON.stringify(damaged));
    assert.equal(await control.meta.sessionSeq(), clock());
  }
  const entry = (from, to, at) => ({ from, to, at });
  await control.meta.set(
    'upgrade_history',
    JSON.stringify([
      entry(null, '1.5.0-dev.1', 1),
      entry('1.5.0-dev.1', 'x\u001b[2J\n[orbit] FORGED', 2),
      entry('1.5.0-dev.1', '1.5.0', '3'),
      'not an entry',
      entry('1.5.0-dev.1', '1.5.0', 4),
      ...Array.from({ length: 60 }, (_, n) => entry('1.5.0', '1.5.0', 10 + n)),
    ])
  );
  const history = await control.meta.upgradeHistory();
  assert.equal(history.length, 50, 'at most the newest 50');
  assert.deepEqual(history.at(-1), entry('1.5.0', '1.5.0', 69));
  assert.ok(
    history.every(item => /^[0-9A-Za-z.+-]+$/.test(item.to) && Number.isSafeInteger(item.at))
  );
  for (const text of ['{', '{"a":1}', 'null']) {
    await control.meta.set('upgrade_history', text);
    assert.deepEqual(await control.meta.upgradeHistory(), [], text);
  }
  // A release recorded over a damaged list carries only what is readable, and an unreadable
  // last_version as unknown.
  await control.meta.set('upgrade_history', JSON.stringify(['x', entry(null, '1.5.0-dev.1', 1)]));
  await control.meta.set('last_version', 'y\u001b[31m');
  const later = openControl(directory, { release: '1.5.1', clock });
  t.after(() => later.close());
  await later.migrate();
  assert.deepEqual(await later.meta.upgradeHistory(), [
    entry(null, '1.5.0-dev.1', 1),
    entry(null, '1.5.1', clock()),
  ]);
});

test('a start removes the temporary files of restore journals a crash stopped before their rename', async t => {
  const directory = temporary(t);
  const root = path.join(directory, 'snapshots');
  fs.mkdirSync(root);
  const leftover = `${restoreJournal}.0b9b1c55-1111-4222-8333-944455556666.tmp`;
  fs.writeFileSync(path.join(root, leftover), '{"snapshot":"manual-1.5.0-20260901T000000000Z"}');
  // A name no journal write uses stays.
  fs.writeFileSync(path.join(root, `${restoreJournal}.tmp`), 'x');
  const started = await startControl(directory, {
    lock: locked(t, directory),
    credentialConfigured: true,
    keyring: 'existing',
    env: {},
    keySources: noSources(directory),
  });
  started.control.close();
  assert.deepEqual(fs.readdirSync(root).sort(), [`${restoreJournal}.tmp`]);
});

test('a snapshot folder whose name is not a snapshot id is never reused for a migration, nor named in a command', async t => {
  const directory = temporary(t);
  fs.writeFileSync(path.join(directory, 'config.json'), '{"services":[]}\n');
  // A copy of a pre-upgrade snapshot under another name (by hand, or crafted: the id is printed
  // in a restore command line), with a manifest that matches this upgrade. Reusing it ran
  // unchangedSince(), which refuses such an id, so every start failed (exit 1).
  const odd = 'pre-upgrade-1.5.0;x';
  fs.mkdirSync(path.join(directory, 'snapshots', odd), { recursive: true });
  fs.copyFileSync(
    path.join(directory, 'config.json'),
    path.join(directory, 'snapshots', odd, 'config.json')
  );
  fs.writeFileSync(
    path.join(directory, 'snapshots', odd, 'manifest.json'),
    JSON.stringify({
      format: 1,
      id: odd,
      reason: 'pre-upgrade',
      release: '1.5.0',
      fromRelease: null,
      createdAt: Date.UTC(2030, 0, 1),
      pinned: true,
      files: [],
      absent: [],
      excluded: [],
    })
  );
  const started = await startControl(directory, {
    lock: locked(t, directory),
    credentialConfigured: true,
    release: '1.5.0',
    keyring: 'existing',
    env: {},
    keySources: noSources(directory),
  });
  started.control.close();
  assert.equal(started.snapshot.reused, false);
  assert.notEqual(started.snapshot.id, odd);
  assert.match(started.snapshot.id, /^pre-upgrade-1\.5\.0-\d{8}T\d{9}Z$/);
});
