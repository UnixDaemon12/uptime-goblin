// The built-in admin at start (lib/identity/bootstrap.mjs, sessions spec §5.6, §5.7): first
// start, the three pre-checks (restore, damaged record, carried database), every row of the drift
// table, and the auth.json mirror with its retries.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import {
  readBuiltinSources,
  createIdentity,
  passwordRequiredMessage,
} from '../../lib/identity/index.mjs';
import { writeAuthRecord as realWrite } from '../../lib/identity/password.mjs';
import { controlFileIdentity } from '../../lib/identity/bootstrap.mjs';
import { metaOps, localModeGuardMessage } from '../../lib/db/control.mjs';
import { sql, id, json } from '../../lib/db/sql.mjs';
import { identityOps } from '../../lib/repo/identity.mjs';
import {
  temporary,
  manualClock,
  countingDerive,
  fakeRecord,
  writeAuthJson,
  startIdentity,
  adminRow,
  settings,
  meta,
  rows,
  instrumented,
  adminPassword,
  otherPassword,
  traceDurability,
  notingRecords,
  openTestControl,
} from './helpers.mjs';

const third = 'a third fixture password';
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const authFile = directory => path.join(directory, 'auth.json');
// builtin.controlFile as a start records it: which file control.sqlite is.
const fileOf = directory => controlFileIdentity(path.join(directory, 'control.sqlite'));
const failingWrite = () => {
  throw Object.assign(new Error('auth.json could not be written'), { code: 'EACCES' });
};
const signIn = (identity, password = adminPassword) =>
  identity.login({ login: 'admin', password, client: '127.0.0.1', userAgent: 'test' });
const refusesSignIn = (identity, password) =>
  assert.rejects(signIn(identity, password), error => error.code === 'invalid_credentials');
const change = (identity, access, from, to) =>
  identity.changePassword(access, { currentPassword: from, password: to, confirmPassword: to });
// What an earlier 1.5 build left after starting without a password (its local preview): the
// admin without one, builtin.source 'none', and no credentials_ever. Uptime Goblin no longer starts like
// that, so a start with a password sets the directory up and this takes the password away.
const passwordless = control =>
  control.db.write(tx => {
    tx.run(
      tx.dialect.update(
        'users',
        { password: null, password_changed_at: null },
        sql`${id('id')} = ${'u_admin'}`
      )
    );
    tx.run(
      tx.dialect.deleteFrom('identity_settings', sql`${id('key')} <> ${'builtin.controlFile'}`)
    );
    identityOps.setSetting(tx, 'builtin.source', 'none', Date.now());
    tx.run(tx.dialect.deleteFrom('meta', sql`${id('key')} = ${'credentials_ever'}`));
  });

// ---------------------------------------------------------------------------------------------
// readBuiltinSources

test('readBuiltinSources: auth.json wins; GOBLIN_PASSWORD is validated only without it', t => {
  const directory = temporary(t);
  assert.deepEqual(readBuiltinSources({ directory, password: '' }), {
    authJson: null,
    env: null,
    configured: false,
  });
  assert.deepEqual(readBuiltinSources({ directory, password: adminPassword }), {
    authJson: null,
    env: { password: adminPassword },
    configured: true,
  });
  assert.throws(
    () => readBuiltinSources({ directory, password: 'short' }),
    error => error.refusal === true && /^GOBLIN_PASSWORD must be/.test(error.message)
  );
  const record = fakeRecord(adminPassword);
  const bytes = writeAuthJson(directory, record);
  // 1.4.x ignores GOBLIN_PASSWORD while auth.json exists, so a short value is not checked.
  assert.deepEqual(readBuiltinSources({ directory, password: 'short' }), {
    authJson: { record, sha256: sha(bytes) },
    env: null,
    configured: true,
  });
  fs.writeFileSync(authFile(directory), '{}');
  assert.throws(
    () => readBuiltinSources({ directory, password: adminPassword }),
    error =>
      error.refusal === true && /^Saved authentication could not be loaded/.test(error.message)
  );
  // Reads only: a directory that does not exist is not created.
  const missing = path.join(temporary(t), 'data');
  assert.equal(readBuiltinSources({ directory: missing, password: '' }).configured, false);
  assert.equal(fs.existsSync(missing), false);
});

// ---------------------------------------------------------------------------------------------
// First start

test('first start with auth.json: its record, change time and fingerprint; files byte-identical', async t => {
  const directory = temporary(t);
  const record = fakeRecord(adminPassword, { passwordChangedAt: 1700000000000 });
  const bytes = writeAuthJson(directory, record);
  const config = Buffer.from('{"services":[]}\n');
  fs.writeFileSync(path.join(directory, 'config.json'), config, { mode: 0o600 });
  const derive = countingDerive();
  const { identity, control } = await startIdentity(t, directory, { password: 'ignored', derive });
  assert.equal(derive.calls, 0, 'nothing to derive: the file holds the record');
  assert.deepEqual(identity.status(), {
    source: 'auth.json',
    mirrorPending: false,
    importedAtStart: null,
    restoredAtStart: false,
  });
  assert.deepEqual(identity.metadata(), {
    username: 'admin',
    passwordChangeAvailable: true,
    passwordChangedAt: 1700000000000,
  });
  const row = await adminRow(control);
  assert.deepEqual(JSON.parse(row.password), record);
  assert.equal(row.password_changed_at, 1700000000000);
  assert.equal(row.login, 'admin');
  assert.equal(row.display_name, 'Administrator');
  assert.equal(row.role, 'admin');
  assert.equal(row.kind, 'person');
  assert.equal(row.epoch, 1);
  assert.equal(row.row_version, 1);
  assert.deepEqual(await settings(control), {
    'builtin.source': 'auth.json',
    'builtin.authJsonSha256': sha(bytes),
    'builtin.controlFile': fileOf(directory),
    'tokens.anchor': JSON.stringify({ controlFile: fileOf(directory), restoreSeen: null }),
  });
  assert.equal(await meta(control, 'credentials_ever'), '1');
  assert.deepEqual(fs.readFileSync(authFile(directory)), bytes);
  assert.deepEqual(fs.readFileSync(path.join(directory, 'config.json')), config);
  await signIn(identity);
  await refusesSignIn(identity, 'ignored');
});

test('first start with GOBLIN_PASSWORD only: one derivation, a verifier, no auth.json', async t => {
  const directory = temporary(t);
  const derive = countingDerive();
  const { identity, control, clock } = await startIdentity(t, directory, {
    password: adminPassword,
    derive,
  });
  assert.equal(derive.calls, 1);
  const row = await adminRow(control);
  const stored = JSON.parse(row.password);
  assert.equal(stored.passwordChangedAt, clock(), 'a valid v1 record');
  assert.equal(
    row.password_changed_at,
    null,
    '"not changed in Uptime Goblin yet", as 1.4.x reported'
  );
  assert.equal(identity.metadata().passwordChangedAt, null);
  const values = await settings(control);
  assert.equal(values['builtin.source'], 'env');
  assert.deepEqual(JSON.parse(values['builtin.envVerifier']), stored);
  assert.equal(values['builtin.authJsonSha256'], undefined);
  assert.equal(await meta(control, 'credentials_ever'), '1');
  assert.equal(fs.existsSync(authFile(directory)), false, 'env-only stays env-only (D13)');
  assert.equal(identity.status().source, 'env');
  await signIn(identity);
});

test('first start without a source is refused before identity writes anything: no passwordless admin', async t => {
  const directory = temporary(t);
  await assert.rejects(
    startIdentity(t, directory, { password: '' }),
    error => error.refusal === true && error.message === passwordRequiredMessage
  );
  // The test opened (and migrated) control.sqlite itself; identity added nothing to it.
  const control = await openTestControl(t, directory);
  assert.deepEqual(await rows(control, 'users'), []);
  assert.deepEqual(await settings(control), {});
  assert.equal(await meta(control, 'credentials_ever'), null);
  assert.equal(fs.existsSync(authFile(directory)), false);
  // The message says how to set a password, and that Uptime Goblin never makes one up.
  assert.match(passwordRequiredMessage, /^Uptime Goblin needs an admin password, and none is set/);
  // Also right for .env.example's GOBLIN_PASSWORD='' copied as it is: set, but empty.
  assert.match(
    passwordRequiredMessage,
    /the data directory has no auth\.json, and GOBLIN_PASSWORD is not set or is empty\./
  );
  assert.equal(readBuiltinSources({ directory, password: '' }).configured, false);
  assert.match(passwordRequiredMessage, /Set GOBLIN_PASSWORD \(12 to 1024 characters\)/);
  assert.match(
    passwordRequiredMessage,
    /\/etc\/uptime-goblin\.env for a native install, where the installer sets one/
  );
  assert.match(passwordRequiredMessage, /\.env for npm start and Docker Compose/);
});

// ---------------------------------------------------------------------------------------------
// Later starts: the drift table

test('auth.json changed outside Uptime Goblin is imported: epoch + 1, every session ends, its time kept', async t => {
  const directory = temporary(t);
  writeAuthJson(directory, fakeRecord(adminPassword));
  const first = await startIdentity(t, directory);
  const { issue } = await signIn(first.identity);
  first.stop();
  // A rollback to 1.4.x changed the password there.
  const record = fakeRecord(otherPassword, {
    salt: Buffer.alloc(32, 9),
    passwordChangedAt: 1750000000000,
  });
  const bytes = writeAuthJson(directory, record);
  const second = await startIdentity(t, directory);
  assert.equal(second.identity.status().importedAtStart, 'auth.json');
  assert.equal(await second.identity.authenticateSession(issue.value, {}), null);
  assert.deepEqual(await rows(second.control, 'sessions'), []);
  const row = await adminRow(second.control);
  assert.equal(row.epoch, 2);
  assert.equal(row.row_version, 2);
  assert.equal(row.password_changed_at, 1750000000000);
  assert.equal(second.identity.metadata().passwordChangedAt, 1750000000000);
  assert.equal((await settings(second.control))['builtin.authJsonSha256'], sha(bytes));
  await signIn(second.identity, otherPassword);
  await refusesSignIn(second.identity, adminPassword);
  assert.match(
    second.logged.text(),
    /Imported the admin password from auth\.json, which changed outside Uptime Goblin; every session was signed out\./
  );
  // Recorded in the unit of the import, by Uptime Goblin, with the change time it stored (§3.4).
  assert.deepEqual(
    second.events
      .filter(event => event.action.startsWith('account.'))
      .map(event => [event.action, event.outcome, event.actor.type, event.detail, event.meta]),
    [
      [
        'account.password.changed-outside',
        'info',
        'system',
        { source: 'auth.json' },
        { audit_password_changed_at: '1750000000000' },
      ],
    ]
  );
  assert.deepEqual(fs.readFileSync(authFile(directory)), bytes, 'an import never writes auth.json');
  // Handled once: the next start imports nothing.
  second.stop();
  const third_ = await startIdentity(t, directory);
  assert.equal(third_.identity.status().importedAtStart, null);
  assert.equal((await adminRow(third_.control)).epoch, 2);
});

test('an unchanged auth.json imports nothing and keeps sessions', async t => {
  const directory = temporary(t);
  const bytes = writeAuthJson(directory, fakeRecord(adminPassword));
  const first = await startIdentity(t, directory);
  const { issue } = await signIn(first.identity);
  first.stop();
  const second = await startIdentity(t, directory);
  assert.equal(second.identity.status().importedAtStart, null);
  assert.equal((await adminRow(second.control)).epoch, 1);
  assert.equal((await second.identity.authenticateSession(issue.value, {})).via, 'session');
  assert.deepEqual(fs.readFileSync(authFile(directory)), bytes);
  assert.equal(second.logged.text(), '');
});

test('an auth.json with a new fingerprint but our salt and hash is adopted, not imported', async t => {
  const directory = temporary(t);
  const record = fakeRecord(adminPassword);
  writeAuthJson(directory, record);
  const first = await startIdentity(t, directory);
  const { issue } = await signIn(first.identity);
  first.stop();
  // The same record, written differently (as a mirror whose rename landed before a crash would
  // leave it, or re-saved by hand).
  const bytes = writeAuthJson(directory, null, { text: JSON.stringify(record, null, 2) });
  const second = await startIdentity(t, directory);
  assert.equal(second.identity.status().importedAtStart, null);
  const values = await settings(second.control);
  assert.equal(values['builtin.authJsonSha256'], sha(bytes));
  assert.equal(values['builtin.source'], 'auth.json');
  assert.equal((await adminRow(second.control)).epoch, 1);
  assert.equal((await second.identity.authenticateSession(issue.value, {})).via, 'session');
});

test('auth.json moved aside with GOBLIN_PASSWORD set (1.4.2 recovery) imports the variable', async t => {
  const directory = temporary(t);
  writeAuthJson(directory, fakeRecord(adminPassword));
  const first = await startIdentity(t, directory);
  const { issue } = await signIn(first.identity);
  first.stop();
  fs.renameSync(authFile(directory), path.join(directory, 'auth.json.aside'));
  const second = await startIdentity(t, directory, { password: third });
  assert.equal(second.identity.status().importedAtStart, 'env');
  assert.equal(second.identity.status().source, 'env');
  const values = await settings(second.control);
  assert.equal(values['builtin.source'], 'env');
  assert.equal(values['builtin.authJsonSha256'], undefined);
  assert.ok(values['builtin.envVerifier']);
  assert.equal(await second.identity.authenticateSession(issue.value, {}), null);
  assert.equal((await adminRow(second.control)).epoch, 2);
  assert.equal((await adminRow(second.control)).password_changed_at, null);
  await signIn(second.identity, third);
  await refusesSignIn(second.identity, adminPassword);
  assert.equal(fs.existsSync(authFile(directory)), false, 'an env import is not mirrored (D13)');
  assert.match(second.logged.text(), /Imported the admin password from GOBLIN_PASSWORD/);
});

test('GOBLIN_PASSWORD: unchanged keeps an in-app change; changed by the operator is imported', async t => {
  const directory = temporary(t);
  const derive = countingDerive();
  const first = await startIdentity(t, directory, {
    password: adminPassword,
    derive,
    writeAuthRecord: failingWrite,
  });
  const signedIn = await signIn(first.identity);
  const result = await change(first.identity, signedIn.access, adminPassword, otherPassword);
  assert.equal(result.mirrorPending, true);
  first.stop();

  // Same GOBLIN_PASSWORD: one derivation to compare it with the verifier; no import.
  derive.calls = 0;
  const second = await startIdentity(t, directory, {
    password: adminPassword,
    derive,
    writeAuthRecord: failingWrite,
  });
  assert.equal(derive.calls, 1);
  assert.equal(second.identity.status().importedAtStart, null);
  assert.equal((await second.identity.authenticateSession(result.issue.value, {})).via, 'session');
  await signIn(second.identity, otherPassword);
  await refusesSignIn(second.identity, adminPassword);
  assert.equal(second.identity.status().mirrorPending, true, 'the failing mirror is still owed');
  second.stop();

  // The operator set a new GOBLIN_PASSWORD: it wins, and replaces the pending mirror.
  const third_ = await startIdentity(t, directory, { password: third, derive });
  assert.equal(third_.identity.status().importedAtStart, 'env');
  assert.equal(third_.identity.status().mirrorPending, false);
  assert.equal(await third_.identity.authenticateSession(result.issue.value, {}), null);
  await signIn(third_.identity, third);
  await refusesSignIn(third_.identity, otherPassword);
  assert.equal(fs.existsSync(authFile(directory)), false);
});

test('an admin an earlier build set up without a password takes the first credential (GOBLIN_PASSWORD or auth.json)', async t => {
  const directory = temporary(t);
  const earlier = await startIdentity(t, directory, { password: third });
  await passwordless(earlier.control);
  earlier.stop();
  const env = await startIdentity(t, directory, { password: adminPassword });
  assert.equal(env.identity.status().importedAtStart, 'env');
  assert.equal(await meta(env.control, 'credentials_ever'), '1');
  await signIn(env.identity);
  await refusesSignIn(env.identity, third);

  const other = temporary(t);
  const before = await startIdentity(t, other, { password: third });
  await passwordless(before.control);
  before.stop();
  writeAuthJson(other, fakeRecord(otherPassword));
  const file = await startIdentity(t, other);
  assert.equal(file.identity.status().importedAtStart, 'auth.json');
  await signIn(file.identity, otherPassword);
  assert.equal(await meta(file.control, 'credentials_ever'), '1');
});

test('without any source a start is refused: an admin without a password, and a stored password (the backstop of D4)', async t => {
  const directory = temporary(t);
  const earlier = await startIdentity(t, directory, { password: adminPassword });
  await passwordless(earlier.control);
  earlier.stop();
  await assert.rejects(
    startIdentity(t, directory, { password: '' }),
    error => error.refusal === true && error.message === passwordRequiredMessage
  );

  const guarded = temporary(t);
  (await startIdentity(t, guarded, { password: adminPassword })).stop();
  await assert.rejects(
    startIdentity(t, guarded, { password: '' }),
    // The backstop's own text (one definition, lib/db/control.mjs): a password was stored, so
    // it says to restore auth.json or set GOBLIN_PASSWORD. server.mjs and startControl refuse such
    // a start first, with passwordRequiredMessage.
    error => error.refusal === true && error.message === localModeGuardMessage
  );
});

// ---------------------------------------------------------------------------------------------
// The three pre-checks

test('a restore marker signs every session out once: epoch + 1, restoreSeen, one log line', async t => {
  const directory = temporary(t);
  writeAuthJson(directory, fakeRecord(adminPassword));
  const first = await startIdentity(t, directory);
  const a = await signIn(first.identity),
    b = await signIn(first.identity);
  first.stop();
  const clock = manualClock();
  const marker = JSON.stringify({ snapshot: '20260901T000000Z-pre-upgrade', at: clock() });
  // What restoreSnapshot stamps into the incoming control.sqlite.
  const second0 = await startIdentity(t, directory);
  await second0.control.db.write(tx => metaOps.set(tx, 'restored', marker, clock()));
  second0.stop();
  const second = await startIdentity(t, directory);
  assert.equal(second.identity.status().restoredAtStart, true);
  for (const old of [a, b])
    assert.equal(await second.identity.authenticateSession(old.issue.value, {}), null);
  assert.deepEqual(await rows(second.control, 'sessions'), []);
  const row = await adminRow(second.control);
  assert.equal(row.epoch, 2);
  assert.equal((await settings(second.control))['builtin.restoreSeen'], marker);
  assert.match(
    second.logged.text(),
    /Uptime Goblin's data was restored from snapshot 20260901T000000Z-pre-upgrade; every session was signed out\./
  );
  // The writer adds the snapshot's system.restore anchor in the same unit (audit spec D16);
  // identity records the sign-out with the snapshot named.
  assert.deepEqual(
    second.events.map(event => [event.action, event.detail]),
    [['session.revoked-restore', { cause: 'snapshot', snapshot: '20260901T000000Z-pre-upgrade' }]]
  );
  // The password is the restored one: nothing imported.
  assert.equal(second.identity.status().importedAtStart, null);
  const c = await signIn(second.identity);
  second.stop();
  const third_ = await startIdentity(t, directory);
  assert.equal(third_.identity.status().restoredAtStart, false, 'handled once');
  assert.equal((await adminRow(third_.control)).epoch, 2);
  assert.equal((await third_.identity.authenticateSession(c.issue.value, {})).via, 'session');
});

test('a restore marker and a changed auth.json in one start: both applied, one write', async t => {
  const directory = temporary(t);
  writeAuthJson(directory, fakeRecord(adminPassword));
  const first = await startIdentity(t, directory);
  await first.control.db.write(tx => metaOps.set(tx, 'restored', '{"snapshot":"s1","at":1}', 1));
  first.stop();
  writeAuthJson(directory, fakeRecord(otherPassword, { salt: Buffer.alloc(32, 3) }));
  const second = await startIdentity(t, directory);
  assert.deepEqual(
    [second.identity.status().restoredAtStart, second.identity.status().importedAtStart],
    [true, 'auth.json']
  );
  assert.equal((await adminRow(second.control)).epoch, 3);
  await signIn(second.identity, otherPassword);
});

// A backup of the data directory restored outside restore-snapshot (tar, cp, a volume copy):
// its control.sqlite holds every session of its time, those signed out since included, and its
// auth.json matches its own fingerprint, so only the file itself shows the restore.
const replaceControl = (directory, backup) => {
  for (const suffix of ['', '-wal', '-shm'])
    fs.rmSync(path.join(directory, 'control.sqlite' + suffix), { force: true });
  for (const name of fs.readdirSync(backup))
    if (name.startsWith('control.sqlite'))
      fs.copyFileSync(path.join(backup, name), path.join(directory, name));
};
const backUpControl = (directory, backup) => {
  fs.mkdirSync(backup, { recursive: true });
  for (const name of fs.readdirSync(directory))
    if (name.startsWith('control.sqlite'))
      fs.copyFileSync(path.join(directory, name), path.join(backup, name));
};
const replacedText =
  /^control\.sqlite is not the file Uptime Goblin last ran with: its data directory was restored from a backup, copied or moved\. Every session was signed out, so sessions that ended after the backup was made cannot come back; sign in again\.$/m;

test('a control.sqlite that is not the file of the last start signs every session out, once', async t => {
  const directory = temporary(t),
    backup = temporary(t);
  writeAuthJson(directory, fakeRecord(adminPassword));
  const first = await startIdentity(t, directory);
  const lost = await signIn(first.identity),
    kept = await signIn(first.identity);
  first.stop();
  backUpControl(directory, backup);
  // Signed out after the backup, on the device kept.
  const second = await startIdentity(t, directory);
  const mine = await second.identity.authenticateSession(kept.issue.value, {});
  assert.deepEqual(await second.identity.revokeSession(mine, lost.issue.id), {
    found: true,
    current: false,
  });
  assert.equal(second.identity.status().restoredAtStart, false, 'a restart is no restore');
  assert.doesNotMatch(second.logged.text(), replacedText);
  second.stop();

  replaceControl(directory, backup);
  const third = await startIdentity(t, directory);
  for (const old of [lost, kept])
    assert.equal(await third.identity.authenticateSession(old.issue.value, {}), null);
  assert.deepEqual(await rows(third.control, 'sessions'), []);
  assert.equal((await adminRow(third.control)).epoch, 2);
  assert.deepEqual(third.identity.status(), {
    source: 'auth.json',
    mirrorPending: false,
    importedAtStart: null,
    restoredAtStart: true,
  });
  assert.match(third.logged.text(), replacedText);
  // The whole-file restore's anchor and the sign-out, in the unit that signed everyone out.
  assert.deepEqual(
    third.events.map(event => [event.action, event.detail]),
    [
      ['system.restore', { cause: 'control_file' }],
      ['session.revoked-restore', { cause: 'control_file' }],
    ]
  );
  assert.equal(
    (await settings(third.control))['builtin.controlFile'],
    fileOf(directory),
    'the restored file is recorded'
  );
  const again = await signIn(third.identity);
  third.stop();
  // Recorded, so the next start keeps every session.
  const fourth = await startIdentity(t, directory);
  assert.equal(fourth.identity.status().restoredAtStart, false);
  assert.equal((await fourth.identity.authenticateSession(again.issue.value, {})).via, 'session');
  assert.equal((await adminRow(fourth.control)).epoch, 2);
  assert.doesNotMatch(fourth.logged.text(), replacedText);
});

test('control.sqlite: a reused inode number with another birth time is another file; no record is no restore', async t => {
  const directory = temporary(t);
  writeAuthJson(directory, fakeRecord(adminPassword));
  const first = await startIdentity(t, directory);
  const session = await signIn(first.identity);
  const now = JSON.parse(fileOf(directory));
  // A database from before the record (or a start that could not read the file): recorded
  // now, and nobody is signed out.
  await first.control.db.write(tx =>
    tx.run(tx.dialect.deleteFrom('identity_settings', sql`${id('key')} = ${'builtin.controlFile'}`))
  );
  first.stop();
  const second = await startIdentity(t, directory);
  assert.equal(second.identity.status().restoredAtStart, false);
  assert.ok(await second.identity.authenticateSession(session.issue.value, {}));
  assert.equal((await settings(second.control))['builtin.controlFile'], fileOf(directory));
  // A record without a birth time (a system that reports none): the same inode is the same file.
  await second.control.db.write(tx =>
    tx.run(
      tx.dialect.update(
        'identity_settings',
        { value: JSON.stringify({ ino: now.ino }) },
        sql`${id('key')} = ${'builtin.controlFile'}`
      )
    )
  );
  second.stop();
  const third = await startIdentity(t, directory);
  assert.equal(third.identity.status().restoredAtStart, false);
  assert.ok(await third.identity.authenticateSession(session.issue.value, {}));
  assert.equal((await settings(third.control))['builtin.controlFile'], fileOf(directory));
  if (now.birth === undefined) {
    t.diagnostic('this file system reports no birth time: the reused-inode case is not testable');
    return;
  }
  // The inode number of a deleted control.sqlite, reused by the restored one: the birth time
  // tells them apart.
  await third.control.db.write(tx =>
    tx.run(
      tx.dialect.update(
        'identity_settings',
        { value: JSON.stringify({ ino: now.ino, birth: String(BigInt(now.birth) - 1n) }) },
        sql`${id('key')} = ${'builtin.controlFile'}`
      )
    )
  );
  third.stop();
  const fourth = await startIdentity(t, directory);
  assert.equal(fourth.identity.status().restoredAtStart, true);
  assert.equal(await fourth.identity.authenticateSession(session.issue.value, {}), null);
  assert.match(fourth.logged.text(), replacedText);
});

test('a snapshot restore, which also replaces control.sqlite, signs out once with its own line', async t => {
  const directory = temporary(t),
    backup = temporary(t);
  writeAuthJson(directory, fakeRecord(adminPassword));
  const first = await startIdentity(t, directory);
  const session = await signIn(first.identity);
  // What restoreSnapshot does: the marker in the incoming copy, which is a new file.
  await first.control.db.write(tx =>
    metaOps.set(tx, 'restored', JSON.stringify({ snapshot: 's1', at: 1 }), 1)
  );
  first.stop();
  backUpControl(directory, backup);
  replaceControl(directory, backup);
  const second = await startIdentity(t, directory);
  assert.equal(await second.identity.authenticateSession(session.issue.value, {}), null);
  assert.equal((await adminRow(second.control)).epoch, 2, 'one sign-out');
  assert.match(second.logged.text(), /restored from snapshot s1; every session was signed out\./);
  assert.doesNotMatch(second.logged.text(), replacedText);
  assert.deepEqual(
    second.events.map(event => [event.action, event.detail]),
    [['session.revoked-restore', { cause: 'snapshot', snapshot: 's1' }]]
  );
});

test('controlFileIdentity: the inode, and a birth time only where the system reports one', t => {
  const file = path.join(temporary(t), 'control.sqlite');
  assert.equal(controlFileIdentity(file), null, 'unreadable: no conclusion');
  fs.writeFileSync(file, 'x');
  const stat = (fields, run) => {
    const mock = t.mock.method(fs, 'statSync', () => ({ ino: 41n, ctimeNs: 9n, ...fields }));
    try {
      return run();
    } finally {
      mock.mock.restore();
    }
  };
  assert.equal(
    stat({ birthtimeNs: 8n }, () => controlFileIdentity(file)),
    '{"ino":"41","birth":"8"}'
  );
  // None reported (0), or the change time in its place (Linux without statx): left out.
  assert.equal(
    stat({ birthtimeNs: 0n }, () => controlFileIdentity(file)),
    '{"ino":"41"}'
  );
  assert.equal(
    stat({ birthtimeNs: 9n }, () => controlFileIdentity(file)),
    '{"ino":"41"}'
  );
});

test('a start that cannot read which file control.sqlite is says so and signs nobody out', async t => {
  const directory = temporary(t);
  writeAuthJson(directory, fakeRecord(adminPassword));
  const first = await startIdentity(t, directory);
  const session = await signIn(first.identity);
  first.stop();
  const original = fs.statSync;
  t.mock.method(fs, 'statSync', (file, ...rest) => {
    if (String(file).endsWith('control.sqlite'))
      throw Object.assign(new Error('denied'), { code: 'EACCES' });
    return original(file, ...rest);
  });
  const second = await startIdentity(t, directory);
  t.mock.restoreAll();
  assert.ok(await second.identity.authenticateSession(session.issue.value, {}));
  assert.match(
    second.logged.text(),
    /^Uptime Goblin could not read which file control\.sqlite is, so it cannot tell whether the data directory was restored from a backup at this start; after restoring one, sign out the other devices under Configure → Account\.$/m
  );
  assert.equal((await settings(second.control))['builtin.controlFile'], fileOf(directory));
});

test('a damaged stored record is re-imported from auth.json or GOBLIN_PASSWORD, never left without a password', async t => {
  const damage = control =>
    control.db.write(tx =>
      tx.run(
        tx.dialect.update(
          'users',
          { password: json({ version: 2, note: 'not a record' }) },
          sql`${id('id')} = ${'u_admin'}`
        )
      )
    );
  // From auth.json, even though its fingerprint is the stored one.
  const withFile = temporary(t);
  writeAuthJson(withFile, fakeRecord(adminPassword));
  const a = await startIdentity(t, withFile);
  const session = await signIn(a.identity);
  await damage(a.control);
  a.stop();
  const a2 = await startIdentity(t, withFile);
  assert.equal(a2.identity.status().importedAtStart, 'auth.json');
  assert.equal(await a2.identity.authenticateSession(session.issue.value, {}), null);
  await signIn(a2.identity);

  // From GOBLIN_PASSWORD.
  const withEnv = temporary(t);
  const b = await startIdentity(t, withEnv, { password: adminPassword });
  await damage(b.control);
  b.stop();
  const b2 = await startIdentity(t, withEnv, { password: adminPassword });
  assert.equal(b2.identity.status().importedAtStart, 'env');
  await signIn(b2.identity);

  // With neither: refused (78), with the fix.
  const bare = temporary(t);
  const c = await startIdentity(t, bare, { password: adminPassword });
  await damage(c.control);
  c.stop();
  await assert.rejects(
    startIdentity(t, bare, { password: '' }),
    error =>
      error.refusal === true &&
      /^The saved admin password in control\.sqlite is damaged, and neither auth\.json nor GOBLIN_PASSWORD is present/.test(
        error.message
      )
  );
});

test('a database without builtin.source (carried from elsewhere) is authoritative and mirrored', async t => {
  const directory = temporary(t);
  writeAuthJson(directory, fakeRecord(adminPassword));
  const first = await startIdentity(t, directory);
  const signedIn = await signIn(first.identity);
  await change(first.identity, signedIn.access, adminPassword, otherPassword);
  const carried = (await rows(first.control, 'users'))[0];
  const kept = await signIn(first.identity, otherPassword);
  // Another data directory's identity_settings are not carried (node-local): only its users,
  // and (a transfer) not this meta either.
  await first.control.db.write(tx => {
    tx.run(tx.dialect.deleteFrom('identity_settings', sql`${id('key')} IS NOT NULL`));
    tx.run(tx.dialect.deleteFrom('meta', sql`${id('key')} = ${'credentials_ever'}`));
  });
  first.stop();
  // This directory's auth.json still holds a different (older) password.
  writeAuthJson(directory, fakeRecord(third, { salt: Buffer.alloc(32, 5) }));
  const second = await startIdentity(t, directory);
  assert.equal(second.identity.status().importedAtStart, null);
  assert.equal(second.identity.status().mirrorPending, false);
  assert.equal(second.identity.status().source, 'auth.json');
  const row = await adminRow(second.control);
  assert.equal(row.epoch, carried.epoch, 'no epoch change');
  assert.equal(row.password, carried.password);
  assert.equal((await second.identity.authenticateSession(kept.issue.value, {})).via, 'session');
  // auth.json now holds the database's password, byte for byte as 1.4.3 writes it.
  const bytes = fs.readFileSync(authFile(directory));
  assert.equal(bytes.toString(), JSON.stringify(JSON.parse(carried.password)) + '\n');
  assert.equal((await settings(second.control))['builtin.authJsonSha256'], sha(bytes));
  await signIn(second.identity, otherPassword);
  await refusesSignIn(second.identity, third);
  assert.match(second.logged.text(), /auth\.json now holds the current admin password again\./);
  assert.equal(await meta(second.control, 'credentials_ever'), '1', 'a credential has existed');

  // A carried row without a password (an earlier build's local preview): the configured source
  // is imported.
  const empty = temporary(t);
  const e = await startIdentity(t, empty, { password: third });
  await passwordless(e.control);
  await e.control.db.write(tx =>
    tx.run(tx.dialect.deleteFrom('identity_settings', sql`${id('key')} IS NOT NULL`))
  );
  e.stop();
  const e2 = await startIdentity(t, empty, { password: adminPassword });
  assert.equal(e2.identity.status().importedAtStart, 'env');
});

// ---------------------------------------------------------------------------------------------
// The mirror

test('an in-app change is mirrored to auth.json byte for byte, then recorded', async t => {
  const directory = temporary(t);
  writeAuthJson(directory, fakeRecord(adminPassword));
  const { identity, control, events } = await startIdentity(t, directory);
  const { access } = await signIn(identity);
  const result = await change(identity, access, adminPassword, otherPassword);
  assert.equal(result.mirrorPending, false);
  const stored = JSON.parse((await adminRow(control)).password);
  const bytes = fs.readFileSync(authFile(directory));
  assert.equal(bytes.toString(), JSON.stringify(stored) + '\n');
  assert.equal(fs.statSync(authFile(directory)).mode & 0o777, 0o600);
  const values = await settings(control);
  assert.equal(values['builtin.authJsonSha256'], sha(bytes));
  assert.equal(values['builtin.source'], 'auth.json');
  assert.equal(values['builtin.mirrorPending'], undefined);
  assert.equal(identity.describe(access).mirrorPending, false);
  // The first start set the account up; the change is recorded once.
  assert.deepEqual(
    events.map(event => event.action).filter(action => action.startsWith('account')),
    ['account.bootstrap', 'account.password.changed']
  );
});

test('a failed mirror keeps the change, is flagged, and is retried by prune and at the next start', async t => {
  const directory = temporary(t);
  const original = writeAuthJson(directory, fakeRecord(adminPassword));
  let broken = true;
  const writer = (...args) => (broken ? failingWrite() : realWrite(...args));
  const first = await startIdentity(t, directory, { writeAuthRecord: writer });
  const { access } = await signIn(first.identity);
  const result = await change(first.identity, access, adminPassword, otherPassword);
  assert.equal(result.mirrorPending, true);
  assert.equal(first.identity.status().mirrorPending, true);
  assert.equal(first.identity.describe(access).mirrorPending, true);
  assert.equal((await settings(first.control))['builtin.mirrorPending'], '1');
  assert.deepEqual(fs.readFileSync(authFile(directory)), original, 'auth.json untouched');
  assert.match(
    first.logged.text(),
    /Uptime Goblin could not update auth\.json \(EACCES\); a rollback to 1\.4\.x would still use the previous admin password\. Uptime Goblin retries hourly\./
  );
  assert.ok(first.events.some(event => event.action === 'identity.mirror.failed'));
  // The new password works meanwhile: the database is authoritative.
  await signIn(first.identity, otherPassword);
  assert.deepEqual(await first.identity.prune(), { sessions: 0, mirror: 'failed' });
  broken = false;
  assert.deepEqual(await first.identity.prune(), { sessions: 0, mirror: 'ok' });
  assert.equal(first.identity.status().mirrorPending, false);
  assert.equal(
    JSON.parse(fs.readFileSync(authFile(directory), 'utf8')).hash,
    JSON.parse((await adminRow(first.control)).password).hash
  );
  assert.deepEqual(await first.identity.prune(), { sessions: 0, mirror: 'none' });
  first.stop();

  // At start: a mirror owed from the last run is retried; the file did not change meanwhile,
  // so nothing is imported (M1).
  const directory2 = temporary(t);
  writeAuthJson(directory2, fakeRecord(adminPassword));
  const a = await startIdentity(t, directory2, { writeAuthRecord: failingWrite });
  const signed = await signIn(a.identity);
  const changed = await change(a.identity, signed.access, adminPassword, otherPassword);
  a.stop();
  const b = await startIdentity(t, directory2);
  assert.equal(b.identity.status().importedAtStart, null);
  assert.equal(b.identity.status().mirrorPending, false);
  assert.equal((await b.identity.authenticateSession(changed.issue.value, {})).via, 'session');
  await signIn(b.identity, otherPassword);
  await refusesSignIn(b.identity, adminPassword);
  assert.match(b.logged.text(), /auth\.json now holds the current admin password again\./);
  assert.equal(
    JSON.parse(fs.readFileSync(authFile(directory2), 'utf8')).hash,
    JSON.parse((await adminRow(b.control)).password).hash
  );
});

test('a pending mirror loses to a password changed under 1.4.x meanwhile (M2): imported, flag cleared', async t => {
  const directory = temporary(t);
  writeAuthJson(directory, fakeRecord(adminPassword));
  const a = await startIdentity(t, directory, { writeAuthRecord: failingWrite });
  const signed = await signIn(a.identity);
  const changed = await change(a.identity, signed.access, adminPassword, otherPassword);
  assert.equal(changed.mirrorPending, true);
  a.stop();
  // 1.4.3 ran with auth.json (still the old password) and the owner changed it there.
  writeAuthJson(directory, fakeRecord(third, { salt: Buffer.alloc(32, 4) }));
  const b = await startIdentity(t, directory);
  assert.equal(b.identity.status().importedAtStart, 'auth.json');
  assert.equal(b.identity.status().mirrorPending, false);
  assert.equal((await settings(b.control))['builtin.mirrorPending'], undefined);
  assert.equal(await b.identity.authenticateSession(changed.issue.value, {}), null);
  await signIn(b.identity, third);
  await refusesSignIn(b.identity, otherPassword);
});

test('a mirror never records a password that changed while it was being written', async t => {
  const directory = temporary(t);
  writeAuthJson(directory, fakeRecord(adminPassword));
  let broken = true;
  const first = await startIdentity(t, directory, {
    writeAuthRecord: (...args) => (broken ? failingWrite() : realWrite(...args)),
  });
  const { access } = await signIn(first.identity);
  await change(first.identity, access, adminPassword, otherPassword);
  // Another process bumps the row between the file write and the record (simulated by moving
  // row_version on): the flag must stay, because what was written may be stale.
  broken = false;
  await first.control.db.write(tx =>
    tx.run(
      tx.dialect.update(
        'users',
        { row_version: sql`${id('row_version')} + 1` },
        sql`${id('id')} = ${'u_admin'}`
      )
    )
  );
  const result = await first.identity.prune();
  assert.equal(result.mirror, 'ok');
  assert.equal((await settings(first.control))['builtin.mirrorPending'], '1');
  assert.equal(first.identity.status().mirrorPending, true);
});

test('a retried mirror whose record cannot be written (a full disk) leaves auth.json current, at prune and at start', async t => {
  // Before, the failure of that write rejected: the hourly retry logged "Identity housekeeping
  // failed", and a start failed. auth.json holds the stored password then, so nothing is owed
  // until the next start, which adopts the file (r5).
  const directory = temporary(t);
  writeAuthJson(directory, fakeRecord(adminPassword));
  let broken = true,
    full = false,
    db;
  // The Db identity uses (instrumented), known before createIdentity runs its start mirror.
  const wrap = control => {
    const wrapped = instrumented(control);
    db = wrapped.db;
    return wrapped;
  };
  const writer = (...args) => {
    if (broken) failingWrite();
    const written = realWrite(...args);
    if (full) db.failWrites(1);
    return written;
  };
  const unrecordedLine =
    /^auth\.json now holds the current admin password, but Uptime Goblin could not record that in control\.sqlite \(full\); the next start of Uptime Goblin records it\.$/m;
  const holdsStored = async control =>
    assert.equal(
      fs.readFileSync(authFile(directory), 'utf8'),
      JSON.stringify(JSON.parse((await adminRow(control)).password)) + '\n'
    );

  // The hourly retry.
  const first = await startIdentity(t, directory, { writeAuthRecord: writer, wrap });
  const signed = await signIn(first.identity);
  const changed = await change(first.identity, signed.access, adminPassword, otherPassword);
  assert.equal(changed.mirrorPending, true);
  broken = false;
  full = true;
  assert.deepEqual(await first.identity.prune(), { sessions: 0, mirror: 'ok' });
  full = false;
  assert.match(first.logged.text(), unrecordedLine);
  assert.doesNotMatch(first.logged.text(), /Identity housekeeping failed|again\./);
  assert.equal(first.identity.status().mirrorPending, false);
  assert.equal((await settings(first.control))['builtin.mirrorPending'], '1');
  await holdsStored(first.control);
  assert.deepEqual(await first.identity.prune(), { sessions: 0, mirror: 'none' });
  first.stop();

  // At start: a mirror still owed (auth.json unchanged since) is retried; its record fails.
  const directory2 = temporary(t);
  writeAuthJson(directory2, fakeRecord(adminPassword));
  const a = await startIdentity(t, directory2, { writeAuthRecord: failingWrite });
  const owed = await change(a.identity, (await signIn(a.identity)).access, adminPassword, third);
  a.stop();
  full = true;
  const b = await startIdentity(t, directory2, { writeAuthRecord: writer, wrap });
  full = false;
  assert.match(b.logged.text(), unrecordedLine);
  assert.equal(b.identity.status().mirrorPending, false);
  assert.equal(b.identity.status().source, 'auth.json');
  assert.equal((await settings(b.control))['builtin.mirrorPending'], '1');
  assert.equal((await b.identity.authenticateSession(owed.issue.value, {})).via, 'session');
  assert.equal(
    fs.readFileSync(authFile(directory2), 'utf8'),
    JSON.stringify(JSON.parse((await adminRow(b.control)).password)) + '\n'
  );
  b.stop();
  const c = await startIdentity(t, directory2);
  assert.equal(c.identity.status().importedAtStart, null);
  assert.equal((await settings(c.control))['builtin.mirrorPending'], undefined, 'adopted');
  assert.equal((await c.identity.authenticateSession(owed.issue.value, {})).via, 'session');
  await signIn(c.identity, third);
});

test('a start adopts a mirrored auth.json only once the data directory is flushed; unflushed, it mirrors again', async t => {
  // An adoption records the fingerprint of a file a mirror renamed into place, perhaps one whose
  // directory that mirror could not flush. Recorded before the rename is on disk, a power loss
  // would leave the previous auth.json under it, imported at the next start (r6).
  const directory = temporary(t);
  writeAuthJson(directory, fakeRecord(adminPassword));
  const a = await startIdentity(t, directory, { writeAuthRecord: failingWrite });
  const changed = await change(a.identity, (await signIn(a.identity)).access, adminPassword, third);
  assert.equal(changed.mirrorPending, true);
  const previous = sha(fs.readFileSync(authFile(directory)));
  const stored = JSON.parse((await adminRow(a.control)).password);
  a.stop();
  // A mirror renamed the stored password into place; its record did not follow.
  realWrite(directory, stored);
  const mirrored = sha(fs.readFileSync(authFile(directory)));

  // The directory cannot be flushed: nothing is adopted; the mirror still owed is written again,
  // and is not recorded either.
  const failing = traceDurability(t, directory, { failFlush: true });
  const b = await startIdentity(t, directory, { wrap: notingRecords(failing.events) });
  failing.stop();
  assert.ok(!failing.events.includes('record'), failing.events.join('\n'));
  failing.at('rename auth.json.<uuid>.tmp -> auth.json');
  assert.equal(b.identity.status().importedAtStart, null);
  assert.equal(b.identity.status().mirrorPending, false);
  assert.match(
    b.logged.text(),
    /^auth\.json now holds the current admin password, but Uptime Goblin could not record that in control\.sqlite \(EIO\); the next start of Uptime Goblin records it\.$/m
  );
  let values = await settings(b.control);
  assert.equal(values['builtin.mirrorPending'], '1');
  assert.equal(values['builtin.authJsonSha256'], previous);
  assert.equal((await b.identity.authenticateSession(changed.issue.value, {})).via, 'session');
  b.stop();

  // Flushed: adopted (not written again), the flush before the record.
  const traced = traceDurability(t, directory);
  const c = await startIdentity(t, directory, { wrap: notingRecords(traced.events) });
  traced.stop();
  assert.ok(traced.at('fsync .') < traced.at('record'), traced.events.join('\n'));
  assert.ok(!traced.events.some(event => event.startsWith('rename')), 'adopted, not mirrored');
  assert.equal(c.identity.status().importedAtStart, null);
  values = await settings(c.control);
  assert.equal(values['builtin.mirrorPending'], undefined);
  assert.equal(values['builtin.authJsonSha256'], mirrored);
  assert.equal((await c.identity.authenticateSession(changed.issue.value, {})).via, 'session');
  await signIn(c.identity, third);
});

test('required: createIdentity refuses a control database that is not SQLite, then needs the audit recorder', async t => {
  const directory = temporary(t);
  const db = { name: 'postgres', read: async () => null, write: async () => null };
  await assert.rejects(
    createIdentity({ control: { db }, directory, sources: readBuiltinSources({ directory }) }),
    error => error.refusal === true && /SQLite control database/.test(error.message)
  );
  await assert.rejects(createIdentity({ directory, sources: {} }), TypeError);
  // Audit spec D23: the recorder is checked after the database (the refusal above came first
  // without one), so identity never starts on a SQLite control database without it.
  const control = await openTestControl(t, directory);
  await assert.rejects(
    createIdentity({ control, directory, sources: readBuiltinSources({ directory }) }),
    error =>
      error instanceof TypeError &&
      error.message === 'createIdentity needs the audit recorder (createAudit() or noopAudit())'
  );
  assert.equal((await rows(control, 'users')).length, 0, 'nothing was bootstrapped');
});

test('tightening auth.json at start warns on a read-only disk but starts', async t => {
  const directory = temporary(t);
  writeAuthJson(directory, fakeRecord(adminPassword));
  fs.chmodSync(authFile(directory), 0o644);
  t.mock.method(fs, 'fchmodSync', () => {
    throw Object.assign(new Error('read-only file system'), { code: 'EROFS' });
  });
  const { identity, logged } = await startIdentity(t, directory);
  await signIn(identity);
  assert.match(logged.text(), /auth\.json permissions could not be tightened: EROFS/);
  t.mock.restoreAll();
  const again = await startIdentity(t, temporary(t), { password: adminPassword });
  assert.equal(again.logged.text(), '');
});
