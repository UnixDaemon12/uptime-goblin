// Password changes (identity.changePassword, sessions spec §5.12): the current password, the
// rotation of this session and the revocation of the others, the compare-and-swap, the Basic
// generation, one change at a time, the mirror and the audit events.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { sql, id } from '../../lib/db/sql.mjs';
import { writeAuthRecord as realWrite } from '../../lib/identity/password.mjs';
import { fakeAudit } from '../helpers/fake-audit.mjs';
import {
  temporary,
  startIdentity,
  instrumented,
  countingDerive,
  fakeRecord,
  writeAuthJson,
  basicBytes,
  rows,
  adminRow,
  settings,
  adminPassword,
  otherPassword,
  traceDurability,
  notingRecords,
} from './helpers.mjs';

const another = 'another fixture password here';
const withCode = code => error => error.code === code;
const input = (from, to, confirm = to) => ({
  currentPassword: from,
  password: to,
  confirmPassword: confirm,
});

async function started(t, options = {}) {
  const directory = temporary(t);
  const original = writeAuthJson(directory, fakeRecord(adminPassword));
  const derive = options.derive ?? countingDerive();
  const context = await startIdentity(t, directory, { derive, wrap: instrumented, ...options });
  const signIn = (extra = {}) =>
    context.identity.login({
      login: 'admin',
      password: adminPassword,
      client: '192.0.2.9',
      userAgent: 'change test',
      ...extra,
    });
  return { ...context, derive, original, signIn };
}

test('the current password is required; a refused change changes nothing', async t => {
  const { identity, control, directory, original, signIn } = await started(t);
  const { access } = await signIn();
  const before = await adminRow(control);
  for (const [value, code] of [
    [{ password: otherPassword, confirmPassword: otherPassword }, 'invalid_request'],
    [input('not the current one', otherPassword), 'current_password_incorrect'],
    [input('x'.repeat(1025), otherPassword), 'current_password_incorrect'],
    [input(adminPassword, 'short'), 'password_invalid'],
    [input(adminPassword, otherPassword, another), 'password_mismatch'],
  ]) {
    await assert.rejects(identity.changePassword(access, value), error => {
      assert.equal(error.code, code);
      assert.equal(error.status, code === 'current_password_incorrect' ? 403 : 400);
      return true;
    });
    identity.assertCurrent(access);
  }
  assert.deepEqual(await adminRow(control), before);
  assert.deepEqual(fs.readFileSync(path.join(directory, 'auth.json')), original);
  await signIn();
  await assert.rejects(signIn({ password: otherPassword }), withCode('invalid_credentials'));
});

test('a change rotates this session (same persistence), deletes the others, moves row_version not epoch', async t => {
  const { identity, control, clock, signIn } = await started(t);
  const mine = await signIn({ remember: true }),
    a = await signIn(),
    b = await signIn();
  const before = await adminRow(control);
  clock.advance(5000);
  const result = await identity.changePassword(mine.access, input(adminPassword, otherPassword), {
    client: '192.0.2.99',
    userAgent: 'the new agent',
  });
  assert.equal(result.revokedOtherSessions, 2);
  assert.equal(result.mirrorPending, false);
  const { issue } = result;
  assert.notEqual(issue.id, mine.issue.id);
  assert.notEqual(issue.value, mine.issue.value);
  assert.equal(issue.persistent, true);
  assert.equal(issue.expiresAt, clock() + 30 * 24 * 3600e3, 'new lifetimes');
  assert.equal(issue.maxAgeSeconds, 30 * 24 * 3600);
  for (const old of [mine, a, b]) {
    assert.throws(() => identity.assertCurrent(old.access), withCode('session_expired'));
    assert.equal(await identity.authenticateSession(old.issue.value, {}), null);
  }
  const sessions = await rows(control, 'sessions');
  assert.deepEqual(
    sessions.map(row => [row.id, row.persistent, row.client_key, row.user_agent]),
    [[issue.id, 1, '192.0.2.99', 'the new agent']]
  );
  const rotated = await identity.authenticateSession(issue.value, {});
  assert.equal(rotated.sessionId, issue.id);
  assert.equal(rotated.epoch, mine.access.epoch);
  assert.equal(rotated.scope, mine.access.scope, 'the idempotency scope survives the rotation');
  const after = await adminRow(control);
  assert.equal(after.row_version, before.row_version + 1);
  assert.equal(after.epoch, before.epoch, 'the epoch is for imports and restores');
  assert.equal(after.password_changed_at, clock());
  assert.equal(identity.metadata().passwordChangedAt, clock());
  assert.notEqual(after.password, before.password);
});

test('a Basic access changes the password without an issue and signs every session out', async t => {
  const { identity, signIn } = await started(t);
  const a = await signIn(),
    b = await signIn();
  const basic = await identity.authenticateBasic(basicBytes(adminPassword));
  const result = await identity.changePassword(basic, input(adminPassword, otherPassword));
  assert.equal(result.issue, null);
  assert.equal(result.revokedOtherSessions, 2);
  for (const old of [a, b]) assert.throws(() => identity.assertCurrent(old.access));
  assert.throws(() => identity.assertCurrent(basic), withCode('signin_required'));
});

test('a row changed underneath (compare-and-swap) refuses with change_in_progress and changes nothing', async t => {
  const { identity, control, directory, original, signIn } = await started(t);
  const mine = await signIn(),
    other = await signIn();
  await control.db.write(tx =>
    tx.run(
      tx.dialect.update(
        'users',
        { row_version: sql`${id('row_version')} + 1` },
        sql`${id('id')} = ${'u_admin'}`
      )
    )
  );
  const before = await adminRow(control);
  await assert.rejects(
    identity.changePassword(mine.access, input(adminPassword, otherPassword)),
    error => error.code === 'change_in_progress' && error.status === 429 && error.retryAfter === 5
  );
  assert.deepEqual(await adminRow(control), before);
  assert.equal((await rows(control, 'sessions')).length, 2);
  identity.assertCurrent(mine.access);
  identity.assertCurrent(other.access);
  assert.equal((await settings(control))['builtin.mirrorPending'], undefined);
  assert.deepEqual(fs.readFileSync(path.join(directory, 'auth.json')), original);
  await signIn();
  await assert.rejects(signIn({ password: otherPassword }), withCode('invalid_credentials'));
});

test('one change at a time: a second change while one runs is refused', async t => {
  const derive = countingDerive();
  const { identity, signIn } = await started(t, { derive });
  const { access } = await signIn();
  derive.hold();
  const first = identity.changePassword(access, input(adminPassword, otherPassword));
  await assert.rejects(
    identity.changePassword(access, input(otherPassword, another)),
    withCode('change_in_progress')
  );
  derive.release();
  const result = await first;
  // Released afterwards, also after a failure.
  await assert.rejects(
    identity.changePassword(
      await identity.authenticateSession(result.issue.value, {}),
      input('wrong current one', another)
    ),
    withCode('current_password_incorrect')
  );
  const rotated = await identity.authenticateSession(result.issue.value, {});
  await identity.changePassword(rotated, input(otherPassword, another));
  await signIn({ password: another });
});

test('a session revoked while the change verifies is refused before anything is written', async t => {
  const derive = countingDerive();
  const { identity, control, signIn } = await started(t, { derive });
  const mine = await signIn();
  const before = await adminRow(control);
  derive.hold();
  const changing = identity.changePassword(mine.access, input(adminPassword, otherPassword));
  await new Promise(resolve => setImmediate(resolve));
  await identity.logout(mine.access);
  derive.release();
  await assert.rejects(changing, withCode('session_expired'));
  assert.deepEqual(await adminRow(control), before);
  await signIn();
});

test('a change whose write fails on a full disk answers storage_full and keeps everything as it was', async t => {
  const { identity, control, db, signIn } = await started(t);
  const mine = await signIn(),
    other = await signIn();
  const before = await adminRow(control);
  db.failWrites(1);
  await assert.rejects(
    identity.changePassword(mine.access, input(adminPassword, otherPassword)),
    error => error.code === 'storage_full' && error.status === 503
  );
  assert.deepEqual(await adminRow(control), before);
  identity.assertCurrent(mine.access);
  identity.assertCurrent(other.access);
  // The in-memory record went back too: the old password still works, the new one does not.
  await signIn();
  await assert.rejects(signIn({ password: otherPassword }), withCode('invalid_credentials'));
  assert.equal(identity.metadata().passwordChangedAt, 123456);
  // And a change after it goes through.
  const result = await identity.changePassword(mine.access, input(adminPassword, otherPassword));
  assert.equal(result.revokedOtherSessions, 2, 'other and the sign-in above');
});

test('a full disk after the mirror wrote auth.json: the change resolves with its cookie, and the next start adopts the file', async t => {
  // The change committed and auth.json was written; then the write recording that failed (the
  // disk filled meanwhile). Before, that rejection reached the route after the commit: 500
  // without the rotated cookie, so the browser was signed out, told the change had failed, and
  // its old password was refused (r5).
  let context,
    full = false;
  const writeAuthRecord = (...args) => {
    const written = realWrite(...args);
    if (full) context.db.failWrites(1);
    return written;
  };
  context = await started(t, { writeAuthRecord });
  const { identity, control, directory, events, logged, signIn } = context;
  const mine = await signIn(),
    other = await signIn();
  events.length = 0;
  full = true;
  const result = await identity.changePassword(mine.access, input(adminPassword, otherPassword));
  full = false;
  assert.deepEqual(
    events.map(event => event.action),
    ['account.password.changed'],
    'auth.json is current: no identity.mirror.failed'
  );
  assert.equal(result.revokedOtherSessions, 1);
  // A rollback would use the new password: no banner, and nothing to retry hourly.
  assert.equal(result.mirrorPending, false);
  const rotated = await identity.authenticateSession(result.issue.value, {});
  assert.equal(rotated.sessionId, result.issue.id);
  assert.equal(identity.describe(rotated).mirrorPending, false);
  for (const old of [mine, other])
    assert.throws(() => identity.assertCurrent(old.access), withCode('session_expired'));
  await signIn({ password: otherPassword });
  await assert.rejects(signIn(), withCode('invalid_credentials'));
  const stored = JSON.parse((await adminRow(control)).password);
  const file = path.join(directory, 'auth.json');
  assert.equal(fs.readFileSync(file, 'utf8'), JSON.stringify(stored) + '\n');
  assert.equal((await settings(control))['builtin.mirrorPending'], '1', 'not recorded yet');
  assert.match(
    logged.text(),
    /^auth\.json now holds the current admin password, but Uptime Goblin could not record that in control\.sqlite \(full\); the next start of Uptime Goblin records it\.$/m
  );
  assert.doesNotMatch(logged.text(), /could not update auth\.json/);
  assert.deepEqual(await identity.prune(), { sessions: 0, mirror: 'none' });
  context.stop();

  // The next start adopts the file: recorded, flag cleared, nobody signed out, nothing imported.
  const next = await startIdentity(t, directory, { derive: context.derive });
  assert.equal(next.identity.status().importedAtStart, null);
  assert.equal(next.identity.status().mirrorPending, false);
  const values = await settings(next.control);
  assert.equal(values['builtin.mirrorPending'], undefined);
  assert.equal(
    values['builtin.authJsonSha256'],
    createHash('sha256').update(fs.readFileSync(file)).digest('hex')
  );
  assert.equal((await next.identity.authenticateSession(result.issue.value, {})).via, 'session');
});

test('a change records auth.json’s new fingerprint only once the data directory is flushed', async t => {
  // The mirror recorded the fingerprint (and cleared builtin.mirrorPending) in control.sqlite,
  // fsynced, right after the rename, with no flush of the directory: on btrfs a power loss in
  // the next 30 s could keep that record and lose the rename. The next start then found the
  // previous auth.json under a fingerprint naming the new one, imported the previous password as
  // a change made outside Uptime Goblin and signed everyone out (r6).
  const events = [];
  const { identity, control, directory, signIn } = await started(t, {
    wrap: notingRecords(events),
  });
  const { access } = await signIn();
  events.length = 0;
  const traced = traceDurability(t, directory, { events });
  await identity.changePassword(access, input(adminPassword, otherPassword));
  traced.stop();
  const renamed = traced.at('rename auth.json.<uuid>.tmp -> auth.json');
  assert.ok(traced.at('fsync auth.json.<uuid>.tmp') < renamed);
  const flushed = traced.at('fsync .', renamed);
  assert.ok(flushed < traced.at('record', flushed), events.join('\n'));
  assert.deepEqual(
    events.filter(event => event === 'record'),
    ['record'],
    'nothing recorded before the flush'
  );
  const values = await settings(control);
  assert.equal(values['builtin.mirrorPending'], undefined);
  assert.equal(
    values['builtin.authJsonSha256'],
    createHash('sha256')
      .update(fs.readFileSync(path.join(directory, 'auth.json')))
      .digest('hex')
  );
});

test('a mirror that cannot flush the data directory records nothing: after a lost rename the next start mirrors again, imports nothing', async t => {
  const context = await started(t);
  const { identity, control, directory, logged, signIn } = context;
  const mine = await signIn();
  const file = path.join(directory, 'auth.json');
  const previous = fs.readFileSync(file);
  const failing = traceDurability(t, directory, { failFlush: true });
  const result = await identity.changePassword(mine.access, input(adminPassword, otherPassword));
  failing.stop();
  // auth.json holds the stored password (a rollback uses it), but its rename may not be on
  // disk: the previous fingerprint and the flag stay, as for a record that could not be written.
  assert.ok(failing.events.includes('fsync .'));
  assert.equal(result.mirrorPending, false);
  const stored = JSON.parse((await adminRow(control)).password);
  assert.equal(fs.readFileSync(file, 'utf8'), JSON.stringify(stored) + '\n');
  const values = await settings(control);
  assert.equal(values['builtin.mirrorPending'], '1');
  assert.equal(
    values['builtin.authJsonSha256'],
    createHash('sha256').update(previous).digest('hex')
  );
  assert.match(
    logged.text(),
    /^auth\.json now holds the current admin password, but Uptime Goblin could not record that in control\.sqlite \(EIO\); the next start of Uptime Goblin records it\.$/m
  );
  context.stop();

  // A power loss took the rename back: the previous auth.json, under its own fingerprint. The
  // next start mirrors the stored password again; nothing is imported, nobody is signed out.
  fs.writeFileSync(file, previous, { mode: 0o600 });
  const next = await startIdentity(t, directory, { derive: context.derive });
  assert.equal(next.identity.status().importedAtStart, null);
  assert.equal(next.identity.status().mirrorPending, false);
  assert.match(next.logged.text(), /auth\.json now holds the current admin password again\./);
  assert.doesNotMatch(next.logged.text(), /Imported the admin password/);
  assert.equal((await next.identity.authenticateSession(result.issue.value, {})).via, 'session');
  assert.equal(fs.readFileSync(file, 'utf8'), JSON.stringify(stored) + '\n');
  assert.equal((await settings(next.control))['builtin.mirrorPending'], undefined);
  await next.identity.login({
    login: 'admin',
    password: otherPassword,
    client: '192.0.2.9',
    userAgent: 'change test',
  });
  await assert.rejects(
    next.identity.login({
      login: 'admin',
      password: adminPassword,
      client: '192.0.2.9',
      userAgent: 'change test',
    }),
    withCode('invalid_credentials')
  );
});

test('a password change needs an access that signed in', async t => {
  const { identity, signIn } = await started(t);
  for (const access of [null, undefined, {}, { via: 'local', authenticated: true }])
    await assert.rejects(
      identity.changePassword(access, input(adminPassword, otherPassword)),
      withCode('signin_required'),
      JSON.stringify(access)
    );
  // Nothing changed: the password still signs in.
  assert.equal((await signIn()).access.via, 'session');
});

test('the audit rows: account.password.changed in the change, identity.mirror.failed after it', async t => {
  const failing = () => {
    throw Object.assign(new Error('nope'), { code: 'EROFS' });
  };
  const { identity, events, signIn } = await started(t, { writeAuthRecord: failing });
  const { access, issue } = await signIn();
  const from = events.length;
  const result = await identity.changePassword(access, input(adminPassword, otherPassword), {
    client: '192.0.2.9',
  });
  assert.equal(result.mirrorPending, true);
  const rows = events.slice(from);
  assert.deepEqual(
    rows.map(row => [row.mode, row.action, row.outcome]),
    [
      ['record', 'account.password.changed', 'ok'],
      ['system', 'identity.mirror.failed', 'failed'],
    ]
  );
  // The session that acted is the one the change replaced; the rotated one is named.
  assert.equal(rows[0].actor.sessionId, access.sessionId);
  assert.equal(rows[0].detail.newSessionId, result.issue.id);
  assert.equal(rows[0].client, '192.0.2.9');
  assert.equal(rows[0].detail.revokedOtherSessions, 0);
  assert.deepEqual(rows[1].target, { type: 'file', id: 'auth.json', name: null });
  assert.equal(rows[1].detail.code, 'EROFS');
  const text = JSON.stringify(rows);
  for (const secret of [adminPassword, otherPassword, issue.value, result.issue.value])
    assert.ok(!text.includes(secret));
});

test('a recorder that rejects the mirror row never fails the change that stands', async t => {
  // audit.system() never rejects; should a recorder's defect make it, the change committed
  // already, and its answer must still carry the rotated cookie.
  const audit = fakeAudit();
  audit.system = async () => {
    throw new Error('audit store down');
  };
  const failing = () => {
    throw Object.assign(new Error('nope'), { code: 'EROFS' });
  };
  const { identity, signIn } = await started(t, { writeAuthRecord: failing, audit });
  const { access } = await signIn();
  const result = await identity.changePassword(access, input(adminPassword, otherPassword));
  assert.equal(result.mirrorPending, true);
  assert.equal((await identity.authenticateSession(result.issue.value, {})).via, 'session');
});

// An independent review of eb1b455: a password change whose write waits out a busy database (SQLite
// retries after a delay) must still be refused if its session ended during that wait, and a
// valid retry must not be refused by what its own rolled-back attempt changed in memory.
// `holdWriter` keeps a second connection's BEGIN IMMEDIATE open so the first write attempt
// meets SQLITE_BUSY; `duringRetry` runs inside the retry wait, after that writer commits.
async function busyChange(t, { duringRetry, via = 'session' } = {}) {
  let retries = 0,
    pending = null;
  const directory = temporary(t);
  writeAuthJson(directory, fakeRecord(adminPassword));
  const started = await startIdentity(t, directory, {
    controlOptions: {
      busyTimeoutMs: 0,
      sleep: async () => {
        retries++;
        const run = pending;
        pending = null;
        await run?.();
      },
    },
  });
  const { identity, control } = started;
  const access =
    via === 'session'
      ? (await identity.login({ login: 'admin', password: adminPassword })).access
      : await identity.authenticateBasic(basicBytes(adminPassword));
  const before = await adminRow(control);
  const writer = new DatabaseSync(path.join(directory, 'control.sqlite'));
  t.after(() => writer.close());
  writer.exec('PRAGMA busy_timeout=0');
  writer.exec('BEGIN IMMEDIATE');
  pending = async () => {
    writer.exec('COMMIT');
    await duringRetry?.({ ...started, access });
  };
  let result, error;
  try {
    result = await identity.changePassword(access, {
      currentPassword: adminPassword,
      password: otherPassword,
      confirmPassword: otherPassword,
    });
  } catch (caught) {
    error = caught;
  }
  const after = await adminRow(control);
  return { retries, error, result, changed: after.password !== before.password, identity };
}

for (const boundary of ['revoked', 'expired'])
  test(`a password change refuses a session ${boundary} while its write waited for a busy database`, async t => {
    const outcome = await busyChange(t, {
      duringRetry: async ({ identity, clock, access }) => {
        if (boundary === 'revoked') await identity.logout(access);
        else clock.set(access.session.idleExpiresAt);
        assert.throws(() => identity.assertCurrent(access), { code: 'session_expired' });
      },
    });
    assert.equal(outcome.retries, 1, 'the write met one genuine SQLITE_BUSY');
    assert.equal(outcome.error?.code, 'session_expired');
    assert.equal(outcome.changed, false, 'the password is unchanged');
    assert.equal(outcome.result, undefined, 'no new session was issued');
  });

for (const via of ['session', 'basic'])
  test(`a valid ${via} password change still succeeds after a busy retry`, async t => {
    const outcome = await busyChange(t, { via });
    assert.equal(outcome.retries, 1, 'the write met one genuine SQLITE_BUSY');
    assert.equal(outcome.error, undefined, String(outcome.error?.code ?? outcome.error));
    assert.equal(outcome.changed, true);
    assert.equal(Boolean(outcome.result?.issue), via === 'session');
    // The new password signs in; the old one no longer does.
    assert.ok(await outcome.identity.authenticateBasic(basicBytes(otherPassword)));
    assert.equal(await outcome.identity.authenticateBasic(basicBytes(adminPassword)), null);
  });

// The case the busy-lock tests above cannot reach: the write callback ran in full (rotating
// the session, revoking the others, advancing the Basic generation in memory) and then SQLite
// rolled the unit back with a retryable error, as a busy COMMIT does. The retry must undo those
// in-memory effects before it checks this request's authority, or it refuses its own change.
for (const via of ['session', 'basic'])
  test(`a valid ${via} password change survives a retry after its first attempt ran and was rolled back`, async t => {
    const directory = temporary(t);
    writeAuthJson(directory, fakeRecord(adminPassword));
    let retries = 0;
    const { identity, control } = await startIdentity(t, directory, {
      controlOptions: { sleep: async () => void retries++ },
    });
    const access =
      via === 'session'
        ? (await identity.login({ login: 'admin', password: adminPassword })).access
        : await identity.authenticateBasic(basicBytes(adminPassword));
    const write = control.db.write.bind(control.db);
    let rolledBack = false;
    control.db.write = (fn, options) =>
      write(tx => {
        const result = fn(tx);
        if (!rolledBack) {
          rolledBack = true;
          // What SqliteDb reports for SQLITE_BUSY: class 'retry', so it rolls back and retries.
          throw Object.assign(new Error('database is locked'), { class: 'retry', errcode: 5 });
        }
        return result;
      }, options);
    const result = await identity.changePassword(access, {
      currentPassword: adminPassword,
      password: otherPassword,
      confirmPassword: otherPassword,
    });
    control.db.write = write;
    assert.equal(rolledBack, true);
    assert.equal(retries, 1, 'one retry after the rollback');
    assert.equal(Boolean(result.issue), via === 'session');
    assert.ok(await identity.authenticateBasic(basicBytes(otherPassword)));
    assert.equal(await identity.authenticateBasic(basicBytes(adminPassword)), null);
  });

// An independent re-review of 369a03d: the first attempt runs in full (marking this session revoked
// tentatively), SQLite rolls it back, and during the retry wait a real sign-out of this very
// session commits. Undoing the rolled-back attempt must not take back that sign-out's mark.
test('a sign-out during the retry wait survives the undo of a rolled-back password change', async t => {
  const directory = temporary(t);
  writeAuthJson(directory, fakeRecord(adminPassword));
  let pending = null,
    retries = 0;
  const { identity, control } = await startIdentity(t, directory, {
    controlOptions: {
      sleep: async () => {
        retries++;
        const run = pending;
        pending = null;
        await run?.();
      },
    },
  });
  const mine = await identity.login({ login: 'admin', password: adminPassword });
  const before = await adminRow(control);
  const write = control.db.write.bind(control.db);
  let rolledBack = false;
  control.db.write = (fn, options) =>
    write(tx => {
      const result = fn(tx);
      if (!rolledBack) {
        rolledBack = true;
        throw Object.assign(new Error('database is locked'), { class: 'retry', errcode: 5 });
      }
      return result;
    }, options);
  pending = async () => {
    await identity.logout(mine.access);
    assert.throws(() => identity.assertCurrent(mine.access), { code: 'session_expired' });
    assert.equal((await rows(control, 'sessions')).length, 0, 'the sign-out deleted the row');
  };
  let result, error;
  try {
    result = await identity.changePassword(mine.access, {
      currentPassword: adminPassword,
      password: otherPassword,
      confirmPassword: otherPassword,
    });
  } catch (caught) {
    error = caught;
  }
  control.db.write = write;
  assert.equal(rolledBack, true);
  assert.equal(retries, 1);
  assert.equal(error?.code, 'session_expired', 'the explicit sign-out is kept');
  assert.equal((await adminRow(control)).password, before.password, 'password unchanged');
  assert.equal(result, undefined, 'no new session issued');
  assert.throws(() => identity.assertCurrent(mine.access), { code: 'session_expired' });
});

// The independent reviewer's companion control: the same rollback, but the sign-out during the retry wait cannot
// delete its row (a full disk). Its refusal then lives only in this process's revoked map, and
// the retry's undo must keep it: the password stays, no session is issued, the row remains.
test('a sign-out whose delete failed during the retry wait also survives the undo', async t => {
  const directory = temporary(t);
  writeAuthJson(directory, fakeRecord(adminPassword));
  let pending = null,
    retries = 0;
  const { identity, control } = await startIdentity(t, directory, {
    controlOptions: {
      sleep: async () => {
        retries++;
        const run = pending;
        pending = null;
        await run?.();
      },
    },
  });
  const mine = await identity.login({ login: 'admin', password: adminPassword });
  const before = await adminRow(control);
  const write = control.db.write.bind(control.db);
  let rolledBack = false,
    failLogout = 0,
    logoutFailures = 0;
  control.db.write = (fn, options) =>
    write(tx => {
      const result = fn(tx);
      if (!rolledBack) {
        rolledBack = true;
        throw Object.assign(new Error('database is locked'), { class: 'retry', errcode: 5 });
      }
      if (failLogout > 0) {
        failLogout -= 1;
        logoutFailures++;
        throw Object.assign(new Error('fixture disk full'), { class: 'full' });
      }
      return result;
    }, options);
  t.after(() => {
    control.db.write = write;
  });
  pending = async () => {
    // The delete fails with its audit row and again alone (audit spec D32).
    failLogout = 2;
    await assert.rejects(identity.logout(mine.access), { code: 'storage_full' });
    assert.throws(() => identity.assertCurrent(mine.access), { code: 'session_expired' });
    assert.deepEqual(
      (await rows(control, 'sessions')).map(row => row.id),
      [mine.access.sessionId],
      'the failed delete leaves the row; only the revoked map refuses it'
    );
    assert.equal(await identity.authenticateSession(mine.issue.value), null);
  };
  let result, error;
  try {
    result = await identity.changePassword(mine.access, {
      currentPassword: adminPassword,
      password: otherPassword,
      confirmPassword: otherPassword,
    });
  } catch (caught) {
    error = caught;
  }
  control.db.write = write;
  assert.equal(retries, 1);
  assert.equal(logoutFailures, 2);
  assert.equal(error?.code, 'session_expired', 'the failed sign-out is kept');
  assert.equal((await adminRow(control)).password, before.password, 'password unchanged');
  assert.equal(result, undefined, 'no session issued');
  assert.deepEqual(
    (await rows(control, 'sessions')).map(row => row.id),
    [mine.access.sessionId]
  );
  assert.throws(() => identity.assertCurrent(mine.access), { code: 'session_expired' });
  assert.equal(await identity.authenticateSession(mine.issue.value), null);
});
