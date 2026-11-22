// The in-memory identity the HTTP tests use must behave as the real service does: the shared
// contract (test/helpers/identity-contract.mjs) runs against it here and against
// lib/identity/index.mjs in test/identity/contract.test.mjs. The tests below cover what the
// HTTP tests rely on beyond the contract: its test controls and the revocation ordering.
import test from 'node:test';
import assert from 'node:assert/strict';
import { identityContract, assertIdentityError } from '../helpers/identity-contract.mjs';
import { fakeIdentity, fakeTokenHash, fullWrite } from '../helpers/fake-identity.mjs';

identityContract(test, fakeIdentity, { name: 'fake identity', recordsAudit: true });

const password = 'fake identity password';

test('fake identity: a failed sign-in write keeps the sessions it would have rotated (§5.9)', async () => {
  const identity = fakeIdentity({ password });
  const before = await identity.login({ login: 'admin', password });
  identity.test.beforeWrite = fullWrite;
  await assert.rejects(
    identity.login({ login: 'admin', password, replacing: [before.issue.value] }),
    error => assertIdentityError(error, 'storage_full')
  );
  identity.test.beforeWrite = null;
  // Nothing changed: the presented session still works and is not in the revoked map.
  identity.assertCurrent(before.access);
  assert.equal(
    (await identity.authenticateSession(before.issue.value, { activity: 'foreground' })).sessionId,
    before.access.sessionId
  );
  assert.deepEqual(identity.test.revokedIds(), []);
  // A successful sign-in that presents it rotates it.
  const after = await identity.login({ login: 'admin', password, replacing: [before.issue.value] });
  assert.equal(await identity.authenticateSession(before.issue.value, {}), null);
  assert.deepEqual(identity.test.revokedIds(), [before.access.sessionId]);
  identity.assertCurrent(after.access);
});

test('fake identity: a failed logout write keeps the session refused (fail closed) until prune', async () => {
  const identity = fakeIdentity({ password });
  const { access, issue } = await identity.login({ login: 'admin', password });
  identity.test.beforeWrite = fullWrite;
  await assert.rejects(identity.logout(access));
  identity.test.beforeWrite = null;
  assert.throws(
    () => identity.assertCurrent(access),
    error => assertIdentityError(error, 'session_expired')
  );
  assert.equal(await identity.authenticateSession(issue.value, {}), null);
  assert.equal(identity.test.rows().length, 1, 'the row is still there');
  assert.deepEqual(await identity.prune(), { sessions: 1, mirror: 'none' });
  assert.equal(identity.test.rows().length, 0);
});

test('fake identity: at most 20 sessions; the least recently seen is evicted', async () => {
  let now = Date.UTC(2026, 9, 1);
  const identity = fakeIdentity({ password, clock: () => now });
  const made = [];
  for (let i = 0; i < 20; i++) {
    made.push(await identity.login({ login: 'admin', password }));
    now += 1000;
  }
  // The oldest is used again, so the second oldest is the least recently seen.
  now += 120e3;
  await identity.authenticateSession(made[0].issue.value, { activity: 'foreground' });
  await identity.login({ login: 'admin', password });
  assert.equal(identity.test.rows().length, 20);
  assert.equal(await identity.authenticateSession(made[1].issue.value, {}), null);
  assert.ok(await identity.authenticateSession(made[0].issue.value, {}));
});

// Audit spec D32, §5.1: a recorder failing as a full disk does fails a sign-in or a password
// change, but a sign-out or revocation is made without its row, which goes to unrecorded().
test('fake identity: rows that cannot be recorded fail a sign-in, never a sign-out', async () => {
  const identity = fakeIdentity({ password });
  const audit = identity.test.audit;
  const { access, issue } = await identity.login({ login: 'admin', password });
  const other = await identity.login({ login: 'admin', password });
  const full = Object.assign(new Error('database or disk is full'), { class: 'full' });
  audit.setFailing('record', full);
  await assert.rejects(identity.login({ login: 'admin', password }), error =>
    assertIdentityError(error, 'storage_full')
  );
  assert.equal(identity.test.rows().length, 2, 'the sign-in made nothing');
  await assert.rejects(
    identity.changePassword(other.access, {
      currentPassword: password,
      password: 'a new fake password',
      confirmPassword: 'a new fake password',
    }),
    error => assertIdentityError(error, 'storage_full')
  );
  identity.assertCurrent(other.access);
  await identity.logout(access);
  assert.equal(await identity.authenticateSession(issue.value, {}), null);
  assert.equal(identity.test.rows().length, 1, 'the sign-out deleted the session');
  assert.deepEqual(
    audit.unrecorded.calls.map(({ event, error }) => [event.action, event.detail, error]),
    [['session.logout', { cause: 'signout' }, full]]
  );
  // Another storage failure fails the sign-out as before (its session stays refused).
  const unavailable = Object.assign(new Error('disk I/O error'), { class: 'unavailable' });
  audit.setFailing('record', unavailable);
  await assert.rejects(
    identity.revokeSession(other.access, other.access.sessionId),
    /disk I\/O error/
  );
  assert.throws(
    () => identity.assertCurrent(other.access),
    error => assertIdentityError(error, 'session_expired')
  );
  audit.setFailing('record', null);
  assert.deepEqual(
    audit.rows.map(row => row.action),
    ['session.login', 'session.login']
  );
});

// Audit spec §5.1: a sign-out whose delete itself fails on a full disk rejects storage_full and
// records `session.logout` failed (detail.code) through audit.system(), outside any unit; the
// session stays refused. A sign-out made without its row (above) records no such row.
test('fake identity: a sign-out whose delete fails records session.logout failed through system()', async () => {
  const identity = fakeIdentity({ password });
  const audit = identity.test.audit;
  const { access } = await identity.login({ login: 'admin', password });
  const a = await identity.login({ login: 'admin', password }),
    b = await identity.login({ login: 'admin', password }),
    c = await identity.login({ login: 'admin', password });
  const request = Object.freeze({
    requestId: 'r-signout',
    route: 'POST /api/auth/logout',
    client: '192.0.2.10',
    userAgent: 'test agent',
    actor: {
      type: 'user',
      id: 'u_admin',
      name: 'admin',
      via: 'session',
      sessionId: access.sessionId,
    },
  });
  const from = audit.rows.length;
  identity.test.beforeWrite = fullWrite;
  await assert.rejects(identity.logout(access, { request }), error =>
    assertIdentityError(error, 'storage_full')
  );
  await assert.rejects(
    identity.revokePresented([a.issue.value, b.issue.value], { cause: 'ended' }),
    error => assertIdentityError(error, 'storage_full')
  );
  // Another failure of the write (not a full disk) records nothing more.
  identity.test.beforeWrite = () => {
    throw Object.assign(new Error('disk I/O error'), { class: 'unavailable' });
  };
  await assert.rejects(identity.logout(c.access), /disk I\/O error/);
  identity.test.beforeWrite = null;
  // Each session ended is the actor of its own row, as in the rows of a sign-out that worked.
  assert.deepEqual(
    audit.rows
      .slice(from)
      .map(row => [
        row.mode,
        row.action,
        row.outcome,
        row.actor.sessionId,
        row.target.id,
        row.detail,
      ]),
    [access, a.access, b.access].map(({ sessionId }) => [
      'system',
      'session.logout',
      'failed',
      sessionId,
      sessionId,
      { code: 'storage_full' },
    ])
  );
  // The request's facts name who asked.
  assert.deepEqual(
    [audit.rows[from].client, audit.rows[from].requestId],
    ['192.0.2.10', 'r-signout']
  );
  assert.deepEqual(audit.unrecorded.calls, []);
  // Each session stays refused, though its row is still stored (fail closed).
  for (const ended of [access, a.access, b.access, c.access])
    assert.throws(
      () => identity.assertCurrent(ended),
      error => assertIdentityError(error, 'session_expired')
    );
});

test('fake identity: the test controls hold, saturate and count checks', async () => {
  const identity = fakeIdentity({ password });
  const bytes = Buffer.from('admin:' + password);
  identity.test.saturated = true;
  await assert.rejects(identity.authenticateBasic(bytes, {}), error => {
    assertIdentityError(error, 'busy');
    assert.equal(error.scope, 'queue');
    return true;
  });
  identity.test.saturated = false;
  let open;
  identity.test.gate = new Promise(resolve => (open = resolve));
  let admitted = 0;
  const admit = () => {
    admitted++;
    return () => {};
  };
  const first = identity.authenticateBasic(bytes, { admit }),
    second = identity.authenticateBasic(Buffer.from(bytes), { admit });
  open();
  identity.test.gate = null;
  assert.equal((await first).verified, true);
  assert.equal((await second).verified, true);
  assert.equal(admitted, 1, 'identical checks in flight share one admission');
  assert.equal(identity.test.checks, 1);
  // setPassword is an import: every session ends and Basic accesses go stale.
  const { access } = await identity.login({ login: 'admin', password });
  const basic = await identity.authenticateBasic(bytes, {});
  identity.test.setPassword('another fake password');
  assert.throws(
    () => identity.assertCurrent(access),
    error => assertIdentityError(error, 'session_expired')
  );
  assert.throws(
    () => identity.assertCurrent(basic),
    error => assertIdentityError(error, 'signin_required')
  );
  assert.equal(identity.isRetiredBasic(bytes), true);
  // 43 characters carry 258 bits: only the encoding whose last 2 bits are zero is canonical.
  assert.equal(fakeTokenHash('v1.' + 'A'.repeat(42) + 'B'), null, 'not a canonical encoding');
  assert.match(fakeTokenHash('v1.' + 'A'.repeat(43)), /^[0-9a-f]{64}$/);
});
