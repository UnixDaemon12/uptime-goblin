// Legacy Basic verification (identity.authenticateBasic, sessions spec §5.11): 1.4.3's
// PasswordAuth.authenticate behaviour, moved here from test/auth.test.mjs and
// test/throttle.test.mjs and pointed at the database record.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  temporary,
  startIdentity,
  countingDerive,
  fakeKey,
  fakeRecord,
  writeAuthJson,
  basicBytes,
  adminPassword,
  otherPassword,
} from './helpers.mjs';

const another = 'another fixture password here';
const settle = () => new Promise(resolve => setImmediate(resolve));
const day = 24 * 3600e3;

async function withAuthJson(t, options = {}) {
  const directory = temporary(t);
  writeAuthJson(directory, fakeRecord(adminPassword));
  const derive = options.derive ?? countingDerive();
  const context = await startIdentity(t, directory, { derive, ...options });
  derive.calls = 0;
  return { ...context, derive };
}
const change = (identity, access, from, to) =>
  identity.changePassword(access, { currentPassword: from, password: to, confirmPassword: to });

test('bootstrap passwords are verified with the slow hash, not a fast digest', async t => {
  const derive = countingDerive();
  const { identity } = await startIdentity(t, temporary(t), { password: adminPassword, derive });
  assert.equal(await identity.authenticateBasic(basicBytes('wrong guess one')), null);
  assert.equal(await identity.authenticateBasic(basicBytes('wrong guess two')), null);
  // One derivation for the GOBLIN_PASSWORD record at the first start, then one per guess.
  assert.equal(derive.calls, 3);
  assert.equal((await identity.authenticateBasic(basicBytes(adminPassword))).verified, true);
  assert.equal((await identity.authenticateBasic(basicBytes(adminPassword))).verified, false);
  assert.equal(derive.calls, 4, 'no derivation for a cached success');
});

test('successful credential cache avoids repeated KDF work and never caches failed passwords', async t => {
  const { identity, derive } = await withAuthJson(t);
  for (let i = 0; i < 4; i++)
    assert.ok(await identity.authenticateBasic(basicBytes(adminPassword)));
  assert.equal(derive.calls, 1);
  for (let i = 0; i < 2; i++)
    assert.equal(await identity.authenticateBasic(basicBytes(otherPassword)), null);
  assert.equal(derive.calls, 3);
  assert.ok(await identity.authenticateBasic(basicBytes(adminPassword)));
  assert.equal(derive.calls, 3);
  await change(
    identity,
    await identity.authenticateBasic(basicBytes(adminPassword)),
    adminPassword,
    otherPassword
  );
  // One derivation verifies the current password, one hashes the new password.
  assert.equal(derive.calls, 5);
  // The new password is not pre-cached: its first use is a full (verified) check.
  const first = await identity.authenticateBasic(basicBytes(otherPassword));
  assert.equal(first.verified, true);
  assert.equal(derive.calls, 6);
  assert.ok(await identity.authenticateBasic(basicBytes(otherPassword)));
  assert.equal(derive.calls, 6);
  // The replaced password is refused after a full check (so timing does not reveal it) and is
  // marked retired, so the http layer does not count it as a guess.
  assert.equal(await identity.authenticateBasic(basicBytes(adminPassword)), null);
  assert.equal(derive.calls, 7);
  assert.equal(identity.isRetiredBasic(basicBytes(adminPassword)), true);
  assert.equal(identity.isRetiredBasic(basicBytes('never used password')), false);
});

test('identical credentials in flight share one check; admit is asked only when a check starts', async t => {
  const { identity, derive } = await withAuthJson(t);
  let admitted = 0,
    released = 0;
  const admit = () => {
    admitted += 1;
    return () => (released += 1);
  };
  derive.hold();
  const together = Array.from({ length: 5 }, () =>
    identity.authenticateBasic(basicBytes(adminPassword), { admit })
  );
  await settle();
  assert.equal(derive.pending(), 1);
  derive.release();
  const accesses = await Promise.all(together);
  assert.ok(accesses.every(access => access.via === 'basic' && access.verified === true));
  assert.equal(derive.calls, 1);
  assert.deepEqual([admitted, released], [1, 1]);
  // A cached success asks nothing of admit.
  await identity.authenticateBasic(basicBytes(adminPassword), { admit });
  assert.equal(admitted, 1);
  // A refusal from admit (this client's parallel attempts) stops the check.
  const refusal = Object.assign(new Error('busy'), { code: 'busy', scope: 'client' });
  await assert.rejects(
    identity.authenticateBasic(basicBytes(otherPassword), {
      admit: () => {
        throw refusal;
      },
    }),
    error => error === refusal
  );
  assert.equal(derive.calls, 1);
});

test('a check started before a password change never succeeds after it, and is never joined', async t => {
  // Holds the first derivation after `armed` is set, until releaseFirst().
  let armed = false,
    releaseFirst;
  const derive = (password, salt) => {
    if (!armed || releaseFirst) return Promise.resolve(fakeKey(password, salt));
    return new Promise(resolve => (releaseFirst = () => resolve(fakeKey(password, salt))));
  };
  const directory = temporary(t);
  writeAuthJson(directory, fakeRecord(adminPassword));
  const { identity } = await startIdentity(t, directory, { derive });
  const session = (await identity.login({ login: 'admin', password: adminPassword })).access;
  armed = true;
  // A check of the old password is still running when the password changes.
  const oldInFlight = identity.authenticateBasic(basicBytes(adminPassword));
  await settle();
  await change(identity, session, adminPassword, otherPassword);
  // A request with the old password arriving now must not join the earlier check.
  assert.equal(await identity.authenticateBasic(basicBytes(adminPassword)), null);
  releaseFirst();
  assert.equal(await oldInFlight, null);
  assert.ok(await identity.authenticateBasic(basicBytes(otherPassword)));
});

test('a Basic access from before a change is no longer current', async t => {
  const { identity } = await withAuthJson(t);
  const before = await identity.authenticateBasic(basicBytes(adminPassword));
  identity.assertCurrent(before);
  const other = await identity.authenticateBasic(basicBytes(adminPassword));
  await change(identity, other, adminPassword, otherPassword);
  assert.throws(
    () => identity.assertCurrent(before),
    error => error.code === 'signin_required' && error.status === 401
  );
  await assert.rejects(
    change(identity, before, otherPassword, another),
    error => error.code === 'signin_required'
  );
});

test('retired passwords: kept 24 h, at most 4, never the password in use', async t => {
  const { identity, clock } = await withAuthJson(t);
  const passwords = [
    adminPassword,
    'retired password one',
    'retired password two',
    'retired password three',
    'retired password four',
    'retired password five',
  ];
  for (let i = 1; i < passwords.length; i++) {
    const access = await identity.authenticateBasic(basicBytes(passwords[i - 1]));
    await change(identity, access, passwords[i - 1], passwords[i]);
  }
  // Five replaced; the oldest fell out.
  assert.deepEqual(
    passwords.map(password => identity.isRetiredBasic(basicBytes(password))),
    [false, true, true, true, true, false]
  );
  // Changing back to a retired password un-retires it.
  const current = await identity.authenticateBasic(basicBytes(passwords[5]));
  await change(identity, current, passwords[5], passwords[2]);
  assert.equal(identity.isRetiredBasic(basicBytes(passwords[2])), false);
  assert.equal(identity.isRetiredBasic(basicBytes(passwords[5])), true);
  clock.advance(day);
  assert.equal(identity.isRetiredBasic(basicBytes(passwords[5])), false, '24 h later');
});

test('changing to the same password keeps it usable and not retired', async t => {
  const { identity } = await withAuthJson(t);
  const access = await identity.authenticateBasic(basicBytes(adminPassword));
  await change(identity, access, adminPassword, adminPassword);
  assert.ok(await identity.authenticateBasic(basicBytes(adminPassword)));
  assert.equal(identity.isRetiredBasic(basicBytes(adminPassword)), false);
});

test('anything but admin:<password> costs one derivation and fails; the queue refuses as busy', async t => {
  const { identity, derive } = await withAuthJson(t);
  for (const bytes of [
    basicBytes(adminPassword, 'root'),
    Buffer.from('admin'),
    Buffer.from(''),
    basicBytes('x'.repeat(1025)),
  ]) {
    const before = derive.calls;
    assert.equal(await identity.authenticateBasic(bytes), null);
    assert.equal(derive.calls, before + 1);
  }
  assert.equal(await identity.authenticateBasic('admin:' + adminPassword), null, 'bytes only');
  assert.equal(identity.isRetiredBasic('admin:x'), false);
  derive.hold();
  const running = Array.from({ length: 18 }, (_, i) =>
    identity.authenticateBasic(basicBytes('queued guess ' + i))
  );
  await settle();
  await assert.rejects(
    identity.authenticateBasic(basicBytes('one too many')),
    error => error.code === 'busy' && error.scope === 'queue'
  );
  derive.release();
  assert.deepEqual(await Promise.all(running), Array(18).fill(null));
});

test('the caller’s buffer is left to the caller; the check keeps its own copy', async t => {
  const { identity, derive } = await withAuthJson(t);
  derive.hold();
  const bytes = basicBytes(adminPassword);
  const pending = identity.authenticateBasic(bytes);
  await settle();
  bytes.fill(0);
  derive.release();
  assert.equal((await pending).via, 'basic');
});

test('only the admin password signs a Basic credential in: 1.4.x ignored credentials without one', async t => {
  const { identity } = await withAuthJson(t);
  // 1.4.x (and earlier 1.5 builds) answered any credential with full access while no password
  // was set; Uptime Goblin no longer starts without one, so every other credential gets nothing.
  for (const value of ['anything', '', adminPassword.toUpperCase()])
    assert.equal(await identity.authenticateBasic(basicBytes(value)), null, value);
  assert.equal(await identity.authenticateBasic(Buffer.from('')), null);
  assert.equal(await identity.authenticateBasic('admin:' + adminPassword), null, 'not bytes');
  assert.equal(identity.isRetiredBasic(basicBytes('anything')), false);
  assert.equal((await identity.authenticateBasic(basicBytes(adminPassword))).via, 'basic');
});
