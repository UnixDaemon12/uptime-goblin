import test from 'node:test';
import assert from 'node:assert/strict';
import {
  startIdentity,
  temporary,
  adminPassword,
  basicBytes,
  fakeKey,
  countingDerive,
} from './helpers.mjs';

const signIn = identity =>
  identity.login({ login: 'admin', password: adminPassword, client: '192.0.2.3' });

test('same-request verifier checks every call, leaves caller buffer alone and clears its byte copies', async t => {
  const seen = [];
  const derive = (bytes, salt) => {
    seen.push(bytes);
    return fakeKey(bytes, salt);
  };
  const { identity, logged } = await startIdentity(t, temporary(t), {
    password: adminPassword,
    derive,
  });
  const { access } = await signIn(identity);
  seen.length = 0;
  const input = Buffer.from(adminPassword);
  assert.equal(await identity.verifyPassword(access, input), true);
  assert.equal(await identity.verifyPassword(access, input), true);
  assert.equal(await identity.verifyPassword(access, Buffer.from('fixture-wrong')), false);
  assert.equal(seen.length, 3, 'no cached password success');
  for (const copy of seen) assert.ok(copy.every(byte => byte === 0));
  assert.equal(input.toString(), adminPassword);
  assert.equal(logged.text().includes(adminPassword), false);
});

test('verifier rejects unsupported principal kinds and invalid byte envelopes before KDF', async t => {
  const derive = countingDerive();
  const { identity } = await startIdentity(t, temporary(t), { password: adminPassword, derive });
  const { access } = await signIn(identity),
    before = derive.calls;
  for (const kind of ['kiosk', 'token', undefined])
    await assert.rejects(
      identity.verifyPassword({ ...access, kind }, Buffer.from(adminPassword)),
      e => e.code === 'forbidden'
    );
  for (const value of ['', adminPassword, null, Buffer.alloc(0), Buffer.alloc(1025)])
    await assert.rejects(identity.verifyPassword(access, value), TypeError);
  await assert.rejects(
    identity.verifyPassword(null, Buffer.from(adminPassword)),
    e => e.code === 'signin_required'
  );
  assert.equal(derive.calls, before);
});

test('Basic can use verification primitive but success grants no route or reusable proof', async t => {
  const { identity } = await startIdentity(t, temporary(t), { password: adminPassword });
  const access = await identity.authenticateBasic(basicBytes(adminPassword));
  assert.equal(await identity.verifyPassword(access, Buffer.from(adminPassword)), true);
  assert.equal(await identity.verifyPassword(access, Buffer.from('fixture-wrong')), false);
  assert.equal(access.permissions.has('tokens:manage'), false);
});

test('a session revoked during verification never receives successful proof', async t => {
  const derive = countingDerive();
  const { identity } = await startIdentity(t, temporary(t), { password: adminPassword, derive });
  const { access } = await signIn(identity);
  derive.hold();
  const pending = identity.verifyPassword(access, Buffer.from(adminPassword));
  const rejected = assert.rejects(pending, e => e.code === 'session_expired');
  await identity.logout(access);
  derive.release();
  await rejected;
});

for (const kind of ['interactive', 'basic'])
  test(`password replacement during verification invalidates ${kind} result`, async t => {
    let pause = false,
      release,
      heldBytes;
    const derive = (bytes, salt) => {
      const key = fakeKey(bytes, salt);
      if (!pause) return key;
      pause = false;
      heldBytes = bytes;
      return new Promise(resolve => {
        release = () => resolve(key);
      });
    };
    const { identity } = await startIdentity(t, temporary(t), { password: adminPassword, derive });
    const original = await signIn(identity);
    const access =
      kind === 'basic'
        ? await identity.authenticateBasic(basicBytes(adminPassword))
        : original.access;
    pause = true;
    const pending = identity.verifyPassword(access, Buffer.from(adminPassword));
    const rejected = assert.rejects(pending, e =>
      ['session_expired', 'signin_required'].includes(e.code)
    );
    await identity.changePassword(original.access, {
      currentPassword: adminPassword,
      password: 'fixture-next-password-long',
      confirmPassword: 'fixture-next-password-long',
    });
    release();
    await rejected;
    assert.ok(heldBytes.every(byte => byte === 0));
  });

test('verifier uses existing bounded KDF queue and propagates busy without admitting excess work', async t => {
  const derive = countingDerive();
  const { identity } = await startIdentity(t, temporary(t), { password: adminPassword, derive });
  const { access } = await signIn(identity);
  derive.hold();
  const requests = Array.from({ length: 19 }, () =>
    identity.verifyPassword(access, Buffer.from(adminPassword)).then(
      value => ({ value }),
      error => ({ error })
    )
  );
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(derive.pending(), 2, 'only existing two active KDF slots');
  derive.release();
  const results = await Promise.all(requests);
  assert.equal(results.filter(r => r.value === true).length, 18);
  assert.equal(results.filter(r => r.error?.code === 'busy').length, 1);
});

test('owned password bytes are cleared when KDF fails', async t => {
  let fail = false,
    seen;
  const derive = (bytes, salt) => {
    if (fail) {
      seen = bytes;
      throw new Error('fixture KDF failure');
    }
    return fakeKey(bytes, salt);
  };
  const { identity } = await startIdentity(t, temporary(t), { password: adminPassword, derive });
  const { access } = await signIn(identity);
  fail = true;
  await assert.rejects(
    identity.verifyPassword(access, Buffer.from(adminPassword)),
    /fixture KDF failure/
  );
  assert.ok(seen.every(byte => byte === 0));
});
