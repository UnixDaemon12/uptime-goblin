import test from 'node:test';
import assert from 'node:assert/strict';
import { withStepUpPassword } from '../../lib/admin/step-up.mjs';
const encoded = input => Buffer.from(JSON.stringify(input));
const wiped = buffer => buffer.every(byte => byte === 0);

test('password is lent only for the awaited operation; handler body is sanitized once', async () => {
  const raw = encoded({
    stepUp: { password: 'fixture-password' },
    name: 'Display',
    other: { x: 1 },
  });
  let borrowed;
  const result = await withStepUpPassword(raw, async (bytes, body) => {
    borrowed = bytes;
    assert.equal(wiped(raw), true);
    assert.equal(bytes.toString(), 'fixture-password');
    assert.deepEqual(body, { name: 'Display', other: { x: 1 } });
    await Promise.resolve();
    assert.equal(bytes.toString(), 'fixture-password');
    return body;
  });
  assert.deepEqual(result, { name: 'Display', other: { x: 1 } });
  assert.equal(wiped(borrowed), true);
  assert.equal(wiped(raw), true);
});

test('operation refusal or disconnect-style failure clears borrowed bytes', async () => {
  const raw = encoded({ stepUp: { password: 'fixture-password' } });
  let borrowed;
  const failure = new Error('fixture failure');
  await assert.rejects(
    withStepUpPassword(raw, async bytes => {
      borrowed = bytes;
      throw failure;
    }),
    error => error === failure
  );
  assert.equal(wiped(borrowed), true);
  assert.equal(wiped(raw), true);
});

test('missing and malformed envelopes refuse before the operation without echoing values', async () => {
  for (const input of [
    null,
    [],
    'string',
    {},
    { stepUp: null },
    { stepUp: [] },
    { stepUp: {} },
    { stepUp: { password: 1 } },
    { stepUp: { password: '' } },
    { stepUp: { password: 'x'.repeat(1025) } },
    { stepUp: { password: '😀'.repeat(257) } },
  ]) {
    const raw = encoded(input);
    let called = false;
    await assert.rejects(
      withStepUpPassword(raw, () => {
        called = true;
      }),
      { code: 'step_up_required' }
    );
    assert.equal(called, false);
    assert.equal(wiped(raw), true);
  }
});

test('UTF-8 byte boundaries accept exactly1 and1024 bytes, without password-strength rules', async () => {
  for (const password of ['x', ' ', 'x'.repeat(1024), '😀'.repeat(256)]) {
    const raw = encoded({ stepUp: { password } });
    await withStepUpPassword(raw, bytes => assert.equal(bytes.toString('utf8'), password));
    assert.equal(wiped(raw), true);
  }
});

test('JSON parsing failures clear raw bytes and never call the verifier', async () => {
  for (const value of [
    '{bad',
    '{"stepUp":{"password":"\\ud800"}}',
    '{"stepUp":{"password":"first","password":"second"}}',
    '{"__proto__":{}}',
  ]) {
    const raw = Buffer.from(value);
    let called = false;
    await assert.rejects(
      withStepUpPassword(raw, () => {
        called = true;
      })
    );
    assert.equal(called, false);
    assert.equal(wiped(raw), true);
  }
});

test('does not validate unrelated handler fields or cache password verification', async () => {
  let checked = 0;
  for (let i = 0; i < 2; i++) {
    const raw = encoded({ stepUp: { password: 'fixture-password' }, name: 42, unknown: null });
    const result = await withStepUpPassword(raw, () => {
      checked++;
      return false;
    });
    assert.equal(result, false);
  }
  assert.equal(checked, 2);
});

test('parser refusal never echoes request-derived member names', async () => {
  const raw = Buffer.from(
    '{"PRIVATE_FIXTURE":1,"PRIVATE_FIXTURE":2,"stepUp":{"password":"PRIVATE_FIXTURE"}}'
  );
  await assert.rejects(
    withStepUpPassword(raw, () => assert.fail()),
    error => {
      assert.equal(error.message, 'Expected valid JSON');
      assert.equal(error.message.includes('PRIVATE_FIXTURE'), false);
      return true;
    }
  );
  assert.equal(wiped(raw), true);
});

test('invalid operation clears its owned request buffer', async () => {
  const raw = encoded({ stepUp: { password: 'fixture-password' } });
  await assert.rejects(withStepUpPassword(raw, null), TypeError);
  assert.equal(wiped(raw), true);
});

test('real identity verifier checks each supplied password and both layers clear owned bytes', async t => {
  const { startIdentity, temporary, adminPassword, fakeKey } = await import(
    '../identity/helpers.mjs'
  );
  const seen = [];
  const { identity } = await startIdentity(t, temporary(t), {
    password: adminPassword,
    derive: (bytes, salt) => {
      seen.push(bytes);
      return fakeKey(bytes, salt);
    },
  });
  const { access } = await identity.login({
    login: 'admin',
    password: adminPassword,
    client: '192.0.2.3',
  });
  seen.length = 0;
  for (const password of [adminPassword, 'fixture-wrong', adminPassword]) {
    const raw = encoded({ stepUp: { password }, name: 'Display' });
    let borrowed;
    const valid = await withStepUpPassword(raw, (bytes, body) => {
      borrowed = bytes;
      assert.deepEqual(body, { name: 'Display' });
      return identity.verifyPassword(access, bytes);
    });
    assert.equal(valid, password === adminPassword);
    assert.equal(wiped(raw), true);
    assert.equal(wiped(borrowed), true);
  }
  assert.equal(seen.length, 3);
  assert.equal(seen.every(wiped), true);
});
