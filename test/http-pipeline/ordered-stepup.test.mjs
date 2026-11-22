import test from 'node:test';
import assert from 'node:assert/strict';
import { serveAuth, raw, login, browserWrite, basic, password } from './harness.mjs';
import { fakeIdentity } from '../helpers/fake-identity.mjs';
import { fakeAudit } from '../helpers/fake-audit.mjs';
import { createRouter, RouteError } from '../../lib/http/router.mjs';
import { json } from '../../lib/http/body.mjs';
import { identityError } from '../../lib/identity/errors.mjs';

const fixture = handler => ({
  method: 'POST',
  path: '/api/stepup-fixture',
  auth: 'session',
  permission: 'settings:write',
  summary: 'Step-up fixture',
  stepUp: true,
  idempotent: false,
  lock: 'logging',
  ifMatch: 'required',
  handler,
});

async function setup(t, options = {}) {
  const identity = fakeIdentity({ password });
  const audit = fakeAudit();
  const buffers = [];
  let checks = 0,
    handled = 0,
    replayed = 0;
  identity.verifyPassword = async (access, bytes) => {
    identity.assertCurrent(access);
    checks++;
    buffers.push(bytes);
    await options.verify?.(access, bytes);
    return bytes.toString() === password;
  };
  const server = await serveAuth(t, {
    identity,
    audit,
    supports: ['stepUp', 'lock'],
    adminUiLock: options.lock ?? 'none',
    permitted: options.permitted,
    loginThrottle: options.throttle,
    idempotency: async () => {
      replayed++;
      assert.fail('password request entered replay store');
    },
    routes: [
      fixture(async ({ res, body }) => {
        handled++;
        assert.ok(buffers.every(b => b.every(byte => byte === 0)));
        const first = await body();
        assert.strictEqual(first, await body());
        assert.equal(Object.hasOwn(first, 'stepUp'), false);
        json(res, 200, first);
      }),
    ],
  });
  const { cookie } = await login(server.port);
  const send = (value, { match = true, csrf = true, asBasic = false } = {}) =>
    raw(
      server.port,
      [
        'POST /api/stepup-fixture HTTP/1.1',
        asBasic ? `Authorization: ${basic()}` : `Cookie: ${cookie}`,
        ...(csrf
          ? browserWrite(`http://127.0.0.1:${server.port}`).filter(
              line =>
                !asBasic || (!line.startsWith('Sec-Fetch-') && !line.startsWith('X-Goblin-Client:'))
            )
          : ['Content-Type: application/json']),
        ...(match ? ['If-Match: "1"'] : []),
        'Idempotency-Key: repeated',
      ],
      value
    );
  return { ...server, send, buffers, audit, counts: () => ({ checks, handled, replayed }) };
}
const body = value => JSON.stringify({ value: 7, stepUp: { password: value } });

test('step-up declarations cannot enable replay, reads, public auth or non-JSON/CSRF bypass', () => {
  for (const override of [
    { idempotent: true },
    { method: 'GET' },
    { auth: 'public', permission: null },
    { csrf: false },
    { contentType: 'none' },
    { body: 'empty' },
  ])
    assert.throws(
      () => createRouter([{ ...fixture(() => {}), ...override }], { supports: ['stepUp', 'lock'] }),
      RouteError
    );
});

test('same-request verification, stripped body reused, buffers zero before handler, no replay', async t => {
  const f = await setup(t);
  for (let i = 0; i < 2; i++) assert.deepEqual((await f.send(body(password))).json, { value: 7 });
  assert.deepEqual(f.counts(), { checks: 2, handled: 2, replayed: 0 });
  assert.equal(f.audit.counts.filter(e => e.action === 'auth.step-up').length, 0);
});

test('CSRF and lock precede If-Match/body; If-Match precedes envelope validation', async t => {
  const locked = await setup(t, { lock: 'logging' });
  assert.equal(
    (await locked.send('{bad', { csrf: false, match: false })).json.code,
    'cross_origin'
  );
  assert.equal((await locked.send('{bad', { match: false })).json.code, 'admin_ui_locked');
  assert.deepEqual(locked.counts(), { checks: 0, handled: 0, replayed: 0 });
  const f = await setup(t);
  assert.equal((await f.send('{bad', { match: false })).json.code, 'if_match_required');
  assert.equal((await f.send('{}')).json.code, 'step_up_required');
  assert.deepEqual(f.counts(), { checks: 0, handled: 0, replayed: 0 });
});

test('generic Basic remains unavailable, even with a valid separate password; strict CSRF first', async t => {
  const f = await setup(t);
  assert.equal(
    (await f.send(body(password), { asBasic: true, csrf: false })).json.code,
    'cross_origin'
  );
  assert.equal((await f.send('{bad', { asBasic: true })).json.code, 'step_up_unavailable');
  assert.deepEqual(f.counts(), { checks: 0, handled: 0, replayed: 0 });
});

test('wrong password is counted once without secret reflection, then valid request verifies anew', async t => {
  const f = await setup(t);
  const answer = await f.send(body('not-the-password'));
  assert.equal(answer.json.code, 'step_up_failed');
  assert.equal(answer.body.includes('not-the-password'), false);
  assert.ok(f.buffers[0].every(b => b === 0));
  assert.equal(f.audit.counts.filter(e => e.action === 'auth.step-up').length, 1);
  assert.equal((await f.send(body(password))).status, 200);
  assert.deepEqual(f.counts(), { checks: 2, handled: 1, replayed: 0 });
});

test('currentness rechecked after verifier await; cleanup and no handler on stale principal', async t => {
  let stale = false;
  const f = await setup(t, {
    verify: async () => {
      stale = true;
    },
  });
  const original = f.identity.assertCurrent.bind(f.identity);
  f.identity.assertCurrent = access => {
    if (stale) throw identityError('session_expired');
    original(access);
  };
  assert.equal((await f.send(body(password))).json.code, 'session_expired');
  assert.ok(f.buffers[0].every(b => b === 0));
  assert.deepEqual(f.counts(), { checks: 1, handled: 0, replayed: 0 });
});

test('envelope shape precedes lockout; locked requests perform no password verification', async t => {
  const f = await setup(t);
  f.loginThrottle.retryAfter = () => 5000;
  assert.equal((await f.send('{}')).json.code, 'step_up_required');
  const denied = await f.send(body(password));
  assert.equal(denied.json.code, 'locked');
  assert.equal(denied.headers['retry-after'], '5');
  assert.deepEqual(f.counts(), { checks: 0, handled: 0, replayed: 0 });
});

test('verifier exception releases admission and clears password bytes', async t => {
  const f = await setup(t, {
    verify: async () => {
      throw new Error('fixture failure');
    },
  });
  let released = 0;
  f.loginThrottle.begin = () => () => {
    released++;
  };
  assert.equal((await f.send(body(password))).status, 500);
  assert.equal(released, 1);
  assert.ok(f.buffers[0].every(b => b === 0));
  assert.deepEqual(f.counts(), { checks: 1, handled: 0, replayed: 0 });
});
