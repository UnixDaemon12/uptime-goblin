import test from 'node:test';
import assert from 'node:assert/strict';
import { fakeIdentity } from '../helpers/fake-identity.mjs';
import { basic, browserWrite, login, password, raw, serveAuth } from './harness.mjs';

for (const kind of ['interactive', 'kiosk', 'token', undefined]) {
  test(`only interactive sessions enter replay store: ${kind}`, async t => {
    const identity = fakeIdentity({ password });
    const authenticate = identity.authenticateSession.bind(identity);
    identity.authenticateSession = async (...args) => {
      const access = await authenticate(...args);
      return access ? { ...access, kind } : access;
    };
    let replayed = 0;
    const { port } = await serveAuth(t, {
      identity,
      idempotency: async (req, res, context, run) => {
        replayed++;
        await run();
      },
    });
    const { cookie } = await login(port);
    assert.ok(cookie);
    for (const [method, path, expected] of [
      ['POST', '/api/unknown', 404],
      ['DELETE', '/api/thing', 405],
    ]) {
      const answer = await raw(
        port,
        [
          `${method} ${path} HTTP/1.1`,
          `Cookie: ${cookie}`,
          ...browserWrite(`http://127.0.0.1:${port}`),
          'Idempotency-Key: fixture-replay-key',
        ],
        '{}'
      );
      assert.equal(answer.status, expected, answer.body);
    }
    assert.equal(replayed, kind === 'interactive' ? 2 : 0);
  });
}
test('Basic keyed writes retain replay protection', async t => {
  let replayed = 0;
  const { port } = await serveAuth(t, {
    idempotency: async (req, res, context, run) => {
      replayed++;
      await run();
    },
  });
  const answer = await raw(
    port,
    [
      'POST /api/thing HTTP/1.1',
      `Authorization: ${basic()}`,
      'Content-Type: application/json',
      'X-Goblin-Request: 1',
      'Idempotency-Key: fixture-basic-key',
    ],
    '{}'
  );
  assert.equal(answer.status, 200, answer.body);
  assert.equal(replayed, 1);
});

test('a redeemed real display session never enters the replay store on unknown writes', async t => {
  const { startReal, cookieFrom } = await import('./harness.mjs');
  const { newDisplayCode } = await import('../../lib/identity/secrets.mjs');
  const { identityOps } = await import('../../lib/repo/identity.mjs');
  const { app, port } = await startReal(t);
  const made = newDisplayCode(),
    now = Date.now();
  await app.control.db.write(tx =>
    identityOps.insertDisplay(tx, {
      id: made.id,
      name: 'Fixture display',
      codeHash: made.codeHash,
      codeExpiresAt: now + 600000,
      createdAt: now,
      createdBy: 'cli:test',
    })
  );
  const signedIn = await raw(
    port,
    ['POST /api/auth/login HTTP/1.1', ...browserWrite(`http://127.0.0.1:${port}`)],
    JSON.stringify({ code: made.code, display: true })
  );
  assert.equal(signedIn.status, 200, signedIn.body);
  assert.equal(signedIn.json.kind, 'kiosk');
  const cookie = cookieFrom(signedIn);
  assert.ok(cookie);
  let replayed = 0;
  const intercepted = await serveAuth(t, {
    identity: app.identity,
    idempotency: async (req, res, context, run) => {
      replayed++;
      await run();
    },
  });
  const answer = await raw(
    intercepted.port,
    [
      'POST /api/unknown HTTP/1.1',
      `Cookie: ${cookie}`,
      ...browserWrite(`http://127.0.0.1:${intercepted.port}`),
      'Idempotency-Key: fixture-real-display',
    ],
    '{}'
  );
  assert.equal(answer.status, 404, answer.body);
  assert.equal(replayed, 0);
});
