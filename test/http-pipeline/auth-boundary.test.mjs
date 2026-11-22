// An independent review of eb1b455: authenticate() checks the session before it resolves, but the
// pipeline resumes a microtask or more later. A sign-out landing in that gap must still stop
// the request: a protected read, an unkeyed write and a keyed write all answer 401, and the
// handler never runs. The hook only delays when the session lookup's result is delivered; the
// lookup result, the credentials and identity's checks are all real.
import test from 'node:test';
import assert from 'node:assert/strict';
import { startReal, login, raw, browserWrite } from './harness.mjs';

for (const [route, method, keyed] of [
  ['/api/config/export', 'GET', false],
  ['/api/refresh', 'POST', false],
  ['/api/refresh', 'POST', true],
])
  test(`a sign-out between authentication and dispatch stops ${method} ${route}${keyed ? ' (keyed)' : ''}`, async t => {
    const trace = [];
    const { app, port } = await startReal(t, {
      collector: () => {
        trace.push('collected');
        return [];
      },
    });
    app.config.update('linux', { apiUrl: 'http://collector.example.test' });
    const signed = await login(port);
    assert.equal(signed.answer.status, 200);
    const value = signed.cookie.slice(signed.cookie.indexOf('=') + 1);
    const access = await app.identity.authenticateSession(value, { transport: 'loopback' });
    const db = app.control.db,
      read = db.read.bind(db);
    let armed = true,
      revocation;
    db.read = async (...args) => {
      const result = await read(...args);
      if (armed && result?.id === access.sessionId) {
        armed = false;
        // Two microtasks: after authenticate() has checked and resolved, before the pipeline
        // continues.
        queueMicrotask(() =>
          queueMicrotask(() => {
            trace.push('revoked');
            revocation = app.identity.logout(access);
            assert.throws(() => app.identity.assertCurrent(access), { code: 'session_expired' });
          })
        );
      }
      return result;
    };
    const response = await raw(
      port,
      [
        `${method} ${route} HTTP/1.1`,
        `Cookie: ${signed.cookie}`,
        ...(method === 'POST'
          ? browserWrite(`http://127.0.0.1:${port}`)
          : ['Sec-Fetch-Site: same-origin']),
        ...(keyed ? ['Idempotency-Key: after-auth-revoke'] : []),
      ],
      method === 'POST' ? '{}' : ''
    );
    await revocation;
    db.read = read;
    assert.equal(armed, false, 'the real session lookup was observed');
    assert.equal(response.status, 401, 'a retired session must not reach the handler');
    assert.equal(response.json?.code, 'session_expired');
    assert.deepEqual(trace, ['revoked']);
  });
