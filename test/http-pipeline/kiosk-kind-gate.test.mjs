import test from 'node:test';
import assert from 'node:assert/strict';
import { principalRouteAllowed } from '../../lib/http/principal-routes.mjs';
import {
  routeTable,
  reservedPaths,
  supportedAuth,
  supportedFeatures,
} from '../../lib/http/routes.mjs';
import { createRouter } from '../../lib/http/router.mjs';
import { fakeIdentity } from '../helpers/fake-identity.mjs';
import { fakeAudit } from '../helpers/fake-audit.mjs';
import { json } from '../../lib/http/body.mjs';
import { serveAuth, raw, login, browserWrite, password } from './harness.mjs';

test('wall-display route inventory remains exactly the six specified signed-in routes', () => {
  const routes = createRouter(
    routeTable({
      nonce: 'fixture',
      site: { build: '000000000000', publicFiles: new Map(), indexPage: Buffer.from('') },
    }),
    { reserved: reservedPaths, auth: supportedAuth, supports: supportedFeatures }
  ).routes;
  const allowed = routes.filter(
    route => route.auth !== 'public' && principalRouteAllowed({ kind: 'kiosk' }, route)
  );
  assert.deepEqual(allowed.map(route => `${route.method} ${route.path}`).sort(), [
    'GET /api/dashboard',
    'GET /api/docs',
    'GET /api/history/:id',
    'GET /api/session',
    'GET /api/version',
    'POST /api/auth/logout',
  ]);
  assert.equal(
    principalRouteAllowed({ kind: 'kiosk' }, { method: 'DELETE', path: '/api/history/:id' }),
    false
  );
});

for (const kind of ['kiosk', 'interactive'])
  test(`a new route cannot borrow display permission to admit a kiosk: ${kind}`, async t => {
    const audit = fakeAudit(),
      identity = fakeIdentity({ password });
    const authenticate = identity.authenticateSession.bind(identity);
    identity.authenticateSession = async (...args) => {
      const access = await authenticate(...args);
      return access ? { ...access, kind } : access;
    };
    let calls = 0;
    const routes = ['GET', 'POST'].map(method => ({
      method,
      head: method === 'GET',
      path: '/api/fixture-future',
      auth: 'session',
      permission: 'dashboard:read',
      csrf: method === 'POST',
      summary: 'fixture',
      handler: ({ res }) => {
        calls++;
        json(res, 200, { ok: true });
      },
    }));
    const { port } = await serveAuth(t, { identity, audit, routes });
    const { cookie } = await login(port);
    for (const method of ['GET', 'HEAD', 'POST']) {
      const answer = await raw(
        port,
        [
          `${method} /api/fixture-future HTTP/1.1`,
          `Cookie: ${cookie}`,
          ...(method === 'POST' ? browserWrite(`http://127.0.0.1:${port}`) : []),
        ],
        method === 'POST' ? '{}' : ''
      );
      assert.equal(answer.status, kind === 'kiosk' ? 403 : 200);
    }
    assert.equal(calls, kind === 'kiosk' ? 0 : 3);
    assert.equal(
      audit.counts.filter(e => e.action === 'auth.forbidden').length,
      kind === 'kiosk' ? 3 : 0
    );
  });
