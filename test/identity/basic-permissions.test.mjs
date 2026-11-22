import test from 'node:test';
import assert from 'node:assert/strict';
import { permissions } from '../../lib/http/router.mjs';
import { json } from '../../lib/http/body.mjs';
import { temporary, startIdentity, adminPassword, basicBytes } from './helpers.mjs';
import { serveAuth, raw, basic } from '../http-pipeline/harness.mjs';

test('Basic excludes only token administration; interactive retains it and Basic retains display management', async t => {
  const { identity } = await startIdentity(t, temporary(t), { password: adminPassword });
  const access = await identity.authenticateBasic(basicBytes(adminPassword));
  assert.deepEqual(
    [...access.permissions].sort(),
    permissions.filter(p => !['tokens:manage', 'tokens:own'].includes(p)).sort()
  );
  assert.equal(access.permissions.has('kiosk:manage'), true);
  assert.throws(() => access.permissions.add('tokens:manage'), /read-only/);
  const interactive = await identity.login({
    login: 'admin',
    password: adminPassword,
    client: '192.0.2.3',
    transport: 'loopback',
  });
  assert.equal(interactive.access.permissions.has('tokens:manage'), true);
  assert.equal(interactive.access.permissions.has('tokens:own'), true);
});

test('real Basic token-permission requests stop before handler, while display management remains admitted', async t => {
  const { identity } = await startIdentity(t, temporary(t), { password: adminPassword });
  let handlers = 0;
  const routes = ['tokens:manage', 'tokens:own', 'kiosk:manage'].map((permission, i) => ({
    method: 'GET',
    path: `/api/fixture-${i}`,
    auth: 'session',
    permission,
    summary: 'fixture',
    handler: ({ res }) => {
      handlers++;
      json(res, 200, { ok: true });
    },
  }));
  const { port } = await serveAuth(t, { identity, routes });
  const credential = `Authorization: ${basic(adminPassword)}`;
  for (const i of [0, 1])
    assert.equal((await raw(port, [`GET /api/fixture-${i} HTTP/1.1`, credential])).status, 403);
  assert.equal(handlers, 0);
  assert.equal((await raw(port, ['GET /api/fixture-2 HTTP/1.1', credential])).status, 200);
  assert.equal(handlers, 1);
});
