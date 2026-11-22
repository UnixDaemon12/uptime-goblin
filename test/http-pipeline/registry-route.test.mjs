import test from 'node:test';
import assert from 'node:assert/strict';
import { ADMIN_ACTIONS, adminRoute, adminPreviewRoute } from '../../lib/admin/actions.mjs';
import { createRouter, RouteError, permissions } from '../../lib/http/router.mjs';
const supports = ['lock', 'stepUp'];
const make = row => ({
  ...row.route,
  auth: 'session',
  summary: 'Registry fixture',
  handler: () => {},
  idempotent: false,
  ...adminRoute(row.name),
});
const build = route => createRouter([route], { supports });

test('17-row binding preserves unsupported admin audit refusals and validates available rows', () => {
  assert.equal(ADMIN_ACTIONS.length, 17);
  for (const row of ADMIN_ACTIONS) {
    const route = make(row);
    if (row.audit === 'admin') {
      // No admin-operation recorder exists yet: metadata consistency must not invent it.
      assert.throws(() => build(route), /audit must be one of/);
      continue;
    }
    assert.equal(build(route).routes[0].action, row.name);
    for (const delta of [
      { path: route.path + '/other' },
      { method: route.method === 'POST' ? 'PUT' : 'POST' },
      { permission: 'dashboard:read' },
      { stepUp: !route.stepUp },
      { lock: route.lock === null ? 'logging' : null },
      { audit: route.audit === 'none' ? 'identity' : 'none' },
      { auth: 'any' },
      { action: 'unknown' },
      { action: null },
    ])
      assert.throws(
        () => build({ ...route, ...delta }),
        RouteError,
        `${row.name} ${JSON.stringify(delta)}`
      );
  }
});

test('only audit-accept has a read-only preview and POST metadata cannot be weakened', () => {
  const row = ADMIN_ACTIONS.find(r => r.name === 'audit-accept');
  const read = { ...make(row), method: 'GET', ...adminPreviewRoute(row.name), head: true };
  const router = build(read);
  assert.equal(router.match('HEAD', '/api/audit/accept').route.method, 'GET');
  assert.equal(router.routes[0].stepUp, false);
  assert.equal(router.routes[0].lock, null);
  assert.equal(router.routes[0].audit, 'none');
  assert.throws(() => build({ ...read, method: 'POST' }), RouteError);
  assert.throws(() => build({ ...read, ...adminRoute(row.name) }), RouteError);
  for (const other of ADMIN_ACTIONS.filter(
    r => r.route.method !== 'GET' && r.name !== 'audit-accept'
  ))
    assert.throws(
      () => build({ ...make(other), method: 'GET', stepUp: false, lock: null, audit: 'none' }),
      RouteError
    );
});

test('reserved admin paths require an action; hooks and replay cannot bypass bound mutation guards', () => {
  for (const path of ['/api/admin', '/api/admin/status', '/api/admin/unknown', '/api/audit/accept'])
    assert.throws(
      () =>
        build({
          method: 'GET',
          path,
          auth: 'session',
          permission: 'system:read',
          summary: 'missing',
          handler: () => {},
        }),
      RouteError
    );
  for (const row of ADMIN_ACTIONS.filter(r => r.route.method !== 'GET')) {
    for (const delta of [
      { idempotent: true },
      { csrf: false },
      { contentType: 'none' },
      { multipleSessions: () => {} },
      { endedSession: () => {} },
    ])
      assert.throws(() => build({ ...make(row), ...delta }), RouteError);
  }
});

test('registry binding does not advertise production pipeline features', async () => {
  const { supportedFeatures } = await import('../../lib/http/routes.mjs');
  assert.deepEqual(supportedFeatures, []);
  const guarded = make(ADMIN_ACTIONS.find(r => r.name === 'display-code'));
  assert.throws(() => createRouter([guarded]), RouteError);
});

test('registry-only permissions do not expand existing principal grants or arbitrary routes', () => {
  for (const permission of ['keys:manage', 'audit:manage']) {
    assert.equal(permissions.includes(permission), false);
    assert.throws(
      () =>
        build({
          method: 'GET',
          path: '/api/other',
          auth: 'session',
          permission,
          summary: 'unbound',
          handler: () => {},
        }),
      RouteError
    );
    assert.throws(
      () =>
        build({
          method: 'GET',
          path: '/api/other',
          auth: 'session',
          permission,
          action: 'audit-accept',
          summary: 'transplanted',
          handler: () => {},
        }),
      RouteError
    );
  }
});
