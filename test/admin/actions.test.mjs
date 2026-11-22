import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ADMIN_ACTIONS,
  adminRoute,
  adminPreviewRoute,
  ALL_LOCKS,
  LOCK_NAMES,
} from '../../lib/admin/actions.mjs';
import { supportedFeatures } from '../../lib/http/routes.mjs';

test('canonical17 actions pin exact route, permission, step-up and lock metadata', () => {
  assert.deepEqual(
    ADMIN_ACTIONS.map(a => [
      a.name,
      a.route.method,
      a.route.path,
      a.permission,
      a.stepUp,
      a.lock,
      a.audit,
      a.offline,
    ]),
    [
      ['status', 'GET', '/api/admin/status', 'system:read', false, null, 'none', false],
      ['snapshots', 'GET', '/api/admin/snapshots', 'system:read', false, null, 'none', false],
      [
        'snapshot-create',
        'POST',
        '/api/admin/snapshots',
        'backup:manage',
        true,
        null,
        'admin',
        false,
      ],
      [
        'snapshot-delete',
        'POST',
        '/api/admin/snapshots/delete',
        'backup:manage',
        true,
        'snapshot-delete',
        'admin',
        true,
      ],
      ['check-data', 'GET', '/api/admin/check-data', 'system:read', false, null, 'none', false],
      ['keys', 'GET', '/api/admin/keys', 'system:read', false, null, 'none', false],
      [
        'key-remove-data-copy',
        'POST',
        '/api/admin/keys/remove-data-copy',
        'keys:manage',
        true,
        'key-remove-data-copy',
        'admin',
        false,
      ],
      ['verify-audit', 'GET', '/api/audit/verify', 'audit:read', false, null, 'none', false],
      [
        'audit-accept',
        'POST',
        '/api/audit/accept',
        'audit:manage',
        true,
        'audit-accept',
        'admin',
        true,
      ],
      [
        'token-create',
        'POST',
        '/api/tokens',
        'tokens:manage',
        true,
        'token-create',
        'identity',
        false,
      ],
      ['tokens', 'GET', '/api/tokens', 'tokens:manage', false, null, 'none', false],
      [
        'token-revoke',
        'DELETE',
        '/api/tokens/:id',
        'tokens:manage',
        false,
        'token-revoke',
        'identity',
        false,
      ],
      [
        'token-revoke-all',
        'DELETE',
        '/api/tokens',
        'tokens:manage',
        false,
        'token-revoke-all',
        'identity',
        false,
      ],
      [
        'display-code',
        'POST',
        '/api/displays/codes',
        'kiosk:manage',
        true,
        'display-code',
        'identity',
        false,
      ],
      ['display-codes', 'GET', '/api/displays/codes', 'kiosk:manage', false, null, 'none', false],
      [
        'display-cancel',
        'DELETE',
        '/api/displays/codes/:id',
        'kiosk:manage',
        false,
        'display-cancel',
        'identity',
        false,
      ],
      [
        'display-cancel-all',
        'DELETE',
        '/api/displays/codes',
        'kiosk:manage',
        false,
        'display-cancel-all',
        'identity',
        false,
      ],
    ]
  );
  assert.equal(LOCK_NAMES.length, 10);
  assert.equal(ALL_LOCKS.length, 9);
  assert.equal(ALL_LOCKS.includes('logging'), false);
  assert.deepEqual(supportedFeatures, [], 'metadata does not advertise nonexistent enforcement');
});

test('all helpers and nested registry metadata are immutable and reject unknown action names', () => {
  for (const a of ADMIN_ACTIONS) {
    const keys = adminRoute(a.name);
    assert.deepEqual(keys, {
      permission: a.permission,
      stepUp: a.stepUp,
      lock: a.lock,
      audit: a.audit,
      action: a.name,
    });
    assert.throws(() => {
      a.route.method = 'GET';
    }, TypeError);
    assert.throws(() => a.command.push('unexpected'), TypeError);
    assert.throws(() => {
      keys.stepUp = false;
    }, TypeError);
  }
  assert.throws(() => adminRoute('__proto__'), TypeError);
  assert.throws(() => adminRoute('unknown'), TypeError);
  assert.throws(() => ADMIN_ACTIONS.pop(), TypeError);
});

test('audit preview derives explicit read-only metadata without weakening canonical POST', () => {
  const before = adminRoute('audit-accept');
  assert.deepEqual(adminPreviewRoute('audit-accept'), {
    permission: 'audit:manage',
    stepUp: false,
    lock: null,
    audit: 'none',
    action: 'audit-accept',
  });
  assert.deepEqual(adminRoute('audit-accept'), before);
  assert.equal(before.stepUp, true);
  assert.equal(before.lock, 'audit-accept');
  assert.equal(before.audit, 'admin');
  assert.equal(ADMIN_ACTIONS.find(a => a.name === 'audit-accept').route.method, 'POST');
  assert.throws(() => adminPreviewRoute('display-code'), TypeError);
  assert.throws(() => {
    adminPreviewRoute('audit-accept').audit = 'admin';
  }, TypeError);
});

test('B6 host commands remain exact static argument templates and online recovery is retained', () => {
  const entries = Object.fromEntries(ADMIN_ACTIONS.map(a => [a.name, a]));
  assert.deepEqual(entries['display-code'].command, ['display', 'code', '--name', '<name>']);
  assert.deepEqual(entries['display-cancel'].command, ['display', 'cancel', '<id>']);
  assert.deepEqual(entries['display-cancel-all'].command, ['display', 'cancel', '--all']);
  assert.deepEqual(entries['token-create'].command, ['token', 'create', '--name', '<name>']);
  assert.deepEqual(entries['token-revoke-all'].command, ['token', 'revoke', '--all']);
  for (const name of [
    'tokens',
    'token-create',
    'token-revoke',
    'token-revoke-all',
    'display-code',
    'display-codes',
    'display-cancel',
    'display-cancel-all',
  ])
    assert.equal(entries[name].offline, false);
});
