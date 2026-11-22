import test from 'node:test';
import assert from 'node:assert/strict';
import { adminError } from '../../lib/admin/errors.mjs';
import { serveAuth, raw, basic } from './harness.mjs';

test('real HTTP adapter preserves bounded guard errors and retry metadata', async t => {
  const cases = [
    ['step_up_required', {}, 403],
    ['step_up_failed', {}, 403],
    ['step_up_unavailable', { variant: 'basic' }, 403],
    ['admin_ui_locked', { lock: 'audit-accept', deployment: { container: true } }, 403],
    ['admin_ui_locked', { lock: 'logging' }, 403],
    ['admin_busy', {}, 409],
  ];
  const routes = cases.map(([code, options], i) => ({
    method: 'GET',
    path: `/api/error-fixture-${i}`,
    auth: 'session',
    permission: 'dashboard:read',
    summary: 'Guard error fixture only',
    handler() {
      throw adminError(code, options);
    },
  }));
  const { port } = await serveAuth(t, { routes });
  for (const [i, [code, options, status]] of cases.entries()) {
    const answer = await raw(port, [
      `GET /api/error-fixture-${i} HTTP/1.1`,
      `Authorization: ${basic()}`,
    ]);
    assert.equal(answer.status, status);
    assert.deepEqual(answer.json, adminError(code, options).body);
    assert.equal(answer.headers['retry-after'], code === 'admin_busy' ? '5' : undefined);
    assert.equal(answer.headers['www-authenticate'], undefined);
  }
});
