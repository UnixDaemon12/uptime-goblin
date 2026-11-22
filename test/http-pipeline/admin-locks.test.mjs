import test from 'node:test';
import assert from 'node:assert/strict';
import { serveAuth, raw, login, browserWrite, basic } from './harness.mjs';
import { createRouter, RouteError } from '../../lib/http/router.mjs';
import { fakeAudit } from '../helpers/fake-audit.mjs';
import { json } from '../../lib/http/body.mjs';
import { createAggregator } from '../../lib/audit/aggregate.mjs';
import { buildRow } from '../../lib/audit/writer.mjs';

const fixture = handler => ({
  method: 'POST',
  path: '/api/lock-fixture',
  auth: 'session',
  permission: 'settings:write',
  summary: 'Lock fixture',
  lock: 'logging',
  ifMatch: 'required',
  handler,
});

test('unknown, public, read and unsupported lock declarations refuse router startup', () => {
  const route = fixture(() => {});
  assert.throws(() => createRouter([route]), RouteError);
  for (const override of [
    { lock: 'unknown' },
    { auth: 'public', permission: null },
    { method: 'GET' },
  ])
    assert.throws(
      () => createRouter([{ ...route, ...override }], { supports: ['lock'] }),
      RouteError
    );
  assert.doesNotThrow(() => createRouter([route], { supports: ['lock'] }));
});

for (const mode of ['interactive', 'basic'])
  test(`lock after permission/CSRF, before replay/If-Match/body: ${mode}`, async t => {
    const audit = fakeAudit();
    let handled = 0,
      replayed = 0;
    const route = fixture(async ({ res, body }) => {
      handled++;
      json(res, 200, await body());
    });
    const { port } = await serveAuth(t, {
      audit,
      routes: [route],
      supports: ['lock'],
      adminUiLock: 'logging',
      idempotency: async () => {
        replayed++;
      },
      adminDeployment: { container: true },
    });
    const { cookie } = await login(port);
    const auth = mode === 'basic' ? `Authorization: ${basic()}` : `Cookie: ${cookie}`;
    const headers =
      mode === 'basic'
        ? ['Content-Type: application/json', 'X-Goblin-Request: 1']
        : browserWrite(`http://127.0.0.1:${port}`);
    const answer = await raw(
      port,
      ['POST /api/lock-fixture HTTP/1.1', auth, ...headers, 'Idempotency-Key: fixture'],
      '{bad'
    );
    assert.equal(answer.status, 403);
    assert.equal(answer.json.code, 'admin_ui_locked');
    assert.equal(answer.json.command, null);
    assert.equal(handled, 0);
    assert.equal(replayed, 0);
    assert.equal(audit.counts.filter(e => e.action === 'auth.step-up').length, 1);
    const cross = await raw(
      port,
      ['POST /api/lock-fixture HTTP/1.1', auth, 'Content-Type: application/json'],
      '{bad'
    );
    assert.equal(cross.json.code, 'cross_origin');
    assert.equal(audit.counts.filter(e => e.action === 'auth.step-up').length, 1);
  });

test('permission refusal precedes lock and is counted under authorization only', async t => {
  const audit = fakeAudit();
  const { port } = await serveAuth(t, {
    audit,
    routes: [fixture(() => assert.fail())],
    supports: ['lock'],
    adminUiLock: 'logging',
    permitted: () => false,
  });
  const answer = await raw(
    port,
    [
      'POST /api/lock-fixture HTTP/1.1',
      `Authorization: ${basic()}`,
      'Content-Type: application/json',
      'X-Goblin-Request: 1',
    ],
    '{}'
  );
  assert.equal(answer.json.code, 'forbidden');
  assert.equal(audit.counts.filter(e => e.action === 'auth.step-up').length, 0);
  assert.equal(audit.counts.filter(e => e.action === 'auth.forbidden').length, 1);
});

test('literal all excludes logging; invalid configuration locks it; unlocked read remains usable', async t => {
  for (const [setting, locked] of [
    ['all', false],
    ['none', false],
    ['typo', true],
  ]) {
    const { port } = await serveAuth(t, {
      routes: [fixture(() => assert.fail('If-Match must stop first'))],
      supports: ['lock'],
      adminUiLock: setting,
    });
    const answer = await raw(
      port,
      [
        'POST /api/lock-fixture HTTP/1.1',
        `Authorization: ${basic()}`,
        'Content-Type: application/json',
        'X-Goblin-Request: 1',
      ],
      '{}'
    );
    assert.equal(answer.json.code, locked ? 'admin_ui_locked' : 'if_match_required');
    assert.equal(
      (await raw(port, ['GET /api/thing HTTP/1.1', `Authorization: ${basic()}`])).status,
      200
    );
  }
});

test('real step-up aggregation preserves first code and bounds repeated refusal rows', async () => {
  const rows = [];
  const aggregate = createAggregator({
    clock: () => 1,
    write: async event => {
      rows.push(buildRow(event, () => 1));
      return true;
    },
  });
  for (let i = 0; i < 100; i++)
    aggregate.count({
      action: 'auth.step-up',
      outcome: 'denied',
      actor: { type: 'user', id: 'u_admin', name: 'admin', via: 'session', sessionId: 's_fixture' },
      client: '192.0.2.1',
      detail: { code: 'admin_ui_locked' },
    });
  await aggregate.idle();
  await aggregate.flush({ force: true });
  await aggregate.idle();
  aggregate.stop();
  assert.equal(rows.length, 2);
  assert.equal(rows[0].detail.code, 'admin_ui_locked');
});
