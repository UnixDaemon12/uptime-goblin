import test from 'node:test';
import assert from 'node:assert/strict';
import { fakeAudit } from '../helpers/fake-audit.mjs';
import { fakeIdentity } from '../helpers/fake-identity.mjs';
import { serveAuth, raw, login, browserWrite, password, basic } from './harness.mjs';
import { createAggregator } from '../../lib/audit/aggregate.mjs';
import { buildRow } from '../../lib/audit/writer.mjs';

for (const credential of ['interactive', 'kiosk', 'basic'])
  test(`permission denial is audited exactly once after CSRF: ${credential}`, async t => {
    const audit = fakeAudit(),
      identity = fakeIdentity({ password });
    if (credential === 'kiosk') {
      const authenticate = identity.authenticateSession.bind(identity);
      identity.authenticateSession = async (...args) => {
        const access = await authenticate(...args);
        return access ? { ...access, kind: 'kiosk' } : access;
      };
    }
    const { port } = await serveAuth(t, { identity, audit, permitted: () => false });
    const { cookie } = await login(port);
    const auth = credential === 'basic' ? `Authorization: ${basic()}` : `Cookie: ${cookie}`;
    const answer = await raw(
      port,
      [
        'POST /api/thing HTTP/1.1',
        auth,
        ...(credential === 'basic'
          ? ['Content-Type: application/json', 'X-Goblin-Request: 1']
          : browserWrite(`http://127.0.0.1:${port}`)),
      ],
      '{}'
    );
    assert.equal(answer.status, 403);
    assert.equal(answer.json.code, 'forbidden');
    const counted = () => audit.counts.filter(e => e.action === 'auth.forbidden');
    assert.equal(counted().length, 1);
    assert.equal(counted()[0].outcome, 'denied');
    assert.deepEqual(counted()[0].detail, { code: 'forbidden' });
    assert.equal(audit.rows.filter(e => e.action === 'auth.forbidden').length, 1);
    assert.equal(audit.unwritten.length, 0);
    const invalid = await raw(
      port,
      ['POST /api/thing HTTP/1.1', auth, 'Content-Type: application/json'],
      '{}'
    );
    assert.equal(invalid.status, 403);
    assert.equal(counted().length, 1, 'earlier CSRF refusal is not mislabelled permission denial');
    const unknown = await raw(port, ['GET /api/no-such-route HTTP/1.1', auth]);
    assert.equal(unknown.status, 404);
    assert.equal(counted().length, 1, 'unknown route is not an authorization refusal');
  });

test('permission refusal remains fail-closed when audit counting fails', async t => {
  const audit = fakeAudit();
  audit.count = () => {
    throw new Error('fixture audit unavailable');
  };
  const { port } = await serveAuth(t, { audit, permitted: () => false });
  const answer = await raw(port, ['GET /api/thing HTTP/1.1', `Authorization: ${basic()}`]);
  assert.equal(answer.status, 403);
});

test('real aggregator records authorization refusals with bounded rows and valid catalogue detail', async () => {
  const events = [];
  const aggregator = createAggregator({
    clock: () => 1,
    write: async event => {
      events.push(buildRow(event, () => 1));
      return true;
    },
    setTimer: () => 0,
    clearTimer: () => {},
  });
  for (let i = 0; i < 100; i++)
    aggregator.count({
      action: 'auth.forbidden',
      outcome: 'denied',
      actor: { type: 'user', id: 'u_admin', name: 'admin', via: 'session', sessionId: 's_fixture' },
      client: '192.0.2.3',
      detail: { code: 'forbidden' },
    });
  await aggregator.idle();
  await aggregator.flush({ force: true });
  await aggregator.idle();
  aggregator.stop();
  assert.equal(events.length, 2);
  assert.equal(
    events.reduce((n, e) => n + e.count, 0),
    100
  );
  assert.equal(events[0].action, 'auth.forbidden');
  assert.deepEqual(events[0].detail, { code: 'forbidden' });
});

test('real redeemed display denial records one authorization refusal, not a password-change refusal', async t => {
  const { startIdentity, temporary, adminPassword } = await import('../identity/helpers.mjs');
  const { identityOps } = await import('../../lib/repo/identity.mjs');
  const { newDisplayCode } = await import('../../lib/identity/secrets.mjs');
  const context = await startIdentity(t, temporary(t), { password: adminPassword });
  const code = newDisplayCode();
  await context.db.write(tx =>
    identityOps.insertDisplay(tx, {
      id: code.id,
      name: 'Fixture',
      codeHash: code.codeHash,
      codeExpiresAt: context.clock() + 600000,
      createdAt: context.clock(),
      createdBy: 'cli:test',
    })
  );
  const session = await context.identity.redeemDisplayCode({
    code: code.code,
    client: '192.0.2.3',
    transport: 'loopback',
  });
  const audit = fakeAudit();
  const { port } = await serveAuth(t, { identity: context.identity, audit });
  const answer = await raw(
    port,
    [
      'POST /api/account/password HTTP/1.1',
      `Cookie: goblin_session=${session.issue.value}`,
      ...browserWrite(`http://127.0.0.1:${port}`),
    ],
    '{}'
  );
  assert.equal(answer.status, 403);
  assert.equal(answer.json.code, 'forbidden');
  assert.equal(audit.counts.filter(e => e.action === 'auth.forbidden').length, 1);
  assert.equal(audit.counts.filter(e => e.action === 'account.password.changed').length, 0);
});
