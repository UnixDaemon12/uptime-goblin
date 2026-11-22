// The catalogue (lib/audit/actions.mjs §5.8) through the writer: every action is recorded once with
// every detail key it lists and the log verifies; an unknown detail key is refused for each; the
// actions the inbox may hold; and every action has its texts.
import test from 'node:test';
import assert from 'node:assert/strict';
import { ACTIONS, AUDIT_TEXTS } from '../../lib/audit/actions.mjs';
import { verifyAudit } from '../../lib/audit/verify.mjs';
import { auditFixture, storedRows } from './helpers.mjs';

// A plausible value for each detail key (plain data of the kind the catalogue describes).
const values = {
  persistent: true,
  transport: 'https',
  ended: 2,
  code: 'invalid_credentials',
  login: 'admin',
  codes: { invalid_credentials: 2 },
  clients: 2,
  more: false,
  sample: ['192.0.2.1', '192.0.2.2'],
  from: 1759490000000,
  to: 1759490001000,
  cause: 'signout',
  count: 3,
  displayCodes: 3,
  kept: 1,
  snapshot: 'manual-1.5.0-dev.2-20260920T081200Z',
  revokedOtherSessions: 2,
  newSessionId: 's_new',
  source: 'env',
  ifMatch: true,
  diff: [
    { path: 'email.host', from: 'a.example', to: 'b.example' },
    { path: 'email.password', change: 'changed' },
  ],
  truncated: true,
  changes: 9,
  credentialsCleared: false,
  historyDeleted: true,
  type: 'plex',
  savedCredentials: true,
  result: 'connected',
  accepted: true,
  retried: 1,
  added: 4,
  changed: 1,
  skipped: 2,
  released: 2,
  shown: true,
  replaced: false,
  reason: 'manual',
  transient: true,
  sources: 3,
  bytes: 2048,
  format: 'csv',
  rows: 10,
  filters: { from: null, actions: [{ name: 'session.', prefix: true }] },
  version: '1.5.0-dev.2',
  build: 'abc123',
  first: false,
  cleanStop: true,
  configRevision: 42,
  security: {
    legacyBasic: false,
    insecureHttpSessions: false,
    trustProxy: null,
    allowedHosts: [],
    webhook: true,
    keySource: 'file',
  },
  securityChanged: ['legacyBasic'],
  uptimeMs: 1000,
  release: '1.5.0-dev.2',
  entries: [{ from: '1.5.0-dev.1', to: '1.5.0-dev.2', at: 1 }],
  markerLost: false,
  at: 1759490000000,
  restoredHead: null,
  head: null,
  lastSeq: null,
  through: 10,
  deleted: 10,
  createdAt: 1759490000000,
  rewrapped: 4,
  purposes: ['audit'],
  retired: ['k1'],
  active: ['k2'],
  lostKeyIds: ['k0'],
  unused: false,
  repaired: true,
  kind: 'kiosk',
  display: 'd_AAAAAAAAAAAAAAAA',
  expiresAt: 1759490600000,
  late: true,
};

const eventOf = (action, detail) => ({
  action,
  outcome:
    ACTIONS[action].outcomes.find(outcome => outcome !== 'attempt') ?? ACTIONS[action].outcomes[0],
  target: { type: ACTIONS[action].targetType[0], id: 'x', name: null },
  detail,
});

test('every action is recorded once with every detail key it lists, and the log verifies', async t => {
  const { audit, db, keyring } = await auditFixture(t);
  for (const [action, entry] of Object.entries(ACTIONS)) {
    const detail = Object.fromEntries(
      entry.detail.map(key => [key, values[key] ?? `${key}-value`])
    );
    for (const key of entry.detail) assert.ok(Object.hasOwn(values, key), `a value for ${key}`);
    await audit.append(eventOf(action, Object.keys(detail).length ? detail : null));
  }
  const rows = await storedRows(db);
  assert.equal(rows.length, Object.keys(ACTIONS).length);
  assert.equal(
    rows.length,
    49,
    '42 base actions, 2 display-code actions, auth.forbidden, auth.step-up and the ntfy and Gotify settings and test, and sources.import'
  );
  for (const row of rows) {
    const listed = ACTIONS[row.action].detail;
    const stored = Object.keys(row.detail ?? {});
    // The writer completes restoredHead and head of its own anchors; every other key is kept.
    assert.deepEqual(stored.sort(), [...listed].sort(), row.action);
  }
  assert.equal((await verifyAudit(db, { keyring })).result, 'intact');
});

test('an unknown detail key is refused for every action', async t => {
  const { audit, db } = await auditFixture(t);
  for (const action of Object.keys(ACTIONS))
    await assert.rejects(
      audit.append(eventOf(action, { notInTheCatalogue: 1 })),
      error => error.code === 'audit_unavailable' && /notInTheCatalogue/.test(error.cause.message),
      action
    );
  assert.deepEqual(await storedRows(db), []);
});

test('the inbox flags: only what identity and the start record before a keyring exists', () => {
  assert.deepEqual(
    Object.entries(ACTIONS)
      .filter(([, entry]) => entry.inbox)
      .map(([action]) => action)
      .sort(),
    [
      'account.bootstrap',
      'account.claimed',
      'account.password.changed-outside',
      'identity.mirror.failed',
      'session.revoked',
      'session.revoked-restore',
      'system.restore',
    ]
  );
});

test('every action has its texts', () => {
  for (const action of Object.keys(ACTIONS)) assert.ok(AUDIT_TEXTS[action], action);
  assert.deepEqual(Object.keys(AUDIT_TEXTS).sort(), Object.keys(ACTIONS).sort());
});
