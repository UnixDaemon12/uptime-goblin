// The real service's answers against test/contract/audit-bodies.json (audit spec §6.6): lane H's
// routes and lane U's page are built against these shapes through fakeAudit, so audit.list,
// audit.export and audit.verify must give exactly them on prepared databases.
import test from 'node:test';
import assert from 'node:assert/strict';
import { sql } from '../../lib/db/sql.mjs';
import { auditOps } from '../../lib/repo/audit.mjs';
import { verifyAudit } from '../../lib/audit/verify.mjs';
import { checkpointMac, GENESIS } from '../../lib/audit/chain.mjs';
import { createAudit } from '../../lib/audit/index.mjs';
import { recordWith } from '../../lib/audit/writer.mjs';
import { parseAuditQuery } from '../../lib/audit/view.mjs';
import { Keyring } from '../../lib/keyring.mjs';
import { bodyMismatches } from '../helpers/fake-audit.mjs';
import { auditFixture, keyA, keyB, storedRows } from './helpers.mjs';

const firefox = 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0';
const sessionActor = {
  type: 'user',
  id: 'u_admin',
  name: 'admin',
  via: 'session',
  sessionId: 's_a1b2c3',
};
const request = (overrides = {}) => ({
  requestId: 'req-0001',
  route: 'PATCH /api/settings',
  client: '192.0.2.10',
  userAgent: firefox,
  actor: sessionActor,
  ...overrides,
});
const matches = (actual, name) => assert.deepEqual(bodyMismatches(actual, name), [], name);
const stop = n => ({ action: 'system.stop', outcome: 'info', detail: { uptimeMs: n } });
const list = (audit, text = '') => audit.list(parseAuditQuery(new URLSearchParams(text), 'list'));
const seqIs = seq => sql`${sql.id('seq')} = ${seq}`;
async function logOf(t, n, options = {}) {
  const fixture = await auditFixture(t, options);
  for (let i = 1; i <= n; i++) {
    await fixture.audit.append(stop(i));
    fixture.clock.advance(1000);
  }
  return fixture;
}
const check = (fixture, options = {}) =>
  verifyAudit(fixture.db, { keyring: fixture.keyring, ...options });
const signed = (fixture, fields) => {
  const line = {
    instance: 'i',
    reason: 'commit',
    key_id: fixture.keyring.activeKid('audit'),
    ...fields,
  };
  const mac = checkpointMac(data => fixture.keyring.hmac('audit', data, line.key_id).mac, line);
  return JSON.stringify({ orbit: 'audit.checkpoint', v: 1, ...line, mac });
};

test('list.empty, list.entries, list.more and list.unwritten', async t => {
  const empty = await auditFixture(t);
  matches(await list(empty.audit), 'list.empty');

  const { audit, db, clock } = await auditFixture(t);
  const tick = () => clock.advance(1000);
  await audit.append({
    action: 'session.login',
    outcome: 'ok',
    actor: sessionActor,
    client: '192.0.2.10',
    userAgent: firefox,
    requestId: 'req-0000',
    target: { type: 'session', id: 's_a1b2c3', name: null },
    detail: { persistent: false, transport: 'https', ended: 0 },
  });
  tick();
  const settings = await audit.begin(request(), {
    action: 'settings.update',
    target: { type: 'settings', id: 'workspace', name: null },
    detail: { ifMatch: true },
    configRevision: 41,
  });
  settings.note({
    detail: {
      diff: [
        { path: 'email.host', from: 'smtp.example.com', to: 'mail.example.com' },
        { path: 'email.password', change: 'changed' },
      ],
      truncated: true,
      changes: 41,
    },
  });
  await settings.end({ status: 200, outcome: 'ok' });
  tick();
  const basic = request({
    userAgent: 'python-requests/2.32.3',
    actor: { type: 'user', id: 'u_admin', name: 'admin', via: 'basic', sessionId: null },
  });
  const retry = await audit.begin(basic, {
    action: 'delivery.retry',
    target: { type: 'delivery', id: 'd_77', name: null },
  });
  await retry.end({ status: 409, outcome: 'denied', code: 'delivery_not_retryable' });
  tick();
  const source = await audit.begin(request(), {
    action: 'source.update',
    target: { type: 'source', id: 'website-2', name: 'Blog' },
    detail: { ifMatch: true },
    configRevision: 41,
  });
  await source.end({ status: 409, outcome: 'conflict' });
  tick();
  await audit.append({
    action: 'settings.update',
    outcome: 'attempt',
    actor: sessionActor,
    client: '192.0.2.10',
    userAgent: firefox,
    requestId: 'req-0009',
    target: { type: 'settings', id: 'workspace', name: null },
    configRevision: 41,
    detail: { ifMatch: true },
  });
  tick();
  const reveal = await audit.begin(request(), {
    action: 'signing.reveal',
    target: { type: 'secret', id: 'env-webhook', name: null },
  });
  tick();
  await audit.append({
    action: 'session.login',
    outcome: 'failed',
    actor: { type: 'anonymous', id: null, name: null, via: null, sessionId: null },
    client: '192.0.2.20',
    userAgent: 'curl/8.5.0',
    target: { type: 'account', id: 'admin', name: null },
    detail: { code: 'invalid_credentials', login: 'admin' },
  });
  tick();
  await audit.append({
    action: 'session.login',
    outcome: 'failed',
    count: 7,
    actor: { type: 'anonymous', id: null, name: null, via: null, sessionId: null },
    target: { type: 'account', id: null, name: null },
    detail: {
      codes: { invalid_credentials: 6, locked: 1 },
      clients: 3,
      more: false,
      sample: ['192.0.2.20', '192.0.2.21', '198.51.100.7'],
      from: clock() - 5000,
      to: clock(),
    },
  });
  tick();
  const test = audit.operation(request(), {
    action: 'source.test',
    target: { type: 'source', id: 'plex-1', name: 'Plex' },
    detail: { type: 'plex', savedCredentials: true },
  });
  test.note({ outcome: 'ok', detail: { result: 'connected', credentialsCleared: false } });
  await test.end({ status: 200 });
  tick();
  await audit.append({
    action: 'system.start',
    outcome: 'info',
    target: { type: 'orbit', id: null, name: null },
    configRevision: 42,
    detail: {
      version: '1.5.0-dev.2',
      build: 'abc123',
      first: false,
      cleanStop: true,
      configRevision: 42,
      security: {
        legacyBasic: true,
        insecureHttpSessions: false,
        trustProxy: null,
        allowedHosts: [],
        webhook: true,
        keySource: 'file',
      },
      securityChanged: ['legacyBasic'],
    },
  });
  tick();
  // A row a later release wrote: its action is not in this release's catalogue.
  await db.write(tx => {
    const last = auditOps.last(tx);
    auditOps.insertRow(tx, {
      seq: last.seq + 1,
      v: 1,
      time: clock(),
      ref: null,
      actor_type: 'user',
      actor_id: 'u_admin',
      actor_name: 'admin',
      via: 'session',
      session_id: 's_a1b2c3',
      client_key: '192.0.2.10',
      user_agent: firefox,
      request_id: 'req-0099',
      action: 'users.created',
      target_type: 'user',
      target_id: 'u_viewer',
      target_name: 'viewer',
      outcome: 'ok',
      status: 201,
      count: 1,
      detail: { role: 'viewer' },
      detailText: '{"role":"viewer"}',
      config_revision: null,
      key_id: 'k-later',
      prev_hash: last.hash,
      hash: 'f'.repeat(64),
    });
  });
  matches(await list(audit), 'list.entries');
  await reveal.end({ status: 200, outcome: 'ok' });

  const more = await auditFixture(t);
  for (let n = 0; n < 118; n++) await more.audit.append(stop(n));
  await more.audit.single(request(), {
    action: 'config.export',
    target: { type: 'config', id: null, name: null },
    detail: { sources: 3, bytes: 2048 },
  });
  await more.audit.append({
    action: 'session.logout',
    outcome: 'ok',
    actor: sessionActor,
    client: '192.0.2.10',
    userAgent: firefox,
    requestId: 'req-0100',
    target: { type: 'session', id: 's_a1b2c3', name: null },
    detail: { cause: 'signout' },
  });
  matches(await list(more.audit, 'limit=2'), 'list.more');

  const failing = await auditFixture(t, {
    wrapDb: (target, purpose) =>
      purpose === 'result'
        ? {
            read: (...args) => target.read(...args),
            write: async () => {
              throw Object.assign(new Error('full'), { class: 'full' });
            },
          }
        : target,
  });
  const lost = await failing.audit.begin(request(), {
    action: 'settings.update',
    target: { type: 'settings', id: 'workspace', name: null },
    detail: { ifMatch: false },
    configRevision: 42,
  });
  await lost.end({ status: 200, outcome: 'ok' });
  matches(await list(failing.audit), 'list.unwritten');
});

test('export.csv and export.ndjson', async t => {
  const { audit, clock } = await auditFixture(t);
  await audit.append({
    action: 'session.login',
    outcome: 'ok',
    actor: sessionActor,
    client: '192.0.2.10',
    userAgent: firefox,
    requestId: 'req-0000',
    target: { type: 'session', id: 's_a1b2c3', name: null },
    detail: { persistent: false, transport: 'https', ended: 0 },
  });
  clock.advance(1000);
  const create = await audit.begin(request(), {
    action: 'source.create',
    target: { type: 'source', id: null, name: '=SUM(A1:A2)' },
    detail: { ifMatch: false },
  });
  create.note({
    target: { type: 'source', id: 'website-3', name: '=SUM(A1:A2)' },
    configRevision: 43,
  });
  await create.end({ status: 201, outcome: 'ok' });
  for (const format of ['csv', 'ndjson']) {
    const query = parseAuditQuery(new URLSearchParams(`format=${format}&outcome=ok`), 'export');
    const result = await audit.export(query, format);
    matches(
      {
        status: 200,
        headers: {
          'content-type': result.contentType,
          'content-disposition': `attachment; filename="${result.filename}"`,
          'x-goblin-export-rows': String(result.rows),
          'x-goblin-export-more': String(result.more),
          'cache-control': 'no-store',
        },
        body: result.body.toString('utf8'),
        rows: result.rows,
        more: result.more,
        filename: result.filename,
        contentType: result.contentType,
      },
      `export.${format}`
    );
  }
});

test('verify.empty, verify.intact, and verify.anchors (one anchor of each kind, intact)', async t => {
  matches(await check(await auditFixture(t)), 'verify.empty');
  const intact = await logOf(t, 13);
  const [row] = await storedRows(intact.db);
  const kid = intact.keyring.activeKid('audit');
  const checkpoint = { seq: 1, time: row.time, hash: row.hash, key_id: kid, reason: 'prune' };
  const instance = await intact.control.meta.instanceId();
  await intact.db.write(tx => {
    auditOps.insertCheckpoint(tx, {
      ...checkpoint,
      mac: checkpointMac(data => intact.keyring.hmac('audit', data, kid).mac, {
        ...checkpoint,
        instance,
      }),
    });
    tx.run(tx.dialect.deleteFrom('audit_log', seqIs(1)));
  });
  matches(await check(intact), 'verify.intact');

  // A lost-key reset of an empty log is the first row; then every other anchor.
  const f = await auditFixture(t, { attach: false });
  const lost = (await f.control.keyringStore.list())
    .filter(r => r.purpose === 'audit')
    .map(r => r.kid);
  const { keyring } = await Keyring.reset(f.control.keyringStore, {
    key: keyB,
    confirmLostKey: true,
    inUnit: (tx, signer) =>
      recordWith(
        tx,
        signer,
        {
          action: 'key.reset',
          outcome: 'ok',
          actor: { type: 'cli', id: null, name: 'cli:dana', via: 'cli', sessionId: null },
          target: { type: 'keyring', id: null, name: null },
          detail: { lostKeyIds: lost },
        },
        { clock: f.clock }
      ),
  });
  const audit = createAudit({ db: f.db, clock: f.clock, out() {}, err() {} });
  t.after(() => audit.close());
  await audit.attach({ keyring, instanceId: 'i' });
  const upgrade = (entries, markerLost) => ({
    action: 'system.upgrade',
    outcome: 'info',
    target: { type: 'orbit', id: null, name: null },
    detail: { release: '1.5.0-dev.2', entries, markerLost },
  });
  await audit.append(
    upgrade(
      [
        { from: '1.5.0-dev.0', to: '1.5.0-dev.1', at: 1 },
        { from: '1.5.0-dev.1', to: '1.5.0-dev.2', at: 2 },
      ],
      true
    )
  );
  await audit.append({
    action: 'audit.gap',
    outcome: 'info',
    target: { type: 'audit', id: null, name: null },
    detail: { reason: 'inbox-discarded', count: 2 },
  });
  for (let n = 0; n < 10; n++) await audit.append(stop(n));
  await f.db.write(tx =>
    auditOps.setMeta(
      tx,
      'restored',
      JSON.stringify({ snapshot: 'manual-1.5.0-dev.2-20260920T081200Z', at: 1758355920000 }),
      1
    )
  );
  const restarted = createAudit({ db: f.db, clock: f.clock, out() {}, err() {} });
  t.after(() => restarted.close());
  await restarted.attach({ keyring, instanceId: 'i' });
  await restarted.append(stop(99)); // the anchor, then this row
  await restarted.append(
    upgrade(
      [
        { from: '1.5.0-dev.2', to: '1.5.0-dev.1', at: 3 },
        { from: '1.5.0-dev.1', to: '1.5.0-dev.2', at: 4 },
      ],
      false
    )
  );
  await f.db.write(tx =>
    restarted.record(tx, {
      action: 'system.restore',
      outcome: 'info',
      target: { type: 'orbit', id: null, name: null },
      detail: { cause: 'control_file' },
    })
  );
  while ((await storedRows(f.db)).length < 40) await restarted.append(stop(1));
  matches(await verifyAudit(f.db, { keyring }), 'verify.anchors');
});

test('verify.incomplete: key_reset, newer_format, restore_unchecked (with the journal), no_key', async t => {
  const reset = await logOf(t, 5);
  const lost = (await reset.control.keyringStore.list())
    .filter(r => r.purpose === 'audit')
    .map(r => r.kid);
  const { keyring } = await Keyring.reset(reset.control.keyringStore, {
    key: keyB,
    confirmLostKey: true,
    inUnit: (tx, signer) =>
      recordWith(
        tx,
        signer,
        {
          action: 'key.reset',
          outcome: 'ok',
          actor: { type: 'cli', id: null, name: 'cli:dana', via: 'cli', sessionId: null },
          target: { type: 'keyring', id: null, name: null },
          detail: { lostKeyIds: lost },
        },
        { clock: reset.clock }
      ),
  });
  const after = createAudit({ db: reset.db, clock: reset.clock, out() {}, err() {} });
  t.after(() => after.close());
  await after.attach({ keyring, instanceId: 'i' });
  for (let n = 0; n < 6; n++) await after.append(stop(n));
  matches(await verifyAudit(reset.db, { keyring }), 'verify.incomplete.key_reset');

  const newer = await logOf(t, 12);
  await newer.db.write(tx => tx.run(tx.dialect.update('audit_log', { v: 2 }, seqIs(5))));
  matches(await check(newer), 'verify.incomplete.newer_format');

  const restore = await logOf(t, 8);
  const rows = await storedRows(restore.db);
  const before = restore.out.join('\n');
  await restore.db.write(tx => {
    tx.run(tx.dialect.deleteFrom('audit_log', sql`${sql.id('seq')} > ${5}`));
    auditOps.setHead(tx, { seq: 5, hash: rows[4].hash, key_id: rows[4].key_id, updated_at: 1 });
    auditOps.setMeta(
      tx,
      'restored',
      JSON.stringify({ snapshot: 'manual-1.5.0-dev.2-20260920T081200Z', at: restore.clock() }),
      1
    );
  });
  restore.clock.advance(60000);
  const lines = [];
  const restarted = createAudit({
    db: restore.db,
    clock: restore.clock,
    out: line => lines.push(line),
    err() {},
  });
  t.after(() => restarted.close());
  await restarted.attach({ keyring: restore.keyring, instanceId: 'i' });
  await restarted.append(stop(7));
  const firstAfter = lines.find(line => line.includes('audit.checkpoint'));
  for (let n = 0; n < 5; n++) await restarted.append(stop(n));
  matches(
    await check(restore, { journal: `${before}\n${firstAfter}`, oneUnit: true }),
    'verify.incomplete.restore_unchecked'
  );

  const nokey = await logOf(t, 12);
  matches(await verifyAudit(nokey.db, { keyring: null }), 'verify.incomplete.no_key');
});

// Integration: unknown_key, the journal lines under a key the keyring does not hold and no reset
// removed (the CLI's JSON): here a rotated audit key deleted with the entries it signed.
test('verify.incomplete.unknown_key (with the journal)', async t => {
  const f = await logOf(t, 12);
  const older = f.keyring.activeKid('audit');
  await f.keyring.rotate({ purposes: ['audit'] });
  const rotated = f.keyring.activeKid('audit');
  for (let n = 0; n < 3; n++) await f.audit.append(stop(n));
  const journal = f.out.join('\n');
  await f.db.write(tx =>
    tx.run(tx.dialect.deleteFrom('audit_log', sql`${sql.id('key_id')} = ${rotated}`))
  );
  const last = (await storedRows(f.db)).at(-1);
  await f.db.write(tx => {
    auditOps.setHead(tx, { seq: last.seq, hash: last.hash, key_id: older, updated_at: 1 });
    tx.run(tx.dialect.deleteFrom('keyring', sql`${sql.id('kid')} = ${rotated}`));
    tx.run(tx.dialect.update('keyring', { retired_at: null }, sql`${sql.id('kid')} = ${older}`));
  });
  const keyring = await Keyring.open(f.control.keyringStore, { key: keyA, create: false });
  matches(
    await verifyAudit(f.db, { keyring, journal, oneUnit: true }),
    'verify.incomplete.unknown_key'
  );
});

test('verify.broken: each of the 12 codes', async t => {
  const cases = {
    start_missing: async () => {
      const f = await logOf(t, 13);
      await f.db.write(tx => tx.run(tx.dialect.deleteFrom('audit_log', seqIs(1))));
      return check(f);
    },
    link_broken: async () => {
      const f = await logOf(t, 12);
      await f.db.write(tx => {
        tx.run(tx.dialect.update('audit_log', { seq: 100 }, seqIs(5)));
        tx.run(tx.dialect.update('audit_log', { seq: 5 }, seqIs(6)));
        tx.run(tx.dialect.update('audit_log', { seq: 6 }, seqIs(100)));
      });
      return check(f);
    },
    seq_gap: async () => {
      const f = await logOf(t, 13);
      await f.db.write(tx => tx.run(tx.dialect.deleteFrom('audit_log', seqIs(7))));
      return check(f);
    },
    hash_mismatch: async () => {
      const f = await logOf(t, 12);
      await f.db.write(tx =>
        tx.run(tx.dialect.update('audit_log', { detail: '{"uptimeMs":0}' }, seqIs(4)))
      );
      return check(f);
    },
    head_mismatch: async () => {
      const f = await logOf(t, 13);
      await f.db.write(tx => tx.run(tx.dialect.deleteFrom('audit_log', seqIs(13))));
      return check(f);
    },
    checkpoint_mismatch: async () => {
      const f = await logOf(t, 12);
      const row = (await storedRows(f.db))[4];
      const kid = f.keyring.activeKid('audit');
      const checkpoint = { seq: 5, time: row.time, hash: GENESIS, key_id: kid, reason: 'prune' };
      const instance = await f.control.meta.instanceId();
      await f.db.write(tx =>
        auditOps.insertCheckpoint(tx, {
          ...checkpoint,
          mac: checkpointMac(data => f.keyring.hmac('audit', data, kid).mac, {
            ...checkpoint,
            instance,
          }),
        })
      );
      return check(f);
    },
    checkpoint_mac: async () => {
      const f = await logOf(t, 12);
      const row = (await storedRows(f.db))[4];
      await f.db.write(tx =>
        auditOps.insertCheckpoint(tx, {
          seq: 5,
          time: row.time,
          hash: row.hash,
          key_id: f.keyring.activeKid('audit'),
          reason: 'prune',
          mac: 'a'.repeat(64),
        })
      );
      return check(f);
    },
    journal_mismatch: async () => {
      const f = await logOf(t, 12);
      const lines = f.out.filter(line => line.includes('audit.checkpoint')).slice(0, 8);
      return check(f, {
        journal: [...lines, signed(f, { seq: 10, time: 5, hash: GENESIS })].join('\n'),
      });
    },
    journal_ahead: async () => {
      const f = await logOf(t, 12);
      const lines = f.out.filter(line => line.includes('audit.checkpoint')).slice(0, 8);
      return check(f, {
        journal: [...lines, signed(f, { seq: 13, time: 5, hash: GENESIS })].join('\n'),
      });
    },
    log_truncated: async () => {
      const f = await logOf(t, 10);
      await f.db.write(tx =>
        auditOps.setHead(tx, { seq: 15, hash: 'b'.repeat(64), key_id: 'k', updated_at: 1 })
      );
      await f.audit.append(stop(11));
      return check(f);
    },
    key_lost: async () => {
      const f = await logOf(t, 12);
      await f.db.write(tx =>
        tx.run(tx.dialect.update('audit_log', { key_id: 'madeup123456' }, seqIs(3)))
      );
      return check(f);
    },
    unreadable: async () => {
      const f = await logOf(t, 12);
      await f.db.write(tx =>
        tx.run(tx.dialect.update('audit_log', { time: 2n ** 53n + 1n }, seqIs(6)))
      );
      return check(f, { chunk: 5 });
    },
  };
  for (const [code, run] of Object.entries(cases)) {
    const result = await run();
    assert.equal(result.problem?.code, code, JSON.stringify(result.problem));
    matches(result, `verify.broken.${code}`);
  }
});
