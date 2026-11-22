// Reading the log for people (lib/audit/view.mjs, audit spec §6.2, §6.3, D19): the query rules
// and their texts, the list's hiding of attempts that have a result, "in progress" against
// "outcome unknown", paging, retention, and the answers when the log cannot be read.
import test from 'node:test';
import assert from 'node:assert/strict';
import { sql } from '../../lib/db/sql.mjs';
import { auditOps } from '../../lib/repo/audit.mjs';
import { parseAuditQuery } from '../../lib/audit/view.mjs';
import { createAudit } from '../../lib/audit/index.mjs';
import { auditBody } from '../helpers/fake-audit.mjs';
import { adminRequest, auditFixture } from './helpers.mjs';

const parse = (text, kind = 'list') => parseAuditQuery(new URLSearchParams(text), kind);
const refused = (text, kind = 'list') => {
  try {
    parse(text, kind);
  } catch (error) {
    return { status: error.status, headers: {}, body: error.body };
  }
  return null;
};

test('parseAuditQuery: every value of every parameter, the defaults, and unknown names ignored', () => {
  assert.deepEqual(parse(''), {
    from: null,
    to: null,
    actor: null,
    actions: null,
    target: null,
    outcome: null,
    limit: 50,
    cursor: null,
    format: null,
  });
  assert.deepEqual(
    parse(
      'from=1&to=1759490000000&actor=cli&action=session.,settings.update&target=source:plex-1&outcome=unknown&limit=500&cursor=1180&other=x&format=csv'
    ),
    {
      from: 1,
      to: 1759490000000,
      actor: { type: 'cli' },
      actions: [
        { name: 'session.', prefix: true },
        { name: 'settings.update', prefix: false },
      ],
      target: { type: 'source', id: 'plex-1' },
      outcome: 'unknown',
      limit: 500,
      cursor: 1180,
      format: null,
    }
  );
  assert.deepEqual(parse('actor=cli:dana (sudo as orbit)').actor, {
    name: 'cli:dana (sudo as orbit)',
  });
  assert.deepEqual(parse('target=session').target, { type: 'session', id: null });
  assert.deepEqual(parse('format=ndjson&limit=9999&cursor=x', 'export'), {
    from: null,
    to: null,
    actor: null,
    actions: null,
    target: null,
    outcome: null,
    limit: null,
    cursor: null,
    format: 'ndjson',
  });
  for (const outcome of ['ok', 'denied', 'failed', 'conflict', 'info', 'unknown', 'attempt'])
    assert.equal(parse(`outcome=${outcome}`).outcome, outcome);
  assert.throws(() => parseAuditQuery(new URLSearchParams(), 'other'), TypeError);
});

test('parseAuditQuery: each rule refuses with its §6.5 text and parameter (the contract error bodies)', () => {
  const cases = {
    from: ['from=abc', 'from=12345678901234567', 'from=9999999999999999', 'from=-1'],
    to: ['to=1.5', 'to='],
    'to/order': ['from=10&to=9'],
    limit: ['limit=0', 'limit=501', 'limit=07', 'limit=1000'],
    cursor: ['cursor=0', 'cursor=abc', 'cursor=9999999999999999'],
    action: [
      'action=',
      'action=Session.login',
      'action=a,,b',
      'action=1abc',
      `action=${Array(9).fill('a').join(',')}`,
    ],
    actor: ['actor=', `actor=${'x'.repeat(201)}`],
    target: ['target=Session', 'target=session:', 'target=s:has space', `target=${'a'.repeat(33)}`],
    outcome: ['outcome=attempted', 'outcome=OK'],
    repeated: ['action=a&action=b'],
  };
  for (const [name, texts] of Object.entries(cases))
    for (const text of texts)
      assert.deepEqual(refused(text), auditBody(`error.audit_query_invalid.${name}`), text);
  for (const text of ['', 'format=xml', 'format=CSV'])
    assert.deepEqual(refused(text, 'export'), auditBody('error.audit_query_invalid.format'), text);
  assert.equal(refused('from=1&from=2').body.parameter, 'from');
  // A parameter only the other kind takes is ignored, also when repeated.
  assert.equal(refused('format=a&format=b'), null);
  assert.equal(refused('limit=1&limit=2&format=csv', 'export'), null);
});

test('hiding: an attempt with a result is left out; an aggregated pair and an operation row are not', async t => {
  const { audit } = await auditFixture(t);
  const change = await audit.begin(adminRequest(), {
    action: 'settings.update',
    target: { type: 'settings', id: 'workspace', name: null },
  });
  await change.end({ status: 200, outcome: 'ok' });
  audit.count({
    action: 'session.login',
    outcome: 'failed',
    client: '192.0.2.1',
    login: 'admin',
    detail: { code: 'invalid_credentials' },
  });
  await audit.idle();
  const op = audit.operation(adminRequest(), {
    action: 'sources.refresh',
    target: { type: 'sources', id: '*', name: null },
  });
  await op.end({ status: 200, outcome: 'ok' });
  await audit.append({
    action: 'session.login',
    outcome: 'failed',
    count: 3,
    detail: {
      codes: { invalid_credentials: 3 },
      clients: 1,
      more: false,
      sample: ['192.0.2.1'],
      from: 1,
      to: 2,
    },
  });
  const listed = await audit.list(parse(''));
  assert.deepEqual(
    listed.entries.map(entry => [entry.seq, entry.action, entry.outcome, entry.ref]),
    [
      [5, 'session.login', 'failed', null],
      [4, 'sources.refresh', 'ok', null],
      [3, 'session.login', 'failed', null],
      [2, 'settings.update', 'ok', 1],
    ]
  );
  // outcome=attempt lists every attempt, with its result.
  const attempts = await audit.list(parse('outcome=attempt'));
  assert.deepEqual(
    attempts.entries.map(entry => [entry.seq, entry.outcome, entry.result?.seq]),
    [[1, 'attempt', 2]]
  );
  assert.equal(attempts.entries[0].result.outcome, 'ok');
  assert.equal(attempts.entries[0].result.status, 200);
  assert.deepEqual(listed.retention, {
    days: 90,
    maxRows: 250000,
    rows: 5,
    oldest: { seq: 1, time: listed.retention.oldest.time },
  });
});

test('in progress: a change begun and not ended lists as attempt here, and as unknown from a new service over the same data', async t => {
  const { audit, db, keyring, control } = await auditFixture(t);
  const change = await audit.begin(adminRequest(), {
    action: 'settings.update',
    target: { type: 'settings', id: 'workspace', name: null },
    detail: { ifMatch: true },
  });
  const here = await audit.list(parse(''));
  assert.equal(here.entries[0].outcome, 'attempt');
  assert.equal(here.entries[0].result, null);
  assert.deepEqual((await audit.list(parse('outcome=unknown'))).entries, []);
  const other = createAudit({ db, out() {}, err() {} });
  t.after(() => other.close());
  await other.attach({ keyring, instanceId: await control.meta.instanceId() });
  assert.equal((await other.list(parse(''))).entries[0].outcome, 'unknown');
  assert.equal((await other.list(parse('outcome=unknown'))).entries.length, 1);
  await change.end({ status: 200, outcome: 'ok' });
  assert.equal((await audit.list(parse(''))).entries[0].outcome, 'ok');
});

test('paging: newest first, nextCursor only when an older matching row exists, and every filter', async t => {
  const { audit, clock } = await auditFixture(t);
  for (let n = 1; n <= 7; n++) {
    await audit.append({ action: 'system.stop', outcome: 'info', detail: { uptimeMs: n } });
    clock.advance(1000);
  }
  const first = await audit.list(parse('limit=3'));
  assert.deepEqual(
    first.entries.map(entry => entry.seq),
    [7, 6, 5]
  );
  assert.equal(first.nextCursor, '5');
  const last = await audit.list(parse('limit=3&cursor=2'));
  assert.deepEqual(
    last.entries.map(entry => entry.seq),
    [1]
  );
  assert.equal(last.nextCursor, null);
  const exactly = await audit.list(parse('limit=4&cursor=5'));
  assert.equal(exactly.nextCursor, null, 'four rows left, four asked: no older page');
  const timeOf = seq => first.entries.find(entry => entry.seq === seq)?.time;
  assert.deepEqual(
    (await audit.list(parse(`from=${timeOf(6)}&to=${timeOf(6)}`))).entries.map(e => e.seq),
    [6]
  );
  assert.deepEqual((await audit.list(parse('actor=system'))).entries.length, 7);
  assert.deepEqual((await audit.list(parse('actor=orbit'))).entries.length, 7);
  assert.deepEqual((await audit.list(parse('actor=admin'))).entries.length, 0);
  assert.deepEqual((await audit.list(parse('action=system.'))).entries.length, 7);
  assert.deepEqual((await audit.list(parse('action=system.start'))).entries.length, 0);
  assert.deepEqual((await audit.list(parse('target=orbit'))).entries.length, 0);
  assert.deepEqual((await audit.list(parse('outcome=info'))).entries.length, 7);
});

test('list, export and verify answer audit_read_unavailable when the log cannot be read', async t => {
  const { audit, db } = await auditFixture(t);
  await audit.append({ action: 'system.stop', outcome: 'info', detail: { uptimeMs: 1 } });
  await db.write(tx =>
    tx.run(tx.dialect.update('audit_log', { time: 2n ** 53n + 1n }, sql`${sql.id('seq')} = ${1}`))
  );
  await assert.rejects(audit.list(parse('')), { code: 'audit_read_unavailable', status: 503 });
  await assert.rejects(audit.export(parse('format=csv', 'export'), 'csv'), {
    code: 'audit_read_unavailable',
  });
  // Verification reports the damage instead (unreadable, broken).
  assert.equal((await audit.verify()).problem.code, 'unreadable');
});

test('hiding: only an attempt row is ever hidden, also when a later row of its action names it', async t => {
  const { audit, db } = await auditFixture(t);
  await audit.append({
    action: 'session.login',
    outcome: 'failed',
    detail: { code: 'invalid_credentials', login: 'other' },
  });
  // A later row of the same action that names the first in `ref` (as a later release might
  // write a summary): the first is no attempt, so it stays listed.
  await db.write(tx => {
    const last = auditOps.last(tx);
    const row = auditOps.rowAt(tx, last.seq);
    auditOps.insertRow(tx, {
      ...row,
      seq: last.seq + 1,
      ref: last.seq,
      count: 4,
      hash: 'a'.repeat(64),
    });
  });
  assert.deepEqual(
    (await audit.list(parse(''))).entries.map(entry => entry.seq),
    [2, 1]
  );
});
