// The audit service's interface (audit spec §4.1), frozen in Phase 0 by noopAudit() (what
// server.mjs gives identity until the real audit is wired) and by test/helpers/fake-audit.mjs
// (what route, identity and web-app tests use). Lane O's writer test asserts that createAudit()
// has these names too. The other Phase 0 fakes' audit hooks are checked here as well:
// fakeAlerting's rotation recorder (§2.1 item 16), so test/notify/helpers.test.mjs stays as it
// was (§9.2).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { noopAudit } from '../../lib/audit/noop.mjs';
import { createAggregator } from '../../lib/audit/aggregate.mjs';
import { AuditError, auditError, AUDIT_ERRORS, QUERY_RULES } from '../../lib/audit/errors.mjs';
import { MAX_ROWS, RETENTION_DEFAULT_DAYS } from '../../lib/audit/actions.mjs';
import { openControl, metaOps } from '../../lib/db/control.mjs';
import { deliveryError } from '../../lib/alerting/errors.mjs';
import {
  auditDefect,
  auditMethods,
  auditBody,
  fakeAudit,
  loginClass,
} from '../helpers/fake-audit.mjs';
import { fakeAlerting } from '../helpers/fake-alerting.mjs';
import { retryOnce } from '../helpers/retry-once.mjs';
import { fakeClock } from '../alerting/fake-clock.mjs';

// §4.1, in its order.
const methods = [
  'attach',
  'record',
  'unrecorded',
  'append',
  'system',
  'count',
  'begin',
  'single',
  'operation',
  'configSnapshot',
  'start',
  'started',
  'maintain',
  'list',
  'export',
  'verify',
  'fromDelivery',
  'state',
  'idle',
  'close',
];
const unavailable = error =>
  error instanceof AuditError &&
  error.code === 'audit_read_unavailable' &&
  error.status === 503 &&
  error.retryAfter === 15;

test('noopAudit has the §4.1 methods, in order; its writes resolve and its reads are unavailable', async () => {
  const audit = noopAudit();
  assert.deepEqual(Object.keys(audit), methods);
  assert.deepEqual(auditMethods, methods);
  assert.ok(Object.isFrozen(audit));
  for (const name of methods) assert.equal(typeof audit[name], 'function', name);
  const event = { action: 'system.start', outcome: 'info' };
  // Synchronous writes return; the others resolve.
  assert.equal(audit.record(null, event), undefined);
  assert.equal(audit.unrecorded(event, new Error('x')), undefined);
  assert.equal(
    audit.count({ action: 'session.login', outcome: 'failed', login: 'admin' }),
    undefined
  );
  assert.equal(audit.fromDelivery({ action: 'channel.working', target: 'email' }), undefined);
  assert.deepEqual(await audit.append(event), { seq: 0 });
  for (const name of [
    'attach',
    'system',
    'single',
    'start',
    'started',
    'maintain',
    'idle',
    'close',
  ])
    assert.equal(await audit[name]({}), undefined, name);
  const change = await audit.begin({}, { action: 'settings.update' });
  assert.equal(change.seq, 0);
  assert.equal(change.note({ outcome: 'ok' }), undefined);
  assert.equal(await change.end({ status: 200 }), undefined);
  const operation = audit.operation({}, { action: 'source.test' });
  assert.equal(operation.note({ outcome: 'ok' }), undefined);
  assert.equal(await operation.end({ status: 200 }), undefined);
  assert.deepEqual(audit.configSnapshot({ revision: 7, title: 'Uptime Goblin' }), {
    revision: 7,
    public: {},
    secrets: {},
  });
  assert.deepEqual(audit.state(), { ready: false, unwritten: null, retention: null });
  for (const name of ['list', 'export', 'verify'])
    await assert.rejects(audit[name]({}), unavailable);
});

test('the audit errors: statuses, Retry-After and the verbatim texts of §6.5', () => {
  assert.deepEqual(Object.keys(AUDIT_ERRORS), [
    'audit_unavailable',
    'audit_read_unavailable',
    'audit_query_invalid',
  ]);
  const cause = Object.assign(new Error('disk full'), { class: 'full', code: 'SQLITE_FULL' });
  const write = auditError('audit_unavailable', { cause });
  assert.ok(write instanceof AuditError && write instanceof Error);
  assert.deepEqual(
    [write.status, write.code, write.retryAfter, write.cause],
    [503, 'audit_unavailable', 30, cause]
  );
  assert.equal(
    write.message,
    'Uptime Goblin cannot write its audit log, so nothing was changed. Try again in a moment; if this continues, free up space or increase the disk size of the Uptime Goblin host.'
  );
  assert.deepEqual(write.body, { error: write.message, code: 'audit_unavailable' });
  const read = auditError('audit_read_unavailable');
  assert.equal(read.message, 'Uptime Goblin could not read its audit log. Try again in a moment.');
  assert.equal(read.cause, undefined);
  const invalid = auditError('audit_query_invalid', {
    parameter: 'limit',
    rule: QUERY_RULES.limit,
  });
  assert.deepEqual([invalid.status, invalid.retryAfter], [400, undefined]);
  assert.deepEqual(invalid.body, {
    error: 'limit must be a whole number from 1 to 500.',
    code: 'audit_query_invalid',
    parameter: 'limit',
  });
  assert.equal(
    auditError('audit_query_invalid', { parameter: 'to', rule: QUERY_RULES.order }).message,
    'to must not be before from.'
  );
  assert.throws(() => auditError('audit_query_invalid', { parameter: 'limit' }), TypeError);
  assert.throws(() => auditError('no_such_code'), TypeError);
});

test('fakeAudit has the §4.1 methods; it keeps rows, counts, unrecorded events and unwritten rows', async () => {
  let now = Date.UTC(2026, 9, 3, 12);
  const audit = fakeAudit({ clock: () => now });
  for (const name of methods) assert.equal(typeof audit[name], 'function', name);
  const request = Object.freeze({
    requestId: 'r-1',
    route: 'PATCH /api/settings',
    client: '192.0.2.10',
    userAgent: 'test agent',
    actor: { type: 'user', id: 'u_admin', name: 'admin', via: 'session', sessionId: 's_1' },
  });
  audit.record(null, {
    action: 'session.login',
    outcome: 'ok',
    meta: { audit_password_changed_at: '1' },
  });
  assert.deepEqual(audit.rows[0], {
    mode: 'record',
    action: 'session.login',
    outcome: 'ok',
    at: now,
    actor: { type: 'system', id: null, name: 'orbit', via: 'system', sessionId: null },
    client: null,
    userAgent: null,
    requestId: null,
    target: null,
    status: null,
    count: 1,
    ref: null,
    detail: null,
    configRevision: null,
    meta: { audit_password_changed_at: '1' },
    seq: 1,
  });
  // Attempt and result: the result carries the attempt's facts and detail, then what was
  // noted (which overrides settle's values), with ref = the attempt's seq; it is written once.
  const change = await audit.begin(request, {
    action: 'settings.update',
    target: { type: 'settings', id: 'workspace', name: null },
    detail: { ifMatch: true },
    configRevision: 4,
  });
  assert.deepEqual(audit.open(), [change.seq]);
  const diff = [{ path: 'title', from: 'Uptime Goblin', to: 'Home' }];
  change.note({ detail: { diff, truncated: false }, configRevision: 5 });
  change.note({ detail: { changes: 1 } });
  await change.end({ status: 200, outcome: 'ok', code: null });
  await change.end({ status: 500, outcome: 'failed' });
  const [attempt, result] = audit.rows.slice(1);
  assert.deepEqual(
    [attempt.mode, attempt.outcome, attempt.requestId, attempt.client, attempt.actor.sessionId],
    ['attempt', 'attempt', 'r-1', '192.0.2.10', 's_1']
  );
  assert.deepEqual(
    [result.mode, result.outcome, result.status, result.ref, result.configRevision, result.detail],
    ['result', 'ok', 200, attempt.seq, 5, { ifMatch: true, diff, truncated: false, changes: 1 }]
  );
  assert.deepEqual(audit.open(), []);
  const refused = await audit.begin(request, { action: 'delivery.retry' });
  refused.note({ outcome: 'denied' });
  await refused.end({ status: 409, outcome: 'conflict', code: 'delivery_not_retryable' });
  assert.deepEqual(
    [audit.rows.at(-1).outcome, audit.rows.at(-1).status, audit.rows.at(-1).detail],
    ['denied', 409, { code: 'delivery_not_retryable' }]
  );
  // Operations write one row when ended; single, append and system write at once.
  const operation = audit.operation(request, { action: 'source.test', detail: { type: 'plex' } });
  const before = audit.rows.length;
  operation.note({ outcome: 'failed', detail: { result: 'timeout' } });
  assert.equal(audit.rows.length, before, 'nothing is written when it is made');
  await operation.end({ status: 200, outcome: 'ok' });
  assert.deepEqual(
    [audit.rows.at(-1).mode, audit.rows.at(-1).outcome, audit.rows.at(-1).detail],
    ['operation', 'failed', { type: 'plex', result: 'timeout' }]
  );
  await audit.single(request, { action: 'config.export', detail: { sources: 1, bytes: 10 } });
  const next = audit.rows.length + 1;
  assert.deepEqual(await audit.append({ action: 'key.rotate', outcome: 'ok' }), { seq: next });
  await audit.system({ action: 'system.stop', outcome: 'info' });
  assert.deepEqual(
    audit.rows.slice(-3).map(row => [row.mode, row.action]),
    [
      ['single', 'config.export'],
      ['append', 'key.rotate'],
      ['system', 'system.stop'],
    ]
  );
  audit.unrecorded({ action: 'session.logout', outcome: 'ok' }, 'full');
  assert.deepEqual(audit.unrecorded.calls, [
    { event: { action: 'session.logout', outcome: 'ok' }, error: 'full' },
  ]);
  assert.deepEqual(
    audit.rows.map(row => row.seq),
    audit.rows.map((_, index) => index + 1)
  );
});

test('fakeAudit.setFailing: record throws, append, begin and single reject, end, operation and system lose their row', async () => {
  const audit = fakeAudit({ clock: () => 1000 });
  const failure = Object.assign(new Error('injected'), { class: 'full' });
  assert.throws(() => audit.setFailing('nothing', failure), TypeError);
  for (const kind of ['record', 'append', 'begin', 'single']) audit.setFailing(kind, failure);
  assert.throws(() => audit.record(null, { action: 'session.login', outcome: 'ok' }), /injected/);
  await assert.rejects(audit.append({ action: 'key.rotate', outcome: 'ok' }), /injected/);
  await assert.rejects(audit.begin({}, { action: 'settings.update' }), /injected/);
  await assert.rejects(audit.single({}, { action: 'config.export' }), /injected/);
  assert.deepEqual(audit.rows, []);
  for (const kind of ['record', 'append', 'begin', 'single']) audit.setFailing(kind, null);
  const change = await audit.begin({}, { action: 'settings.update' });
  for (const kind of ['end', 'operation', 'system']) audit.setFailing(kind, failure);
  await change.end({ status: 200, outcome: 'ok' });
  await audit.operation({}, { action: 'sources.refresh' }).end({ status: 200, outcome: 'ok' });
  await audit.system({ action: 'system.stop', outcome: 'info' });
  assert.deepEqual(
    audit.unwritten.map(row => [row.mode, row.action, row.error]),
    [
      ['result', 'settings.update', failure],
      ['operation', 'sources.refresh', failure],
      ['system', 'system.stop', failure],
    ]
  );
  assert.deepEqual(audit.state(), {
    ready: true,
    unwritten: { since: 1000, count: 3 },
    retention: { days: 90, maxRows: 250000 },
  });
  assert.deepEqual(
    [RETENTION_DEFAULT_DAYS, MAX_ROWS],
    [90, 250000],
    "the maintainer's 90 days (OD7)"
  );
  assert.deepEqual(audit.open(), [], 'an end whose row is lost still closes its change');
  audit.setFailing('list', failure);
  await assert.rejects(audit.list({}), /injected/);
});

test('fakeAudit answers list, export and verify from test/contract/audit-bodies.json', async () => {
  const audit = fakeAudit();
  assert.deepEqual(await audit.list({}), auditBody('list.entries'));
  assert.deepEqual(await audit.verify(), auditBody('verify.intact'));
  const csv = await audit.export({}, 'csv');
  assert.ok(Buffer.isBuffer(csv.body));
  assert.deepEqual([...csv.body.subarray(0, 3)], [0xef, 0xbb, 0xbf], 'the BOM');
  assert.deepEqual([csv.rows, csv.more, csv.contentType], [2, false, 'text/csv; charset=utf-8']);
  audit.answer('list.empty');
  audit.answer('verify.broken.seq_gap');
  audit.answer('export.ndjson');
  assert.deepEqual((await audit.list({})).entries, []);
  assert.equal((await audit.verify()).problem.code, 'seq_gap');
  assert.match((await audit.export({}, 'ndjson')).body.toString(), /^\{"orbit":"audit\.export"/);
  assert.throws(() => audit.answer('error.audit_unavailable'), TypeError);
  assert.throws(() => audit.answer('list.nothing'), /has no list\.nothing/);
  // Each answer is a copy: a test that changes one does not change the next.
  (await audit.list({})).entries.push('x');
  assert.deepEqual((await audit.list({})).entries, []);
});

test('fakeAudit before attach: identity rows go to the inbox and request writes throw', async () => {
  const audit = fakeAudit({ ready: false });
  assert.equal(audit.state().ready, false);
  audit.record(null, { action: 'account.bootstrap', outcome: 'info' });
  await audit.system({ action: 'identity.mirror.failed', outcome: 'failed' });
  assert.throws(() => audit.operation({}, { action: 'sources.refresh' }), TypeError);
  await assert.rejects(audit.begin({}, { action: 'settings.update' }), TypeError);
  await assert.rejects(audit.append({ action: 'key.rotate', outcome: 'ok' }), TypeError);
  await audit.attach({ keyring: {}, instanceId: 'i_1' });
  audit.record(null, { action: 'session.login', outcome: 'ok' });
  assert.deepEqual(
    audit.rows.map(row => row.mode),
    ['inbox', 'inbox', 'record']
  );
});

test('fakeAudit.count: the login reduced to its class, one immediate row per window, then one summary', () => {
  let now = Date.UTC(2026, 9, 3, 12, 5);
  const audit = fakeAudit({ clock: () => now });
  assert.deepEqual(
    ['admin', ' ADMIN ', 'ａｄｍｉｎ', 'root', 'hunter2 typed as a name', '', '  ', null, 7].map(
      loginClass
    ),
    ['admin', 'admin', 'admin', 'other', 'other', null, null, null, null]
  );
  const refuse = (login, client, code = 'invalid_credentials') =>
    audit.count({
      action: 'session.login',
      outcome: code === 'invalid_credentials' ? 'failed' : 'denied',
      client,
      userAgent: 'curl/8',
      login,
      detail: { code },
    });
  refuse('admin', '192.0.2.1');
  refuse('a password typed as a name', '192.0.2.2');
  refuse('root', '192.0.2.2', 'locked');
  assert.equal(JSON.stringify(audit.counts).includes('typed as a name'), false, 'never kept');
  assert.deepEqual(
    audit.counts.map(event => event.login),
    ['admin', 'other', 'other']
  );
  assert.equal(audit.rows.length, 1, 'the window has one immediate row');
  assert.deepEqual(
    [audit.rows[0].mode, audit.rows[0].actor.type, audit.rows[0].target, audit.rows[0].detail],
    [
      'aggregate',
      'anonymous',
      { type: 'account', id: 'admin', name: null },
      { code: 'invalid_credentials', login: 'admin' },
    ]
  );
  // The next hour's first event ends the window: its summary, then its own immediate row.
  now += 3600e3;
  refuse('other', '192.0.2.3');
  assert.deepEqual(
    audit.rows.slice(1).map(row => [row.mode, row.outcome, row.count, row.client]),
    [
      ['aggregate', 'failed', 2, null],
      ['aggregate', 'failed', 1, '192.0.2.3'],
    ]
  );
  assert.deepEqual(audit.rows[1].detail, {
    codes: { invalid_credentials: 1, locked: 1 },
    clients: 1,
    more: false,
    sample: ['192.0.2.2'],
    from: Date.UTC(2026, 9, 3, 12, 5),
    to: Date.UTC(2026, 9, 3, 12, 5),
  });
  assert.equal(audit.rows[1].at, Date.UTC(2026, 9, 3, 13), "the window's end");
});

// Codex review A5 (verification): the route tests see the summaries fakeAudit writes, so its
// actor must follow the real aggregator's rule: the first actor counted, the first signed-in
// session when password changes refused before sign-in are counted beside a session's.
test('Codex review A5: fakeAudit names the actor of an aggregated row as the real aggregator does', async () => {
  const at = Date.UTC(2026, 9, 3, 12, 5);
  const session = sessionId => ({
    type: 'user',
    id: 'u_admin',
    name: 'admin',
    via: 'session',
    sessionId,
  });
  const nobody = { type: 'anonymous', id: null, name: null, via: null, sessionId: null };
  const [s1, s2] = [session('s_1'), session('s_2')];
  for (const actors of [
    [nobody, nobody, s2, s2, s2, s2],
    [nobody, s1, nobody, s2],
    [s1, nobody, s2],
    [s1, s1, s2],
    [nobody, nobody, nobody],
  ]) {
    const fake = fakeAudit({ clock: () => at });
    const written = [];
    const real = createAggregator({
      clock: () => at,
      write: async (event, kind) => written.push({ kind, actor: event.actor }) > 0,
      setTimer: () => ({}),
      clearTimer: () => {},
    });
    for (const actor of actors) {
      const event = {
        action: 'account.password.changed',
        outcome: actor === nobody ? 'denied' : 'failed',
        actor,
        client: '192.0.2.9',
        userAgent: 'curl/8',
        detail: { code: actor === nobody ? 'signin_required' : 'current_password_incorrect' },
      };
      fake.count(event);
      real.count(event);
    }
    await real.idle();
    fake.flush();
    await real.flush({ force: true });
    const named = rows => rows.map(row => [row.kind, row.actor.sessionId]);
    const sequence = actors.map(actor => actor.sessionId ?? 'nobody').join(' ');
    // The first event took the immediate row; the summary counts the others and names the
    // first signed-in session among them, else no one.
    const counted = actors.slice(1);
    const expected = counted.find(actor => actor !== nobody) ?? counted[0];
    assert.deepEqual(
      named(written),
      [
        ['immediate', actors[0].sessionId],
        ['summary', expected.sessionId],
      ],
      sequence
    );
    assert.deepEqual(
      fake.rows.map(row => [row.actor.type, row.actor.sessionId]),
      written.map(row => [row.actor.type, row.actor.sessionId]),
      sequence
    );
  }
});

test('fakeAudit.fromDelivery: records with an actor are left to their route; system records become rows', async () => {
  const audit = fakeAudit({ clock: () => 5 });
  const records = [
    { at: 1, action: 'signing.rotate', outcome: 'ok', actor: 'admin', target: 'env-webhook' },
    {
      at: 2,
      action: 'signing.created',
      outcome: 'ok',
      target: 'env-webhook',
      detail: { replaced: true },
    },
    {
      at: 3,
      action: 'channel.paused',
      outcome: 'ok',
      target: 'email',
      detail: { reason: 'x'.repeat(300), transient: true },
    },
    { at: 4, action: 'channel.working', outcome: 'ok', target: 'email' },
    { at: 5, action: 'notifications.unsaved', outcome: 'ok', target: 'outbox' },
    { at: 6, action: 'notifications.saved', outcome: 'ok', target: 'outbox' },
    { at: 7, action: 'delivery.retry', outcome: 'refused', target: 'd_1' },
    null,
  ];
  for (const record of records) audit.fromDelivery(record);
  await Promise.resolve();
  assert.deepEqual(
    audit.rows.map(row => [
      row.mode,
      row.action,
      row.outcome,
      row.at,
      row.target.type,
      row.target.id,
    ]),
    [
      ['system', 'signing.created', 'info', 2, 'secret', 'env-webhook'],
      ['system', 'channel.paused', 'info', 3, 'channel', 'email'],
      ['system', 'channel.working', 'info', 4, 'channel', 'email'],
      ['system', 'notifications.unsaved', 'info', 5, 'outbox', null],
      ['system', 'notifications.saved', 'info', 6, 'outbox', null],
    ]
  );
  assert.deepEqual(audit.rows[0].detail, { replaced: true });
  assert.equal(audit.rows[1].detail.reason.length, 200);
});

// §4.1, D32: the fake refuses what the writer refuses before it writes, and sends the event
// where the writer would, so a lane finds a bad action, outcome or key against the fake.
test('fakeAudit refuses what the writer refuses: record and best-effort rows go unwritten, fail-closed writes reject', async () => {
  const refused = [
    [{ action: 'no.such.action', outcome: 'ok' }, /"no\.such\.action" is not an action/],
    [{ action: 'session.login', outcome: 'whatever' }, /session\.login has no outcome "whatever"/],
    [
      { action: 'session.logout', outcome: 'ok', detail: { anything: 1 } },
      /no detail key anything/,
    ],
    [{ action: 'session.logout', outcome: 'ok', detail: { cause: new Date(0) } }, /holds Date/],
    [{ action: 'session.revoked', outcome: 'ok', detail: { count: 1.5 } }, /not a safe integer/],
    [{ action: 'config.changed-outside', outcome: 'info', detail: { diff: [1, , 3] } }, /hole/],
    [{ action: 'session.logout', outcome: 'ok', detail: ['signout'] }, /detail must be a plain/],
    [{ action: 'session.logout', outcome: 'ok', meta: { not_a_key: '1' } }, /meta key not_a_key/],
    [{ action: 'session.logout', outcome: 'ok', actor: { type: 'robot' } }, /actor\.type/],
    [{ action: 'session.logout', outcome: 'ok', status: 2 ** 53 }, /status must be a safe/],
    [{ action: 'session.logout', outcome: 'ok', count: 0 }, /count must be/],
    [{ action: 'session.logout', outcome: 'ok', target: { type: 7 } }, /target\.type/],
  ];
  for (const [event, why] of refused) assert.match(auditDefect(event) ?? '', why, why.source);
  assert.equal(
    auditDefect({
      action: 'session.logout',
      outcome: 'ok',
      actor: { type: 'user', id: 'u_admin', name: 'admin', via: 'session', sessionId: 's_1' },
      target: { type: 'session', id: 's_1', name: null },
      detail: { cause: 'signout', code: undefined },
      meta: { audit_password_changed_at: 5 },
    }),
    null,
    'a key left undefined is left out, as canonical JSON leaves it out'
  );
  assert.equal(auditDefect({ action: 'settings.update', outcome: 'attempt' }), null);

  const audit = fakeAudit({ clock: () => 7 });
  const request = Object.freeze({
    requestId: 'r-2',
    route: 'PATCH /api/settings',
    client: '192.0.2.10',
    userAgent: 'test agent',
    actor: { type: 'user', id: 'u_admin', name: 'admin', via: 'session', sessionId: 's_1' },
  });
  const bad = { action: 'session.logout', outcome: 'ok', detail: { anything: 1 } };
  // In-unit: never thrown (D32); the row goes where audit.unwritten lines go.
  assert.equal(audit.record(null, bad), undefined);
  await audit.system(bad);
  // Fail closed: audit_unavailable, the refusal as its cause; nothing written.
  const unavailable = why => error =>
    error instanceof AuditError &&
    error.code === 'audit_unavailable' &&
    error.cause instanceof TypeError &&
    why.test(error.cause.message);
  await assert.rejects(audit.append(bad), unavailable(/no detail key anything/));
  await assert.rejects(
    audit.single(request, { action: 'config.export', detail: { secret: 'x' } }),
    unavailable(/no detail key secret/)
  );
  // An attempt of an action that has none (an operation's) is refused the same way.
  await assert.rejects(
    audit.begin(request, { action: 'source.test' }),
    unavailable(/source\.test has no outcome "attempt"/)
  );
  // Best effort: the result, the operation row and an aggregated row are lost, not thrown.
  const change = await audit.begin(request, {
    action: 'settings.update',
    detail: { ifMatch: false },
  });
  change.note({ detail: { password: 'not a detail key' } });
  await change.end({ status: 200, outcome: 'ok' });
  await audit.operation(request, { action: 'sources.refresh' }).end({ outcome: 'conflict' });
  audit.count({ action: 'auth.basic.used', outcome: 'denied', client: '192.0.2.10' });
  assert.deepEqual(
    audit.rows.map(row => [row.mode, row.action]),
    [['attempt', 'settings.update']]
  );
  assert.deepEqual(
    audit.unwritten.map(row => [row.mode, row.action, row.error instanceof TypeError]),
    [
      ['record', 'session.logout', true],
      ['system', 'session.logout', true],
      ['result', 'settings.update', true],
      ['operation', 'sources.refresh', true],
      ['aggregate', 'auth.basic.used', true],
    ]
  );
  assert.deepEqual(audit.open(), [], 'the change ended though its row was refused');
  assert.deepEqual(audit.state().unwritten, { since: 7, count: 5 });
});

// §4.3, D4, D32: like the writer, record() inside a unit keeps its row until the unit commits,
// so identity's "retry once" and "throw after record" tests (§9.1 I) hold against the fake too.
test("fakeAudit.record inside a write unit: its row, or its refusal, waits for the unit's commit", async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-fake-audit-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const control = openControl(directory, { release: '1.5.0', env: {} });
  t.after(() => control.close());
  await control.migrate();
  const audit = fakeAudit({ clock: () => 1 });
  const revoked = count => ({
    action: 'session.revoked',
    outcome: 'info',
    detail: { cause: 'retried', count },
  });
  // Run again after a retry: one row.
  let runs = 0;
  await retryOnce(control.db).write(tx => {
    runs += 1;
    metaOps.set(tx, 'test_mark', runs, 1);
    audit.record(tx, revoked(1));
  });
  assert.equal(runs, 2, 'the first attempt was rolled back and run again');
  assert.deepEqual(
    audit.rows.map(row => [row.mode, row.detail.count]),
    [['record', 1]]
  );
  // A unit that throws after its record(): no row.
  await assert.rejects(
    control.db.write(tx => {
      metaOps.set(tx, 'test_mark', 'x', 1);
      audit.record(tx, revoked(2));
      throw new Error('the change fails');
    }),
    /the change fails/
  );
  assert.equal(audit.rows.length, 1);
  // Not there before the commit; there after it.
  let during = null;
  await control.db.write(tx => {
    audit.record(tx, revoked(3));
    during = audit.rows.length;
  });
  assert.deepEqual([during, audit.rows.length], [1, 2]);
  // A refused event: unwritten once its unit commits, never when the unit rolls back.
  const bad = { action: 'session.revoked', outcome: 'info', detail: { nope: true } };
  await assert.rejects(
    control.db.write(tx => {
      audit.record(tx, bad);
      throw new Error('rolled back');
    }),
    /rolled back/
  );
  assert.deepEqual(audit.unwritten, []);
  await control.db.write(tx => {
    audit.record(tx, bad);
    during = audit.unwritten.length;
  });
  assert.deepEqual([during, audit.unwritten.length], [0, 1]);
  // A storage failure is thrown into the unit, which fails with nothing written.
  audit.setFailing('record', new Error('injected storage failure'));
  await assert.rejects(
    control.db.write(tx => audit.record(tx, revoked(4))),
    /injected storage failure/
  );
  assert.equal(audit.rows.length, 2);
});

// Audit spec §5.3, §2.1 item 16: the rotation records its row through the settings unit's
// recorder; the fake calls it as the settings store does.
test('fakeAlerting: signing.rotate({audit}) calls the recorder once per rotation, with the path-form diff', async () => {
  const clock = fakeClock();
  const fake = fakeAlerting({ clock });
  const calls = [];
  const audit = (tx, change) => calls.push([tx, change]);
  const before = fake.signing.describe();
  const rotated = await fake.signing.rotate({ actor: 'admin', audit });
  assert.deepEqual(calls, [
    [
      null,
      {
        diff: [
          { path: 'signingKey', change: 'changed' },
          { path: 'previousSigningKey', change: 'set' },
          { path: 'previousUntil', from: null, to: rotated.previousUntil },
          ...(before.createdAt === rotated.createdAt
            ? []
            : [{ path: 'createdAt', from: before.createdAt, to: rotated.createdAt }]),
        ],
      },
    ],
  ]);
  assert.doesNotMatch(JSON.stringify(calls), /KEY-----|[0-9a-f]{64}/, 'never a key');
  assert.deepEqual(fake.calls.at(-1), ['signing.rotate', { actor: 'admin', audit: true }]);
  // A refused rotation (a conflict, no webhook) never calls it; one that throws changes nothing.
  fake.fail('signing.rotate', deliveryError('signing_conflict'));
  await assert.rejects(fake.signing.rotate({ actor: 'admin', audit }), {
    code: 'signing_conflict',
  });
  const current = (await fake.signing.publicKeys()).keyId;
  await assert.rejects(
    fake.signing.rotate({
      audit: () => {
        throw new Error('no audit row');
      },
    }),
    /no audit row/
  );
  assert.equal((await fake.signing.publicKeys()).keyId, current);
  assert.equal(calls.length, 1);
  // Without a recorder it rotates as before.
  await fake.signing.rotate({ actor: 'admin' });
  assert.notEqual((await fake.signing.publicKeys()).keyId, current);
  assert.deepEqual(fake.calls.at(-2), ['signing.rotate', { actor: 'admin' }]);
});
