// The audit stage of the request pipeline (audit spec §4.4, §5.2-§5.5, §6, D29) over the
// in-memory audit service (fakeAudit), identity (fakeIdentity) and delivery service
// (fakeAlerting): the attempt row before a change and its result after the answer, fail closed,
// operations after the answer, the refusals counted into aggregated rows, the export rule, and
// the audit routes' answers (test/contract/audit-bodies.json). What the real audit core then
// stores is lane O's to test; test/audit.test.mjs runs both together.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import { serveAudited, gate, until, raw, basic, password } from './audit-app.mjs';
import { serveAuth, login, browserWrite } from './harness.mjs';
import {
  answerCode,
  answerStatus,
  auditActor,
  basicLogin,
  settledOutcome,
} from '../../lib/http/pipeline.mjs';
import { createRouter, RouteError } from '../../lib/http/router.mjs';
import { json } from '../../lib/http/body.mjs';
import { BusyError } from '../../lib/http/exclusive.mjs';
import { auditError } from '../../lib/audit/errors.mjs';
import { parseAuditQuery } from '../../lib/audit/view.mjs';
import { deliveryError } from '../../lib/alerting/errors.mjs';
import { identityError } from '../../lib/identity/errors.mjs';
import { InputError } from '../../lib/config.mjs';
import { StorageFullError } from '../../lib/storage-guard.mjs';
import { auditBody, fakeAudit } from '../helpers/fake-audit.mjs';

const diskFull = () => Object.assign(new Error('database or disk is full'), { class: 'full' });
const unavailable = () => auditError('audit_unavailable', { cause: diskFull() });
const jsonSource = { type: 'json', name: 'API', apiUrl: 'https://api.example.test' };
const emailSettings = {
  email: {
    from: 'sender@example.com',
    to: 'recipient@example.com',
    password: 'fixture-audit-email-password',
    enabled: true,
  },
};
// The answer an audit error gets, as test/contract/audit-bodies.json writes it.
function assertAuditError(answer, name) {
  const expected = auditBody(`error.${name}`);
  assert.equal(answer.status, expected.status, `${name}: ${answer.body}`);
  assert.deepEqual(answer.json, expected.body, name);
  for (const [header, value] of Object.entries(expected.headers))
    assert.equal(answer.headers[header], value, `${name}: ${header}`);
  assert.equal(answer.headers['cache-control'], 'no-store', name);
}
// A script's export: Basic (s.script's) and X-Goblin-Request: 1, which every export needs (D29),
// as every change does.
const exporting = Object.freeze({ lines: ['X-Goblin-Request: 1'] });
// The rows of a mode, as [action, outcome, status] (and detail.code when there is one).
const summary = rows =>
  rows.map(row => [row.mode, row.action, row.outcome, row.status, row.detail?.code ?? null]);

test('stage: the status fail() answers, the code a row names and the outcome of each status class', () => {
  const cases = [
    [identityError('session_expired'), 401, 'session_expired'],
    [identityError('storage_full'), 503, 'storage_full'],
    [deliveryError('delivery_not_found'), 404, 'delivery_not_found'],
    [deliveryError('signing_conflict'), 409, 'signing_conflict'],
    [unavailable(), 503, 'audit_unavailable'],
    [auditError('audit_read_unavailable'), 503, 'audit_read_unavailable'],
    [
      auditError('audit_query_invalid', { parameter: 'limit', rule: 'x' }),
      400,
      'audit_query_invalid',
    ],
    [new StorageFullError(), 503, 'storage_full'],
    [Object.assign(new Error('no space'), { code: 'ENOSPC' }), 503, 'storage_full'],
    [diskFull(), 503, 'storage_full'],
    [new BusyError('busy'), 503, 'busy'],
    [new InputError('Expected valid JSON'), 400, null],
    [Object.assign(new Error('locked'), { class: 'unavailable' }), 500, 'unavailable'],
    [new Error('a remote text with https://user:token@host/'), 500, null],
  ];
  for (const [error, status, code] of cases) {
    assert.equal(answerStatus(error), status, error.message);
    assert.equal(answerCode(error), code, error.message);
  }
  for (const status of [200, 201, 202, 204]) assert.equal(settledOutcome(status), 'ok');
  // A configuration or email-test 409 is a conflict; a DeliveryError 409 refuses the delivery's
  // state (MEC-14), except the signing key's compare-and-swap.
  assert.equal(settledOutcome(409), 'conflict');
  assert.equal(settledOutcome(409, deliveryError('delivery_not_retryable')), 'denied');
  assert.equal(
    settledOutcome(409, deliveryError('channel_paused', { name: 'x', reason: 'y' })),
    'denied'
  );
  assert.equal(settledOutcome(409, deliveryError('signing_conflict')), 'conflict');
  for (const status of [401, 403, 429]) assert.equal(settledOutcome(status), 'denied');
  for (const status of [400, 404, 422, 500, 503]) assert.equal(settledOutcome(status), 'failed');
  // Actors (D25): the admin with the public session id, a script, nobody.
  const principal = { userId: 'u_admin', login: 'admin' };
  assert.deepEqual(auditActor({ via: 'session', sessionId: 's_x', principal }), {
    type: 'user',
    id: 'u_admin',
    name: 'admin',
    via: 'session',
    sessionId: 's_x',
  });
  assert.equal(auditActor({ via: 'basic', principal }).via, 'basic');
  assert.equal(auditActor(null).type, 'anonymous');
  // A Basic header's name, never its password.
  assert.equal(basicLogin(basic('pw-sentinel')), 'admin');
  assert.equal(basicLogin('Basic ' + Buffer.from('root:x').toString('base64')), 'root');
  assert.equal(basicLogin('Bearer abc'), null);
  assert.equal(basicLogin('Basic ' + Buffer.from('no-colon').toString('base64')), null);
});

// Routes that begin changes and make operations, then answer (or throw) as their name says.
// Opened by the routes that wait for their client to leave, once they are waiting.
let waiting = gate();
function stageRoutes() {
  const stage = (name, handler, audit = 'config') => ({
    method: 'POST',
    path: `/api/stage/${name}`,
    auth: 'session',
    permission: 'sources:write',
    audit,
    summary: `stage ${name}`,
    handler,
  });
  const begun = audit =>
    audit.begin({ action: 'settings.update', target: { type: 'settings', id: 'workspace' } });
  const status =
    code =>
    async ({ res, audit }) => {
      await begun(audit);
      json(res, code, {});
    };
  const throws =
    error =>
    async ({ audit }) => {
      await begun(audit);
      throw error();
    };
  return [
    // The request's facts as the pipeline hands them to every recording (§4.1).
    stage(
      'facts',
      async ({ res, audit }) =>
        json(res, 200, { ...audit.request, frozen: Object.isFrozen(audit.request) }),
      'none'
    ),
    stage('ok', status(200)),
    stage('conflict', status(409)),
    stage('forbidden', status(403)),
    stage('limited', status(429)),
    stage('missing', status(404)),
    stage(
      'refused',
      throws(() => deliveryError('delivery_not_retryable'))
    ),
    stage(
      'signing',
      throws(() => deliveryError('signing_conflict'))
    ),
    stage(
      'expired',
      throws(() => identityError('session_expired'))
    ),
    stage(
      'broken',
      throws(() => new Error('remote text https://user:secret@host/'))
    ),
    stage(
      'invalid',
      throws(() => new InputError('Expected valid JSON'))
    ),
    stage(
      'full',
      throws(() => new StorageFullError())
    ),
    stage('noted', async ({ res, audit }) => {
      const change = await begun(audit);
      change.note({ outcome: 'conflict', detail: { ifMatch: true } });
      json(res, 200, {});
    }),
    stage('applied', async ({ audit }) => {
      const change = await begun(audit);
      change.note({ applied: true });
      throw new Error('history step failed after the save');
    }),
    stage('committed', async ({ audit, committed }) => {
      await begun(audit);
      committed(201, { ok: true });
    }),
    stage(
      'operation',
      async ({ res, audit }) => {
        audit.operation({ action: 'sources.refresh', target: { type: 'sources', id: '*' } });
        json(res, 422, {});
      },
      'operation'
    ),
    stage('order', async ({ res, audit }) => {
      await begun(audit);
      await audit.begin({ action: 'channel.resume', target: { type: 'channel', id: 'email' } });
      json(res, 200, {});
    }),
    // The client goes away: no answer is ever sent.
    stage('gone', async ({ audit, gone }) => {
      await begun(audit);
      waiting.open();
      await until(gone, 'the client to leave');
    }),
    stage(
      'gone-operation',
      async ({ audit, gone }) => {
        const operation = audit.operation({ action: 'source.test', target: { type: 'source' } });
        operation.note({ outcome: 'ok', detail: { result: 'connected' } });
        waiting.open();
        await until(gone, 'the client to leave');
      },
      'operation'
    ),
    // A route that records otherwise than its kind declares (D18): a defect, refused before
    // anything is recorded or done.
    stage('undeclared', async ({ res, audit }) => {
      audit.operation({ action: 'sources.refresh', target: { type: 'sources', id: '*' } });
      json(res, 202, {});
    }),
    stage(
      'none',
      async ({ res, audit }) => {
        await audit.begin({ action: 'settings.update' });
        json(res, 200, {});
      },
      'none'
    ),
    stage(
      'single',
      async ({ res, audit }) => {
        await audit.single({ action: 'config.export', target: { type: 'config' } });
        json(res, 200, {});
      },
      'operation'
    ),
  ];
}

test('stage: settle ends every change and operation, in order, with the answer and its outcome', async t => {
  const audit = fakeAudit();
  const { port } = await serveAuth(t, { audit, routes: stageRoutes() });
  const { cookie } = await login(port);
  const origin = `http://127.0.0.1:${port}`;
  const post = name =>
    raw(
      port,
      [`POST /api/stage/${name} HTTP/1.1`, `Cookie: ${cookie}`, ...browserWrite(origin)],
      '{}'
    );
  const ended = async name => {
    const from = audit.rows.length;
    const answer = await post(name);
    return { answer, rows: audit.rows.slice(from) };
  };
  const expect = {
    ok: [200, 'ok', null],
    conflict: [409, 'conflict', null],
    forbidden: [403, 'denied', null],
    limited: [429, 'denied', null],
    missing: [404, 'failed', null],
    refused: [409, 'denied', 'delivery_not_retryable'],
    signing: [409, 'conflict', 'signing_conflict'],
    expired: [401, 'denied', 'session_expired'],
    broken: [500, 'failed', null],
    invalid: [400, 'failed', null],
    full: [503, 'failed', 'storage_full'],
    // The handler's note wins; a change noted applied is `ok` whatever the status.
    noted: [200, 'conflict', null],
    applied: [500, 'ok', null],
    committed: [201, 'ok', null],
  };
  for (const [name, [status, outcome, code]] of Object.entries(expect)) {
    const { answer, rows } = await ended(name);
    assert.equal(answer.status, status, `${name}: ${answer.body}`);
    assert.deepEqual(
      rows.map(row => row.mode),
      ['attempt', 'result'],
      name
    );
    const [attempt, result] = rows;
    assert.equal(result.ref, attempt.seq, name);
    assert.equal(result.status, status, name);
    assert.equal(result.outcome, outcome, name);
    assert.equal(result.detail?.code ?? null, code, name);
    // No error text ever: only codes.
    assert.doesNotMatch(JSON.stringify(rows), /secret@host/, name);
  }
  // The request's facts: who (the session), from where, which request, by which route.
  const facts = await post('facts');
  assert.deepEqual(facts.json, {
    requestId: facts.headers['x-request-id'],
    route: 'POST /api/stage/facts',
    client: 'loopback',
    userAgent: null,
    actor: {
      type: 'user',
      id: 'u_admin',
      name: 'admin',
      via: 'session',
      sessionId: facts.json.actor.sessionId,
    },
    frozen: true,
  });
  const [, result] = (await ended('ok')).rows;
  assert.equal(result.actor.via, 'session');
  assert.match(result.actor.sessionId, /^s_/);
  assert.equal(result.client, 'loopback');
  assert.match(result.requestId, /^[0-9a-f-]{36}$/);
  // The noted detail is kept beside the attempt's.
  const noted = (await ended('noted')).rows[1];
  assert.deepEqual(noted.detail, { ifMatch: true });

  // An operation's row, after the answer.
  const operation = await ended('operation');
  assert.deepEqual(summary(operation.rows), [
    ['operation', 'sources.refresh', 'failed', 422, null],
  ]);
  // Several: ended in the order they were made.
  const order = await ended('order');
  assert.deepEqual(
    order.rows.map(row => [row.mode, row.action]),
    [
      ['attempt', 'settings.update'],
      ['attempt', 'channel.resume'],
      ['result', 'settings.update'],
      ['result', 'channel.resume'],
    ]
  );

  // No answer (the client went away): no status, `failed` unless noted, client_closed.
  const abandon = async (name, rows) => {
    waiting = gate();
    const from = audit.rows.length;
    const request = http.request({
      host: '127.0.0.1',
      port,
      method: 'POST',
      path: `/api/stage/${name}`,
      headers: {
        Host: `127.0.0.1:${port}`,
        Cookie: cookie,
        'X-Goblin-Request': '1',
        'Content-Type': 'application/json',
        Origin: origin,
        'Sec-Fetch-Site': 'same-origin',
      },
    });
    request.on('error', () => {});
    request.end('{}');
    await waiting.promise;
    request.destroy();
    await until(() => audit.rows.length >= from + rows, `the rows of ${name}`);
    return audit.rows.slice(from).map(row => [row.mode, row.outcome, row.status, row.detail?.code]);
  };
  assert.deepEqual(await abandon('gone', 2), [
    ['attempt', 'attempt', null, undefined],
    ['result', 'failed', null, 'client_closed'],
  ]);
  assert.deepEqual(await abandon('gone-operation', 1), [
    ['operation', 'ok', null, 'client_closed'],
  ]);

  // Recording otherwise than the route's kind declares: 500, and no row.
  for (const name of ['undeclared', 'none', 'single']) {
    const { answer, rows } = await ended(name);
    assert.equal(answer.status, 500, name);
    assert.deepEqual(rows, [], name);
  }
});

test('fail closed: when the attempt row cannot be written nothing is changed, sent or shown (503 audit_unavailable)', async t => {
  const logged = [];
  t.mock.method(console, 'error', (...args) => logged.push(args.join(' ')));
  const s = await serveAudited(t);
  const cookie = await s.signIn();
  const { uid } = s.alerting.add({
    channel: 'env-webhook',
    status: 'failed',
    alert: { service: 'plex' },
  });
  s.alerting.setChannel('email', { state: 'paused', pausedReason: 'The mail server refused.' });
  const before = fs.readFileSync(s.config.file);
  const revision = s.config.value.revision;
  const rows = s.audit.rows.length;
  s.audit.setFailing('begin', unavailable());
  const changes = [
    ['PATCH', '/api/settings', { title: 'Not saved' }],
    ['POST', '/api/services', jsonSource],
    ['PATCH', '/api/services/linux', { name: 'Not renamed' }],
    ['DELETE', '/api/services/linux', undefined],
    ['POST', `/api/notifications/deliveries/${uid}/retry`, {}],
    ['POST', '/api/notifications/channels/email/resume', {}],
  ];
  for (const [method, target, body] of changes) {
    const answer = await s.page(cookie, method, target, { body });
    assertAuditError(answer, 'audit_unavailable');
    assert.doesNotMatch(answer.body, /PRIVATE KEY/, `${target}: no key`);
  }
  // The webhook's public key is a read Uptime Goblin does not record: it is answered all the same.
  const publicKey = await s.page(cookie, 'GET', '/api/notifications/webhook/public-key');
  assert.equal(publicKey.status, 200);
  assert.doesNotMatch(publicKey.body, /PRIVATE KEY/);
  assert.deepEqual(fs.readFileSync(s.config.file), before, 'config.json byte-identical');
  assert.equal(s.config.value.revision, revision);
  const serviceCalls = s.alerting.calls.map(([name]) => name);
  for (const name of ['retry', 'resume'])
    assert.ok(!serviceCalls.includes(name), `${name} was never called`);
  assert.deepEqual(
    s.calls.filter(([name]) => name === 'history.forget'),
    [],
    'no history deleted'
  );
  assert.equal(s.audit.rows.length, rows, 'no row of any kind');
  // The cause, a full disk, was reported to the storage guard (§4.8).
  assert.ok(s.guard.noted.length >= changes.length);
  assert.ok(s.guard.noted.every(error => error.class === 'full'));

  // An export's row: neither export is sent.
  s.audit.setFailing('begin', null);
  s.audit.setFailing('single', unavailable());
  for (const target of ['/api/config/export', '/api/audit/export?format=csv']) {
    const answer = await s.page(cookie, 'GET', target);
    assertAuditError(answer, 'audit_unavailable');
    assert.equal(answer.headers['content-disposition'], undefined, target);
  }
  assert.equal(s.audit.rows.length, rows);
  // One line on stderr for each refused request: why (the cause's code or class), never the
  // cause's text.
  const refusals = logged.filter(line =>
    line.startsWith('Request refused: Uptime Goblin could not write its audit log:')
  );
  assert.equal(refusals.length, changes.length + 2, logged.join('\n'));
  for (const line of refusals) {
    assert.match(line, /log: full /);
    assert.doesNotMatch(line, /database or disk/);
  }
});

test('operations under failure: a source test, a test email and a refresh answer as without the audit, their rows on stderr', async t => {
  const s = await serveAudited(t);
  const cookie = await s.signIn();
  s.config.updateGlobal(emailSettings);
  // Every write of the audit fails: an operation needs none before it runs (unlike a change or
  // an export, which fail closed), and its own row is lost to stderr.
  for (const kind of ['operation', 'begin', 'single', 'append', 'system'])
    s.audit.setFailing(kind, diskFull());
  const tested = await s.page(cookie, 'POST', '/api/test-service', {
    body: { settings: jsonSource },
  });
  assert.equal(tested.status, 200, tested.body);
  const mailed = await s.page(cookie, 'POST', '/api/email/test', { body: {} });
  assert.equal(mailed.status, 200, mailed.body);
  const refreshed = await s.page(cookie, 'POST', '/api/refresh', { body: {} });
  assert.equal(refreshed.status, 202, refreshed.body);
  assert.deepEqual(
    s.audit.unwritten.map(row => [row.action, row.outcome, row.status]),
    [
      ['source.test', 'ok', 200],
      ['email.test', 'ok', 200],
      ['sources.refresh', 'ok', 202],
    ]
  );
  assert.deepEqual(
    s.audit.rows.filter(row => row.mode === 'operation'),
    []
  );
});

test('operation rows: a source test per result, the test email per answer, a refresh; refused and coalesced requests write none', async t => {
  let collect = async () => [{ key: 'up', label: 'Up', value: 1, unit: '' }];
  let send = async () => ({ accepted: true, acceptedAt: 1 });
  const s = await serveAudited(t, {
    collect: (service, signal) => collect(service, signal),
    send: () => send(),
  });
  const cookie = await s.signIn();
  const operations = () => s.audit.rows.filter(row => row.mode === 'operation');
  const testSource = body => s.page(cookie, 'POST', '/api/test-service', { body });

  assert.equal((await testSource({ settings: jsonSource })).status, 200);
  let row = operations().at(-1);
  assert.deepEqual(
    [row.action, row.outcome, row.status, row.target, row.detail],
    [
      'source.test',
      'ok',
      200,
      { type: 'source', id: null, name: 'API' },
      { type: 'json', savedCredentials: false, result: 'connected', credentialsCleared: false },
    ]
  );
  // A saved source with credentials: named by its id; never its address or the credential.
  s.config.update('radarr', { apiUrl: 'https://radarr.example.test', apiKey: 'fixture-saved-key' });
  assert.equal(
    (await testSource({ serviceId: 'radarr', settings: { name: 'Radarr' } })).status,
    200
  );
  row = operations().at(-1);
  assert.deepEqual([row.target.id, row.detail.savedCredentials], ['radarr', true]);
  assert.doesNotMatch(JSON.stringify(row), /fixture-saved-key|radarr\.example\.test/);
  // Tested as a website check on another server: the saved credential is not sent, and noted.
  const moved = await testSource({
    serviceId: 'radarr',
    settings: { collector: 'http', apiUrl: 'https://www.example.test' },
  });
  assert.equal(moved.status, 200, moved.body);
  assert.equal(operations().at(-1).detail.credentialsCleared, true);

  collect = async () => {
    throw new Error('connect ECONNREFUSED https://user:pw@api.example.test');
  };
  assert.equal((await testSource({ settings: jsonSource })).status, 422);
  row = operations().at(-1);
  assert.deepEqual([row.outcome, row.status, row.detail.result], ['failed', 422, 'failed']);
  assert.doesNotMatch(JSON.stringify(row), /ECONNREFUSED|user:pw/);
  collect = async () => {
    throw new Error(
      'Collection exceeded its time limit. Try fewer devices or a more focused source.'
    );
  };
  assert.equal((await testSource({ settings: jsonSource })).status, 422);
  assert.equal(operations().at(-1).detail.result, 'timeout');

  // Two tests already running: the third is refused (429) and writes nothing.
  const held = gate();
  collect = () => held.promise.then(() => []);
  const first = testSource({ settings: jsonSource }),
    second = testSource({ settings: jsonSource });
  await until(() => s.tests.size === 2, 'two running tests');
  const before = s.audit.rows.length;
  assert.equal((await testSource({ settings: jsonSource })).status, 429);
  held.open();
  await Promise.all([first, second]);
  assert.equal(s.audit.rows.length, before + 2, 'the two tests, not the refused one');

  // A refresh; a coalesced click within 5 s writes nothing.
  assert.equal((await s.page(cookie, 'POST', '/api/refresh', { body: {} })).status, 202);
  assert.deepEqual(summary([operations().at(-1)]), [
    ['operation', 'sources.refresh', 'ok', 202, null],
  ]);
  assert.deepEqual(operations().at(-1).target, { type: 'sources', id: '*', name: null });
  const count = operations().length;
  const coalesced = await s.page(cookie, 'POST', '/api/refresh', { body: {} });
  assert.equal(coalesced.json.coalesced, true);
  assert.equal(operations().length, count);

  // The test email: its outcome is its answer's.
  s.config.updateGlobal(emailSettings);
  const mail = async () => {
    s.advance(60000);
    const answer = await s.page(cookie, 'POST', '/api/email/test', { body: {} });
    return [answer.status, operations().at(-1)];
  };
  let [status, mailed] = await mail();
  assert.deepEqual(
    [status, mailed.action, mailed.outcome, mailed.detail],
    [200, 'email.test', 'ok', { accepted: true }]
  );
  assert.deepEqual(mailed.target, { type: 'channel', id: 'email', name: null });
  send = async () => {
    throw Object.assign(new Error('535 authentication failed for fixture-audit-email-password'), {
      code: 'EAUTH',
    });
  };
  [status, mailed] = await mail();
  assert.deepEqual([status, mailed.outcome, mailed.detail], [422, 'failed', { accepted: false }]);
  // The provider's text, not a bare 535: the row's time, id and session id are digits too.
  assert.doesNotMatch(JSON.stringify(mailed), /535 authentication|fixture-audit-email-password/);
  send = async () => {
    throw Object.assign(new Error('busy'), { code: 'EMAIL_BUSY' });
  };
  [status, mailed] = await mail();
  assert.deepEqual([status, mailed.outcome, mailed.detail], [429, 'denied', null]);
  send = async () => ({ accepted: false });
  [status, mailed] = await mail();
  assert.deepEqual([status, mailed.outcome], [409, 'conflict']);
  // Within the minute: refused before anything is sent, and not recorded.
  const recorded = operations().length;
  assert.equal((await s.page(cookie, 'POST', '/api/email/test', { body: {} })).status, 429);
  assert.equal(operations().length, recorded);
});

test('aborted test: a connection test whose browser went away is recorded with no status and client_closed', async t => {
  const started = gate();
  const s = await serveAudited(t, {
    collect: (service, signal) =>
      new Promise((resolve, reject) => {
        started.open();
        signal.addEventListener('abort', () => reject(new Error('aborted')));
      }),
  });
  const cookie = await s.signIn();
  const request = http.request({
    host: '127.0.0.1',
    port: s.port,
    method: 'POST',
    path: '/api/test-service',
    headers: {
      Host: `127.0.0.1:${s.port}`,
      Cookie: cookie,
      'X-Goblin-Request': '1',
      'Content-Type': 'application/json',
      Origin: s.origin,
      'Sec-Fetch-Site': 'same-origin',
    },
  });
  request.on('error', () => {});
  request.end(JSON.stringify({ settings: jsonSource }));
  await started.promise;
  request.destroy();
  await until(() => s.rowsOf('source.test').length === 1, 'the source.test row');
  const [row] = s.rowsOf('source.test');
  assert.deepEqual(
    [row.outcome, row.status, row.detail.code, row.detail.result],
    ['failed', null, 'client_closed', 'failed']
  );
});

// Holds the fake audit's begin() until the gate opens; resolves once it was called.
function holdBegin(audit) {
  const held = gate(),
    called = gate();
  const begin = audit.begin;
  audit.begin = async (...args) => {
    called.open();
    await held.promise;
    audit.begin = begin;
    return begin(...args);
  };
  return { called: called.promise, release: held.open };
}

test('sign-out during begin: the change ends denied (401) and nothing is applied', async t => {
  const s = await serveAudited(t);
  const cookie = await s.signIn();
  const before = fs.readFileSync(s.config.file);
  const held = holdBegin(s.audit);
  const change = s.page(cookie, 'PATCH', '/api/settings', { body: { title: 'Not saved' } });
  await held.called;
  assert.equal((await s.page(cookie, 'POST', '/api/auth/logout', { body: {} })).status, 204);
  held.release();
  const answer = await change;
  assert.equal(answer.status, 401);
  assert.deepEqual(fs.readFileSync(s.config.file), before, 'nothing applied');
  assert.deepEqual(summary(s.rowsOf('settings.update')), [
    ['attempt', 'settings.update', 'attempt', null, null],
    ['result', 'settings.update', 'denied', 401, answer.json.code],
  ]);

  // The same for a Retry: the service is never called.
  const again = await s.signIn();
  const { uid } = s.alerting.add({
    channel: 'env-webhook',
    status: 'failed',
    alert: { service: 'plex' },
  });
  const retry = holdBegin(s.audit);
  const retried = s.page(again, 'POST', `/api/notifications/deliveries/${uid}/retry`, { body: {} });
  await retry.called;
  assert.equal((await s.page(again, 'POST', '/api/auth/logout', { body: {} })).status, 204);
  retry.release();
  assert.equal((await retried).status, 401);
  assert.ok(!s.alerting.calls.some(([name]) => name === 'retry'));
  assert.equal(s.rowsOf('delivery.retry').at(-1).outcome, 'denied');

  // And for a Resume (review round 1): the paused channel stays paused, what it held stays
  // held, and the result says denied 401, never "ok 200" for an answer that was a 401.
  s.alerting.setChannel('env-webhook', {
    state: 'paused',
    pausedReason: 'The webhook answered 401.',
  });
  s.alerting.add({ channel: 'env-webhook', status: 'paused', alert: { service: 'plex' } });
  const third = await s.signIn();
  const resume = holdBegin(s.audit);
  const resumed = s.page(third, 'POST', '/api/notifications/channels/env-webhook/resume', {
    body: {},
  });
  await resume.called;
  assert.equal((await s.page(third, 'POST', '/api/auth/logout', { body: {} })).status, 204);
  resume.release();
  const resumeAnswer = await resumed;
  assert.equal(resumeAnswer.status, 401);
  assert.ok(!s.alerting.calls.some(([name]) => name === 'resume'), 'resume never called');
  assert.deepEqual(summary(s.rowsOf('channel.resume')), [
    ['attempt', 'channel.resume', 'attempt', null, null],
    ['result', 'channel.resume', 'denied', 401, resumeAnswer.json.code],
  ]);
});

test('abandoned during begin: a client that leaves while its attempt is written changes nothing (MEC-6)', async t => {
  const s = await serveAudited(t);
  const cookie = await s.signIn();
  const before = fs.readFileSync(s.config.file);
  const held = holdBegin(s.audit);
  const request = http.request({
    host: '127.0.0.1',
    port: s.port,
    method: 'PATCH',
    path: '/api/settings',
    headers: {
      Host: `127.0.0.1:${s.port}`,
      Cookie: cookie,
      'X-Goblin-Request': '1',
      'Content-Type': 'application/json',
      Origin: s.origin,
      'Sec-Fetch-Site': 'same-origin',
    },
  });
  request.on('error', () => {});
  request.end(JSON.stringify({ title: 'Not saved' }));
  await held.called;
  request.destroy();
  // The server sees the connection close.
  await new Promise(resolve => setTimeout(resolve, 50));
  held.release();
  await until(() => s.rowsOf('settings.update').length === 2, 'the result row');
  assert.deepEqual(fs.readFileSync(s.config.file), before, 'config.json unchanged');
  assert.deepEqual(summary(s.rowsOf('settings.update')), [
    ['attempt', 'settings.update', 'attempt', null, null],
    ['result', 'settings.update', 'failed', null, 'client_closed'],
  ]);
});

test('replays write nothing: a keyed change sent twice, or joined, has one attempt and one result; a key reused with another body none', async t => {
  const s = await serveAudited(t);
  const cookie = await s.signIn();
  const keyed = (key, body) =>
    s.page(cookie, 'PATCH', '/api/settings', { body, lines: [`Idempotency-Key: ${key}`] });
  assert.equal((await keyed('replay-key-1', { title: 'One' })).status, 200);
  const replayed = await keyed('replay-key-1', { title: 'One' });
  assert.equal(replayed.headers['idempotent-replayed'], 'true');
  assert.equal(s.rowsOf('settings.update').length, 2, 'one attempt, one result');
  // Joined: the second waits for the first and is answered from it.
  const held = holdBegin(s.audit);
  const first = keyed('replay-key-2', { title: 'Two' });
  await held.called;
  const joined = keyed('replay-key-2', { title: 'Two' });
  await new Promise(resolve => setTimeout(resolve, 20));
  held.release();
  assert.equal((await first).status, 200);
  assert.equal((await joined).headers['idempotent-replayed'], 'true');
  assert.equal(s.rowsOf('settings.update').length, 4);
  // The same key with another body: 422, no row.
  assert.equal((await keyed('replay-key-2', { title: 'Other' })).status, 422);
  assert.equal(s.rowsOf('settings.update').length, 4);
});

test('A62: a Retry and a rotation applied as their session ended are recorded ok; the retry signed in again replays with no new row', async t => {
  const s = await serveAudited(t);
  const cookie = await s.signIn();
  const { uid } = s.alerting.add({
    channel: 'env-webhook',
    status: 'failed',
    alert: { service: 'plex' },
  });
  // The write is applied, then the service call is held while the session ends. (A session that
  // ends before the service applies it stops it: nothing is requeued or replaced, see
  // http-pipeline/sessions.test.mjs.)
  const hold = (service, name) => {
    const held = gate(),
      called = gate();
    const original = service[name];
    service[name] = async (...args) => {
      const result = await original(...args);
      called.open();
      await held.promise;
      return result;
    };
    return { called: called.promise, release: held.open };
  };
  const retry = hold(s.alerting, 'retry');
  const retryPath = `/api/notifications/deliveries/${uid}/retry`;
  const keyed = (session, target) =>
    s.page(session, 'POST', target, { body: {}, lines: ['Idempotency-Key: a62-key-0001'] });
  const answered = keyed(cookie, retryPath);
  await retry.called;
  assert.equal((await s.page(cookie, 'POST', '/api/auth/logout', { body: {} })).status, 204);
  retry.release();
  assert.equal((await answered).status, 401);
  assert.deepEqual(summary(s.rowsOf('delivery.retry')), [
    ['attempt', 'delivery.retry', 'attempt', null, null],
    ['result', 'delivery.retry', 'ok', 200, 'session_expired'],
  ]);
  assert.deepEqual(s.rowsOf('delivery.retry')[1].detail, { retried: 1, code: 'session_expired' });
  const again = await s.signIn();
  const replayed = await keyed(again, retryPath);
  assert.equal(replayed.status, 200);
  assert.equal(replayed.headers['idempotent-replayed'], 'true');
  assert.equal(s.rowsOf('delivery.retry').length, 2, 'no new row for the replay');

  // The rotation: its row is in the settings unit, so it exists once the secret is replaced.
  const rotate = hold(s.alerting.signing, 'rotate');
  const rotation = s.page(again, 'POST', '/api/notifications/webhook/signing-secret', {
    body: {},
    lines: ['Idempotency-Key: a62-key-0002'],
  });
  await rotate.called;
  assert.equal((await s.page(again, 'POST', '/api/auth/logout', { body: {} })).status, 204);
  rotate.release();
  assert.equal((await rotation).status, 401);
  const third = await s.signIn();
  const rotatedAgain = await s.page(third, 'POST', '/api/notifications/webhook/signing-secret', {
    body: {},
    lines: ['Idempotency-Key: a62-key-0002'],
  });
  assert.equal(rotatedAgain.headers['idempotent-replayed'], 'true');
  const rotated = s.rowsOf('signing.rotate');
  assert.deepEqual(summary(rotated), [['record', 'signing.rotate', 'ok', null, null]]);
  assert.deepEqual(rotated[0].target, { type: 'secret', id: 'env-webhook', name: null });
  // The diff in the path form, private keys only as changed or set (never a key).
  assert.deepEqual(
    rotated[0].detail.diff.filter(entry => entry.change).map(entry => [entry.path, entry.change]),
    [
      ['signingKey', 'changed'],
      ['previousSigningKey', 'set'],
    ]
  );
  assert.doesNotMatch(JSON.stringify(rotated), /a1a1a1a1/);
  assert.equal(rotated[0].actor.via, 'session');
});

// The other side of A62: a session that ends before Retry or Resume acted stops them. The routes
// hand the service their session check, which it runs right before the requeue or the release.
test('Retry and Resume whose session ends before they act: 401, nothing requeued or released, recorded as denied', async t => {
  const s = await serveAudited(t);
  let cookie = await s.signIn();
  const { uid } = s.alerting.add({
    channel: 'env-webhook',
    status: 'failed',
    alert: { service: 'plex' },
  });
  s.alerting.setChannel('email', { state: 'paused', pausedReason: 'Sign-in failed.' });
  const holdBefore = (service, name) => {
    const held = gate(),
      called = gate();
    const original = service[name];
    service[name] = async (...args) => {
      service[name] = original;
      called.open();
      await held.promise;
      return original(...args);
    };
    return { called: called.promise, release: held.open };
  };
  for (const [name, path, action] of [
    ['retry', `/api/notifications/deliveries/${uid}/retry`, 'delivery.retry'],
    ['resume', '/api/notifications/channels/email/resume', 'channel.resume'],
  ]) {
    const hold = holdBefore(s.alerting, name);
    const answered = s.page(cookie, 'POST', path, { body: {} });
    await hold.called;
    assert.equal((await s.page(cookie, 'POST', '/api/auth/logout', { body: {} })).status, 204);
    hold.release();
    const answer = await answered;
    assert.deepEqual([answer.status, answer.json.code], [401, 'session_expired'], name);
    assert.deepEqual(summary(s.rowsOf(action)), [
      ['attempt', action, 'attempt', null, null],
      ['result', action, 'denied', 401, 'session_expired'],
    ]);
    cookie = await s.signIn();
  }
  const listed = (await s.alerting.deliveries({})).deliveries.find(item => item.uid === uid);
  assert.equal(listed.status, 'failed', 'not requeued');
  assert.equal(
    s.alerting.snapshot().channels.find(channel => channel.id === 'email').state,
    'paused',
    'not resumed'
  );
});

test('the public key is read without an audit row; the rotation row never holds a key', async t => {
  const s = await serveAudited(t);
  const cookie = await s.signIn();
  const rows = s.audit.rows.length;
  const first = await s.page(cookie, 'GET', '/api/notifications/webhook/public-key');
  assert.equal(first.status, 200);
  assert.equal(first.json.algorithm, 'Ed25519');
  assert.equal(s.audit.rows.length, rows, 'reading the public key records nothing');
  assert.equal(s.rowsOf('signing.reveal').length, 0);
  const rotated = await s.page(cookie, 'POST', '/api/notifications/webhook/signing-secret', {
    body: {},
  });
  assert.equal(rotated.status, 200);
  const second = await s.page(cookie, 'GET', '/api/notifications/webhook/public-key');
  assert.equal(second.json.previous.keyId, first.json.keyId);
  const recorded = JSON.stringify(s.audit.rows);
  assert.doesNotMatch(recorded, /PRIVATE KEY|PUBLIC KEY/);
  for (const answer of [first, second]) {
    assert.doesNotMatch(answer.body, /PRIVATE KEY/);
    assert.equal(recorded.includes(answer.json.publicKeyRaw), false);
  }
});

test('the configuration writes record their attempt and result with what only the task knows', async t => {
  const s = await serveAudited(t);
  const cookie = await s.signIn();
  const revision = s.config.value.revision;
  // A source added: the result names its id; the attempt only the name asked for.
  const added = await s.page(cookie, 'POST', '/api/services', { body: jsonSource });
  assert.equal(added.status, 201, added.body);
  let [attempt, result] = s.rowsOf('source.create');
  assert.deepEqual(attempt.target, { type: 'source', id: null, name: 'API' });
  assert.equal(attempt.configRevision, revision);
  assert.deepEqual(result.target, { type: 'source', id: added.json.service.id, name: 'API' });
  assert.deepEqual(
    [result.outcome, result.status, result.configRevision],
    ['ok', 201, revision + 1]
  );
  assert.deepEqual(attempt.detail, { ifMatch: false });
  // A stale If-Match: a conflict, nothing applied.
  const stale = await s.page(cookie, 'PATCH', '/api/settings', {
    body: { title: 'Stale' },
    lines: [`If-Match: "${revision}"`],
  });
  assert.equal(stale.status, 409);
  [attempt, result] = s.rowsOf('settings.update');
  assert.deepEqual(attempt.detail, { ifMatch: true });
  assert.deepEqual([result.outcome, result.status], ['conflict', 409]);
  // A source changed and one deleted: their names, and the history deletion noted.
  const linuxName = s.config.get('linux').name;
  assert.equal(
    (await s.page(cookie, 'PATCH', '/api/services/linux', { body: { name: 'Linux 2' } })).status,
    200
  );
  [attempt, result] = s.rowsOf('source.update');
  assert.deepEqual(attempt.target, { type: 'source', id: 'linux', name: linuxName });
  assert.equal(result.outcome, 'ok');
  // A website check moved to another server: its saved credential is dropped, and noted.
  s.config.update('sonarr', { apiUrl: 'https://sonarr.example.test', apiKey: 'fixture-key' });
  const moved = await s.page(cookie, 'PATCH', '/api/services/sonarr', {
    body: { collector: 'http', apiUrl: 'https://www.example.test' },
  });
  assert.equal(moved.status, 200, moved.body);
  assert.deepEqual(s.rowsOf('source.update').at(-1).detail, {
    ifMatch: false,
    credentialsCleared: true,
  });
  // A source deleted while its change waited for its attempt row: 404 inside the turn, failed.
  const held = holdBegin(s.audit);
  const gone = s.page(cookie, 'PATCH', '/api/services/sonarr', { body: { name: 'Gone' } });
  await held.called;
  s.config.remove('sonarr');
  held.release();
  assert.equal((await gone).status, 404);
  assert.deepEqual(
    [s.rowsOf('source.update').at(-1).outcome, s.rowsOf('source.update').at(-1).status],
    ['failed', 404]
  );
  assert.equal((await s.page(cookie, 'DELETE', '/api/services/linux')).status, 200);
  [attempt, result] = s.rowsOf('source.delete');
  assert.deepEqual(attempt.target, { type: 'source', id: 'linux', name: 'Linux 2' });
  assert.deepEqual(
    [result.outcome, result.detail],
    ['ok', { ifMatch: false, historyDeleted: true }]
  );
  // A full disk refuses before the attempt: no row at all (D7).
  s.guard.setFull(true);
  const rows = s.audit.rows.length;
  const refused = await s.page(cookie, 'PATCH', '/api/settings', { body: { title: 'Full' } });
  assert.equal(refused.status, 503);
  assert.equal(refused.json.code, 'storage_full');
  assert.equal(s.audit.rows.length, rows, 'no attempt row for a write the full disk refused');
  const rotation = await s.page(cookie, 'POST', '/api/notifications/webhook/signing-secret', {
    body: {},
  });
  assert.equal(rotation.status, 503);
  assert.equal(s.audit.rows.length, rows, 'nor for a rotation');
});

test('malformed configuration writes are refused before an attempt row is written', async t => {
  const s = await serveAudited(t);
  const cookie = await s.signIn();
  const malformed = [
    ['PATCH', '/api/settings', []],
    ['PATCH', '/api/settings', { pollSeconds: 'x' }],
    ['PATCH', '/api/settings', { title: '' }],
    ['PATCH', '/api/settings', { email: { port: 70000 } }],
    ['POST', '/api/services', { type: 'link', name: 'n'.repeat(500), group: 'g' }],
    ['POST', '/api/services', { type: 'no-such-type', name: 'n', group: 'g' }],
    ['POST', '/api/services', { ...jsonSource, apiUrl: 'ftp://api.example.test' }],
    ['PATCH', '/api/services/linux', { pollSeconds: 5 }],
    ['PATCH', '/api/services/linux', { type: 'json' }],
    ['PATCH', '/api/services/linux', { metrics: [{ key: 'cpu', path: 'node_load5' }] }],
  ];
  const check = async what => {
    const rows = s.audit.rows.length,
      before = fs.readFileSync(s.config.file);
    for (const [method, target, body] of malformed) {
      const answer = await s.page(cookie, method, target, { body });
      const where = `${what}: ${method} ${target} ${JSON.stringify(body)}`;
      assert.equal(answer.status, 400, `${where} -> ${answer.status} ${answer.body}`);
    }
    // No attempt or result row, and nothing saved: the write never took its turn.
    assert.equal(s.audit.rows.length, rows, what);
    assert.deepEqual(fs.readFileSync(s.config.file), before, what);
  };
  await check('a disk with space');
  // A full disk refuses a valid write (503 storage_full), but a malformed one is still the
  // client's mistake: 400, not "the disk is full", and still no row.
  s.guard.setFull(true);
  await check('a full disk');
  const valid = await s.page(cookie, 'PATCH', '/api/settings', { body: { title: 'Full' } });
  assert.equal(valid.status, 503);
  assert.equal(valid.json.code, 'storage_full');
});

test('refusals counted: every refused sign-in, password change and Basic request once, the login name only as its class', async t => {
  const s = await serveAudited(t);
  const counts = () => s.audit.counts;
  const last = () => counts().at(-1);
  const signIn = (body, lines = browserWrite(s.origin)) =>
    raw(s.port, ['POST /api/auth/login HTTP/1.1', ...lines], JSON.stringify(body));
  const wrong = 'wrong-password-sentinel-1';
  assert.equal((await signIn({ login: 'admin', password: wrong })).status, 401);
  assert.deepEqual(
    [last().action, last().outcome, last().login, last().detail, last().client],
    ['session.login', 'failed', 'admin', { code: 'invalid_credentials' }, 'loopback']
  );
  // A password typed into the name field is kept only as `other`.
  assert.equal((await signIn({ login: wrong, password: wrong })).status, 401);
  assert.equal(last().login, 'other');
  assert.equal((await signIn({ login: 5 })).status, 400);
  assert.deepEqual(
    [last().outcome, last().detail.code, last().login],
    ['denied', 'invalid_request', null]
  );
  // The cross-origin refusal no handler sees: counted by the pipeline, with no name.
  const crossed = await signIn({ login: 'admin', password: wrong }, [
    'Content-Type: application/json',
    'Origin: http://evil.example.test',
  ]);
  assert.equal(crossed.status, 403);
  assert.deepEqual([last().detail.code, last().login], ['cross_origin', null]);
  assert.equal(counts().length, 4, 'each refusal counted once');
  // Until locked: each refusal once, the lockout's too.
  let answer;
  for (let i = 0; i < 20 && answer?.status !== 429; i++)
    answer = await signIn({ login: 'admin', password: wrong });
  assert.equal(answer.status, 429);
  assert.deepEqual([last().outcome, last().detail.code], ['denied', 'locked']);
  assert.equal(counts().length, 4 + counts().filter((c, i) => i >= 4).length);
  assert.ok(counts().every(c => c.action === 'session.login'));
  assert.doesNotMatch(JSON.stringify(counts()), new RegExp(wrong));

  // A fresh Uptime Goblin: the password change and Basic.
  const p = await serveAudited(t);
  const cookie = await p.signIn();
  const change = (body, lines) => p.page(cookie, 'POST', '/api/account/password', { body, lines });
  const pass = {
    currentPassword: wrong,
    password: 'a-new-password-1',
    confirmPassword: 'a-new-password-1',
  };
  assert.equal((await change(pass)).status, 403);
  let counted = p.audit.counts.at(-1);
  assert.deepEqual(
    [counted.action, counted.outcome, counted.detail, counted.actor.via],
    ['account.password.changed', 'failed', { code: 'current_password_incorrect' }, 'session']
  );
  const mismatch = {
    currentPassword: password,
    password: 'a-new-password-1',
    confirmPassword: 'another-one-22',
  };
  assert.equal((await change(mismatch)).status, 400);
  assert.deepEqual(
    [p.audit.counts.at(-1).outcome, p.audit.counts.at(-1).detail.code],
    ['denied', 'password_mismatch']
  );
  // Cross-origin, refused before the handler: counted once by the pipeline, as the admin.
  const crossOrigin = await raw(
    p.port,
    [
      'POST /api/account/password HTTP/1.1',
      `Cookie: ${cookie}`,
      'Content-Type: application/json',
      'X-Goblin-Request: 1',
    ],
    JSON.stringify(pass)
  );
  assert.equal(crossOrigin.status, 403);
  counted = p.audit.counts.at(-1);
  assert.deepEqual([counted.detail.code, counted.actor.sessionId !== null], ['cross_origin', true]);
  assert.equal(p.audit.counts.length, 3);
  assert.doesNotMatch(JSON.stringify(p.audit.counts), new RegExp(wrong));

  // Basic: failures with the name's class, use by the admin.
  const before = p.audit.counts.length;
  assert.equal((await p.script('GET', '/api/dashboard', { credential: basic(wrong) })).status, 401);
  counted = p.audit.counts.at(-1);
  assert.deepEqual(
    [counted.action, counted.outcome, counted.login, counted.detail],
    ['auth.basic.failed', 'failed', 'admin', { code: 'invalid_credentials' }]
  );
  const root = 'Basic ' + Buffer.from(`root:${wrong}`).toString('base64');
  assert.equal((await p.script('GET', '/api/dashboard', { credential: root })).status, 401);
  assert.deepEqual(
    [p.audit.counts.at(-1).login, p.audit.counts.at(-1).detail.code],
    ['other', 'invalid_credentials']
  );
  const both = await raw(p.port, [
    'GET /api/dashboard HTTP/1.1',
    `Authorization: ${basic()}`,
    `Cookie: ${cookie}`,
  ]);
  assert.equal(both.status, 401);
  assert.equal(p.audit.counts.at(-1).detail.code, 'multiple_credentials');
  assert.equal((await p.script('GET', '/api/dashboard')).status, 200);
  counted = p.audit.counts.at(-1);
  assert.deepEqual(
    [counted.action, counted.outcome, counted.actor.via, counted.actor.id],
    ['auth.basic.used', 'ok', 'basic', 'u_admin']
  );
  assert.equal(p.audit.counts.length, before + 4);
  // The password changed: the old one, within its day, is `retired_password` (not a guess).
  const changed = {
    currentPassword: password,
    password: 'a-new-password-1',
    confirmPassword: 'a-new-password-1',
  };
  assert.equal((await change(changed)).status, 200);
  assert.equal(
    (await p.script('GET', '/api/dashboard', { credential: basic(password) })).status,
    401
  );
  counted = p.audit.counts.at(-1);
  assert.deepEqual(
    [counted.action, counted.outcome, counted.detail.code],
    ['auth.basic.failed', 'denied', 'retired_password']
  );
  assert.doesNotMatch(
    JSON.stringify(p.audit.counts),
    new RegExp(`${wrong}|${password}|a-new-password-1`)
  );

  // Basic switched off: basic_disabled.
  const off = await serveAudited(t, { legacyBasic: false });
  assert.equal((await off.script('GET', '/api/dashboard')).status, 401);
  assert.deepEqual(
    [off.audit.counts.at(-1).action, off.audit.counts.at(-1).detail.code],
    ['auth.basic.failed', 'basic_disabled']
  );

  // A Bearer credential is no Basic one: neither a cookie beside it nor its lockout is counted
  // into auth.basic.failed (each Bearer try is a guess, so the client is soon locked).
  const other = await serveAudited(t);
  const otherCookie = await other.signIn();
  const bearer = 'Bearer not-a-basic-credential';
  const beside = await raw(other.port, [
    'GET /api/dashboard HTTP/1.1',
    `Authorization: ${bearer}`,
    `Cookie: ${otherCookie}`,
  ]);
  assert.equal(beside.json.code, 'multiple_credentials');
  let refusal;
  for (let i = 0; i < 10 && refusal?.json?.code !== 'locked'; i++)
    refusal = await other.script('GET', '/api/dashboard', { credential: bearer });
  assert.equal(refusal.json.code, 'locked');
  assert.deepEqual(
    other.audit.counts.filter(c => c.action === 'auth.basic.failed'),
    [],
    'no Basic refusal'
  );
});

// Independent review A5: the password change's refusals made before its credential signed in (none
// sent, an ended session, two cookies, another site's page, a Bearer header) escaped the count
// spec §5.2 promises: only the refusals of the signed-in part were counted.
test('Independent review A5: password-change refusals before sign-in are counted once, as nobody signed in; the answers stay as they were', async t => {
  const s = await serveAudited(t);
  const cookie = await s.signIn();
  const pass = {
    currentPassword: 'synthetic-current',
    password: 'synthetic-next-0001',
    confirmPassword: 'synthetic-next-0001',
  };
  const anonymous = { type: 'anonymous', id: null, name: null, via: null, sessionId: null };
  const changes = () => s.audit.counts.filter(c => c.action === 'account.password.changed');
  // Sends `lines` (after the request line) to `target`; resolves the answer and what it added.
  const send = async (target, lines) => {
    const before = s.audit.counts.length;
    const answer = await raw(s.port, [`POST ${target} HTTP/1.1`, ...lines], JSON.stringify(pass));
    return { answer, added: s.audit.counts.slice(before) };
  };
  const counted = (added, code, outcome = 'denied') => {
    assert.equal(added.length, 1, `${code}: counted once`);
    const [event] = added;
    assert.deepEqual(
      [event.action, event.outcome, event.actor, event.detail, event.client, event.login],
      ['account.password.changed', outcome, anonymous, { code }, 'loopback', null],
      code
    );
  };

  // No credential (both addresses): 401 signin_required, as on a route that counts nothing.
  for (const target of ['/api/account/password', '/api/auth/password']) {
    const { answer, added } = await send(target, browserWrite(s.origin));
    assert.deepEqual([answer.status, answer.json.code], [401, 'signin_required'], target);
    counted(added, 'signin_required');
    const plain = await send('/api/services', browserWrite(s.origin));
    assert.deepEqual(plain.added, [], 'a route without refusals counts nothing');
    assert.deepEqual(
      [answer.status, answer.json, answer.headers['www-authenticate'], answer.headers.deprecation],
      [
        plain.answer.status,
        plain.answer.json,
        plain.answer.headers['www-authenticate'],
        plain.answer.headers.deprecation,
      ],
      `${target}: the same answer`
    );
  }
  // An ended session: 401 session_expired.
  const ended = await s.signIn();
  assert.equal((await s.page(ended, 'POST', '/api/auth/logout', { body: {} })).status, 204);
  let sent = await send('/api/account/password', [`Cookie: ${ended}`, ...browserWrite(s.origin)]);
  assert.deepEqual([sent.answer.status, sent.answer.json.code], [401, 'session_expired']);
  counted(sent.added, 'session_expired');
  // Two session cookies, and a page of another site of this one (the session is never read).
  sent = await send('/api/account/password', [
    `Cookie: ${cookie}; ${ended}`,
    ...browserWrite(s.origin),
  ]);
  assert.equal(sent.answer.json.code, 'multiple_credentials');
  counted(sent.added, 'multiple_credentials');
  sent = await send('/api/account/password', [
    `Cookie: ${cookie}`,
    ...browserWrite(s.origin).map(line =>
      line.startsWith('Sec-Fetch-Site') ? 'Sec-Fetch-Site: same-site' : line
    ),
  ]);
  assert.deepEqual([sent.answer.status, sent.answer.json.code], [403, 'cross_origin']);
  counted(sent.added, 'cross_origin');
  // A script's Bearer header: invalid_credentials, but no password of the change was checked.
  sent = await send('/api/account/password', [
    'Authorization: Bearer not-a-basic-credential',
    'X-Goblin-Request: 1',
    'Content-Type: application/json',
  ]);
  assert.deepEqual([sent.answer.status, sent.answer.json.code], [401, 'invalid_credentials']);
  counted(sent.added, 'invalid_credentials', 'denied');
  // A wrong Basic password is the Basic rule's: counted into auth.basic.failed, not again here.
  sent = await send('/api/account/password', [
    `Authorization: ${basic('wrong-password-sentinel-5')}`,
    'X-Goblin-Request: 1',
    'Content-Type: application/json',
  ]);
  assert.equal(sent.answer.status, 401);
  assert.deepEqual(
    sent.added.map(c => [c.action, c.detail.code]),
    [['auth.basic.failed', 'invalid_credentials']]
  );
  // Signed in, a refusal still names the session that was refused, once.
  sent = await send('/api/account/password', [`Cookie: ${cookie}`, ...browserWrite(s.origin)]);
  assert.equal(sent.answer.json.code, 'current_password_incorrect');
  assert.deepEqual(
    sent.added.map(c => [c.action, c.outcome, c.actor.type, c.actor.sessionId !== null]),
    [['account.password.changed', 'failed', 'user', true]]
  );
  assert.equal(changes().length, 7, 'two without a credential, four other refusals, one signed in');
  assert.doesNotMatch(JSON.stringify(s.audit.counts), /synthetic-current|synthetic-next/);
});

// Holds `service[name]` once until the gate opens; resolves `called` when it was called.
function holdOnce(service, name) {
  const held = gate(),
    called = gate();
  const original = service[name];
  service[name] = async (...args) => {
    called.open();
    await held.promise;
    service[name] = original;
    return original.apply(service, args);
  };
  return { called: called.promise, release: held.open };
}

test('signed out while the log or the configuration was read: 401, and nothing of it is sent', async t => {
  const s = await serveAudited(t);
  const singles = () => s.audit.rows.filter(row => row.mode === 'single').length;
  for (const [method, target] of [
    ['single', '/api/config/export'],
    ['single', '/api/audit/export?format=csv'],
    ['export', '/api/audit/export?format=csv'],
    ['list', '/api/audit'],
    ['verify', '/api/audit/verify'],
  ]) {
    const cookie = await s.signIn();
    const before = singles();
    const held = holdOnce(s.audit, method);
    const answer = s.page(cookie, 'GET', target);
    await held.called;
    assert.equal((await s.page(cookie, 'POST', '/api/auth/logout', { body: {} })).status, 204);
    held.release();
    const ended = await answer;
    assert.equal(ended.status, 401, target);
    assert.equal(ended.headers['content-disposition'], undefined, target);
    assert.deepEqual(Object.keys(ended.json).sort(), ['code', 'error', 'transport'], target);
    // Signed out while the audit export was built (review round 1): no "exported" row for a
    // session that had ended and was sent nothing. (A sign-out during single's own write cannot
    // stop that row; the answer is still a 401.)
    if (method !== 'single') assert.equal(singles(), before, `${method} ${target}: no row`);
  }
});

// Each audit export is built in memory (up to 16 MiB) from reads of the log: at most two are
// built at once, and a request beyond that is refused before anything is read or recorded.
test('at most two audit exports are built at once: another gets 503 busy, reads nothing and writes no row', async t => {
  const s = await serveAudited(t);
  const cookie = await s.signIn();
  const held = gate();
  let building = 0,
    built = 0;
  const exported = s.audit.export;
  s.audit.export = async (...args) => {
    building++;
    built++;
    await held.promise;
    building--;
    return exported(...args);
  };
  const rows = () =>
    s.audit.rows.filter(row => row.mode === 'single' && row.action === 'audit.export').length;
  const target = '/api/audit/export?format=csv';
  const first = s.page(cookie, 'GET', target),
    second = s.page(cookie, 'GET', target);
  await until(() => building === 2, 'two builds');
  // Refused at once. (Built, it would wait for the gate like the others: opened after 2 s.)
  const opening = setTimeout(held.open, 2000);
  const third = await s.page(cookie, 'GET', target);
  clearTimeout(opening);
  assert.deepEqual(
    [third.status, third.json.code, third.headers['retry-after']],
    [503, 'busy', '5']
  );
  assert.equal(third.headers['content-disposition'], undefined);
  assert.equal(built, 2, 'the third built nothing');
  assert.equal(rows(), 0, 'and recorded nothing');
  held.open();
  assert.deepEqual([(await first).status, (await second).status], [200, 200]);
  assert.equal(rows(), 2);
  // A build that fails gives its place back: three failures, then exports are built again.
  s.audit.export = async () => {
    throw auditError('audit_read_unavailable');
  };
  for (let n = 0; n < 3; n++)
    assert.equal((await s.page(cookie, 'GET', target)).json.code, 'audit_read_unavailable');
  s.audit.export = exported;
  assert.equal((await s.page(cookie, 'GET', target)).status, 200);
});

// The place is held until the answer has gone: a client that reads only the headers keeps the
// whole body (up to 16 MiB) referenced by its connection, and with the place given back once the
// body was built, one script could hold any number of them. One that stops reading is closed
// after exportIdleMs, so two such clients cannot hold both places for good.
test('an audit export keeps its place until its answer has gone: clients that do not read cannot hold more than two bodies', async t => {
  const s = await serveAudited(t);
  s.app.exportIdleMs = 1500;
  const exported = s.audit.export;
  let built = 0;
  s.audit.export = async (...args) => {
    built++;
    // A body larger than the kernel's buffers take, so the client must read to receive it all.
    return { ...(await exported(...args)), body: Buffer.alloc(16 * 2 ** 20, 0x61) };
  };
  const sockets = [];
  t.after(() => sockets.forEach(socket => socket.destroy()));
  // As a script would, one at a time: each waits only for its headers, then never reads. An
  // export that never answers, or a connection closed before the headers, fails within 10
  // seconds instead of holding the run for ever.
  const headersOnly = () =>
    new Promise((resolve, reject) => {
      const socket = net.connect(s.port, '127.0.0.1');
      sockets.push(socket);
      let head = '';
      const deadline = setTimeout(() => {
        socket.destroy();
        reject(new Error('No answer headers within 10 seconds'));
      }, 10000);
      socket.on('data', chunk => {
        head += chunk.toString('latin1');
        if (!head.includes('\r\n\r\n')) return;
        clearTimeout(deadline);
        socket.pause();
        socket.removeAllListeners('data');
        resolve({ socket, status: Number(head.split(' ')[1]) });
      });
      socket.on('close', () => {
        clearTimeout(deadline);
        reject(new Error(`The connection closed before the answer headers: ${head}`));
      });
      socket.on('error', error => {
        clearTimeout(deadline);
        reject(error);
      });
      socket.write(
        `GET /api/audit/export?format=ndjson HTTP/1.1\r\nHost: 127.0.0.1:${s.port}\r\nAuthorization: ${basic()}\r\nX-Orbit-Request: 1\r\n\r\n`
      );
    });
  const statuses = [];
  for (let i = 0; i < 4; i++) statuses.push((await headersOnly()).status);
  assert.deepEqual(statuses, [200, 200, 503, 503]);
  assert.equal(built, 2, 'only two bodies were built');
  // Those two never take their bodies: Uptime Goblin closes their answers after exportIdleMs, and
  // their places are free again while the clients are still there.
  const freed = async () => {
    for (const started = Date.now(); Date.now() - started < 6000; ) {
      const answer = await s.script('GET', '/api/audit/export?format=ndjson', exporting);
      if (answer.status === 200) return true;
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    return false;
  };
  assert.equal(await freed(), true, 'the places of clients that never read are given back');
  assert.ok(
    sockets.slice(0, 2).every(socket => !socket.destroyed),
    'the clients were still there'
  );
  // Both places: the two clients connected one after the other, so the second's answer is
  // closed up to that gap after the first's, and one free place is not yet two. Two clients
  // that hold their places (they do not read) are both let in only when both are free.
  const bothFree = async () => {
    for (const started = Date.now(); Date.now() - started < 6000; ) {
      const pair = [await headersOnly(), await headersOnly()];
      if (pair.every(client => client.status === 200)) return pair;
      pair.forEach(client => client.socket.destroy());
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    return null;
  };
  const pair = await bothFree();
  assert.ok(pair, 'both places are free again');
  // A client that goes gives its place back at once.
  pair.forEach(client => client.socket.destroy());
  assert.equal(await freed(), true);
});

// A build goes on after its client left (the audit service takes no signal), and its handler holds
// the body until it has written the export's row, so its place is held until the handler has
// finished: given back when the client left, a script that asks and leaves, again and again,
// would have any number of builds (each up to 50,000 rows and a 16 MiB body) running at once.
test('an audit export whose client leaves during the build keeps its place until the build and its row are done', async t => {
  const s = await serveAudited(t);
  let held = gate();
  let building = 0,
    most = 0,
    started = 0;
  const exported = s.audit.export;
  s.audit.export = async (...args) => {
    started++;
    building++;
    most = Math.max(most, building);
    try {
      await held.promise;
      return await exported(...args);
    } finally {
      building--;
    }
  };
  const sockets = [];
  t.after(() => sockets.forEach(socket => socket.destroy()));
  const statuses = [];
  for (let i = 0; i < 8; i++) {
    const socket = net.connect(s.port, '127.0.0.1');
    sockets.push(socket);
    let head = '';
    socket.on('data', chunk => (head += chunk.toString('latin1')));
    socket.on('error', () => {});
    const before = started;
    socket.write(
      `GET /api/audit/export?format=ndjson HTTP/1.1\r\nHost: 127.0.0.1:${s.port}\r\nAuthorization: ${basic()}\r\nX-Orbit-Request: 1\r\n\r\n`
    );
    // Its build has started, or it was answered (503 busy): then it leaves.
    await until(() => started > before || head.includes('\r\n\r\n'), 'a build or an answer');
    statuses.push(head.includes('\r\n\r\n') ? Number(head.split(' ')[1]) : 'building');
    socket.destroy();
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  assert.deepEqual(statuses, ['building', 'building', 503, 503, 503, 503, 503, 503]);
  assert.equal(most, 2, 'at most two builds at once');
  // Built, their handlers still hold the bodies while each writes its row: still no place.
  const single = s.audit.single,
    written = gate();
  let writing = 0;
  s.audit.single = async (...args) => {
    // Only those two rows wait.
    if (++writing <= 2) await written.promise;
    return single.apply(s.audit, args);
  };
  held.open();
  await until(() => building === 0 && writing === 2, 'the builds to end and their rows');
  const target = '/api/audit/export?format=ndjson';
  const busy = await s.script('GET', target, exporting);
  assert.deepEqual([busy.status, busy.json?.code], [503, 'busy']);
  assert.equal(started, 2, 'and nothing more was built');
  s.audit.single = single;
  written.open();
  // Both places are given back once those handlers finished: two exports are built at once.
  held = gate();
  const first = s.script('GET', target, exporting),
    second = s.script('GET', target, exporting);
  await until(() => building === 2, 'two builds again');
  held.open();
  assert.deepEqual([(await first).status, (await second).status], [200, 200]);
});

test("exports D29: only from Uptime Goblin's page or a script; refused exports write no row and build nothing", async t => {
  const s = await serveAudited(t);
  const cookie = await s.signIn();
  let built = 0;
  const exported = s.audit.export;
  s.audit.export = (...args) => {
    built++;
    return exported(...args);
  };
  const singles = () => s.audit.rows.filter(row => row.mode === 'single');
  for (const target of ['/api/config/export', '/api/audit/export?format=csv']) {
    const get = lines => raw(s.port, [`GET ${target} HTTP/1.1`, `Cookie: ${cookie}`, ...lines]);
    // A cookie another page made the browser send: no custom header.
    assertAuditError(await get([]), 'cross_origin.read');
    // An Origin naming another host.
    assertAuditError(
      await get(['X-Goblin-Request: 1', 'Origin: http://other.example.test']),
      'cross_origin.read'
    );
    // Sec-Fetch-Site: same-site is refused by the pipeline before the session is read.
    assertAuditError(
      await get(['X-Goblin-Request: 1', 'Sec-Fetch-Site: same-site']),
      'cross_origin.read'
    );
    assert.equal(singles().length, 0, target);
    assert.equal(built, 0, target);
  }
  // Uptime Goblin's page.
  const page = await s.page(cookie, 'GET', '/api/config/export');
  assert.equal(page.status, 200);
  assert.equal(
    page.headers['content-disposition'],
    'attachment; filename="uptime-goblin-config-redacted.json"'
  );
  let row = singles().at(-1);
  assert.deepEqual(
    [row.action, row.outcome, row.target, row.detail],
    [
      'config.export',
      'ok',
      { type: 'config', id: null, name: null },
      { sources: page.json.config.services.length, bytes: Buffer.byteLength(page.body) },
    ]
  );
  assert.equal(row.actor.via, 'session');
  // A script with Basic, no browser headers and X-Goblin-Request: 1.
  const script = await s.script(
    'GET',
    '/api/audit/export?format=ndjson&action=session.&outcome=ok',
    exporting
  );
  assert.equal(script.status, 200, script.body);
  assert.equal(built, 1);
  row = singles().at(-1);
  const { format, ...filters } = parseAuditQuery(
    new URLSearchParams('format=ndjson&action=session.&outcome=ok'),
    'export'
  );
  assert.deepEqual(
    [row.action, row.target, row.detail],
    [
      'audit.export',
      { type: 'audit', id: null, name: null },
      { format, rows: 2, more: false, filters },
    ]
  );
  assert.equal(row.actor.via, 'basic');
});

// Wherever a browser sends no fetch metadata, a load that another site's page starts (an image,
// a navigation) and that carries the browser's cached 1.4.x Basic login reads as a script's
// request: at a plain-HTTP address on the network (not localhost, 127.x or [::1]), Uptime Goblin's own
// (the `http` transport) or that of a proxy on this host that sends no forwarding headers and
// keeps a loopback Host (the `loopback` transport, which Uptime Goblin cannot tell from this computer's
// own scripts), and over HTTPS from a browser that predates fetch metadata. An export is therefore held to D29 with Basic on every transport: X-Goblin-Request:
// 1, as scripts already send with every change, and an Origin, when sent, naming the Host
// (review ROUTES-1 for `http`; finding F4 of the static review for `loopback` and `https`, which
// kept 1.4.3's rule for Basic before).
test('exports D29 with Basic on every transport: X-Goblin-Request is needed over http, https and loopback', async t => {
  const s = await serveAudited(t, { insecureHttpSessions: true, trustProxy: 'loopback' });
  let built = 0;
  const exported = s.audit.export;
  s.audit.export = (...args) => {
    built++;
    return exported(...args);
  };
  const singles = () => s.audit.rows.filter(row => row.mode === 'single');
  const transports = [
    // nginx on the Uptime Goblin host relaying a LAN browser's plain-HTTP request,
    ['http', ['X-Forwarded-For: 198.51.100.9', 'X-Forwarded-Proto: http'], '198.51.100.9'],
    // and its HTTPS one (a browser that sends no fetch metadata).
    ['https', ['X-Forwarded-For: 198.51.100.9', 'X-Forwarded-Proto: https'], '198.51.100.9'],
    // The Uptime Goblin host itself, or a proxy there that sends no forwarding headers and keeps
    // nginx's default Host 127.0.0.1:<port> (s.script's).
    ['loopback', [], 'loopback'],
  ];
  const targets = ['/api/config/export', '/api/audit/export?format=ndjson'];
  const get = (target, lines) => s.script('GET', target, { lines });
  for (const [kind, via] of transports)
    for (const target of targets) {
      for (const lines of [
        // What another site's image or link makes the browser send: the cached Basic login
        // (s.script's), a Referer, no fetch metadata and no custom header.
        [...via, 'Referer: http://evil.example.test/page'],
        [...via],
        // An Origin naming another host is refused as for a session, custom header or not.
        [...via, 'X-Goblin-Request: 1', 'Origin: http://evil.example.test'],
        // The custom header with another value.
        [...via, 'X-Goblin-Request: yes'],
      ])
        assertAuditError(await get(target, lines), 'cross_origin.read');
      // A browser that does send fetch metadata is a browser: its Authorization is not read.
      const browser = await get(target, [...via, 'Sec-Fetch-Site: cross-site']);
      assert.deepEqual([browser.status, browser.json.code], [401, 'signin_required'], kind);
      assert.equal(singles().length, 0, `${kind} ${target}`);
      assert.equal(built, 0, `${kind} ${target}`);
    }
  // A script sends X-Goblin-Request: 1 (an Origin naming the Host may come with it), on every
  // transport.
  for (const [kind, via, client] of transports)
    for (const lines of [
      [...via, 'X-Goblin-Request: 1'],
      [...via, 'X-Goblin-Request: 1', 'Referer: http://evil.example.test/page'],
      [...via, 'X-Goblin-Request: 1', `Origin: ${s.origin}`],
    ])
      for (const target of targets) {
        const answer = await get(target, lines);
        assert.equal(answer.status, 200, `${kind} ${target} ${lines.join(' / ')}: ${answer.body}`);
        const row = singles().at(-1);
        assert.deepEqual([row.actor.via, row.client], ['basic', client], `${kind} ${target}`);
      }
  assert.deepEqual([singles().length, built], [18, 9]);
});

// Finding F4 of the static review, as reported: a proxy on the Uptime Goblin host that sends no
// forwarding headers and keeps a loopback Host (nginx's bare proxy_pass), with neither
// GOBLIN_TRUST_PROXY nor the plain-HTTP opt-in, is the loopback transport. Basic exports there
// kept 1.4.3's rule, so another site's page could make a browser that remembers a Basic login
// for Uptime Goblin have exports built and recorded through such a proxy, again and again. Now nothing
// is built or recorded; the Basic sign-in itself is still checked and counted as a script's,
// and a script on the Uptime Goblin host that sends X-Goblin-Request: 1 exports as before.
test("exports D29 through a proxy on this host that sends no forwarding headers: a browser's cached Basic login has nothing built or recorded", async t => {
  const s = await serveAudited(t);
  let built = 0;
  const exported = s.audit.export;
  s.audit.export = (...args) => {
    built++;
    return exported(...args);
  };
  const singles = () => s.audit.rows.filter(row => row.mode === 'single');
  const counted = action => s.audit.counts.filter(event => event.action === action).length;
  const targets = ['/api/config/export', '/api/audit/export?format=ndjson'];
  for (const target of targets)
    for (let i = 0; i < 3; i++)
      // What another site's image or link sends through that proxy: the Host is nginx's
      // default 127.0.0.1:<port> (s.script's), a Referer, no fetch metadata, no custom header.
      assertAuditError(
        await s.script('GET', target, { lines: ['Referer: http://evil.example.test/page'] }),
        'cross_origin.read'
      );
  assert.deepEqual([singles().length, built], [0, 0]);
  assert.deepEqual([counted('auth.basic.used'), counted('auth.basic.failed')], [6, 0]);
  // A script on the Uptime Goblin host (or through that proxy) that sends the header.
  for (const target of targets) {
    const answer = await s.script('GET', target, { lines: ['X-Goblin-Request: 1'] });
    assert.equal(answer.status, 200, `${target}: ${answer.body}`);
    const row = singles().at(-1);
    assert.deepEqual([row.actor.via, row.client], ['basic', 'loopback'], target);
  }
  assert.deepEqual([singles().length, built], [2, 1]);
  // Only exports: a script's other reads with Basic still need no custom header there.
  for (const target of ['/api/dashboard', '/api/audit?limit=1'])
    assert.equal((await s.script('GET', target)).status, 200, target);
});

// Earlier 1.5 builds served exports without a credential in their passwordless local preview,
// and so held them to crossOrigin() there (a deviation from D29's wording). Uptime Goblin now always has
// a password: an export without a credential is not signed in, from any page or none.
test('exports without a credential: 401, no row and nothing built, from any page', async t => {
  const s = await serveAudited(t);
  let built = 0;
  const exported = s.audit.export;
  s.audit.export = (...args) => {
    built++;
    return exported(...args);
  };
  const singles = () => s.audit.rows.filter(row => row.mode === 'single');
  for (const target of ['/api/config/export', '/api/audit/export?format=csv']) {
    const get = lines => raw(s.port, [`GET ${target} HTTP/1.1`, ...lines]);
    for (const lines of [
      // What a page of another site makes the browser send (an image, a no-cors fetch).
      ['Sec-Fetch-Site: cross-site', 'Origin: https://other.example.test'],
      // Nothing at all, from this computer.
      [],
      // What Uptime Goblin's own page sends, without a session.
      ['X-Goblin-Request: 1', 'Sec-Fetch-Site: same-origin'],
    ]) {
      const answer = await get(lines);
      assert.equal(answer.status, 401, `${target} ${lines.join(' / ')}`);
      assert.equal(JSON.parse(answer.body).code, 'signin_required');
    }
    assert.equal(singles().length, 0, target);
    assert.equal(built, 0, target);
  }
});

test('the audit routes: audit:read, Cache-Control: no-store on every answer, query validation and the contract bodies', async t => {
  let denied = null;
  const s = await serveAudited(t, {
    permitted: (access, permission) => permission !== denied && access.permissions.has(permission),
  });
  const cookie = await s.signIn();
  const routes = ['/api/audit', '/api/audit/export?format=csv', '/api/audit/verify'];
  const answers = [];
  const get = async target => {
    const answer = await s.page(cookie, 'GET', target);
    answers.push([target, answer]);
    return answer;
  };
  // The bodies the service resolves, as they are.
  for (const name of ['list.entries', 'list.more', 'list.empty', 'list.unwritten']) {
    s.audit.answer(name);
    const answer = await get('/api/audit');
    assert.equal(answer.status, 200);
    assert.deepEqual(answer.json, auditBody(name), name);
  }
  for (const name of ['verify.intact', 'verify.empty', 'verify.anchors', 'verify.broken.seq_gap']) {
    s.audit.answer(name);
    const answer = await get('/api/audit/verify');
    assert.equal(answer.status, 200, 'every verification result is a 200');
    assert.deepEqual(answer.json, auditBody(name), name);
  }
  for (const format of ['csv', 'ndjson']) {
    s.audit.answer(`export.${format}`);
    const expected = auditBody(`export.${format}`);
    const answer = await get(`/api/audit/export?format=${format}`);
    assert.equal(answer.status, expected.status);
    assert.equal(answer.body, expected.body, format);
    for (const [header, value] of Object.entries(expected.headers))
      assert.equal(answer.headers[header], value, `${format}: ${header}`);
  }
  // The service's file name goes out as a quoted-string of printable ASCII: a quote or a
  // backslash would end or escape it, and a character beyond ASCII makes Node refuse the header
  // (the answer would fail after the export's row was written).
  const exportOf = s.audit.export;
  for (const [filename, sent] of [
    ['orbit-"audit\\é✓.csv', 'orbit-_audit___.csv'],
    [undefined, 'uptime-goblin-audit'],
  ]) {
    s.audit.export = async (...args) => ({ ...(await exportOf(...args)), filename });
    const answer = await get('/api/audit/export?format=csv');
    assert.equal(answer.status, 200, answer.body);
    assert.equal(answer.headers['content-disposition'], `attachment; filename="${sent}"`);
  }
  s.audit.export = exportOf;
  // The query the service was given is parseAuditQuery's.
  let asked;
  const list = s.audit.list;
  s.audit.list = query => {
    asked = query;
    return list(query);
  };
  const params =
    'action=session.,settings.update&outcome=unknown&limit=10&cursor=99&from=1&to=2&actor=user&target=source:linux&_=1';
  assert.equal((await get(`/api/audit?${params}`)).status, 200);
  assert.deepEqual(asked, parseAuditQuery(new URLSearchParams(params), 'list'));
  // Every rule of §6.5, with its parameter.
  const invalid = {
    from: '/api/audit?from=yesterday',
    to: '/api/audit?to=-1',
    'to/order': '/api/audit?from=10&to=5',
    limit: '/api/audit?limit=501',
    cursor: '/api/audit?cursor=0',
    action: '/api/audit?action=Session',
    actor: `/api/audit?actor=${'a'.repeat(201)}`,
    target: '/api/audit?target=Source',
    outcome: '/api/audit?outcome=maybe',
    format: '/api/audit/export?format=xml',
    repeated: '/api/audit?action=session.&action=key.',
  };
  for (const [rule, target] of Object.entries(invalid))
    assertAuditError(await get(target), `audit_query_invalid.${rule}`);
  // Unavailable reads.
  for (const [kind, target] of [
    ['list', '/api/audit'],
    ['export', '/api/audit/export?format=csv'],
    ['verify', '/api/audit/verify'],
  ]) {
    s.audit.setFailing(kind, auditError('audit_read_unavailable'));
    assertAuditError(await get(target), 'audit_read_unavailable');
    s.audit.setFailing(kind, null);
  }
  // audit:read on each route.
  denied = 'audit:read';
  for (const target of routes) {
    const answer = await get(target);
    assert.equal(answer.status, 403, target);
    assert.equal(answer.json.code, 'forbidden', target);
  }
  denied = null;
  // Signed out, and from another site.
  for (const target of routes) {
    const signedOut = await raw(s.port, [`GET ${target} HTTP/1.1`, 'X-Goblin-Request: 1']);
    assert.equal(signedOut.status, 401);
    answers.push([target, signedOut]);
    answers.push([target, await raw(s.port, [`GET ${target} HTTP/1.1`, `Cookie: ${cookie}`])]);
  }
  for (const [target, answer] of answers)
    assert.equal(answer.headers['cache-control'], 'no-store', `${target} ${answer.status}`);
  assert.ok(answers.some(([, answer]) => answer.status === 403));
});

test('a route may count its refusals only into an aggregated action of an identity route', () => {
  const route = extra => ({
    method: 'POST',
    path: '/api/x',
    auth: 'session',
    permission: 'account:self',
    summary: 'x',
    handler() {},
    ...extra,
  });
  assert.ok(createRouter([route({ audit: 'identity', refusals: 'account.password.changed' })]));
  for (const extra of [
    { audit: 'config', refusals: 'session.login' },
    { audit: 'identity', refusals: 'session.logout' },
    { audit: 'identity', refusals: 'session.signin' },
  ])
    assert.throws(() => createRouter([route(extra)]), RouteError, JSON.stringify(extra));
});

test("fromDelivery: the delivery records Uptime Goblin emits become their system rows; a person's actions are left to their routes (D24)", async () => {
  const audit = fakeAudit();
  const at = Date.UTC(2026, 9, 3);
  // As lib/alerting/signing.mjs and service.mjs emit them (target and detail as they set them).
  const records = [
    {
      at,
      target: 'env-webhook',
      action: 'signing.created',
      outcome: 'ok',
      detail: { replaced: true },
    },
    { at, target: 'env-webhook', action: 'signing.rotate', outcome: 'ok', actor: 'admin' },
    {
      at,
      action: 'delivery.retry',
      outcome: 'ok',
      actor: 'admin',
      target: 'd_x',
      detail: { retried: 1 },
    },
    {
      at,
      action: 'channel.resume',
      outcome: 'ok',
      actor: 'admin',
      target: 'email',
      detail: { released: 2 },
    },
    {
      at,
      action: 'channel.paused',
      outcome: 'ok',
      target: 'env-webhook',
      detail: { reason: 'The webhook answered 401.', transient: false },
    },
    { at, action: 'channel.working', outcome: 'ok', target: 'env-webhook' },
    { at, action: 'notifications.unsaved', outcome: 'ok', target: 'outbox' },
    { at, action: 'notifications.saved', outcome: 'ok', target: 'outbox' },
    { at, action: 'something.new', outcome: 'ok', target: 'x' },
  ];
  for (const record of records) audit.fromDelivery(record);
  await audit.idle();
  assert.deepEqual(
    audit.rows.map(row => [
      row.mode,
      row.action,
      row.outcome,
      row.target?.id ?? null,
      row.actor.type,
    ]),
    [
      ['system', 'signing.created', 'info', 'env-webhook', 'system'],
      ['system', 'channel.paused', 'info', 'env-webhook', 'system'],
      ['system', 'channel.working', 'info', 'env-webhook', 'system'],
      ['system', 'notifications.unsaved', 'info', null, 'system'],
      ['system', 'notifications.saved', 'info', null, 'system'],
    ]
  );
  assert.deepEqual(audit.rows[0].detail, { replaced: true });
  assert.deepEqual(audit.rows[1].detail, { reason: 'The webhook answered 401.', transient: false });
});

test("the identity routes hand identity the request's facts, and each sign-out its cause (audit spec §5.1)", async t => {
  const s = await serveAudited(t);
  const agent = 'Mozilla/5.0 (X11; Linux x86_64) audit-test';
  const signIn = async () => {
    const answer = await raw(
      s.port,
      [
        'POST /api/auth/login HTTP/1.1',
        'X-Goblin-Request: 1',
        'Content-Type: application/json',
        `Origin: ${s.origin}`,
        'Sec-Fetch-Site: same-origin',
        `User-Agent: ${agent}`,
      ],
      JSON.stringify({ login: 'admin', password })
    );
    assert.equal(answer.status, 200, answer.body);
    const cookie = [].concat(answer.headers['set-cookie'])[0].split(';')[0];
    return { cookie, requestId: answer.headers['x-request-id'] };
  };
  // Each identity row carries the facts of the request that caused it.
  const last = action => s.rowsOf(action).at(-1);
  const facts = (row, requestId) => {
    assert.equal(row.requestId, requestId, row.action);
    assert.equal(row.client, 'loopback', row.action);
  };
  const a = await signIn();
  facts(last('session.login'), a.requestId);
  assert.equal(last('session.login').userAgent, agent);
  const sessionsOf = async cookie =>
    (await s.page(cookie, 'GET', '/api/account/sessions')).json.sessions;
  const aId = (await sessionsOf(a.cookie)).find(row => row.current).id;
  // A newer session ends the older one.
  const b = await signIn();
  const revoked = await s.page(b.cookie, 'DELETE', `/api/account/sessions/${aId}`);
  assert.equal(revoked.status, 204);
  facts(last('session.revoked'), revoked.headers['x-request-id']);
  // The newest ends the others.
  const c = await signIn();
  const others = await s.page(c.cookie, 'DELETE', '/api/account/sessions');
  assert.equal(others.status, 200);
  facts(last('session.revoked-others'), others.headers['x-request-id']);
  // A sign-out: cause signout.
  const out = await s.page(c.cookie, 'POST', '/api/auth/logout');
  assert.equal(out.status, 204);
  facts(last('session.logout'), out.headers['x-request-id']);
  assert.equal(last('session.logout').detail.cause, 'signout');
  // A sign-out sent with two session cookies: each presented session ends, cause presented.
  const d = await signIn(),
    e = await signIn();
  const both = await raw(
    s.port,
    [
      'POST /api/auth/logout HTTP/1.1',
      `Cookie: ${d.cookie}`,
      `Cookie: ${e.cookie}`,
      'X-Goblin-Request: 1',
      'Content-Type: application/json',
      `Origin: ${s.origin}`,
      'Sec-Fetch-Site: same-origin',
    ],
    '{}'
  );
  assert.equal(both.status, 200, both.body);
  const presented = s.rowsOf('session.logout').slice(-2);
  for (const row of presented) {
    facts(row, both.headers['x-request-id']);
    assert.equal(row.detail.cause, 'presented');
  }
  // A sign-out whose delete failed, sent again with its cookie (endedSession): cause ended.
  const f = await signIn();
  s.identity.test.beforeWrite = () => {
    throw Object.assign(new Error('database or disk is full'), { class: 'full' });
  };
  assert.notEqual((await s.page(f.cookie, 'POST', '/api/auth/logout')).status, 204);
  s.identity.test.beforeWrite = null;
  const again = await s.page(f.cookie, 'POST', '/api/auth/logout');
  assert.equal(again.status, 204, again.body);
  facts(last('session.logout'), again.headers['x-request-id']);
  assert.equal(last('session.logout').detail.cause, 'ended');
  // The password change.
  const g = await signIn();
  const changed = await s.page(g.cookie, 'POST', '/api/account/password', {
    body: {
      currentPassword: password,
      password: 'a-new-password-9',
      confirmPassword: 'a-new-password-9',
    },
  });
  assert.equal(changed.status, 200, changed.body);
  facts(last('account.password.changed'), changed.headers['x-request-id']);
});
