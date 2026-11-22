// The audit trail through a real Uptime Goblin (createApp; audit spec §9.1 H and the gates of §9.3):
// every recording route writes its rows of §5.8 and GET /api/audit lists them; an attempt is
// "in progress" only in the process that began it; the fail-closed and result-row gates; the
// start rows; checkpoints and the mirror on stdout; the environment's settings; the prune; one
// verification at a time; the export; and the canary. The webhook receiver and the mail
// transport are fixtures of this file: nothing leaves 127.0.0.1.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import net from 'node:net';
import path from 'node:path';
import http from 'node:http';
import { randomBytes, createPrivateKey } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { pathToFileURL } from 'node:url';
import { createApp, auditSettings, securitySnapshot } from '../server.mjs';
import { LoginThrottle } from '../lib/throttle.mjs';
import { ACTIONS } from '../lib/audit/actions.mjs';
import { routeTable } from '../lib/http/routes.mjs';
import { checkpointMac } from '../lib/audit/chain.mjs';
import { configureDestinations } from '../lib/destinations.mjs';
import { emailDefaults } from '../lib/catalog.mjs';
import { openControl } from '../lib/db/control.mjs';
import { acquireLock } from '../lib/db/lock.mjs';
import { createSnapshot, restoreSnapshot } from '../lib/db/snapshot.mjs';
import { Keyring, parseKey } from '../lib/keyring.mjs';
import { auditSentinels, findSentinels } from './helpers/audit-sentinels.mjs';
import { signIn, sessionCall, browserHeaders } from './helpers/session.mjs';
import { retryOnce } from './helpers/retry-once.mjs';
import { webhookReceiver } from './helpers/webhook-receiver.mjs';
import {
  start as startProcess,
  temporary as processDirectory,
  workingTree,
} from './upgrade/harness.mjs';

configureDestinations({ lookup: async () => [{ address: '192.0.2.1' }] });

const release = JSON.parse(
  fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')
).version;
// Throwaway values for these data directories only.
const password = 'audit-test-password-0001';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const hour = 3600000,
  day = 24 * hour;

async function until(condition, { timeoutMs = 15000, what = 'the condition' } = {}) {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const value = await condition();
    if (value) return value;
    if (Date.now() > end) assert.fail(`${what} was not reached within ${timeoutMs} ms`);
    await sleep(10);
  }
}

function temporary(t, prefix = 'orbit-audit-') {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

/** Captures console output: {lines: [{stream, text}], out(), err(), audit(kind)}. */
function capture(t) {
  const lines = [];
  for (const [level, stream] of [
    ['log', 'out'],
    ['info', 'out'],
    ['warn', 'err'],
    ['error', 'err'],
  ])
    t.mock.method(console, level, (...args) => lines.push({ stream, text: args.join(' ') }));
  return {
    lines,
    out: () => lines.filter(line => line.stream === 'out').map(line => line.text),
    err: () => lines.filter(line => line.stream === 'err').map(line => line.text),
    /** The JSON lines of `kind` (audit, audit.checkpoint, audit.unwritten), parsed. */
    audit: kind =>
      lines
        .filter(line => line.text.startsWith(`{"orbit":"${kind}"`))
        .map(line => JSON.parse(line.text)),
  };
}

/** A mail transport recording each message; while `refuse()` is true it refuses the sign-in. */
function mailbox({ refuse = () => false } = {}) {
  const messages = [];
  return {
    messages,
    factory: () => ({
      async sendMail(message) {
        if (refuse())
          throw Object.assign(new Error('535 authentication failed'), { code: 'EAUTH' });
        messages.push(message);
        return { accepted: ['recipient@example.test'], rejected: [] };
      },
      close() {},
    }),
  };
}
const emailSettings = (extra = {}) => ({
  ...emailDefaults(),
  enabled: true,
  from: 'sender@example.test',
  to: 'recipient@example.test',
  password: 'audit-mail-fixture-0001',
  host: 'smtp.example.test',
  ...extra,
});
const fastFailure = {
  availabilityFailures: 1,
  availabilitySeconds: 0,
  retryCount: 0,
  recoverySuccesses: 1,
  recoverySeconds: 0,
};
const plenty = () => ({
  type: 0,
  bsize: 1,
  blocks: 2 ** 40,
  bfree: 2 ** 34,
  bavail: 2 ** 34,
  files: 1000,
  ffree: 1000,
});
const full = () =>
  Object.assign(new Error('database or disk is full'), { code: 'SQLITE_FULL', class: 'full' });

/**
 * Uptime Goblin on `directory` (a new one unless given), Basic on for scripts. `down` names the sources
 * whose collection fails; `listen: false` returns before listen(). Resolves {app, base, port,
 * script(route, method, body, headers), directory}.
 */
async function start(
  t,
  {
    directory = temporary(t),
    hook = null,
    mail = null,
    down = new Set(),
    listen = true,
    ...options
  } = {}
) {
  const app = await createApp({
    directory,
    host: '127.0.0.1',
    port: 0,
    password,
    allowedHosts: '',
    trustProxy: '',
    startScheduler: false,
    legacyBasic: true,
    webhook: hook?.url ?? '',
    emailBatchMs: 60000,
    mailTransportFactory:
      mail?.factory ??
      (() => {
        throw new Error('Unexpected mail attempt');
      }),
    collector: async service => {
      if (down.has(service.id)) throw new Error(`${service.id} is down`);
      return [{ key: 'up', label: 'Up', value: 1, unit: '' }];
    },
    delivery: { pollMs: 20, rng: () => 1, policy: { baseMs: 100, capMs: 100 } },
    ...options,
  });
  t.after(() => app.close());
  if (!listen) return { app, directory };
  const { port } = await app.listen();
  const base = `http://127.0.0.1:${port}`;
  const script = async (route, method = 'GET', body, headers = {}) => {
    const response = await fetch(base + route, {
      method,
      headers: {
        Authorization:
          'Basic ' + Buffer.from('admin:' + (headers.secret ?? password)).toString('base64'),
        'Content-Type': 'application/json',
        'X-Goblin-Request': '1',
        ...Object.fromEntries(Object.entries(headers).filter(([name]) => name !== 'secret')),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await response.text();
    let value = text;
    try {
      value = JSON.parse(text);
    } catch {}
    return { status: response.status, headers: response.headers, body: value };
  };
  return { app, base, port, script, directory };
}

/** The audit_log rows (detail parsed), oldest first; readable while Uptime Goblin runs (WAL). */
function auditRows(directory) {
  const db = new DatabaseSync(path.join(directory, 'control.sqlite'), { readOnly: true });
  try {
    return db
      .prepare('SELECT * FROM audit_log ORDER BY seq')
      .all()
      .map(row => ({ ...row, detail: row.detail === null ? null : JSON.parse(row.detail) }));
  } finally {
    db.close();
  }
}
/** Every row of `table`, and every `meta` value, as text (for the canary). */
function tableText(directory, tables) {
  const db = new DatabaseSync(path.join(directory, 'control.sqlite'), { readOnly: true });
  try {
    return tables
      .map(table => JSON.stringify(db.prepare(`SELECT * FROM ${table}`).all()))
      .join('\n');
  } finally {
    db.close();
  }
}
const inboxSequence = directory => {
  const db = new DatabaseSync(path.join(directory, 'control.sqlite'), { readOnly: true });
  try {
    return db.prepare("SELECT seq FROM sqlite_sequence WHERE name = 'audit_inbox'").get()?.seq ?? 0;
  } finally {
    db.close();
  }
};

/**
 * Checks each checkpoint line's MAC under the keyring of `directory` (Uptime Goblin stopped; the key is
 * the secret.key Uptime Goblin generated there). Returns how many verified.
 */
async function verifiedCheckpoints(directory, lines) {
  const control = openControl(directory, { readOnly: true, env: {} });
  try {
    const key = parseKey(fs.readFileSync(path.join(directory, 'secret.key'), 'utf8'));
    const keyring = await Keyring.open(control.keyringStore, { key, create: false });
    let verified = 0;
    for (const line of lines) {
      const mac = checkpointMac(data => keyring.hmac('audit', data, line.key_id).mac, line);
      assert.equal(mac, line.mac, `checkpoint #${line.seq}`);
      verified++;
    }
    return verified;
  } finally {
    control.close();
  }
}
// The rows a list answers, by action.
const listed = async (call, query = '') => (await call(`/api/audit${query}`)).body.entries;

test('the environment: GOBLIN_AUDIT_LOG and GOBLIN_AUDIT_RETENTION_DAYS are checked, with the start warnings of D13 and D14', () => {
  assert.deepEqual(auditSettings({}), {
    mirror: 'off',
    retention: { days: 90, maxRows: 250000 },
    warnings: [],
  });
  for (const value of ['off', 'stdout', 'stdout-full'])
    assert.deepEqual(auditSettings({ auditLog: value }), {
      mirror: value,
      retention: { days: 90, maxRows: 250000 },
      warnings: [],
    });
  // Exactly as D13 writes them (review round 1): another case or spaces around is another
  // value, off with the warning, as docs/configuration.md says ("Any other value …").
  for (const value of ['STDOUT', 'Stdout-Full', ' stdout ', 'stdout-full\t'])
    assert.deepEqual(
      auditSettings({ auditLog: value }),
      {
        mirror: 'off',
        retention: { days: 90, maxRows: 250000 },
        warnings: [
          `GOBLIN_AUDIT_LOG must be off, stdout or stdout-full; it is set to ${value.replace('\t', '')}, so the audit log is not copied to Uptime Goblin's log.`,
        ],
      },
      JSON.stringify(value)
    );
  const loud = auditSettings({
    auditLog: 'loud\u001b[31m and a very long value that goes on and on',
  });
  assert.equal(loud.mirror, 'off');
  assert.deepEqual(loud.warnings, [
    "GOBLIN_AUDIT_LOG must be off, stdout or stdout-full; it is set to loud[31m and a very long value that goes, so the audit log is not copied to Uptime Goblin's log.",
  ]);
  const cases = [
    [
      '10',
      30,
      'GOBLIN_AUDIT_RETENTION_DAYS must be from 30 to 3650 days; it is 10, so Uptime Goblin keeps audit entries for 30 days.',
    ],
    [
      '9999',
      3650,
      'GOBLIN_AUDIT_RETENTION_DAYS must be from 30 to 3650 days; it is 9999, so Uptime Goblin keeps audit entries for 3650 days.',
    ],
    [
      'abc',
      90,
      'GOBLIN_AUDIT_RETENTION_DAYS must be a whole number of days from 30 to 3650; it is set to abc, so Uptime Goblin keeps audit entries for 90 days.',
    ],
    [
      '30.5',
      90,
      'GOBLIN_AUDIT_RETENTION_DAYS must be a whole number of days from 30 to 3650; it is set to 30.5, so Uptime Goblin keeps audit entries for 90 days.',
    ],
  ];
  for (const [value, days, warning] of cases) {
    const settings = auditSettings({ auditRetentionDays: value });
    assert.equal(settings.retention.days, days, value);
    assert.deepEqual(settings.warnings, [warning], value);
  }
  for (const [value, days] of [
    ['30', 30],
    ['3650', 3650],
    ['400', 400],
    ['', 90],
  ])
    assert.deepEqual(auditSettings({ auditRetentionDays: value }), {
      mirror: 'off',
      retention: { days, maxRows: 250000 },
      warnings: [],
    });
  // D30: the security settings from the environment, never the webhook's URL.
  const security = securitySnapshot({
    legacyBasic: 1,
    insecureHttpSessions: 0,
    trustProxy: ' loopback , 10.0.0.0/8 ',
    allowedHosts: 'Goblin.Example.Test:443, a.example.test,goblin.example.test:443',
    webhook: 'https://hooks.example.test/x?token=secret-in-url',
    keySource: 'file',
    maxConnectionsPerClient: 64,
  });
  assert.deepEqual(security, {
    legacyBasic: true,
    insecureHttpSessions: false,
    trustProxy: 'loopback,10.0.0.0/8',
    allowedHosts: ['a.example.test', 'goblin.example.test:443'],
    webhook: true,
    keySource: 'file',
    maxConnectionsPerClient: 64,
  });
  assert.equal(securitySnapshot({ trustProxy: '' }).trustProxy, null);
  // A wall display's limits (B6 design §7.5), whole days, only when given.
  assert.deepEqual(
    Object.entries(securitySnapshot({ displaySessionDays: 14, displayIdleDays: 3 })).slice(-2),
    [
      ['displaySessionDays', 14],
      ['displayIdleDays', 3],
    ]
  );
  assert.equal('displayIdleDays' in securitySnapshot({ displayIdleDays: 2.5 }), false);
  // The per-client connection share as Uptime Goblin applies it (a whole number), else null.
  for (const value of [undefined, '64', 64.5, NaN])
    assert.equal(
      securitySnapshot({ maxConnectionsPerClient: value }).maxConnectionsPerClient,
      null
    );
  assert.equal(
    securitySnapshot({ allowedHosts: Array.from({ length: 30 }, (_, i) => `h${i}.test`).join(',') })
      .allowedHosts.length,
    20
  );
});

test('the environment reaches the audit: a bad GOBLIN_AUDIT_LOG stays off; the retention is clamped', async t => {
  const output = capture(t);
  const { app, script } = await start(t, { auditLog: 'loud', auditRetentionDays: '10' });
  assert.ok(
    output
      .err()
      .some(line => line.startsWith('GOBLIN_AUDIT_LOG must be off, stdout or stdout-full'))
  );
  assert.ok(
    output.err().some(line => line.includes('so Uptime Goblin keeps audit entries for 30 days.'))
  );
  assert.deepEqual(app.audit.state().retention, { days: 30, maxRows: 250000 });
  assert.equal((await script('/api/audit')).body.retention.days, 30);
  assert.deepEqual(output.audit('audit'), [], 'no mirror line while off');
});

test('table-driven: each recording route and each identity route writes exactly its rows of §5.8, and the list shows them', async t => {
  let mode = 'refuse-firing';
  const hook = await webhookReceiver(t, {
    respond: request =>
      mode === 'refuse-firing' && JSON.parse(request.body).kind === 'firing' ? 422 : 200,
  });
  const mail = mailbox();
  const down = new Set();
  const { app, base, script, directory } = await start(t, { hook, mail, down });
  app.config.updateGlobal({ monitoring: fastFailure, email: emailSettings() });
  app.config.update('plex', { apiUrl: 'https://plex.example.test', apiKey: 'fixture-key' });
  const before = auditRows(directory).length;

  const a = await signIn(base, password);
  const A = sessionCall(base, a.cookie);
  const ok = async (answer, status = 200) => {
    const resolved = await answer;
    assert.equal(resolved.status, status, JSON.stringify(resolved.body));
    return resolved;
  };
  await ok(A('/api/settings', 'PATCH', { title: 'Audited lab' }));
  const created = await ok(
    A('/api/services', 'POST', {
      type: 'json',
      name: 'Audited API',
      apiUrl: 'https://api.example.test',
    }),
    201
  );
  const id = created.body.service.id;
  await ok(A(`/api/services/${id}`, 'PATCH', { name: 'Audited API 2' }));
  await ok(A('/api/test-service', 'POST', { serviceId: id, settings: {} }));
  await ok(A(`/api/services/${id}`, 'DELETE'));
  await ok(A('/api/email/test', 'POST', {}));
  await ok(A('/api/refresh', 'POST', {}), 202);
  // A refused firing to retry.
  down.add('plex');
  await app.poll(app.config.get('plex'));
  await app.flushNotifications();
  const failed = await until(async () =>
    (await A('/api/notifications/deliveries?channel=env-webhook')).body.deliveries.find(
      row => row.alert.service === 'plex' && row.status === 'failed'
    )
  );
  mode = 'accept';
  await ok(A(`/api/notifications/deliveries/${failed.uid}/retry`, 'POST', {}));
  await ok(A('/api/notifications/channels/env-webhook/resume', 'POST', {}));
  const before0 = (await app.control.settings.get('notify', 'envWebhook')).value.signingKey;
  const publicKey = await ok(A('/api/notifications/webhook/public-key'));
  await ok(A('/api/notifications/webhook/signing-secret', 'POST', {}));
  const after0 = (await app.control.settings.get('notify', 'envWebhook')).value.signingKey;
  await ok(A('/api/config/export'));
  await ok(A('/api/audit/export?format=csv'));
  // Identity: B ends A (a newer session may), C ends the others, C changes the password (its
  // session is rotated) and signs out.
  const aId = (await A('/api/account/sessions')).body.sessions.find(s => s.current).id;
  const b = await signIn(base, password);
  const B = sessionCall(base, b.cookie);
  const bId = (await B('/api/account/sessions')).body.sessions.find(s => s.current).id;
  assert.equal((await B(`/api/account/sessions/${aId}`, 'DELETE')).status, 204);
  const c = await signIn(base, password);
  const C = sessionCall(base, c.cookie);
  await ok(C('/api/account/sessions', 'DELETE'));
  const newPassword = 'audit-test-password-0002';
  const changed = await ok(
    C('/api/account/password', 'POST', {
      currentPassword: password,
      password: newPassword,
      confirmPassword: newPassword,
    })
  );
  const rotated = changed.headers.getSetCookie().map(value => value.split(';')[0])[0];
  assert.equal((await sessionCall(base, rotated)('/api/auth/logout', 'POST', {})).status, 204);
  // Two refused sign-ins (one immediate row, one counted) and a script with the password.
  for (let i = 0; i < 2; i++)
    assert.equal(
      (
        await fetch(new URL('/api/auth/login', base), {
          method: 'POST',
          headers: browserHeaders(base),
          body: JSON.stringify({ login: 'admin', password: 'wrong-password-0001' }),
        })
      ).status,
      401
    );
  assert.equal(
    (await script('/api/dashboard', 'GET', undefined, { secret: newPassword })).status,
    200
  );

  const rows = auditRows(directory).slice(before);
  const of = action => rows.filter(row => row.action === action);
  const keysOf = row => Object.keys(row.detail ?? {});
  const within = (row, required) => {
    for (const key of required) assert.ok(keysOf(row).includes(key), `${row.action}: ${key}`);
    for (const key of keysOf(row))
      assert.ok(ACTIONS[row.action].detail.includes(key), `${row.action}: unknown ${key}`);
  };
  // Attempt and result (P): the attempt first, its result linked by ref, written after.
  for (const [action, status, type, target, required] of [
    ['settings.update', 200, 'settings', 'workspace', ['ifMatch', 'diff']],
    ['source.create', 201, 'source', id, ['ifMatch', 'diff']],
    ['source.update', 200, 'source', id, ['ifMatch', 'diff']],
    ['source.delete', 200, 'source', id, ['ifMatch', 'diff', 'historyDeleted']],
    ['delivery.retry', 200, 'delivery', failed.uid, ['retried']],
    ['channel.resume', 200, 'channel', 'env-webhook', ['released']],
  ]) {
    const [attempt, result, ...more] = of(action);
    assert.equal(more.length, 0, `${action}: exactly two rows`);
    assert.deepEqual(
      [attempt.outcome, attempt.ref, attempt.status],
      ['attempt', null, null],
      action
    );
    assert.deepEqual(
      [result.outcome, result.ref, result.status, result.target_type, result.target_id],
      ['ok', attempt.seq, status, type, target],
      action
    );
    assert.ok(result.seq > attempt.seq);
    within(result, required);
    assert.equal(result.actor_type, 'user');
    assert.equal(result.via, 'session');
  }
  // Reading the public key is not recorded: no row of the reveal that went with the HMAC secret.
  assert.deepEqual(of('signing.reveal'), []);
  assert.equal(publicKey.body.algorithm, 'Ed25519');
  // One row after the answer (O), one before it (S), in the unit of the change (U).
  for (const [action, outcome, status, type, target, required] of [
    ['source.test', 'ok', 200, 'source', id, ['type', 'savedCredentials', 'result']],
    ['email.test', 'ok', 200, 'channel', 'email', ['accepted']],
    ['sources.refresh', 'ok', 202, 'sources', '*', []],
    // Written before the answer (status: the one it is about to send, or none).
    ['config.export', 'ok', undefined, 'config', null, ['sources', 'bytes']],
    ['audit.export', 'ok', undefined, 'audit', null, ['format', 'rows', 'more', 'filters']],
    ['signing.rotate', 'ok', null, 'secret', 'env-webhook', ['diff']],
    ['session.revoked', 'ok', null, 'session', aId, ['cause']],
    ['session.revoked-others', 'ok', null, 'account', 'u_admin', ['count', 'kept']],
    [
      'account.password.changed',
      'ok',
      null,
      'account',
      'u_admin',
      ['revokedOtherSessions', 'newSessionId'],
    ],
    ['session.logout', 'ok', null, 'session', undefined, ['cause']],
  ]) {
    const found = of(action).filter(row => row.outcome === outcome);
    assert.equal(found.length, 1, `${action}: one row`);
    const [row] = found;
    assert.equal(row.target_type, type, action);
    if (status === undefined) assert.ok([null, 200].includes(row.status), action);
    else assert.equal(row.status, status, action);
    if (target !== undefined) assert.equal(row.target_id, target, action);
    within(row, required);
  }
  assert.equal(of('session.revoked')[0].detail.cause, 'by_user');
  assert.equal(of('session.revoked')[0].session_id, bId, 'the session that acted');
  assert.deepEqual(of('session.revoked-others')[0].detail, { count: 1, kept: 0 });
  assert.equal(of('session.logout')[0].detail.cause, 'signout');
  // Sign-ins: one row each, naming the new session.
  const logins = of('session.login').filter(row => row.outcome === 'ok');
  assert.equal(logins.length, 3);
  assert.ok(logins.every(row => row.session_id === row.target_id));
  // Aggregated: the first refusal at once (anonymous, its class only), the second counted.
  const refused = of('session.login').filter(row => row.outcome === 'failed');
  assert.equal(refused.length, 1);
  assert.deepEqual(
    [refused[0].actor_type, refused[0].count, refused[0].target_id, refused[0].detail],
    ['anonymous', 1, 'admin', { code: 'invalid_credentials', login: 'admin' }]
  );
  const used = of('auth.basic.used');
  assert.equal(used.length, 1);
  assert.deepEqual([used[0].via, used[0].count], ['basic', 1]);
  // Neither private key is in any row (as PEM, its body or the raw seed).
  for (const key of [before0, after0]) {
    const seed = createPrivateKey(key).export({ format: 'jwk' }).d;
    for (const form of [key.split('\n')[1], seed, Buffer.from(seed, 'base64url').toString('hex')])
      assert.equal(JSON.stringify(rows).includes(form), false);
  }
  // Delivery's own system event at the start (a new signing key) became a system row (D24);
  // the rotation is only its route's row.
  const secretRows = auditRows(directory).filter(row => row.action === 'signing.created');
  assert.equal(secretRows.length, 1);
  assert.deepEqual([secretRows[0].actor_type, secretRows[0].outcome], ['system', 'info']);

  // The list: results stand for their attempts; with outcome=attempt every attempt shows its
  // result. The aggregated row stays listed.
  const D = sessionCall(base, (await signIn(base, newPassword)).cookie);
  const entries = await listed(D, '?limit=500');
  for (const action of ['settings.update', 'delivery.retry']) {
    const shown = entries.filter(entry => entry.action === action);
    assert.deepEqual(
      shown.map(entry => entry.outcome),
      ['ok'],
      `${action}: the attempt is hidden behind its result`
    );
  }
  const attempts = await listed(D, '?outcome=attempt&limit=500');
  // The six attempt/result actions above (the reveal, a seventh, went with the HMAC secret).
  assert.ok(attempts.length >= 6);
  for (const entry of attempts) {
    assert.equal(entry.outcome, 'attempt');
    assert.ok(entry.result, `${entry.action}: result filled`);
    assert.equal(entry.result.outcome, 'ok');
  }
  assert.ok(entries.some(entry => entry.action === 'session.login' && entry.outcome === 'failed'));
  // The summary of the counted refusal is written at the window's end, or at the stop.
  await app.close();
  const summary = auditRows(directory).filter(
    row => row.action === 'session.login' && row.outcome === 'failed' && row.client_key === null
  );
  assert.equal(summary.length, 1);
  assert.equal(summary[0].count, 1);
  assert.deepEqual(summary[0].detail.codes, { invalid_credentials: 1 });
});

test(
  'in progress (server): an attempt is in progress only while its process runs; after a kill -9 it is unknown',
  { timeout: 120000 },
  async t => {
    const directory = processDirectory(t, 'orbit-audit-process-');
    const data = path.join(directory, 'data');
    // Holds the settings change inside its task: lowering the retention waits for the history
    // prune (up to settingsPruneMs, 20 s), which this preload never lets finish.
    const preload = path.join(directory, 'hold-prune.mjs');
    fs.writeFileSync(
      preload,
      `import { Store } from ${JSON.stringify(new URL('../lib/store.mjs', import.meta.url).href)};\nStore.prototype.prune = () => new Promise(() => {});\n`
    );
    const first = await startProcess(t, {
      app: workingTree,
      data,
      env: { NODE_OPTIONS: `--import=${pathToFileURL(preload).href}` },
    });
    const held = first.request('PATCH', '/api/settings', { body: { retentionDays: 7 } });
    held.catch(() => {});
    const entry = await until(
      async () =>
        (await first.request('GET', '/api/audit?action=settings.update')).json?.entries?.find(
          item => item.outcome === 'attempt'
        ),
      { what: 'the attempt in progress' }
    );
    assert.equal(entry.result, null);
    await first.kill();
    const second = await startProcess(t, { app: workingTree, data });
    const after = (await second.request('GET', '/api/audit?action=settings.update')).json.entries;
    const same = after.find(item => item.seq === entry.seq);
    assert.deepEqual([same.outcome, same.result], ['unknown', null]);
    const unknown = (await second.request('GET', '/api/audit?outcome=unknown')).json.entries;
    assert.ok(unknown.some(item => item.seq === entry.seq));
    // The change was saved before the kill: its result row is lost, so this start records it as
    // changed outside Uptime Goblin (its meta keys never moved, §3.4).
    const outside = (await second.request('GET', '/api/audit?action=config.changed-outside')).json
      .entries;
    assert.ok(
      outside.some(item => item.detail.diff.some(change => change.path === 'retentionDays')),
      JSON.stringify(outside)
    );
    // Unlike an unwritten result, a kill leaves no audit.unwritten line and no count on the page;
    // what the admin sees instead is this start's "previous stop was not recorded". docs/configuration.md
    // says so where it defines "Outcome unknown", rather than sending him to a line that does not
    // exist (review round 1).
    const listing = (await second.request('GET', '/api/audit?outcome=unknown')).json;
    assert.equal(listing.unwritten, null);
    assert.doesNotMatch(first.output(), /"orbit":"audit\.unwritten"/);
    const restarted = (await second.request('GET', '/api/audit?action=system.start&limit=1')).json
      .entries[0];
    assert.equal(restarted.detail.cleanStop, false);
    const guide = fs.readFileSync(new URL('../docs/configuration.md', import.meta.url), 'utf8');
    const meaning = guide.slice(
      guide.indexOf('**Outcome unknown** ('),
      guide.indexOf('\n\n- **Filters**')
    );
    assert.match(
      meaning,
      /^\*\*Outcome unknown\*\* \(Uptime Goblin could not record how a change ended/
    );
    assert.match(
      meaning,
      /or Uptime Goblin stopped during the change \(a crash, a kill or a power loss\), which leaves no such line and no count: Uptime Goblin's next start then reads "its previous stop was not recorded"/
    );
    await second.stop();
  }
);

test('the fail-closed gate (§9.3): without its attempt row nothing is changed, sent, shown or exported; sign-in and reads go on', async t => {
  const output = capture(t);
  const seam = { failing: false };
  // Every write unit of the audit's own units fails as a full disk does; reads pass.
  const wrapDb = (db, purpose) =>
    purpose === 'read'
      ? db
      : new Proxy(db, {
          get(target, property) {
            const value = target[property];
            if (property === 'write')
              return (...args) =>
                seam.failing ? Promise.reject(full()) : value.apply(target, args);
            return typeof value === 'function' ? value.bind(target) : value;
          },
        });
  const hook = await webhookReceiver(t, {
    respond: request => (JSON.parse(request.body).kind === 'firing' ? 422 : 200),
  });
  // The mail server refuses Uptime Goblin's sign-in until the gate is tested: email pauses and holds what
  // it has to send, so a Resume of email that acted would send it.
  let refusing = true;
  const mail = mailbox({ refuse: () => refusing });
  const down = new Set();
  // One audit window, which ends while Uptime Goblin runs: the audit's clock stays a second before
  // 13:00 until the recovery, then moves past it. The aggregation's timer, armed by the first
  // counted refusal, finds the window still open each time it fires until then.
  let now = Date.UTC(2026, 9, 3, 12, 59, 59);
  const { app, base, directory } = await start(t, {
    hook,
    mail,
    down,
    // Only fail() reporting the first AuditError's cause can make the guard full.
    storageGuard: { statfs: plenty, checkMs: 24 * hour },
    audit: { wrapDb, clock: () => now },
    // The refusals below are about the audit, not the lockout.
    loginThrottle: new LoginThrottle({ freeAttempts: 1000, globalFailures: 1000 }),
  });
  app.config.updateGlobal({ monitoring: fastFailure, email: emailSettings() });
  app.config.update('plex', { apiUrl: 'https://plex.example.test', apiKey: 'fixture-key' });
  down.add('plex');
  await app.poll(app.config.get('plex'));
  await app.flushNotifications();
  const A = sessionCall(base, (await signIn(base, password)).cookie);
  const failed = await until(async () =>
    (await A('/api/notifications/deliveries?channel=env-webhook')).body.deliveries.find(
      row => row.status === 'failed'
    )
  );
  const emailChannel = async () =>
    (await A('/api/notifications')).body.channels.find(channel => channel.id === 'email');
  const heldEmail = async () =>
    (await A('/api/notifications/deliveries?channel=email')).body.deliveries
      .filter(row => row.state === 'held')
      .map(row => row.uid);
  const held = await until(async () => {
    const uids = await heldEmail();
    return (await emailChannel()).state === 'paused' && uids.length ? uids : null;
  });
  const configFile = path.join(directory, 'config.json');
  const configBefore = fs.readFileSync(configFile);
  const revision = app.config.value.revision;

  seam.failing = true;
  await assert.rejects(
    app.audit.append({
      action: 'notifications.saved',
      outcome: 'info',
      target: { type: 'outbox', id: null, name: null },
    }),
    error => error.code === 'audit_unavailable',
    'the seam fails the audit before anything is asserted'
  );
  const rowsAt = auditRows(directory).length;
  const first = await A('/api/settings', 'PATCH', { title: 'Not saved' });
  assert.equal(first.status, 503);
  assert.equal(first.body.code, 'audit_unavailable');
  assert.equal(first.headers.get('retry-after'), '30');
  assert.deepEqual(fs.readFileSync(configFile), configBefore);
  assert.equal(app.config.value.revision, revision);
  assert.equal(app.guard.state().full, true, 'fail() reported the cause to the guard');
  // The guard is full: configuration writes are refused before their attempt.
  for (const [route, method, body] of [
    ['/api/settings', 'PATCH', { title: 'Not saved' }],
    ['/api/services', 'POST', { type: 'json', name: 'X', apiUrl: 'https://x.example.test' }],
    ['/api/notifications/webhook/signing-secret', 'POST', {}],
  ]) {
    const refused = await A(route, method, body);
    assert.equal(refused.status, 503, route);
    assert.equal(refused.body.code, 'storage_full', route);
  }
  // Retry and Resume: fail closed, nothing sent. Alerts are still sent, and the full guard has
  // one of its own: raised when the first refusal above made the guard full, it reaches the
  // receiver on the outbox's schedule, normally a few milliseconds later, while the refusals
  // above run. Whenever it came later than they did (a slower send, a busy machine), it arrived
  // during Retry and Resume and was counted as a send of theirs. So it is waited for, and
  // everything due is sent, before the count is taken.
  const body = request => JSON.parse(request.body);
  await until(() => hook.requests.some(request => body(request).rule === '__disk'), {
    what: 'the full disk alert at the receiver',
  });
  await app.flushNotifications();
  const sent = hook.requests.length,
    mailed = mail.messages.length;
  // Email would now send what it holds, were it resumed.
  refusing = false;
  for (const route of [
    `/api/notifications/deliveries/${failed.uid}/retry`,
    '/api/notifications/channels/env-webhook/resume',
    '/api/notifications/channels/email/resume',
  ]) {
    const refused = await A(route, 'POST', {});
    assert.equal(refused.status, 503, route);
    assert.equal(refused.body.code, 'audit_unavailable', route);
  }
  // A delivery they had queued again or released would be due at once (Retry sets it due now):
  // after a moment for anything they started, the flush sends everything due, digest windows
  // included, and waits for those sends, so nothing can still be on its way when the receiver
  // is read, however slowly the delivery worker runs.
  await sleep(200);
  await app.flushNotifications();
  assert.deepEqual(hook.requests.slice(sent).map(body), [], 'the receiver got nothing');
  assert.deepEqual(mail.messages.slice(mailed), [], 'no email was sent');
  assert.equal((await emailChannel()).state, 'paused', 'email is still paused');
  assert.deepEqual(
    (await heldEmail()).filter(uid => held.includes(uid)),
    held,
    'what email held is still held'
  );
  // The public key is a read Uptime Goblin does not record, so it is answered all the same (it holds
  // nothing secret); the reveal of the pre-release builds is gone.
  const publicKey = await A('/api/notifications/webhook/public-key');
  assert.equal(publicKey.status, 200);
  assert.equal(JSON.stringify(publicKey.body).includes('PRIVATE KEY'), false);
  assert.equal(
    (await A('/api/notifications/webhook/signing-secret/reveal', 'POST', {})).status,
    404
  );
  for (const route of ['/api/config/export', '/api/audit/export?format=csv']) {
    const refused = await A(route);
    assert.equal(refused.status, 503, route);
    assert.equal(refused.headers.get('content-disposition'), null, route);
  }
  assert.equal((await A('/api/dashboard')).status, 200);
  assert.equal((await A('/api/audit')).status, 200);
  assert.equal(auditRows(directory).length, rowsAt, 'no row for anything refused');
  // A sign-in writes its session row and its row in identity's own unit (not the audit's).
  const b = await signIn(base, password);
  assert.ok(b.cookie);
  const signedIn = auditRows(directory).slice(rowsAt);
  assert.deepEqual(
    signedIn.map(row => [row.action, row.outcome]),
    [['session.login', 'ok']]
  );
  // Refused sign-ins while full are only counted.
  for (let i = 0; i < 20; i++) {
    const answer = await fetch(new URL('/api/auth/login', base), {
      method: 'POST',
      headers: browserHeaders(base),
      body: JSON.stringify({ login: `name-${i}`, password: 'wrong-password-0001' }),
    });
    assert.equal(answer.status, 401);
  }
  assert.equal(auditRows(directory).length, rowsAt + 1);
  // Operations run as without the audit; their rows go to stderr.
  assert.equal(
    (await A('/api/test-service', 'POST', { serviceId: 'plex', settings: {} })).status,
    200
  );
  assert.equal((await A('/api/email/test', 'POST', {})).status, 200);
  assert.equal((await A('/api/refresh', 'POST', {})).status, 202);
  const unwritten = output.audit('audit.unwritten').map(line => line.row?.action);
  for (const action of ['source.test', 'email.test', 'sources.refresh'])
    assert.equal(unwritten.filter(name => name === action).length, 1, action);
  assert.equal(auditRows(directory).length, rowsAt + 1);

  // The seam lifted and the guard's check run: the next change writes its rows.
  seam.failing = false;
  app.guard.check();
  assert.equal(app.guard.state().full, false);
  assert.equal((await A('/api/settings', 'PATCH', { title: 'Saved' })).status, 200);
  assert.deepEqual(
    auditRows(directory)
      .filter(row => row.action === 'settings.update')
      .map(row => row.outcome),
    ['attempt', 'ok']
  );
  // The window ends (the audit's clock moves past 13:00): while Uptime Goblin runs, its summary is
  // written at the window's end and holds exactly the 20 refusals (no immediate row was taken
  // while full).
  now = Date.UTC(2026, 9, 3, 13, 0, 30);
  const refusals = await until(
    () => {
      const found = auditRows(directory).filter(
        row => row.action === 'session.login' && row.outcome !== 'ok'
      );
      return found.length ? found : null;
    },
    { what: "the window's summary" }
  );
  assert.equal(refusals.length, 1);
  assert.equal(refusals[0].time, Date.UTC(2026, 9, 3, 13), "at the window's end");
  assert.deepEqual(
    [refusals[0].count, refusals[0].detail.codes],
    [20, { invalid_credentials: 20 }]
  );
  assert.equal(refusals[0].detail.clients, 1);
  await app.close();
  assert.equal(
    auditRows(directory).filter(row => row.action === 'session.login' && row.outcome !== 'ok')
      .length,
    1,
    'nothing left for the stop'
  );
});

test('the result-row gate (§9.3): a lost result goes to stderr once, its attempt reads unknown, and the next start records the change', async t => {
  const output = capture(t);
  const seam = { failing: false };
  const wrapDb = (db, purpose) =>
    purpose === 'result'
      ? new Proxy(db, {
          get(target, property) {
            const value = target[property];
            if (property === 'write')
              return (...args) =>
                seam.failing ? Promise.reject(full()) : value.apply(target, args);
            return typeof value === 'function' ? value.bind(target) : value;
          },
        })
      : db;
  const directory = temporary(t);
  const first = await start(t, { directory, audit: { wrapDb } });
  const A = sessionCall(first.base, (await signIn(first.base, password)).cookie);
  seam.failing = true;
  const changed = await A('/api/settings', 'PATCH', { title: 'Result lost' });
  assert.equal(changed.status, 200);
  assert.equal(
    JSON.parse(fs.readFileSync(path.join(directory, 'config.json'))).title,
    'Result lost'
  );
  const lost = output.audit('audit.unwritten');
  assert.equal(lost.length, 1, 'one line, at once');
  assert.equal(lost[0].row.action, 'settings.update');
  assert.ok(lost[0].row.detail.diff.some(change => change.path === 'title'));
  const unknown = await A('/api/audit?outcome=unknown');
  const attempt = unknown.body.entries.find(entry => entry.action === 'settings.update');
  assert.ok(attempt, 'the attempt is listed unknown');
  assert.deepEqual(unknown.body.unwritten.count, 1);
  assert.equal(typeof unknown.body.unwritten.since, 'number');
  // Lifted: a later unit writes only its own rows; the lost one is never written.
  seam.failing = false;
  assert.equal((await A('/api/refresh', 'POST', {})).status, 202);
  assert.equal(auditRows(directory).filter(row => row.ref === attempt.seq).length, 0);
  assert.equal(output.audit('audit.unwritten').length, 1);
  await first.app.close();
  // The next start: the change is recorded as made outside Uptime Goblin, with the same diff.
  await start(t, { directory });
  const outside = auditRows(directory).filter(row => row.action === 'config.changed-outside');
  assert.equal(outside.length, 1);
  assert.deepEqual(
    outside[0].detail.diff.find(change => change.path === 'title'),
    lost[0].row.detail.diff.find(change => change.path === 'title')
  );
});

// Codex review A3: exclusive() ends a write's turn before settle writes its result row, so the
// next configuration write can be answered and its result written while the first result still
// waits (between SQLite retries). That result moved the configuration keys to its own
// after-snapshot, which held the first change: lost, the first change was in neither a result
// row nor the next start's config.changed-outside.
const configKeysIn = directory => {
  const db = new DatabaseSync(path.join(directory, 'control.sqlite'), { readOnly: true });
  try {
    return Object.fromEntries(
      db
        .prepare(
          "SELECT key, value FROM meta WHERE key IN ('config_revision_seen', 'audit_config_public', 'audit_config_secrets') ORDER BY key"
        )
        .all()
        .map(row => [row.key, row.value])
    );
  } finally {
    db.close();
  }
};
test('the result-row gate, overlapping (Codex review A3): a result written while the result of an earlier configuration write waits leaves the keys below it; lost, the next start records the earlier change; written, the keys follow the later one', async t => {
  for (const [name, times] of [
    ['lost after the retries', 4],
    ['written at its third attempt', 2],
  ])
    await t.test(name, async t => {
      const output = capture(t);
      let reached, release;
      const seam = {
        armed: false,
        reached: new Promise(resolve => (reached = resolve)),
        released: new Promise(resolve => (release = resolve)),
      };
      t.after(() => release()); // a failed assertion does not leave the write waiting
      // The first result row written once armed waits until released, then goes through the
      // real Db's retry loop: `times` attempts rolled back (3 retries, so 4 is a failure).
      const wrapDb = (db, purpose) => {
        if (purpose !== 'result' || !seam.armed) return db;
        seam.armed = false;
        const retried = retryOnce(db, { times });
        return new Proxy(db, {
          get(target, property) {
            if (property === 'write')
              return async (...args) => {
                reached();
                await seam.released;
                return retried.write(...args);
              };
            const value = Reflect.get(target, property, target);
            return typeof value === 'function' ? value.bind(target) : value;
          },
        });
      };
      const directory = temporary(t);
      const first = await start(t, { directory, audit: { wrapDb } });
      const A = sessionCall(first.base, (await signIn(first.base, password)).cookie);
      const results = () =>
        auditRows(directory).filter(row => row.action === 'settings.update' && row.ref !== null);
      const baseline = configKeysIn(directory);
      seam.armed = true;
      const a = A('/api/settings', 'PATCH', { title: 'Changed by A' });
      await seam.reached;
      // A's turn has ended and its result waits: B is applied, answered and recorded.
      const b = await A('/api/settings', 'PATCH', { pollSeconds: 120 });
      assert.equal(b.status, 200);
      await until(() => results().length === 1, { what: "B's result row" });
      assert.deepEqual(
        results()[0].detail.diff.map(change => change.path),
        ['pollSeconds']
      );
      assert.deepEqual(configKeysIn(directory), baseline, 'B leaves the keys below A');
      release();
      assert.equal((await a).status, 200);
      const config = JSON.parse(fs.readFileSync(path.join(directory, 'config.json'), 'utf8'));
      if (times === 4) {
        await until(() => output.audit('audit.unwritten').length === 1, { what: 'A lost' });
        assert.equal(output.audit('audit.unwritten')[0].row.action, 'settings.update');
        assert.equal(results().length, 1);
        assert.deepEqual(configKeysIn(directory), baseline, 'the keys stayed');
      } else {
        await until(() => results().length === 2, { what: "A's result row" });
        assert.equal(output.audit('audit.unwritten').length, 0);
        assert.equal(
          configKeysIn(directory).config_revision_seen,
          String(config.revision),
          'A, settled last, publishes the newer snapshot B held back'
        );
      }
      await first.app.close();
      await start(t, { directory });
      const outside = auditRows(directory).filter(row => row.action === 'config.changed-outside');
      if (times === 4) {
        assert.equal(outside.length, 1);
        assert.deepEqual(outside[0].detail.diff.map(change => change.path).sort(), [
          'pollSeconds',
          'title',
        ]);
        assert.deepEqual(
          outside[0].detail.diff.find(change => change.path === 'title'),
          { path: 'title', from: 'Uptime Goblin', to: 'Changed by A' }
        );
      } else assert.deepEqual(outside, [], 'both changes have results');
    });
});

// The limits a supervised start runs without, because GOBLIN_ALLOW_UNLIMITED allows it (server.mjs's
// main block hands what it found to createApp as resourceLimits), are in that start's
// system.start entry, and their coming and going are security changes.
test('start rows: a start that runs without a resource limit under GOBLIN_ALLOW_UNLIMITED records which in system.start', async t => {
  for (const level of ['log', 'info', 'warn', 'error']) t.mock.method(console, level, () => {});
  const directory = temporary(t);
  const starts = () => auditRows(directory).filter(row => row.action === 'system.start');
  const status = (cpu, allowUnlimited) => ({
    supervised: true,
    allowUnlimited,
    limits: {
      memory: { state: 'enforced', detail: 'memory.max 1073741824' },
      cpu,
      pids: { state: 'enforced', detail: 'pids.max 256' },
    },
  });
  // Every limit in force (or not supervised): no `unlimited`, as before.
  await (await start(t, { directory })).app.close();
  assert.equal(Object.hasOwn(starts().at(-1).detail.security, 'unlimited'), false);
  // The CPU limit not in force, and allowed.
  const allowed = await start(t, {
    directory,
    resourceLimits: status({ state: 'missing', detail: 'cpu.max is max' }, ['cpu']),
  });
  assert.deepEqual(starts().at(-1).detail.security.unlimited, ['cpu']);
  assert.deepEqual(starts().at(-1).detail.securityChanged, ['unlimited']);
  await allowed.app.close();
  // Allowed but in force: nothing runs without a limit, so nothing is recorded, and its going is
  // a change.
  const needless = await start(t, {
    directory,
    resourceLimits: status({ state: 'enforced', detail: 'cpu.max 100000 100000: 1 CPU' }, ['cpu']),
  });
  assert.equal(Object.hasOwn(starts().at(-1).detail.security, 'unlimited'), false);
  assert.deepEqual(starts().at(-1).detail.securityChanged, ['unlimited']);
  await needless.app.close();
  // The same again: no change.
  await (await start(t, { directory })).app.close();
  assert.deepEqual(starts().at(-1).detail.securityChanged ?? [], []);
});

// The connections one client may hold open at once (GOBLIN_MAX_CONNECTIONS_PER_CLIENT) are a
// security setting: each start records the share it applies, and a change is a security change.
test('start rows: system.start records the per-client connection share it applies, and its change', async t => {
  for (const level of ['log', 'info', 'warn', 'error']) t.mock.method(console, level, () => {});
  const directory = temporary(t);
  const starts = () => auditRows(directory).filter(row => row.action === 'system.start');
  await (await start(t, { directory })).app.close();
  assert.equal(starts().at(-1).detail.security.maxConnectionsPerClient, 32, 'the default');
  const raised = await start(t, { directory, maxConnectionsPerClient: '64' });
  assert.equal(starts().at(-1).detail.security.maxConnectionsPerClient, 64);
  assert.deepEqual(starts().at(-1).detail.securityChanged, ['maxConnectionsPerClient']);
  await raised.app.close();
  await (await start(t, { directory, maxConnectionsPerClient: '64' })).app.close();
  assert.deepEqual(starts().at(-1).detail.securityChanged, []);
});

// A 1.5 build before the share was recorded stored a snapshot without it: the first start after
// the update reads it as the default share, so nobody's unchanged environment reads as a change.
test('start rows: a stored security snapshot without the per-client share reads as the default, 32', async t => {
  for (const level of ['log', 'info', 'warn', 'error']) t.mock.method(console, level, () => {});
  const directory = temporary(t);
  const starts = () => auditRows(directory).filter(row => row.action === 'system.start');
  // What the earlier build left: the same snapshot, without the key.
  const withoutShare = () => {
    const db = new DatabaseSync(path.join(directory, 'control.sqlite'));
    try {
      const { value } = db
        .prepare("SELECT value FROM meta WHERE key = 'audit_security_seen'")
        .get();
      const seen = JSON.parse(value);
      assert.equal(seen.maxConnectionsPerClient, 32);
      delete seen.maxConnectionsPerClient;
      db.prepare("UPDATE meta SET value = ? WHERE key = 'audit_security_seen'").run(
        JSON.stringify(seen)
      );
    } finally {
      db.close();
    }
  };
  await (await start(t, { directory })).app.close();
  withoutShare();
  await (await start(t, { directory })).app.close();
  assert.equal(starts().at(-1).detail.security.maxConnectionsPerClient, 32);
  assert.deepEqual(starts().at(-1).detail.securityChanged, [], 'the default is no change');
  // Another value than the default is a change from it.
  withoutShare();
  await (await start(t, { directory, maxConnectionsPerClient: '64' })).app.close();
  assert.deepEqual(starts().at(-1).detail.securityChanged, ['maxConnectionsPerClient']);
});

test(
  'start rows: system.start once Uptime Goblin serves, cleanStop, changes made while stopped, the security settings, a listen failure, a snapshot restore',
  { timeout: 120000 },
  async t => {
    for (const level of ['log', 'info', 'warn', 'error']) t.mock.method(console, level, () => {});
    const directory = temporary(t);
    const starts = () => auditRows(directory).filter(row => row.action === 'system.start');
    // A new directory: no system.start before listen().
    const unlistened = await start(t, { directory, listen: false });
    assert.equal(starts().length, 0);
    await unlistened.app.listen();
    assert.equal(starts().length, 1);
    assert.equal(starts()[0].detail.first, true);
    assert.equal(starts()[0].detail.version, release);
    await unlistened.app.close();
    // A clean stop, then a start.
    const second = await start(t, { directory });
    assert.deepEqual(
      [starts().at(-1).detail.first, starts().at(-1).detail.cleanStop],
      [false, true]
    );
    // The key the first start generated is read from the data directory now: the same key from
    // the same place, so no security setting changed (integration, the check's finding 3).
    assert.deepEqual(
      [starts()[0].detail.security.keySource, starts().at(-1).detail.security.keySource],
      ['generated', 'data-directory']
    );
    assert.deepEqual(starts().at(-1).detail.securityChanged, []);
    await second.app.close();
    // config.json edited while stopped, its revision kept: found by its content.
    const file = path.join(directory, 'config.json');
    const edit = change => {
      const value = JSON.parse(fs.readFileSync(file, 'utf8'));
      change(value);
      fs.writeFileSync(file, JSON.stringify(value, null, 2));
      return value.revision;
    };
    const revision = edit(value => (value.title = 'Edited by hand'));
    // GOBLIN_LEGACY_BASIC changed between starts (true until now).
    const third = await start(t, { directory, legacyBasic: false });
    const outside = () =>
      auditRows(directory).filter(row => row.action === 'config.changed-outside');
    assert.equal(outside().length, 1);
    assert.deepEqual([outside()[0].detail.from, outside()[0].detail.to], [revision, revision]);
    assert.equal(
      outside()[0].detail.diff.find(change => change.path === 'title').to,
      'Edited by hand'
    );
    assert.deepEqual(starts().at(-1).detail.securityChanged, ['legacyBasic']);
    assert.equal(starts().at(-1).detail.security.legacyBasic, false);
    await third.app.close();
    // A source URL carrying a token: the diff holds it stripped (the start repaired the file and
    // saved it, so the revision moved and `repaired` says why).
    edit(value => {
      value.services.find(s => s.id === 'linux').url =
        'https://linux.example.test/?token=AUDITSENTINEL01';
    });
    const fourth = await start(t, { directory, legacyBasic: false });
    assert.equal(outside().length, 2);
    const stripped = outside()[1].detail.diff.find(change => change.path === 'services.linux.url');
    assert.ok(stripped, JSON.stringify(outside()[1].detail));
    assert.equal(stripped.to, 'https://linux.example.test/');
    assert.equal(outside()[1].detail.repaired, true);
    assert.doesNotMatch(JSON.stringify(auditRows(directory)), /AUDITSENTINEL01/);
    assert.deepEqual(starts().at(-1).detail.securityChanged, [], 'nothing changed this time');
    await fourth.app.close();
    // A start that cannot listen (its port taken), three times: no start row, nothing else.
    const taken = net.createServer();
    await new Promise(resolve => taken.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => taken.close(resolve)));
    const count = auditRows(directory).length;
    for (let i = 0; i < 3; i++) {
      const app = await createApp({
        directory,
        host: '127.0.0.1',
        port: taken.address().port,
        password,
        allowedHosts: '',
        trustProxy: '',
        startScheduler: false,
        webhook: '',
      });
      await assert.rejects(app.listen(), error => error.code === 'EADDRINUSE');
      await app.close();
    }
    assert.equal(
      auditRows(directory).length,
      count,
      'nothing written by the starts that never served'
    );
    // A snapshot, more rows, a restore of it, a start.
    const snapshot = await createSnapshot(directory, { reason: 'manual', release, history: false });
    const fifth = await start(t, { directory });
    await signIn(fifth.base, password);
    await fifth.app.close();
    const lock = acquireLock(directory);
    try {
      await restoreSnapshot(directory, snapshot.id, { lock, release });
    } finally {
      lock.release();
    }
    const restored = await start(t, { directory });
    const rows = auditRows(directory);
    const anchor = rows.find(row => row.action === 'system.restore');
    assert.deepEqual([anchor.detail.cause, anchor.detail.snapshot], ['snapshot', snapshot.id]);
    assert.ok(rows.some(row => row.action === 'session.revoked-restore' && row.seq > anchor.seq));
    const snapshots = rows.filter(row => row.action === 'data.snapshot').map(row => row.target_id);
    assert.ok(snapshots.includes(snapshot.id), JSON.stringify(snapshots));
    const verified = await restored.script('/api/audit/verify');
    assert.equal(verified.body.result, 'intact', JSON.stringify(verified.body));
    assert.ok(verified.body.anchors.some(item => item.action === 'system.restore'));
  }
);

// Codex review A5: a password change refused before its credential signed in (none sent; an
// ended session) answered its 401 but left no trace in the log, though spec §5.2 counts every
// refusal of the route. Through a real Uptime Goblin: one row each, as nobody signed in, the first at
// once and the second in the summary written at the stop; the log still verifies.
test('Codex review A5: password changes refused before sign-in are rows of the log, as nobody signed in', async t => {
  const { app, base, script, directory } = await start(t);
  const pass = {
    currentPassword: 'synthetic-current',
    password: 'synthetic-next-0001',
    confirmPassword: 'synthetic-next-0001',
  };
  const missing = await sessionCall(base, null)('/api/account/password', 'POST', pass);
  assert.deepEqual([missing.status, missing.body.code], [401, 'signin_required']);
  const B = sessionCall(base, (await signIn(base, password)).cookie);
  assert.equal((await B('/api/auth/logout', 'POST', {})).status, 204);
  const ended = await B('/api/account/password', 'POST', pass);
  assert.deepEqual([ended.status, ended.body.code], [401, 'session_expired']);
  const listedRows = (await script('/api/audit?action=account.password.changed')).body.entries;
  assert.deepEqual(
    listedRows.map(entry => [entry.outcome, entry.actor?.type, entry.detail]),
    [['denied', 'anonymous', { code: 'signin_required' }]]
  );
  assert.equal((await script('/api/audit/verify')).body.result, 'intact');
  await app.close();
  const rows = auditRows(directory).filter(row => row.action === 'account.password.changed');
  assert.deepEqual(
    rows.map(row => [
      row.outcome,
      row.count,
      row.actor_type,
      row.actor_id,
      row.actor_name,
      row.via,
      row.session_id,
      row.target_type,
      row.target_id,
    ]),
    [
      ['denied', 1, 'anonymous', null, null, null, null, 'account', 'u_admin'],
      ['denied', 1, 'anonymous', null, null, null, null, 'account', 'u_admin'],
    ]
  );
  assert.deepEqual([rows[0].detail, rows[0].client_key], [{ code: 'signin_required' }, 'loopback']);
  assert.deepEqual([rows[1].detail.codes, rows[1].client_key], [{ session_expired: 1 }, null]);
  assert.doesNotMatch(JSON.stringify(auditRows(directory)), /synthetic-current|synthetic-next/);
  // Restarted, the log with both rows verifies.
  const again = await start(t, { directory });
  const verified = await again.script('/api/audit/verify');
  assert.equal(verified.body.result, 'intact', JSON.stringify(verified.body));
});

// A5 verification: counted into the same action, refusals made before sign-in once wiped a
// signed-in session from the log. A thief holding a stolen session cookie sent two password
// changes without a credential at the top of the hour (the first takes the immediate row, the
// second put nobody into the summary), then guessed the current password from the session: the
// summary that counted the guesses named no one, and no row held the session's id. Through a
// real Uptime Goblin, the summary names the guessing session; its codes say which refusal came first.
test('Codex review A5: password-change refusals before sign-in cannot wipe a guessing session from the log', async t => {
  // One audit window whatever the time of day: the audit's clock stays where the test began.
  const now = Date.now();
  const { app, base, directory } = await start(t, { audit: { clock: () => now } });
  const guess = n => ({
    currentPassword: `synthetic-guess-${n}`,
    password: 'synthetic-next-0001',
    confirmPassword: 'synthetic-next-0001',
  });
  const stolen = sessionCall(base, (await signIn(base, password)).cookie);
  const sessionId = auditRows(directory)
    .filter(row => row.action === 'session.login' && row.outcome === 'ok')
    .at(-1).session_id;
  assert.match(sessionId, /^s_/);
  const nobody = sessionCall(base, null);
  const answers = [];
  for (let n = 0; n < 2; n++)
    answers.push((await nobody('/api/account/password', 'POST', guess(n))).body.code);
  for (let n = 1; n <= 4; n++)
    answers.push((await stolen('/api/account/password', 'POST', guess(n))).body.code);
  assert.deepEqual(answers, [
    'signin_required',
    'signin_required',
    'current_password_incorrect',
    'current_password_incorrect',
    'current_password_incorrect',
    'current_password_incorrect',
  ]);
  await app.close();
  const rows = auditRows(directory).filter(row => row.action === 'account.password.changed');
  assert.deepEqual(
    rows.map(row => [
      row.outcome,
      row.count,
      row.actor_type,
      row.session_id,
      row.detail.code ?? row.detail.codes,
    ]),
    [
      ['denied', 1, 'anonymous', null, 'signin_required'],
      ['failed', 5, 'user', sessionId, { current_password_incorrect: 4, signin_required: 1 }],
    ]
  );
  assert.doesNotMatch(JSON.stringify(auditRows(directory)), /synthetic-guess|synthetic-next/);
  const again = await start(t, { directory });
  const verified = await again.script('/api/audit/verify');
  assert.equal(verified.body.result, 'intact', JSON.stringify(verified.body));
});

test('aborted test: a connection test whose browser went away is recorded with no status and client_closed', async t => {
  for (const level of ['log', 'info', 'warn', 'error']) t.mock.method(console, level, () => {});
  let started;
  const collecting = new Promise(resolve => (started = resolve));
  const { base, directory } = await start(t, {
    collector: async service =>
      new Promise((resolve, reject) => {
        started();
        service.signal.addEventListener('abort', () => reject(new Error('aborted')));
      }),
  });
  const a = await signIn(base, password);
  const request = http.request(new URL('/api/test-service', base), {
    method: 'POST',
    headers: { ...browserHeaders(base), Cookie: a.cookie },
  });
  request.on('error', () => {});
  request.end(
    JSON.stringify({
      settings: { type: 'json', name: 'Aborted', apiUrl: 'https://a.example.test' },
    })
  );
  await collecting;
  request.destroy();
  const row = await until(() => auditRows(directory).find(item => item.action === 'source.test'));
  assert.deepEqual([row.status, row.detail.code, row.outcome], [null, 'client_closed', 'failed']);
});

test('checkpoints: every unit that records prints one line with a valid MAC; GOBLIN_AUDIT_LOG copies the rows', async t => {
  const output = capture(t);
  for (const mirror of ['off', 'stdout', 'stdout-full']) {
    const from = output.lines.length;
    const lines = kind =>
      output.lines
        .slice(from)
        .filter(line => line.text.startsWith(`{"orbit":"${kind}"`))
        .map(line => JSON.parse(line.text));
    const directory = temporary(t);
    const { app, base } = await start(t, { directory, auditLog: mirror });
    const atStart = lines('audit.checkpoint').length;
    assert.ok(atStart >= 1, 'the start rows printed theirs');
    const a = await signIn(base, password);
    assert.equal(lines('audit.checkpoint').length, atStart + 1, 'the sign-in');
    assert.equal(
      (await sessionCall(base, a.cookie)('/api/settings', 'PATCH', { title: `Mirror ${mirror}` }))
        .status,
      200
    );
    assert.equal(lines('audit.checkpoint').length, atStart + 3, 'its attempt and its result');
    const rows = auditRows(directory);
    // Each line names the last row of its unit.
    for (const line of lines('audit.checkpoint').slice(atStart)) {
      const row = rows.find(item => item.seq === line.seq);
      assert.deepEqual([line.hash, line.time, line.reason], [row.hash, row.time, 'commit']);
    }
    const mirrored = lines('audit');
    if (mirror === 'off') assert.deepEqual(mirrored, []);
    else {
      assert.equal(mirrored.length, rows.length, 'one line per row');
      const change = mirrored.find(
        line => line.action === 'settings.update' && line.outcome === 'ok'
      );
      assert.equal('detail' in change, mirror === 'stdout-full');
      if (mirror === 'stdout-full')
        assert.ok(change.detail.diff.some(item => item.path === 'title'));
    }
    await app.close();
    const all = lines('audit.checkpoint');
    assert.equal(await verifiedCheckpoints(directory, all), all.length);
  }
});

test(
  'the prune: past the retention, its checkpoint first, then audit.pruned; the leading run only; not with the clock behind; the row cap',
  { timeout: 120000 },
  async t => {
    const output = capture(t);
    // Now, as identity's own rows (its clock is the real one) are written now too.
    let now = Date.now();
    const directory = temporary(t);
    const { app, base, script } = await start(t, {
      directory,
      auditRetentionDays: '30',
      audit: { clock: () => now, maxRows: 2000 },
    });
    const A = sessionCall(base, (await signIn(base, password)).cookie);
    for (let i = 0; i < 5; i++)
      assert.equal((await A('/api/settings', 'PATCH', { title: `Old ${i}` })).status, 200);
    const head = auditRows(directory).at(-1).seq;
    // 32 days on: every row but the newest is past the window and a day.
    now += 32 * day;
    await app.jobs.runNow('audit.maintain');
    const pruneLines = output.audit('audit.checkpoint').filter(line => line.reason === 'prune');
    assert.equal(pruneLines.length, 1);
    assert.equal(pruneLines[0].seq, head - 1);
    const rows = auditRows(directory);
    const pruned = rows.find(row => row.action === 'audit.pruned');
    assert.deepEqual([pruned.detail.through, pruned.detail.reason], [head - 1, 'age']);
    assert.equal(rows[0].seq, head, 'only the leading run of expired rows went');
    assert.equal((await script('/api/audit/verify')).body.result, 'intact');

    // The clock behind the newest row by more than an hour: no age prune, one warning a day.
    now -= 2 * hour;
    await app.jobs.runNow('audit.maintain');
    await app.jobs.runNow('audit.maintain');
    const behind = output
      .err()
      .filter(line => line.startsWith("Uptime Goblin's clock is behind its newest audit entry"));
    assert.equal(behind.length, 1);
    assert.equal(auditRows(directory).filter(row => row.action === 'audit.pruned').length, 1);
    now += 2 * hour;
  }
);

test(
  'the prune: beyond the row cap by more than 1,000 rows, the oldest go',
  { timeout: 120000 },
  async t => {
    capture(t);
    const directory = temporary(t);
    const { app, script } = await start(t, { directory, audit: { maxRows: 2000 } });
    for (let i = 0; i < 3005; i++)
      await app.audit.append({
        action: 'notifications.saved',
        outcome: 'info',
        target: { type: 'outbox', id: null, name: null },
      });
    await app.jobs.runNow('audit.maintain');
    const pruned = auditRows(directory).filter(row => row.action === 'audit.pruned');
    assert.equal(pruned.length, 1);
    assert.equal(pruned[0].detail.reason, 'cap');
    assert.ok(auditRows(directory).length <= 2002, `${auditRows(directory).length} rows`);
    assert.equal((await script('/api/audit/verify')).body.result, 'intact');
  }
);

test('the prune: one row with a wrong time near the head deletes nothing', async t => {
  capture(t);
  let now = Date.UTC(2026, 9, 3);
  const directory = temporary(t);
  const { app, base } = await start(t, {
    directory,
    auditRetentionDays: '30',
    audit: { clock: () => now },
  });
  const A = sessionCall(base, (await signIn(base, password)).cookie);
  const real = now;
  now = 0;
  assert.equal((await A('/api/refresh', 'POST', {})).status, 202);
  now = real;
  assert.equal((await A('/api/settings', 'PATCH', { title: 'After' })).status, 200);
  const count = auditRows(directory).length;
  await app.jobs.runNow('audit.maintain');
  assert.equal(auditRows(directory).length, count);
  assert.ok(!auditRows(directory).some(row => row.action === 'audit.pruned'));
});

test('one verification at a time: concurrent checks join; a prune waits for a running check and runs after it', async t => {
  capture(t);
  // Now, as identity's own rows (its clock is the real one) are written now too.
  let now = Date.now();
  const reads = { count: 0, hold: null };
  const wrapDb = (db, purpose) =>
    purpose === 'read'
      ? new Proxy(db, {
          get(target, property) {
            const value = target[property];
            if (property === 'read')
              return async (...args) => {
                reads.count++;
                if (reads.hold) {
                  const gate = reads.hold;
                  reads.hold = null;
                  await gate.promise;
                }
                return value.apply(target, args);
              };
            return typeof value === 'function' ? value.bind(target) : value;
          },
        })
      : db;
  const directory = temporary(t);
  const { app, script } = await start(t, {
    directory,
    auditRetentionDays: '30',
    audit: { clock: () => now, wrapDb },
  });
  for (let i = 0; i < 3; i++) assert.equal((await script('/api/refresh', 'POST', {})).status, 202);
  reads.count = 0;
  const alone = await script('/api/audit/verify');
  const once = reads.count;
  // The second request arrives while the first verification waits on its first read.
  reads.count = 0;
  let release;
  reads.hold = { promise: new Promise(resolve => (release = resolve)) };
  const first = script('/api/audit/verify');
  await until(() => reads.hold === null, { what: 'the first verification to start' });
  const second = script('/api/audit/verify');
  await sleep(100);
  release();
  const [one, two] = await Promise.all([first, second]);
  assert.equal(reads.count, once, 'the second request joined the first');
  assert.deepEqual(one.body, two.body);
  assert.equal(alone.body.result, 'intact');

  // A prune waits for a verification in progress.
  now += 32 * day;
  let open;
  reads.hold = { promise: new Promise(resolve => (open = resolve)) };
  const checking = script('/api/audit/verify');
  await until(() => reads.hold === null, { what: 'the verification to start' });
  const pruning = app.jobs.runNow('audit.maintain');
  await sleep(200);
  assert.ok(
    !auditRows(directory).some(row => row.action === 'audit.pruned'),
    'not during the check'
  );
  open();
  assert.equal((await checking).body.result, 'intact');
  await pruning;
  assert.ok(
    auditRows(directory).some(row => row.action === 'audit.pruned'),
    'in the same run'
  );
});

test("export: the CSV starts with the BOM, and its own row comes before the next request's", async t => {
  capture(t);
  const { base, directory } = await start(t);
  const A = sessionCall(base, (await signIn(base, password)).cookie);
  const response = await fetch(new URL('/api/audit/export?format=csv', base), {
    headers: { ...browserHeaders(base), Cookie: (await signIn(base, password)).cookie },
  });
  assert.equal(response.status, 200);
  const bytes = Buffer.from(await response.arrayBuffer());
  assert.deepEqual([...bytes.subarray(0, 3)], [0xef, 0xbb, 0xbf]);
  assert.match(
    response.headers.get('content-disposition'),
    /^attachment; filename="uptime-goblin-audit-\d{8}-\d{6}Z\.csv"$/
  );
  assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal((await A('/api/refresh', 'POST', {})).status, 202);
  const rows = auditRows(directory);
  const exported = rows.find(row => row.action === 'audit.export');
  const next = rows.find(row => row.action === 'sources.refresh');
  assert.ok(exported.seq < next.seq);
  assert.equal(exported.detail.rows, Number(response.headers.get('x-goblin-export-rows')));
});

test(
  'canary (§9.3): no secret, password or token reaches a row, the API, an export, the log or the data directory',
  { timeout: 120000 },
  async t => {
    const sentinels = auditSentinels();
    const output = capture(t);
    // The first firing is refused, so there is a delivery to retry.
    let refuseFiring = true;
    const hook = await webhookReceiver(t, {
      path: `/hook?token=${sentinels.webhookToken}`,
      respond: request => (refuseFiring && JSON.parse(request.body).kind === 'firing' ? 422 : 200),
    });
    const mail = mailbox();
    const directory = temporary(t);
    const down = new Set();
    const options = {
      directory,
      hook,
      mail,
      down,
      password: sentinels.adminPassword,
      auditLog: 'stdout-full',
    };
    process.env.GOBLIN_SECRET_KEY = sentinels.secretKey;
    t.after(() => delete process.env.GOBLIN_SECRET_KEY);
    const first = await start(t, options);
    const base = first.base;
    const basic = (secret, login = 'admin') =>
      'Basic ' + Buffer.from(`${login}:${secret}`).toString('base64');
    const call = async (
      route,
      method = 'GET',
      body,
      authorization = sentinels.basicAuthorization
    ) => {
      const response = await fetch(base + route, {
        method,
        headers: {
          Authorization: authorization,
          'Content-Type': 'application/json',
          'X-Goblin-Request': '1',
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      const text = await response.text();
      return {
        route,
        method,
        status: response.status,
        text,
        body: (() => {
          try {
            return JSON.parse(text);
          } catch {
            return text;
          }
        })(),
      };
    };
    const answers = [],
      asked = [];
    // Each route's answer is checked too: a refused call would search nothing it records.
    const record = async (promise, status = 200) => {
      const answer = await promise;
      answers.push(answer.text);
      asked.push(`${answer.method} ${answer.route.split('?')[0]}`);
      assert.equal(answer.status, status, answer.text);
      return answer;
    };
    // Settings and sources with their secrets: set, changed, cleared.
    await record(
      call('/api/settings', 'PATCH', {
        monitoring: fastFailure,
        email: emailSettings({ password: sentinels.smtpPassword }),
      })
    );
    await record(
      call('/api/settings', 'PATCH', { email: { password: sentinels.smtpPasswordChanged } })
    );
    const created = await record(
      call('/api/services', 'POST', {
        type: 'json',
        name: 'Canary',
        apiUrl: 'https://canary.example.test/api',
        apiKey: sentinels.sourceApiKey,
      }),
      201
    );
    const id = created.body.service.id;
    // Codex review A2: fragment tokens beside an empty, a valueless or (verification round) a
    // route-like member before them, sent to the API here and hand-edited into config.json
    // below. These values are this test's own (the sentinel list is frozen) and are searched
    // with the others.
    const fragmentTokens = Object.fromEntries(
      [
        'fragmentEmpty',
        'fragmentValueless',
        'fragmentRouteLed',
        'fragmentBangLed',
        'editedFragmentEmpty',
        'editedFragmentValueless',
        'editedFragmentRouteLed',
        'editedFragmentSlashLed',
      ].map(name => [name, `Canary${name}-${randomBytes(9).toString('hex')}`])
    );
    // Refused like an ordinary #access_token=…, with the same answer.
    for (const [name, prefix, suffix] of [
      ['fragmentEmpty', '', '&'],
      ['fragmentValueless', '', '&state'],
      ['fragmentRouteLed', '/home&', ''],
      ['fragmentBangLed', '!&', '&state'],
    ]) {
      const refused = await record(
        call('/api/services', 'POST', {
          type: 'link',
          name: 'Fragment',
          url: `https://fragment.example.test/#${prefix}access_token=${fragmentTokens[name]}${suffix}`,
        }),
        400
      );
      assert.equal(refused.body.error, 'Keep credentials out of destination URLs');
    }
    await record(
      call(`/api/services/${id}`, 'PATCH', {
        username: 'canary',
        password: sentinels.sourcePassword,
      })
    );
    await record(call('/api/test-service', 'POST', { serviceId: id, settings: {} }));
    await record(call('/api/email/test', 'POST', {}));
    await record(call('/api/settings', 'PATCH', { email: { password: '' } }));
    await record(call('/api/refresh', 'POST', {}), 202);
    // Retry: the source with the sentinel credentials fails, its firing is refused, then retried.
    down.add(id);
    await first.app.poll(first.app.config.get(id));
    await first.app.flushNotifications();
    const failed = await until(async () =>
      (await call('/api/notifications/deliveries?channel=env-webhook')).body.deliveries?.find(
        row => row.alert.service === id && row.status === 'failed'
      )
    );
    refuseFiring = false;
    await record(call(`/api/notifications/deliveries/${failed.uid}/retry`, 'POST', {}));
    await record(call('/api/notifications/channels/email/resume', 'POST', {}));
    // The webhook's private signing keys, the first and the one a rotation makes, are planted
    // values too (Uptime Goblin's own): as PEM, as the PEM's body and as the raw 32-byte seed in base64,
    // base64url and hex. The public-key read and the rotation answer are searched with the
    // other answers, none left out.
    const privateKeys = [];
    const privateKey = async () => {
      const key = (await first.app.control.settings.get('notify', 'envWebhook')).value.signingKey;
      assert.match(key, /^-----BEGIN PRIVATE KEY-----\n/);
      privateKeys.push(key);
    };
    await privateKey();
    const publicKey = await record(call('/api/notifications/webhook/public-key'));
    assert.equal(publicKey.body.algorithm, 'Ed25519');
    await record(call('/api/notifications/webhook/signing-secret', 'POST', {}));
    await privateKey();
    assert.notEqual(privateKeys[0], privateKeys[1]);
    await record(call('/api/notifications/webhook/public-key'));
    await record(call('/api/notifications'));
    await record(call('/api/notifications/deliveries'));
    // ntfy and Gotify: their tokens and password are this test's own planted values (the
    // sentinel list is frozen), set, changed and cleared, and searched with the others. Both
    // stay switched off (no alert is routed to them), and each test goes to an address the
    // policy refuses before connecting, so nothing leaves 127.0.0.1.
    const pushSecrets = Object.fromEntries(
      ['ntfyToken', 'ntfyTokenChanged', 'ntfyPassword', 'gotifyToken'].map(name => [
        name,
        `Canary${name}-${randomBytes(9).toString('hex')}`,
      ])
    );
    const nowhere = { enabled: false, server: 'http://169.254.169.254', allowPlainHttp: true };
    await record(
      call('/api/notifications/channels/ntfy/settings', 'PATCH', {
        ...nowhere,
        topic: 'orbit-canary',
        token: pushSecrets.ntfyToken,
      })
    );
    await record(
      call('/api/notifications/channels/ntfy/settings', 'PATCH', {
        token: pushSecrets.ntfyTokenChanged,
      })
    );
    await record(
      call('/api/notifications/channels/ntfy/settings', 'PATCH', {
        token: null,
        username: 'canary',
        password: pushSecrets.ntfyPassword,
      })
    );
    await record(
      call('/api/notifications/channels/gotify/settings', 'PATCH', {
        ...nowhere,
        token: pushSecrets.gotifyToken,
      })
    );
    await record(call('/api/notifications/channels/ntfy/settings'));
    await record(call('/api/notifications/channels/gotify/settings'));
    await record(call('/api/notifications/channels/ntfy/test', 'POST', {}), 422);
    await record(call('/api/notifications/channels/gotify/test', 'POST', {}), 422);
    // Every notification route of the route table answered here, so its answer is searched.
    const notificationRoutes = routeTable({
      nonce: 'n',
      site: { build: '000000000000', publicFiles: new Map(), indexPage: Buffer.from('') },
    }).filter(route => route.path.startsWith('/api/notifications'));
    assert.equal(notificationRoutes.length, 9);
    for (const route of notificationRoutes) {
      const pattern = new RegExp(
        `^${route.method} ${route.path.replace(/:\w+/g, '[^/]+').replaceAll('/', '\\/')}$`
      );
      assert.ok(
        asked.some(call => pattern.test(call)),
        `${route.method} ${route.path} answered`
      );
    }
    const seeds = privateKeys.map(key =>
      Buffer.from(createPrivateKey(key).export({ format: 'jwk' }).d, 'base64url')
    );
    const secrets = { ...sentinels, ...fragmentTokens, ...pushSecrets };
    for (const [n, key] of privateKeys.entries()) {
      secrets[`signingKeyPem${n}`] = key;
      secrets[`signingKeyBody${n}`] = key.split('\n')[1];
      secrets[`signingKeySeedBase64${n}`] = seeds[n].toString('base64');
      secrets[`signingKeySeedBase64url${n}`] = seeds[n].toString('base64url');
      secrets[`signingKeySeedHex${n}`] = seeds[n].toString('hex');
    }
    await record(call('/api/config/export'));
    await record(call(`/api/services/${id}`, 'DELETE'));
    // Sign-ins, refused ones (a password typed as the name too), password changes, Basic.
    // Review round 2: the refusal with a password typed as the name comes first. Only the first
    // refusal of a window has a row of its own, the only aggregated row that keeps anything of
    // the name (its class, D9); later ones are only counted into the summary, so a sentinel
    // typed as the name second would search nothing that could leak it (§9.4, "login class").
    const a = await signIn(base, sentinels.adminPassword);
    secrets.cookie = a.cookie.split('=').slice(1).join('=');
    for (const [login, attempt] of [
      [sentinels.loginFieldPassword, sentinels.wrongPassword],
      ['admin', sentinels.wrongPassword],
    ])
      await fetch(new URL('/api/auth/login', base), {
        method: 'POST',
        headers: browserHeaders(base),
        body: JSON.stringify({ login, password: attempt }),
      });
    const A = sessionCall(base, a.cookie);
    await A('/api/account/password', 'POST', {
      currentPassword: sentinels.wrongCurrentPassword,
      password: sentinels.refusedNewPassword,
      confirmPassword: sentinels.refusedNewPassword,
    });
    const changed = await A('/api/account/password', 'POST', {
      currentPassword: sentinels.adminPassword,
      password: sentinels.newAdminPassword,
      confirmPassword: sentinels.newAdminPassword,
    });
    assert.equal(changed.status, 200);
    // Basic the same way: the first refusal gives a password as the name, then the admin's.
    await call(
      '/api/dashboard',
      'GET',
      undefined,
      basic(sentinels.basicWrongPassword, sentinels.loginFieldPassword)
    );
    await call('/api/dashboard', 'GET', undefined, basic(sentinels.basicWrongPassword));
    await call('/api/dashboard', 'GET', undefined, basic(sentinels.newAdminPassword));
    const lists = [];
    const reader = (route, as = basic(sentinels.newAdminPassword)) =>
      call(route, 'GET', undefined, as).then(answer => (lists.push(answer.text), answer));
    await reader('/api/audit?limit=500');
    await reader('/api/audit?outcome=attempt&limit=500');
    await reader('/api/audit/export?format=csv');
    await reader('/api/audit/export?format=ndjson');
    await first.app.close();
    // config.json edited while stopped: its source URLs carry tokens.
    const file = path.join(directory, 'config.json');
    const edited = JSON.parse(fs.readFileSync(file, 'utf8'));
    edited.services.find(s => s.id === 'linux').url =
      `https://linux.example.test/?token=${sentinels.urlToken}`;
    edited.services.find(s => s.id === 'linux').apiUrl =
      `https://linux.example.test/api?token=${sentinels.apiUrlToken}`;
    // Codex review A2: fragment tokens beside an empty and a valueless member.
    edited.services.find(s => s.id === 'docker').url =
      `https://docker.example.test/#access_token=${fragmentTokens.editedFragmentEmpty}&`;
    edited.services.find(s => s.id === 'windows').url =
      `https://windows.example.test/#access_token=${fragmentTokens.editedFragmentValueless}&state`;
    // Verification round: after a route-like member.
    edited.services.find(s => s.id === 'proxmox').url =
      `https://proxmox.example.test/#/home&access_token=${fragmentTokens.editedFragmentRouteLed}`;
    edited.services.find(s => s.id === 'synology').url =
      `https://synology.example.test/#home/&access_token=${fragmentTokens.editedFragmentSlashLed}&state`;
    fs.writeFileSync(file, JSON.stringify(edited, null, 2));
    process.env.GOBLIN_SECRET_KEY = sentinels.secretKey;
    const second = await start(t, { ...options, password: sentinels.newAdminPassword });
    // Repaired at the start like an ordinary #access_token=…: only the pair goes.
    assert.equal(second.app.config.get('docker').url, 'https://docker.example.test/');
    assert.equal(second.app.config.get('windows').url, 'https://windows.example.test/#state');
    assert.equal(second.app.config.get('proxmox').url, 'https://proxmox.example.test/#/home');
    assert.equal(
      second.app.config.get('synology').url,
      'https://synology.example.test/#home/&state'
    );
    for (const route of [
      '/api/audit?limit=500',
      '/api/audit/export?format=csv',
      '/api/audit/export?format=ndjson',
      '/api/config/export',
    ]) {
      const again = await second.script(route, 'GET', undefined, {
        secret: sentinels.newAdminPassword,
      });
      assert.equal(again.status, 200, route);
      lists.push(typeof again.body === 'string' ? again.body : JSON.stringify(again.body));
    }
    await second.app.close();
    // The hand edit's row names the destinations as repaired (the canary searched them).
    const outside = JSON.stringify(
      auditRows(directory).filter(row => row.action === 'config.changed-outside')
    );
    assert.match(outside, /https:\/\/docker\.example\.test\/(?![#\w])/);
    assert.match(outside, /https:\/\/windows\.example\.test\/#state\b/);
    assert.match(outside, /https:\/\/proxmox\.example\.test\/#\/home(?![\w&])/);
    assert.match(outside, /https:\/\/synology\.example\.test\/#home\/&state\b/);

    const places = {
      rows: tableText(directory, [
        'audit_log',
        'audit_inbox',
        'audit_checkpoints',
        'audit_head',
        'meta',
      ]),
      api: lists.join('\n'),
      answers: answers.join('\n'),
      output: output.lines.map(line => line.text).join('\n'),
    };
    for (const [where, text] of Object.entries(places))
      assert.deepEqual(findSentinels(text, secrets), [], where);
    // The public-key answers were searched, and hold the public keys only.
    assert.ok(places.answers.includes(publicKey.body.publicKeyRaw));
    assert.doesNotMatch(places.answers, /PRIVATE KEY/);
    // Every file of the data directory but config.json (and a snapshot's copy of it).
    const walk = dir =>
      fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
        const full = path.join(dir, entry.name);
        return entry.isDirectory() ? walk(full) : [full];
      });
    for (const file of walk(directory)) {
      if (path.basename(file) === 'config.json') continue;
      const bytes = fs.readFileSync(file);
      assert.deepEqual(findSentinels(bytes, secrets), [], path.relative(directory, file));
      // The raw seeds as bytes too: only sealed, never stored as they are.
      for (const seed of seeds)
        assert.equal(bytes.includes(seed), false, `${path.relative(directory, file)}: a raw seed`);
    }
    // The rows exist (the canary searched something).
    for (const action of ['delivery.retry', 'signing.rotate', 'config.changed-outside'])
      assert.ok(
        auditRows(directory).some(row => row.action === action),
        action
      );
    // The first refusal row of each anonymous action, the only one with something of the name,
    // is the one whose name was a password: its class is all it keeps (D9), and it was searched.
    for (const action of ['session.login', 'auth.basic.failed']) {
      const own = auditRows(directory).filter(
        row => row.action === action && row.outcome !== 'ok' && !row.detail?.codes
      );
      assert.deepEqual(
        own.slice(0, 1).map(row => row.detail),
        [{ code: 'invalid_credentials', login: 'other' }],
        action
      );
    }
  }
);

// Review round 2: docs/architecture.md's Jobs paragraph listed four jobs and left out the audit's
// hourly audit.maintain (server.mjs), so its closed list no longer matched what Uptime Goblin runs.
test("docs: architecture.md's Jobs paragraph names every job a running Uptime Goblin registers", async t => {
  capture(t);
  const { app } = await start(t, { listen: false });
  // notify.delivery is registered once the delivery service's start sequence has run.
  const names = await until(
    () => {
      const list = app.jobs.status().map(job => job.name);
      return list.includes('notify.delivery') && list;
    },
    { what: 'the delivery job' }
  );
  assert.ok(names.includes('audit.maintain'), names.join(', '));
  const maintain = app.jobs.status().find(job => job.name === 'audit.maintain');
  assert.deepEqual([maintain.intervalMs, maintain.leaderOnly], [hour, true]);
  const guide = fs.readFileSync(new URL('../docs/architecture.md', import.meta.url), 'utf8');
  const paragraph = guide.slice(
    guide.indexOf('Jobs (`lib/jobs.mjs`):'),
    guide.indexOf('\n\n**The storage guard**')
  );
  for (const name of names)
    assert.ok(paragraph.includes(`\`${name}\``), `${name} in the Jobs list`);
  assert.match(
    paragraph,
    /`audit\.maintain` \(hourly, the first run 60 s after the start: the audit summaries a missed timer left, the entries a first start recorded before its keyring existed that a full disk kept out of the log, then the prune of audit entries past the retention or the 250,000 cap\)/
  );
});
