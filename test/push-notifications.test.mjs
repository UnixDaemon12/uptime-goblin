// ntfy and Gotify through a real Uptime Goblin (createApp): their settings routes (validation, secrets
// write-only and sealed, the audit row), alerts and recoveries reaching fake ntfy and Gotify
// servers on 127.0.0.1, retries with a stable X-Goblin-Delivery, a pause on a refused token and
// Resume, a save that resumes, the address policy, and the test route. Nothing leaves 127.0.0.1.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { DatabaseSync } from 'node:sqlite';
import { createApp } from '../server.mjs';
import { configureDestinations } from '../lib/destinations.mjs';
import { PUSH_LOOPBACK } from '../lib/notify/address-policy.mjs';

configureDestinations({ lookup: async () => [{ address: '192.0.2.1' }] });

// Throwaway values for these data directories only.
const password = 'push-notifications-test-password';
const ntfyToken = 'tk_push-integration-canary-0001';
const ntfyPassword = 'push-integration-password-canary';
const gotifyToken = 'AgotifyCanary.0001';
const topic = 'orbit-canary-topic-0001';
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

async function until(condition, { timeoutMs = 15000, what = 'the condition' } = {}) {
  const end = Date.now() + timeoutMs;
  for (;;) {
    const value = await condition();
    if (value) return value;
    if (Date.now() > end) assert.fail(`${what} was not reached within ${timeoutMs} ms`);
    await sleep(10);
  }
}

function temporary(t) {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-push-')));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

/** A fake ntfy or Gotify server: records each request, answers `respond(request, n)`. */
async function fakeServer(t, respond = () => 200) {
  const requests = [];
  const server = http.createServer(async (req, res) => {
    let body = '';
    req.setEncoding('utf8');
    for await (const chunk of req) body += chunk;
    const request = { url: req.url, headers: req.headers, body };
    requests.push(request);
    const answer = respond(request, requests.length);
    const { status = 200, headers = {} } = typeof answer === 'number' ? { status: answer } : answer;
    res.writeHead(status, headers);
    res.end('{}');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => {
    server.closeAllConnections();
    return new Promise(resolve => server.close(resolve));
  });
  return {
    base: `http://127.0.0.1:${server.address().port}`,
    requests,
    bodies: () => requests.map(request => JSON.parse(request.body)),
  };
}

async function start(t, { allowLoopback = true, directory = temporary(t) } = {}) {
  const down = new Set();
  const app = await createApp({
    directory,
    host: '127.0.0.1',
    port: 0,
    password,
    allowedHosts: '',
    trustProxy: '',
    startScheduler: false,
    legacyBasic: true,
    allowLoopback,
    webhook: '',
    mailTransportFactory: () => {
      throw new Error('Unexpected mail attempt');
    },
    collector: async service => {
      if (down.has(service.id)) throw new Error(`${service.id} is down`);
      return [{ key: 'up', label: 'Up', value: 1, unit: '' }];
    },
    delivery: { pollMs: 20, rng: () => 1, policy: { baseMs: 100, capMs: 100 } },
  });
  const { port } = await app.listen();
  t.after(() => app.close());
  // Later tests in this file start with the default again.
  t.after(() => configureDestinations({ allowLoopback: false }));
  const base = `http://127.0.0.1:${port}`;
  const call = async (route, method = 'GET', body, headers = {}) => {
    const res = await fetch(base + route, {
      method,
      headers: {
        Authorization: 'Basic ' + Buffer.from('admin:' + password).toString('base64'),
        'Content-Type': 'application/json',
        'X-Goblin-Request': '1',
        ...headers,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    let value = text;
    try {
      value = JSON.parse(text);
    } catch {}
    return { status: res.status, headers: res.headers, body: value, text };
  };
  app.config.updateGlobal({
    monitoring: {
      availabilityFailures: 1,
      availabilitySeconds: 0,
      retryCount: 0,
      recoverySuccesses: 1,
      recoverySeconds: 0,
    },
  });
  for (const id of ['plex', 'sonarr'])
    if (!app.config.get(id)?.apiUrl)
      app.config.update(id, { apiUrl: `https://${id}.example.test`, apiKey: 'fixture-key' });
  const fire = async id => {
    down.add(id);
    await app.poll(app.config.get(id));
  };
  const recover = async id => {
    down.delete(id);
    await app.poll(app.config.get(id));
  };
  return { app, call, fire, recover, directory, base };
}

const channel = async (call, id) =>
  (await call('/api/notifications')).body.channels.find(c => c.id === id);
const historyOf = async (call, id) =>
  (await call(`/api/notifications/deliveries?channel=${id}`)).body.deliveries;

test('settings: validated on the server, secrets write-only and sealed, never in an answer, export or audit row', async t => {
  const { call, directory } = await start(t);
  // Defaults before anything was saved.
  const fresh = await call('/api/notifications/channels/ntfy/settings');
  assert.equal(fresh.status, 200);
  assert.equal(fresh.body.version, 0);
  assert.deepEqual(fresh.body.settings, {
    enabled: false,
    server: 'https://ntfy.sh',
    topic: '',
    username: '',
    password: { set: false },
    token: { set: false },
    priorityFiring: 4,
    priorityResolved: 3,
    tags: [],
    dashboardUrl: '',
    allowPlainHttp: false,
  });
  // Refused whole, with a reason that never repeats a value.
  for (const [body, pattern] of [
    [{ enabled: true }, /Enter the ntfy topic/],
    [{ topic: 'has spaces' }, /The topic may hold only letters/],
    [{ topic, server: 'http://192.0.2.10/' }, /plain HTTP to another computer/],
    [{ topic, server: `https://user:${ntfyPassword}@ntfy.example.test` }, /user name or password/],
    [{ topic, token: ntfyToken, username: 'orbit', password: ntfyPassword }, /not both/],
    [{ priorityFiring: 9 }, /The alert priority must be a whole number from 1/],
    [{ tags: ['ok', 'not ok'] }, /The tags each tag/],
    [{ dashboardUrl: 'javascript:alert(1)' }, /http: or https:/],
    [{ surprise: true }, /There is no setting named surprise/],
    [{ version: 'x' }, /version must be/],
  ]) {
    const refused = await call('/api/notifications/channels/ntfy/settings', 'PATCH', body);
    assert.equal(refused.status, 400, JSON.stringify(body));
    assert.equal(refused.body.code, 'channel_settings_invalid');
    assert.match(refused.body.error, pattern);
    assert.equal(refused.text.includes(ntfyPassword), false);
  }
  assert.equal(
    (await call('/api/notifications/channels/ntfy/settings', 'PATCH', [])).body.code,
    'channel_settings_invalid'
  );
  assert.equal((await call('/api/notifications/channels/slack/settings')).status, 404);
  assert.equal(
    (await call('/api/notifications/channels/email/settings', 'PATCH', {})).body.code,
    'channel_unknown'
  );
  // Saved: the token reads as {set: true} only.
  const saved = await call('/api/notifications/channels/ntfy/settings', 'PATCH', {
    version: 0,
    enabled: true,
    server: 'https://ntfy.example.test',
    topic,
    token: ntfyToken,
    tags: ['house'],
  });
  assert.equal(saved.status, 200, saved.text);
  assert.equal(saved.body.version, 1);
  assert.deepEqual(saved.body.settings.token, { set: true });
  assert.equal(saved.text.includes(ntfyToken), false);
  // A stale version is refused.
  const stale = await call('/api/notifications/channels/ntfy/settings', 'PATCH', {
    version: 0,
    priorityFiring: 5,
  });
  assert.equal(stale.status, 409);
  assert.equal(stale.body.code, 'channel_settings_conflict');
  const gotify = await call('/api/notifications/channels/gotify/settings', 'PATCH', {
    enabled: true,
    server: 'https://gotify.example.test',
    token: gotifyToken,
  });
  assert.equal(gotify.status, 200, gotify.text);
  assert.equal(gotify.text.includes(gotifyToken), false);
  // Every read answers without them.
  for (const route of [
    '/api/notifications/channels/ntfy/settings',
    '/api/notifications/channels/gotify/settings',
    '/api/notifications',
    '/api/dashboard',
    '/api/system',
    '/api/config/export',
    '/api/audit?limit=500',
    '/api/audit/export?format=ndjson',
    '/api/audit/export?format=csv',
  ]) {
    const answer = await call(route);
    assert.equal(answer.status, 200, route);
    for (const secret of [ntfyToken, gotifyToken])
      assert.equal(answer.text.includes(secret), false, `${route} never holds a token`);
  }
  // The audit row: what changed, the token and the topic only as set.
  const entries = (await call('/api/audit?limit=500')).body.entries.filter(
    entry => entry.action === 'channel.settings'
  );
  assert.equal(entries.length, 2);
  const ntfyRow = entries.find(entry => entry.target?.id === 'ntfy');
  assert.equal(ntfyRow.outcome, 'ok');
  const diff = Object.fromEntries(ntfyRow.detail.diff.map(change => [change.path, change]));
  assert.deepEqual(diff.token, { path: 'token', change: 'set' });
  assert.deepEqual(diff.topic, { path: 'topic', change: 'set' });
  assert.deepEqual(diff.enabled, { path: 'enabled', from: false, to: true });
  assert.equal(JSON.stringify(ntfyRow).includes(topic), false, 'the topic is not in the audit');
  // Sealed at rest: control.sqlite never holds them in clear.
  const db = new DatabaseSync(path.join(directory, 'control.sqlite'), { readOnly: true });
  try {
    const rows = db.prepare("SELECT value FROM settings WHERE component = 'notify'").all();
    assert.ok(rows.length >= 2);
    for (const row of rows)
      for (const secret of [ntfyToken, gotifyToken])
        assert.equal(String(row.value).includes(secret), false);
  } finally {
    db.close();
  }
  // Clearing removes it; an unchanged save writes no audit row.
  const cleared = await call('/api/notifications/channels/ntfy/settings', 'PATCH', {
    token: null,
  });
  assert.deepEqual(cleared.body.settings.token, { set: false });
  await call('/api/notifications/channels/ntfy/settings', 'PATCH', { topic });
  const after = (await call('/api/audit?limit=500')).body.entries.filter(
    entry => entry.action === 'channel.settings' && entry.target?.id === 'ntfy'
  );
  assert.equal(after.length, 2);
  assert.deepEqual(after[0].detail.diff, [{ path: 'token', change: 'cleared' }]);
});

test('signed out: every ntfy and Gotify route answers 401 and changes nothing', async t => {
  const { base, call } = await start(t);
  for (const [method, route, body] of [
    ['GET', '/api/notifications/channels/ntfy/settings'],
    ['PATCH', '/api/notifications/channels/ntfy/settings', { enabled: true }],
    ['POST', '/api/notifications/channels/gotify/test', {}],
  ]) {
    const res = await fetch(base + route, {
      method,
      headers: { 'Content-Type': 'application/json', 'X-Goblin-Request': '1' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    assert.equal(res.status, 401, `${method} ${route}`);
  }
  assert.equal((await call('/api/notifications/channels/ntfy/settings')).body.version, 0);
});

test('an alert and its recovery reach ntfy and Gotify with the token, the priorities and one delivery id per notification', async t => {
  const ntfy = await fakeServer(t);
  const gotify = await fakeServer(t);
  const { call, fire, recover } = await start(t);
  assert.equal(
    (
      await call('/api/notifications/channels/ntfy/settings', 'PATCH', {
        enabled: true,
        server: `${ntfy.base}/ntfy/`,
        topic,
        username: 'orbit',
        password: ntfyPassword,
        priorityFiring: 5,
        priorityResolved: 2,
        dashboardUrl: 'https://orbit.example.test/',
      })
    ).status,
    200
  );
  assert.equal(
    (
      await call('/api/notifications/channels/gotify/settings', 'PATCH', {
        enabled: true,
        server: gotify.base,
        token: gotifyToken,
      })
    ).status,
    200
  );
  const card = await channel(call, 'ntfy');
  assert.equal(card.configured, true);
  assert.equal(card.host, '127.0.0.1', 'the host only, never the path or topic');
  await fire('plex');
  await until(() => ntfy.requests.length >= 1 && gotify.requests.length >= 1, {
    what: 'the alert on both',
  });
  await recover('plex');
  await until(() => ntfy.requests.length >= 2 && gotify.requests.length >= 2, {
    what: 'the recovery on both',
  });
  const [firing, resolved] = ntfy.requests;
  assert.equal(firing.url, '/ntfy/');
  assert.equal(
    firing.headers.authorization,
    `Basic ${Buffer.from(`orbit:${ntfyPassword}`).toString('base64')}`
  );
  const name = 'Plex';
  assert.deepEqual(
    ntfy.bodies().map(body => [body.topic, body.title, body.priority, body.click, body.tags]),
    [
      [topic, `${name} alert`, 5, 'https://orbit.example.test/', ['warning']],
      [topic, `${name} recovered`, 2, 'https://orbit.example.test/', ['white_check_mark']],
    ]
  );
  assert.notEqual(firing.headers['x-goblin-delivery'], resolved.headers['x-goblin-delivery']);
  assert.match(firing.headers['x-goblin-delivery'], /^d_[a-z2-7]{26}$/);
  assert.equal(gotify.requests[0].url, '/message');
  assert.equal(gotify.requests[0].headers['x-gotify-key'], gotifyToken);
  assert.deepEqual(
    gotify.bodies().map(body => body.priority),
    [8, 4]
  );
  const rows = await historyOf(call, 'gotify');
  assert.equal(rows.length, 2);
  assert.ok(rows.every(row => row.status === 'delivered'));
  for (const answer of [
    await call('/api/notifications'),
    await call('/api/notifications/deliveries'),
  ])
    for (const secret of [ntfyPassword, gotifyToken, topic])
      assert.equal(answer.text.includes(secret), false);
});

test('a 503 is retried with the same X-Goblin-Delivery until it is accepted', async t => {
  const ntfy = await fakeServer(t, (request, n) =>
    n <= 2 ? { status: 503, headers: { 'Retry-After': '0' } } : 200
  );
  const { call, fire } = await start(t);
  await call('/api/notifications/channels/ntfy/settings', 'PATCH', {
    enabled: true,
    server: ntfy.base,
    topic,
  });
  await fire('plex');
  await until(() => ntfy.requests.length >= 3, { what: 'two retries' });
  const ids = new Set(ntfy.requests.map(request => request.headers['x-goblin-delivery']));
  assert.equal(ids.size, 1, 'every attempt carries the same delivery id');
  const [row] = await until(async () => {
    const list = await historyOf(call, 'ntfy');
    return list[0]?.status === 'delivered' && list;
  });
  assert.equal(row.attempts, 3);
});

test('a refused token pauses the channel and holds its alerts; Resume sends them; a save resumes too', async t => {
  let accept = false;
  const gotify = await fakeServer(t, () => (accept ? 200 : 401));
  const { call, fire, recover } = await start(t);
  await call('/api/notifications/channels/gotify/settings', 'PATCH', {
    enabled: true,
    server: gotify.base,
    token: gotifyToken,
  });
  await fire('plex');
  const paused = await until(async () => {
    const c = await channel(call, 'gotify');
    return c.state === 'paused' && c;
  });
  assert.match(paused.pausedReason, /refused Uptime Goblin's credentials \(401\)/);
  assert.equal(paused.nextAttemptAt, null, 'no probe: it waits for a fix');
  // Further alerts are held, unsent.
  await fire('sonarr');
  await until(async () => (await channel(call, 'gotify')).counts.paused >= 2);
  const sent = gotify.requests.length;
  await sleep(200);
  assert.equal(gotify.requests.length, sent, 'nothing is sent while paused');
  // Resume, with the server fixed: the held alerts go.
  accept = true;
  const resumed = await call('/api/notifications/channels/gotify/resume', 'POST', {});
  assert.equal(resumed.status, 200);
  assert.ok(resumed.body.released >= 1);
  await until(
    async () => (await historyOf(call, 'gotify')).filter(r => r.status === 'delivered').length >= 2
  );
  assert.equal((await channel(call, 'gotify')).state, 'ok');
  // Paused again; saving a new token resumes it without Resume.
  accept = false;
  await recover('plex');
  await until(async () => (await channel(call, 'gotify')).state === 'paused');
  accept = true;
  const saved = await call('/api/notifications/channels/gotify/settings', 'PATCH', {
    token: `${gotifyToken}x`,
  });
  assert.equal(saved.status, 200);
  await until(async () => (await channel(call, 'gotify')).state === 'ok');
  await until(
    async () => (await historyOf(call, 'gotify')).filter(r => r.status === 'delivered').length >= 3
  );
  // The audit log names the pause, the Resume and the save, never the token.
  const audit = await call('/api/audit?limit=500');
  const actions = audit.body.entries.map(entry => entry.action);
  for (const action of ['channel.paused', 'channel.resume', 'channel.settings'])
    assert.ok(actions.includes(action), action);
  assert.equal(audit.text.includes(gotifyToken), false);
});

test('the address policy: a loopback server is refused without GOBLIN_ALLOW_LOOPBACK, and nothing reaches it', async t => {
  const ntfy = await fakeServer(t);
  const { call, fire } = await start(t, { allowLoopback: false });
  await call('/api/notifications/channels/ntfy/settings', 'PATCH', {
    enabled: true,
    server: ntfy.base,
    topic,
  });
  await fire('plex');
  const paused = await until(async () => {
    const c = await channel(call, 'ntfy');
    return c.state === 'paused' && c;
  });
  assert.equal(paused.pausedReason, PUSH_LOOPBACK);
  // The test route is refused the same way.
  const tested = await call('/api/notifications/channels/ntfy/test', 'POST', {});
  assert.equal(tested.status, 422);
  assert.equal(tested.body.error, PUSH_LOOPBACK);
  // And metadata addresses whatever the setting.
  await call('/api/notifications/channels/gotify/settings', 'PATCH', {
    enabled: true,
    server: 'http://169.254.169.254',
    allowPlainHttp: true,
    token: gotifyToken,
  });
  const metadata = await call('/api/notifications/channels/gotify/test', 'POST', {});
  assert.equal(metadata.status, 422);
  assert.match(metadata.body.error, /link-local, multicast or reserved/);
  assert.equal(ntfy.requests.length, 0);
});

test('Send test notification: sent with the saved settings while switched off, recorded, and limited to one per 30 seconds', async t => {
  const ntfy = await fakeServer(t);
  const { call } = await start(t);
  const unset = await call('/api/notifications/channels/ntfy/test', 'POST', {});
  assert.equal(unset.status, 409);
  assert.equal(unset.body.code, 'channel_not_set_up');
  assert.equal(
    unset.body.error,
    'Save an ntfy server and topic before sending a test notification.'
  );
  assert.equal(
    (await call('/api/notifications/channels/ntfy/test', 'POST', { extra: 1 })).status,
    400
  );
  await call('/api/notifications/channels/ntfy/settings', 'PATCH', {
    enabled: false,
    server: ntfy.base,
    topic,
    token: ntfyToken,
  });
  const tested = await call('/api/notifications/channels/ntfy/test', 'POST', {});
  assert.equal(tested.status, 200, tested.text);
  assert.deepEqual(tested.body, {
    ok: true,
    accepted: true,
    message: 'ntfy accepted the test notification.',
  });
  assert.equal(ntfy.requests.length, 1);
  assert.equal(ntfy.bodies()[0].title, 'Uptime Goblin: test notification');
  assert.equal(ntfy.requests[0].headers.authorization, `Bearer ${ntfyToken}`);
  const again = await call('/api/notifications/channels/ntfy/test', 'POST', {});
  assert.equal(again.status, 429);
  assert.equal(again.body.code, 'test_rate_limited');
  assert.ok(Number(again.headers.get('retry-after')) >= 1);
  assert.equal(ntfy.requests.length, 1);
  const card = await channel(call, 'ntfy');
  assert.equal(card.state, 'off');
  assert.ok(card.lastSuccess > 0, 'the test is in the channel status');
  const tests = (await call('/api/audit?limit=500')).body.entries.filter(
    entry => entry.action === 'channel.test'
  );
  assert.ok(tests.some(entry => entry.outcome === 'ok' && entry.detail?.accepted === true));
  assert.equal(JSON.stringify(tests).includes(ntfyToken), false);
  // No alert is routed to a channel switched off.
  assert.equal((await historyOf(call, 'ntfy')).length, 0);
});
