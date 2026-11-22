// The ntfy and Gotify channels on their own: their bodies and priority mapping, the server address
// rule, how an answer or a failure becomes an outcome, the address policy, and sends to fake
// servers on 127.0.0.1 (plain and TLS). Nothing leaves this computer.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import { configureDestinations } from '../../lib/destinations.mjs';
import {
  pushAddressProblem,
  PUSH_LOOPBACK,
  PUSH_REFUSED,
} from '../../lib/notify/address-policy.mjs';
import {
  classifyPushError,
  classifyPushResponse,
  endpoint,
  parseDashboardUrl,
  parseServerUrl,
  PushConfigError,
  pushMessage,
  pushTitle,
  serverHost,
  PUSH_LIMITS,
} from '../../lib/notify/channels/push.mjs';
import {
  checkNtfy,
  createNtfyChannel,
  ntfyAuthorization,
  ntfyBody,
  ntfyFields,
  ntfySetup,
} from '../../lib/notify/channels/ntfy.mjs';
import {
  checkGotify,
  createGotifyChannel,
  gotifyBody,
  gotifySetup,
} from '../../lib/notify/channels/gotify.mjs';
import { OutboundError } from '../../lib/notify/http.mjs';
import { pushAuditDiff, ntfySettings, gotifySettings } from '../../lib/alerting/push-settings.mjs';
import { createSettings, memorySettingsStore } from '../../lib/settings.mjs';

// The same throwaway key and self-signed certificate for 127.0.0.1 as test/notify/webhook.test.mjs.
const testKey = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghuGBHo0qfEiG0qZ1
EsibliVvmhsX4HOqrbKWT9I84NihRANCAAQFjmoJU3qtkYtb00on5KP9bpoFlf8H
xhoJwnjJau0QU348mW4qa6XxYIbHzJJy0vW0NNfzq0a0tFCNjbJPs0L6
-----END PRIVATE KEY-----
`;
const testCert = `-----BEGIN CERTIFICATE-----
MIIBpzCCAU2gAwIBAgIUZjM1lW7gob7f6mZeyEs5LrM/JI0wCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPT3JiaXQgdGVzdCBTTVRQMCAXDTIwMDEwMTAwMDAwMFoYDzIx
MjAwMTAxMDAwMDAwWjAaMRgwFgYDVQQDDA9PcmJpdCB0ZXN0IFNNVFAwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAQFjmoJU3qtkYtb00on5KP9bpoFlf8HxhoJwnjJ
au0QU348mW4qa6XxYIbHzJJy0vW0NNfzq0a0tFCNjbJPs0L6o28wbTAdBgNVHQ4E
FgQUJ8Me3qSp90BFQ89KOn3yz1GK2rwwHwYDVR0jBBgwFoAUJ8Me3qSp90BFQ89K
On3yz1GK2rwwDwYDVR0TAQH/BAUwAwEB/zAaBgNVHREEEzARhwR/AAABgglsb2Nh
bGhvc3QwCgYIKoZIzj0EAwIDSAAwRQIhAIuTWtjk3wtDnvEzcRn9MX04ahwYWDFo
Qj8kCcYZv68YAiB252dfaXIjquMafoDOouciNR0KkHAS4Px0N9PvCxSpXA==
-----END CERTIFICATE-----
`;
// Throwaway values for these tests only.
const token = 'tk_push-unit-canary-0001';
const password = 'push-unit-password-canary';
const allowAll = async () => null;

async function server(t, { reply = () => ({ status: 200 }), secure = false } = {}) {
  const requests = [];
  const handler = async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const request = {
      method: req.method,
      url: req.url,
      headers: req.headers,
      body: Buffer.concat(chunks).toString('utf8'),
    };
    requests.push(request);
    const answer = reply(request, requests.length);
    res.writeHead(answer.status, answer.headers ?? {});
    res.end(answer.body ?? '');
  };
  const listener = secure
    ? https.createServer({ key: testKey, cert: testCert }, handler)
    : http.createServer(handler);
  await new Promise(resolve => listener.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => listener.close(resolve)));
  const { port } = listener.address();
  return { requests, base: `${secure ? 'https' : 'http'}://127.0.0.1:${port}` };
}

const event = (kind = 'firing', extra = {}) => ({
  service: 'plex',
  name: 'Plex',
  kind,
  category: 'availability',
  rule: '__availability',
  message: 'Source is unavailable',
  time: 1800000000000,
  ...extra,
});
const message = (kind = 'firing') => ({
  uid: 'd_abcdefghijklmnopqrstuvwxyz',
  channelId: 'ntfy',
  kind,
  attempt: 1,
  events: [event(kind)],
});
const ntfyValue = (extra = {}) => ({
  enabled: true,
  server: 'https://ntfy.example.test',
  topic: 'orbit-alerts',
  username: '',
  password: null,
  token: null,
  priorityFiring: 4,
  priorityResolved: 3,
  tags: [],
  dashboardUrl: '',
  allowPlainHttp: false,
  ...extra,
});
const gotifyValue = (extra = {}) => ({
  enabled: true,
  server: 'https://gotify.example.test',
  token,
  priorityFiring: 8,
  priorityResolved: 4,
  dashboardUrl: '',
  allowPlainHttp: false,
  ...extra,
});

test('ntfy bodies: topic, title, message, the priority by kind, tags and the click-through', () => {
  const settings = ntfyValue({
    tags: ['house', 'warning'],
    dashboardUrl: 'https://orbit.example.test',
  });
  assert.deepEqual(ntfyBody(event('firing'), settings), {
    topic: 'orbit-alerts',
    title: 'Plex alert',
    message: 'Source is unavailable',
    priority: 4,
    // The saved tags first, the kind's once.
    tags: ['house', 'warning'],
    click: 'https://orbit.example.test/',
  });
  assert.deepEqual(ntfyBody(event('resolved', { message: 'Source is available' }), settings), {
    topic: 'orbit-alerts',
    title: 'Plex recovered',
    message: 'Source is available',
    priority: 3,
    tags: ['house', 'warning', 'white_check_mark'],
    click: 'https://orbit.example.test/',
  });
  // A configured mapping, no dashboard address: no click.
  const mapped = ntfyValue({ priorityFiring: 5, priorityResolved: 1 });
  assert.equal(ntfyBody(event('firing'), mapped).priority, 5);
  assert.equal(ntfyBody(event('resolved'), mapped).priority, 1);
  assert.equal('click' in ntfyBody(event(), mapped), false);
  // Uptime Goblin's own notices and a test.
  const own = ntfyBody(
    event('firing', { service: 'orbit', name: 'Uptime Goblin', rule: '__disk' }),
    mapped
  );
  assert.equal(own.title, 'Uptime Goblin alert');
  const probe = ntfyBody(
    event('firing', { service: 'orbit', name: 'Uptime Goblin', rule: '__test' }),
    mapped
  );
  assert.equal(probe.title, 'Uptime Goblin: test notification');
  assert.deepEqual(probe.tags, ['bell']);
});

test('Gotify bodies: title, message, the priority by kind and the click-through extra', () => {
  assert.deepEqual(gotifyBody(event('firing'), gotifyValue()), {
    title: 'Plex alert',
    message: 'Source is unavailable',
    priority: 8,
  });
  assert.deepEqual(
    gotifyBody(
      event('resolved'),
      gotifyValue({ priorityResolved: 0, dashboardUrl: 'https://orbit.example.test/#dashboard' })
    ),
    {
      title: 'Plex recovered',
      message: 'Source is unavailable',
      priority: 0,
      extras: {
        'client::notification': { click: { url: 'https://orbit.example.test/#dashboard' } },
      },
    }
  );
});

test('titles and messages are one line, capped, and never empty', () => {
  assert.equal(pushTitle({ name: 'A\nB C', kind: 'firing' }), 'A B C alert');
  assert.equal(pushTitle({}), 'Uptime Goblin alert');
  assert.equal([...pushTitle({ name: 'x'.repeat(500) })].length, 206);
  assert.equal(pushMessage({ kind: 'resolved' }), 'The alert recovered.');
  assert.equal([...pushMessage({ message: 'y'.repeat(5000) })].length, 2000);
});

test('ntfy credentials: a Bearer token, or Basic with a user name and password, else none', () => {
  assert.equal(ntfyAuthorization(ntfyValue({ token })), `Bearer ${token}`);
  assert.equal(
    ntfyAuthorization(ntfyValue({ username: 'orbit', password })),
    `Basic ${Buffer.from(`orbit:${password}`).toString('base64')}`
  );
  assert.equal(ntfyAuthorization(ntfyValue()), null);
});

test('server addresses: http(s) with a host only; plain HTTP to another computer needs the opt-in', () => {
  assert.equal(parseServerUrl('https://ntfy.example.test/').href, 'https://ntfy.example.test/');
  assert.equal(
    parseServerUrl('https://example.test/ntfy//').pathname,
    '/ntfy',
    'a path prefix is kept without its trailing slash'
  );
  assert.equal(endpoint(parseServerUrl('https://example.test/ntfy')).pathname, '/ntfy/');
  assert.equal(
    endpoint(parseServerUrl('https://example.test/gotify/'), 'message').pathname,
    '/gotify/message'
  );
  // Loopback over plain HTTP is this computer: no opt-in needed.
  for (const local of ['http://127.0.0.1:8080', 'http://localhost:2586', 'http://[::1]:80'])
    assert.equal(parseServerUrl(local).protocol, 'http:', local);
  assert.throws(() => parseServerUrl('http://192.0.2.10'), /plain HTTP to another computer/);
  assert.equal(
    parseServerUrl('http://192.0.2.10', { allowPlainHttp: true }).hostname,
    '192.0.2.10'
  );
  const secret = 'S3cr3tPathToken';
  for (const [value, pattern] of [
    ['', /is required/],
    ['not a url', /not a valid address/],
    [`ftp://example.test/${secret}`, /http: or https:/],
    [`https://user:${secret}@example.test`, /user name or password/],
    [`https://example.test/?auth=${secret}`, /query/],
    [`https://example.test/#${secret}`, /fragment/],
    [`https://example.test/${'a'.repeat(2100)}`, /longer than 2048/],
  ]) {
    let error;
    try {
      parseServerUrl(value);
    } catch (caught) {
      error = caught;
    }
    assert.ok(error instanceof PushConfigError, value.slice(0, 40));
    assert.match(error.message, pattern);
    assert.equal(error.message.includes(secret), false, 'an error never repeats the address');
  }
  assert.equal(parseDashboardUrl(''), '');
  assert.throws(() => parseDashboardUrl('javascript:alert(1)'), /http: or https:/);
  assert.throws(() => parseDashboardUrl('https://a:b@example.test'), /user name or password/);
  assert.equal(serverHost('https://ntfy.example.test/secret-topic'), 'ntfy.example.test');
  assert.equal(serverHost('nonsense'), null);
});

test('the documents’ rules: a topic while on, token or password not both, Gotify needs a token', () => {
  assert.doesNotThrow(() => checkNtfy(ntfyValue()));
  assert.throws(() => checkNtfy(ntfyValue({ topic: '' })), /Enter the ntfy topic/);
  assert.doesNotThrow(() => checkNtfy(ntfyValue({ topic: '', enabled: false })));
  assert.throws(
    () => checkNtfy(ntfyValue({ token, username: 'orbit', password })),
    /either an ntfy access token or a user name and password/
  );
  assert.throws(() => checkNtfy(ntfyValue({ username: 'orbit' })), /needs its password/);
  assert.throws(() => ntfyFields.topic('has space'), /letters, digits/);
  assert.throws(() => ntfyFields.topic('x'.repeat(65)), /at most 64/);
  assert.throws(() => ntfyFields.tags(['a', 'b', 'c', 'd', 'e', 'f']), /at most 5/);
  assert.throws(() => ntfyFields.tags(['no spaces']), /each tag/);
  assert.deepEqual(ntfyFields.tags([' a ', 'a', 'b']), ['a', 'b']);
  assert.throws(() => ntfyFields.priority(6), /1 \(min\) to 5/);
  assert.throws(() => ntfyFields.priority(2.5), /whole number/);
  assert.throws(() => ntfyFields.username('a:b'), /colon/);
  assert.throws(() => ntfyFields.token('has space'), /without spaces/);
  assert.throws(() => checkGotify(gotifyValue({ token: null })), /application token/);
  assert.throws(() => checkGotify(gotifyValue({ server: '' })), /is required/);
  assert.doesNotThrow(() => checkGotify(gotifyValue({ enabled: false, server: '', token: null })));
  assert.deepEqual(ntfySetup(ntfyValue()), { configured: true, enabled: true });
  assert.deepEqual(ntfySetup(ntfyValue({ topic: '', enabled: false })), {
    configured: false,
    enabled: false,
  });
  assert.deepEqual(gotifySetup(gotifyValue({ token: null })), { configured: false, enabled: true });
  assert.deepEqual(gotifySetup(null), { configured: false, enabled: false });
});

test('answers: 2xx accepted, 408/425/429/5xx retried, 401/403 paused until fixed, 404/410/3xx probed, other 4xx failed', () => {
  const now = 1800000000000;
  assert.deepEqual(classifyPushResponse('ntfy', 200), {
    type: 'accepted',
    status: 200,
    externalRef: null,
  });
  const slow = classifyPushResponse('ntfy', 429, { 'retry-after': '120' }, now);
  assert.equal(slow.type, 'retry');
  assert.equal(slow.afterMs, 120000);
  for (const status of [408, 425, 500, 502, 503])
    assert.equal(classifyPushResponse('Gotify', status).type, 'retry', String(status));
  for (const status of [401, 403]) {
    const outcome = classifyPushResponse('Gotify', status);
    assert.equal(outcome.type, 'pause', String(status));
    assert.equal(outcome.transient, false, 'a wrong token stays paused until something changes');
    assert.match(outcome.reason, /refused Uptime Goblin's credentials/);
  }
  for (const status of [404, 410, 301, 302, 307, 308]) {
    const outcome = classifyPushResponse('ntfy', status);
    assert.equal(outcome.type, 'pause', String(status));
    assert.equal(outcome.transient, true, String(status));
  }
  for (const status of [400, 413, 422]) {
    const outcome = classifyPushResponse('ntfy', status);
    assert.equal(outcome.type, 'failed', String(status));
    assert.equal(outcome.status, status);
  }
});

test('failures: a refused address or untrusted TLS pauses, sent-but-unanswered is unknown, the rest retry', () => {
  assert.deepEqual(
    classifyPushError('ntfy', new OutboundError('EPOLICY', PUSH_REFUSED)).type,
    'pause'
  );
  const tls = classifyPushError(
    'ntfy',
    new OutboundError('DEPTH_ZERO_SELF_SIGNED_CERT', 'untrusted', { phase: 'send' })
  );
  assert.equal(tls.type, 'pause');
  assert.equal(tls.transient, true);
  assert.equal(
    classifyPushError(
      'ntfy',
      new OutboundError('ETIMEDOUT', 'The request timed out.', { phase: 'await' })
    ).type,
    'unknown'
  );
  assert.equal(
    classifyPushError('ntfy', new OutboundError('ECONNREFUSED', 'refused', { phase: 'connect' }))
      .type,
    'retry'
  );
  assert.equal(classifyPushError('ntfy', new OutboundError('ETOOLARGE', 'big')).type, 'failed');
});

test('the address policy: the collectors’ rule, loopback only with GOBLIN_ALLOW_LOOPBACK', async t => {
  t.after(() => configureDestinations({ allowLoopback: false }));
  configureDestinations({ allowLoopback: false });
  for (const address of [
    '169.254.169.254',
    '0.0.0.0',
    '224.0.0.1',
    'fe80::1',
    '::ffff:169.254.169.254',
    '64:ff9b::a9fe:a9fe',
    '2002:a9fe:a9fe::1',
  ])
    assert.equal(await pushAddressProblem(address), PUSH_REFUSED, address);
  for (const address of ['127.0.0.1', '::1', '::ffff:127.0.0.1'])
    assert.equal(await pushAddressProblem(address), PUSH_LOOPBACK, address);
  for (const address of ['192.168.1.10', '10.0.0.5', 'fd00::5', '192.0.2.10'])
    assert.equal(await pushAddressProblem(address), null, address);
  assert.match(await pushAddressProblem('not-an-ip'), /did not resolve/);
  configureDestinations({ allowLoopback: true });
  assert.equal(await pushAddressProblem('127.0.0.1'), null);
  assert.equal(await pushAddressProblem('169.254.169.254'), PUSH_REFUSED, 'never metadata');
});

test('ntfy sends one JSON POST to the server root with the token and X-Goblin-Delivery', async t => {
  const fake = await server(t);
  const saved = {
    value: ntfyValue({
      server: `${fake.base}/ntfy`,
      token,
      tags: ['house'],
      dashboardUrl: 'https://orbit.example.test/',
    }),
    unreadable: [],
  };
  const channel = createNtfyChannel({ getSettings: () => saved, addressPolicy: allowAll });
  assert.equal((await channel.send(message('firing'))).type, 'accepted');
  const [request] = fake.requests;
  assert.equal(request.method, 'POST');
  assert.equal(request.url, '/ntfy/', 'the token is never in the address');
  assert.equal(request.headers.authorization, `Bearer ${token}`);
  assert.equal(request.headers['x-goblin-delivery'], 'd_abcdefghijklmnopqrstuvwxyz');
  assert.equal(request.headers['content-type'], 'application/json');
  assert.equal(request.headers['user-agent'], 'Uptime-Goblin');
  assert.deepEqual(JSON.parse(request.body), {
    topic: 'orbit-alerts',
    title: 'Plex alert',
    message: 'Source is unavailable',
    priority: 4,
    tags: ['house', 'warning'],
    click: 'https://orbit.example.test/',
  });
  assert.equal(request.body.includes(token), false, 'the body never carries the token');
});

test('Gotify sends to /message with X-Gotify-Key, never the token in the address', async t => {
  const fake = await server(t, { reply: () => ({ status: 200, body: '{"id":1}' }) });
  const saved = { value: gotifyValue({ server: fake.base }), unreadable: [] };
  const channel = createGotifyChannel({ getSettings: () => saved, addressPolicy: allowAll });
  assert.equal((await channel.send(message('resolved'))).type, 'accepted');
  const [request] = fake.requests;
  assert.equal(request.url, '/message');
  assert.equal(request.headers['x-gotify-key'], token);
  assert.equal(request.url.includes(token), false);
  assert.deepEqual(JSON.parse(request.body), {
    title: 'Plex recovered',
    message: 'Source is unavailable',
    priority: 4,
  });
});

test('TLS is verified: an untrusted certificate pauses, a trusted CA delivers', async t => {
  const fake = await server(t, { secure: true });
  const saved = { value: ntfyValue({ server: fake.base }), unreadable: [] };
  const untrusted = createNtfyChannel({ getSettings: () => saved, addressPolicy: allowAll });
  const refused = await untrusted.send(message());
  assert.equal(refused.type, 'pause');
  assert.equal(refused.transient, true);
  assert.equal(fake.requests.length, 0);
  const trusted = createNtfyChannel({
    getSettings: () => saved,
    addressPolicy: allowAll,
    ca: testCert,
  });
  assert.equal((await trusted.send(message())).type, 'accepted');
  assert.equal(fake.requests.length, 1);
});

test('the default address policy refuses metadata and loopback before connecting', async t => {
  t.after(() => configureDestinations({ allowLoopback: false }));
  configureDestinations({ allowLoopback: false });
  const fake = await server(t);
  for (const [server, reason] of [
    ['http://169.254.169.254', PUSH_REFUSED],
    [fake.base, PUSH_LOOPBACK],
  ]) {
    const saved = {
      value: ntfyValue({ server, allowPlainHttp: true }),
      unreadable: [],
    };
    const outcome = await createNtfyChannel({ getSettings: () => saved }).send(message());
    assert.equal(outcome.type, 'pause', server);
    assert.equal(outcome.reason, reason);
    const gotify = await createGotifyChannel({
      getSettings: () => ({ value: gotifyValue({ server, allowPlainHttp: true }), unreadable: [] }),
    }).send(message());
    assert.equal(gotify.reason, reason);
  }
  assert.equal(fake.requests.length, 0, 'nothing reached the loopback server');
});

test('switched off: skipped, except a test; not set up or unreadable credentials: paused', async t => {
  const fake = await server(t);
  let saved = { value: ntfyValue({ server: fake.base, enabled: false }), unreadable: [] };
  const channel = createNtfyChannel({ getSettings: () => saved, addressPolicy: allowAll });
  assert.equal((await channel.send(message())).type, 'skipped');
  assert.equal(fake.requests.length, 0);
  assert.equal((await channel.send(message(), { test: true })).type, 'accepted');
  assert.equal(fake.requests.length, 1);
  saved = { value: ntfyValue({ server: fake.base, topic: '' }), unreadable: [] };
  assert.match((await channel.send(message())).reason, /^ntfy is not set up: Enter the ntfy topic/);
  saved = { value: ntfyValue({ server: fake.base }), unreadable: ['token'] };
  assert.match((await channel.send(message())).reason, /cannot be opened/);
  saved = null;
  const unread = await channel.send(message());
  assert.equal(unread.type, 'pause');
  assert.equal(unread.transient, true);
  assert.equal(fake.requests.length, 1);
});

test('answers are read at most 4 KiB and a slow server is cut at the deadline', async t => {
  const big = await server(t, { reply: () => ({ status: 200, body: 'x'.repeat(1024 * 1024) }) });
  const saved = { value: ntfyValue({ server: big.base }), unreadable: [] };
  assert.equal(
    (await createNtfyChannel({ getSettings: () => saved, addressPolicy: allowAll }).send(message()))
      .type,
    'accepted'
  );
  assert.equal(PUSH_LIMITS.maxResponseBytes, 4096);
  // A server that never answers: the request was sent, so acceptance is unknown.
  const silent = http.createServer(() => {});
  await new Promise(resolve => silent.listen(0, '127.0.0.1', resolve));
  t.after(() => {
    silent.closeAllConnections();
    return new Promise(resolve => silent.close(resolve));
  });
  const quiet = {
    value: ntfyValue({ server: `http://127.0.0.1:${silent.address().port}` }),
    unreadable: [],
  };
  const outcome = await createNtfyChannel({
    getSettings: () => quiet,
    addressPolicy: allowAll,
    timeoutMs: 200,
  }).send(message());
  assert.equal(outcome.type, 'unknown');
});

test('the settings documents seal tokens and passwords, and the audit diff hides them and the topic', async () => {
  // A stand-in keyring: what lib/settings.mjs needs of it (sealText/openText), reversible.
  const keyring = {
    sealText: (purpose, text, aad) => Buffer.from(`${aad}|${text}`).toString('base64'),
    openText: (purpose, sealed, aad) => {
      const text = Buffer.from(sealed, 'base64').toString();
      if (!text.startsWith(`${aad}|`)) throw new Error('wrong aad');
      return text.slice(aad.length + 1);
    },
  };
  const store = memorySettingsStore();
  const settings = createSettings({ store, definitions: [ntfySettings, gotifySettings], keyring });
  const saved = await settings.update('notify', 'ntfy', {
    enabled: true,
    topic: 'orbit-alerts',
    token,
  });
  assert.deepEqual(saved.value.token, { set: true });
  assert.deepEqual(
    saved.diff.find(entry => entry.field === 'token'),
    {
      field: 'token',
      change: 'set',
    }
  );
  const row = await store.get('notify', 'ntfy');
  assert.equal(row.value.includes(token), false, 'sealed at rest');
  assert.equal((await settings.get('notify', 'ntfy')).value.token, token);
  const view = await settings.view('notify', 'ntfy');
  assert.equal(JSON.stringify(view).includes(token), false);
  // The diff as the audit row keeps it: the topic only as set/changed/cleared.
  assert.deepEqual(
    pushAuditDiff('ntfy', [
      { path: 'topic', from: '', to: 'orbit-alerts' },
      { path: 'topic', from: 'a', to: 'b' },
      { path: 'topic', from: 'a', to: '' },
      { path: 'token', change: 'changed' },
      { path: 'priorityFiring', from: 4, to: 5 },
    ]),
    [
      { path: 'topic', change: 'set' },
      { path: 'topic', change: 'changed' },
      { path: 'topic', change: 'cleared' },
      { path: 'token', change: 'changed' },
      { path: 'priorityFiring', from: 4, to: 5 },
    ]
  );
  // A document that breaks the rules is refused whole.
  await assert.rejects(settings.update('notify', 'ntfy', { topic: '' }), {
    code: 'settings_invalid',
  });
  await assert.rejects(settings.update('notify', 'gotify', { enabled: true }), {
    code: 'settings_invalid',
  });
  await assert.rejects(settings.update('notify', 'ntfy', { surprise: 1 }), {
    code: 'settings_invalid',
  });
  // Clearing removes the sealed value.
  await settings.update('notify', 'ntfy', { token: null });
  assert.equal((await settings.get('notify', 'ntfy')).value.token, null);
});

test('budget: routing checks and bodies cost microseconds per alert (20,000 in well under a second)', () => {
  // Every relayed alert asks whether ntfy and Gotify are set up (the settings rule) and each send
  // builds one body. Measured on the development host (2026-11-21) at 47-53 ms for these rounds;
  // the bound leaves a slow CI runner about 20 times that.
  const ntfy = ntfyValue({ token, tags: ['house'], dashboardUrl: 'https://orbit.example.test/' });
  const gotify = gotifyValue({ dashboardUrl: 'https://orbit.example.test/' });
  const started = performance.now();
  let size = 0;
  for (let i = 0; i < 20000; i++) {
    ntfySetup(ntfy);
    gotifySetup(gotify);
    size += JSON.stringify(ntfyBody(event(i % 2 ? 'resolved' : 'firing'), ntfy)).length;
    size += JSON.stringify(gotifyBody(event(), gotify)).length;
  }
  const elapsed = performance.now() - started;
  assert.ok(size > 0);
  assert.ok(elapsed < 1000, `20,000 rounds took ${Math.round(elapsed)} ms`);
  // A body is bounded whatever the alert: at most the request limit.
  const huge = event('firing', { name: 'n'.repeat(5000), message: 'm'.repeat(50000) });
  assert.ok(Buffer.byteLength(JSON.stringify(ntfyBody(huge, ntfy))) < PUSH_LIMITS.maxRequestBytes);
  assert.ok(
    Buffer.byteLength(JSON.stringify(gotifyBody(huge, gotify))) < PUSH_LIMITS.maxRequestBytes
  );
});

test('routing: ntfy and Gotify get a row only when set up and switched on, after 1.4.2’s channels', async () => {
  const { legacyEntries, legacyChannels } = await import('../../lib/alerting/policy.mjs');
  const { channelSetup } = await import('../../lib/alerting/view.mjs');
  assert.deepEqual(
    legacyChannels({ webhookConfigured: true, emailEnabled: true, push: ['gotify', 'ntfy'] }),
    ['env-webhook', 'email', 'ntfy', 'gotify']
  );
  assert.deepEqual(legacyChannels({ push: ['slack'] }), []);
  const settings = { enabled: true, notifyOnAlert: true, notifyOnRecovery: true };
  const rows = legacyEntries(event(), { eventUid: 'e_1', settings, push: ['ntfy'] });
  assert.deepEqual(
    rows.map(row => [row.channelId, row.kind, row.orderKey]),
    [['ntfy', 'firing', 'plex\n__availability']]
  );
  // Switched off alerts route nowhere, ntfy included.
  assert.deepEqual(
    legacyEntries(event(), { eventUid: 'e_2', settings: { enabled: false }, push: ['ntfy'] }),
    []
  );
  const push = { ntfy: ntfyValue({ enabled: false }), gotify: null };
  assert.deepEqual(channelSetup('ntfy', { push }), { configured: true, enabled: false });
  assert.deepEqual(channelSetup('gotify', { push }), { configured: false, enabled: false });
});
