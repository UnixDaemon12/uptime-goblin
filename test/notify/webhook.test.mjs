// The outbound client, the env-webhook address rule and the env-webhook channel, against real
// servers on 127.0.0.1 only.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { post, OutboundError, describeNetworkError } from '../../lib/notify/http.mjs';
import {
  envWebhookAddressProblem,
  parseWebhookUrl,
  ENV_WEBHOOK_REFUSED,
} from '../../lib/notify/address-policy.mjs';
import {
  createEnvWebhookChannel as createWebhookChannel,
  classifyWebhookResponse,
  classifyWebhookError,
  legacyWebhookBody,
} from '../../lib/notify/channels/webhook.mjs';
import {
  verifyWebhookSignature,
  generateSigningKey,
  publicSigningKey,
} from '../../lib/notify/sign.mjs';
import { configureDestinations } from '../../lib/destinations.mjs';
import { createOutbox, deliveryUid } from '../../lib/notify/outbox.mjs';
import { createMemoryOutboxStore } from '../../lib/notify/memory-store.mjs';
import { fakeClock, quietLogger } from '../alerting/fake-clock.mjs';

// Test-only key and self-signed certificate for 127.0.0.1 and localhost (valid 2020-2120), the
// same pair as test/mail.test.mjs.
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

// An HTTP(S) receiver on 127.0.0.1 that records requests and answers with `reply(request)`:
// {status, headers, body, afterMs}, or 'silent' to read the request and never answer.
async function receiver(t, { reply = () => ({ status: 200 }), secure = false } = {}) {
  const requests = [],
    sockets = new Set();
  let connections = 0;
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
    const answer = reply(request);
    if (answer === 'silent') return;
    if (answer.afterMs) await new Promise(resolve => setTimeout(resolve, answer.afterMs));
    if (res.destroyed) return;
    res.writeHead(answer.status, answer.headers ?? {});
    res.end(answer.body ?? '');
  };
  const server = secure
    ? https.createServer({ key: testKey, cert: testCert }, handler)
    : http.createServer(handler);
  server.on('connection', socket => {
    connections++;
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => {
    for (const socket of sockets) socket.destroy();
    server.close();
  });
  const base = `${secure ? 'https' : 'http'}://127.0.0.1:${server.address().port}`;
  return {
    requests,
    base,
    get connections() {
      return connections;
    },
  };
}

// A lookup (dns.lookup's signature) answering every name with these addresses.
const answering =
  (...addresses) =>
  (host, options, callback) =>
    callback(
      null,
      addresses.map(address => ({ address, family: net.isIP(address) }))
    );
const allowAll = async () => null;
const event = {
  service: 'plex',
  name: 'Plex',
  kind: 'firing',
  category: 'availability',
  rule: '__availability',
  message: 'Source is unavailable: <b>"quoted"</b> é',
  time: 1800000000000,
};
const message = (overrides = {}) => ({
  uid: 'd_abcdefghijklmnopqrstuvwxyz',
  channelId: 'env-webhook',
  target: '',
  kind: 'firing',
  attempt: 1,
  digest: false,
  events: [event],
  ...overrides,
});

// Transport/address/retry tests use a real synthetic signing key so their requests
// reach the boundary being tested. Explicit empty-key tests override this default.
const transportSigningKey = generateSigningKey();
const createEnvWebhookChannel = options =>
  createWebhookChannel({
    signingKeys: () => [transportSigningKey],
    ...options,
  });

test('post() sends the exact body once, returns the answer and never follows redirects', async t => {
  const server = await receiver(t, {
    reply: request =>
      request.url === '/moved'
        ? { status: 302, headers: { Location: 'http://127.0.0.1:1/elsewhere' } }
        : { status: 201, headers: { 'X-Reply': 'yes' }, body: 'x'.repeat(100) },
  });
  const body = JSON.stringify({ hello: 'wörld' });
  const answer = await post(`${server.base}/hook?token=abc`, body, {
    headers: { 'Content-Type': 'application/json' },
    addressPolicy: allowAll,
    maxResponseBytes: 10,
  });
  assert.equal(answer.status, 201);
  assert.equal(answer.headers['x-reply'], 'yes');
  assert.equal(answer.body.toString(), 'x'.repeat(10));
  assert.equal(answer.truncated, true);
  assert.equal(server.requests[0].url, '/hook?token=abc');
  assert.equal(server.requests[0].body, body);
  assert.equal(server.requests[0].headers['content-length'], String(Buffer.byteLength(body)));
  const moved = await post(`${server.base}/moved`, '{}', { addressPolicy: allowAll });
  assert.equal(moved.status, 302);
  assert.equal(server.requests.length, 2, 'the redirect was not followed');
  await assert.rejects(
    post(server.base, 'x'.repeat(65537), { addressPolicy: allowAll }),
    error => error instanceof OutboundError && error.code === 'ETOOLARGE' && !error.sent
  );
  await assert.rejects(post('ftp://127.0.0.1/', ''), { code: 'EURL' });
  await assert.rejects(post('not a url', ''), { code: 'EURL' });
});

test('the address policy is applied to every resolved address at connect time', async t => {
  const server = await receiver(t);
  const port = new URL(server.base).port;
  const refuse169 = async address => (address.startsWith('169.254.') ? 'refused' : null);
  // A name that resolves to a refused address (here the metadata service) is never connected to,
  // even when another answer is allowed.
  for (const addresses of [['169.254.169.254'], ['127.0.0.1', '169.254.169.254']])
    await assert.rejects(
      post(`http://hook.example.test:${port}/`, '{}', {
        lookup: answering(...addresses),
        addressPolicy: refuse169,
      }),
      error => {
        assert.equal(error.code, 'EPOLICY');
        assert.equal(error.message, 'refused');
        assert.equal(error.sent, false);
        return true;
      }
    );
  // An IP literal is checked before connecting (no lookup happens for it).
  await assert.rejects(
    post('http://169.254.169.254/latest/meta-data', '{}', { addressPolicy: refuse169 }),
    { code: 'EPOLICY' }
  );
  assert.equal(server.connections, 0);
  // An allowed answer connects to exactly that address.
  const ok = await post(`http://hook.example.test:${port}/`, '{}', {
    lookup: answering('127.0.0.1'),
    addressPolicy: refuse169,
  });
  assert.equal(ok.status, 200);
  assert.equal(server.requests[0].headers.host, `hook.example.test:${port}`);
});

test('failures report whether the request was sent, without the URL', async t => {
  const silent = await receiver(t, { reply: () => 'silent' });
  const waited = await post(`${silent.base}/secret-path`, '{}', {
    addressPolicy: allowAll,
    timeoutMs: 200,
  }).catch(error => error);
  assert.equal(waited.code, 'ETIMEDOUT');
  assert.equal(waited.sent, true, 'sent, no answer: acceptance unknown');
  assert.ok(!waited.message.includes('secret-path'));
  // A lookup that never answers: nothing was sent.
  const hung = await post('http://hook.example.test/', '{}', {
    lookup: () => {},
    timeoutMs: 100,
  }).catch(error => error);
  assert.equal(hung.code, 'ETIMEDOUT');
  assert.equal(hung.phase, 'resolve');
  assert.equal(hung.sent, false);
  // A closed port refuses the connection: nothing was sent.
  const closed = net.createServer();
  await new Promise(resolve => closed.listen(0, '127.0.0.1', resolve));
  const port = closed.address().port;
  await new Promise(resolve => closed.close(resolve));
  const refused = await post(`http://127.0.0.1:${port}/`, '{}', { addressPolicy: allowAll }).catch(
    error => error
  );
  assert.equal(refused.code, 'ECONNREFUSED');
  assert.equal(refused.sent, false);
  assert.equal(refused.message, 'The server refused the connection.');
  // Cancelling works before and during a request.
  const controller = new AbortController();
  const pending = post(`${silent.base}/`, '{}', {
    addressPolicy: allowAll,
    signal: controller.signal,
  }).catch(error => error);
  setTimeout(() => controller.abort(), 50);
  assert.equal((await pending).code, 'EABORTED');
  const aborted = new AbortController();
  aborted.abort();
  await assert.rejects(post(silent.base, '{}', { signal: aborted.signal }), { code: 'EABORTED' });
  assert.equal(describeNetworkError('ENOTFOUND'), 'The host name could not be resolved.');
  assert.equal(describeNetworkError('weird code!'), 'The request failed.');
});

test('HTTPS verifies the certificate; a private CA must be trusted explicitly', async t => {
  const server = await receiver(t, { secure: true });
  const ok = await post(`${server.base}/`, '{}', { addressPolicy: allowAll, ca: testCert });
  assert.equal(ok.status, 200);
  const untrusted = await post(`${server.base}/`, '{}', { addressPolicy: allowAll }).catch(
    error => error
  );
  assert.ok(untrusted instanceof OutboundError);
  assert.match(untrusted.message, /TLS certificate is not trusted/);
  assert.equal(classifyWebhookError(untrusted).type, 'pause');
});

test('the env webhook keeps loopback and refuses link-local, multicast and reserved addresses', async t => {
  for (const allowLoopback of [false, true]) {
    configureDestinations({ allowLoopback });
    for (const address of ['127.0.0.1', '127.8.9.10', '::1', '::ffff:127.0.0.1'])
      assert.equal(await envWebhookAddressProblem(address), null, address);
    for (const address of ['10.0.0.5', '192.168.1.20', '172.16.0.1', 'fd00::1', '203.0.113.9'])
      assert.equal(await envWebhookAddressProblem(address), null, address);
    for (const address of [
      '169.254.169.254',
      '0.0.0.0',
      '224.0.0.1',
      '240.0.0.1',
      '255.255.255.255',
      'fe80::1',
      'fe80::1%eth0',
      'ff02::1',
      '::',
      'fd00:ec2::254',
      '::ffff:169.254.169.254',
    ])
      assert.equal(await envWebhookAddressProblem(address), ENV_WEBHOOK_REFUSED, address);
    assert.match(await envWebhookAddressProblem('not-an-ip'), /did not resolve/);
  }
  t.after(() => configureDestinations({ allowLoopback: false }));
});

test('GOBLIN_WEBHOOK_URL is parsed without ever repeating it in an error', () => {
  assert.equal(
    parseWebhookUrl(' http://127.0.0.1:9000/hook?x=1#frag ').href,
    'http://127.0.0.1:9000/hook?x=1'
  );
  for (const [value, pattern] of [
    ['not a url', /not a valid URL/],
    // No "//": safeReason() would show "or https://." as "or [url]" (docs audit 1.5).
    ['ftp://example.com/hook', /^GOBLIN_WEBHOOK_URL must be an http: or https: address\.$/],
    ['https://user:secret@example.com/hook', /user name or password/],
  ])
    assert.throws(
      () => parseWebhookUrl(value),
      error => pattern.test(error.message) && !error.message.includes('secret'),
      value
    );
});

test('the env webhook sends 1.4.2’s exact body, plus a delivery id and a signature', async t => {
  const server = await receiver(t);
  const current = generateSigningKey(),
    previous = generateSigningKey();
  let keys = [current];
  const signed = createEnvWebhookChannel({
    url: `${server.base}/alerts`,
    signingKeys: () => keys,
    now: () => 1800000000000,
    addressPolicy: allowAll,
  });
  assert.equal(signed.name, 'env-webhook');
  assert.deepEqual(await signed.send(message()), {
    type: 'accepted',
    status: 200,
    externalRef: null,
  });
  const [request] = server.requests;
  // Byte for byte what 1.4.2's fetch sent: JSON.stringify({source: 'orbit', ...event}).
  assert.equal(request.body, JSON.stringify({ source: 'orbit', ...event }));
  assert.equal(request.body, legacyWebhookBody(event));
  assert.equal(request.method, 'POST');
  assert.equal(request.url, '/alerts');
  assert.equal(request.headers['content-type'], 'application/json');
  assert.equal(request.headers['user-agent'], 'Uptime-Goblin');
  assert.equal(request.headers['x-goblin-delivery'], 'd_abcdefghijklmnopqrstuvwxyz');
  // Receivers written for Orbit read the old names: the same values, in 1.5 and 1.6.
  assert.equal(request.headers['x-orbit-delivery'], 'd_abcdefghijklmnopqrstuvwxyz');
  assert.equal(request.headers['x-orbit-signature'], request.headers['x-goblin-signature']);
  // The signature covers the request's own X-Goblin-Delivery, and only that one. Receivers
  // verify with the public key.
  const verify = (key, req, deliveryId = req.headers['x-goblin-delivery']) =>
    verifyWebhookSignature(
      publicSigningKey(key).publicKey,
      req.body,
      req.headers['x-goblin-signature'],
      {
        nowMs: 1800000000000,
        deliveryId,
      }
    );
  assert.match(
    request.headers['x-goblin-signature'],
    new RegExp(`^t=1800000000,v1a=${publicSigningKey(current).keyId}:[0-9a-f]{128}$`)
  );
  assert.deepEqual(verify(current, request), { ok: true });
  assert.equal(verify(current, request, 'd_another0000000000000000000').reason, 'mismatch');
  assert.equal(verify(previous, request).reason, 'mismatch');
  // During a rotation (the keys are read at each send) a second v1a signs with the old one.
  keys = [current, previous];
  await signed.send(message());
  const rotated = server.requests[1];
  assert.equal(rotated.headers['x-goblin-signature'].split(',').length, 3);
  assert.deepEqual(verify(current, rotated), { ok: true });
  assert.deepEqual(verify(previous, rotated), { ok: true });
  // No available key holds delivery before POST; an empty URL still skips it.
  keys = [];
  assert.equal((await signed.send(message())).type, 'pause');
  const plain = createWebhookChannel({ url: `${server.base}/alerts`, addressPolicy: allowAll });
  assert.equal((await plain.send(message())).type, 'pause');
  assert.equal(server.requests.length, 2);
  const off = createEnvWebhookChannel({ url: '' });
  assert.equal((await off.send(message())).type, 'skipped');
  assert.equal(server.requests.length, 2);
  // An HMAC secret of an earlier pre-release (or anything but an Ed25519 private key) is
  // refused when the channel tries to sign with it: nothing goes out signed with HMAC.
  const hmac = createEnvWebhookChannel({
    url: server.base,
    signingKeys: () => ['a'.repeat(64)],
    addressPolicy: allowAll,
  });
  await assert.rejects(hmac.send(message()), RangeError);
  assert.equal(server.requests.length, 2);
  assert.throws(() => createEnvWebhookChannel({ url: server.base, signingKeys: 'x' }), TypeError);
});

// Review F2: while the delivery service holds the webhook (a new signing key receivers may not
// have), each send pauses the channel with that reason before anything is signed or sent; the
// hold is read at each send, so the next send after it ends goes out signed.
test('a held webhook pauses before it signs or sends anything; once the hold ends it sends signed', async t => {
  const server = await receiver(t);
  const key = generateSigningKey();
  let held = 'Held for a new signing key.',
    signed = 0;
  const channel = createEnvWebhookChannel({
    url: `${server.base}/alerts`,
    signingKeys: () => {
      signed++;
      return [key];
    },
    hold: () => held,
    now: () => 1800000000000,
    addressPolicy: allowAll,
  });
  assert.deepEqual(await channel.send(message()), {
    type: 'pause',
    reason: 'Held for a new signing key.',
    status: null,
    transient: false,
  });
  assert.deepEqual([server.requests.length, signed], [0, 0]);
  held = null;
  assert.equal((await channel.send(message())).type, 'accepted');
  assert.equal(server.requests.length, 1);
  assert.match(
    server.requests[0].headers['x-goblin-signature'],
    new RegExp(`^t=1800000000,v1a=${publicSigningKey(key).keyId}:[0-9a-f]{128}$`)
  );
  // An invalid GOBLIN_WEBHOOK_URL is named first; a hold that is not a function is refused.
  const invalid = createEnvWebhookChannel({ url: 'ftp://x', hold: () => 'Held.' });
  assert.notEqual((await invalid.send(message())).reason, 'Held.');
  assert.throws(() => createEnvWebhookChannel({ url: server.base, hold: 'x' }), TypeError);
});

test('webhook answers are classified: retry, pause or fail', async t => {
  const now = Date.parse('2027-01-15T10:00:00Z');
  const table = [
    [200, 'accepted'],
    [204, 'accepted'],
    [301, 'pause'],
    [302, 'pause'],
    [400, 'failed'],
    [401, 'pause'],
    [403, 'pause'],
    [404, 'pause'],
    [408, 'retry'],
    [410, 'pause'],
    [413, 'failed'],
    [422, 'failed'],
    [425, 'retry'],
    [429, 'retry'],
    [500, 'retry'],
    [502, 'retry'],
    [503, 'retry'],
  ];
  for (const [status, type] of table) {
    const outcome = classifyWebhookResponse(status, {}, now);
    assert.equal(outcome.type, type, String(status));
    assert.equal(outcome.status, status);
    // 401, 403, 404, 410 and redirects may clear by themselves (a proxy restarting): transient,
    // so the outbox probes every 15 minutes (D10).
    if (type === 'pause') assert.equal(outcome.transient, true, String(status));
  }
  // An untrusted certificate is transient too; a refused address needs a change.
  assert.equal(
    classifyWebhookError(Object.assign(new Error('x'), { code: 'CERT_HAS_EXPIRED' })).transient,
    true
  );
  const policy = classifyWebhookError(
    Object.assign(new Error('The alert webhook address is refused.'), { code: 'EPOLICY' })
  );
  assert.deepEqual([policy.type, policy.transient], ['pause', false]);
  assert.equal(classifyWebhookResponse(429, { 'retry-after': '120' }, now).afterMs, 120000);
  assert.equal(
    classifyWebhookResponse(503, { 'retry-after': 'Fri, 15 Jan 2027 10:01:00 GMT' }, now).afterMs,
    60000
  );
  // End to end through a receiver answering each status in turn.
  const statuses = [503, 404, 400];
  const server = await receiver(t, {
    reply: () => ({ status: statuses.shift(), headers: { 'Retry-After': '30' } }),
  });
  const channel = createEnvWebhookChannel({ url: server.base, addressPolicy: allowAll });
  assert.deepEqual((await channel.send(message())).afterMs, 30000);
  assert.equal((await channel.send(message())).type, 'pause');
  assert.equal((await channel.send(message())).type, 'failed');
});

test('the env webhook pauses on refused or invalid addresses and never echoes the URL', async t => {
  configureDestinations({ allowLoopback: false });
  const server = await receiver(t);
  // Loopback works with the real rule even though collectors may not use loopback.
  const loopback = createEnvWebhookChannel({ url: `${server.base}/hook` });
  assert.equal((await loopback.send(message())).type, 'accepted');
  const metadata = await createEnvWebhookChannel({
    url: 'http://169.254.169.254/latest/meta-data',
  }).send(message());
  assert.equal(metadata.type, 'pause');
  assert.equal(metadata.reason, ENV_WEBHOOK_REFUSED);
  assert.equal(metadata.transient, false);
  // The same through NAT64 (probe P6), and through the channel's own lookup option.
  const nat64 = await createEnvWebhookChannel({ url: 'http://[64:ff9b::a9fe:a9fe]/' }).send(
    message()
  );
  assert.deepEqual([nat64.type, nat64.reason], ['pause', ENV_WEBHOOK_REFUSED]);
  const resolvedThere = await createEnvWebhookChannel({
    url: `http://hook.example.test:${new URL(server.base).port}/`,
    lookup: answering('169.254.169.254'),
  }).send(message());
  assert.deepEqual([resolvedThere.type, resolvedThere.reason], ['pause', ENV_WEBHOOK_REFUSED]);
  const lookedUp = await createEnvWebhookChannel({
    url: `http://hook.example.test:${new URL(server.base).port}/`,
    lookup: answering('127.0.0.1'),
  }).send(message());
  assert.equal(lookedUp.type, 'accepted');
  const rebinding = await createEnvWebhookChannel({
    url: `http://hook.example.test:${new URL(server.base).port}/`,
    post: (url, body, options) =>
      post(url, body, { ...options, lookup: answering('169.254.169.254') }),
  }).send(message());
  assert.equal(rebinding.type, 'pause');
  for (const url of ['https://user:hunter2@example.com/x', 'gopher://example.com/', '::bad::'])
    await createEnvWebhookChannel({ url })
      .send(message())
      .then(outcome => {
        assert.equal(outcome.type, 'pause', url);
        assert.ok(!outcome.reason.includes('hunter2'));
      });
  assert.equal(server.requests.length, 2);
});

test('a timeout after sending is "unknown"; failing to connect is a retry', async t => {
  const silent = await receiver(t, { reply: () => 'silent' });
  const channel = createEnvWebhookChannel({
    url: silent.base,
    addressPolicy: allowAll,
    timeoutMs: 150,
  });
  const outcome = await channel.send(message());
  assert.equal(outcome.type, 'unknown');
  assert.match(outcome.reason, /may have received the alert/);
  // D30: one resend, 2 minutes later (overridable for tests).
  assert.deepEqual(channel.unknown, { resendAfterMs: 120000, maxResends: 1 });
  assert.deepEqual(
    createEnvWebhookChannel({ url: silent.base, unknown: { resendAfterMs: 5, maxResends: 2 } })
      .unknown,
    { resendAfterMs: 5, maxResends: 2 }
  );
  const closed = net.createServer();
  await new Promise(resolve => closed.listen(0, '127.0.0.1', resolve));
  const port = closed.address().port;
  await new Promise(resolve => closed.close(resolve));
  const refused = await createEnvWebhookChannel({
    url: `http://127.0.0.1:${port}/`,
    addressPolicy: allowAll,
  }).send(message());
  assert.equal(refused.type, 'retry');
  assert.equal(refused.afterMs, null);
  // Cancelled mid-request (Uptime Goblin stopping) after the body went out: unknown.
  const controller = new AbortController();
  const pending = createEnvWebhookChannel({ url: silent.base, addressPolicy: allowAll }).send(
    message(),
    { signal: controller.signal }
  );
  setTimeout(() => controller.abort(), 50);
  assert.equal((await pending).type, 'unknown');
});

test('a receiver that answers after the deadline gets exactly two requests with one delivery id', async t => {
  // Probe P4, inverted: the receiver does its work before answering (an n8n flow answering at
  // the end) and takes longer than Uptime Goblin waits. Scaled down: a 150 ms deadline stands for 8 s.
  const server = await receiver(t, { reply: () => ({ status: 200, afterMs: 300 }) });
  const clock = fakeClock();
  const store = createMemoryOutboxStore();
  const outbox = createOutbox({
    store,
    clock,
    rng: () => 1,
    logger: quietLogger(),
    channels: [
      createEnvWebhookChannel({
        url: `${server.base}/slow`,
        addressPolicy: allowAll,
        timeoutMs: 150,
      }),
    ],
  });
  t.after(() => outbox.stop({ timeoutMs: 0 }));
  await outbox.enqueue({
    eventUid: 'e_slow',
    channelId: 'env-webhook',
    kind: 'firing',
    orderKey: 'plex\n__availability',
    event,
  });
  const sendAndSettle = async () => {
    await outbox.pump();
    while (outbox.inFlight) await new Promise(resolve => setTimeout(resolve, 20));
  };
  await sendAndSettle();
  let [row] = await store.list({ limit: 10 });
  assert.deepEqual([row.state, row.unknowns], ['queued', 1]);
  // Not again before 2 minutes.
  await clock.advance(119999);
  await sendAndSettle();
  assert.equal(server.requests.length, 1);
  await clock.advance(1);
  await sendAndSettle();
  [row] = await store.list({ limit: 10 });
  assert.deepEqual([row.state, row.deadReason], ['dead', 'unknown']);
  // Hours later, still two: the row ended "may have arrived".
  await clock.advance(6 * 3600 * 1000);
  await sendAndSettle();
  await new Promise(resolve => setTimeout(resolve, 400));
  assert.equal(server.requests.length, 2);
  const ids = server.requests.map(request => request.headers['x-goblin-delivery']);
  assert.deepEqual(ids, [
    deliveryUid('e_slow', 'env-webhook'),
    deliveryUid('e_slow', 'env-webhook'),
  ]);
});

// A receiver on 127.0.0.1 that speaks HTTP by hand: once a whole request is in (its headers and
// Content-Length bytes), `answer(socket, request)` writes what it likes, and the connection stays
// open until the test ends unless the answer closes it (a body that ends only with the
// connection, on a connection kept open).
async function rawReceiver(t, answer) {
  const requests = [],
    sockets = new Set();
  const server = net.createServer(socket => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => {});
    let seen = Buffer.alloc(0);
    socket.on('data', chunk => {
      seen = Buffer.concat([seen, chunk]);
      const end = seen.indexOf('\r\n\r\n');
      if (end < 0) return;
      const head = seen.subarray(0, end).toString('latin1');
      const length = Number(/content-length:\s*(\d+)/i.exec(head)?.[1] ?? 0);
      if (seen.length < end + 4 + length) return;
      const request = {
        head,
        delivery: /x-goblin-delivery:\s*(\S+)/i.exec(head)?.[1] ?? null,
        body: seen.subarray(end + 4, end + 4 + length).toString('utf8'),
      };
      seen = Buffer.alloc(0);
      requests.push(request);
      answer(socket, request);
    });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => {
    for (const socket of sockets) socket.destroy();
    server.close();
  });
  return { requests, base: `http://127.0.0.1:${server.address().port}` };
}

test('a 2xx counts once its status is in, however its body ends: deadline, cancellation or a slow end', async t => {
  // 1.4.3's fetch() resolved on the headers and never read the body. A status that arrived is the
  // receiver's answer: cutting its body short (the deadline, Uptime Goblin stopping) must not turn an
  // accepted alert into "unknown", which resent it and counted it against the channel.
  const open = await rawReceiver(t, socket =>
    socket.write('HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok\n')
  );
  const answer = await post(`${open.base}/hook`, '{}', { addressPolicy: allowAll, timeoutMs: 200 });
  assert.deepEqual(
    [answer.status, answer.truncated, answer.body.toString()],
    [200, true, 'ok\n'],
    'the deadline ends the body, not the answer'
  );
  const channel = createEnvWebhookChannel({
    url: `${open.base}/hook`,
    addressPolicy: allowAll,
    timeoutMs: 200,
  });
  const sent = await channel.send(message());
  assert.deepEqual([sent.type, sent.status], ['accepted', 200]);
  assert.equal(open.requests.length, 2, 'one request each');

  // A framework that flushes the status, then works before it ends the body.
  const slowEnd = http.createServer((req, res) => {
    req.resume();
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.write('working');
      setTimeout(() => res.end(' done'), 1500);
    });
  });
  await new Promise(resolve => slowEnd.listen(0, '127.0.0.1', resolve));
  t.after(() => {
    slowEnd.closeAllConnections();
    slowEnd.close();
  });
  const started = Date.now();
  const outcome = await createEnvWebhookChannel({
    url: `http://127.0.0.1:${slowEnd.address().port}/`,
    addressPolicy: allowAll,
    timeoutMs: 300,
  }).send(message());
  assert.deepEqual([outcome.type, outcome.status], ['accepted', 200]);
  assert.ok(Date.now() - started < 1400, 'answered at the deadline, not at the end of the body');

  // Uptime Goblin stopping while the body is read: the alert was accepted.
  let statusSent;
  const statusIn = new Promise(resolve => (statusSent = resolve));
  const held = await rawReceiver(t, socket => {
    socket.write('HTTP/1.1 202 Accepted\r\nContent-Length: 100\r\n\r\npartial');
    statusSent();
  });
  const controller = new AbortController();
  const pending = createEnvWebhookChannel({ url: held.base, addressPolicy: allowAll }).send(
    message(),
    { signal: controller.signal }
  );
  await statusIn;
  await new Promise(resolve => setTimeout(resolve, 50));
  controller.abort();
  const stopped = await pending;
  assert.deepEqual([stopped.type, stopped.status], ['accepted', 202]);

  // Any status counts the same way: a 503 whose body never ends is a retry after Retry-After.
  const busy = await rawReceiver(t, socket =>
    socket.write('HTTP/1.1 503 Service Unavailable\r\nRetry-After: 30\r\n\r\nbusy')
  );
  const later = await createEnvWebhookChannel({
    url: busy.base,
    addressPolicy: allowAll,
    timeoutMs: 200,
  }).send(message());
  assert.deepEqual([later.type, later.status, later.afterMs], ['retry', 503, 30000]);
});

test('a receiver that sends 200 at once and ends its body late gets one request per alert, all delivered', async t => {
  // Through the outbox: before, each such alert was "unknown", sent again after 2 minutes, ended
  // "may have arrived", and after five of them the circuit opened (every request was answered 200).
  const server = await rawReceiver(t, socket =>
    socket.write('HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok\n')
  );
  const clock = fakeClock();
  const store = createMemoryOutboxStore();
  const outbox = createOutbox({
    store,
    clock,
    rng: () => 1,
    logger: quietLogger(),
    channels: [
      createEnvWebhookChannel({
        url: `${server.base}/hook`,
        addressPolicy: allowAll,
        timeoutMs: 150,
      }),
    ],
  });
  t.after(() => outbox.stop({ timeoutMs: 0 }));
  for (let i = 1; i <= 6; i++)
    await outbox.enqueue({
      eventUid: `e_late_${i}`,
      channelId: 'env-webhook',
      kind: 'firing',
      orderKey: `src${i}\n__availability`,
      event: { ...event, service: `src${i}` },
    });
  const sendAndSettle = async () => {
    for (let i = 0; i < 20; i++) {
      const { started } = await outbox.pump();
      while (outbox.inFlight) await new Promise(resolve => setTimeout(resolve, 20));
      if (!started) return;
    }
  };
  await sendAndSettle();
  // Ten minutes later: nothing is sent again.
  for (let minute = 0; minute < 10; minute++) {
    await clock.advance(60 * 1000);
    await sendAndSettle();
  }
  assert.equal(server.requests.length, 6);
  assert.equal(new Set(server.requests.map(request => request.delivery)).size, 6);
  const rows = await store.list({ limit: 10 });
  assert.deepEqual(
    rows.map(row => row.state),
    Array(6).fill('delivered')
  );
  const status = await store.channel('env-webhook');
  assert.deepEqual(
    [status.state, status.deliveredTotal, status.failedTotal, status.consecutiveFailures],
    ['ok', 6, 0, 0]
  );
});
