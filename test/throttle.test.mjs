import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { createApp, startupExitCode } from '../server.mjs';
import { passwordRequiredMessage } from '../lib/identity/index.mjs';
import { LoginThrottle, clientAddress, throttleKey, trustedProxies } from '../lib/throttle.mjs';
import { decideTransport } from '../lib/http/transport.mjs';
import { limitConnectionsPerClient, loopbackClient, requestClient } from '../lib/http/pipeline.mjs';

const password = 'fixture-throttle-password';
const basic = value => 'Basic ' + Buffer.from('admin:' + value).toString('base64');
function temporary(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-throttle-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

test('throttle allows free attempts, then doubles lockouts up to the cap', () => {
  let now = 0;
  const throttle = new LoginThrottle({
    freeAttempts: 3,
    baseMs: 1000,
    maxMs: 8000,
    now: () => now,
  });
  for (let i = 0; i < 3; i++) throttle.failure('a');
  assert.equal(throttle.retryAfter('a'), 0);
  const expected = [1000, 2000, 4000, 8000, 8000];
  for (const wait of expected) {
    throttle.failure('a');
    assert.equal(throttle.retryAfter('a'), wait);
    now += wait;
    assert.equal(throttle.retryAfter('a'), 0);
  }
  assert.equal(throttle.retryAfter('b'), 0);
  throttle.success('a');
  throttle.failure('a');
  assert.equal(throttle.retryAfter('a'), 0);
});

test('throttle forgets idle clients and bounds memory', () => {
  let now = 0;
  const throttle = new LoginThrottle({
    freeAttempts: 0,
    forgetMs: 100,
    maxClients: 3,
    now: () => now,
  });
  throttle.failure('old');
  now = 200;
  assert.equal(throttle.retryAfter('old'), 0);
  for (const key of ['a', 'b', 'c', 'd']) throttle.failure(key);
  assert.equal(throttle.size, 3);
  assert.equal(throttle.retryAfter('a'), 0);
  assert.ok(throttle.retryAfter('d') > 0);
});

test('client address ignores forwarding headers unless the proxy is trusted', () => {
  const req = {
    headers: { 'x-forwarded-for': '203.0.113.9, 198.51.100.7' },
    socket: { remoteAddress: '10.0.0.2' },
  };
  assert.equal(clientAddress(req), '10.0.0.2');
  assert.equal(clientAddress(req, trustedProxies('10.0.0.0/8')), '198.51.100.7');
  // A peer that is not a listed proxy cannot choose its own throttling key.
  assert.equal(clientAddress(req, trustedProxies('loopback')), '10.0.0.2');
  assert.equal(
    clientAddress(
      { headers: {}, socket: { remoteAddress: '10.0.0.2' } },
      trustedProxies('10.0.0.2')
    ),
    '10.0.0.2'
  );
  // Unparseable forwarded values fall back to the peer address.
  assert.equal(
    clientAddress(
      { headers: { 'x-forwarded-for': 'not-an-ip' }, socket: { remoteAddress: '10.0.0.2' } },
      trustedProxies('10.0.0.2')
    ),
    '10.0.0.2'
  );
});

// A GOBLIN_TRUST_PROXY entry may name the proxy by its IPv4-mapped IPv6 address (::ffff:a.b.c.d)
// or range (::ffff:a.b.c.d/104 to /128, the IPv4 /8 to /32 it stands for), and the proxy's peer
// address reads a.b.c.d on an IPv4 listener and ::ffff:a.b.c.d on a dual-stack one.
// trustedProxies() keeps such an entry as an IPv6 rule and checks a mapped peer as plain IPv4;
// net.BlockList matches the two spellings across, both ways. These pin that: each user of the
// check (the lockout key, the HTTPS decision, the connection share) trusts the proxy however the
// entry and the peer are spelled, as it does for the plain entry, and trusts nothing else.
test('an IPv4-mapped GOBLIN_TRUST_PROXY entry trusts its proxy in either peer spelling, and nothing more', () => {
  const forwarded = remoteAddress => ({
    headers: { 'x-forwarded-for': '203.0.113.9, 198.51.100.7', 'x-forwarded-proto': 'https' },
    socket: { remoteAddress },
  });
  const inside = ['192.0.2.10', '::ffff:192.0.2.10', '::ffff:c000:20a'];
  const outside = [
    '192.0.3.10',
    '::ffff:192.0.3.10',
    '10.0.2.10',
    '::ffff:10.0.2.10',
    // The other IPv6 forms that carry 192.0.2.10 (NAT64, IPv4-compatible, IPv4-translated) are
    // other peers, a gateway or translator connecting for that client, not the proxy.
    '64:ff9b::192.0.2.10',
    '::192.0.2.10',
    '::ffff:0:192.0.2.10',
    '2001:db8::c000:20a',
  ];
  for (const entry of [
    '::ffff:192.0.2.10',
    '::ffff:c000:20a',
    '0:0:0:0:0:ffff:192.0.2.10',
    '::ffff:192.0.2.10/128',
    '::ffff:192.0.2.8/126',
    '::ffff:192.0.2.0/120',
    // The plain spellings give the same answers.
    '192.0.2.10',
    '192.0.2.0/24',
  ]) {
    const trusted = trustedProxies(entry);
    assert.deepEqual(trusted.warnings, [], entry);
    for (const peer of inside) {
      const req = forwarded(peer),
        transport = decideTransport({ peer, headers: req.headers, trusted });
      assert.equal(trusted(peer), true, `${entry} ${peer}`);
      assert.equal(transport.kind, 'https', `${entry} ${peer}`);
      assert.equal(clientAddress(req, trusted), '198.51.100.7', `${entry} ${peer}`);
      assert.equal(requestClient(req, transport, trusted), '198.51.100.7', `${entry} ${peer}`);
    }
    for (const peer of outside) {
      const req = forwarded(peer),
        transport = decideTransport({ peer, headers: req.headers, trusted });
      assert.equal(trusted(peer), false, `${entry} ${peer}`);
      assert.equal(transport.kind, 'http', `${entry} ${peer}`);
      assert.equal(clientAddress(req, trusted), throttleKey(peer), `${entry} ${peer}`);
      assert.equal(requestClient(req, transport, trusted), throttleKey(peer), `${entry} ${peer}`);
    }
  }
  // A proxy on this host named by its mapped loopback address or range: its clients get their
  // own lockout keys, not the host's own, in either peer spelling. A loopback peer it does not
  // name (::1, another 127.x) keeps the host's key.
  for (const entry of ['::ffff:127.0.0.1', '::ffff:127.0.0.0/104']) {
    const trusted = trustedProxies(entry);
    for (const peer of ['127.0.0.1', '::ffff:127.0.0.1']) {
      const req = forwarded(peer),
        transport = decideTransport({ peer, headers: req.headers, trusted });
      assert.equal(transport.kind, 'https', `${entry} ${peer}`);
      assert.equal(requestClient(req, transport, trusted), '198.51.100.7', `${entry} ${peer}`);
    }
    const req = forwarded('::1');
    assert.equal(
      requestClient(req, decideTransport({ peer: '::1', headers: req.headers, trusted }), trusted),
      loopbackClient,
      entry
    );
  }
  const other = forwarded('::ffff:127.0.0.2'),
    named = trustedProxies('::ffff:127.0.0.1');
  assert.equal(
    requestClient(
      other,
      decideTransport({ peer: '::ffff:127.0.0.2', headers: other.headers, trusted: named }),
      named
    ),
    loopbackClient
  );
  // A mapped range ends where the IPv4 range it stands for ends: ::ffff:192.168.0.0/113 is
  // 192.168.0.0/17.
  const slash17 = trustedProxies('::ffff:192.168.0.0/113');
  for (const [peer, expected] of [
    ['192.168.0.0', true],
    ['192.168.127.255', true],
    ['192.168.128.0', false],
    ['192.167.255.255', false],
  ])
    for (const spelled of [peer, `::ffff:${peer}`])
      assert.equal(slash17(spelled), expected, spelled);
  // The connection share: a trusted proxy holds none of its own, in either spelling; any other
  // client, in either spelling, is held to it.
  const server = new EventEmitter(),
    lines = [];
  limitConnectionsPerClient(server, {
    limit: 2,
    trusted: trustedProxies('::ffff:192.0.2.0/120'),
    log: { warn: line => lines.push(line) },
  });
  const connect = remoteAddress => {
    const socket = Object.assign(new EventEmitter(), {
      remoteAddress,
      destroyed: false,
      destroy() {
        this.destroyed = true;
      },
    });
    server.emit('connection', socket);
    return socket.destroyed;
  };
  for (let i = 0; i < 4; i++) {
    assert.equal(connect('192.0.2.10'), false);
    assert.equal(connect('::ffff:192.0.2.10'), false);
  }
  assert.deepEqual(['192.0.3.10', '::ffff:192.0.3.10', '192.0.3.10'].map(connect), [
    false,
    false,
    true,
  ]);
  assert.equal(lines.length, 1);
  // Nothing wider is accepted: the mapped prefix, or a mapped range wider than an IPv4 /8,
  // still refuses the start.
  for (const value of ['::ffff:0:0/96', '::ffff:0.0.0.0/96', '::ffff:10.0.0.0/103'])
    assert.throws(
      () => trustedProxies(value),
      error => error.refusal === true && /trusts too many addresses/.test(error.message),
      value
    );
});

// 'bootstrap passwords are verified with the slow hash, not a fast digest' moved with
// PasswordAuth to identity: test/identity/basic.test.mjs (sessions spec §8.2).

test('repeated failed sign-ins are locked out, even with the correct password', async t => {
  const app = await createApp({
    directory: temporary(t),
    port: 0,
    password,
    startScheduler: false,
    trustProxy: '',
    // The untrusted forwarding headers below make the requests plain HTTP, where Basic is
    // checked only with GOBLIN_INSECURE_HTTP_SESSIONS=1 (without it: 403, never counted).
    insecureHttpSessions: true,
    loginThrottle: new LoginThrottle({ freeAttempts: 2, baseMs: 60000 }),
  });
  const { port } = await app.listen();
  t.after(() => app.close());
  const get = (authorization, headers = {}) =>
    fetch(`http://127.0.0.1:${port}/api/dashboard`, {
      headers: authorization ? { Authorization: authorization, ...headers } : headers,
    });
  // Requests without credentials (the browser's first request) never count.
  for (let i = 0; i < 5; i++) assert.equal((await get()).status, 401);
  assert.equal((await get(basic(password))).status, 200);
  for (let i = 0; i < 3; i++) assert.equal((await get(basic('not it ' + i))).status, 401);
  const locked = await get(basic(password));
  assert.equal(locked.status, 429);
  assert.ok(Number(locked.headers.get('retry-after')) >= 59);
  // Untrusted forwarding headers cannot be used to dodge the lockout: they are not believed,
  // and every request from the Uptime Goblin host that no trusted proxy relays has the host's own key
  // (`loopback`, D18), with or without them, whatever address they name. The lockout above
  // holds for them too: one key, never a second one with fresh attempts.
  for (const headers of [
    { 'X-Forwarded-For': '203.0.113.50' },
    { 'X-Forwarded-For': '198.51.100.7' },
    { 'X-Real-IP': '203.0.113.51' },
    { Forwarded: 'for=203.0.113.52' },
  ])
    assert.equal((await get(basic(password), headers)).status, 429, JSON.stringify(headers));
});

test('a trusted proxy lockout applies per forwarded client', async t => {
  const app = await createApp({
    directory: temporary(t),
    port: 0,
    password,
    startScheduler: false,
    trustProxy: true,
    loginThrottle: new LoginThrottle({ freeAttempts: 1, baseMs: 60000 }),
  });
  const { port } = await app.listen();
  t.after(() => app.close());
  // Scripts through the trusted proxy over HTTPS.
  const get = (authorization, client) =>
    fetch(`http://127.0.0.1:${port}/api/dashboard`, {
      headers: {
        Authorization: authorization,
        'X-Forwarded-For': client,
        'X-Forwarded-Proto': 'https',
      },
    });
  for (let i = 0; i < 2; i++) assert.equal((await get(basic('bad'), '203.0.113.1')).status, 401);
  assert.equal((await get(basic(password), '203.0.113.1')).status, 429);
  assert.equal((await get(basic(password), '203.0.113.2')).status, 200);
});

test('a proxy named by its IPv4-mapped address or range gets HTTPS sign-in and per-client lockouts; another mapped address gets neither', async t => {
  const start = async trustProxy => {
    const app = await createApp({
      directory: temporary(t),
      port: 0,
      password,
      startScheduler: false,
      trustProxy,
      loginThrottle: new LoginThrottle({ freeAttempts: 1, baseMs: 60000 }),
    });
    const { port } = await app.listen();
    t.after(() => app.close());
    // The proxy connects from 127.0.0.1 (an IPv4 listener's spelling of ::ffff:127.0.0.1).
    return (authorization, client) =>
      fetch(`http://127.0.0.1:${port}/api/dashboard`, {
        headers: {
          Authorization: authorization,
          'X-Forwarded-For': client,
          'X-Forwarded-Proto': 'https',
        },
      });
  };
  for (const trustProxy of ['::ffff:127.0.0.1', '::ffff:127.0.0.0/104']) {
    const get = await start(trustProxy);
    for (let i = 0; i < 2; i++)
      assert.equal((await get(basic('bad'), '203.0.113.1')).status, 401, trustProxy);
    assert.equal((await get(basic(password), '203.0.113.1')).status, 429, trustProxy);
    assert.equal((await get(basic(password), '203.0.113.2')).status, 200, trustProxy);
  }
  // A proxy the entry does not name: its X-Forwarded-Proto is not believed, so the request is
  // plain HTTP, where a password is refused without GOBLIN_INSECURE_HTTP_SESSIONS=1.
  const untrusted = await start('::ffff:127.0.0.2');
  assert.equal((await untrusted(basic(password), '203.0.113.2')).status, 403);
});

test('throttle keys group IPv6 by /64 and unwrap IPv4-mapped addresses', () => {
  assert.equal(throttleKey('::ffff:203.0.113.5'), '203.0.113.5');
  assert.equal(throttleKey('203.0.113.5'), '203.0.113.5');
  assert.equal(throttleKey('2001:db8:1:2::a'), throttleKey('2001:db8:1:2:ffff:1:2:3'));
  assert.notEqual(throttleKey('2001:db8:1:2::a'), throttleKey('2001:db8:1:3::a'));
  let now = 0;
  const throttle = new LoginThrottle({ freeAttempts: 2, now: () => now });
  for (let i = 1; i <= 3; i++) throttle.failure(throttleKey(`2001:db8:1:2::${i}`));
  assert.ok(throttle.retryAfter(throttleKey('2001:db8:1:2::99')) > 0);
});

test('sign-in attempts refused as busy still count, so they cannot probe a cached password', async t => {
  const app = await createApp({
    directory: temporary(t),
    port: 0,
    password,
    startScheduler: false,
    trustProxy: '',
    loginThrottle: new LoginThrottle({ freeAttempts: 5, baseMs: 60000 }),
  });
  const { port } = await app.listen();
  t.after(() => app.close());
  const get = authorization =>
    fetch(`http://127.0.0.1:${port}/api/dashboard`, { headers: { Authorization: authorization } });
  assert.equal((await get(basic(password))).status, 200); // the correct password is now cached
  // A burst larger than the verification queue (2 at work, 16 waiting): some are checked, some
  // refused as busy. 30 at once, so the burst stays within one client's connections (32).
  const statuses = await Promise.all(
    Array.from({ length: 30 }, (_, i) => get(basic('burst guess ' + i)).then(r => r.status))
  );
  assert.ok(statuses.every(status => status === 401 || status === 429));
  // Every refused attempt counted, so the correct (cached) password is now refused too.
  assert.equal((await get(basic(password))).status, 429);
});

test('a replaced password is refused without counting as a guess, and a change clears failures', async t => {
  const app = await createApp({
    directory: temporary(t),
    port: 0,
    password,
    startScheduler: false,
    trustProxy: '',
    loginThrottle: new LoginThrottle({ freeAttempts: 2, baseMs: 60000 }),
  });
  const { port } = await app.listen();
  t.after(() => app.close());
  const call = (authorization, method = 'GET', route = '/api/dashboard', body) =>
    fetch(`http://127.0.0.1:${port}${route}`, {
      method,
      headers: {
        Authorization: authorization,
        'Content-Type': 'application/json',
        'X-Goblin-Request': '1',
      },
      body: body && JSON.stringify(body),
    });
  const next = 'the next fixture password';
  assert.equal((await call(basic('typo one'))).status, 401);
  assert.equal(
    (
      await call(basic(password), 'POST', '/api/auth/password', {
        currentPassword: password,
        password: next,
        confirmPassword: next,
      })
    ).status,
    200
  );
  // A stale device keeps polling with the old password: refused, never a lockout.
  for (let i = 0; i < 6; i++) assert.equal((await call(basic(password))).status, 401);
  assert.equal((await call(basic(next))).status, 200);
  // The earlier typo was cleared by the successful change, so two more typos stay free.
  for (let i = 0; i < 2; i++) assert.equal((await call(basic('typo ' + i))).status, 401);
  assert.equal((await call(basic(next))).status, 200);
});

test('a password change body held open is re-checked against a lockout set meanwhile', async t => {
  const throttle = new LoginThrottle({ freeAttempts: 1, baseMs: 60000 });
  const app = await createApp({
    directory: temporary(t),
    port: 0,
    password,
    startScheduler: false,
    trustProxy: '',
    loginThrottle: throttle,
  });
  const { port } = await app.listen();
  t.after(() => app.close());
  await fetch(`http://127.0.0.1:${port}/api/dashboard`, {
    headers: { Authorization: basic(password) },
  });
  const body = JSON.stringify({
    currentPassword: 'held guess',
    password: 'a new fixture password',
    confirmPassword: 'a new fixture password',
  });
  const held = new Promise((resolve, reject) => {
    const request = http.request(
      {
        host: '127.0.0.1',
        port,
        path: '/api/auth/password',
        method: 'POST',
        headers: {
          Authorization: basic(password),
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
          'X-Goblin-Request': '1',
        },
      },
      response => {
        response.resume();
        response.on('end', () => resolve(response.statusCode));
      }
    );
    request.on('error', reject);
    request.write(body.slice(0, 10));
    setTimeout(() => {
      // Lock this client (the Uptime Goblin host's own key) while the body is still arriving.
      throttle.failure('loopback');
      throttle.failure('loopback');
      request.end(body.slice(10));
    }, 100);
  });
  assert.equal(await held, 429);
});

test('without a password Uptime Goblin refuses to start, behind a proxy or not; with one, no request is served without a credential', async t => {
  // 1.4.x started without a password as a local preview (full access from this computer, 403
  // through a proxy). Uptime Goblin now refuses every such start, also on loopback with no proxy.
  for (const options of [
    { trustProxy: '1' },
    { trustProxy: '', allowedHosts: 'goblin.example.com' },
    { trustProxy: '', allowedHosts: 'localhost:4317' },
    { trustProxy: '', allowedHosts: '', host: '127.0.0.1' },
  ])
    await assert.rejects(
      createApp({ directory: temporary(t), password: '', startScheduler: false, ...options }),
      error => startupExitCode(error) === 78 && error.message === passwordRequiredMessage,
      JSON.stringify(options)
    );
  const app = await createApp({
    directory: temporary(t),
    port: 0,
    password,
    startScheduler: false,
    trustProxy: '',
    allowedHosts: 'localhost:4317',
  });
  const { port } = await app.listen();
  t.after(() => app.close());
  // Header-less from this computer, and through a proxy: 401, never the dashboard.
  for (const headers of [{}, { 'X-Forwarded-For': '203.0.113.9' }]) {
    const answer = await fetch(`http://127.0.0.1:${port}/api/dashboard`, { headers });
    assert.equal(answer.status, 401, JSON.stringify(headers));
    assert.equal((await answer.json()).code, 'signin_required');
  }
  // A script's credential from this computer is served. Through the (untrusted) proxy the
  // request is plain HTTP, where Basic needs GOBLIN_INSECURE_HTTP_SESSIONS=1: refused unchecked.
  const signedIn = await fetch(`http://127.0.0.1:${port}/api/dashboard`, {
    headers: { Authorization: basic(password) },
  });
  assert.equal(signedIn.status, 200);
  const plain = await fetch(`http://127.0.0.1:${port}/api/dashboard`, {
    headers: { Authorization: basic(password), 'X-Forwarded-For': '203.0.113.9' },
  });
  assert.equal(plain.status, 403);
  assert.equal((await plain.json()).code, 'https_required');
});

test('GOBLIN_TRUST_PROXY rejects malformed entries', () => {
  assert.throws(() => trustedProxies('10.0.0.0/99'), /invalid entry/);
  assert.throws(() => trustedProxies('proxy.example'), /invalid entry/);
  for (const value of ['127.0.0.1/8/ignored', '127.0.0.1/8/', '::1/0/128'])
    assert.throws(() => trustedProxies(value), /invalid entry/, value);
  // The entry is shown escaped and cut: a line break or terminal escape in it forged a line of
  // the log in the start's refusal.
  assert.throws(
    () => trustedProxies('x\u001b[2J\nFAKE LOG LINE'),
    error =>
      error.refusal === true &&
      error.message === 'GOBLIN_TRUST_PROXY has an invalid entry: "x\\u001b[2J\\nFAKE LOG LINE"'
  );
  assert.equal(trustedProxies(''), null);
  assert.equal(trustedProxies('0'), null);
  // Only commas and blanks name no proxy, yet are not off: a refusal, the one answer Uptime Goblin and
  // the native installer (which judges the value with this function) give (review CFG-4). Before,
  // it trusted no peer while the installer took it for a proxy.
  for (const value of [',', ' , ', ',,', ' \t,'])
    assert.throws(
      () => trustedProxies(value),
      error =>
        error.refusal === true &&
        error.message ===
          `GOBLIN_TRUST_PROXY names no proxy: it holds only commas and blanks (it is ${JSON.stringify(value).replace('\t', '\\t')}). Name your reverse proxy (loopback for one on this computer, or its address), or leave it empty (or set it to off) to trust none.`,
      JSON.stringify(value)
    );
  for (const value of ['off', ' off ', 'No', 'false'])
    assert.equal(trustedProxies(value), null, value);
});

test('parallel guesses from one client get no more password checks than sequential ones', async t => {
  const app = await createApp({
    directory: temporary(t),
    port: 0,
    password,
    startScheduler: false,
    trustProxy: '',
    loginThrottle: new LoginThrottle({ freeAttempts: 5, baseMs: 60000 }),
  });
  const { port } = await app.listen();
  t.after(() => app.close());
  const get = authorization =>
    fetch(`http://127.0.0.1:${port}/api/dashboard`, { headers: { Authorization: authorization } });
  const statuses = await Promise.all(
    Array.from({ length: 30 }, (_, i) => get(basic('parallel guess ' + i)).then(r => r.status))
  );
  // Only checked guesses answer 401; the rest were refused before any check.
  assert.ok(statuses.filter(status => status === 401).length <= 5, statuses.join(','));
  assert.equal((await get(basic(password))).status, 429);
});

test('a browser sending the same new credentials in parallel is verified once and not refused', async t => {
  const app = await createApp({
    directory: temporary(t),
    port: 0,
    password,
    startScheduler: false,
    trustProxy: '',
    loginThrottle: new LoginThrottle({ freeAttempts: 2, baseMs: 60000 }),
  });
  const { port } = await app.listen();
  t.after(() => app.close());
  const statuses = await Promise.all(
    ['/', '/app.js', '/style.css', '/favicon.svg', '/api/dashboard', '/api/system'].map(route =>
      fetch(`http://127.0.0.1:${port}${route}`, {
        headers: { Authorization: basic(password) },
      }).then(r => r.status)
    )
  );
  assert.deepEqual(statuses, [200, 200, 200, 200, 200, 200]);
});
