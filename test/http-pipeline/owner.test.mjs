// The owner's deployment (sessions spec §9.2): nginx on the Uptime Goblin host proxies goblin.example to
// Uptime Goblin on 127.0.0.1, with GOBLIN_TRUST_PROXY=loopback. Whether nginx sends X-Forwarded-Proto is
// unknown, so every variant it might send is played here against a real Uptime Goblin: the owner must
// be able to sign in, or be told exactly what to change, and never be locked out.
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { LoginThrottle, trustedProxies } from '../../lib/throttle.mjs';
import { loopbackClient, requestClient } from '../../lib/http/pipeline.mjs';
import { basic, cookieFrom, password, raw, startReal } from './harness.mjs';

const browser = (origin = 'https://goblin.example') => [
  `Origin: ${origin}`,
  'Sec-Fetch-Site: same-origin',
  'X-Goblin-Request: 1',
  'Content-Type: application/json',
];
const nginx = ({ proto, host = 'goblin.example', client = '198.51.100.20' } = {}) => [
  `Host: ${host}`,
  `X-Forwarded-For: ${client}`,
  ...(proto ? [`X-Forwarded-Proto: ${proto}`] : []),
];
const credentials = JSON.stringify({ login: 'admin', password });

// Uptime Goblin writes its diagnostics with console.warn; each owner() collects them until the next
// owner() starts (tests read one Uptime Goblin's journal at a time), and the test's end restores it.
const originalWarn = console.warn;

async function owner(t, options = {}) {
  const warnings = [];
  console.warn = (...args) => warnings.push(args.join(' '));
  t.after(() => (console.warn = originalWarn));
  const started = await startReal(t, {
    host: '127.0.0.1',
    trustProxy: 'loopback',
    allowedHosts: 'goblin.example',
    ...options,
  });
  // Only what the sign-in diagnostics write (§6.13), not start-up notes.
  const journal = () => warnings.filter(line => line.startsWith('Sign-in refused'));
  // The line that names a proxy on this host sending no forwarding headers (§16 C1).
  const headerlessLines = () => warnings.filter(line => line.startsWith('A reverse proxy on this'));
  const signIn = (lines, body = credentials) =>
    raw(started.port, ['POST /api/auth/login HTTP/1.1', ...lines], body);
  const get = (route, lines) => raw(started.port, [`GET ${route} HTTP/1.1`, ...lines]);
  return { ...started, journal, headerlessLines, signIn, get };
}

test('O1: nginx sends X-Forwarded-Proto: https — sign-in sets the __Host- cookie', async t => {
  const { signIn, get } = await owner(t);
  const answer = await signIn([...nginx({ proto: 'https' }), ...browser()]);
  assert.equal(answer.status, 200);
  const [cookie] = [].concat(answer.headers['set-cookie']);
  assert.match(
    cookie,
    /^__Host-goblin_session=v1\.[A-Za-z0-9_-]{43}; Path=\/; Secure; HttpOnly; SameSite=Strict$/
  );
  const session = await get('/api/session', [
    ...nginx({ proto: 'https' }),
    `Cookie: ${cookieFrom(answer)}`,
    'Sec-Fetch-Site: same-origin',
  ]);
  assert.equal(session.status, 200);
  assert.equal(session.json.transport.kind, 'https');
  assert.equal(session.json.transport.https, true);
});

for (const [id, proto] of [
  ['O2', null],
  ['O4', 'http'],
]) {
  test(`${id}: nginx sends ${proto ? 'X-Forwarded-Proto: http' : 'no protocol'} — refused with the fix, never counted`, async t => {
    const { signIn, get, journal } = await owner(t);
    for (let i = 0; i < 10; i++) {
      const refused = await signIn([...nginx({ proto }), ...browser()]);
      assert.equal(refused.status, 403);
      assert.equal(refused.json.code, 'proxy_proto_missing');
      assert.match(refused.json.error, /proxy_set_header X-Forwarded-Proto \$scheme;/);
    }
    assert.deepEqual(journal(), [
      'Sign-in refused: the browser used HTTPS (Origin https://goblin.example) but the request from 127.0.0.1 carries no X-Forwarded-Proto: https. Make the proxy send X-Forwarded-Proto: https (nginx: proxy_set_header X-Forwarded-Proto $scheme;) and make sure GOBLIN_TRUST_PROXY names it, or set GOBLIN_INSECURE_HTTP_SESSIONS=1 until it is fixed.',
    ]);
    // The page learns the transport before any attempt.
    const probe = await get('/api/session', [...nginx({ proto }), 'Sec-Fetch-Site: same-origin']);
    assert.equal(probe.status, 401);
    assert.deepEqual(probe.json.transport, { kind: 'http', insecureAllowed: false });
    // A script's Basic through the same nginx is plain HTTP too: refused as the sign-in is
    // (https_required), before its password is checked.
    const plain = await get('/api/dashboard', [...nginx({ proto }), `Authorization: ${basic()}`]);
    assert.equal(plain.status, 403);
    assert.equal(plain.json.code, 'https_required');
    // Nothing was counted: a script with Basic from the same forwarded client over HTTPS is
    // signed in.
    const script = await get('/api/dashboard', [
      ...nginx({ proto: 'https' }),
      `Authorization: ${basic()}`,
    ]);
    assert.equal(script.status, 200);
  });
}

test('O3: without the protocol but with GOBLIN_INSECURE_HTTP_SESSIONS=1 — signed in over plain HTTP', async t => {
  const { signIn, get } = await owner(t, { insecureHttpSessions: true });
  const answer = await signIn([...nginx(), ...browser()]);
  assert.equal(answer.status, 200);
  const [cookie] = [].concat(answer.headers['set-cookie']);
  assert.match(cookie, /^goblin_session=v1\.[^;]+; Path=\/; HttpOnly; SameSite=Strict$/);
  assert.doesNotMatch(cookie, /Secure/);
  assert.deepEqual(answer.json.transport, {
    kind: 'http',
    https: false,
    insecure: true,
    insecureAllowed: true,
  });
  const session = await get('/api/session', [
    ...nginx(),
    `Cookie: ${cookieFrom(answer)}`,
    'Sec-Fetch-Site: same-origin',
  ]);
  assert.equal(session.status, 200);
  assert.equal(session.json.transport.insecure, true);
});

test('O5: an https claim from a proxy Uptime Goblin does not trust is not believed, and the journal says so', async t => {
  const { signIn, journal } = await owner(t, { trustProxy: '' });
  const refused = await signIn([...nginx({ proto: 'https' }), ...browser()]);
  assert.equal(refused.status, 403);
  assert.equal(refused.json.code, 'proxy_proto_missing');
  assert.equal(journal().length, 1);
  assert.match(
    journal()[0],
    /from 127\.0\.0\.1 comes from a proxy that GOBLIN_TRUST_PROXY does not trust\./
  );
});

test('O6: a browser on the Uptime Goblin host itself (loopback) signs in with the plain cookie', async t => {
  const { signIn, port } = await owner(t);
  const answer = await signIn([`Host: 127.0.0.1:${port}`, ...browser(`http://127.0.0.1:${port}`)]);
  assert.equal(answer.status, 200);
  assert.match(
    [].concat(answer.headers['set-cookie'])[0],
    /^goblin_session=v1\.[^;]+; Path=\/; HttpOnly; SameSite=Strict$/
  );
  assert.equal(answer.json.transport.kind, 'loopback');
});

test('O7: a browser still holding 1.4.x Basic credentials is not prompted and signs in', async t => {
  const { signIn, get } = await owner(t);
  const cached = `Authorization: ${basic()}`;
  const probe = await get('/api/dashboard', [
    ...nginx({ proto: 'https' }),
    cached,
    'Sec-Fetch-Site: same-origin',
  ]);
  assert.equal(probe.status, 401);
  assert.equal(probe.headers['www-authenticate'], undefined);
  assert.equal(probe.json.code, 'signin_required');
  const answer = await signIn([...nginx({ proto: 'https' }), cached, ...browser()]);
  assert.equal(answer.status, 200);
  const dashboard = await get('/api/dashboard', [
    ...nginx({ proto: 'https' }),
    cached,
    `Cookie: ${cookieFrom(answer)}`,
    'Sec-Fetch-Site: same-origin',
  ]);
  assert.equal(dashboard.status, 200, 'the session decides; the cached Basic header is ignored');
});

test('O8: a proxy that hard-codes https for an http:// page is refused either way, with a way out', async t => {
  for (const insecureHttpSessions of [false, true]) {
    const { signIn, journal } = await owner(t, { insecureHttpSessions });
    const refused = await signIn([
      ...nginx({ proto: 'https' }),
      ...browser('http://goblin.example'),
    ]);
    assert.equal(refused.status, 403);
    assert.equal(refused.json.code, 'proxy_proto_mismatch');
    assert.deepEqual(journal(), [
      'Sign-in refused: the browser used http:// (Origin http://goblin.example) but the trusted proxy 127.0.0.1 sent X-Forwarded-Proto: https. Make it send the real scheme (nginx: proxy_set_header X-Forwarded-Proto $scheme;).',
    ]);
  }
  // The temporary escape (§9.3): stop trusting the proxy and allow plain-HTTP sessions.
  const escape = await owner(t, { trustProxy: '', insecureHttpSessions: true });
  const answer = await escape.signIn([
    ...nginx({ proto: 'https' }),
    ...browser('http://goblin.example'),
  ]);
  assert.equal(answer.status, 200);
  const cookie = cookieFrom(answer);
  assert.match(cookie, /^goblin_session=/);
  const dashboard = await escape.get('/api/dashboard', [
    ...nginx({ proto: 'https' }),
    `Cookie: ${cookie}`,
    'Sec-Fetch-Site: same-origin',
  ]);
  assert.equal(dashboard.status, 200);
});

test('O9: nginx’s default Host ($proxy_host) passes when the name is allowlisted, else says what to change', async t => {
  const upstream = port => [
    `Host: 127.0.0.1:${port}`,
    'X-Forwarded-For: 198.51.100.20',
    'X-Forwarded-Proto: https',
  ];
  const allowed = await owner(t);
  const ok = await allowed.signIn([...upstream(allowed.port), ...browser()]);
  assert.equal(ok.status, 200, ok.body);
  const bare = await owner(t, { allowedHosts: '' });
  const refused = await bare.signIn([...upstream(bare.port), ...browser()]);
  assert.equal(refused.status, 403);
  assert.equal(refused.json.code, 'cross_origin');
  assert.equal(bare.journal().length, 1);
  assert.match(bare.journal()[0], /proxy_set_header Host \$http_host;/);
  assert.match(bare.journal()[0], /add goblin\.example to GOBLIN_ALLOWED_HOSTS/);
});

test('O10: during a many-address attack a new forwarded client waits, the host itself does not', async t => {
  const loginThrottle = new LoginThrottle();
  const { signIn, get, port } = await owner(t, { loginThrottle });
  const first = await signIn([...nginx({ proto: 'https', client: '203.0.113.200' }), ...browser()]);
  assert.equal(first.status, 200);
  for (let i = 0; i < 50; i++) {
    const wrong = await signIn(
      [...nginx({ proto: 'https', client: `198.51.100.${i + 1}` }), ...browser()],
      JSON.stringify({ login: 'admin', password: `guess ${i}` })
    );
    assert.equal(wrong.status, 401);
  }
  assert.equal(loginThrottle.globalLocked(), true);
  const newcomer = await signIn([...nginx({ proto: 'https', client: '192.0.2.77' }), ...browser()]);
  assert.equal(newcomer.status, 429);
  assert.equal(newcomer.json.code, 'locked');
  assert.equal(newcomer.headers['retry-after'], '60');
  // The owner on the host itself (ssh -L to 127.0.0.1) is not held by the global lock (D18).
  const local = await signIn([`Host: 127.0.0.1:${port}`, ...browser(`http://127.0.0.1:${port}`)]);
  assert.equal(local.status, 200);
  // A browser already signed in keeps working: session requests are never throttle-checked.
  const kept = await get('/api/dashboard', [
    ...nginx({ proto: 'https', client: '203.0.113.200' }),
    `Cookie: ${cookieFrom(first)}`,
    'Sec-Fetch-Site: same-origin',
  ]);
  assert.equal(kept.status, 200);
});

test('O11: 6 KiB of other sites’ cookies beside the session cookie still sign in (D23)', async t => {
  const { signIn, get } = await owner(t);
  const answer = await signIn([...nginx({ proto: 'https' }), ...browser()]);
  const others = [];
  while (others.join('; ').length < 6 * 1024)
    others.push(`CF_Authorization_${others.length}=${randomBytes(48).toString('base64url')}`);
  others.push('malformed cookie without equals', 'goblin_session=from-a-parent-domain');
  const header = [...others.slice(0, 20), cookieFrom(answer), ...others.slice(20)].join('; ');
  assert.ok(header.length > 6 * 1024);
  const dashboard = await get('/api/dashboard', [
    ...nginx({ proto: 'https' }),
    `Cookie: ${header}`,
    'Sec-Fetch-Site: same-origin',
  ]);
  assert.equal(dashboard.status, 200);
});

// A proxy on this host that sends no forwarding headers at all (no X-Forwarded-For, no
// X-Forwarded-Proto): its requests come from 127.0.0.1 like a browser on the host itself, but
// they relay browsers from anywhere. Such a proxy that forwards the Host (O12), or keeps
// nginx's default Host 127.0.0.1:<port> with the name allowlisted for the Origin check (O13),
// must never get the loopback transport's plain cookie, banner-free and exempt from the
// global lock: it is refused with the fix, or with the opt-in it is plain HTTP, with the banner.
const headerless = (fix, origin) =>
  `Sign-in refused: the browser used ${
    origin.startsWith('https:')
      ? `HTTPS (Origin ${origin}) but the request from 127.0.0.1 comes from a proxy on this host that sends no forwarding headers. Make the proxy send X-Forwarded-Proto: https (nginx: proxy_set_header X-Forwarded-Proto $scheme;) and make sure GOBLIN_TRUST_PROXY names it, or set GOBLIN_INSECURE_HTTP_SESSIONS=1 until it is fixed.`
      : `plain HTTP (Origin ${origin}) through a proxy on this host that sends no forwarding headers (Host ${fix}). Serve Uptime Goblin over HTTPS through the proxy and make it send X-Forwarded-Proto (nginx: proxy_set_header X-Forwarded-Proto $scheme;) with GOBLIN_TRUST_PROXY=loopback, or set GOBLIN_INSECURE_HTTP_SESSIONS=1 on a trusted network.`
  }`;

for (const [id, what, hostOf] of [
  ['O12', 'forwards the Host', () => 'goblin.example'],
  ['O13', 'keeps nginx’s default Host', port => `127.0.0.1:${port}`],
])
  test(`${id}: a proxy that sends no forwarding headers and ${what} — refused with the fix, or plain HTTP with the opt-in`, async t => {
    for (const trustProxy of ['', 'loopback']) {
      const { signIn, get, journal, port } = await owner(t, { trustProxy });
      const proxy = [`Host: ${hostOf(port)}`];
      for (const [origin, code] of [
        ['https://goblin.example', 'proxy_proto_missing'],
        ['http://goblin.example', 'https_required'],
      ]) {
        const refused = await signIn([...proxy, ...browser(origin)]);
        assert.equal(refused.status, 403, `${trustProxy} ${origin}`);
        assert.equal(refused.json.code, code);
        assert.equal(refused.headers['set-cookie'], undefined);
      }
      assert.deepEqual(journal(), [
        headerless(hostOf(port), 'https://goblin.example'),
        headerless(hostOf(port), 'http://goblin.example'),
      ]);
      // The ssh tunnel (a page on 127.0.0.1) is still the loopback transport.
      const tunnel = await signIn([
        `Host: 127.0.0.1:${port}`,
        ...browser(`http://127.0.0.1:${port}`),
      ]);
      assert.equal(tunnel.status, 200);
      assert.equal(tunnel.json.transport.kind, 'loopback');
      assert.equal(tunnel.json.transport.insecure, false);
      if (id === 'O12') {
        // The page learns before any attempt that this way in needs HTTPS or the opt-in.
        const probe = await get('/api/session', [...proxy, 'Sec-Fetch-Site: same-origin']);
        assert.deepEqual(probe.json.transport, { kind: 'http', insecureAllowed: false });
        // And the loopback session cookie is not read through it.
        const through = await get('/api/session', [
          ...proxy,
          `Cookie: ${cookieFrom(tunnel)}`,
          'Sec-Fetch-Site: same-origin',
        ]);
        assert.equal(through.status, 401);
      }
    }
    // With GOBLIN_INSECURE_HTTP_SESSIONS=1: signed in over plain HTTP, and the banner stays on
    // every later request of that session, however it arrives (O13's look like loopback).
    const { signIn, get, port } = await owner(t, { insecureHttpSessions: true });
    const proxy = [`Host: ${hostOf(port)}`];
    const tunnel = await signIn([
      `Host: 127.0.0.1:${port}`,
      ...browser(`http://127.0.0.1:${port}`),
    ]);
    assert.equal(tunnel.status, 200);
    for (const origin of ['https://goblin.example', 'http://goblin.example']) {
      const answer = await signIn([...proxy, ...browser(origin)]);
      assert.equal(answer.status, 200, origin);
      const [cookie] = [].concat(answer.headers['set-cookie']);
      assert.match(cookie, /^goblin_session=v1\.[^;]+; Path=\/; HttpOnly; SameSite=Strict$/);
      assert.deepEqual(answer.json.transport, {
        kind: id === 'O12' ? 'http' : 'loopback',
        https: false,
        insecure: true,
        insecureAllowed: true,
      });
      const session = await get('/api/session', [
        ...proxy,
        `Cookie: ${cookieFrom(answer)}`,
        'Sec-Fetch-Site: same-origin',
      ]);
      assert.equal(session.status, 200);
      assert.equal(session.json.transport.insecure, true, 'the plain-HTTP banner');
    }
    // The tunnel's own session has no banner.
    const own = await get('/api/session', [
      `Host: 127.0.0.1:${port}`,
      `Cookie: ${cookieFrom(tunnel)}`,
      'Sec-Fetch-Site: same-origin',
    ]);
    assert.equal(own.json.transport.insecure, false);
    // The global lock (D18) holds the proxy's clients that the connection shows are not the
    // Uptime Goblin host's own (O12: a forwarded Host makes them `http`, keyed by the proxy's address),
    // never the tunnel. The tunnel's sign-in trusts the host's own lockout key only, so they stay
    // held. Those that keep nginx's default Host (O13) are the loopback transport, which only
    // the connection decides: whatever page address they send, they have the tunnel's key and
    // are not held either (§16 C1, see O15 and O16).
    const attacked = await owner(t, {
      insecureHttpSessions: true,
      loginThrottle: new LoginThrottle(),
    });
    for (let i = 0; i < 50; i++)
      await attacked.signIn(
        [...nginx({ proto: 'https', client: `198.51.100.${i + 1}` }), ...browser()],
        JSON.stringify({ login: 'admin', password: `guess ${i}` })
      );
    const through = [`Host: ${hostOf(attacked.port)}`, ...browser()];
    const held = await attacked.signIn(through);
    if (id === 'O12') {
      assert.equal(held.status, 429);
      assert.equal(held.json.code, 'locked');
    } else
      assert.equal(held.status, 200, 'the loopback transport is not held, whatever its Origin');
    const host = `127.0.0.1:${attacked.port}`;
    assert.equal(
      (await attacked.signIn([`Host: ${host}`, ...browser(`http://${host}`)])).status,
      200
    );
    if (id === 'O12') assert.equal((await attacked.signIn(through)).status, 429, 'still held');
  });

// A proxy on this host that does not name its client in X-Forwarded-For (it sends X-Real-IP and
// X-Forwarded-Proto only, or passes on whatever X-Forwarded-For the browser sent): every client
// behind it shares the proxy's address as its lockout key. A remote attacker who keeps failing
// there must not lock out the owner's way in over the ssh tunnel (D18, §9.3 item 5).
test('O14: a proxy that names no client never locks out the ssh tunnel; the journal says why', async t => {
  let now = Date.UTC(2026, 9, 1, 8);
  const loginThrottle = new LoginThrottle({ now: () => now });
  const { signIn, port } = await owner(t, { loginThrottle });
  const warnings = [];
  console.warn = (...args) => warnings.push(args.join(' '));
  for (const proxy of [
    ['Host: goblin.example', 'X-Real-IP: 203.0.113.66', 'X-Forwarded-Proto: https'],
    ['Host: goblin.example', 'X-Forwarded-For: 127.0.0.1', 'X-Forwarded-Proto: https'],
  ]) {
    // The attacker waits out each lockout and fails again, until it lasts 15 minutes.
    for (let i = 0; i < 20; i++) {
      now += loginThrottle.retryAfter('127.0.0.1');
      const wrong = await signIn(
        [...proxy, ...browser()],
        JSON.stringify({ login: 'admin', password: `guess ${i}` })
      );
      assert.equal(wrong.status, 401);
    }
    assert.equal(loginThrottle.retryAfter('127.0.0.1'), 15 * 60e3);
    now += 14 * 60e3;
    // Every client behind that proxy is locked out, the right password included.
    const held = await signIn([...proxy, ...browser()]);
    assert.equal(held.status, 429);
    assert.equal(held.json.code, 'locked');
  }
  assert.equal(loginThrottle.globalLocked(), false);
  // The owner, over ssh -L 4317:127.0.0.1:4317 at http://localhost:4317: signed in.
  const tunnel = await signIn([`Host: localhost:${port}`, ...browser(`http://localhost:${port}`)]);
  assert.equal(tunnel.status, 200);
  assert.equal(tunnel.json.transport.kind, 'loopback');
  assert.ok(
    warnings.some(line =>
      line.startsWith(
        'Requests from the trusted proxy 127.0.0.1 do not name their client in X-Forwarded-For'
      )
    )
  );
});

// A proxy on this host that sends no forwarding headers at all and keeps a loopback Host
// (nginx's default 127.0.0.1:<port>, or the client's own Host passed on with $http_host): its
// requests cannot be told from the Uptime Goblin host's own (§16 C1), whatever Origin they carry (a
// script's or a scanner's Authorization without one, a forged loopback page address, or the
// proxy's own page). They get the ssh tunnel's lockout key and are not held by the global lock,
// as the docs now say; the journal names such a proxy once a request shows it, and a restart is
// the documented way back in.
test('O15: through a proxy that sends no forwarding headers, a remote client can lock the ssh tunnel; the journal names the proxy', async t => {
  let now = Date.UTC(2026, 9, 1, 8);
  const tunnelOf = port => [`Host: localhost:${port}`, ...browser(`http://localhost:${port}`)];
  for (const [what, attack] of [
    [
      'a scanner’s Basic without an Origin',
      (port, i) => [
        'GET /api/dashboard',
        [
          `Host: 127.0.0.1:${port}`,
          `Authorization: Basic ${Buffer.from(`root:toor${i}`).toString('base64')}`,
        ],
      ],
    ],
    [
      'a Bearer token without an Origin',
      port => [
        'GET /api/dashboard',
        [`Host: 127.0.0.1:${port}`, 'Authorization: Bearer scanner-token'],
      ],
    ],
    [
      'a sign-in from a forged loopback page',
      port => [
        'POST /api/auth/login',
        [`Host: 127.0.0.1:${port}`, ...browser(`http://127.0.0.1:${port}`)],
      ],
    ],
    [
      'Basic with the Host the client chose (a proxy forwarding $http_host)',
      (port, i) => [
        'GET /api/dashboard',
        [`Host: localhost:${port}`, `Authorization: ${basic(`guess ${i}`)}`],
      ],
    ],
  ]) {
    const loginThrottle = new LoginThrottle({ now: () => now });
    const { signIn, port } = await owner(t, { loginThrottle });
    // The attacker waits out each lockout and fails again, until it lasts 15 minutes.
    for (let i = 0; i < 20; i++) {
      now += loginThrottle.retryAfter('loopback');
      const [request, lines] = attack(port, i);
      const answer = await raw(
        port,
        [`${request} HTTP/1.1`, ...lines],
        request.startsWith('POST') ? JSON.stringify({ login: 'admin', password: `guess ${i}` }) : ''
      );
      assert.equal(answer.status, 401, `${what} ${i}`);
    }
    assert.equal(loginThrottle.retryAfter('loopback'), 15 * 60e3, what);
    assert.equal(loginThrottle.retryAfter('127.0.0.1'), 0, what);
    now += 60e3;
    // The owner's tunnel, with the right password, is locked out with them.
    const tunnel = await signIn(tunnelOf(port));
    assert.equal(tunnel.status, 429, what);
    assert.equal(tunnel.json.code, 'locked');
    // The documented way back: the lock is in memory, so a restart ends it; sign in at once.
    const restarted = await owner(t, { loginThrottle: new LoginThrottle({ now: () => now }) });
    assert.equal((await restarted.signIn(tunnelOf(restarted.port))).status, 200, what);
  }

  // Not held by the global lock either: while it holds, a wrong password from the proxy's own
  // page is still checked, as is the forged loopback page's: the Origin chooses no key (O16).
  const loginThrottle = new LoginThrottle({ now: () => now });
  const attacked = await owner(t, { loginThrottle, insecureHttpSessions: true });
  for (let i = 0; i < 50; i++)
    await attacked.signIn(
      [...nginx({ proto: 'https', client: `198.51.100.${i + 1}` }), ...browser()],
      JSON.stringify({ login: 'admin', password: `guess ${i}` })
    );
  assert.equal(loginThrottle.globalLocked(), true);
  const host = `127.0.0.1:${attacked.port}`;
  const page = await attacked.signIn(
    [`Host: ${host}`, ...browser()],
    JSON.stringify({ login: 'admin', password: 'a guess from the page' })
  );
  assert.deepEqual([page.status, page.json.code], [401, 'invalid_credentials']);
  const forged = await attacked.signIn(
    [`Host: ${host}`, ...browser(`http://${host}`)],
    JSON.stringify({ login: 'admin', password: 'one more guess' })
  );
  assert.deepEqual([forged.status, forged.json.code], [401, 'invalid_credentials']);

  // The journal names such a proxy once a request shows one: a page served under an allowed
  // name through nginx's default Host (above), or the allowed name as the Host, once an hour.
  assert.deepEqual(attacked.headerlessLines(), [
    `A reverse proxy on this computer sends Uptime Goblin requests without any forwarding header (seen: a request from 127.0.0.1 for Host ${host} from a page at https://goblin.example). Uptime Goblin cannot tell its clients from this computer's own browsers and scripts whenever they keep a loopback Host, so they share the ssh tunnel's sign-in lockout (failed sign-ins through the proxy can lock out the tunnel) and are not held by the global sign-in lock. Make the proxy send X-Forwarded-For and X-Forwarded-Proto (nginx: proxy_set_header X-Forwarded-For $remote_addr; proxy_set_header X-Forwarded-Proto $scheme;) with GOBLIN_TRUST_PROXY=loopback. If the tunnel is locked out meanwhile, restart Uptime Goblin and sign in through the tunnel at once.`,
  ]);
  const forwarded = await owner(t);
  for (let i = 0; i < 3; i++) await forwarded.get('/api/session', ['Host: goblin.example']);
  assert.equal(forwarded.headerlessLines().length, 1);
  assert.match(
    forwarded.headerlessLines()[0],
    /\(seen: a request from 127\.0\.0\.1 for Host goblin\.example\)/
  );
  // Neither the tunnel itself, a proxy that sends forwarding headers, nor another site's page
  // that a browser on this computer was made to send (an Origin that is no Uptime Goblin name) is one.
  const quiet = await owner(t);
  await quiet.signIn(tunnelOf(quiet.port));
  await quiet.signIn([...nginx({ proto: 'https' }), ...browser()]);
  await quiet.signIn([`Host: 127.0.0.1:${quiet.port}`, ...browser('https://evil.test')]);
  await quiet.get('/api/session', [`Host: 127.0.0.1:${quiet.port}`, `Authorization: ${basic()}`]);
  assert.deepEqual(quiet.headerlessLines(), []);
});

// The lockout key comes from the connection (the peer and the transport) and a trusted proxy's
// forwarding headers, never from a header the client chooses. Through a proxy on this host,
// trusted or not, that sends no forwarding headers and keeps a loopback Host, a remote script's
// guesses count against the ssh tunnel's key whatever Origin it sends, so it cannot pick a
// second key (the proxy's address) to double its guesses. Untrusted, every request from this
// computer has that one key (O17). And no Origin gives the tunnel's exemption from the global
// lock to a request that is not the loopback transport.
test('O16: the Origin never chooses the lockout key; only the loopback transport gives the tunnel’s exemption', async t => {
  const peer = { remoteAddress: '127.0.0.1' };
  for (const origin of [undefined, 'http://127.0.0.1:4317', 'https://goblin.example', 'null'])
    assert.equal(
      requestClient({ headers: { origin }, socket: peer }, { kind: 'loopback' }),
      loopbackClient,
      String(origin)
    );
  // A loopback peer that GOBLIN_TRUST_PROXY does not name (none, or another proxy): the tunnel's
  // key on the http transport too, whatever its Host, Origin or forwarding headers say.
  for (const headers of [
    { host: 'goblin.example' },
    { host: 'localhost:4317', origin: 'http://localhost:4317' },
    { host: 'localhost:4317', 'x-real-ip': '203.0.113.5' },
    { host: 'localhost:4317', forwarded: 'for=203.0.113.6;proto=https' },
    { host: 'goblin.example', 'x-forwarded-for': '203.0.113.7' },
  ])
    for (const trusted of [null, trustedProxies('192.0.2.1')])
      for (const remoteAddress of ['127.0.0.1', '::1', '::ffff:127.0.0.2'])
        assert.equal(
          requestClient({ headers, socket: { remoteAddress } }, { kind: 'http' }, trusted),
          loopbackClient,
          `${remoteAddress} ${JSON.stringify(headers)}`
        );
  // A trusted proxy on this host (GOBLIN_TRUST_PROXY=loopback): its forwarding headers, as for any
  // trusted proxy, else its own address; the Origin plays no part.
  const loopbackProxy = trustedProxies('loopback');
  for (const origin of [undefined, 'http://localhost:4317'])
    assert.equal(
      requestClient({ headers: { origin }, socket: peer }, { kind: 'http' }, loopbackProxy),
      '127.0.0.1',
      String(origin)
    );
  assert.equal(
    requestClient(
      { headers: { 'x-forwarded-for': '203.0.113.7' }, socket: peer },
      { kind: 'http' },
      loopbackProxy
    ),
    '203.0.113.7'
  );
  // Any other peer: its own address, whatever it sends.
  assert.equal(
    requestClient(
      {
        headers: { host: 'localhost:4317', 'x-forwarded-for': '127.0.0.1' },
        socket: { remoteAddress: '198.51.100.4' },
      },
      { kind: 'http' }
    ),
    '198.51.100.4'
  );

  const now = Date.UTC(2026, 9, 1, 8);
  const loginThrottle = new LoginThrottle({ now: () => now });
  const { port } = await owner(t, { loginThrottle });
  const host = `127.0.0.1:${port}`;
  const origins = [null, `http://${host}`, 'https://goblin.example', 'https://evil.example'];
  for (const [i, origin] of [...origins, ...origins].entries()) {
    const answer = await raw(port, [
      'GET /api/dashboard HTTP/1.1',
      `Host: ${host}`,
      ...(origin ? [`Origin: ${origin}`] : []),
      `Authorization: ${basic(`guess ${i}`)}`,
    ]);
    assert.equal(answer.status, i < 6 ? 401 : 429, `${origin} ${i}`);
  }
  // Eight guesses, one key: locked out once the five free ones were used, whatever the Origin
  // said.
  assert.equal(loginThrottle.size, 1);
  assert.ok(loginThrottle.retryAfter('loopback') > 0);
  assert.equal(loginThrottle.retryAfter('127.0.0.1'), 0);

  // During a guessing attack, a loopback Origin does not lift the global lock for a request
  // that is not the loopback transport: a forwarded Host, or forwarding headers.
  const locked = new LoginThrottle({ now: () => now });
  // Plain-HTTP Basic allowed, so the forwarded Host's request is checked at all (D16).
  const attacked = await owner(t, { loginThrottle: locked, insecureHttpSessions: true });
  for (let i = 0; i < 50; i++)
    await attacked.signIn(
      [...nginx({ proto: 'https', client: `198.51.100.${i + 1}` }), ...browser()],
      JSON.stringify({ login: 'admin', password: `guess ${i}` })
    );
  assert.equal(locked.globalLocked(), true);
  const own = `localhost:${attacked.port}`;
  for (const lines of [
    ['Host: goblin.example', `Origin: http://${own}`],
    [...nginx({ proto: 'https', host: own, client: '203.0.113.7' }), `Origin: http://${own}`],
  ]) {
    const held = await attacked.get('/api/dashboard', [...lines, `Authorization: ${basic()}`]);
    assert.deepEqual([held.status, held.json.code], [429, 'locked'], lines.join(' '));
  }
  // The tunnel itself, with or without an Origin, is not held.
  for (const origin of [[], [`Origin: http://${own}`]])
    assert.equal(
      (
        await attacked.get('/api/dashboard', [
          `Host: ${own}`,
          ...origin,
          `Authorization: ${basic()}`,
        ])
      ).status,
      200
    );
});

// Without GOBLIN_TRUST_PROXY, Uptime Goblin believes nothing a proxy on this host says about its clients:
// every request from a loopback address that no trusted proxy relays counts against one lockout,
// the ssh tunnel's (`loopback`), whatever its Host or forwarding headers say. A remote client
// relayed by such a proxy cannot reach a second lockout (twice the guesses) by asking for
// another Host or adding X-Real-IP, Forwarded or X-Forwarded-For. Its sessions and audit rows
// show that key too. Only the loopback transport is exempt from the global lock: the trust a
// sign-in through the tunnel gives the key never lets the others through. A trusted proxy keeps
// its clients' own keys.
test('O17: untrusted, everything from a loopback address counts against one lockout, whatever its Host or forwarding headers; a trusted proxy keeps per-client keys', async t => {
  let now = Date.UTC(2026, 9, 1, 8);
  const loginThrottle = new LoginThrottle({ now: () => now });
  // Plain-HTTP sign-in and Basic allowed, so the `http` transport's requests are checked at all.
  const { port, get, signIn } = await owner(t, {
    trustProxy: '',
    loginThrottle,
    insecureHttpSessions: true,
  });
  const own = `localhost:${port}`;
  const ways = [
    ['Host: localhost', [`Host: ${own}`]],
    ['a non-loopback allowed Host', ['Host: goblin.example']],
    ['an added X-Real-IP', [`Host: ${own}`, 'X-Real-IP: 203.0.113.5']],
    ['an added Forwarded', [`Host: ${own}`, 'Forwarded: for=203.0.113.6;proto=https']],
    ['an added X-Forwarded-For', ['Host: goblin.example', 'X-Forwarded-For: 203.0.113.7']],
  ];
  // The five free guesses spread over the ways in, and a sixth: one key, locked.
  for (const [i, [what, lines]] of [...ways, ways[1]].entries()) {
    const answer = await get('/api/dashboard', [...lines, `Authorization: ${basic(`guess ${i}`)}`]);
    assert.deepEqual([answer.status, answer.json.code], [401, 'invalid_credentials'], what);
  }
  assert.equal(loginThrottle.size, 1);
  assert.ok(loginThrottle.retryAfter(loopbackClient) > 0);
  assert.equal(loginThrottle.retryAfter('127.0.0.1'), 0);
  // The lockout reached is in force whichever way comes next, the right password included.
  for (const [what, lines] of ways) {
    const held = await get('/api/dashboard', [...lines, `Authorization: ${basic()}`]);
    assert.deepEqual([held.status, held.json.code], [429, 'locked'], what);
  }
  const page = await signIn(['Host: goblin.example', ...browser('http://goblin.example')]);
  assert.deepEqual([page.status, page.json.code], [429, 'locked'], 'a sign-in from the page');
  // Once the lockout is over, a sign-in through the proxy's own name records the same key: the
  // sessions list and the audit entry show `loopback`.
  now += loginThrottle.retryAfter(loopbackClient);
  const signedIn = await signIn(['Host: goblin.example', ...browser('http://goblin.example')]);
  assert.equal(signedIn.status, 200);
  const session = ['Host: goblin.example', `Cookie: ${cookieFrom(signedIn)}`];
  const listed = await get('/api/account/sessions', session);
  assert.equal(listed.status, 200);
  assert.deepEqual(
    listed.json.sessions.map(entry => entry.client),
    [loopbackClient]
  );
  const audit = await get('/api/audit', session);
  assert.equal(audit.status, 200);
  const login = audit.json.entries.find(entry => entry.action === 'session.login');
  assert.equal(login.actor.client, loopbackClient);

  // The global lock: only the loopback transport is exempt. The tunnel signs in, so the
  // `loopback` key proved the password; the proxy's clients still wait, whatever they send.
  const locked = new LoginThrottle({ now: () => now });
  const attacked = await owner(t, {
    trustProxy: '',
    loginThrottle: locked,
    insecureHttpSessions: true,
  });
  const tunnelHost = `localhost:${attacked.port}`;
  const tunnel = [`Host: ${tunnelHost}`, ...browser(`http://${tunnelHost}`)];
  assert.equal((await attacked.signIn(tunnel)).status, 200);
  assert.equal(locked.trusted(loopbackClient), true);
  for (let i = 0; i < 50; i++) locked.failure(`198.51.100.${i + 1}`);
  assert.equal(locked.globalLocked(), true);
  for (const lines of [
    ['Host: goblin.example'],
    [`Host: ${tunnelHost}`, 'X-Real-IP: 203.0.113.5'],
    [`Host: ${tunnelHost}`, 'Forwarded: for=203.0.113.6'],
  ]) {
    const held = await attacked.get('/api/dashboard', [...lines, `Authorization: ${basic()}`]);
    assert.deepEqual([held.status, held.json.code], [429, 'locked'], lines.join(' '));
  }
  const page2 = await attacked.signIn([
    'Host: goblin.example',
    ...browser('http://goblin.example'),
  ]);
  assert.deepEqual([page2.status, page2.json.code], [429, 'locked']);
  // The tunnel itself is not held.
  assert.equal(
    (await attacked.get('/api/dashboard', [`Host: ${tunnelHost}`, `Authorization: ${basic()}`]))
      .status,
    200
  );
  assert.equal((await attacked.signIn(tunnel)).status, 200);

  // A proxy on this host that GOBLIN_TRUST_PROXY names: its forwarding headers give each client
  // its own key, and the tunnel keeps its own.
  const perClient = new LoginThrottle({ now: () => now });
  const trusted = await owner(t, { loginThrottle: perClient, insecureHttpSessions: true });
  const proxied = client => nginx({ proto: 'https', client });
  for (let i = 0; i < 6; i++) {
    const wrong = await trusted.get('/api/dashboard', [
      ...proxied('198.51.100.1'),
      `Authorization: ${basic(`guess ${i}`)}`,
    ]);
    assert.equal(wrong.status, 401);
  }
  assert.ok(perClient.retryAfter('198.51.100.1') > 0);
  assert.equal(
    (await trusted.get('/api/dashboard', [...proxied('198.51.100.1'), `Authorization: ${basic()}`]))
      .status,
    429
  );
  assert.equal(
    (await trusted.get('/api/dashboard', [...proxied('198.51.100.2'), `Authorization: ${basic()}`]))
      .status,
    200
  );
  const trustedTunnel = `localhost:${trusted.port}`;
  assert.equal(
    (await trusted.get('/api/dashboard', [`Host: ${trustedTunnel}`, `Authorization: ${basic()}`]))
      .status,
    200
  );
  assert.equal(perClient.retryAfter(loopbackClient), 0);
  assert.equal(perClient.size, 1);
});
