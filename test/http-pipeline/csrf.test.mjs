// The CSRF gate (sessions spec §6.7): a session cookie is sent by the browser on its own, so a
// write made with one, and a sign-in, must prove it comes from Uptime Goblin's own page.
import test from 'node:test';
import assert from 'node:assert/strict';
import { basic, browserWrite, cookieFrom, login, password, raw, serveAuth } from './harness.mjs';
import { strictCrossOrigin } from '../../lib/http/pipeline.mjs';

const refusedBody = { error: 'Cross-origin changes are not allowed', code: 'cross_origin' };

test('a session write needs X-Goblin-Request, an Origin naming this host, same-origin fetch and JSON', async t => {
  const { port, identity, loginThrottle } = await serveAuth(t);
  const { cookie } = await login(port);
  assert.ok(cookie);
  const self = `http://127.0.0.1:${port}`;
  const post = (lines, body = '{"a":1}') =>
    raw(port, ['POST /api/thing HTTP/1.1', `Cookie: ${cookie}`, ...lines], body);
  const good = [
    'X-Goblin-Request: 1',
    'Content-Type: application/json',
    `Origin: ${self}`,
    'Sec-Fetch-Site: same-origin',
  ];
  const without = name => good.filter(line => !line.startsWith(name));
  assert.equal((await post(good)).status, 200);
  // Sec-Fetch-Site may be absent (older browsers); Origin may not.
  assert.equal((await post(without('Sec-Fetch-Site'))).status, 200);
  for (const [name, lines] of [
    ['no X-Goblin-Request', without('X-Goblin-Request')],
    ['X-Goblin-Request other than 1', [...without('X-Goblin-Request'), 'X-Goblin-Request: yes']],
    ['no Origin', without('Origin')],
    ['a foreign Origin', [...without('Origin'), 'Origin: http://evil.test']],
    ['another port', [...without('Origin'), 'Origin: http://127.0.0.1:1']],
    [
      'an https Origin of this host name',
      [...without('Origin'), `Origin: https://127.0.0.1:${port}`],
    ],
    ['Origin null', [...without('Origin'), 'Origin: null']],
    ['cross-site', [...without('Sec-Fetch-Site'), 'Sec-Fetch-Site: cross-site']],
    ['same-site', [...without('Sec-Fetch-Site'), 'Sec-Fetch-Site: same-site']],
    ['none', [...without('Sec-Fetch-Site'), 'Sec-Fetch-Site: none']],
  ]) {
    const answer = await post(lines);
    // The https-Origin case differs from Host only by scheme: the host matches, so it passes
    // the host rule (the transport rule, not CSRF, judges schemes on sign-in).
    if (name === 'an https Origin of this host name') {
      assert.equal(answer.status, 200, name);
      continue;
    }
    assert.equal(answer.status, 403, name);
    assert.deepEqual(answer.json, refusedBody, name);
  }
  const text = await post(without('Content-Type'));
  assert.equal(text.status, 415);
  assert.equal((await post([...without('Content-Type'), 'Content-Type: text/plain'])).status, 415);
  // Refusals are not guesses.
  assert.equal(loginThrottle.size, 0);
  assert.equal(identity.test.rows().length, 1, 'the session is untouched');
});

test('an Origin naming a GOBLIN_ALLOWED_HOSTS entry passes although Host differs (D20)', async t => {
  const { port } = await serveAuth(t, {
    configuredHosts: ['Goblin.Example'],
    trustProxy: 'loopback',
  });
  // nginx's default Host: $proxy_host is 127.0.0.1:<port>, while the browser is at goblin.example.
  const proxy = ['X-Forwarded-For: 198.51.100.20', 'X-Forwarded-Proto: https'];
  const signedIn = await raw(
    port,
    [
      'POST /api/auth/login HTTP/1.1',
      ...proxy,
      'X-Goblin-Request: 1',
      'Content-Type: application/json',
      'Origin: https://goblin.example',
      'Sec-Fetch-Site: same-origin',
    ],
    JSON.stringify({ login: 'admin', password })
  );
  assert.equal(signedIn.status, 200, signedIn.body);
  const cookie = cookieFrom(signedIn);
  const write = origin =>
    raw(
      port,
      [
        'POST /api/thing HTTP/1.1',
        ...proxy,
        `Cookie: ${cookie}`,
        'X-Goblin-Request: 1',
        'Content-Type: application/json',
        `Origin: ${origin}`,
      ],
      '{}'
    );
  assert.equal((await write('http://goblin.example')).status, 200);
  assert.equal((await write('https://GOBLIN.example')).status, 200);
  assert.equal(
    (await write('https://goblin.example:8443')).status,
    403,
    'another port is another host'
  );
  assert.equal((await write('https://evil.example')).status, 403);
  // The implicit loopback names are not allowlist entries for this rule.
  assert.equal((await write('http://localhost')).status, 403);
});

test('sign-in is held to the same rule (login CSRF), and a host mismatch is logged once', async t => {
  const { port, identity, logged } = await serveAuth(t);
  const body = JSON.stringify({ login: 'admin', password: 'wrong-but-never-checked' });
  const attempt = lines => raw(port, ['POST /api/auth/login HTTP/1.1', ...lines], body);
  const self = `http://127.0.0.1:${port}`;
  const cases = {
    'no X-Goblin-Request': ['Content-Type: application/json', `Origin: ${self}`],
    'no Origin': ['X-Goblin-Request: 1', 'Content-Type: application/json'],
    'foreign Origin': [
      'X-Goblin-Request: 1',
      'Content-Type: application/json',
      'Origin: https://evil.test',
    ],
    'cross-site': [
      'X-Goblin-Request: 1',
      'Content-Type: application/json',
      `Origin: ${self}`,
      'Sec-Fetch-Site: cross-site',
    ],
  };
  for (const [name, lines] of Object.entries(cases)) {
    const answer = await attempt(lines);
    assert.equal(answer.status, 403, name);
    assert.deepEqual(answer.json, refusedBody, name);
    assert.equal(answer.headers['set-cookie'], undefined, name);
  }
  const form = await attempt([
    'X-Goblin-Request: 1',
    `Origin: ${self}`,
    'Content-Type: application/x-www-form-urlencoded',
  ]);
  assert.equal(form.status, 415);
  assert.equal(identity.test.checks, 0, 'no password was checked');
  // Only the host mismatch names the proxy fix, and only once an hour.
  await attempt(cases['foreign Origin']);
  assert.deepEqual(logged, [
    "Sign-in refused: the browser's address https://evil.test does not match the Host header 127.0.0.1:" +
      port +
      ', and evil.test is not in GOBLIN_ALLOWED_HOSTS. Make the reverse proxy forward the Host header (nginx: proxy_set_header Host $http_host;) or add evil.test to GOBLIN_ALLOWED_HOSTS.',
  ]);
});

test('the log line strips control characters and long values from the request', async t => {
  const { port, logged } = await serveAuth(t);
  await raw(
    port,
    [
      'POST /api/auth/login HTTP/1.1',
      'X-Goblin-Request: 1',
      'Content-Type: application/json',
      `Origin: https://${'a'.repeat(300)}.example`,
    ],
    '{}'
  );
  assert.equal(logged.length, 1);
  assert.doesNotMatch(logged[0], /[\u0000-\u001f]/);
  assert.ok(!logged[0].includes('a'.repeat(201)), 'each value is cut to 200 characters');
});

test('Basic keeps the 1.4.3 rule; Sec-Fetch-Site makes a browser context; no credential, no write', async t => {
  const { port } = await serveAuth(t);
  const auth = `Authorization: ${basic()}`;
  const write = ['X-Goblin-Request: 1', 'Content-Type: application/json'];
  const post = lines => raw(port, ['POST /api/thing HTTP/1.1', auth, ...lines], '{}');
  // No Origin is fine for a script; a foreign one is not.
  assert.equal((await post(write)).status, 200);
  assert.equal((await post([...write, `Origin: http://127.0.0.1:${port}`])).status, 200);
  assert.equal((await post([...write, 'Origin: http://evil.test'])).status, 403);
  assert.equal((await post(['Content-Type: application/json'])).status, 403);
  // With Sec-Fetch-Site the Basic header is ignored: signed out, not a CSRF refusal.
  const browser = await post([...write, 'Sec-Fetch-Site: cross-site']);
  assert.equal(browser.status, 401);
  assert.equal(browser.json.code, 'signin_required');
  // Without a credential nothing is written, from any page or none (1.4.x's passwordless local
  // preview took these writes from this computer; Uptime Goblin no longer runs without a password).
  const bare = lines => raw(port, ['POST /api/thing HTTP/1.1', ...lines], '{}');
  for (const lines of [
    write,
    [...write, 'Sec-Fetch-Site: same-site'],
    [...write, 'Sec-Fetch-Site: same-origin', `Origin: http://127.0.0.1:${port}`],
    [...write, 'Sec-Fetch-Site: cross-site'],
  ]) {
    const answer = await bare(lines);
    assert.equal(answer.status, 401, lines.join(' / '));
    assert.equal(answer.json.code, 'signin_required');
  }
});

test('no answer carries an Access-Control-* header, OPTIONS and preflights included', async t => {
  const { port } = await serveAuth(t);
  const { cookie } = await login(port);
  const preflight = [
    'Origin: https://evil.test',
    'Access-Control-Request-Method: POST',
    'Access-Control-Request-Headers: x-goblin-request, content-type',
  ];
  const answers = [
    await raw(port, ['OPTIONS /api/thing HTTP/1.1', ...preflight]),
    await raw(port, ['OPTIONS /api/auth/login HTTP/1.1', ...preflight]),
    await raw(port, ['OPTIONS /api/thing HTTP/1.1', `Cookie: ${cookie}`, ...preflight]),
    await raw(port, ['GET /api/thing HTTP/1.1', `Cookie: ${cookie}`, 'Origin: https://evil.test']),
    await raw(port, ['GET /api/session HTTP/1.1', `Cookie: ${cookie}`]),
    await raw(port, ['POST /api/auth/login HTTP/1.1', ...browserWrite('https://evil.test')], '{}'),
    await raw(port, [
      'OPTIONS /api/thing HTTP/1.1',
      `Cookie: ${cookie}`,
      ...browserWrite(`http://127.0.0.1:${port}`),
    ]),
  ];
  for (const answer of answers)
    for (const name of Object.keys(answer.headers))
      assert.doesNotMatch(name, /^access-control-/i, `${answer.status} ${name}`);
  assert.deepEqual(
    answers.map(answer => answer.status),
    // OPTIONS is no route of Uptime Goblin's: signed out it is 401 (sign-in comes first, the login
    // path included), with a foreign Origin a CSRF refusal, from Uptime Goblin's page a 405.
    [401, 401, 403, 200, 200, 403, 405]
  );
});

test('strictCrossOrigin names why a write was refused', () => {
  const request = headers => ({ headers: { host: 'goblin.example', ...headers } });
  const good = { 'x-goblin-request': '1', origin: 'https://goblin.example' };
  assert.equal(strictCrossOrigin(request(good)), null);
  assert.equal(
    strictCrossOrigin(request({ ...good, 'x-goblin-request': undefined })),
    'request-header'
  );
  assert.equal(strictCrossOrigin(request({ ...good, origin: undefined })), 'origin-missing');
  assert.equal(strictCrossOrigin(request({ ...good, origin: 'garbage' })), 'origin-missing');
  assert.equal(strictCrossOrigin(request({ ...good, origin: 'https://x.test' })), 'origin-host');
  assert.equal(
    strictCrossOrigin(request({ ...good, origin: 'https://x.test' }), new Set(['x.test'])),
    null
  );
  assert.equal(
    strictCrossOrigin(request({ ...good, 'sec-fetch-site': 'same-site' })),
    'fetch-site'
  );
  assert.equal(strictCrossOrigin({ headers: { ...good } }), 'origin-host', 'no Host at all');
});
