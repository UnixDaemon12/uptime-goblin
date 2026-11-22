import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { LoginThrottle, trustedProxies } from '../../lib/throttle.mjs';
import { createRouter } from '../../lib/http/router.mjs';
import {
  routeTable,
  reservedPaths,
  supportedAuth,
  supportedFeatures,
} from '../../lib/http/routes.mjs';
import { json } from '../../lib/http/body.mjs';
import { BusyError } from '../../lib/http/exclusive.mjs';
import { identityError } from '../../lib/identity/errors.mjs';
import {
  createPipeline,
  fail,
  presentedCredentials,
  requestId,
  requestIdPattern,
} from '../../lib/http/pipeline.mjs';
import { readCookies } from '../../lib/http/cookies.mjs';
import { fakeIdentity } from '../helpers/fake-identity.mjs';

const password = 'fixture-pipeline-password';
const basic = (value = password) => 'Basic ' + Buffer.from('admin:' + value).toString('base64');
const build = 'b1b1b1b1b1b1';

/**
 * Sends one request whose headers are given as lines, in order and possibly repeated (which
 * fetch() cannot do); resolves to {status, headers, body}. The Host is 127.0.0.1:<port> unless
 * a line sets it.
 */
function raw(port, lines, body = '') {
  const [method, target] = lines[0].split(' ');
  const hostLine = lines.slice(1).some(line => /^host:/i.test(line));
  const headers = [...(hostLine ? [] : ['Host', `127.0.0.1:${port}`]), 'Connection', 'close'];
  for (const line of lines.slice(1)) {
    const at = line.indexOf(':');
    headers.push(line.slice(0, at), line.slice(at + 1).trim());
  }
  if (body) headers.push('Content-Length', String(Buffer.byteLength(body)));
  return new Promise((resolve, reject) => {
    const request = http.request(
      { host: '127.0.0.1', port, method, path: target, headers, agent: false },
      response => {
        let text = '';
        response.setEncoding('utf8');
        response.on('data', chunk => (text += chunk));
        response.on('end', () =>
          resolve({ status: response.statusCode, headers: response.headers, body: text })
        );
      }
    );
    request.on('error', reject);
    request.end(body || undefined);
  });
}

// `peer`, when given, is the address the pipeline sees as the connection's (socket.remoteAddress)
// in place of the test's own loopback one: a client on another host, without leaving loopback.
async function serve(
  t,
  { routes, identity = fakeIdentity({ password }), legacyBasic = true, log, peer, ...options }
) {
  const loginThrottle = options.loginThrottle ?? new LoginThrottle();
  let closed = false;
  const logged = [];
  const handle = createPipeline({
    router: createRouter(routes, { reserved: ['/api/*'], auth: ['public', 'session'] }),
    identity,
    loginThrottle,
    release: { build, version: '9.9.9' },
    allowedHost: host => /^127\.0\.0\.1:\d+$/.test(host ?? '') || host === 'goblin.example',
    isClosed: () => closed,
    legacyBasic,
    log: log ?? { warn: line => logged.push(line), error: line => logged.push(line) },
    ...options,
  });
  const server = http.createServer(
    peer === undefined
      ? handle
      : (req, res) => {
          Object.defineProperty(req.socket, 'remoteAddress', { value: peer, configurable: true });
          return handle(req, res);
        }
  );
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  return {
    port: server.address().port,
    identity,
    loginThrottle,
    logged,
    stop: () => (closed = true),
  };
}

/** Signs in through the fake on loopback and returns the loopback Cookie line and the issue. */
async function session(identity, options = {}) {
  const { issue, access } = await identity.login({
    login: 'admin',
    password,
    transport: 'loopback',
    ...options,
  });
  return { cookie: `Cookie: goblin_session=${issue.value}`, issue, access };
}

const table = extra => [
  {
    method: 'GET',
    path: '/health',
    head: true,
    auth: 'public',
    permission: null,
    summary: 'health',
    handler: ({ res }) => json(res, 200, { status: 'ok' }),
  },
  {
    method: 'GET',
    path: '/api/thing',
    auth: 'session',
    permission: 'dashboard:read',
    summary: 'read',
    handler: ({ res, requestId: id, access }) => json(res, 200, { ok: true, id, via: access.via }),
  },
  {
    method: 'POST',
    path: '/api/thing',
    auth: 'session',
    permission: 'sources:write',
    summary: 'write',
    bodyLimit: 64,
    handler: async ({ res, body }) => json(res, 200, { received: await body() }),
  },
  {
    method: 'POST',
    path: '/api/once',
    auth: 'session',
    permission: 'account:self',
    idempotent: false,
    summary: 'never replayed',
    handler: ({ res }) => json(res, 200, { ok: true }),
  },
  {
    method: 'GET',
    path: '/*',
    head: true,
    auth: 'session',
    permission: 'dashboard:read',
    summary: 'files',
    handler: ({ res }) => {
      res.writeHead(404);
      res.end('Not found');
    },
  },
  ...(extra ?? []),
];
const write = ['X-Goblin-Request: 1', 'Content-Type: application/json'];
const browser = ['Sec-Fetch-Site: same-origin', 'X-Goblin-Client: web/test'];
const origin = port => `Origin: http://127.0.0.1:${port}`;
const transport = (kind, insecureAllowed = false) => ({ kind, insecureAllowed });

test('a request presenting two credentials is refused, not decided by header order (X1)', async t => {
  const { port, identity, loginThrottle } = await serve(t, { routes: table() });
  const signed = await raw(port, ['GET /api/thing HTTP/1.1', `Authorization: ${basic()}`]);
  assert.equal(signed.status, 200);
  const checks = identity.test.checks;
  const { cookie } = await session(identity);
  const pairs = [
    [basic(), basic()],
    [basic(), basic('wrong')],
    [basic(), 'Bearer token-value'],
  ];
  for (const [first, second] of pairs)
    for (let i = 0; i < 8; i++) {
      const both = await raw(port, [
        'GET /api/thing HTTP/1.1',
        `Authorization: ${first}`,
        `Authorization: ${second}`,
      ]);
      assert.equal(both.status, 401, second);
      assert.deepEqual(JSON.parse(both.body), {
        error: 'Send one credential per request.',
        code: 'multiple_credentials',
        transport: transport('loopback'),
      });
      // A script is challenged while legacy Basic is on; every answer names the build (D10),
      // only signed-in ones the version.
      assert.match(both.headers['www-authenticate'], /^Basic /);
      assert.equal(both.headers['x-goblin-build'], build);
      assert.equal(both.headers['x-goblin-version'], undefined);
    }
  // A script's Basic header and a session cookie are two credentials too.
  const mixed = await raw(port, ['GET /api/thing HTTP/1.1', `Authorization: ${basic()}`, cookie]);
  assert.equal(mixed.status, 401);
  assert.equal(JSON.parse(mixed.body).code, 'multiple_credentials');
  // Nothing was checked, so nothing counted towards the sign-in lockout.
  assert.equal(identity.test.checks, checks + 1, 'only the sign-in above ran a check');
  assert.equal(loginThrottle.retryAfter('127.0.0.1'), 0);
  assert.equal(
    (await raw(port, ['GET /api/thing HTTP/1.1', `Authorization: ${basic()}`])).status,
    200
  );
});

test('credential counting covers Authorization headers, the session cookie and forward-auth', () => {
  const request = (rawHeaders, extra = {}) => {
    const headersDistinct = {};
    for (let i = 0; i < rawHeaders.length; i += 2)
      (headersDistinct[rawHeaders[i].toLowerCase()] ??= []).push(rawHeaders[i + 1]);
    return {
      headersDistinct,
      headers: Object.fromEntries(Object.entries(headersDistinct).map(([k, v]) => [k, v[0]])),
      ...extra,
    };
  };
  const kinds = (req, options) => presentedCredentials(req, options).map(c => c.kind);
  const cookiesOf = req => readCookies(req.headersDistinct.cookie);
  assert.deepEqual(kinds(request([])), []);
  assert.deepEqual(kinds(request(['Authorization', basic()])), ['basic']);
  assert.deepEqual(kinds(request(['authorization', 'bearer abc'])), ['bearer']);
  assert.deepEqual(kinds(request(['Authorization', 'Digest x'])), ['authorization']);
  assert.deepEqual(kinds(request(['Authorization', basic(), 'Authorization', basic()])), [
    'basic',
    'basic',
  ]);
  const cookies = request(['Cookie', 'theme=dark; goblin_session=a', 'Cookie', 'goblin_session=b']);
  assert.deepEqual(kinds(cookies), [], 'no cookie is a credential without a cookie name');
  assert.deepEqual(kinds(cookies, { cookieName: 'goblin_session', cookies: cookiesOf(cookies) }), [
    'session',
    'session',
  ]);
  assert.deepEqual(
    kinds(cookies, { cookieName: '__Host-goblin_session', cookies: cookiesOf(cookies) }),
    [],
    'only this transport’s cookie name counts'
  );
  const both = request(['Cookie', 'theme=dark', 'Authorization', basic()]);
  assert.deepEqual(
    kinds(both, {
      cookieName: 'goblin_session',
      cookies: cookiesOf(both),
      forwardAuth: () => true,
    }),
    ['basic', 'forward']
  );
  // A browser context's Authorization header is ignored: neither evaluated nor counted (D12).
  const cached = request(['Authorization', basic(), 'Cookie', 'goblin_session=a']);
  assert.deepEqual(
    kinds(cached, { cookieName: 'goblin_session', cookies: cookiesOf(cached), browser: true }),
    ['session']
  );
  // Without headersDistinct (a plain object request), the one header still counts.
  assert.deepEqual(presentedCredentials({ headers: { authorization: basic() } }).length, 1);
});

test('the one-credential rule counts this transport’s session cookie, not a browser’s Basic', async t => {
  const { port, identity } = await serve(t, { routes: table() });
  const { cookie } = await session(identity);
  const answer = await raw(port, ['GET /api/thing HTTP/1.1', `Authorization: ${basic()}`, cookie]);
  assert.equal(answer.status, 401);
  assert.equal(
    (
      await raw(port, [
        'GET /api/thing HTTP/1.1',
        `Authorization: ${basic()}`,
        'Cookie: unrelated=1; __Host-goblin_session=other-transport',
      ])
    ).status,
    200
  );
  // A browser that cached 1.4.x Basic credentials and holds a session is signed in by the
  // session, not refused as presenting two credentials.
  for (const context of browser) {
    const signed = await raw(port, [
      'GET /api/thing HTTP/1.1',
      `Authorization: ${basic()}`,
      cookie,
      context,
    ]);
    assert.equal(signed.status, 200, context);
    assert.equal(JSON.parse(signed.body).via, 'session');
  }
});

test('every answer carries an X-Request-Id; only a trusted proxy’s well-formed id is kept', async t => {
  const untrusted = await serve(t, { routes: table() });
  const trusted = await serve(t, { routes: table(), trusted: () => true });
  const id = header => header?.['x-request-id'];
  const inbound = 'req-1.a_B';
  const answers = [
    await raw(untrusted.port, ['GET /api/thing HTTP/1.1', `Authorization: ${basic()}`]),
    await raw(untrusted.port, ['GET /api/thing HTTP/1.1']),
    await raw(untrusted.port, ['GET /health HTTP/1.1']),
    await raw(untrusted.port, ['GET /api/nothing HTTP/1.1', `Authorization: ${basic()}`]),
    await raw(untrusted.port, [
      'DELETE /api/thing HTTP/1.1',
      `Authorization: ${basic()}`,
      ...write,
    ]),
    await raw(untrusted.port, ['GET //[ HTTP/1.1']),
    await raw(untrusted.port, ['GET /api/thing HTTP/1.1', `X-Request-Id: ${inbound}`]),
  ];
  assert.deepEqual(
    answers.map(a => a.status),
    [200, 401, 200, 404, 405, 400, 401]
  );
  for (const answer of answers) assert.match(id(answer.headers), requestIdPattern);
  assert.notEqual(id(answers[6].headers), inbound, 'an untrusted peer’s id is replaced');
  assert.equal(
    JSON.parse(answers[0].body).id,
    id(answers[0].headers),
    'the handler sees the same id'
  );
  const kept = await raw(trusted.port, ['GET /api/thing HTTP/1.1', `X-Request-Id: ${inbound}`]);
  assert.equal(id(kept.headers), inbound);
  for (const bad of ['has space', 'x'.repeat(65), 'a,b', 'a/b', ''])
    assert.notEqual(
      id((await raw(trusted.port, ['GET /api/thing HTTP/1.1', `X-Request-Id: ${bad}`])).headers),
      bad,
      bad
    );
  const twice = await raw(trusted.port, [
    'GET /api/thing HTTP/1.1',
    'X-Request-Id: first',
    'X-Request-Id: second',
  ]);
  assert.ok(!['first', 'second'].includes(id(twice.headers)));
  // Also while stopping.
  untrusted.stop();
  const stopping = await raw(untrusted.port, ['GET /health HTTP/1.1']);
  assert.equal(stopping.status, 503);
  assert.match(id(stopping.headers), requestIdPattern);
  // Generated ids are unique.
  const ids = new Set(Array.from({ length: 50 }, () => requestId({ headers: {}, socket: {} })));
  assert.equal(ids.size, 50);
});

test('the pipeline keeps the 1.4.3 order: public routes, sign-in, CSRF, then 404/405', async t => {
  const { port, identity } = await serve(t, { routes: table() });
  const auth = `Authorization: ${basic()}`;
  const status = async lines => (await raw(port, lines)).status;
  // /health needs no sign-in with GET or HEAD; another method is signed in, CSRF-checked, 405.
  assert.equal(await status(['GET /health HTTP/1.1']), 200);
  assert.equal(await status(['HEAD /health HTTP/1.1']), 200);
  assert.equal(await status(['POST /health HTTP/1.1', ...write]), 401);
  assert.equal(await status(['POST /health HTTP/1.1', auth]), 403);
  const health = await raw(port, ['POST /health HTTP/1.1', auth, ...write, 'Content-Length: 0']);
  assert.equal(health.status, 405);
  assert.equal(health.headers.allow, 'GET, HEAD');
  assert.deepEqual(JSON.parse(health.body), { error: 'Method not allowed' });
  // An unknown API path is a JSON 404 even for writes, but only after the CSRF check.
  const refused = await raw(port, ['DELETE /api/nothing HTTP/1.1', auth]);
  assert.equal(refused.status, 403);
  assert.deepEqual(JSON.parse(refused.body), {
    error: 'Cross-origin changes are not allowed',
    code: 'cross_origin',
  });
  assert.equal(await status(['DELETE /api/nothing HTTP/1.1', auth, 'X-Goblin-Request: 1']), 415);
  const missing = await raw(port, ['DELETE /api/nothing HTTP/1.1', auth, ...write]);
  assert.equal(missing.status, 404);
  assert.deepEqual(JSON.parse(missing.body), { error: 'Route not found' });
  const wrong = await raw(port, ['PUT /api/thing HTTP/1.1', auth, ...write]);
  assert.equal(wrong.status, 405);
  assert.equal(wrong.headers.allow, 'GET, POST');
  assert.deepEqual(JSON.parse(wrong.body), { error: 'Use GET, POST for this route' });
  assert.equal(wrong.headers['x-goblin-build'], build);
  // Foreign origins are refused even with the header (1.4.3 rule for Basic).
  assert.equal(
    await status(['POST /api/thing HTTP/1.1', auth, ...write, 'Origin: http://evil.test']),
    403
  );
  // Sec-Fetch-Site makes the request a browser's, whose Basic header is ignored: it is not
  // signed in at all (was 403 in 1.4.3). The cross-site refusal itself holds for a session
  // cookie.
  const crossSite = await raw(port, [
    'POST /api/thing HTTP/1.1',
    auth,
    ...write,
    'Sec-Fetch-Site: cross-site',
  ]);
  assert.equal(crossSite.status, 401);
  assert.equal(crossSite.headers['www-authenticate'], undefined);
  const { cookie } = await session(identity);
  assert.equal(
    await status([
      'POST /api/thing HTTP/1.1',
      cookie,
      ...write,
      origin(port),
      'Sec-Fetch-Site: cross-site',
    ]),
    403
  );
  // Without a credential a write is not signed in, from any page (1.4.3's passwordless local
  // preview took it unless it came cross-site).
  for (const site of ['cross-site', 'same-site', 'same-origin'])
    assert.equal(
      await status(['POST /api/thing HTTP/1.1', ...write, `Sec-Fetch-Site: ${site}`]),
      401,
      site
    );
  // A Host outside the allowlist is refused before anything else, /health included.
  const foreign = await new Promise((resolve, reject) =>
    http
      .get({ host: '127.0.0.1', port, path: '/health', headers: { Host: 'evil.test' } }, resolve)
      .on('error', reject)
  );
  assert.equal(foreign.statusCode, 403);
  assert.equal(foreign.headers['x-goblin-build'], undefined, 'refused before the allowlist passed');
});

test('every answer after the Host allowlist names the build (401 and 403 too), except /health', async t => {
  const { port, identity } = await serve(t, {
    routes: table(),
    permitted: (access, permission) => permission !== 'sources:write',
  });
  const { cookie } = await session(identity);
  const answers = {
    public: await raw(port, ['GET /health HTTP/1.1']),
    // Under /health/ but not a route of this table: answered by the /* route (signed in here).
    healthOther: await raw(port, ['GET /health/nothing HTTP/1.1']),
    unsigned: await raw(port, ['GET /api/thing HTTP/1.1']),
    expired: await raw(port, [
      'GET /api/thing HTTP/1.1',
      `Cookie: goblin_session=v1.${'x'.repeat(43)}`,
    ]),
    csrf: await raw(port, ['POST /api/thing HTTP/1.1', cookie]),
    forbidden: await raw(port, ['POST /api/thing HTTP/1.1', cookie, ...write, origin(port)], '{}'),
    malformed: await raw(port, ['GET //[ HTTP/1.1']),
    signed: await raw(port, ['GET /api/thing HTTP/1.1', cookie]),
    missing: await raw(port, ['GET /api/nothing HTTP/1.1', cookie]),
  };
  assert.deepEqual(Object.fromEntries(Object.entries(answers).map(([k, v]) => [k, v.status])), {
    public: 200,
    healthOther: 401,
    unsigned: 401,
    expired: 401,
    csrf: 403,
    forbidden: 403,
    malformed: 400,
    signed: 200,
    missing: 404,
  });
  for (const [name, answer] of Object.entries(answers)) {
    const health = name.startsWith('public') || name.startsWith('health');
    assert.equal(answer.headers['x-goblin-build'], health ? undefined : build, name);
    assert.equal(
      answer.headers['x-goblin-version'],
      ['signed', 'missing', 'forbidden', 'csrf'].includes(name) ? '9.9.9' : undefined,
      name
    );
  }
  assert.deepEqual(JSON.parse(answers.forbidden.body), {
    error: 'You do not have permission to do this.',
    code: 'forbidden',
  });
  assert.deepEqual(JSON.parse(answers.expired.body), {
    error: 'Your session has ended. Sign in again.',
    code: 'session_expired',
    transport: transport('loopback'),
  });
  // A browser is never challenged (no native prompt), a script only while Basic is on.
  assert.equal(answers.expired.headers['www-authenticate'], 'Basic realm="Orbit", charset="UTF-8"');
  for (const context of browser)
    assert.equal(
      (await raw(port, ['GET /api/thing HTTP/1.1', context])).headers['www-authenticate'],
      undefined
    );
  const off = await serve(t, { routes: table(), legacyBasic: false });
  const noBasic = await raw(off.port, ['GET /api/thing HTTP/1.1']);
  assert.equal(noBasic.status, 401);
  assert.equal(noBasic.headers['www-authenticate'], undefined);
  assert.equal(JSON.parse(noBasic.body).code, 'signin_required');
});

test('bodies: route limits, prototype keys, and the credential re-check after the body', async t => {
  const identity = fakeIdentity({ password });
  const { port } = await serve(t, {
    identity,
    routes: table([
      {
        method: 'POST',
        path: '/api/rotating',
        auth: 'session',
        permission: 'settings:write',
        summary: 'the password changes while the body arrives',
        handler: async ({ res, body }) => {
          identity.test.setPassword('another-fixture-password');
          json(res, 200, await body());
        },
      },
    ]),
  });
  const post = body =>
    raw(port, ['POST /api/thing HTTP/1.1', `Authorization: ${basic()}`, ...write], body);
  assert.deepEqual(JSON.parse((await post('{"a":1}')).body), { received: { a: 1 } });
  // Over the route's limit: 413, before the body is read, and the connection is closed.
  const large = await post(JSON.stringify({ a: 'x'.repeat(100) }));
  assert.equal(large.status, 413);
  assert.match(JSON.parse(large.body).error, /too large/);
  assert.equal(large.headers.connection, 'close');
  // Only the shapes that reach a prototype are refused: __proto__, and prototype directly
  // inside constructor (body.test.mjs has the rule in detail).
  for (const text of ['{"__proto__":{"x":1}}', '{"a":[{"constructor":{"prototype":{}}}]}']) {
    const refused = await post(text);
    assert.equal(refused.status, 400, text);
    assert.match(
      JSON.parse(refused.body).error,
      /^Field name (__proto__|constructor\.prototype) is not allowed$/
    );
  }
  // On their own the names are ordinary data (Orbit 1.4.x saved them as metric labels).
  for (const text of ['{"a":[{"constructor":{}}]}', '{"prototype":1}']) {
    const accepted = await post(text);
    assert.equal(accepted.status, 200, text);
    assert.deepEqual(JSON.parse(accepted.body), { received: JSON.parse(text) });
  }
  const rotating = await raw(
    port,
    ['POST /api/rotating HTTP/1.1', `Authorization: ${basic()}`, ...write],
    '{"a":1}'
  );
  assert.equal(rotating.status, 401);
  assert.equal(JSON.parse(rotating.body).code, 'signin_required');
  assert.match(rotating.headers['www-authenticate'], /^Basic /);
  assert.equal(rotating.headers['x-goblin-version'], undefined, 'a refusal names no version');
});

test('permission is checked for matched routes, after CSRF; the default is the access’s permissions', async t => {
  const asked = [];
  const { port } = await serve(t, {
    routes: table(),
    permitted: (access, permission) => {
      asked.push(permission);
      return permission !== 'sources:write';
    },
  });
  const auth = `Authorization: ${basic()}`;
  assert.equal((await raw(port, ['GET /api/thing HTTP/1.1', auth])).status, 200);
  assert.equal((await raw(port, ['POST /api/thing HTTP/1.1', auth])).status, 403);
  const denied = await raw(port, ['POST /api/thing HTTP/1.1', auth, ...write], '{}');
  assert.equal(denied.status, 403);
  assert.deepEqual(JSON.parse(denied.body), {
    error: 'You do not have permission to do this.',
    code: 'forbidden',
  });
  assert.deepEqual(asked, ['dashboard:read', 'sources:write']);
  // Without `permitted`, the access decides: the admin holds every route permission.
  const admin = await serve(t, { routes: table() });
  assert.equal(
    (await raw(admin.port, ['POST /api/thing HTTP/1.1', auth, ...write], '{}')).status,
    200
  );
});

test('Idempotency-Key writes go through the hook, scoped to the principal, except routes that opt out', async t => {
  const calls = [];
  const { port, identity } = await serve(t, {
    routes: table(),
    idempotency: async (req, res, { key, scope, body }, run) => {
      calls.push({ key, scope, body: body.toString() });
      await run();
    },
  });
  const auth = `Authorization: ${basic()}`;
  const key = 'Idempotency-Key: fixture-key-0001';
  assert.equal(
    (await raw(port, ['POST /api/thing HTTP/1.1', auth, ...write, key], '{"a":1}')).status,
    200
  );
  assert.equal(
    (await raw(port, ['POST /api/once HTTP/1.1', auth, ...write, key], '{}')).status,
    200
  );
  assert.equal(
    (await raw(port, ['PUT /api/once HTTP/1.1', auth, ...write, key], '{}')).status,
    405
  );
  assert.equal((await raw(port, ['GET /api/thing HTTP/1.1', auth, key])).status, 200);
  assert.equal(
    (await raw(port, ['PUT /api/thing HTTP/1.1', auth, ...write, key], '{}')).status,
    405
  );
  // Two different sessions of the same person share the scope (D22): a retry sent after
  // signing in again joins or replays its first attempt.
  for (let i = 0; i < 2; i++) {
    const { cookie } = await session(identity);
    assert.equal(
      (
        await raw(
          port,
          ['POST /api/thing HTTP/1.1', cookie, ...write, origin(port), ...browser, key],
          '{"a":2}'
        )
      ).status,
      200
    );
  }
  assert.deepEqual(calls, [
    { key: 'fixture-key-0001', scope: 'user:u_admin:1\nPOST\n/api/thing', body: '{"a":1}' },
    { key: 'fixture-key-0001', scope: 'user:u_admin:1\nPUT\n/api/thing', body: '{}' },
    { key: 'fixture-key-0001', scope: 'user:u_admin:1\nPOST\n/api/thing', body: '{"a":2}' },
    { key: 'fixture-key-0001', scope: 'user:u_admin:1\nPOST\n/api/thing', body: '{"a":2}' },
  ]);
  // A password import (a new epoch) is a new scope: nothing kept before it is replayed.
  identity.test.setPassword(password);
  await raw(port, ['POST /api/thing HTTP/1.1', auth, ...write, key], '{"a":3}');
  assert.equal(calls.at(-1).scope, 'user:u_admin:2\nPOST\n/api/thing');
  // A keyed write without a credential never reaches the hook: there is no scope without one.
  const before = calls.length;
  const bare = await raw(port, ['POST /api/thing HTTP/1.1', ...write, key], '{}');
  assert.equal(bare.status, 401);
  assert.equal(calls.length, before);
});

test('a keyed refusal answered by the idempotency hook keeps the request’s browser context', async t => {
  // server.mjs's idempotent() answers a refusal with fail(res, e): the pipeline recorded how
  // this request must be answered, so a browser gets the coded 401 without the Basic prompt.
  const { port, identity } = await serve(t, {
    routes: table(),
    idempotency: async (req, res, { access }, run) => {
      try {
        identity.assertCurrent(access);
        await run();
      } catch (e) {
        fail(res, e);
      }
    },
    handlers: undefined,
  });
  const { cookie, access } = await session(identity);
  await identity.logout(access);
  const refused = await raw(
    port,
    [
      'POST /api/thing HTTP/1.1',
      cookie,
      ...write,
      origin(port),
      ...browser,
      'Idempotency-Key: fixture-key-0101',
    ],
    '{}'
  );
  assert.equal(refused.status, 401);
  // The session was already gone when the request arrived, so it never reached the hook;
  // a session ended while the request waited is refused inside it (below).
  assert.equal(JSON.parse(refused.body).code, 'session_expired');
  assert.equal(refused.headers['www-authenticate'], undefined);

  let release;
  const held = new Promise(resolve => (release = resolve));
  const second = await session(identity);
  const hooked = await serve(t, {
    identity,
    routes: table(),
    idempotency: async (req, res, { access: waiting }, run) => {
      await held;
      try {
        identity.assertCurrent(waiting);
        await run();
      } catch (e) {
        fail(res, e);
      }
    },
  });
  const pending = raw(
    hooked.port,
    [
      'POST /api/thing HTTP/1.1',
      second.cookie,
      ...write,
      origin(hooked.port),
      ...browser,
      'Idempotency-Key: fixture-key-0102',
    ],
    '{}'
  );
  await new Promise(resolve => setTimeout(resolve, 50));
  await identity.logout(second.access);
  release();
  const answer = await pending;
  assert.equal(answer.status, 401);
  assert.deepEqual(JSON.parse(answer.body), {
    error: 'Your session has ended. Sign in again.',
    code: 'session_expired',
    transport: transport('loopback'),
  });
  assert.equal(answer.headers['www-authenticate'], undefined);
  assert.equal(answer.headers['x-goblin-build'], build);
  assert.equal(answer.headers['x-goblin-version'], undefined);
});

test('public writes need no credential but are strictly CSRF- and JSON-checked, never replayed', async t => {
  const calls = [];
  const { port, identity } = await serve(t, {
    routes: table([
      {
        method: 'POST',
        path: '/api/open',
        auth: 'public',
        permission: null,
        summary: 'a public write (as sign-in is)',
        bodyLimit: 32,
        handler: async ({ res, body, access, assertCurrent }) => {
          assertCurrent();
          json(res, 200, { got: await body(), access });
        },
      },
      {
        method: 'POST',
        path: '/api/beacon',
        auth: 'public',
        permission: null,
        csrf: false,
        contentType: 'none',
        summary: 'a public write that opts out of both checks',
        handler: ({ res }) => json(res, 202, { ok: true }),
      },
    ]),
    idempotency: async (req, res, options, run) => {
      calls.push(options.scope);
      await run();
    },
  });
  const status = async (lines, body) => (await raw(port, lines, body)).status;
  assert.equal(await status(['POST /api/open HTTP/1.1'], '{}'), 403);
  // An Origin is required for a public write (sign-in CSRF), unlike Basic's 1.4.3 rule.
  assert.equal(await status(['POST /api/open HTTP/1.1', ...write], '{}'), 403);
  assert.equal(
    await status(['POST /api/open HTTP/1.1', 'X-Goblin-Request: 1', origin(port)], '{}'),
    415
  );
  assert.equal(
    await status(['POST /api/open HTTP/1.1', ...write, 'Origin: http://evil.test'], '{}'),
    403
  );
  const ok = await raw(
    port,
    ['POST /api/open HTTP/1.1', ...write, origin(port), 'Idempotency-Key: fixture-key-0002'],
    '{"a":1}'
  );
  assert.equal(ok.status, 200);
  assert.deepEqual(JSON.parse(ok.body), { got: { a: 1 }, access: null });
  assert.equal(ok.headers['x-goblin-build'], build, 'every answer names the build (D10)');
  assert.equal(
    ok.headers['x-goblin-version'],
    undefined,
    'only signed-in answers name the version'
  );
  assert.equal(
    (await raw(port, ['POST /api/open HTTP/1.1', ...write, origin(port)], '{"__proto__":{}}'))
      .status,
    400
  );
  assert.equal(
    (
      await raw(
        port,
        ['POST /api/open HTTP/1.1', ...write, origin(port)],
        JSON.stringify({ a: 'x'.repeat(40) })
      )
    ).status,
    413
  );
  assert.equal(await status(['POST /api/beacon HTTP/1.1'], 'plain text'), 202);
  assert.deepEqual(calls, [], 'no public write went through the idempotency hook');
  assert.equal(identity.test.checks, 0, 'no credential was checked');
});

test('a route that requires If-Match refuses a write without it (428), after CSRF and permission', async t => {
  let ran = 0;
  const { port } = await serve(t, {
    routes: table([
      {
        method: 'PUT',
        path: '/api/guarded',
        auth: 'session',
        permission: 'settings:write',
        ifMatch: 'required',
        summary: 'needs If-Match',
        handler: ({ res }) => {
          ran++;
          json(res, 200, { ok: true });
        },
      },
      {
        method: 'PUT',
        path: '/api/guarded-denied',
        auth: 'session',
        permission: 'users:write',
        ifMatch: 'required',
        summary: 'needs If-Match and a permission the caller lacks',
        handler: () => ran++,
      },
    ]),
    permitted: (access, permission) => permission !== 'users:write',
  });
  const auth = `Authorization: ${basic()}`;
  assert.equal((await raw(port, ['PUT /api/guarded HTTP/1.1', auth], '{}')).status, 403);
  const denied = await raw(port, ['PUT /api/guarded-denied HTTP/1.1', auth, ...write], '{}');
  assert.equal(denied.status, 403);
  assert.match(JSON.parse(denied.body).error, /permission/);
  const missing = await raw(port, ['PUT /api/guarded HTTP/1.1', auth, ...write], '{}');
  assert.equal(missing.status, 428);
  assert.equal(JSON.parse(missing.body).code, 'if_match_required');
  assert.equal(ran, 0);
  const sent = await raw(
    port,
    ['PUT /api/guarded HTTP/1.1', auth, ...write, 'If-Match: "3"'],
    '{}'
  );
  assert.equal(sent.status, 200);
  assert.equal(ran, 1);
});

test('a deprecated route says so on its own answers only; Basic answers always do', async t => {
  const deprecated = {
    method: 'GET',
    path: '/api/old',
    auth: 'session',
    permission: 'dashboard:read',
    deprecated: '2026-10-01',
    sunset: '2027-04-01',
    summary: 'an old route',
    handler: ({ res }) => json(res, 200, { ok: true }),
  };
  const { port, identity } = await serve(t, {
    routes: table([
      deprecated,
      {
        ...deprecated,
        method: 'POST',
        path: '/api/old-health',
        auth: 'public',
        permission: null,
        csrf: false,
        contentType: 'none',
      },
    ]),
  });
  const { cookie } = await session(identity);
  const answered = await raw(port, ['GET /api/old HTTP/1.1', cookie]);
  assert.equal(answered.status, 200);
  assert.equal(answered.headers.deprecation, `@${Date.UTC(2026, 9, 1) / 1000}`);
  assert.equal(answered.headers.sunset, 'Thu, 01 Apr 2027 00:00:00 GMT');
  assert.equal(answered.headers.link, undefined);
  const open = await raw(port, ['POST /api/old-health HTTP/1.1']);
  assert.equal(open.status, 200);
  assert.ok(open.headers.deprecation);
  // Refused before the route was reached, or another route: nothing about it is said.
  for (const lines of [
    ['GET /api/old HTTP/1.1'],
    ['POST /api/old HTTP/1.1', cookie, ...write, origin(port)],
    ['GET /api/thing HTTP/1.1', cookie],
  ]) {
    const answer = await raw(port, lines);
    assert.equal(answer.headers.deprecation, undefined, lines[0]);
    assert.equal(answer.headers.sunset, undefined, lines[0]);
  }
  // Every Basic-signed-in answer says that Basic is deprecated, and where to read about it.
  const scripted = await raw(port, ['GET /api/thing HTTP/1.1', `Authorization: ${basic()}`]);
  assert.equal(scripted.status, 200);
  assert.equal(scripted.headers.deprecation, '@1790812800');
  assert.equal(scripted.headers.link, '</api/docs?doc=authentication>; rel="deprecation"');
  assert.equal(scripted.headers.sunset, undefined);
});

test('permission is checked before an Idempotency-Key can replay anything', async t => {
  const calls = [];
  const { port } = await serve(t, {
    routes: table(),
    permitted: (access, permission) => permission !== 'sources:write',
    idempotency: async (req, res, options, run) => {
      calls.push(options.key);
      await run();
    },
  });
  const denied = await raw(
    port,
    [
      'POST /api/thing HTTP/1.1',
      `Authorization: ${basic()}`,
      ...write,
      'Idempotency-Key: fixture-key-0003',
    ],
    '{}'
  );
  assert.equal(denied.status, 403);
  assert.deepEqual(calls, []);
  // A 404 or 405 needs no permission and may still be keyed, as in 1.4.3.
  assert.equal(
    (
      await raw(
        port,
        [
          'PUT /api/thing HTTP/1.1',
          `Authorization: ${basic()}`,
          ...write,
          'Idempotency-Key: fixture-key-0004',
        ],
        '{}'
      )
    ).status,
    405
  );
  assert.deepEqual(calls, ['fixture-key-0004']);
});

test('an unexpected failure is logged with the request id the client received', async t => {
  const { port } = await serve(t, {
    routes: table([
      {
        method: 'GET',
        path: '/api/broken',
        auth: 'session',
        permission: 'dashboard:read',
        summary: 'fails',
        handler: () => {
          throw Object.assign(new Error('boom'), { code: 'EFIXTURE' });
        },
      },
    ]),
  });
  const logged = [];
  t.mock.method(console, 'error', (...args) => logged.push(args.join(' ')));
  const answer = await raw(port, ['GET /api/broken HTTP/1.1', `Authorization: ${basic()}`]);
  t.mock.restoreAll();
  assert.equal(answer.status, 500);
  assert.deepEqual(JSON.parse(answer.body), {
    error: 'Uptime Goblin could not complete this request',
  });
  assert.deepEqual(logged, [
    `Request failed: EFIXTURE (request ${answer.headers['x-request-id']})`,
  ]);
});

test('429 and 503 refusals carry Retry-After from the error, 5 s when it names none', async t => {
  const errors = {
    '/api/e/locked': identityError('locked', { retryAfter: 42 }),
    '/api/e/busy': identityError('busy', { scope: 'queue' }),
    '/api/e/full': identityError('storage_full'),
    '/api/e/queue': new BusyError(
      'Uptime Goblin is busy saving other changes. Nothing was changed; try again.'
    ),
    '/api/e/bare': Object.assign(identityError('change_in_progress'), { retryAfter: undefined }),
  };
  const { port } = await serve(t, {
    routes: table(
      Object.entries(errors).map(([route, error]) => ({
        method: 'GET',
        path: route,
        auth: 'session',
        permission: 'dashboard:read',
        summary: 'refuses',
        handler: () => {
          throw error;
        },
      }))
    ),
  });
  const answers = {};
  for (const route of Object.keys(errors)) {
    const answer = await raw(port, [`GET ${route} HTTP/1.1`, `Authorization: ${basic()}`]);
    answers[route] = [answer.status, answer.headers['retry-after'], JSON.parse(answer.body).code];
  }
  assert.deepEqual(answers, {
    '/api/e/locked': [429, '42', 'locked'],
    '/api/e/busy': [429, '5', 'busy'],
    '/api/e/full': [503, '30', 'storage_full'],
    '/api/e/queue': [503, '5', 'busy'],
    '/api/e/bare': [429, '5', 'change_in_progress'],
  });
});

test('no request is signed in without the admin password: header-less loopback, proxied, or a wrong credential', async t => {
  // 1.4.x (and earlier 1.5 builds) answered all of these from the passwordless local preview,
  // with full access from this computer and 403 through a proxy. Uptime Goblin always has a password.
  const { port, identity } = await serve(t, { routes: table() });
  const refusals = [
    [['GET /api/thing HTTP/1.1'], 'signin_required'],
    [['GET /api/thing HTTP/1.1', ...browser], 'signin_required'],
    [
      ['GET /api/thing HTTP/1.1', `Authorization: ${basic('anything at all')}`],
      'invalid_credentials',
    ],
    [['GET /api/thing HTTP/1.1', 'Authorization: Bearer x'], 'invalid_credentials'],
    [['GET /api/thing HTTP/1.1', 'Cookie: goblin_session=not-a-session'], 'session_expired'],
    [['POST /api/thing HTTP/1.1', ...write], 'signin_required'],
  ];
  // Forwarding headers change nothing but the transport: no 403 "Set GOBLIN_PASSWORD" any more.
  for (const name of [
    'X-Forwarded-For',
    'X-Forwarded-Proto',
    'Forwarded',
    'X-Real-IP',
    'X-Forwarded-Host',
  ])
    refusals.push([['GET /api/thing HTTP/1.1', `${name}: x`], 'signin_required']);
  for (const [lines, code] of refusals) {
    const answer = await raw(port, lines, lines[0].startsWith('POST') ? '{}' : '');
    assert.equal(answer.status, 401, lines.join(' | '));
    assert.equal(JSON.parse(answer.body).code, code, lines.join(' | '));
    assert.doesNotMatch(answer.body, /GOBLIN_PASSWORD/);
    assert.equal(answer.headers['x-goblin-version'], undefined, 'not signed in');
  }
  // Public routes answer without a credential, also through a proxy.
  assert.equal((await raw(port, ['GET /health HTTP/1.1'])).status, 200);
  assert.equal(
    (await raw(port, ['GET /health HTTP/1.1', 'X-Forwarded-For: 192.0.2.1'])).status,
    200
  );
  // The admin password still signs a script in.
  const signedIn = await raw(port, ['GET /api/thing HTTP/1.1', `Authorization: ${basic()}`]);
  assert.equal(signedIn.status, 200);
  assert.equal(JSON.parse(signedIn.body).via, 'basic');
  assert.ok(identity.test.checks > 0);
});

test('sessions are read only on this transport’s cookie, and on plain HTTP only with the opt-in (D16)', async t => {
  const identity = fakeIdentity({ password, insecureHttpSessions: true });
  const signIn = transport => identity.login({ login: 'admin', password, transport });
  const overHttp = (await signIn('http')).issue.value;
  // Through an untrusted proxy the transport is http: no session is read without the opt-in.
  const plain = await serve(t, { routes: table(), identity });
  const viaProxy = [`Cookie: goblin_session=${overHttp}`, 'X-Forwarded-For: 192.0.2.7'];
  const refused = await raw(plain.port, ['GET /api/thing HTTP/1.1', ...viaProxy, ...browser]);
  assert.equal(refused.status, 401);
  assert.deepEqual(JSON.parse(refused.body), {
    error: 'Sign in to Uptime Goblin.',
    code: 'signin_required',
    transport: transport('http'),
  });
  const allowed = await serve(t, { routes: table(), identity, insecureHttpSessions: true });
  const insecure = await raw(allowed.port, ['GET /api/thing HTTP/1.1', ...viaProxy, ...browser]);
  assert.equal(insecure.status, 200);
  // On https (a trusted proxy said so) only __Host-goblin_session is read.
  const secure = await serve(t, {
    routes: table(),
    identity,
    trusted: trustedProxies('loopback'),
  });
  const overHttps = (await signIn('https')).issue.value;
  const https = ['X-Forwarded-For: 192.0.2.7', 'X-Forwarded-Proto: https', ...browser];
  const get = (port, cookie, lines = []) =>
    raw(port, ['GET /api/thing HTTP/1.1', `Cookie: ${cookie}`, ...lines]).then(a => a.status);
  assert.equal(
    await get(secure.port, `goblin_session=${overHttps}`, https),
    401,
    'the plain-HTTP cookie is not a credential on https'
  );
  assert.equal(await get(secure.port, `__Host-goblin_session=${overHttps}`, https), 200);
  // A session is bound to the cookie it was issued as: a secret that crossed the network in
  // clear never works as the Secure cookie, and the Secure one never as the plain one.
  assert.equal(await get(secure.port, `__Host-goblin_session=${overHttp}`, https), 401);
  assert.equal(await get(plain.port, `goblin_session=${overHttps}`), 401);
  // And on loopback only goblin_session.
  const overLoopback = (await signIn('loopback')).issue.value;
  assert.equal(await get(plain.port, `__Host-goblin_session=${overHttps}`), 401);
  assert.equal(await get(plain.port, `goblin_session=${overLoopback}`), 200);
  assert.equal(await get(secure.port, `__Host-goblin_session=${overLoopback}`, https), 401);
});

test('two values of this transport’s session cookie are refused and logged once; one malformed value is session_expired', async t => {
  const { port, identity, loginThrottle, logged } = await serve(t, { routes: table() });
  const { issue } = await identity.login({ login: 'admin', password });
  for (let i = 0; i < 3; i++) {
    const twice = await raw(port, [
      'GET /api/thing HTTP/1.1',
      `Cookie: goblin_session=${issue.value}; goblin_session=${issue.value}`,
      ...browser,
    ]);
    assert.equal(twice.status, 401);
    assert.equal(JSON.parse(twice.body).code, 'multiple_credentials');
    assert.equal(twice.headers['www-authenticate'], undefined);
  }
  // Also when they come in two Cookie headers.
  const split = await raw(port, [
    'GET /api/thing HTTP/1.1',
    `Cookie: goblin_session=${issue.value}`,
    'Cookie: goblin_session=other',
  ]);
  assert.equal(JSON.parse(split.body).code, 'multiple_credentials');
  assert.deepEqual(logged, [
    "A browser sent two goblin_session cookies, so its requests are refused until this site's cookies are cleared. Another site on a parent domain may set a cookie with the same name.",
  ]);
  for (const value of ['', 'garbage', `v1.${'!'.repeat(43)}`, `v2.${'A'.repeat(43)}`, '"quoted"']) {
    const answer = await raw(port, ['GET /api/thing HTTP/1.1', `Cookie: goblin_session=${value}`]);
    assert.equal(answer.status, 401, value);
    assert.equal(JSON.parse(answer.body).code, 'session_expired', value);
  }
  assert.equal(loginThrottle.size, 0, 'no session refusal counted as a guess');
});

test('X-Goblin-Activity: background never extends the idle limit; anything else does', async t => {
  let now = Date.UTC(2026, 9, 1, 8);
  const identity = fakeIdentity({ password, clock: () => now });
  const { port } = await serve(t, { routes: table(), identity });
  const { cookie } = await session(identity);
  const row = () => identity.test.rows()[0];
  const started = row().idle_expires_at;
  now += 10 * 60e3;
  await raw(port, ['GET /api/thing HTTP/1.1', cookie, 'X-Goblin-Activity: background']);
  assert.equal(row().idle_expires_at, started, 'a poll leaves the idle limit alone');
  assert.equal(row().last_seen_at, now, 'but records that the session was seen');
  now += 10 * 60e3;
  await raw(port, ['GET /api/thing HTTP/1.1', cookie, 'X-Goblin-Activity: foreground']);
  assert.equal(row().idle_expires_at, now + 12 * 3600e3);
  now += 10 * 60e3;
  await raw(port, ['GET /api/thing HTTP/1.1', cookie]);
  assert.equal(row().idle_expires_at, now + 12 * 3600e3, 'no header is foreground');
});

test('session requests are never held to the sign-in lockout; they keep trust but never make it', async t => {
  let now = Date.UTC(2026, 9, 1, 8);
  const loginThrottle = new LoginThrottle({ freeAttempts: 1, globalFailures: 3, now: () => now });
  const { port, identity } = await serve(t, {
    routes: table(),
    loginThrottle,
    trusted: trustedProxies('loopback'),
  });
  const { cookie } = await session(identity);
  for (let i = 0; i < 5; i++) loginThrottle.failure('loopback');
  for (let i = 0; i < 5; i++) loginThrottle.failure(`198.51.100.${i}`);
  assert.ok(loginThrottle.retryAfter('loopback') > 0);
  assert.ok(loginThrottle.globalLocked());
  for (let i = 0; i < 3; i++)
    assert.equal((await raw(port, ['GET /api/thing HTTP/1.1', cookie])).status, 200);
  // A script's Basic from the same client is held to its client lock.
  const locked = await raw(port, ['GET /api/thing HTTP/1.1', `Authorization: ${basic()}`]);
  assert.equal(locked.status, 429);
  assert.deepEqual(JSON.parse(locked.body), {
    error: 'Too many failed sign-in attempts. Wait before trying again.',
    code: 'locked',
  });
  assert.ok(Number(locked.headers['retry-after']) >= 1);
  // A session proves the cookie, not the password: a copied cookie used from any address must
  // not exempt that address from the global lock, now or after the session is revoked.
  const proxied = [
    'Host: goblin.example',
    'X-Forwarded-For: 203.0.113.9',
    'X-Forwarded-Proto: https',
  ];
  const { issue } = await identity.login({ login: 'admin', password, transport: 'https' });
  const secure = `Cookie: __Host-goblin_session=${issue.value}`;
  assert.equal((await raw(port, ['GET /api/thing HTTP/1.1', ...proxied, secure])).status, 200);
  assert.equal(loginThrottle.trusted('203.0.113.9'), false, 'a session makes no client trusted');
  assert.equal(loginThrottle.trusted('loopback'), false);
  // A client a password made trusted stays trusted while its sessions are used.
  loginThrottle.trust('203.0.113.9');
  now += 29 * 86400e3;
  assert.equal((await raw(port, ['GET /api/thing HTTP/1.1', ...proxied, secure])).status, 200);
  now += 2 * 86400e3;
  assert.equal(loginThrottle.trusted('203.0.113.9'), true, 'its trust was extended');
});

test('the global lock never applies on the loopback transport, the client lock does (D18)', async t => {
  const loginThrottle = new LoginThrottle({ globalFailures: 3 });
  const { port } = await serve(t, {
    routes: table(),
    loginThrottle,
    trusted: trustedProxies('loopback'),
  });
  for (let i = 0; i < 3; i++) loginThrottle.failure(`198.51.100.${i}`);
  assert.ok(loginThrottle.globalLocked());
  // Loopback (no forwarding headers): a shell on the Uptime Goblin host is the way in.
  assert.equal(
    (await raw(port, ['GET /api/thing HTTP/1.1', `Authorization: ${basic()}`])).status,
    200
  );
  // Through the proxy on the same host (over HTTPS) from a new client: refused for 60 s.
  const forwarded = await raw(port, [
    'GET /api/thing HTTP/1.1',
    `Authorization: ${basic()}`,
    'X-Forwarded-For: 203.0.113.9',
    'X-Forwarded-Proto: https',
  ]);
  assert.equal(forwarded.status, 429);
  assert.equal(forwarded.headers['retry-after'], '60');
  assert.equal(JSON.parse(forwarded.body).code, 'locked');
  // The client lock still holds on loopback: the host's own key, which is not an address.
  for (let i = 0; i < 6; i++) loginThrottle.failure('loopback');
  const own = await raw(port, ['GET /api/thing HTTP/1.1', `Authorization: ${basic()}`]);
  assert.equal(own.status, 429);
  assert.notEqual(own.headers['retry-after'], '60');
});

test('the Uptime Goblin host’s own lockout key is no address: a proxy’s clients can never lock it (D18)', async t => {
  const loginThrottle = new LoginThrottle({ freeAttempts: 2, baseMs: 60000 });
  const { port, logged } = await serve(t, {
    routes: table(),
    loginThrottle,
    trusted: trustedProxies('loopback'),
  });
  const attempt = (lines, secret = 'a wrong guess') =>
    raw(port, ['GET /api/thing HTTP/1.1', `Authorization: ${basic(secret)}`, ...lines]);
  // A proxy on this host that names no client (it sends X-Real-IP and X-Forwarded-Proto but no
  // X-Forwarded-For) and one that passes the client's own X-Forwarded-For through: Uptime Goblin keys
  // both by the address they name or by the proxy's, 127.0.0.1, never by the host's own key.
  for (const lines of [
    ['Host: goblin.example', 'X-Real-IP: 203.0.113.9', 'X-Forwarded-Proto: https'],
    ['Host: goblin.example', 'X-Forwarded-For: 127.0.0.1', 'X-Forwarded-Proto: https'],
  ])
    for (let i = 0; i < 4; i++) await attempt(lines);
  assert.ok(loginThrottle.retryAfter('127.0.0.1') > 0, 'the proxy’s clients are locked out');
  assert.equal(loginThrottle.retryAfter('loopback'), 0);
  assert.equal(
    (await attempt(['Host: goblin.example', 'X-Forwarded-Proto: https'], password)).status,
    429
  );
  // The owner on the host itself (ssh -L to 127.0.0.1) still signs in.
  assert.equal((await attempt([], password)).status, 200);
  // The journal says why the proxy's clients share one lockout, once an hour.
  assert.deepEqual(logged, [
    "Requests from the trusted proxy 127.0.0.1 do not name their client in X-Forwarded-For, so every client behind it shares one sign-in lockout: one client's failed sign-ins lock out the others. Make the proxy send it (nginx: proxy_set_header X-Forwarded-For $remote_addr;).",
  ]);
  // A proxy that names its client is not reported.
  const named = await serve(t, { routes: table(), trusted: trustedProxies('loopback') });
  await raw(named.port, [
    'GET /api/thing HTTP/1.1',
    'Host: goblin.example',
    'X-Forwarded-For: 203.0.113.9',
    'X-Forwarded-Proto: https',
  ]);
  assert.deepEqual(named.logged, []);
});

// Review CFG-3: with plain-HTTP sign-in allowed, a proxy on this host that GOBLIN_TRUST_PROXY
// does not name but that sends forwarding headers relays sign-ins from anywhere as plain HTTP,
// and the opt-in accepts them. Uptime Goblin names it in the journal once an hour, by the connection's
// own address only: never a forwarded address, a Host or a credential the request carried.
test('an unnamed proxy on this host that sends forwarding headers is named once an hour while plain-HTTP sign-in is allowed', async t => {
  const proxyLines = logged =>
    logged.filter(line =>
      line.startsWith('A reverse proxy on this computer that GOBLIN_TRUST_PROXY does not name')
    );
  const shapes = [
    ['Host: goblin.example', 'X-Forwarded-For: 203.0.113.9', 'X-Forwarded-Proto: http'],
    ['X-Real-IP: 203.0.113.9'],
    ['Host: goblin.example', 'Forwarded: for=203.0.113.9;proto=https'],
  ];
  const send = (port, lines, secret = password) =>
    raw(port, ['GET /api/thing HTTP/1.1', `Authorization: ${basic(secret)}`, ...lines]);
  // No proxy named, or another one: the request is plain HTTP, accepted under the opt-in.
  for (const trusted of [null, trustedProxies('192.0.2.10')]) {
    const { port, logged } = await serve(t, {
      routes: table(),
      insecureHttpSessions: true,
      ...(trusted ? { trusted } : {}),
    });
    for (const lines of shapes) assert.equal((await send(port, lines)).status, 200);
    await send(port, shapes[0], 'a wrong guess');
    assert.deepEqual(proxyLines(logged), [
      "A reverse proxy on this computer that GOBLIN_TRUST_PROXY does not name sends Uptime Goblin requests with forwarding headers (from 127.0.0.1), and plain-HTTP sign-in is allowed (GOBLIN_INSECURE_HTTP_SESSIONS): Uptime Goblin believes nothing such a proxy says, so sign-ins through it, and scripts' Basic passwords while legacy Basic is on, are accepted as plain HTTP from wherever the proxy took them. Name the proxy in GOBLIN_TRUST_PROXY (loopback for one on this computer) and make it serve Uptime Goblin over HTTPS (nginx: proxy_set_header X-Forwarded-Proto $scheme;).",
    ]);
    const journal = logged.join('\n');
    for (const sent of ['203.0.113.9', 'goblin.example', password, 'a wrong guess', basic()])
      assert.equal(journal.includes(sent), false, `the journal holds ${sent}`);
  }
  // Not named: the opt-in off (refused https_required anyway), the proxy named in
  // GOBLIN_TRUST_PROXY, or no forwarding headers (the loopback transport, or the header-less
  // proxy that has a line of its own).
  for (const [options, lines] of [
    [{ insecureHttpSessions: false }, shapes],
    [{ insecureHttpSessions: true, trusted: trustedProxies('loopback') }, shapes],
    [{ insecureHttpSessions: true }, [[], ['Host: goblin.example']]],
  ]) {
    const { port, logged } = await serve(t, { routes: table(), ...options });
    for (const each of lines) await send(port, each);
    assert.deepEqual(proxyLines(logged), [], JSON.stringify(options));
  }
  // The connection's own address decides, never a header: an IPv4-mapped loopback peer is this
  // computer too, and a peer on another host that sends forwarding headers (a proxy there that
  // is not named, or a client that writes them itself) is no proxy on this computer, so the
  // line would name the wrong thing (review of R2B, the isLoopbackPeer clause).
  const mapped = await serve(t, {
    routes: table(),
    insecureHttpSessions: true,
    peer: '::ffff:127.0.0.1',
  });
  for (const lines of shapes) assert.equal((await send(mapped.port, lines)).status, 200);
  assert.equal(proxyLines(mapped.logged).length, 1, mapped.logged.join('\n'));
  assert.match(proxyLines(mapped.logged)[0], /forwarding headers \(from ::ffff:127\.0\.0\.1\)/);
  for (const peer of ['192.0.2.44', '2001:db8::5', '::ffff:192.0.2.44']) {
    const remote = await serve(t, { routes: table(), insecureHttpSessions: true, peer });
    for (const lines of shapes) assert.equal((await send(remote.port, lines)).status, 200, peer);
    assert.deepEqual(proxyLines(remote.logged), [], peer);
  }
});

test('a session cookie works only from Uptime Goblin’s own pages: a same-site request is refused unread', async t => {
  let now = Date.UTC(2026, 9, 1, 8);
  const identity = fakeIdentity({ password, clock: () => now });
  const loginThrottle = new LoginThrottle();
  const { port } = await serve(t, { routes: table(), identity, loginThrottle });
  const { cookie } = await session(identity);
  const row = () => identity.test.rows()[0];
  const started = row().idle_expires_at;
  // Another app under the same parent domain (or another port of localhost) has the browser
  // load an Uptime Goblin address: the SameSite=Strict cookie goes along, Sec-Fetch-Site says same-site.
  for (const site of ['same-site', 'cross-site']) {
    now += 10 * 60e3;
    const answer = await raw(port, [
      'GET /api/thing HTTP/1.1',
      cookie,
      `Sec-Fetch-Site: ${site}`,
      'Sec-Fetch-Mode: no-cors',
      'Sec-Fetch-Dest: image',
    ]);
    assert.equal(answer.status, 403, site);
    assert.deepEqual(JSON.parse(answer.body), {
      error: 'Requests from other sites cannot use your Uptime Goblin session.',
      code: 'cross_origin',
    });
    assert.equal(answer.headers['x-goblin-version'], undefined, 'not a signed-in answer');
  }
  assert.equal(row().idle_expires_at, started, 'the idle limit did not move');
  assert.equal(row().last_seen_at, started - 12 * 3600e3, 'the session was not even touched');
  const posted = await raw(
    port,
    ['POST /api/thing HTTP/1.1', cookie, ...write, origin(port), 'Sec-Fetch-Site: same-site'],
    '{}'
  );
  assert.equal(posted.status, 403);
  assert.equal(JSON.parse(posted.body).error, 'Cross-origin changes are not allowed');
  assert.equal(row().idle_expires_at, started);
  assert.equal(loginThrottle.size, 0, 'not counted as a guess');
  // Uptime Goblin's own page (same-origin), a typed address or bookmark (none) and a client without
  // fetch metadata use the session as before.
  for (const lines of [['Sec-Fetch-Site: same-origin'], ['Sec-Fetch-Site: none'], []]) {
    now += 10 * 60e3;
    const answer = await raw(port, ['GET /api/thing HTTP/1.1', cookie, ...lines]);
    assert.equal(answer.status, 200, lines.join());
    assert.equal(row().idle_expires_at, now + 12 * 3600e3, lines.join());
  }
});

// --- The same rules through a real Uptime Goblin (createApp) -------------------------------------

// `config`, when given, is saved as config.json first: a configuration an older release wrote.
async function orbit(t, { config, ...options } = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-pipeline-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  if (config !== undefined)
    fs.writeFileSync(path.join(directory, 'config.json'), JSON.stringify(config, null, 2));
  // Loaded here, not at the top: the pipeline tests above need no running Uptime Goblin.
  const { createApp } = await import('../../server.mjs');
  const app = await createApp({
    directory,
    port: 0,
    password,
    // Basic stays on for these script-style requests (G2 turns it off on new directories).
    legacyBasic: true,
    allowedHosts: '',
    webhook: '',
    startScheduler: false,
    trustProxy: '',
    ...options,
  });
  const { port } = await app.listen();
  t.after(() => app.close());
  return { app, port };
}

test('Uptime Goblin refuses prototype-shaped keys in every JSON body and changes nothing', async t => {
  const { app, port } = await orbit(t);
  const before = JSON.stringify(app.config.value);
  const auth = `Authorization: ${basic()}`;
  // A label named 'constructor' on its own ({"labels":{"constructor":"x"}}) was refused here
  // until 1.5 accepted it again, as 1.4.x does: see the 1.4.x upgrade test below. A
  // constructor.prototype chain inside the same labels is still refused.
  for (const [line, body] of [
    ['PATCH /api/settings HTTP/1.1', '{"__proto__":{"title":"Polluted"}}'],
    ['PATCH /api/settings HTTP/1.1', '{"monitoring":{"constructor":{"prototype":{}}}}'],
    ['PATCH /api/services/linux HTTP/1.1', '{"rules":[{"key":"cpu","__proto__":{"x":1}}]}'],
    [
      'PATCH /api/services/linux HTTP/1.1',
      '{"metrics":[{"key":"a","path":"a","labels":{"constructor":{"prototype":{"x":1}}}}]}',
    ],
    ['POST /api/services HTTP/1.1', '{"type":"json","name":"X","__proto__":{"enabled":false}}'],
    [
      'POST /api/test-service HTTP/1.1',
      '{"settings":{"constructor":{"prototype":{"enabled":false}}}}',
    ],
  ]) {
    const answer = await raw(port, [line, auth, ...write], body);
    assert.equal(answer.status, 400, `${line} ${body}`);
    assert.match(
      JSON.parse(answer.body).error,
      /^Field name (__proto__|constructor\.prototype) is not allowed$/
    );
  }
  assert.equal(JSON.stringify(app.config.value), before);
  assert.equal({}.title, undefined);
  assert.equal({}.enabled, undefined);
  assert.equal({}.x, undefined);
});

// A Prometheus source as Orbit 1.4.3 saves it (POST /api/services, then a drawer save) when its
// metric labels are named 'constructor' and 'prototype': 1.4.x accepts any \w+ label name.
// Global settings are left out: Uptime Goblin fills in the defaults of any it does not find.
const exporter14 = {
  id: 'prometheus-1',
  type: 'prometheus',
  name: 'Exporter',
  group: 'Infrastructure',
  color: 'orange',
  icon: 'activity',
  labels: [],
  enabled: true,
  showOnDashboard: true,
  pollSeconds: 0,
  url: '',
  apiUrl: 'http://192.0.2.10:9100',
  apiKey: '',
  username: '',
  password: '',
  siteId: '',
  nodeName: '',
  metricPath: '',
  httpExpectedStatus: '200-399',
  httpMethod: 'GET',
  collector: 'native',
  monitoring: {},
  alerts: {},
  metrics: [
    {
      key: 'fs_free',
      label: 'Free',
      path: 'node_filesystem_avail_bytes',
      unit: 'B',
      scale: 1,
      labels: { constructor: 'x', prototype: 'y' },
    },
  ],
  rules: [],
};

test('a 1.4.x Prometheus source with labels named constructor and prototype can still be saved and tested', async t => {
  // What the collector was asked to collect: the labels must reach it as saved.
  const collected = [];
  const { app, port } = await orbit(t, {
    config: { services: [exporter14], revision: 3, sourceCounters: { prometheus: 1 } },
    collector: async service => {
      collected.push(structuredClone(service.metrics));
      return [{ key: 'fs_free', label: 'Free', value: 1, unit: 'B' }];
    },
  });
  const auth = `Authorization: ${basic()}`;
  const dashboard = await raw(port, ['GET /api/dashboard HTTP/1.1', auth]);
  assert.equal(dashboard.status, 200);
  const { config } = JSON.parse(dashboard.body);
  const source = config.services.find(s => s.id === 'prometheus-1');
  assert.deepEqual(source.metrics, exporter14.metrics, 'the upgrade loaded the labels');
  // The body the source drawer sends (public/modules/drawer/drawer.js connectionInput()) for a
  // Prometheus source: every visible field, the metric mappings textarea parsed back whole,
  // and the per-source monitoring and notification choices left to inherit (null).
  const drawer = {
    type: source.type,
    name: 'Exporter (renamed)',
    group: source.group,
    color: source.color,
    url: source.url,
    apiUrl: source.apiUrl,
    enabled: source.enabled,
    showOnDashboard: source.showOnDashboard,
    pollSeconds: source.pollSeconds,
    collector: source.collector,
    metricPath: source.metricPath,
    monitoring: Object.fromEntries(
      [
        'retryCount',
        'retryDelaySeconds',
        'timeoutSeconds',
        'availabilityFailures',
        'availabilitySeconds',
        'recoverySuccesses',
        'recoverySeconds',
      ].map(key => [key, null])
    ),
    alerts: { notifyAvailability: null, notifyMeasurements: null },
    rules: [],
    metrics: JSON.parse(JSON.stringify(source.metrics, null, 2)),
  };
  // Test connection, then Save, as the drawer's buttons send them.
  const tested = await raw(
    port,
    ['POST /api/test-service HTTP/1.1', auth, ...write, 'Idempotency-Key: fixture-key-1401'],
    JSON.stringify({ serviceId: 'prometheus-1', settings: drawer })
  );
  const saved = await raw(
    port,
    [
      'PATCH /api/services/prometheus-1 HTTP/1.1',
      auth,
      ...write,
      `If-Match: ${config.revision}`,
      'Idempotency-Key: fixture-key-1402',
    ],
    JSON.stringify(drawer)
  );
  assert.deepEqual(
    {
      test: [tested.status, tested.body.slice(0, 80)],
      save: [saved.status, saved.body.slice(0, 80)],
    },
    {
      test: [200, tested.body.slice(0, 80)],
      save: [200, saved.body.slice(0, 80)],
    }
  );
  assert.equal(JSON.parse(tested.body).ok, true);
  assert.deepEqual(collected, [exporter14.metrics]);
  assert.equal(JSON.parse(saved.body).service.name, 'Exporter (renamed)');
  const kept = app.config.get('prometheus-1');
  assert.deepEqual(kept.metrics, exporter14.metrics, 'the labels were saved unchanged');
  assert.ok(Object.hasOwn(kept.metrics[0].labels, 'constructor'));
  assert.equal(Object.getPrototypeOf(kept.metrics[0].labels), Object.prototype);
  assert.equal({}.x, undefined);
  assert.equal({}.y, undefined);
});

// Nothing in Uptime Goblin merges a request body recursively into another object: lib/config.mjs and
// the routes copy named fields, and the one map whose keys a client chooses (metric labels,
// \w+ names) is copied one level deep with string values. So a pollution attempt that the
// body check lets through must still leave every prototype alone. This sends each shape, at
// the top level and inside every nested field a JSON route reads, to every JSON route of a
// real Uptime Goblin.
test('no JSON route lets a body pollute Object.prototype or Object', async t => {
  const { app, port } = await orbit(t, {
    collector: async () => [{ key: 'probe', label: 'Probe', value: 1, unit: '' }],
  });
  const auth = `Authorization: ${basic()}`;
  // Scripts send an Origin naming the Host (allowed by the 1.4.3 rule), so sign-in, a public
  // write held to the stricter rule, reads its body too.
  const sameOrigin = `Origin: http://127.0.0.1:${port}`;
  // The table as server.mjs builds it (route factories only keep references to `app`).
  const site = { build: '000000000000', publicFiles: new Map(), indexPage: Buffer.from('') };
  const routes = createRouter(routeTable({ nonce: 'n', site }), {
    reserved: reservedPaths,
    auth: supportedAuth,
    supports: supportedFeatures,
  })
    .routes.filter(route => route.contentType === 'json')
    // DELETE removes the source the others write to, so it goes last.
    .sort((a, b) => (a.method === 'DELETE') - (b.method === 'DELETE'));
  assert.deepEqual(
    routes.map(route => `${route.method} ${route.path}`),
    [
      'POST /api/auth/login',
      'POST /api/auth/logout',
      'POST /api/account/password',
      'POST /api/auth/password',
      'PATCH /api/settings',
      'POST /api/email/test',
      'POST /api/test-service',
      'POST /api/services',
      'PATCH /api/services/:id',
      'POST /api/refresh',
      // The Uptime Kuma import: a backup whose fields reach a prototype is refused (400).
      'POST /api/import/uptime-kuma/preview',
      'POST /api/import/uptime-kuma',
      // 1.5 delivery (delivery spec §6.4): each takes {} and refuses any field.
      'POST /api/notifications/deliveries/:uid/retry',
      'POST /api/notifications/channels/:id/resume',
      // ntfy and Gotify: their settings (every field validated, unknown ones refused) and test.
      'PATCH /api/notifications/channels/:id/settings',
      'POST /api/notifications/channels/:id/test',
      'POST /api/notifications/webhook/signing-secret',
      'DELETE /api/account/sessions',
      'DELETE /api/account/sessions/:id',
      'DELETE /api/services/:id',
    ],
    'a new JSON route joins this probe'
  );
  // A path the route accepts, so its body is read: a source, a delivery id, a channel. A saved
  // source keeps its type, so a change is sent to the Prometheus source POST /api/services added
  // (it comes first in the table).
  const target = route =>
    route.path
      .replace(':uid', 'd_abcdefghijklmnopqrstuvwxyz')
      .replace(
        ':id',
        route.path.endsWith('/settings') || route.path.endsWith('/test')
          ? 'ntfy'
          : route.path.includes('/channels/')
            ? 'email'
            : route.method === 'PATCH'
              ? 'prometheus-1'
              : 'linux'
      );
  const snapshot = () =>
    JSON.stringify([
      Reflect.ownKeys(Object.prototype).map(String),
      Reflect.ownKeys(Object).map(String),
      Reflect.ownKeys(Array.prototype).map(String),
      Reflect.ownKeys(Function.prototype).map(String),
    ]);
  const pristine = snapshot();
  const refused = [
    '{"__proto__":{"polluted":"yes"}}',
    '{"constructor":{"prototype":{"polluted":"yes"}}}',
  ];
  const allowed = [
    '{"constructor":{"polluted":"yes"}}',
    '{"prototype":{"polluted":"yes"}}',
    '{"constructor":"polluted","prototype":"polluted"}',
  ];
  // Where a route looks inside the body: settings sections, a source's nested fields, a
  // metric's labels (the one map whose keys a source chooses), a rule, and the connection
  // test's settings. The Prometheus source is complete, so a harmless shape is saved or run.
  const prometheus = '"type":"prometheus","name":"P","apiUrl":"http://192.0.2.10:9100"';
  const labelled = shape => `{${prometheus},"metrics":[{"key":"m","path":"p","labels":${shape}}]}`;
  const places = [
    shape => shape,
    shape => `{"monitoring":${shape}}`,
    shape => `{"alerts":${shape}}`,
    shape => `{"appearance":${shape}}`,
    shape => `{"email":${shape}}`,
    shape => `{"rules":[${shape}]}`,
    shape => `{"settings":${shape}}`,
    shape => `{"settings":{${prometheus},"monitoring":${shape}}}`,
    labelled,
    shape => `{"settings":${labelled(shape)}}`,
  ];
  // These take no body (`body: 'empty'`): anything but nothing or {} is refused before their
  // handler runs (400, or 413 past their 64 bytes), so no shape in it reaches anything.
  const bodiless = [
    'POST /api/refresh',
    'POST /api/auth/logout',
    'DELETE /api/account/sessions',
    'DELETE /api/account/sessions/:id',
    'DELETE /api/services/:id',
  ];
  let sent = 0;
  const reached = new Set();
  for (const route of routes)
    for (const place of places)
      for (const shape of [...refused, ...allowed]) {
        const body = place(shape);
        const line = `${route.method} ${target(route)} HTTP/1.1`;
        // A route that requires If-Match answers 428 before reading the body without one, so
        // it is sent the current revision and reads the body.
        const ifMatch =
          route.ifMatch === 'required' ? [`If-Match: ${app.config.value.revision}`] : [];
        const answer = await raw(port, [line, auth, ...write, sameOrigin, ...ifMatch], body);
        sent++;
        const where = `${line} ${body}`;
        assert.ok(answer.status < 500, `${where} -> ${answer.status} ${answer.body}`);
        const error = answer.status >= 400 ? JSON.parse(answer.body).error : '';
        if (bodiless.includes(`${route.method} ${route.path}`)) {
          assert.ok([400, 413].includes(answer.status), `${where} -> ${answer.status}`);
          assert.match(
            error,
            /^(?:Field name .+ is not allowed|This request takes no body: send nothing or \{\}|Request is too large)$/,
            where
          );
        } else if (refused.includes(shape)) {
          assert.equal(answer.status, 400, where);
          assert.match(error, /^Field name .+ is not allowed$/, where);
        } else {
          // Past the body check, so the route itself handled the shape.
          assert.doesNotMatch(error, /^Field name /, where);
          if (answer.status < 300) reached.add(`${route.method} ${route.path}`);
        }
        assert.equal({}.polluted, undefined, where);
        assert.equal(Object.polluted, undefined, where);
        assert.equal([].polluted, undefined, where);
        assert.equal(snapshot(), pristine, where);
      }
  assert.equal(sent, routes.length * places.length * (refused.length + allowed.length));
  // Some of them were accepted and saved or run, so the probe went beyond validation errors.
  assert.deepEqual([...reached].sort(), [
    'PATCH /api/services/:id',
    'POST /api/services',
    'POST /api/test-service',
  ]);
  // The labels were saved as ordinary own data, and the configuration is ordinary objects.
  const added = app.config.value.services.filter(service => service.type === 'prometheus');
  assert.equal(added.length, 1);
  assert.deepEqual(added[0].metrics[0].labels, { constructor: 'polluted', prototype: 'polluted' });
  for (const service of app.config.value.services) {
    assert.equal(Object.getPrototypeOf(service), Object.prototype);
    for (const metric of service.metrics)
      assert.equal(Object.getPrototypeOf(metric.labels ?? {}), Object.prototype);
  }
});

test('Uptime Goblin refuses two credentials and names each answer with a request id', async t => {
  const { app, port } = await orbit(t, { trustProxy: 'loopback' });
  const both = await raw(port, [
    'GET /api/dashboard HTTP/1.1',
    `Authorization: ${basic()}`,
    `Authorization: ${basic()}`,
  ]);
  assert.equal(both.status, 401);
  assert.equal(JSON.parse(both.body).code, 'multiple_credentials');
  // Named by build (a 1.4.3 tab reloads itself on a build change, D10), not by version.
  assert.equal(both.headers['x-goblin-build'], app.build);
  assert.equal(both.headers['x-goblin-version'], undefined);
  for (let i = 0; i < 10; i++)
    await raw(port, [
      'GET /api/dashboard HTTP/1.1',
      `Authorization: ${basic('wrong')}`,
      `Authorization: ${basic('also-wrong')}`,
    ]);
  // Ten refusals later the right password still works: none of them counted as a guess.
  const one = await raw(port, [
    'GET /api/dashboard HTTP/1.1',
    `Authorization: ${basic()}`,
    'X-Request-Id: nginx-0001',
  ]);
  assert.equal(one.status, 200);
  assert.equal(one.headers['x-request-id'], 'nginx-0001', 'kept from the trusted loopback proxy');
  assert.match(both.headers['x-request-id'], requestIdPattern);
});

test('forward-auth is counted by the one-credential rule but not accepted yet, and never counted as a guess', async t => {
  const { port, loginThrottle } = await serve(t, { routes: table(), forwardAuth: () => true });
  const alone = await raw(port, ['GET /api/thing HTTP/1.1']);
  assert.equal(alone.status, 401);
  assert.equal(JSON.parse(alone.body).code, 'signin_required');
  const both = await raw(port, ['GET /api/thing HTTP/1.1', `Authorization: ${basic()}`]);
  assert.equal(both.status, 401);
  assert.equal(JSON.parse(both.body).code, 'multiple_credentials');
  assert.equal(loginThrottle.size, 0);
});
