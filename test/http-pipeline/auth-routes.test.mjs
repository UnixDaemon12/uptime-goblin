// The sign-in, sign-out, session and account routes (sessions spec §6.2, §6.3, §6.10, §6.11)
// over the in-memory identity: every answer, cookie and throttle decision, without a database.
// test/http-pipeline/sessions.test.mjs runs the same flows through a real Uptime Goblin.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { LoginThrottle } from '../../lib/throttle.mjs';
import { identityError } from '../../lib/identity/errors.mjs';
import {
  basic,
  browserWrite,
  build,
  cookieFrom,
  login,
  password,
  raw,
  serveAuth,
} from './harness.mjs';
import { fakeIdentity, fullWrite } from '../helpers/fake-identity.mjs';

const bodies = JSON.parse(
  fs.readFileSync(new URL('../contract/identity-bodies.json', import.meta.url), 'utf8')
);
const nextPassword = 'fixture-http-lane-next-password';
const loginBody = (extra = {}) => JSON.stringify({ login: 'admin', password, ...extra });

/** The GET /api/session body with its volatile values written as the fixture writes them. */
function shaped(body) {
  return {
    ...body,
    build: body.build === build ? '<build>' : body.build,
    session: body.session && {
      ...body.session,
      id: /^s_[A-Za-z0-9_-]{16}$/.test(body.session.id) ? '<id>' : body.session.id,
      ...Object.fromEntries(
        ['createdAt', 'lastSeenAt', 'expiresAt', 'idleExpiresAt'].map(key => [
          key,
          Number.isSafeInteger(body.session[key]) ? '<ms>' : body.session[key],
        ])
      ),
    },
  };
}

// A request that arrives as the owner's nginx on this host would send it.
const viaProxy = (proto, origin = 'https://goblin.example') => [
  'Host: goblin.example',
  'X-Forwarded-For: 198.51.100.20',
  ...(proto ? [`X-Forwarded-Proto: ${proto}`] : []),
  ...browserWrite(origin),
];

test('sign-in on loopback: 200, the exact cookie, the session body, never replayed', async t => {
  const { port, identity, loginThrottle } = await serveAuth(t);
  const { answer, cookie } = await login(port);
  assert.equal(answer.status, 200);
  const [setCookie] = [].concat(answer.headers['set-cookie']);
  assert.match(
    setCookie,
    /^goblin_session=v1\.[A-Za-z0-9_-]{43}; Path=\/; HttpOnly; SameSite=Strict$/
  );
  assert.equal(answer.headers['cache-control'], 'no-store');
  assert.equal(answer.headers['x-goblin-version'], '1.5.0-test');
  assert.equal(answer.headers['x-goblin-build'], build);
  assert.deepEqual(shaped(answer.json), {
    ...bodies.session.session,
    transport: { kind: 'loopback', https: false, insecure: false, insecureAllowed: false },
  });
  assert.equal(answer.json.session.id, identity.test.rows()[0].id);
  assert.ok(!answer.body.includes(cookie.split('=')[1]), 'the body never holds the secret');
  // The Uptime Goblin host's own lockout key, not an address (D18).
  assert.equal(loginThrottle.trusted('loopback'), true);
  assert.equal(loginThrottle.trusted('127.0.0.1'), false);
  // The cookie works, and GET /api/session answers the same body.
  const current = await raw(port, ['GET /api/session HTTP/1.1', `Cookie: ${cookie}`]);
  assert.equal(current.status, 200);
  assert.deepEqual(shaped(current.json), shaped(answer.json));
});

test('Keep me signed in makes the cookie persistent (Max-Age of 30 days)', async t => {
  const { port } = await serveAuth(t);
  const { answer } = await login(port, { remember: true });
  const [setCookie] = [].concat(answer.headers['set-cookie']);
  assert.match(setCookie, /; Max-Age=2592000$/);
  assert.equal(answer.json.session.persistent, true);
  assert.equal(answer.json.session.expiresAt - answer.json.session.createdAt, 30 * 86400e3);
  const plain = await login(port);
  assert.doesNotMatch([].concat(plain.answer.headers['set-cookie'])[0], /Max-Age/);
  assert.equal(
    plain.answer.json.session.expiresAt - plain.answer.json.session.createdAt,
    7 * 86400e3
  );
});

test('the transport rule: https gets __Host-goblin_session; plain HTTP is refused unless opted in', async t => {
  const secure = await serveAuth(t, {
    trustProxy: 'loopback',
    configuredHosts: ['goblin.example'],
  });
  const https = await raw(
    secure.port,
    ['POST /api/auth/login HTTP/1.1', ...viaProxy('https')],
    loginBody()
  );
  assert.equal(https.status, 200);
  assert.match(
    [].concat(https.headers['set-cookie'])[0],
    /^__Host-goblin_session=v1\.[A-Za-z0-9_-]{43}; Path=\/; Secure; HttpOnly; SameSite=Strict$/
  );
  assert.deepEqual(https.json.transport, {
    kind: 'https',
    https: true,
    insecure: false,
    insecureAllowed: false,
  });
  // The trusted proxy says nothing (or http) about the protocol: refused, not counted.
  for (const proto of [null, 'http']) {
    const refused = await raw(
      secure.port,
      ['POST /api/auth/login HTTP/1.1', ...viaProxy(proto)],
      loginBody()
    );
    assert.equal(refused.status, 403);
    assert.deepEqual(refused.json, bodies['403'].proxy_proto_missing.http);
    assert.equal(refused.headers['set-cookie'], undefined);
  }
  const plainPage = await raw(
    secure.port,
    ['POST /api/auth/login HTTP/1.1', ...viaProxy(null, 'http://goblin.example')],
    loginBody()
  );
  assert.equal(plainPage.status, 403);
  assert.deepEqual(plainPage.json, bodies['403'].https_required.http);
  assert.equal(secure.loginThrottle.size, 0);
  assert.equal(secure.identity.test.checks, 1, 'only the https sign-in checked a password');
  assert.deepEqual(secure.logged, [
    'Sign-in refused: the browser used HTTPS (Origin https://goblin.example) but the request from 127.0.0.1 carries no X-Forwarded-Proto: https. Make the proxy send X-Forwarded-Proto: https (nginx: proxy_set_header X-Forwarded-Proto $scheme;) and make sure GOBLIN_TRUST_PROXY names it, or set GOBLIN_INSECURE_HTTP_SESSIONS=1 until it is fixed.',
  ]);
  // An untrusted proxy's https claim is not believed, and the line says why.
  const untrusted = await serveAuth(t, { configuredHosts: ['goblin.example'] });
  const spoofed = await raw(
    untrusted.port,
    ['POST /api/auth/login HTTP/1.1', ...viaProxy('https')],
    loginBody()
  );
  assert.equal(spoofed.json.code, 'proxy_proto_missing');
  assert.match(untrusted.logged[0], /comes from a proxy that GOBLIN_TRUST_PROXY does not trust\./);
  // With GOBLIN_INSECURE_HTTP_SESSIONS=1 plain HTTP signs in, with the plain cookie.
  const insecure = await serveAuth(t, {
    trustProxy: 'loopback',
    configuredHosts: ['goblin.example'],
    insecureHttpSessions: true,
  });
  for (const origin of ['https://goblin.example', 'http://goblin.example']) {
    const allowed = await raw(
      insecure.port,
      ['POST /api/auth/login HTTP/1.1', ...viaProxy('http', origin)],
      loginBody()
    );
    assert.equal(allowed.status, 200, origin);
    assert.match(
      [].concat(allowed.headers['set-cookie'])[0],
      /^goblin_session=[^;]+; Path=\/; HttpOnly; SameSite=Strict$/
    );
    assert.deepEqual(allowed.json.transport, {
      kind: 'http',
      https: false,
      insecure: true,
      insecureAllowed: true,
    });
    // And the session is read on that transport.
    const cookie = cookieFrom(allowed);
    const again = await raw(insecure.port, [
      'GET /api/session HTTP/1.1',
      `Cookie: ${cookie}`,
      'Host: goblin.example',
      'X-Forwarded-For: 198.51.100.20',
    ]);
    assert.equal(again.status, 200);
  }
});

test('an http page behind a proxy that claims https is refused, whatever the opt-in says (D19)', async t => {
  for (const insecureHttpSessions of [false, true]) {
    const { port, logged, identity } = await serveAuth(t, {
      trustProxy: 'loopback',
      configuredHosts: ['goblin.example'],
      insecureHttpSessions,
    });
    for (let i = 0; i < 3; i++) {
      const refused = await raw(
        port,
        ['POST /api/auth/login HTTP/1.1', ...viaProxy('https', 'http://goblin.example')],
        loginBody()
      );
      assert.equal(refused.status, 403);
      assert.deepEqual(refused.json, bodies['403'].proxy_proto_mismatch.https);
    }
    assert.equal(identity.test.checks, 0);
    assert.deepEqual(logged, [
      'Sign-in refused: the browser used http:// (Origin http://goblin.example) but the trusted proxy 127.0.0.1 sent X-Forwarded-Proto: https. Make it send the real scheme (nginx: proxy_set_header X-Forwarded-Proto $scheme;).',
    ]);
  }
});

test('sign-in: a wrong password is counted, a bad shape is not', async t => {
  const loginThrottle = new LoginThrottle({ freeAttempts: 3, baseMs: 60000 });
  const { port, identity } = await serveAuth(t, { loginThrottle });
  for (const body of ['{}', '[]', '"admin"', JSON.stringify({ login: 'admin', password: 7 })]) {
    const answer = await raw(
      port,
      ['POST /api/auth/login HTTP/1.1', ...browserWrite(`http://127.0.0.1:${port}`)],
      body
    );
    assert.equal(answer.status, 400, body);
    assert.deepEqual(answer.json, {
      error: 'Enter your login name and password.',
      code: 'invalid_request',
    });
  }
  assert.equal(loginThrottle.size, 0);
  for (let i = 0; i < 4; i++) {
    const wrong = await login(port, { password: `wrong-${i}` });
    assert.equal(wrong.answer.status, 401);
    assert.deepEqual(wrong.answer.json, bodies['401'].invalid_credentials.loopback);
    assert.equal(
      wrong.answer.headers['www-authenticate'],
      undefined,
      'a browser is never challenged'
    );
  }
  const locked = await login(port);
  assert.equal(locked.answer.status, 429);
  assert.deepEqual(locked.answer.json, {
    error: 'Too many failed sign-in attempts. Wait before trying again.',
    code: 'locked',
  });
  assert.ok(Number(locked.answer.headers['retry-after']) > 1);
  assert.equal(identity.test.checks, 4, 'the locked attempt checked no password');
});

test('the global lock refuses new forwarded clients but never loopback (D18)', async t => {
  const loginThrottle = new LoginThrottle({ globalFailures: 5 });
  const { port } = await serveAuth(t, {
    loginThrottle,
    trustProxy: 'loopback',
    configuredHosts: ['goblin.example'],
  });
  for (let i = 0; i < 5; i++) loginThrottle.failure(`192.0.2.${i}`);
  const forwarded = await raw(
    port,
    ['POST /api/auth/login HTTP/1.1', ...viaProxy('https')],
    loginBody()
  );
  assert.equal(forwarded.status, 429);
  assert.equal(forwarded.headers['retry-after'], '60');
  assert.equal(forwarded.json.code, 'locked');
  const loopback = await login(port);
  assert.equal(loopback.answer.status, 200);
  // A forwarded client that signed in before (trusted) may still sign in.
  loginThrottle.trust('198.51.100.20');
  assert.equal(
    (await raw(port, ['POST /api/auth/login HTTP/1.1', ...viaProxy('https')], loginBody())).status,
    200
  );
});

test('busy and full-disk refusals: a client’s own burst counts, a full queue or disk does not', async t => {
  const identity = fakeIdentity({ password });
  const loginThrottle = new LoginThrottle();
  const counted = [];
  const failure = loginThrottle.failure.bind(loginThrottle);
  loginThrottle.failure = key => {
    counted.push(key);
    failure(key);
  };
  const { port } = await serveAuth(t, { identity, loginThrottle });
  identity.test.saturated = true;
  const queue = await login(port);
  assert.equal(queue.answer.status, 429);
  assert.equal(queue.answer.json.code, 'busy');
  assert.equal(queue.answer.headers['retry-after'], '5');
  identity.test.saturated = false;
  identity.test.beforeWrite = fullWrite;
  const full = await login(port);
  assert.equal(full.answer.status, 503);
  assert.deepEqual(full.answer.json, {
    error:
      "Uptime Goblin's disk is full, so it cannot save your sign-in or password change. Anyone already signed in stays signed in. Free some space on the Uptime Goblin host, then try again.",
    code: 'storage_full',
  });
  assert.equal(full.answer.headers['retry-after'], '30');
  identity.test.beforeWrite = null;
  assert.deepEqual(counted, []);
  // Parallel sign-ins beyond the free attempts are refused by admit, and counted.
  let open;
  identity.test.gate = new Promise(resolve => (open = resolve));
  const burst = Array.from({ length: 8 }, (_, i) => login(port, { password: `guess-${i}` }));
  await new Promise(resolve => setTimeout(resolve, 100));
  open();
  identity.test.gate = null;
  const answers = await Promise.all(burst);
  assert.ok(answers.some(({ answer }) => answer.json.code === 'busy'));
  assert.equal(counted.length, 8);
});

test('signing in rotates the presented session; on https it also ends the plain-HTTP cookie', async t => {
  const { port, identity } = await serveAuth(t, {
    trustProxy: 'loopback',
    configuredHosts: ['goblin.example'],
  });
  const first = await login(port);
  const second = await login(port, { lines: [`Cookie: ${first.cookie}`] });
  assert.equal(second.answer.status, 200);
  assert.equal(identity.test.rows().length, 1, 'the presented session was replaced');
  const old = await raw(port, ['GET /api/session HTTP/1.1', `Cookie: ${first.cookie}`]);
  assert.equal(old.status, 401);
  assert.deepEqual(old.json, bodies['401'].session_expired.loopback);
  // Moving to https: the insecure cookie is expired in the browser and its row revoked.
  const https = await raw(
    port,
    ['POST /api/auth/login HTTP/1.1', ...viaProxy('https'), `Cookie: ${second.cookie}`],
    loginBody()
  );
  assert.equal(https.status, 200);
  const cookies = [].concat(https.headers['set-cookie']);
  assert.equal(cookies.length, 2);
  assert.match(cookies[0], /^__Host-goblin_session=v1\./);
  assert.equal(cookies[1], 'goblin_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0');
  assert.equal(identity.test.rows().length, 1);
  assert.equal(
    (await raw(port, ['GET /api/session HTTP/1.1', `Cookie: ${second.cookie}`])).status,
    401
  );
  // A value that is not one of the admin's sessions is simply ignored by the rotation.
  const planted = await login(port, { lines: [`Cookie: goblin_session=v1.${'A'.repeat(43)}`] });
  assert.equal(planted.answer.status, 200);
});

test('logout: 204, the cookie expired, the cache cleared; the old cookie is refused', async t => {
  const { port, identity } = await serveAuth(t);
  const { cookie } = await login(port);
  const out = await raw(port, [
    'POST /api/auth/logout HTTP/1.1',
    `Cookie: ${cookie}`,
    ...browserWrite(`http://127.0.0.1:${port}`),
  ]);
  assert.equal(out.status, 204);
  assert.deepEqual([].concat(out.headers['set-cookie']), [
    'goblin_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0',
  ]);
  assert.equal(out.headers['clear-site-data'], '"cache"');
  assert.equal(out.headers['cache-control'], 'no-store');
  assert.equal(out.body, '');
  assert.deepEqual(identity.test.rows(), []);
  const after = await raw(port, [
    'GET /api/session HTTP/1.1',
    `Cookie: ${cookie}`,
    'Sec-Fetch-Site: same-origin',
  ]);
  assert.equal(after.status, 401);
  assert.deepEqual(after.json, bodies['401'].session_expired.loopback);
  assert.equal(after.headers['www-authenticate'], undefined);
  // Logout is a write: from another site it is refused before anything happens.
  const second = await login(port);
  const forged = await raw(port, [
    'POST /api/auth/logout HTTP/1.1',
    `Cookie: ${second.cookie}`,
    ...browserWrite('https://evil.test'),
  ]);
  assert.equal(forged.status, 403);
  assert.equal(identity.test.rows().length, 1);
});

test('a logout whose write fails keeps the cookie and does not answer as a sign-out: the page and the journal say so; sent again, it finishes', async t => {
  // The session is refused at once, but its row is still in control.sqlite until something
  // deletes it, and a restart before that would accept it again: no 204 (§16 C2). The cookie
  // stays, so that the same sign-out sent again can name the session and delete it (§20 H1).
  const { port, identity, logged } = await serveAuth(t);
  const originalError = console.error;
  t.after(() => (console.error = originalError));
  console.error = () => {};
  for (const [failure, status, code] of [
    [() => Object.assign(new Error('disk I/O error'), { code: 'SQLITE_IOERR' }), 500, undefined],
    [() => identityError('storage_full', { variant: 'signout' }), 503, 'storage_full'],
  ]) {
    logged.length = 0;
    const { cookie } = await login(port);
    const logout = () =>
      raw(port, [
        'POST /api/auth/logout HTTP/1.1',
        `Cookie: ${cookie}`,
        ...browserWrite(`http://127.0.0.1:${port}`),
      ]);
    identity.test.beforeWrite = () => {
      throw failure();
    };
    const out = await logout();
    identity.test.beforeWrite = null;
    assert.equal(out.status, status);
    assert.equal(out.json.code, code);
    // The browser keeps its cookie: it is what names the session to a retry.
    assert.equal(out.headers['set-cookie'], undefined);
    assert.equal(out.headers['clear-site-data'], '"cache"');
    assert.equal(out.headers['cache-control'], 'no-store');
    if (code) {
      assert.equal(out.headers['retry-after'], '30');
      assert.match(out.json.error, /could not record this sign-out/);
    }
    assert.equal(logged.length, 1);
    assert.match(
      logged[0],
      /^Signing out could not be saved: the session is refused until Uptime Goblin restarts, and Uptime Goblin retries removing it hourly and when it stops: /
    );
    assert.equal((await raw(port, ['GET /api/session HTTP/1.1', `Cookie: ${cookie}`])).status, 401);
    assert.equal(identity.test.rows().length, 1, 'still stored');
    // Sent again: the cookie no longer signs in, but it still names the session, which ends.
    const again = await logout();
    assert.equal(again.status, 204);
    assert.deepEqual([].concat(again.headers['set-cookie']), [
      'goblin_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0',
    ]);
    assert.equal(again.headers['clear-site-data'], '"cache"');
    assert.equal(again.headers['x-goblin-version'], undefined);
    assert.deepEqual(identity.test.rows(), []);
    // Nothing stored under it any more: the 401 a signed-out cookie always got.
    const gone = await logout();
    assert.equal(gone.status, 401);
    assert.deepEqual(gone.json, bodies['401'].session_expired.loopback);
    assert.equal(gone.headers['set-cookie'], undefined);
  }
});

test('a logout with a session cookie that no longer signs in is held to the strict CSRF and JSON rules, and only on that route', async t => {
  // §20 H1: the retry of a sign-out whose delete failed runs without a signed-in access, so,
  // as for multipleSessions, only Uptime Goblin's own page may send it; any other route answers the
  // 401 as before, and the cookie ends nothing there.
  const { port, identity } = await serveAuth(t);
  const originalError = console.error;
  t.after(() => (console.error = originalError));
  console.error = () => {};
  const self = `http://127.0.0.1:${port}`;
  const { cookie } = await login(port);
  identity.test.beforeWrite = () => {
    throw identityError('storage_full', { variant: 'signout' });
  };
  const failed = await raw(port, [
    'POST /api/auth/logout HTTP/1.1',
    `Cookie: ${cookie}`,
    ...browserWrite(self),
  ]);
  identity.test.beforeWrite = null;
  assert.equal(failed.status, 503);
  const send = (lines, body = '{}') =>
    raw(port, ['POST /api/auth/logout HTTP/1.1', `Cookie: ${cookie}`, ...lines], body);
  const refusals = [
    [browserWrite('https://evil.test'), 403],
    [browserWrite(self).filter(line => !line.startsWith('Origin:')), 403],
    [browserWrite(self).filter(line => !line.startsWith('X-Goblin-Request:')), 403],
    [
      browserWrite(self).map(line =>
        line.startsWith('Sec-Fetch') ? 'Sec-Fetch-Site: same-site' : line
      ),
      403,
    ],
    [
      browserWrite(self).map(line =>
        line.startsWith('Content-Type') ? 'Content-Type: text/plain' : line
      ),
      415,
    ],
  ];
  for (const [lines, status] of refusals) {
    const refused = await send(lines);
    assert.equal(refused.status, status, lines.join(' | '));
    assert.equal(refused.headers['set-cookie'], undefined);
    assert.equal(identity.test.rows().length, 1, 'nothing ended');
  }
  // Another write signed in by session is not a sign-out: the cookie ends nothing there.
  const other = await raw(
    port,
    ['DELETE /api/account/sessions HTTP/1.1', `Cookie: ${cookie}`, ...browserWrite(self)],
    '{}'
  );
  assert.deepEqual([other.status, other.json.code], [401, 'session_expired']);
  assert.equal(identity.test.rows().length, 1);
  // From Uptime Goblin's own page it finishes.
  assert.equal((await send(browserWrite(self))).status, 204);
  assert.deepEqual(identity.test.rows(), []);
});

test('a logout sent with two session cookies ends every session among them, or says it could not', async t => {
  // One of the two is another site's (§19 G1): nothing tells them apart, so the request is not
  // signed in, but the sign-out still ends what the browser holds and expires Uptime Goblin's cookie.
  const { port, identity, logged } = await serveAuth(t);
  const originalError = console.error;
  t.after(() => (console.error = originalError));
  console.error = () => {};
  const origin = `http://127.0.0.1:${port}`;
  const logout = cookies =>
    raw(port, ['POST /api/auth/logout HTTP/1.1', `Cookie: ${cookies}`, ...browserWrite(origin)]);
  const { cookie } = await login(port);
  const planted = `goblin_session=v1.${'A'.repeat(43)}`;
  const out = await logout(`${planted}; ${cookie}`);
  assert.equal(out.status, 200);
  assert.equal(out.json.signedOut, true);
  assert.equal(out.json.code, 'multiple_credentials');
  assert.deepEqual([].concat(out.headers['set-cookie']), [
    'goblin_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0',
  ]);
  assert.equal(out.headers['clear-site-data'], '"cache"');
  assert.deepEqual(identity.test.rows(), []);
  // The operator still learns that a browser sends two cookies of Uptime Goblin's name.
  assert.equal(logged.length, 1);
  assert.match(logged[0], /^A browser sent two goblin_session cookies/);
  // Nothing of the admin's among them: still a sign-out of this browser's side.
  const none = await logout(`${planted}; goblin_session=x`);
  assert.equal(none.status, 200);
  assert.equal(none.json.code, 'multiple_credentials');
  // A failed delete answers as any sign-out's: the cookie stays, the error says so, and the
  // same sign-out sent again (both cookies come again) finishes it (§20 H1).
  for (const [failure, status, code] of [
    [() => Object.assign(new Error('disk I/O error'), { code: 'SQLITE_IOERR' }), 500, undefined],
    [() => identityError('storage_full', { variant: 'signout' }), 503, 'storage_full'],
  ]) {
    logged.length = 0;
    const again = await login(port);
    identity.test.beforeWrite = () => {
      throw failure();
    };
    const failed = await logout(`${planted}; ${again.cookie}`);
    identity.test.beforeWrite = null;
    assert.equal(failed.status, status);
    assert.equal(failed.json.code, code);
    assert.equal(failed.headers['set-cookie'], undefined);
    assert.equal(failed.headers['clear-site-data'], '"cache"');
    assert.ok(logged.some(line => /^Signing out could not be saved: /.test(line)));
    // Refused at once all the same (fail closed).
    assert.equal(
      (await raw(port, ['GET /api/session HTTP/1.1', `Cookie: ${again.cookie}`])).status,
      401
    );
    assert.equal(identity.test.rows().length, 1, 'still stored');
    const retried = await logout(`${planted}; ${again.cookie}`);
    assert.deepEqual([retried.status, retried.json.code], [200, 'multiple_credentials']);
    assert.deepEqual([].concat(retried.headers['set-cookie']), [
      'goblin_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0',
    ]);
    assert.deepEqual(identity.test.rows(), []);
  }
});

test('GET /api/session for Basic; 401 when signed out, also with Basic off', async t => {
  const { port } = await serveAuth(t);
  const scripted = await raw(port, ['GET /api/session HTTP/1.1', `Authorization: ${basic()}`]);
  assert.equal(scripted.status, 200);
  assert.deepEqual(shaped(scripted.json), bodies.session.basic);
  const out = await raw(port, ['GET /api/session HTTP/1.1']);
  assert.equal(out.status, 401);
  assert.deepEqual(out.json, bodies['401'].signin_required.loopback);
  // A header-less request from this computer is not signed in, with Basic on or off (1.4.x's
  // passwordless local preview signed it in).
  const noBasic = await serveAuth(t, { legacyBasic: false });
  const bare = await raw(noBasic.port, ['GET /api/session HTTP/1.1']);
  assert.equal(bare.status, 401);
  assert.deepEqual(bare.json, bodies['401'].signin_required.loopback);
  // Basic logout: nothing to revoke.
  const basicOut = await raw(port, [
    'POST /api/auth/logout HTTP/1.1',
    `Authorization: ${basic()}`,
    'X-Goblin-Request: 1',
    'Content-Type: application/json',
  ]);
  assert.equal(basicOut.status, 204);
});

test('the error bodies are those of the contract fixture, per code and transport', async t => {
  // Shared by the servers below, one of which allows plain-HTTP sessions.
  const identity = fakeIdentity({ password, insecureHttpSessions: true });
  const scripts = await serveAuth(t, {
    identity,
    trustProxy: 'loopback',
    configuredHosts: ['goblin.example'],
  });
  const noBasic = await serveAuth(t, {
    identity,
    legacyBasic: false,
    trustProxy: 'loopback',
    configuredHosts: ['goblin.example'],
  });
  const insecure = await serveAuth(t, {
    identity,
    trustProxy: 'loopback',
    configuredHosts: ['goblin.example'],
    insecureHttpSessions: true,
  });
  const transports = {
    https: ['Host: goblin.example', 'X-Forwarded-For: 198.51.100.1', 'X-Forwarded-Proto: https'],
    loopback: [],
    http: ['Host: goblin.example', 'X-Forwarded-For: 198.51.100.1'],
  };
  const origins = { https: 'https://goblin.example', http: 'http://goblin.example' };
  const originFor = (kind, port) => origins[kind] ?? `http://127.0.0.1:${port}`;
  for (const [kind, lines] of Object.entries(transports)) {
    const get = (server, extra) =>
      raw(server.port, ['GET /api/thing HTTP/1.1', ...lines, ...extra]);
    // On http a Basic credential reaches the password check only with
    // GOBLIN_INSECURE_HTTP_SESSIONS=1, as a session does; without it, the refusal below.
    const basicServer = kind === 'http' ? insecure : scripts;
    const seen = {
      signin_required: await get(scripts, []),
      'invalid_credentials/basic': await get(basicServer, [`Authorization: ${basic('nope')}`]),
      multiple_credentials: await get(scripts, [
        `Authorization: ${basic()}`,
        `Authorization: ${basic()}`,
      ]),
      basic_disabled: await get(noBasic, [`Authorization: ${basic()}`]),
    };
    const sessionServer = kind === 'http' ? insecure : scripts;
    const name = kind === 'https' ? '__Host-goblin_session' : 'goblin_session';
    seen.session_expired = await get(sessionServer, [`Cookie: ${name}=v1.${'B'.repeat(43)}`]);
    seen.invalid_credentials = await raw(
      sessionServer.port,
      [
        'POST /api/auth/login HTTP/1.1',
        ...lines,
        ...browserWrite(originFor(kind, sessionServer.port)),
      ],
      loginBody({ password: 'wrong password here' })
    );
    for (const [code, answer] of Object.entries(seen)) {
      assert.equal(answer.status, 401, `${code} ${kind}`);
      assert.deepEqual(answer.json, bodies['401'][code][kind], `${code} ${kind}`);
    }
    if (kind === 'http') {
      // Without the opt-in, Basic on plain HTTP gets the refusal a sign-in gets there, before
      // its password is checked; and no 401 there offers the Basic challenge.
      for (const password of [undefined, 'nope']) {
        const refused = await get(scripts, [`Authorization: ${basic(password)}`]);
        assert.equal(refused.status, 403, `Basic ${password ?? 'right'} password on http`);
        assert.deepEqual(refused.json, bodies['403'].https_required.http);
        assert.equal(refused.headers['www-authenticate'], undefined);
      }
      assert.equal(seen.signin_required.headers['www-authenticate'], undefined);
      assert.match(seen['invalid_credentials/basic'].headers['www-authenticate'], /^Basic /);
    } else assert.match(seen.signin_required.headers['www-authenticate'], /^Basic /);
    const crossOrigin = await raw(
      basicServer.port,
      [
        'POST /api/thing HTTP/1.1',
        ...lines,
        `Authorization: ${basic()}`,
        'X-Goblin-Request: 1',
        'Content-Type: application/json',
        'Origin: https://evil.test',
      ],
      '{}'
    );
    assert.deepEqual(crossOrigin.json, bodies['403'].cross_origin[kind], kind);
  }
  // Every 401 and 403 code in the fixture is one of identity's codes.
  const { errorCodes } = await import('../../lib/identity/errors.mjs');
  for (const status of ['401', '403'])
    for (const [key, byKind] of Object.entries(bodies[status]))
      for (const body of Object.values(byKind)) {
        const code = key.split('/')[0];
        assert.equal(body.code, code);
        assert.equal(errorCodes[code].status, Number(status), key);
        assert.ok(Object.values(errorCodes[code].messages).includes(body.error), key);
      }
});

test('password change: rotates this session, signs out the others, counts a wrong current password', async t => {
  const loginThrottle = new LoginThrottle({ freeAttempts: 2, baseMs: 60000 });
  const { port, identity } = await serveAuth(t, { loginThrottle });
  const self = `http://127.0.0.1:${port}`;
  const mine = await login(port, { remember: true });
  const other = await login(port);
  const change = (cookie, input, route = '/api/account/password') =>
    raw(
      port,
      [`POST ${route} HTTP/1.1`, `Cookie: ${cookie}`, ...browserWrite(self)],
      JSON.stringify(input)
    );
  const input = {
    currentPassword: password,
    password: nextPassword,
    confirmPassword: nextPassword,
  };
  const wrong = await change(mine.cookie, { ...input, currentPassword: 'not the password at all' });
  assert.equal(wrong.status, 403);
  assert.deepEqual(wrong.json, bodies['403'].current_password_incorrect.loopback);
  assert.equal(loginThrottle.size, 1, 'a wrong current password counts');
  for (const [bad, code] of [
    [{ ...input, password: 'short', confirmPassword: 'short' }, 'password_invalid'],
    [{ ...input, confirmPassword: 'something else entirely' }, 'password_mismatch'],
    [{ password: nextPassword }, 'invalid_request'],
  ]) {
    const refused = await change(mine.cookie, bad);
    assert.equal(refused.status, 400, code);
    assert.equal(refused.json.code, code);
  }
  assert.equal(loginThrottle.size, 1, 'shape errors do not count');
  const changed = await change(mine.cookie, input);
  assert.equal(changed.status, 200);
  assert.deepEqual(changed.json, {
    ok: true,
    revokedOtherSessions: 1,
    mirrorPending: false,
    reauthenticate: false,
  });
  const [rotated] = [].concat(changed.headers['set-cookie']);
  assert.match(
    rotated,
    /^goblin_session=v1\.[A-Za-z0-9_-]{43}; Path=\/; HttpOnly; SameSite=Strict; Max-Age=\d+$/
  );
  const fresh = rotated.split(';')[0];
  assert.notEqual(fresh, mine.cookie);
  assert.equal(loginThrottle.size, 0, 'the verified change cleared the failure');
  for (const old of [mine.cookie, other.cookie])
    assert.equal((await raw(port, ['GET /api/session HTTP/1.1', `Cookie: ${old}`])).status, 401);
  assert.equal((await raw(port, ['GET /api/session HTTP/1.1', `Cookie: ${fresh}`])).status, 200);
  // The deprecated 1.4.x address answers the same, and says it is deprecated.
  identity.test.mirrorFails = true;
  const alias = await change(
    fresh,
    {
      currentPassword: nextPassword,
      password: password,
      confirmPassword: password,
    },
    '/api/auth/password'
  );
  assert.equal(alias.status, 200);
  assert.equal(alias.headers.deprecation, '@1790812800');
  assert.equal(alias.json.mirrorPending, true);
  assert.equal(alias.json.revokedOtherSessions, 0);
});

test('password change refusals: lockout re-check, busy, a change in progress, full disk, no credential', async t => {
  const loginThrottle = new LoginThrottle({ freeAttempts: 1, baseMs: 60000 });
  const identity = fakeIdentity({ password });
  const { port } = await serveAuth(t, { loginThrottle, identity });
  const self = `http://127.0.0.1:${port}`;
  const { cookie } = await login(port);
  const change = input =>
    raw(
      port,
      ['POST /api/account/password HTTP/1.1', `Cookie: ${cookie}`, ...browserWrite(self)],
      JSON.stringify(input)
    );
  const input = {
    currentPassword: password,
    password: nextPassword,
    confirmPassword: nextPassword,
  };
  const counted = [];
  const failure = loginThrottle.failure.bind(loginThrottle);
  loginThrottle.failure = key => {
    counted.push(key);
    failure(key);
  };
  identity.test.saturated = true;
  assert.equal((await change(input)).json.code, 'busy');
  identity.test.saturated = false;
  identity.test.beforeWrite = fullWrite;
  const full = await change(input);
  assert.equal(full.status, 503);
  assert.equal(full.json.code, 'storage_full');
  identity.test.beforeWrite = () => {
    throw identityError('change_in_progress');
  };
  const busy = await change(input);
  assert.equal(busy.status, 429);
  assert.equal(busy.json.code, 'change_in_progress');
  assert.equal(busy.headers['retry-after'], '5');
  identity.test.beforeWrite = null;
  assert.deepEqual(counted, [], 'none of these checked a wrong password');
  // A locked client is refused after the body arrives, before any password work.
  loginThrottle.failure('loopback');
  loginThrottle.failure('loopback');
  const checks = identity.test.checks;
  const locked = await change(input);
  assert.equal(locked.status, 429);
  assert.equal(locked.json.code, 'locked');
  assert.equal(identity.test.checks, checks);
  // Without a credential the change is not signed in.
  const none = await raw(
    port,
    ['POST /api/account/password HTTP/1.1', ...browserWrite(self)],
    JSON.stringify(input)
  );
  assert.equal(none.status, 401);
  assert.deepEqual(none.json, bodies['401'].signin_required.loopback);
});

test('password change: during the global lock only a client that proved the password, or the host, may try', async t => {
  // The current password is checked here, so a session (a lost device, a copied cookie) must
  // not be a way around the global lock that sign-in itself is held to.
  const loginThrottle = new LoginThrottle({ globalFailures: 5 });
  const identity = fakeIdentity({ password });
  const { port } = await serveAuth(t, {
    loginThrottle,
    identity,
    trustProxy: 'loopback',
    configuredHosts: ['goblin.example'],
  });
  const { issue } = await identity.login({ login: 'admin', password, transport: 'https' });
  const change = (lines, input) =>
    raw(
      port,
      ['POST /api/account/password HTTP/1.1', ...lines],
      JSON.stringify({ password: nextPassword, confirmPassword: nextPassword, ...input })
    );
  const proxied = [`Cookie: __Host-goblin_session=${issue.value}`, ...viaProxy('https')];
  for (let i = 0; i < 5; i++) loginThrottle.failure(`192.0.2.${i}`);
  assert.equal(loginThrottle.globalLocked(), true);
  const checks = identity.test.checks;
  const held = await change(proxied, { currentPassword: 'a guess' });
  assert.deepEqual([held.status, held.json.code], [429, 'locked']);
  assert.equal(held.headers['retry-after'], '60');
  assert.equal(identity.test.checks, checks, 'no password was checked');
  // The same session, from a client that signed in with the password recently: checked.
  loginThrottle.trust('198.51.100.20');
  const wrong = await change(proxied, { currentPassword: 'a guess' });
  assert.equal(wrong.json.code, 'current_password_incorrect');
  // The Uptime Goblin host itself (D18) is never held by the global lock.
  const host = await login(port);
  const local = await change(
    [`Cookie: ${host.cookie}`, ...browserWrite(`http://127.0.0.1:${port}`)],
    {
      currentPassword: 'another guess',
    }
  );
  assert.equal(local.json.code, 'current_password_incorrect');
});

test('signing out over https also ends the plain-HTTP session the browser presents, if it is the admin’s', async t => {
  const identity = fakeIdentity({ password, insecureHttpSessions: true });
  const { port } = await serveAuth(t, {
    identity,
    insecureHttpSessions: true,
    trustProxy: 'loopback',
    configuredHosts: ['goblin.example'],
  });
  for (const route of ['logout', 'delete']) {
    const secure = await identity.login({ login: 'admin', password, transport: 'https' });
    const plain = await identity.login({ login: 'admin', password, transport: 'http' });
    const other = await identity.login({ login: 'admin', password, transport: 'http' });
    const cookies = `Cookie: __Host-goblin_session=${secure.issue.value}; goblin_session=${plain.issue.value}`;
    const out = await raw(port, [
      route === 'logout'
        ? 'POST /api/auth/logout HTTP/1.1'
        : `DELETE /api/account/sessions/${secure.access.sessionId} HTTP/1.1`,
      cookies,
      ...viaProxy('https'),
    ]);
    assert.equal(out.status, 204, route);
    assert.equal([].concat(out.headers['set-cookie']).length, 2, route);
    assert.deepEqual(
      identity.test.rows().map(row => row.id),
      [other.access.sessionId],
      `${route}: both of this browser’s sessions ended, another device’s did not`
    );
    await identity.logout(other.access);
  }
  // A plain-HTTP cookie that is unknown, or presented twice, is only expired.
  const secure = await identity.login({ login: 'admin', password, transport: 'https' });
  const out = await raw(port, [
    'POST /api/auth/logout HTTP/1.1',
    `Cookie: __Host-goblin_session=${secure.issue.value}; goblin_session=v1.${'A'.repeat(43)}`,
    ...viaProxy('https'),
  ]);
  assert.equal(out.status, 204);
  assert.deepEqual(identity.test.rows(), []);
});

test('a Basic password change answers reauthenticate: true and sets no cookie', async t => {
  const { port } = await serveAuth(t);
  const answer = await raw(
    port,
    [
      'POST /api/account/password HTTP/1.1',
      `Authorization: ${basic()}`,
      'X-Goblin-Request: 1',
      'Content-Type: application/json',
    ],
    JSON.stringify({
      currentPassword: password,
      password: nextPassword,
      confirmPassword: nextPassword,
    })
  );
  assert.equal(answer.status, 200);
  assert.deepEqual(answer.json, {
    ok: true,
    revokedOtherSessions: 0,
    mirrorPending: false,
    reauthenticate: true,
  });
  assert.equal(answer.headers['set-cookie'], undefined);
  assert.equal(
    (await raw(port, ['GET /api/thing HTTP/1.1', `Authorization: ${basic()}`])).status,
    401,
    'the old password is refused'
  );
  assert.equal(
    (await raw(port, ['GET /api/thing HTTP/1.1', `Authorization: ${basic(nextPassword)}`])).status,
    200
  );
});

test('sessions: list, sign out one, sign out the others, sign out this one', async t => {
  const { port, identity } = await serveAuth(t);
  const self = `http://127.0.0.1:${port}`;
  // This device signs in last: a session ends only those that signed in no later than it.
  const a = await login(port);
  const b = await login(port);
  const mine = await login(port, { lines: ['User-Agent: fixture browser/1.0'] });
  const as = cookie => [`Cookie: ${cookie}`, ...browserWrite(self)];
  const list = await raw(port, ['GET /api/account/sessions HTTP/1.1', `Cookie: ${mine.cookie}`]);
  assert.equal(list.status, 200);
  assert.equal(list.json.sessions.length, 3);
  assert.equal(list.json.sessions[0].current, true);
  assert.equal(list.json.sessions[0].userAgent, 'fixture browser/1.0');
  assert.equal(
    list.json.sessions[0].client,
    'loopback',
    'signed in on the Uptime Goblin host itself'
  );
  assert.ok(!list.body.includes('token_hash') && !list.body.includes(mine.cookie.split('=')[1]));
  const missing = await raw(port, [
    'DELETE /api/account/sessions/s_AAAAAAAAAAAAAAAA HTTP/1.1',
    ...as(mine.cookie),
  ]);
  assert.equal(missing.status, 404);
  assert.deepEqual(missing.json, { error: 'Session not found', code: 'not_found' });
  const one = await raw(port, [
    `DELETE /api/account/sessions/${a.answer.json.session.id} HTTP/1.1`,
    ...as(mine.cookie),
  ]);
  assert.equal(one.status, 204);
  assert.equal(one.headers['set-cookie'], undefined, 'another device: this cookie stays');
  assert.equal((await raw(port, ['GET /api/session HTTP/1.1', `Cookie: ${a.cookie}`])).status, 401);
  const others = await raw(port, ['DELETE /api/account/sessions HTTP/1.1', ...as(mine.cookie)]);
  assert.equal(others.status, 200);
  assert.deepEqual(others.json, { revoked: 1, kept: 0 });
  assert.equal((await raw(port, ['GET /api/session HTTP/1.1', `Cookie: ${b.cookie}`])).status, 401);
  const own = await raw(port, [
    `DELETE /api/account/sessions/${mine.answer.json.session.id} HTTP/1.1`,
    ...as(mine.cookie),
  ]);
  assert.equal(own.status, 204);
  assert.deepEqual([].concat(own.headers['set-cookie']), [
    'goblin_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0',
  ]);
  assert.equal(own.headers['clear-site-data'], '"cache"');
  assert.deepEqual(identity.test.rows(), []);
});
