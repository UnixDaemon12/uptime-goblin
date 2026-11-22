// Legacy HTTP Basic (sessions spec §6.4, §6.5, §6.8): scripts keep signing in with it while it
// is on; a browser request (Sec-Fetch-Site or X-Goblin-Client) never does, so a browser that
// cached 1.4.x credentials can neither be prompted nor lock anyone out where it sends those
// headers. To a plain-HTTP address on the network (not localhost, 127.x or [::1]) it sends no
// Sec-Fetch-Site, and its requests are a script's there.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { LoginThrottle } from '../../lib/throttle.mjs';
import { identityError } from '../../lib/identity/errors.mjs';
import { basic, login, password, raw, serveAuth } from './harness.mjs';
import { fakeIdentity } from '../helpers/fake-identity.mjs';
import { fakeAudit } from '../helpers/fake-audit.mjs';

test('1,000 browser requests with a wrong Basic header lock nobody out and prompt no one (T22)', async t => {
  for (const context of ['Sec-Fetch-Site: same-origin', 'X-Goblin-Client: web/0123456789ab']) {
    const { port, identity, loginThrottle } = await serveAuth(t);
    const wrong = `Authorization: ${basic('a guessed password')}`;
    const statuses = new Map();
    for (let batch = 0; batch < 20; batch++)
      await Promise.all(
        Array.from({ length: 50 }, async () => {
          const answer = await raw(port, ['GET /api/thing HTTP/1.1', wrong, context]);
          statuses.set(answer.status, (statuses.get(answer.status) ?? 0) + 1);
          assert.equal(answer.headers['www-authenticate'], undefined);
          assert.deepEqual(answer.json, {
            error: 'Sign in to Uptime Goblin.',
            code: 'signin_required',
            transport: { kind: 'loopback', insecureAllowed: false },
          });
        })
      );
    assert.deepEqual([...statuses], [[401, 1000]], context);
    assert.equal(identity.test.checks, 0, 'no password was checked');
    assert.equal(loginThrottle.size, 0, 'nothing was counted');
    assert.equal(loginThrottle.globalLocked(), false);
    // The owner signs in at once from the same address.
    const { answer } = await login(port);
    assert.equal(answer.status, 200, context);
    // A script from the same address is not locked either.
    assert.equal(
      (await raw(port, ['GET /api/thing HTTP/1.1', `Authorization: ${basic()}`])).status,
      200
    );
  }
});

test('a browser with cached Basic and a valid session is signed in by the session', async t => {
  const { port } = await serveAuth(t);
  const { cookie } = await login(port);
  for (const cached of [basic(), basic('an old password')]) {
    const answer = await raw(port, [
      'GET /api/thing HTTP/1.1',
      `Authorization: ${cached}`,
      `Cookie: ${cookie}`,
      'Sec-Fetch-Site: same-origin',
    ]);
    assert.equal(answer.status, 200);
    assert.equal(answer.json.via, 'session');
    assert.equal(answer.headers.deprecation, undefined, 'not a Basic answer');
  }
});

test('scripts still get the challenge and, signed in, the deprecation headers', async t => {
  const { port, loginThrottle } = await serveAuth(t);
  const refused = await raw(port, ['GET /api/thing HTTP/1.1']);
  assert.equal(refused.status, 401);
  assert.equal(refused.headers['www-authenticate'], 'Basic realm="Orbit", charset="UTF-8"');
  assert.equal(refused.json.code, 'signin_required');
  const wrong = await raw(port, ['GET /api/thing HTTP/1.1', `Authorization: ${basic('nope')}`]);
  assert.equal(wrong.status, 401);
  assert.deepEqual(wrong.json, {
    error: 'Sign in to Uptime Goblin.',
    code: 'invalid_credentials',
    transport: { kind: 'loopback', insecureAllowed: false },
  });
  assert.equal(wrong.headers['www-authenticate'], 'Basic realm="Orbit", charset="UTF-8"');
  const ok = await raw(port, ['GET /api/thing HTTP/1.1', `Authorization: ${basic()}`]);
  assert.equal(ok.status, 200);
  assert.equal(ok.json.via, 'basic');
  assert.equal(ok.headers.deprecation, '@1790812800');
  assert.equal(ok.headers.link, '</api/docs?doc=authentication>; rel="deprecation"');
  assert.equal(ok.headers['x-goblin-version'], '1.5.0-test');
  // The verified sign-in cleared the failure the wrong password counted.
  assert.equal(loginThrottle.size, 0);
  assert.equal(loginThrottle.trusted('loopback'), true, 'the Uptime Goblin host’s own key (D18)');
});

// The maintainer's decision (2026-11-12): Basic sends the password itself with every request, so on the
// plain-HTTP transport it takes exactly the sessions' opt-in, GOBLIN_INSECURE_HTTP_SESSIONS=1.
// Without it, the refusal a sign-in gets there (403 https_required), before the password is
// checked: not a guess, not challenged, counted into auth.basic.failed. Loopback and HTTPS through
// a trusted proxy are unchanged.
test('legacy Basic on the plain-HTTP transport follows GOBLIN_INSECURE_HTTP_SESSIONS, as sessions do', async t => {
  // Plain HTTP: a trusted proxy on this host that names the client but not the protocol, and a
  // request for Uptime Goblin's public name from this host with no forwarding header (a proxy that
  // sends none). `https`: the trusted proxy says the browser used HTTPS.
  const plain = [
    ['Host: goblin.example', 'X-Forwarded-For: 198.51.100.7'],
    ['Host: goblin.example'],
  ];
  const https = [
    'Host: goblin.example',
    'X-Forwarded-For: 198.51.100.7',
    'X-Forwarded-Proto: https',
  ];
  const get = (port, lines, secret) =>
    raw(port, ['GET /api/thing HTTP/1.1', ...lines, `Authorization: ${basic(secret)}`]);
  for (const insecureHttpSessions of [false, true]) {
    const audit = fakeAudit();
    const { port, identity, loginThrottle, logged } = await serveAuth(t, {
      insecureHttpSessions,
      trustProxy: 'loopback',
      configuredHosts: ['goblin.example'],
      audit,
    });
    for (const lines of plain)
      for (const secret of [undefined, 'a wrong guess']) {
        const answer = await get(port, lines, secret);
        if (!insecureHttpSessions) {
          assert.equal(answer.status, 403, JSON.stringify(lines));
          assert.deepEqual(answer.json, {
            error: identityError('https_required').message,
            code: 'https_required',
          });
          assert.equal(answer.headers['www-authenticate'], undefined);
          assert.equal(answer.headers.deprecation, undefined, 'not signed in');
        } else assert.equal(answer.status, secret === undefined ? 200 : 401, JSON.stringify(lines));
      }
    if (!insecureHttpSessions) {
      assert.equal(identity.test.checks, 0, 'no password was checked');
      assert.equal(loginThrottle.size, 0, 'nothing was counted as a guess');
      // No credential on plain HTTP: no Basic challenge either.
      const none = await raw(port, ['GET /api/thing HTTP/1.1', ...plain[0]]);
      assert.equal(none.status, 401);
      assert.equal(none.headers['www-authenticate'], undefined);
      // Each refusal is counted into the scripts' aggregated row, under its code.
      const refusals = audit.counts.filter(c => c.action === 'auth.basic.failed');
      assert.equal(refusals.length, 4);
      assert.ok(refusals.every(c => c.detail.code === 'https_required'));
      // One line for the operator (an hour), naming the fix.
      const lines = logged.filter(line => line.startsWith("A script's HTTP Basic sign-in"));
      assert.equal(lines.length, 1, logged.join('\n'));
      assert.match(lines[0], /over plain HTTP was refused \(https_required\)/);
      assert.match(lines[0], /GOBLIN_INSECURE_HTTP_SESSIONS=1 on a network you trust/);
    } else {
      // One wrong password per client key (the forwarded client, and the header-less request's,
      // which shares the Uptime Goblin host's own key): checked and counted.
      assert.equal(loginThrottle.size, plain.length, 'the wrong passwords were checked');
    }
    // Loopback and HTTPS through the trusted proxy: Basic as before, opt-in or not.
    assert.equal((await get(port, [])).status, 200);
    assert.equal((await get(port, https)).status, 200);
    const challenged = await raw(port, ['GET /api/thing HTTP/1.1']);
    assert.equal(challenged.headers['www-authenticate'], 'Basic realm="Orbit", charset="UTF-8"');
  }
});

// The order is pinned (review tests/F3, mutant T6): without the plain-HTTP opt-in, a script's
// Basic on the `http` transport is not an attempt, so it is refused https_required before any
// lockout is consulted. A locked-out client, or any client during the global lock, gets the same
// answer as one that is not locked, and nothing is checked or counted; over HTTPS the same
// client's Basic is an attempt and gets the lockout.
test('a locked-out client’s Basic on plain HTTP without the opt-in still gets https_required', async t => {
  // A fixed clock, so the lockout's remaining time shows whether anything more was counted.
  const loginThrottle = new LoginThrottle({ freeAttempts: 1, baseMs: 60000, now: () => 1e12 });
  const { port, identity } = await serveAuth(t, {
    loginThrottle,
    trustProxy: 'loopback',
    configuredHosts: ['goblin.example'],
  });
  const client = '198.51.100.7';
  const plain = ['Host: goblin.example', `X-Forwarded-For: ${client}`];
  const get = lines =>
    raw(port, ['GET /api/thing HTTP/1.1', ...lines, `Authorization: ${basic()}`]);
  const httpsRequired = async what => {
    const answer = await get(plain);
    assert.equal(answer.status, 403, what);
    assert.deepEqual(
      answer.json,
      { error: identityError('https_required').message, code: 'https_required' },
      what
    );
    assert.equal(answer.headers['retry-after'], undefined, what);
  };
  // The client's own lockout.
  for (let i = 0; i < 3; i++) loginThrottle.failure(client);
  const locked = loginThrottle.retryAfter(client);
  assert.ok(locked > 0);
  await httpsRequired('locked out');
  const overHttps = await get([...plain, 'X-Forwarded-Proto: https']);
  assert.deepEqual([overHttps.status, overHttps.json.code], [429, 'locked']);
  // The global lock of a many-address attack, for a client that never proved the password.
  for (let i = 0; i < 50; i++) loginThrottle.failure(`203.0.113.${i}`);
  assert.equal(loginThrottle.globalLocked(), true);
  await httpsRequired('global lock');
  assert.equal(identity.test.checks, 0, 'no password was checked');
  assert.equal(loginThrottle.retryAfter(client), locked, 'nothing more was counted');
});

test('malformed Basic headers are counted as guesses; only admin: parses', async t => {
  const { port, loginThrottle } = await serveAuth(t, {
    loginThrottle: new LoginThrottle({ freeAttempts: 100 }),
  });
  let counted = 0;
  const original = loginThrottle.failure.bind(loginThrottle);
  loginThrottle.failure = key => {
    counted++;
    original(key);
  };
  for (const header of [
    'Basic !!!',
    'Basic ' + Buffer.from('root:' + password).toString('base64'),
    'Basic ' + Buffer.from('admin:' + password).toString('base64') + '=',
    'Basic',
  ]) {
    const answer = await raw(port, ['GET /api/thing HTTP/1.1', `Authorization: ${header}`]);
    assert.equal(answer.status, 401, header);
    assert.equal(answer.json.code, 'invalid_credentials', header);
  }
  assert.equal(counted, 4);
});

test('with legacy Basic off a script gets basic_disabled, never counted and never challenged', async t => {
  const loginThrottle = new LoginThrottle({ freeAttempts: 1 });
  const { port } = await serveAuth(t, { legacyBasic: false, loginThrottle });
  for (let i = 0; i < 10; i++) {
    const answer = await raw(port, ['GET /api/thing HTTP/1.1', `Authorization: ${basic('x')}`]);
    assert.equal(answer.status, 401);
    assert.deepEqual(answer.json, {
      error: 'HTTP Basic sign-in is turned off (GOBLIN_LEGACY_BASIC=0).',
      code: 'basic_disabled',
      transport: { kind: 'loopback', insecureAllowed: false },
    });
    assert.equal(answer.headers['www-authenticate'], undefined);
  }
  // Sign-in with a session still works.
  const { answer } = await login(port);
  assert.equal(answer.status, 200);
  assert.equal(answer.json.legacyBasic, false);
  // Even a locked client learns only that Basic is off: nothing is evaluated.
  loginThrottle.failure('loopback');
  loginThrottle.failure('loopback');
  assert.equal(
    (await raw(port, ['GET /api/thing HTTP/1.1', `Authorization: ${basic()}`])).json.code,
    'basic_disabled'
  );
  assert.equal(loginThrottle.size, 1, 'only the two failures made by hand');
  // A signed-out answer to a script names no challenge either.
  assert.equal(
    (await raw(port, ['GET /api/thing HTTP/1.1'])).headers['www-authenticate'],
    undefined
  );
});

test('Authorization: Bearer from a script is refused and counted', async t => {
  const loginThrottle = new LoginThrottle({ freeAttempts: 2, baseMs: 60000 });
  const { port } = await serveAuth(t, { loginThrottle });
  for (let i = 0; i < 3; i++) {
    const answer = await raw(port, ['GET /api/thing HTTP/1.1', 'Authorization: Bearer abc']);
    assert.equal(answer.status, 401);
    assert.equal(answer.json.code, 'invalid_credentials');
  }
  const locked = await raw(port, ['GET /api/thing HTTP/1.1', 'Authorization: Bearer abc']);
  assert.equal(locked.status, 429);
  assert.equal(locked.json.code, 'locked');
  // From a browser the same header is ignored.
  const browser = await raw(port, [
    'GET /api/thing HTTP/1.1',
    'Authorization: Bearer abc',
    'Sec-Fetch-Site: same-origin',
  ]);
  assert.equal(browser.status, 401);
  assert.equal(browser.json.code, 'signin_required');
});

test('a full hasher queue answers busy without counting; a client’s own burst still counts', async t => {
  const identity = fakeIdentity({ password });
  const loginThrottle = new LoginThrottle();
  const { port } = await serveAuth(t, { identity, loginThrottle });
  const failures = [];
  const original = loginThrottle.failure.bind(loginThrottle);
  loginThrottle.failure = key => {
    failures.push(key);
    original(key);
  };
  identity.test.saturated = true;
  for (let i = 0; i < 12; i++) {
    const answer = await raw(port, ['GET /api/thing HTTP/1.1', `Authorization: ${basic()}`]);
    assert.equal(answer.status, 429);
    assert.equal(answer.json.code, 'busy');
    assert.equal(answer.json.error, 'Sign-in is busy. Please wait a moment and try again.');
    assert.equal(answer.headers['retry-after'], '5');
  }
  assert.deepEqual(failures, []);
  identity.test.saturated = false;
  assert.equal(
    (await raw(port, ['GET /api/thing HTTP/1.1', `Authorization: ${basic()}`])).status,
    200
  );
  // Parallel wrong guesses from one client beyond its free attempts are refused by admit and
  // counted (1.4.3): parallel guessing gets no more checks than sequential guessing. The checks
  // are held until all eight guesses have reached admit (loginThrottle.begin, which each one
  // calls once): five run and wait, three are refused. A fixed wait instead (100 ms) let a guess
  // that arrived late, on a loaded host, find the client already locked by the first five
  // failures, which answers it locked and counts nothing (6 !== 8).
  let open, arrived;
  identity.test.gate = new Promise(resolve => (open = resolve));
  const admitted = new Promise(resolve => (arrived = resolve));
  let reached = 0;
  const begin = loginThrottle.begin.bind(loginThrottle);
  loginThrottle.begin = key => {
    if (++reached === 8) arrived();
    return begin(key);
  };
  const guesses = Array.from({ length: 8 }, (_, i) =>
    raw(port, ['GET /api/thing HTTP/1.1', `Authorization: ${basic(`guess-${i}`)}`])
  );
  // A guess answered without reaching admit, or none for 30 s, fails here instead of hanging
  // the suite; the checks are let go either way.
  let timer;
  try {
    await Promise.race([
      admitted,
      // Settles only once every guess is answered: with the checks held, only if one never
      // reached admit. A guess that failed is reported by Promise.all below.
      Promise.all(guesses).catch(() => {}),
      new Promise((_, reject) => {
        timer = setTimeout(
          () => reject(new Error(`only ${reached} of 8 guesses reached admit in 30 s`)),
          30000
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
    open();
  }
  assert.equal(reached, 8, 'every guess reached admit before the checks were let go');
  const answers = await Promise.all(guesses);
  const busy = answers.filter(answer => answer.json?.code === 'busy');
  assert.ok(busy.length > 0, 'some guesses were refused while others ran');
  assert.equal(busy.length, 3, 'five checks ran (the free attempts), the other three were refused');
  for (const answer of busy)
    assert.equal(answer.json.error, 'Too many sign-in attempts at once. Wait before trying again.');
  assert.equal(failures.length, 8, 'every guess counted, admitted or not');
});

// The same through a real Uptime Goblin: the hasher (2 running, 16 waiting) is filled by other clients
// behind the trusted proxy; the victim's sign-in is refused as busy and not counted.
test('with the real hasher filled by other clients, the victim’s busy answers are not counted', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-basic-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  let gate = null;
  const derive = async (secret, salt) => {
    if (gate) await gate;
    return createHash('sha512').update(salt).update(secret).digest();
  };
  const loginThrottle = new LoginThrottle();
  const counted = [];
  const failure = loginThrottle.failure.bind(loginThrottle);
  loginThrottle.failure = key => {
    counted.push(key);
    failure(key);
  };
  const { createApp } = await import('../../server.mjs');
  const app = await createApp({
    directory,
    port: 0,
    password,
    allowedHosts: '',
    webhook: '',
    trustProxy: 'loopback',
    startScheduler: false,
    legacyBasic: true,
    loginThrottle,
    identityOptions: { derive },
  });
  const { port } = await app.listen();
  t.after(() => app.close());
  // Through the trusted proxy over HTTPS: Basic on plain HTTP needs GOBLIN_INSECURE_HTTP_SESSIONS.
  const from = address => [`X-Forwarded-For: ${address}`, 'X-Forwarded-Proto: https'];
  let open;
  gate = new Promise(resolve => (open = resolve));
  const flood = Array.from({ length: 18 }, (_, i) =>
    raw(port, [
      'GET /api/dashboard HTTP/1.1',
      `Authorization: ${basic(`flood-${i}`)}`,
      ...from(`198.51.100.${i + 1}`),
    ])
  );
  await new Promise(resolve => setTimeout(resolve, 200));
  for (let i = 0; i < 5; i++) {
    const victim = await raw(port, [
      'GET /api/dashboard HTTP/1.1',
      `Authorization: ${basic()}`,
      ...from('203.0.113.50'),
    ]);
    assert.equal(victim.status, 429);
    assert.equal(victim.json.code, 'busy');
    assert.equal(victim.json.error, 'Sign-in is busy. Please wait a moment and try again.');
  }
  assert.ok(!counted.includes('203.0.113.50'), 'the victim’s refusals were not counted');
  open();
  gate = null;
  const flooded = await Promise.all(flood);
  assert.ok(flooded.every(answer => answer.status === 401));
  const signed = await raw(port, [
    'GET /api/dashboard HTTP/1.1',
    `Authorization: ${basic()}`,
    ...from('203.0.113.50'),
  ]);
  assert.equal(signed.status, 200);
});
