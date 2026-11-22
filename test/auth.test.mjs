import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { LoginThrottle } from '../lib/throttle.mjs';
import { createApp } from '../server.mjs';
const bootstrap = 'fixture-bootstrap-password',
  changed = 'a different fixture password',
  another = 'another fixture password';
const basic = (password, user = 'admin') =>
  'Basic ' + Buffer.from(user + ':' + password).toString('base64');
function temporary(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-auth-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}
async function fixture(t, options = {}) {
  const directory = options.directory || temporary(t),
    app = await createApp({
      directory,
      host: '127.0.0.1',
      port: 0,
      password: bootstrap,
      allowedHosts: '',
      webhook: '',
      startScheduler: false,
      mailTransportFactory: () => {
        throw new Error('No SMTP permitted in auth tests');
      },
      ...options,
    });
  const address = await app.listen();
  let closed = false;
  const close = async () => {
    if (!closed) {
      closed = true;
      await app.close();
    }
  };
  t.after(close);
  const call = async (route, method = 'GET', body, password = bootstrap, headers = {}) => {
    const res = await fetch(`http://127.0.0.1:${address.port}` + route, {
      method,
      headers: {
        Authorization: basic(password),
        'Content-Type': 'application/json',
        'X-Goblin-Request': '1',
        ...headers,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: res.status, headers: res.headers, body: await res.json() };
  };
  return { app, directory, address, call, close };
}
// Deterministic KDF fixtures isolate scheduling and persistence tests. Production uses real scrypt.
const fakeKey = (password, salt) => createHash('sha512').update(salt).update(password).digest();
function fakeRecord(directory, password = bootstrap) {
  const salt = Buffer.alloc(32, 7),
    record = {
      version: 1,
      algorithm: 'scrypt',
      parameters: { N: 32768, r: 8, p: 3, keyLength: 64 },
      salt: salt.toString('hex'),
      hash: fakeKey(Buffer.from(password), salt).toString('hex'),
      passwordChangedAt: 123456,
    };
  fs.writeFileSync(path.join(directory, 'auth.json'), JSON.stringify(record), { mode: 0o600 });
  return record;
}

// The PasswordAuth tests of 1.4.x moved with the password code to lib/identity (sessions spec
// §8.2); each now runs against identity in test/identity/:
//   bootstrap authentication remains compatible, has safe metadata and does not persist
//     plaintext → basic.test.mjs, bootstrap.test.mjs (GOBLIN_PASSWORD first start)
//   password change persists a private salted slow hash and never falls back to bootstrap
//     after restart → bootstrap.test.mjs (mirror, GOBLIN_PASSWORD unchanged), change.test.mjs
//   new password validation checks Unicode characters, bytes and confirmation without altering
//     authentication → password.test.mjs (checkNewPassword)
//   failed atomic persistence leaves the old credential, hash record and change time intact
//     → password.test.mjs (writeAuthRecord); in 1.5 the change stands with mirrorPending (D13):
//     bootstrap.test.mjs "a failed mirror keeps the change…"
//   a password change preserves an unowned temporary file/symlink on exclusive-create
//     collision, a password save never closes a descriptor reused after a close error
//     → password.test.mjs (writeAuthRecord)
//   successful credential cache avoids repeated KDF work and never caches failed passwords,
//     credential rotation invalidates an old verification still in progress and stale change
//     grants, changing to the same password keeps it usable → basic.test.mjs, change.test.mjs
//   verification runs at most two KDF jobs, queues a few briefly and refuses the rest
//     → password.test.mjs (createHasher)
//   concurrent password changes cannot overwrite each other, password changes require the
//     current password → change.test.mjs
//   the bootstrap password must be 12 to 1024 characters and not only spaces
//     → password.test.mjs, bootstrap.test.mjs (readBuiltinSources)
// What stays here runs through createApp and the HTTP API.
test('corrupt, unsupported, oversized and symlinked auth records fail closed even with bootstrap present', async t => {
  const refused = error =>
    /Saved authentication could not be loaded/.test(error.message) && error.refusal === true;
  for (const value of [
    'not-json',
    '{}',
    JSON.stringify({
      ...fakeRecord(temporary(t)),
      parameters: { N: 1, r: 8, p: 3, keyLength: 64 },
    }),
    'x'.repeat(8193),
  ]) {
    const directory = temporary(t);
    fs.writeFileSync(path.join(directory, 'auth.json'), value);
    await assert.rejects(
      createApp({ directory, password: bootstrap, startScheduler: false }),
      refused
    );
  }
  const directory = temporary(t);
  fs.symlinkSync('missing-target', path.join(directory, 'auth.json'));
  await assert.rejects(
    createApp({ directory, password: bootstrap, startScheduler: false }),
    refused
  );
});
test('password API requires authenticated admin and CSRF protection but no manually repeated old password', async t => {
  const { call, directory } = await fixture(t);
  for (const [password, headers, status, code] of [
    [changed, {}, 401, 'invalid_credentials'],
    [bootstrap, { 'X-Goblin-Request': '' }, 403, 'cross_origin'],
    [bootstrap, { Origin: 'https://foreign.example' }, 403, 'cross_origin'],
    // Sec-Fetch-Site makes it a browser's request, whose Basic header is ignored (D12): it is
    // signed out, and never prompted. The cross-site refusal of a session cookie is in
    // test/http-pipeline/csrf.test.mjs.
    [bootstrap, { 'Sec-Fetch-Site': 'cross-site' }, 401, 'signin_required'],
  ]) {
    const answer = await call(
      '/api/auth/password',
      'POST',
      { currentPassword: bootstrap, password: changed, confirmPassword: changed },
      password,
      headers
    );
    assert.equal(answer.status, status, JSON.stringify(headers));
    assert.equal(answer.body.code, code);
    if (headers['Sec-Fetch-Site']) assert.equal(answer.headers.get('www-authenticate'), null);
  }
  assert.equal(fs.existsSync(path.join(directory, 'auth.json')), false);
  const invalid = await call('/api/auth/password', 'POST', {
    currentPassword: bootstrap,
    password: changed,
    confirmPassword: another,
  });
  assert.equal(invalid.status, 400);
  assert.equal(fs.existsSync(path.join(directory, 'auth.json')), false);
  const result = await call('/api/auth/password', 'POST', {
    currentPassword: bootstrap,
    password: changed,
    confirmPassword: changed,
  });
  assert.equal(result.status, 200);
  assert.deepEqual(result.body, {
    ok: true,
    revokedOtherSessions: 0,
    mirrorPending: false,
    reauthenticate: true,
  });
  // The change is mirrored to auth.json, so a rollback to 1.4.x uses the new password (D13).
  assert.equal(fs.existsSync(path.join(directory, 'auth.json')), true);
  assert.equal((await call('/api/system')).status, 401);
  assert.equal((await call('/api/system', 'GET', undefined, changed)).status, 200);
});
test('system metadata and exports never expose the password, salt, hash or auth file', async t => {
  const { call, directory, address } = await fixture(t);
  const before = await call('/api/system');
  assert.equal(before.body.authenticationRequired, true);
  assert.deepEqual(before.body.authentication, {
    username: 'admin',
    passwordChangeAvailable: true,
    passwordChangedAt: null,
  });
  await call('/api/auth/password', 'POST', {
    currentPassword: bootstrap,
    password: changed,
    confirmPassword: changed,
  });
  const record = JSON.parse(fs.readFileSync(path.join(directory, 'auth.json')));
  for (const route of ['/api/system', '/api/config/export', '/api/dashboard']) {
    const result = await call(route, 'GET', undefined, changed);
    assert.equal(result.status, 200);
    const encoded = JSON.stringify(result.body);
    for (const value of [bootstrap, changed, record.salt, record.hash])
      assert.ok(!encoded.includes(value));
    if (route === '/api/system')
      assert.equal(result.body.authentication.passwordChangedAt, record.passwordChangedAt);
  }
  const res = await fetch(`http://127.0.0.1:${address.port}/auth.json`, {
    headers: { Authorization: basic(changed) },
  });
  assert.equal(res.status, 404);
});
test('there is no unauthenticated loopback preview: no start without a password, and no change or test email without a credential', async t => {
  await assert.rejects(
    createApp({ directory: temporary(t), host: '127.0.0.1', password: '', startScheduler: false }),
    error => error.refusal === true && /^Uptime Goblin needs an admin password/.test(error.message)
  );
  const { call, directory, address } = await fixture(t);
  const bare = (route, body) =>
    fetch(`http://127.0.0.1:${address.port}${route}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Goblin-Request': '1' },
      body: JSON.stringify(body),
    });
  for (const [route, body] of [
    [
      '/api/auth/password',
      { currentPassword: bootstrap, password: changed, confirmPassword: changed },
    ],
    [
      '/api/account/password',
      { currentPassword: bootstrap, password: changed, confirmPassword: changed },
    ],
    ['/api/email/test', {}],
  ]) {
    const answer = await bare(route, body);
    assert.equal(answer.status, 401, route);
    assert.equal((await answer.json()).code, 'signin_required', route);
  }
  assert.equal(fs.existsSync(path.join(directory, 'auth.json')), false);
  // Signed in, the system page always reports sign-in as required.
  const system = await call('/api/system');
  assert.equal(system.body.authenticationRequired, true);
  assert.equal(system.body.authentication.passwordChangeAvailable, true);
});
test('persisted authentication permits network binding without environment bootstrap and dynamically guards email tests', async t => {
  // The saved password: an app run with GOBLIN_PASSWORD, then a change through the API, which
  // Uptime Goblin mirrors to auth.json.
  const directory = temporary(t);
  const first = await fixture(t, { directory });
  assert.equal(
    (
      await first.call('/api/auth/password', 'POST', {
        currentPassword: bootstrap,
        password: changed,
        confirmPassword: changed,
      })
    ).status,
    200
  );
  await first.close();
  const network = await createApp({
    directory,
    host: '0.0.0.0',
    password: '',
    startScheduler: false,
  });
  await network.close();
  await assert.rejects(
    createApp({ directory: temporary(t), host: '0.0.0.0', password: '', startScheduler: false }),
    /GOBLIN_PASSWORD/
  );
  const { call } = await fixture(t, { directory, password: '' });
  assert.equal((await call('/api/system', 'GET', undefined, bootstrap)).status, 401);
  assert.equal((await call('/api/system', 'GET', undefined, changed)).status, 200);
  const email = await call('/api/email/test', 'POST', {}, changed);
  assert.equal(email.status, 400);
  assert.match(email.body.error, /Save a sender/);
});
test('successful API password change survives app restart and ignores a different bootstrap value', async t => {
  const first = await fixture(t);
  await first.call('/api/auth/password', 'POST', {
    currentPassword: bootstrap,
    password: changed,
    confirmPassword: changed,
  });
  await first.close();
  const restarted = await fixture(t, { directory: first.directory, password: another });
  for (const password of [bootstrap, another])
    assert.equal((await restarted.call('/api/system', 'GET', undefined, password)).status, 401);
  assert.equal((await restarted.call('/api/system', 'GET', undefined, changed)).status, 200);
});
test('a mutation authenticated before rotation cannot finish its delayed request body afterward', async t => {
  const { app, address, call } = await fixture(t);
  const text = JSON.stringify({ title: 'Stale request must not save' });
  let resolveResponse;
  const response = new Promise(resolve => (resolveResponse = resolve));
  const req = http.request(
    {
      host: '127.0.0.1',
      port: address.port,
      path: '/api/settings',
      method: 'PATCH',
      headers: {
        Authorization: basic(bootstrap),
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(text),
        'X-Goblin-Request': '1',
      },
    },
    res => {
      res.resume();
      res.on('end', () => resolveResponse(res.statusCode));
    }
  );
  t.after(() => req.destroy());
  req.write(text.slice(0, 5));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(
    (
      await call('/api/auth/password', 'POST', {
        currentPassword: bootstrap,
        password: changed,
        confirmPassword: changed,
      })
    ).status,
    200
  );
  req.end(text.slice(5));
  assert.equal(await response, 401);
  assert.notEqual(app.config.value.title, 'Stale request must not save');
});

test('keyed requests held across rotation cannot trigger refresh or replay a saved response', async t => {
  for (const replay of [false, true]) {
    await t.test(replay ? 'saved response' : 'new refresh', async t => {
      let collections = 0;
      const { app, address, call } = await fixture(t, {
        collector: async () => {
          collections++;
          return [];
        },
      });
      app.config.update('linux', { apiUrl: 'https://node.example.test' });
      // Warm the credential cache before opening the held request.
      assert.equal((await call('/api/system')).status, 200);
      const route = replay ? '/api/settings' : '/api/refresh',
        method = replay ? 'PATCH' : 'POST',
        body = replay ? { title: 'A completed save' } : {},
        key = { 'Idempotency-Key': 'held-across-password-rotation' };
      if (replay) assert.equal((await call(route, method, body, bootstrap, key)).status, 200);
      const text = JSON.stringify(body);
      let req;
      const arrived = new Promise(resolve => app.server.once('request', resolve));
      const response = new Promise((resolve, reject) => {
        req = http.request(
          {
            host: '127.0.0.1',
            port: address.port,
            path: route,
            method,
            headers: {
              Authorization: basic(bootstrap),
              'Content-Type': 'application/json',
              'Content-Length': Buffer.byteLength(text),
              'X-Goblin-Request': '1',
              ...key,
            },
          },
          res => {
            res.resume();
            res.on('end', () => resolve(res.statusCode));
          }
        );
        req.on('error', reject);
        req.write(text.slice(0, 1));
      });
      t.after(() => req.destroy());
      await arrived;
      assert.equal(
        (
          await call('/api/auth/password', 'POST', {
            currentPassword: bootstrap,
            password: changed,
            confirmPassword: changed,
          })
        ).status,
        200
      );
      req.end(text.slice(1));
      assert.equal(await response, 401);
      assert.equal(collections, 0);
    });
  }
});

test('a keyed retry waiting for another request rechecks authentication after rotation', async t => {
  let release, started;
  const entered = new Promise(resolve => (started = resolve)),
    held = new Promise(resolve => (release = resolve));
  const { app, call } = await fixture(t, {
    collector: async () => {
      started();
      await held;
      return [];
    },
  });
  t.after(() => release());
  const body = { settings: { type: 'linux', apiUrl: 'https://node.example.test' } },
    key = { 'Idempotency-Key': 'wait-across-password-rotation' };
  const first = call('/api/test-service', 'POST', body, bootstrap, key);
  await entered;
  const arrived = new Promise(resolve => app.server.once('request', resolve));
  const second = call('/api/test-service', 'POST', body, bootstrap, key);
  await arrived;
  assert.equal(
    (
      await call('/api/auth/password', 'POST', {
        currentPassword: bootstrap,
        password: changed,
        confirmPassword: changed,
      })
    ).status,
    200
  );
  release();
  // The connection test itself re-checks after its collection (1.5, §6.5): the password
  // changed while it ran, so its readings are discarded too.
  assert.equal((await first).status, 401);
  const retry = await second;
  assert.equal(retry.status, 401);
  assert.equal(retry.headers.get('idempotent-replayed'), null);
});

test('a wrong current password over the API counts toward the sign-in lockout', async t => {
  const { call } = await fixture(t, {
    loginThrottle: new LoginThrottle({ freeAttempts: 1, baseMs: 60000 }),
  });
  for (let i = 0; i < 2; i++)
    assert.equal(
      (
        await call('/api/auth/password', 'POST', {
          currentPassword: 'wrong current password',
          password: changed,
          confirmPassword: changed,
        })
      ).status,
      403
    );
  assert.equal((await call('/api/dashboard')).status, 429);
});
