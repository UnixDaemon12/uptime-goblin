// Wall displays through a real Uptime Goblin (B6 design §7, §8): POST /api/auth/login with a display
// code, the read-only session it makes, the routes it may use and the dashboard it reads.
import test from 'node:test';
import assert from 'node:assert/strict';
import { newDisplayCode } from '../../lib/identity/secrets.mjs';
import { identityOps } from '../../lib/repo/identity.mjs';
import { basic, browserWrite, cookieFrom, raw, startReal } from './harness.mjs';

/** A waiting code in `app`'s control.sqlite, as goblin-admin display code makes it. */
async function waiting(app, name = 'Lobby TV') {
  const made = newDisplayCode();
  const now = Date.now();
  await app.control.db.write(tx =>
    identityOps.insertDisplay(tx, {
      id: made.id,
      name,
      codeHash: made.codeHash,
      codeExpiresAt: now + 10 * 60e3,
      createdAt: now,
      createdBy: 'cli:test',
    })
  );
  return made;
}

const local = port => `http://127.0.0.1:${port}`;
const signIn = (port, body, lines = browserWrite(local(port))) =>
  raw(port, ['POST /api/auth/login HTTP/1.1', ...lines], JSON.stringify(body));
const get = (port, route, cookie) =>
  raw(port, [`GET ${route} HTTP/1.1`, `Cookie: ${cookie}`, 'Sec-Fetch-Site: same-origin']);
const send = (port, method, route, cookie, body) =>
  raw(
    port,
    [`${method} ${route} HTTP/1.1`, `Cookie: ${cookie}`, ...browserWrite(local(port))],
    body === undefined ? '' : JSON.stringify(body)
  );
const admin = (port, method, route, body) =>
  raw(
    port,
    [
      `${method} ${route} HTTP/1.1`,
      `Authorization: ${basic()}`,
      'Content-Type: application/json',
      'X-Goblin-Request: 1',
    ],
    body === undefined ? '' : JSON.stringify(body)
  );

test('a display code signs a wall display in: a persistent, read-only session, once', async t => {
  const { app, port } = await startReal(t);
  const { code } = await waiting(app);
  // Typed loosely: lower case, spaces for hyphens.
  const answer = await signIn(port, {
    code: code.toLowerCase().replaceAll('-', ' '),
    display: true,
  });
  assert.equal(answer.status, 200, answer.body);
  assert.match(
    [].concat(answer.headers['set-cookie'])[0],
    /^goblin_session=v1\.[A-Za-z0-9_-]{43}; Path=\/; HttpOnly; SameSite=Strict; Max-Age=2592000$/
  );
  assert.equal(answer.json.kind, 'kiosk');
  assert.equal(answer.json.via, 'session');
  assert.deepEqual(answer.json.permissions, ['dashboard:read', 'session:self']);
  assert.equal('user' in answer.json, false, 'a display is told no user');
  assert.equal(answer.json.session.persistent, true);
  const cookie = cookieFrom(answer);

  const session = await get(port, '/api/session', cookie);
  assert.equal(session.status, 200);
  assert.equal(session.json.kind, 'kiosk');
  assert.equal((await get(port, '/api/dashboard', cookie)).status, 200);
  assert.equal((await get(port, '/api/version', cookie)).status, 200);
  // Nothing beyond the dashboard.
  for (const route of [
    '/api/system',
    '/api/account/sessions',
    '/api/audit',
    '/api/notifications',
  ]) {
    const refused = await get(port, route, cookie);
    assert.deepEqual([refused.status, refused.json?.code], [403, 'forbidden'], route);
  }
  for (const [method, route, body] of [
    ['POST', '/api/refresh', {}],
    ['PATCH', '/api/settings', { title: 'Mine' }],
    ['DELETE', '/api/account/sessions', undefined],
    [
      'POST',
      '/api/account/password',
      { currentPassword: 'x', password: 'y', confirmPassword: 'y' },
    ],
  ]) {
    const refused = await send(port, method, route, cookie, body);
    assert.deepEqual([refused.status, refused.json?.code], [403, 'forbidden'], route);
  }

  // A code works once.
  const again = await signIn(port, { code, display: true });
  assert.deepEqual([again.status, again.json.code], [401, 'display_code_invalid']);

  // The admin sees the display by name, and can sign it out.
  const listed = await admin(port, 'GET', '/api/account/sessions');
  const entry = listed.json.sessions.find(s => s.id === session.json.session.id);
  assert.deepEqual([entry.kind, entry.display], ['kiosk', 'Lobby TV']);
  for (const other of listed.json.sessions.filter(s => s !== entry))
    assert.deepEqual([other.kind, other.display], ['interactive', null]);
  // A display may sign itself out.
  assert.equal((await send(port, 'POST', '/api/auth/logout', cookie)).status, 204);
  assert.equal((await get(port, '/api/session', cookie)).status, 401);
});

test('a display sends {code, display: true} and nothing else', async t => {
  const { app, port } = await startReal(t);
  const { code } = await waiting(app);
  for (const body of [
    { code, display: true, login: 'admin' },
    { code, display: true, password: 'x' },
    { code, display: true, remember: true },
    { code, display: false },
    { code },
    { code: 'not-a-code', display: true },
    { code: 12345, display: true },
    { code: `${code.slice(0, -1)}${code.endsWith('0') ? '1' : '0'}`, display: true },
  ]) {
    const refused = await signIn(port, body);
    assert.deepEqual(
      [refused.status, refused.json?.code],
      [400, 'invalid_request'],
      JSON.stringify(body)
    );
    assert.equal(refused.headers['set-cookie'], undefined);
  }
  // A well-formed code Uptime Goblin never made.
  const unknown = await signIn(port, { code: newDisplayCode().code, display: true });
  assert.deepEqual([unknown.status, unknown.json.code], [401, 'display_code_invalid']);
  // None of that used the real code up.
  assert.equal((await signIn(port, { code, display: true })).status, 200);
});

test('a code sent over plain HTTP is refused and cancelled', async t => {
  const { app, port } = await startReal(t, {
    trustProxy: 'loopback',
    allowedHosts: 'goblin.example',
  });
  const proxy = ['Host: goblin.example', 'X-Forwarded-For: 198.51.100.20'];
  const https = [...proxy, 'X-Forwarded-Proto: https'];
  const { code } = await waiting(app);
  const plain = await signIn(port, { code, display: true }, [
    ...proxy,
    ...browserWrite('http://goblin.example'),
  ]);
  assert.deepEqual([plain.status, plain.json.code], [403, 'https_required']);
  assert.match(plain.json.error, /Uptime Goblin cancelled it/);
  // Over HTTPS now, the code no longer works: it crossed the network in clear.
  const late = await signIn(port, { code, display: true }, [
    ...https,
    ...browserWrite('https://goblin.example'),
  ]);
  assert.deepEqual([late.status, late.json.code], [401, 'display_code_invalid']);
  // A fresh code over HTTPS signs in, with a Secure cookie.
  const fresh = await waiting(app);
  const ok = await signIn(port, { code: fresh.code, display: true }, [
    ...https,
    ...browserWrite('https://goblin.example'),
  ]);
  assert.equal(ok.status, 200, ok.body);
  assert.match([].concat(ok.headers['set-cookie'])[0], /^__Host-goblin_session=.*; Secure;/);
});

test('a display reads the dashboard without addresses, and not a hidden source', async t => {
  const { app, port } = await startReal(t);
  const shown = await admin(port, 'POST', '/api/services', {
    type: 'link',
    name: 'NAS',
    group: 'Storage',
    url: 'https://nas.example/admin',
  });
  assert.equal(shown.status, 201, shown.body);
  const hidden = await admin(port, 'POST', '/api/services', {
    type: 'link',
    name: 'Router',
    group: 'Network',
    url: 'https://router.example/',
    showOnDashboard: false,
  });
  assert.equal(hidden.status, 201, hidden.body);
  const shownId = shown.json.service.id,
    hiddenId = hidden.json.service.id;

  const { code } = await waiting(app);
  const cookie = cookieFrom(await signIn(port, { code, display: true }));
  const dashboard = await get(port, '/api/dashboard', cookie);
  assert.equal(dashboard.status, 200);
  const ids = dashboard.json.config.services.map(s => s.id);
  assert.ok(ids.includes(shownId));
  assert.ok(!ids.includes(hiddenId), 'a hidden source is not sent to a display');
  for (const source of dashboard.json.config.services) assert.equal(source.url, '');
  assert.doesNotMatch(dashboard.body, /nas\.example|router\.example/);
  assert.equal((await get(port, `/api/history/${shownId}?range=1h`, cookie)).status, 200);
  const unknown = await get(port, `/api/history/${hiddenId}?range=1h`, cookie);
  assert.deepEqual([unknown.status, unknown.json.error], [404, 'Source not found']);

  // The admin's dashboard still has both, with their addresses.
  const full = await admin(port, 'GET', '/api/dashboard');
  assert.ok(full.json.config.services.some(s => s.id === hiddenId));
  assert.match(full.body, /nas\.example/);
});
