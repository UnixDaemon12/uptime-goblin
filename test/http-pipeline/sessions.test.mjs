// Sessions through a real Uptime Goblin (createApp, control.sqlite, the identity service): sign-in and
// sign-out, rotation, the account routes, and the re-checks that stop a request whose session
// ended while it waited (sessions spec §8.1 "sessions.test.mjs").
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import nodemailer from 'nodemailer';
import { LoginThrottle } from '../../lib/throttle.mjs';
import { writeAuthRecord as realWrite } from '../../lib/identity/password.mjs';
import { configureDestinations } from '../../lib/destinations.mjs';
import { emailDefaults } from '../../lib/catalog.mjs';
import { fragment, sql } from '../../lib/db/sql.mjs';
import { newSession } from '../../lib/identity/secrets.mjs';
import { smtpServer } from '../helpers/smtp.mjs';
import { basic, browserWrite, cookieFrom, login, password, raw, startReal } from './harness.mjs';

const bodies = JSON.parse(
  fs.readFileSync(new URL('../contract/identity-bodies.json', import.meta.url), 'utf8')
);
const nextPassword = 'fixture-sessions-next-password';
// SMTP hosts are checked against the destination policy; resolve them instantly, never via DNS.
configureDestinations({ lookup: async () => [{ address: '192.0.2.1' }] });

/** The GET /api/session body with its volatile values written as the fixture writes them. */
function shaped(body, build) {
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

/** Session rows as control.sqlite holds them. */
const sessionRows = app =>
  app.control.db.read(tx => tx.all(sql`SELECT id, persistent FROM sessions ORDER BY created_at`));

/**
 * Makes `app`'s control.sqlite writes fail as a full (or failing, `as` 'io') disk makes them:
 * the returned fail(n, as) fails the next n writes, fail(Infinity) every one.
 */
function failingWrites(app) {
  const db = app.control.db,
    write = db.write.bind(db);
  let failing = 0,
    kind = 'full';
  db.write = (...args) =>
    failing-- > 0
      ? Promise.reject(
          Object.assign(new Error(kind === 'full' ? 'database or disk is full' : 'disk I/O'), {
            code: kind === 'full' ? 'SQLITE_FULL' : 'SQLITE_IOERR',
            class: kind,
          })
        )
      : write(...args);
  return (count, as = 'full') => {
    failing = count;
    kind = as;
  };
}

/** A browser tab of `port` holding `cookie`. */
const tab = (port, cookie) => ({
  get: (route, lines = []) =>
    raw(port, [
      `GET ${route} HTTP/1.1`,
      `Cookie: ${cookie}`,
      'Sec-Fetch-Site: same-origin',
      ...lines,
    ]),
  send: (method, route, body, lines = []) =>
    raw(
      port,
      [
        `${method} ${route} HTTP/1.1`,
        `Cookie: ${cookie}`,
        ...browserWrite(`http://127.0.0.1:${port}`),
        ...lines,
      ],
      body === undefined ? '' : JSON.stringify(body)
    ),
});

test('sign in, read the session, sign out: the cookie, the body and the row', async t => {
  const { app, port } = await startReal(t);
  const { answer, cookie } = await login(port);
  assert.equal(answer.status, 200);
  assert.match(
    [].concat(answer.headers['set-cookie'])[0],
    /^goblin_session=v1\.[A-Za-z0-9_-]{43}; Path=\/; HttpOnly; SameSite=Strict$/
  );
  const me = tab(port, cookie);
  const session = await me.get('/api/session');
  assert.equal(session.status, 200);
  assert.deepEqual(shaped(session.json, app.build), {
    ...bodies.session.session,
    transport: { kind: 'loopback', https: false, insecure: false, insecureAllowed: false },
  });
  assert.deepEqual(
    (await sessionRows(app)).map(row => row.id),
    [session.json.session.id]
  );
  const out = await me.send('POST', '/api/auth/logout');
  assert.equal(out.status, 204);
  assert.deepEqual([].concat(out.headers['set-cookie']), [
    'goblin_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0',
  ]);
  assert.equal(out.headers['clear-site-data'], '"cache"');
  assert.deepEqual(await sessionRows(app), []);
  const after = await me.get('/api/session');
  assert.equal(after.status, 401);
  assert.deepEqual(after.json, bodies['401'].session_expired.loopback);
  assert.equal(after.headers['www-authenticate'], undefined);
});

test('Keep me signed in sets Max-Age; signing in again rotates the presented session', async t => {
  const { app, port } = await startReal(t);
  const remembered = await login(port, { remember: true });
  assert.match([].concat(remembered.answer.headers['set-cookie'])[0], /; Max-Age=2592000$/);
  assert.deepEqual(
    (await sessionRows(app)).map(row => Boolean(row.persistent)),
    [true]
  );
  const again = await login(port, { lines: [`Cookie: ${remembered.cookie}`] });
  assert.equal(again.answer.status, 200);
  assert.equal((await sessionRows(app)).length, 1, 'the presented session was replaced');
  assert.equal((await tab(port, remembered.cookie).get('/api/session')).status, 401);
  assert.equal((await tab(port, again.cookie).get('/api/session')).status, 200);
});

test('an https sign-in carrying the plain-HTTP cookie expires it and revokes its row', async t => {
  const { app, port } = await startReal(t, {
    trustProxy: 'loopback',
    allowedHosts: 'goblin.example',
  });
  const plain = await login(port);
  const https = await raw(
    port,
    [
      'POST /api/auth/login HTTP/1.1',
      'Host: goblin.example',
      'X-Forwarded-For: 198.51.100.4',
      'X-Forwarded-Proto: https',
      `Cookie: ${plain.cookie}`,
      ...browserWrite('https://goblin.example'),
    ],
    JSON.stringify({ login: 'admin', password })
  );
  assert.equal(https.status, 200);
  const cookies = [].concat(https.headers['set-cookie']);
  assert.match(
    cookies[0],
    /^__Host-goblin_session=v1\.[^;]+; Path=\/; Secure; HttpOnly; SameSite=Strict$/
  );
  assert.equal(cookies[1], 'goblin_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0');
  assert.deepEqual(
    (await sessionRows(app)).map(row => row.id),
    [https.json.session.id]
  );
  assert.equal((await tab(port, plain.cookie).get('/api/session')).status, 401);
});

test('the account routes: list, sign out one, the others, and this one', async t => {
  const { port } = await startReal(t);
  // This device signs in last: a session ends only those that signed in no later than it.
  const a = await login(port);
  const b = await login(port);
  const mine = await login(port, { lines: ['User-Agent: fixture/1'] });
  const me = tab(port, mine.cookie);
  const list = await me.get('/api/account/sessions');
  assert.equal(list.status, 200);
  assert.equal(list.json.sessions.length, 3);
  assert.deepEqual(
    list.json.sessions.map(view => view.current),
    [true, false, false]
  );
  assert.equal(list.json.sessions[0].userAgent, 'fixture/1');
  assert.ok(!list.body.includes('token_hash'));
  assert.equal(
    (await me.send('DELETE', `/api/account/sessions/${a.answer.json.session.id}`)).status,
    204
  );
  assert.equal((await tab(port, a.cookie).get('/api/session')).status, 401);
  const missing = await me.send('DELETE', '/api/account/sessions/s_AAAAAAAAAAAAAAAA');
  assert.equal(missing.status, 404);
  assert.deepEqual(missing.json, { error: 'Session not found', code: 'not_found' });
  const others = await me.send('DELETE', '/api/account/sessions');
  assert.deepEqual([others.status, others.json], [200, { revoked: 1, kept: 0 }]);
  assert.equal((await tab(port, b.cookie).get('/api/session')).status, 401);
  const own = await me.send('DELETE', `/api/account/sessions/${mine.answer.json.session.id}`);
  assert.equal(own.status, 204);
  assert.deepEqual([].concat(own.headers['set-cookie']), [
    'goblin_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0',
  ]);
  assert.equal((await me.get('/api/session')).status, 401);
});

// A sign-out whose delete fails (a full or failing disk) is refused only in this process, so a
// restart would accept the session again (§16 C2). It must not be answered as done, a retry must
// delete it, and the stop must delete what is left, or say in the log that it could not.
test('sign-outs whose delete failed are not answered as done; retries and the stop delete them, across a restart', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-signout-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const warnings = [];
  const log = { info() {}, log() {}, warn: (...args) => warnings.push(args.join(' ')) };
  const originalError = console.error;
  t.after(() => (console.error = originalError));
  console.error = () => {};
  // An Uptime Goblin on `directory` whose control.sqlite writes can be made to fail (failingWrites).
  const orbit = async () => {
    const started = await startReal(t, { directory, identityOptions: { log } });
    const fail = failingWrites(started.app);
    return { ...started, fail, as: cookie => tab(started.port, cookie) };
  };
  const status = async (running, session) =>
    (await running.as(session.cookie).get('/api/session')).status;
  const idOf = session => session.answer.json.session.id;

  const first = await orbit();
  const signedOut = await login(first.port),
    one = await login(first.port),
    others = [await login(first.port), await login(first.port), await login(first.port)];
  // The owner signs in last, so its session may end every other one.
  const owner = await login(first.port);
  const me = first.as(owner.cookie);

  // Sign out: the answer says the sign-out was not recorded, and the browser keeps its cookie,
  // with which pressing Sign out again would delete the session (§20 H1; the next test). Left
  // as it is here, Sign out other devices deletes it below.
  first.fail(1, 'io');
  const out = await first.as(signedOut.cookie).send('POST', '/api/auth/logout', {});
  assert.equal(out.status, 500);
  assert.equal(out.headers['set-cookie'], undefined);
  assert.equal(await status(first, signedOut), 401);

  // Sign out one device: 503, then the retry still finds the session and deletes it.
  first.fail(1);
  const refused = await me.send('DELETE', `/api/account/sessions/${idOf(one)}`);
  assert.equal(refused.status, 503);
  assert.equal(refused.json.code, 'storage_full');
  assert.match(refused.json.error, /could not record this sign-out/);
  assert.equal(await status(first, one), 401);
  assert.equal((await me.send('DELETE', `/api/account/sessions/${idOf(one)}`)).status, 204);

  // Sign out other devices: 503, then the retry deletes and counts every other row, the
  // sign-out above whose delete failed included.
  first.fail(1);
  assert.equal((await me.send('DELETE', '/api/account/sessions')).status, 503);
  const retried = await me.send('DELETE', '/api/account/sessions');
  assert.deepEqual([retried.status, retried.json], [200, { revoked: 4, kept: 0 }]);
  assert.deepEqual(
    (await sessionRows(first.app)).map(row => row.id),
    [idOf(owner)]
  );

  // A sign-out whose delete fails just before the stop: the stop deletes it.
  const late = await login(first.port);
  first.fail(1);
  assert.equal((await first.as(late.cookie).send('POST', '/api/auth/logout', {})).status, 503);
  await first.app.close();
  assert.deepEqual(warnings, [], 'nothing left over');

  const second = await orbit();
  for (const session of [signedOut, one, ...others, late])
    assert.equal(await status(second, session), 401, 'still signed out after the restart');
  assert.equal(await status(second, owner), 200);
  // The disk stays full until the stop: the log says the sign-out is undone by a restart.
  const stuck = await login(second.port);
  second.fail(Infinity);
  assert.equal((await second.as(stuck.cookie).send('POST', '/api/auth/logout', {})).status, 503);
  await second.app.close();
  assert.equal(warnings.length, 1);
  assert.match(
    warnings[0],
    /^Uptime Goblin could not remove 1 signed-out session from control\.sqlite \(full\), so it is accepted again after Uptime Goblin starts\. Free some space on the Uptime Goblin host, start Uptime Goblin, and sign out the other devices again under Configure → Account \(or change the admin password\)\.$/
  );
  // As the line says.
  const third = await orbit();
  assert.equal(await status(third, stuck), 200);
});

test('the browser’s own sign-out that Uptime Goblin could not record is finished by pressing Sign out again, or by signing in again', async t => {
  // §20 H1. The row stays in control.sqlite, refused only by this process: a stop that cannot
  // run the shutdown's delete (a crash, an OOM kill, power loss, a disk still full) before the
  // hourly prune lets the session back in. The answer says to try again, so the retry this
  // browser sends must delete it. Before, the failed answer expired the cookie, so the retry
  // came without a session (401 signin_required), and one with the old cookie was refused (401
  // session_expired): the page takes either as a completed sign-out, and the row stayed.
  const originalError = console.error;
  t.after(() => (console.error = originalError));
  console.error = () => {};
  const { app, port } = await startReal(t);
  const fail = failingWrites(app);
  const ids = async () => (await sessionRows(app)).map(row => row.id);
  for (const [kind, status] of [
    ['full', 503],
    ['io', 500],
  ]) {
    const browser = await login(port);
    const me = tab(port, browser.cookie);
    fail(1, kind);
    const out = await me.send('POST', '/api/auth/logout', {});
    assert.equal(out.status, status, kind);
    assert.equal(out.headers['set-cookie'], undefined, 'the browser keeps its cookie');
    assert.equal(out.headers['clear-site-data'], '"cache"');
    if (kind === 'full') {
      assert.equal(out.json.code, 'storage_full');
      assert.match(out.json.error, /Free some space on the Uptime Goblin host, then try again\.$/);
    }
    assert.deepEqual(await ids(), [browser.answer.json.session.id], 'still stored');
    // Refused meanwhile (fail closed), as before.
    const meanwhile = await me.get('/api/session');
    assert.deepEqual([meanwhile.status, meanwhile.json.code], [401, 'session_expired']);
    // Sign out pressed again, as the browser sends it: deleted, and the browser's side ends.
    const again = await me.send('POST', '/api/auth/logout', {});
    assert.equal(again.status, 204, kind);
    assert.deepEqual([].concat(again.headers['set-cookie']), [
      'goblin_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0',
    ]);
    assert.equal(again.headers['clear-site-data'], '"cache"');
    assert.deepEqual(await ids(), [], kind);
    // Once more (another tab of the same browser): nothing is stored under it any more.
    const gone = await me.send('POST', '/api/auth/logout', {});
    assert.deepEqual([gone.status, gone.json.code], [401, 'session_expired']);
    assert.equal(gone.headers['set-cookie'], undefined);
  }

  // A retry that fails too says so again and keeps the cookie; one that comes from another
  // site's page, or is not JSON, ends nothing; the next one from Uptime Goblin's page finishes it.
  const stuck = await login(port);
  const me = tab(port, stuck.cookie);
  fail(2);
  assert.equal((await me.send('POST', '/api/auth/logout', {})).status, 503);
  const failedAgain = await me.send('POST', '/api/auth/logout', {});
  assert.deepEqual([failedAgain.status, failedAgain.json.code], [503, 'storage_full']);
  assert.equal(failedAgain.headers['set-cookie'], undefined);
  const forged = await raw(
    port,
    [
      'POST /api/auth/logout HTTP/1.1',
      `Cookie: ${stuck.cookie}`,
      ...browserWrite('https://evil.test'),
    ],
    '{}'
  );
  assert.deepEqual([forged.status, forged.json.code], [403, 'cross_origin']);
  const notJson = await raw(
    port,
    [
      'POST /api/auth/logout HTTP/1.1',
      `Cookie: ${stuck.cookie}`,
      ...browserWrite(`http://127.0.0.1:${port}`).map(line =>
        line.startsWith('Content-Type:') ? 'Content-Type: text/plain' : line
      ),
    ],
    '{}'
  );
  assert.equal(notJson.status, 415);
  assert.deepEqual(await ids(), [stuck.answer.json.session.id]);
  assert.equal((await me.send('POST', '/api/auth/logout', {})).status, 204);
  assert.deepEqual(await ids(), []);

  // Signing in again from that browser deletes it too: the sign-in rotates the session its
  // cookie names.
  const rotated = await login(port);
  fail(1);
  assert.equal((await tab(port, rotated.cookie).send('POST', '/api/auth/logout', {})).status, 503);
  const back = await login(port, { lines: [`Cookie: ${rotated.cookie}`] });
  assert.equal(back.answer.status, 200);
  assert.deepEqual(await ids(), [back.answer.json.session.id]);

  // DELETE of the browser's own session is a sign-out too: when its delete fails, the cookie
  // stays as well, and logout with it finishes it (the DELETE itself is refused: not signed in).
  const own = tab(port, back.cookie);
  fail(1);
  const deleted = await own.send('DELETE', `/api/account/sessions/${back.answer.json.session.id}`);
  assert.deepEqual([deleted.status, deleted.json.code], [503, 'storage_full']);
  assert.equal(deleted.headers['set-cookie'], undefined);
  assert.equal(
    (await own.send('DELETE', `/api/account/sessions/${back.answer.json.session.id}`)).status,
    401
  );
  assert.equal((await own.send('POST', '/api/auth/logout', {})).status, 204);
  assert.deepEqual(await ids(), []);
});

test('over https, a sign-out Uptime Goblin could not record keeps both cookies, and pressing it again also ends the plain-HTTP session', async t => {
  // §20 H1 with §19 G1: the plain-HTTP session's secret crossed the network in clear, so its
  // row is the one a restart must not let back in, and its cookie the one the retry must still
  // carry. Before, the failed answer expired both cookies and nothing could reach the rows.
  const originalError = console.error;
  t.after(() => (console.error = originalError));
  console.error = () => {};
  const { app, port } = await startReal(t, {
    trustProxy: 'loopback',
    allowedHosts: 'goblin.example',
    insecureHttpSessions: true,
  });
  const fail = failingWrites(app);
  const proxy = ['Host: goblin.example', 'X-Forwarded-For: 198.51.100.20'];
  const https = [...proxy, 'X-Forwarded-Proto: https'];
  const body = JSON.stringify({ login: 'admin', password });
  const signIn = (lines, origin) =>
    raw(port, ['POST /api/auth/login HTTP/1.1', ...lines, ...browserWrite(origin)], body);
  const secure = cookieFrom(await signIn(https, 'https://goblin.example'));
  const plain = cookieFrom(await signIn(proxy, 'http://goblin.example'));
  assert.match(secure, /^__Host-goblin_session=/);
  assert.match(plain, /^goblin_session=/);
  const logout = () =>
    raw(
      port,
      [
        'POST /api/auth/logout HTTP/1.1',
        ...https,
        `Cookie: ${secure}; ${plain}`,
        ...browserWrite('https://goblin.example'),
      ],
      '{}'
    );
  fail(1);
  const out = await logout();
  assert.deepEqual([out.status, out.json.code], [503, 'storage_full']);
  assert.equal(out.headers['set-cookie'], undefined, 'the browser keeps both cookies');
  assert.equal((await sessionRows(app)).length, 2, 'neither delete was recorded');
  const again = await logout();
  assert.equal(again.status, 204);
  assert.deepEqual([].concat(again.headers['set-cookie']), [
    '__Host-goblin_session=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0',
    'goblin_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0',
  ]);
  assert.deepEqual(await sessionRows(app), []);
  // Replayed by whoever captured it on the network: ended.
  const replayed = await raw(port, [
    'GET /api/session HTTP/1.1',
    ...proxy,
    `Cookie: ${plain}`,
    'Sec-Fetch-Site: same-origin',
  ]);
  assert.deepEqual([replayed.status, replayed.json.code], [401, 'session_expired']);
});

test('a password change rotates this session and signs out the others; the alias says it is deprecated', async t => {
  const { app, port } = await startReal(t);
  const mine = await login(port, { remember: true });
  const other = await login(port);
  const changed = await tab(port, mine.cookie).send('POST', '/api/account/password', {
    currentPassword: password,
    password: nextPassword,
    confirmPassword: nextPassword,
  });
  assert.equal(changed.status, 200);
  assert.deepEqual(changed.json, {
    ok: true,
    revokedOtherSessions: 1,
    mirrorPending: false,
    reauthenticate: false,
  });
  const rotated = cookieFrom(changed);
  assert.ok(rotated && rotated !== mine.cookie);
  assert.match([].concat(changed.headers['set-cookie'])[0], /; Max-Age=\d+$/, 'still persistent');
  for (const old of [mine.cookie, other.cookie])
    assert.equal((await tab(port, old).get('/api/session')).status, 401);
  assert.equal((await tab(port, rotated).get('/api/session')).status, 200);
  assert.equal((await sessionRows(app)).length, 1);
  // Scripts learn the new password is needed; the 1.4.x address still works, deprecated.
  const alias = await raw(
    port,
    [
      'POST /api/auth/password HTTP/1.1',
      `Authorization: ${basic(nextPassword)}`,
      'X-Goblin-Request: 1',
      'Content-Type: application/json',
    ],
    JSON.stringify({ currentPassword: nextPassword, password, confirmPassword: password })
  );
  assert.equal(alias.status, 200);
  assert.equal(alias.headers.deprecation, '@1790812800');
  assert.deepEqual(alias.json, {
    ok: true,
    revokedOtherSessions: 1,
    mirrorPending: false,
    reauthenticate: true,
  });
  assert.equal((await tab(port, rotated).get('/api/session')).status, 401);
});

test('a password change whose auth.json record cannot be saved (a full disk) still answers 200 with the rotated cookie', async t => {
  // The change committed and auth.json was written, then the disk filled before the write that
  // records it. Before, that failure reached the route after the commit (r5): 500 without
  // Set-Cookie, so the browser was signed out and told the change had failed, its old password
  // was then refused, and the proven current password did not clear the client's failures.
  const warnings = [];
  const log = { info() {}, log() {}, warn: (...args) => warnings.push(args.join(' ')) };
  let fill = false,
    full = 0;
  const writeAuthRecord = (...args) => {
    const written = realWrite(...args);
    if (fill) {
      fill = false;
      full = 1;
    }
    return written;
  };
  const loginThrottle = new LoginThrottle();
  const successes = [];
  const success = loginThrottle.success.bind(loginThrottle);
  loginThrottle.success = client => {
    successes.push(client);
    return success(client);
  };
  const { app, port } = await startReal(t, {
    loginThrottle,
    identityOptions: { log, writeAuthRecord },
  });
  const db = app.control.db,
    write = db.write.bind(db);
  db.write = (...args) =>
    full-- > 0
      ? Promise.reject(
          Object.assign(new Error('database or disk is full'), {
            code: 'SQLITE_FULL',
            class: 'full',
          })
        )
      : write(...args);
  const mine = await login(port, { remember: true });
  const other = await login(port);
  const before = successes.length;
  fill = true;
  const changed = await tab(port, mine.cookie).send('POST', '/api/account/password', {
    currentPassword: password,
    password: nextPassword,
    confirmPassword: nextPassword,
  });
  assert.equal(changed.status, 200);
  assert.deepEqual(changed.json, {
    ok: true,
    revokedOtherSessions: 1,
    // auth.json holds the new password, so a rollback would use it: no banner.
    mirrorPending: false,
    reauthenticate: false,
  });
  assert.deepEqual(successes.slice(before), ['loopback']);
  const rotated = cookieFrom(changed);
  assert.ok(rotated && rotated !== mine.cookie);
  const session = await tab(port, rotated).get('/api/session');
  assert.equal(session.status, 200);
  assert.equal(session.json.mirrorPending, false);
  for (const old of [mine.cookie, other.cookie])
    assert.equal((await tab(port, old).get('/api/session')).status, 401);
  assert.equal((await login(port, { password: nextPassword })).answer.status, 200);
  assert.equal((await login(port)).answer.json.code, 'invalid_credentials');
  assert.deepEqual(warnings, [
    'auth.json now holds the current admin password, but Uptime Goblin could not record that in control.sqlite (full); the next start of Uptime Goblin records it.',
  ]);
});

test('a session request is never counted nor refused by a client lock', async t => {
  const loginThrottle = new LoginThrottle({ freeAttempts: 1, baseMs: 60000 });
  const { port } = await startReal(t, { loginThrottle });
  const { cookie } = await login(port);
  for (let i = 0; i < 3; i++) loginThrottle.failure('loopback');
  assert.ok(loginThrottle.retryAfter('loopback') > 0);
  const me = tab(port, cookie);
  for (let i = 0; i < 5; i++) assert.equal((await me.get('/api/dashboard')).status, 200);
  const expired = tab(port, `goblin_session=v1.${'C'.repeat(43)}`);
  for (let i = 0; i < 5; i++) assert.equal((await expired.get('/api/dashboard')).status, 401);
  // A script from the same client is locked; sign-in too.
  assert.equal(
    (await raw(port, ['GET /api/dashboard HTTP/1.1', `Authorization: ${basic()}`])).status,
    429
  );
  assert.equal((await login(port)).answer.status, 429);
});

// A PATCH waits in exclusive() behind a settings save whose history prune is held.
async function queuedBehindPrune(t, app, port, cookie, extraLines = []) {
  const prune = app.store.prune.bind(app.store);
  let release;
  app.store.prune = async (...args) => {
    await new Promise(resolve => (release = resolve));
    return prune(...args);
  };
  const me = tab(port, cookie);
  const slow = me.send('PATCH', '/api/settings', { retentionDays: 7 });
  while (!release) await new Promise(resolve => setTimeout(resolve, 10));
  const queued = me.send(
    'PATCH',
    '/api/settings',
    { title: 'Saved by an ended session' },
    extraLines
  );
  await new Promise(resolve => setTimeout(resolve, 50));
  return { slow, queued, release: () => release() };
}

test('a write queued behind history work is refused after logout, a revocation or a password change elsewhere', async t => {
  for (const ending of ['logout', 'revoke', 'password']) {
    await t.test(ending, async t => {
      const { app, port } = await startReal(t);
      const { cookie, answer } = await login(port);
      const other = await login(port);
      const { slow, queued, release } = await queuedBehindPrune(t, app, port, cookie);
      if (ending === 'logout')
        assert.equal((await tab(port, cookie).send('POST', '/api/auth/logout')).status, 204);
      if (ending === 'revoke')
        assert.equal(
          (
            await tab(port, other.cookie).send(
              'DELETE',
              `/api/account/sessions/${answer.json.session.id}`
            )
          ).status,
          204
        );
      if (ending === 'password')
        assert.equal(
          (
            await tab(port, other.cookie).send('POST', '/api/account/password', {
              currentPassword: password,
              password: nextPassword,
              confirmPassword: nextPassword,
            })
          ).status,
          200
        );
      release();
      assert.equal((await slow).status, 200, 'it was already running');
      const refused = await queued;
      assert.equal(refused.status, 401);
      assert.equal(refused.json.code, 'session_expired');
      assert.notEqual(app.config.value.title, 'Saved by an ended session');
    });
  }
});

test('the queued PATCH sent with an Idempotency-Key answers the browser’s 401, which is not kept', async t => {
  const { app, port } = await startReal(t);
  const { cookie } = await login(port);
  const key = 'Idempotency-Key: fixture-queued-0001';
  const { slow, queued, release } = await queuedBehindPrune(t, app, port, cookie, [key]);
  assert.equal((await tab(port, cookie).send('POST', '/api/auth/logout')).status, 204);
  release();
  await slow;
  const refused = await queued;
  assert.equal(refused.status, 401);
  assert.deepEqual(refused.json, bodies['401'].session_expired.loopback);
  assert.equal(refused.headers['www-authenticate'], undefined, 'no native prompt in a browser');
  assert.equal(refused.headers['x-goblin-build'], app.build);
  assert.equal(refused.headers['x-goblin-version'], undefined);
  // Signed in again, the retry with the same key runs: the refusal was not kept as its reply.
  const again = await login(port);
  const retried = await tab(port, again.cookie).send(
    'PATCH',
    '/api/settings',
    { title: 'Saved by an ended session' },
    [key]
  );
  assert.equal(retried.status, 200);
  assert.equal(retried.headers['idempotent-replayed'], undefined);
  assert.equal(app.config.value.title, 'Saved by an ended session');
});

test('a keyed write in flight when its session ends is replayed, not run again, after signing in again', async t => {
  const { app, port } = await startReal(t);
  const { cookie } = await login(port);
  const prune = app.store.prune.bind(app.store);
  let release;
  app.store.prune = async (...args) => {
    await new Promise(resolve => (release = resolve));
    return prune(...args);
  };
  const key = 'Idempotency-Key: fixture-inflight-0001';
  const revision = app.config.value.revision;
  const body = { retentionDays: 7, title: 'Saved once' };
  const first = tab(port, cookie).send('PATCH', '/api/settings', body, [key]);
  while (!release) await new Promise(resolve => setTimeout(resolve, 10));
  // The session ends while the save runs (another tab signs this one out).
  const other = await login(port);
  const list = await tab(port, other.cookie).get('/api/account/sessions');
  const target = list.json.sessions.find(view => !view.current).id;
  assert.equal(
    (await tab(port, other.cookie).send('DELETE', `/api/account/sessions/${target}`)).status,
    204
  );
  // The dialog signs in again and retries the save with the same key, joining the first.
  const again = await login(port);
  const retry = tab(port, again.cookie).send('PATCH', '/api/settings', body, [key]);
  await new Promise(resolve => setTimeout(resolve, 50));
  release();
  const [answered, replayed] = await Promise.all([first, retry]);
  assert.equal(answered.status, 200, 'the save that was running completes');
  assert.equal(replayed.status, 200);
  assert.equal(replayed.headers['idempotent-replayed'], 'true');
  assert.deepEqual(replayed.json, answered.json);
  assert.equal(app.config.value.revision, revision + 1, 'ran once');
  // And once more after it finished: still the stored reply.
  const later = await tab(port, again.cookie).send('PATCH', '/api/settings', body, [key]);
  assert.equal(later.headers['idempotent-replayed'], 'true');
  assert.equal(app.config.value.revision, revision + 1);
});

// Delivery spec A62: Replace signing key, Retry and Resume check the session again once they
// have been applied, so a session that ended meanwhile gets 401 (and never the answer). That 401
// must not drop the key's outcome: the Sign in again dialog retries with the same key, and a
// second rotation would push the signing key replaced first out of both slots, ending its 24
// hours.
test('Replace signing key, Retry and Resume applied as their session ended are replayed after signing in again, never applied twice', async t => {
  const answers = JSON.parse(
    fs.readFileSync(new URL('../contract/notifications-bodies.json', import.meta.url), 'utf8')
  ).answers;
  const actions = {
    rotate: { path: '/api/notifications/webhook/signing-secret' },
    retry: {
      path: '/api/notifications/deliveries/d_abcdefghijklmnopqrstuvwxyz/retry',
      answer: answers.retry,
    },
    resume: { path: '/api/notifications/channels/env-webhook/resume', answer: answers.resume },
  };
  for (const [name, action] of Object.entries(actions))
    for (const timing of ['after its 401', 'while it runs'])
      await t.test(`${name}, retried ${timing}`, async t => {
        const { app, port } = await startReal(t, { webhook: 'http://127.0.0.1:1/hook' });
        const settings = async () => (await app.control.settings.get('notify', 'envWebhook')).value;
        const original = (await settings()).signingKey;
        // The service call, counted and held once it has been applied. Rotation is Uptime Goblin's own
        // (persisted settings); Retry and Resume answer the contract bodies.
        const owner = name === 'rotate' ? app.alerting.signing : app.alerting,
          applied = owner[name];
        let calls = 0,
          entered,
          release;
        const running = new Promise(resolve => (entered = resolve)),
          held = new Promise(resolve => (release = resolve));
        t.after(() => release());
        owner[name] = async (...args) => {
          calls++;
          const result = action.answer
            ? structuredClone(action.answer)
            : await applied.apply(owner, args);
          entered();
          await held;
          return result;
        };
        const key = 'Idempotency-Key: fixture-committed-0001';
        const { cookie } = await login(port);
        const first = tab(port, cookie).send('POST', action.path, {}, [key]);
        await running;
        assert.equal((await tab(port, cookie).send('POST', '/api/auth/logout')).status, 204);
        const again = await login(port);
        const send = to => tab(port, to).send('POST', action.path, {}, [key]);
        let joined = null;
        if (timing === 'while it runs') {
          joined = send(again.cookie);
          await new Promise(resolve => setTimeout(resolve, 50));
        }
        release();
        const refused = await first;
        assert.equal(refused.status, 401, refused.body);
        assert.equal(refused.json.code, 'session_expired');
        assert.equal(refused.headers['idempotent-replayed'], undefined);
        assert.equal(refused.body.includes('released'), false, 'no outcome for an ended session');
        assert.equal(refused.body.includes('createdAt'), false, 'no outcome for an ended session');
        // The ended session's own retry is refused, never answered from the kept outcome.
        const stale = await send(cookie);
        assert.equal(stale.status, 401);
        assert.equal(stale.json.code, 'session_expired');
        assert.equal(stale.headers['idempotent-replayed'], undefined);
        // Signed in again, the same key is answered with what was applied, once.
        const retried = joined ? await joined : await send(again.cookie);
        assert.equal(retried.status, 200, retried.body);
        assert.equal(calls, 1, `${name} applied once`);
        assert.equal(retried.headers['idempotent-replayed'], 'true');
        if (action.answer) assert.deepEqual(retried.json, action.answer);
        else {
          const after = await settings();
          assert.notEqual(after.signingKey, original, 'replaced');
          assert.equal(after.previousSigningKey, original, 'the replaced key keeps 24 hours');
          assert.deepEqual(Object.keys(retried.json).sort(), ['createdAt', 'previousUntil']);
          assert.equal(retried.json.createdAt, after.createdAt);
          assert.equal(/KEY-----/.test(retried.body), false, 'no key in the stored answer');
        }
        const later = await send(again.cookie);
        assert.equal(later.headers['idempotent-replayed'], 'true');
        assert.equal(calls, 1);
      });
});

test('a connection test answers 401 when its session is signed out while it runs', async t => {
  let started, release;
  const entered = new Promise(resolve => (started = resolve)),
    held = new Promise(resolve => (release = resolve));
  const { port } = await startReal(t, {
    collector: async () => {
      started();
      await held;
      return [{ key: 'probe', label: 'Probe', value: 1, unit: '' }];
    },
  });
  t.after(() => release());
  const { cookie } = await login(port);
  const me = tab(port, cookie);
  const testing = me.send('POST', '/api/test-service', {
    settings: { type: 'linux', name: 'Probe', apiUrl: 'http://node.example.test:9100' },
  });
  await entered;
  assert.equal((await me.send('POST', '/api/auth/logout')).status, 204);
  release();
  const answer = await testing;
  assert.equal(answer.status, 401);
  assert.equal(answer.json.code, 'session_expired');
  assert.ok(!answer.body.includes('Probe'), 'the readings are discarded');
});

test('a test email answers 401 when its session is signed out while it is sent', async t => {
  let started,
    release,
    sent = 0;
  const entered = new Promise(resolve => (started = resolve)),
    held = new Promise(resolve => (release = resolve));
  const { port } = await startReal(t, {
    mailTransportFactory: () => ({
      sendMail: async () => {
        sent++;
        started();
        await held;
        return { accepted: ['recipient@example.test'], rejected: [] };
      },
      close() {},
    }),
  });
  t.after(() => release());
  const { cookie } = await login(port);
  const me = tab(port, cookie);
  const saved = await me.send('PATCH', '/api/settings', {
    email: {
      ...emailDefaults(),
      enabled: false,
      from: 'sender@example.test',
      to: 'recipient@example.test',
      password: 'private-mail-fixture',
    },
  });
  assert.equal(saved.status, 200, saved.body);
  const testing = me.send('POST', '/api/email/test', {});
  await entered;
  assert.equal((await me.send('POST', '/api/auth/logout')).status, 204);
  release();
  const answer = await testing;
  assert.equal(answer.status, 401);
  assert.equal(answer.json.code, 'session_expired');
  assert.equal(sent, 1, 'the message itself was handed over before the session ended');
});

// Delivery spec A68: a test email checks the session once the mail server has answered, as
// A62's actions do, so a session that ended meanwhile gets 401 and never the outcome. The
// message is out by then: the **Sign in again** dialog's retry with the same key must get that
// outcome, not send a second test email.
test('a test email sent as its session ended is replayed after signing in again, never sent twice', async t => {
  for (const ending of ['revoked', 'signed out'])
    for (const timing of ['after its 401', 'while it runs'])
      for (const outcome of ['accepted', 'refused'])
        await t.test(`${outcome}, the session ${ending}, retried ${timing}`, async t => {
          // The real fake SMTP server: the first message is read and held unanswered (handed
          // over, not yet confirmed); any later one is answered at once.
          let holding = true;
          const smtp = await smtpServer(t, { holdAfterData: () => holding });
          // The send and signing in again take a minute, so the one-test-a-minute limit no
          // longer stands in the way of a second send.
          let skew = 0;
          const { port } = await startReal(t, {
            allowLoopback: true,
            monotonic: () => performance.now() + skew,
            mailTransportFactory: options =>
              nodemailer.createTransport({ ...options, tls: { ...options.tls, ca: smtp.cert } }),
          });
          t.after(() => configureDestinations({ allowLoopback: false }));
          const { cookie, answer } = await login(port);
          const other = await login(port);
          const saved = await tab(port, cookie).send('PATCH', '/api/settings', {
            email: {
              ...emailDefaults(),
              enabled: false,
              host: smtp.host,
              port: smtp.port,
              secure: true,
              from: 'sender@example.test',
              to: 'recipient@example.test',
              password: 'private-mail-fixture',
            },
          });
          assert.equal(saved.status, 200, saved.body);
          const key = 'Idempotency-Key: fixture-email-test-0001';
          const send = to => tab(port, to).send('POST', '/api/email/test', {}, [key]);
          const first = send(cookie);
          while (smtp.held === 0) await new Promise(resolve => setTimeout(resolve, 10));
          // The message is with the mail server; the session ends before it answers.
          const ended =
            ending === 'revoked'
              ? await tab(port, other.cookie).send(
                  'DELETE',
                  `/api/account/sessions/${answer.json.session.id}`
                )
              : await tab(port, cookie).send('POST', '/api/auth/logout');
          assert.equal(ended.status, 204);
          const again = await login(port);
          skew += 61000;
          let joined = null;
          if (timing === 'while it runs') {
            joined = send(again.cookie);
            await new Promise(resolve => setTimeout(resolve, 50));
          }
          holding = false;
          if (outcome === 'accepted') smtp.release();
          else smtp.release('554 5.7.1 Message refused');
          const refused = await first;
          assert.equal(refused.status, 401, refused.body);
          assert.equal(refused.json.code, 'session_expired');
          assert.equal(refused.headers['idempotent-replayed'], undefined);
          assert.equal(/accept|confirm/i.test(refused.body), false, 'no outcome for it');
          // The ended session's own retry is refused, never answered from the kept outcome.
          const stale = await send(cookie);
          assert.equal(stale.status, 401);
          assert.equal(stale.json.code, 'session_expired');
          assert.equal(stale.headers['idempotent-replayed'], undefined);
          // Signed in again, the same key is answered with what the mail server said, once.
          const retried = joined ? await joined : await send(again.cookie);
          assert.equal(smtp.messages.length, 1, 'one test email');
          assert.equal(retried.headers['idempotent-replayed'], 'true');
          if (outcome === 'accepted') {
            assert.equal(retried.status, 200, retried.body);
            assert.deepEqual(Object.keys(retried.json).sort(), [
              'accepted',
              'acceptedAt',
              'message',
              'ok',
            ]);
            assert.equal(retried.json.accepted, true);
          } else {
            assert.equal(retried.status, 422, retried.body);
            assert.match(retried.json.error, /not confirmed by the mail server/);
          }
          const later = await send(again.cookie);
          assert.equal(later.headers['idempotent-replayed'], 'true');
          assert.equal(smtp.messages.length, 1);
        });
});

test('401s and unauthenticated 403s name the build but not the version', async t => {
  const { app, port } = await startReal(t, {
    trustProxy: 'loopback',
    allowedHosts: 'goblin.example',
  });
  const answers = [
    await raw(port, ['GET /api/dashboard HTTP/1.1', 'Sec-Fetch-Site: same-origin']),
    await raw(port, ['GET /api/dashboard HTTP/1.1', `Cookie: goblin_session=v1.${'D'.repeat(43)}`]),
    await raw(port, ['GET /api/dashboard HTTP/1.1', `Authorization: ${basic('wrong')}`]),
    // Sign-in refusals: no session CSRF proof, and a proxy that does not say https.
    await raw(port, ['POST /api/auth/login HTTP/1.1', 'Content-Type: application/json'], '{}'),
    await raw(
      port,
      [
        'POST /api/auth/login HTTP/1.1',
        'Host: goblin.example',
        'X-Forwarded-For: 198.51.100.9',
        ...browserWrite('https://goblin.example'),
      ],
      JSON.stringify({ login: 'admin', password })
    ),
  ];
  assert.deepEqual(
    answers.map(answer => [answer.status, answer.json.code]),
    [
      [401, 'signin_required'],
      [401, 'session_expired'],
      [401, 'invalid_credentials'],
      [403, 'cross_origin'],
      [403, 'proxy_proto_missing'],
    ]
  );
  for (const answer of answers) {
    assert.equal(answer.headers['x-goblin-build'], app.build);
    assert.equal(answer.headers['x-goblin-version'], undefined);
  }
});

test('a sign-in that cannot be saved on a full disk answers 503; an existing session keeps working', async t => {
  const { app, port } = await startReal(t);
  const { cookie } = await login(port);
  // A full disk, made real: control.sqlite may grow by two pages only, and rows of a user that
  // is not the admin (ignored by sign-in, fail closed) fill every page left. The next sign-in
  // then fails with SQLITE_FULL (class 'full').
  const db = app.control.db;
  await db.write(tx => {
    const { page_count: pages } = tx.get(sql`PRAGMA page_count`);
    // PRAGMA values cannot be bound parameters: engine-specific text, as the dialects write it.
    tx.get(fragment([`PRAGMA max_page_count = ${Number(pages) + 2}`], [], 'sqlite'));
  });
  let n = 0;
  // Large rows first, then rows no larger than a sign-in's, so no gap a sign-in fits in is left.
  for (const agent of ['x'.repeat(200), null]) {
    let full = false;
    for (let i = 0; i < 20000 && !full; i++, n++) {
      const now = Date.now();
      try {
        await db.write(tx =>
          tx.run(sql`INSERT INTO sessions (id, token_hash, user_id, kind, stage, via, transport,
            persistent, created_at, auth_time, last_seen_at, idle_expires_at, expires_at,
            client_key, user_agent) VALUES (${`s_f${String(n).padStart(13, '0')}`},
            ${String(n).padStart(64, '0')}, ${'u_filler'}, ${'interactive'}, ${'full'},
            ${'password'}, ${'loopback'}, ${0}, ${now}, ${now}, ${now}, ${now + 3600e3},
            ${now + 3600e3}, ${null}, ${agent})`)
        );
      } catch (error) {
        if (error.class !== 'full') throw error;
        full = true;
      }
    }
    assert.ok(full, 'control.sqlite is full');
  }
  const refused = (await login(port)).answer;
  assert.equal(refused.status, 503);
  assert.equal(refused.json.code, 'storage_full');
  assert.equal(refused.headers['retry-after'], '30');
  const me = tab(port, cookie);
  assert.equal((await me.get('/api/dashboard', ['X-Goblin-Activity: background'])).status, 200);
  assert.equal((await me.get('/api/session')).status, 200);
});

test('removing GOBLIN_INSECURE_HTTP_SESSIONS ends the sessions signed in over plain HTTP, on every transport (D16)', async t => {
  // A cookie captured while plain-HTTP sign-in was allowed must not keep working once the
  // owner fixed TLS and removed the opt-in: not over http, not on loopback, and not as the
  // Secure cookie through the https proxy.
  const proxy = ['Host: goblin.example', 'X-Forwarded-For: 198.51.100.20'];
  const https = [...proxy, 'X-Forwarded-Proto: https'];
  const options = { trustProxy: 'loopback', allowedHosts: 'goblin.example' };
  const body = JSON.stringify({ login: 'admin', password });
  const signIn = (port, lines, origin) =>
    raw(port, ['POST /api/auth/login HTTP/1.1', ...lines, ...browserWrite(origin)], body);
  const get = (port, lines, route = '/api/session') =>
    raw(port, [`GET ${route} HTTP/1.1`, 'Sec-Fetch-Site: same-origin', ...lines]);

  const first = await startReal(t, { ...options, insecureHttpSessions: true });
  const plain = await signIn(first.port, proxy, 'http://goblin.example');
  assert.equal(plain.status, 200);
  assert.match(cookieFrom(plain), /^goblin_session=/);
  const secret = cookieFrom(plain).slice('goblin_session='.length);
  const secure = await signIn(first.port, https, 'https://goblin.example');
  assert.equal(secure.status, 200);
  const owner = `Cookie: ${cookieFrom(secure)}`;
  assert.equal((await get(first.port, [...proxy, `Cookie: goblin_session=${secret}`])).status, 200);
  // Even while it is allowed, the plain-HTTP secret is never the Secure cookie.
  const asSecure = await get(first.port, [...https, `Cookie: __Host-goblin_session=${secret}`]);
  assert.equal(asSecure.status, 401);
  assert.equal(asSecure.json.code, 'session_expired');
  await first.app.close();

  const logged = [];
  const log = {
    info: (...args) => logged.push(args.join(' ')),
    log: (...args) => logged.push(args.join(' ')),
    warn: (...args) => logged.push(args.join(' ')),
    error: (...args) => logged.push(args.join(' ')),
  };
  const second = await startReal(t, {
    ...options,
    directory: first.directory,
    insecureHttpSessions: false,
    identityOptions: { log },
  });
  for (const [lines, cookie, code] of [
    [proxy, `goblin_session=${secret}`, 'signin_required'],
    [https, `__Host-goblin_session=${secret}`, 'session_expired'],
    [[], `goblin_session=${secret}`, 'session_expired'],
  ]) {
    const answer = await get(second.port, [...lines, `Cookie: ${cookie}`]);
    assert.equal(answer.status, 401, cookie);
    assert.equal(answer.json.code, code, cookie);
    const write = await raw(
      second.port,
      [
        'PATCH /api/settings HTTP/1.1',
        ...lines,
        `Cookie: ${cookie}`,
        ...browserWrite('https://goblin.example'),
      ],
      '{}'
    );
    assert.equal(write.status, 401, `settings write with ${cookie}`);
  }
  // The https session is untouched, and the sessions list shows it alone.
  const listed = await get(second.port, [...https, owner], '/api/account/sessions');
  assert.equal(listed.status, 200);
  assert.equal(listed.json.sessions.length, 1);
  assert.equal(listed.json.sessions[0].current, true);
  assert.ok(
    logged.includes(
      'Signed out 1 session that signed in over plain HTTP: GOBLIN_INSECURE_HTTP_SESSIONS is off.'
    ),
    logged.join('\n')
  );
});

test('a stolen session cookie exempts no address from the global lock, before or after it is revoked', async t => {
  // A session proves only that its holder has the cookie (a lost device, a copied cookie): it
  // must not make the addresses it is used from "trusted", or each of them could guess the
  // admin password at sign-in or in a password change while the global lock holds, also after
  // the owner signed the device out and changed the password.
  const loginThrottle = new LoginThrottle();
  const { port } = await startReal(t, {
    trustProxy: 'loopback',
    allowedHosts: 'goblin.example',
    loginThrottle,
  });
  const from = client => [
    'Host: goblin.example',
    `X-Forwarded-For: ${client}`,
    'X-Forwarded-Proto: https',
  ];
  const signIn = (client, secret, lines = []) =>
    raw(
      port,
      [
        'POST /api/auth/login HTTP/1.1',
        ...from(client),
        ...browserWrite('https://goblin.example'),
        ...lines,
      ],
      JSON.stringify({ login: 'admin', password: secret })
    );
  const as = (client, cookie) => ({
    get: route =>
      raw(port, [
        `GET ${route} HTTP/1.1`,
        ...from(client),
        `Cookie: ${cookie}`,
        'Sec-Fetch-Site: same-origin',
      ]),
    send: (method, route, body) =>
      raw(
        port,
        [
          `${method} ${route} HTTP/1.1`,
          ...from(client),
          `Cookie: ${cookie}`,
          ...browserWrite('https://goblin.example'),
        ],
        body === undefined ? '' : JSON.stringify(body)
      ),
  });
  const owner = await signIn('203.0.113.10', password);
  assert.equal(owner.status, 200);
  const stolen = cookieFrom(owner);
  // The thief uses the cookie once from each of many addresses.
  const thieves = Array.from({ length: 6 }, (_, i) => `192.0.2.${100 + i}`);
  for (const client of thieves)
    assert.equal((await as(client, stolen).get('/api/session')).status, 200);
  // Fifty failed sign-ins from fifty addresses trip the global lock.
  for (let i = 1; i <= 50; i++)
    assert.equal((await signIn(`198.51.100.${i}`, `guess ${i}`)).status, 401);
  assert.equal(loginThrottle.globalLocked(), true);
  // Every thief address is refused before any password is checked, at sign-in and in a
  // password change made with the stolen session.
  const guess = await signIn(thieves[0], 'a guess');
  assert.deepEqual(
    [guess.status, guess.json.code, guess.headers['retry-after']],
    [429, 'locked', '60']
  );
  const change = await as(thieves[1], stolen).send('POST', '/api/account/password', {
    currentPassword: 'another guess',
    password: nextPassword,
    confirmPassword: nextPassword,
  });
  assert.deepEqual([change.status, change.json.code], [429, 'locked']);
  // The owner, whose address proved the password, signs the thief out and changes it.
  const kept = await signIn('203.0.113.10', password);
  assert.equal(kept.status, 200, 'the owner’s address is still trusted');
  const me = as('203.0.113.10', cookieFrom(kept));
  assert.deepEqual((await me.send('DELETE', '/api/account/sessions')).json, {
    revoked: 1,
    kept: 0,
  });
  const changed = await me.send('POST', '/api/account/password', {
    currentPassword: password,
    password: nextPassword,
    confirmPassword: nextPassword,
  });
  assert.equal(changed.status, 200);
  const dead = await as(thieves[2], stolen).get('/api/session');
  assert.equal(dead.status, 401, 'the stolen cookie is dead');
  for (const client of thieves) {
    const after = await signIn(client, 'one more guess');
    assert.deepEqual([after.status, after.json.code], [429, 'locked'], client);
  }
});

test('a stolen session that signs out other devices in a loop cannot end a newer sign-in, which ends it', async t => {
  // A cookie from a lost device (or copied over plain HTTP) proves nothing about the password.
  // Its holder ran "Sign out other devices" in a loop and so ended every new sign-in before
  // its owner could sign the cookie out or change the password (review round 5). A sign-in
  // proves the password again, so it outranks every session there is. Real scrypt: the
  // password change spends two derivations while the loop runs.
  const { port } = await startReal(t, { fastKdf: false, legacyBasic: false });
  const sessionOf = async cookie => (await tab(port, cookie).get('/api/session')).status;
  // The thief's loops: "Sign out other devices" back to back, until its session ends.
  const loop = cookie => {
    let calls = 0;
    const run = async () => {
      for (;;) {
        const answer = await tab(port, cookie).send('DELETE', '/api/account/sessions');
        calls += 1;
        if (answer.status !== 200) return answer;
        assert.equal(answer.json.revoked, 0, 'the stolen session ended nobody');
      }
    };
    return { done: Promise.all([run(), run()]), calls: () => calls };
  };

  const thief = await login(port);
  const owner = await login(port);
  const me = tab(port, owner.cookie),
    stolen = tab(port, thief.cookie);
  // Neither way of signing out ends the newer sign-in; the list says why.
  assert.deepEqual((await stolen.send('DELETE', '/api/account/sessions')).json, {
    revoked: 0,
    kept: 1,
  });
  const one = await stolen.send('DELETE', `/api/account/sessions/${owner.answer.json.session.id}`);
  assert.deepEqual([one.status, one.json.code], [403, 'session_newer']);
  assert.match(one.json.error, /^That session signed in after this one, so only a newer sign-in/);
  assert.deepEqual(
    (await stolen.get('/api/account/sessions')).json.sessions.map(view => [
      view.current,
      view.newer,
    ]),
    [
      [true, false],
      [false, true],
    ]
  );
  assert.equal(await sessionOf(owner.cookie), 200);

  // With the loops running, the owner's "Sign out other devices", sent the moment the sign-in
  // answers (as the Sign in again dialog's retry does), ends the stolen session.
  let running = loop(thief.cookie);
  const fresh = await login(port);
  const out = await tab(port, fresh.cookie).send('DELETE', '/api/account/sessions');
  assert.deepEqual([out.status, out.json], [200, { revoked: 2, kept: 0 }]);
  for (const answer of await running.done)
    assert.deepEqual([answer.status, answer.json.code], [401, 'session_expired']);
  assert.ok(running.calls() >= 2);
  assert.equal(await sessionOf(thief.cookie), 401);
  assert.equal(await sessionOf(owner.cookie), 401, 'the fresh sign-in ended the older one too');

  // And a password change, whose two derivations take a while, completes under the loops too.
  assert.equal((await tab(port, fresh.cookie).send('POST', '/api/auth/logout', {})).status, 204);
  const second = await login(port);
  running = loop(second.cookie);
  const mine = await login(port);
  const changed = await tab(port, mine.cookie).send('POST', '/api/account/password', {
    currentPassword: password,
    password: nextPassword,
    confirmPassword: nextPassword,
  });
  assert.deepEqual(
    [changed.status, changed.json.revokedOtherSessions],
    [200, 1],
    JSON.stringify(changed.json)
  );
  for (const answer of await running.done) assert.equal(answer.status, 401);
  assert.equal(await sessionOf(second.cookie), 401);
  assert.equal(await sessionOf(cookieFrom(changed)), 200);
});

test('restoring a backup of the data directory signs every session out, so none ended since comes back', async t => {
  // Sessions live in control.sqlite, so a backup holds every session of its time, those signed
  // out after it included; its auth.json (or the stored GOBLIN_PASSWORD verifier) matches the
  // restored database, so no password import signs anyone out (review round 5).
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-backup-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const directory = path.join(root, 'data'),
    backup = path.join(root, 'backup');
  const lines = [];
  const log = {
    info: (...args) => lines.push(args.join(' ')),
    log: (...args) => lines.push(args.join(' ')),
    warn: (...args) => lines.push(args.join(' ')),
  };
  const start = () => startReal(t, { directory, identityOptions: { log } });
  const restore = () => {
    // As the documented procedure: Uptime Goblin stopped, the directory replaced by the archive's.
    fs.rmSync(directory, { recursive: true, force: true });
    fs.cpSync(backup, directory, { recursive: true });
  };
  const sessionOf = async (port, cookie) => (await tab(port, cookie).get('/api/session')).status;
  const replaced =
    /^control\.sqlite is not the file Uptime Goblin last ran with: .*Every session was signed out/;

  let orbit = await start();
  const phone = await login(orbit.port),
    laptop = await login(orbit.port);
  await orbit.app.close();
  fs.cpSync(directory, backup, { recursive: true });

  // The phone is lost: "Sign out other devices" on the laptop; then a password change.
  orbit = await start();
  assert.equal(
    (await tab(orbit.port, laptop.cookie).send('DELETE', '/api/account/sessions')).json.revoked,
    1
  );
  assert.equal(await sessionOf(orbit.port, phone.cookie), 401);
  assert.equal(lines.filter(line => replaced.test(line)).length, 0, 'a restart is no restore');
  await orbit.app.close();

  restore();
  orbit = await start();
  assert.equal(await sessionOf(orbit.port, phone.cookie), 401, 'the lost phone stays out');
  assert.equal(await sessionOf(orbit.port, laptop.cookie), 401, 'everyone signs in again');
  assert.equal(lines.filter(line => replaced.test(line)).length, 1, lines.join('\n'));
  // A new sign-in survives the restarts that follow: Uptime Goblin's own writes keep the file.
  const again = await login(orbit.port);
  await orbit.app.close();
  orbit = await start();
  assert.equal(await sessionOf(orbit.port, again.cookie), 200);
  assert.equal(lines.filter(line => replaced.test(line)).length, 1);

  // A password change since the backup (env-only: the backup has no auth.json): the restore
  // brings back that time's password and, without this, the sessions the change ended.
  const kept = await login(orbit.port);
  await orbit.app.close();
  fs.rmSync(backup, { recursive: true, force: true });
  fs.cpSync(directory, backup, { recursive: true });
  orbit = await start();
  const mine = await login(orbit.port);
  const changed = await tab(orbit.port, mine.cookie).send('POST', '/api/account/password', {
    currentPassword: password,
    password: nextPassword,
    confirmPassword: nextPassword,
  });
  assert.equal(changed.status, 200);
  assert.equal(await sessionOf(orbit.port, kept.cookie), 401);
  await orbit.app.close();
  restore();
  orbit = await start();
  assert.equal(await sessionOf(orbit.port, kept.cookie), 401, 'ended by the change');
  assert.equal(lines.filter(line => replaced.test(line)).length, 2);
});

test('signing out over https also ends the plain-HTTP session this browser still holds', async t => {
  // With GOBLIN_INSECURE_HTTP_SESSIONS=1 a browser can hold both cookies of one host (signed in
  // over https, then over plain HTTP). Signing out over https expires both cookies; the
  // plain-HTTP session, whose secret crossed the network in clear, must end too, not only be
  // forgotten by this browser. Logout and DELETE of the browser's own session alike.
  const { app, port } = await startReal(t, {
    trustProxy: 'loopback',
    allowedHosts: 'goblin.example',
    insecureHttpSessions: true,
  });
  const proxy = ['Host: goblin.example', 'X-Forwarded-For: 198.51.100.20'];
  const https = [...proxy, 'X-Forwarded-Proto: https'];
  const body = JSON.stringify({ login: 'admin', password });
  const signIn = (lines, origin) =>
    raw(port, ['POST /api/auth/login HTTP/1.1', ...lines, ...browserWrite(origin)], body);
  const get = (lines, cookie) =>
    raw(port, [
      'GET /api/session HTTP/1.1',
      ...lines,
      `Cookie: ${cookie}`,
      'Sec-Fetch-Site: same-origin',
    ]);
  for (const how of ['logout', 'delete']) {
    const secure = cookieFrom(await signIn(https, 'https://goblin.example'));
    const plain = cookieFrom(await signIn(proxy, 'http://goblin.example'));
    assert.match(secure, /^__Host-goblin_session=/);
    assert.match(plain, /^goblin_session=/);
    assert.equal((await get(proxy, plain)).status, 200);
    const both = `Cookie: ${secure}; ${plain}`;
    const current = (await get(https, secure)).json.session.id;
    const out = await raw(
      port,
      how === 'logout'
        ? [
            'POST /api/auth/logout HTTP/1.1',
            ...https,
            both,
            ...browserWrite('https://goblin.example'),
          ]
        : [
            `DELETE /api/account/sessions/${current} HTTP/1.1`,
            ...https,
            both,
            ...browserWrite('https://goblin.example'),
          ]
    );
    assert.equal(out.status, 204, how);
    assert.deepEqual([].concat(out.headers['set-cookie']), [
      '__Host-goblin_session=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0',
      'goblin_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0',
    ]);
    assert.equal((await get(https, secure)).status, 401, how);
    // Replayed by whoever captured it on the network: ended.
    const replayed = await get(proxy, plain);
    assert.equal(replayed.status, 401, how);
    assert.equal(replayed.json.code, 'session_expired');
    assert.deepEqual(await sessionRows(app), [], how);
  }
});

test('a request another site’s page makes with the cookie neither answers nor extends the idle limit', async t => {
  // Another app under the same parent domain, or any page on another port of localhost, is
  // "same-site": the browser sends the SameSite=Strict cookie with an <img> or fetch() it makes
  // to Uptime Goblin. Such a page left open must not keep an idle session signed in for ever (D7).
  let now = Date.UTC(2026, 9, 1, 8);
  const { app, port } = await startReal(t, { identityOptions: { clock: () => now } });
  const { cookie } = await login(port);
  const idle = async () =>
    (await app.control.db.read(tx => tx.all(sql`SELECT idle_expires_at FROM sessions`)))[0]
      .idle_expires_at;
  const started = await idle();
  for (let hour = 1; hour <= 30; hour++) {
    now += 3600e3;
    if (hour % 10) continue;
    const image = await raw(port, [
      'GET /api/version HTTP/1.1',
      `Cookie: ${cookie}`,
      'Sec-Fetch-Site: same-site',
      'Sec-Fetch-Mode: no-cors',
      'Sec-Fetch-Dest: image',
    ]);
    assert.equal(image.status, 403, `hour ${hour}`);
    assert.equal(image.json.code, 'cross_origin');
  }
  assert.equal(await idle(), started, 'the idle limit did not move');
  const after = await tab(port, cookie).get('/api/session');
  assert.equal(after.status, 401, '12 idle hours ended it');
  assert.equal(after.json.code, 'session_expired');
});

// §19 G1: cookies of Uptime Goblin's name that another site set (another port of the host, a parent
// domain, an injection over plain HTTP) reach Uptime Goblin beside the browser's own. Sent first when
// their path is longer, the way a browser orders them.
const plantedCookies = () => [
  `goblin_session=${newSession().value}`,
  'goblin_session=x',
  ...Array.from({ length: 6 }, () => `goblin_session=${newSession().value}`),
];

test('a sign-out sent with another site’s goblin_session cookie still ends the browser’s session and expires its cookie', async t => {
  const { app, port } = await startReal(t);
  const { cookie } = await login(port);
  const bystander = await login(port);
  const other = (await tab(port, bystander.cookie).get('/api/session')).json.session.id;
  const both = [...plantedCookies(), cookie].join('; ');
  const send = lines =>
    raw(port, ['POST /api/auth/logout HTTP/1.1', `Cookie: ${both}`, ...lines], '{}');
  // Still a write held to the session rule (§6.7): another site's page cannot sign it out, and
  // nothing is ended or expired.
  const origin = `http://127.0.0.1:${port}`;
  for (const [lines, status] of [
    [browserWrite(`http://127.0.0.1:${port + 1}`), 403],
    [browserWrite(origin).filter(line => !line.startsWith('Origin')), 403],
    [browserWrite(origin).filter(line => !line.startsWith('X-Goblin-Request')), 403],
    [
      browserWrite(origin).map(line =>
        line.startsWith('Sec-Fetch-Site') ? 'Sec-Fetch-Site: same-site' : line
      ),
      403,
    ],
    [browserWrite(origin).filter(line => !line.startsWith('Content-Type')), 415],
  ]) {
    const refused = await send(lines);
    assert.equal(refused.status, status, lines.join(' | '));
    assert.equal(refused.headers['set-cookie'], undefined);
    assert.equal((await sessionRows(app)).length, 2);
  }
  const out = await send(browserWrite(origin));
  assert.equal(out.status, 200);
  assert.deepEqual(out.json, {
    signedOut: true,
    code: 'multiple_credentials',
    message:
      "Signed out. This browser also sent an Uptime Goblin sign-in cookie that another site set, which Uptime Goblin cannot remove: remove this site's cookies in the browser before signing in again.",
  });
  assert.deepEqual([].concat(out.headers['set-cookie']), [
    'goblin_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0',
  ]);
  assert.equal(out.headers['clear-site-data'], '"cache"');
  assert.equal(out.headers['cache-control'], 'no-store');
  assert.equal(out.headers['x-goblin-version'], undefined, 'not a signed-in answer');
  // The browser's own session ended; another device's did not.
  assert.deepEqual(
    (await sessionRows(app)).map(row => row.id),
    [other]
  );
  const after = await tab(port, cookie).get('/api/session');
  assert.equal(after.status, 401);
  assert.equal(after.json.code, 'session_expired');
  // Every session the request carried ends, the other device's too when its cookie is sent.
  const second = await login(port);
  const out2 = await raw(
    port,
    [
      'POST /api/auth/logout HTTP/1.1',
      `Cookie: ${second.cookie}; ${bystander.cookie}`,
      ...browserWrite(origin),
    ],
    '{}'
  );
  assert.equal(out2.status, 200);
  assert.deepEqual(await sessionRows(app), []);
  // Any other request with two cookies is refused as before, and so is a script that sends an
  // Authorization beside them.
  const third = await login(port);
  const twice = `Cookie: goblin_session=x; ${third.cookie}`;
  const read = await raw(port, ['GET /api/session HTTP/1.1', twice, 'Sec-Fetch-Site: same-origin']);
  assert.equal(read.status, 401);
  assert.equal(read.json.code, 'multiple_credentials');
  const script = await raw(
    port,
    [
      'POST /api/auth/logout HTTP/1.1',
      twice,
      `Authorization: ${basic()}`,
      'X-Goblin-Request: 1',
      'Content-Type: application/json',
      `Origin: ${origin}`,
    ],
    '{}'
  );
  assert.equal(script.status, 401);
  assert.equal(script.json.code, 'multiple_credentials');
  assert.equal((await sessionRows(app)).length, 1);
});

test('signing in with another site’s goblin_session cookie still rotates the presented session', async t => {
  const { app, port } = await startReal(t);
  const old = await login(port);
  const fresh = await login(port, {
    lines: [`Cookie: ${[...plantedCookies(), old.cookie].join('; ')}`],
  });
  assert.equal(fresh.answer.status, 200);
  assert.deepEqual(
    (await sessionRows(app)).map(row => row.id),
    [fresh.answer.json.session.id]
  );
  assert.equal((await tab(port, old.cookie).get('/api/session')).status, 401);
  assert.equal((await tab(port, fresh.cookie).get('/api/session')).status, 200);
});

test('on https a second goblin_session cookie does not keep the plain-HTTP session from ending at sign-in or sign-out', async t => {
  // The attacker this protects against is on the plain-HTTP path: having captured the
  // plain-HTTP cookie, they can also inject more cookies of its name.
  const proxy = ['Host: goblin.example', 'X-Forwarded-For: 198.51.100.21'];
  const https = [...proxy, 'X-Forwarded-Proto: https'];
  const body = JSON.stringify({ login: 'admin', password });
  for (const how of ['login', 'logout', 'delete']) {
    const { app, port } = await startReal(t, {
      trustProxy: 'loopback',
      allowedHosts: 'goblin.example',
      insecureHttpSessions: true,
    });
    const signIn = (lines, origin) =>
      raw(port, ['POST /api/auth/login HTTP/1.1', ...lines, ...browserWrite(origin)], body);
    const get = (lines, cookie) =>
      raw(port, [
        'GET /api/session HTTP/1.1',
        ...lines,
        `Cookie: ${cookie}`,
        'Sec-Fetch-Site: same-origin',
      ]);
    const secure = cookieFrom(await signIn(https, 'https://goblin.example'));
    const plain = cookieFrom(await signIn(proxy, 'http://goblin.example'));
    assert.equal((await get(proxy, plain)).status, 200, how);
    const cookies = `Cookie: ${[...plantedCookies(), plain, secure].join('; ')}`;
    let out;
    if (how === 'login')
      out = await raw(
        port,
        [
          'POST /api/auth/login HTTP/1.1',
          ...https,
          cookies,
          ...browserWrite('https://goblin.example'),
        ],
        body
      );
    else {
      const current = (await get(https, secure)).json.session.id;
      out = await raw(
        port,
        [
          how === 'logout'
            ? 'POST /api/auth/logout HTTP/1.1'
            : `DELETE /api/account/sessions/${current} HTTP/1.1`,
          ...https,
          cookies,
          ...browserWrite('https://goblin.example'),
        ],
        '{}'
      );
    }
    assert.equal(out.status, how === 'login' ? 200 : 204, how);
    assert.ok(
      []
        .concat(out.headers['set-cookie'])
        .includes('goblin_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0'),
      how
    );
    const replayed = await get(proxy, plain);
    assert.equal(replayed.status, 401, how);
    assert.equal(replayed.json.code, 'session_expired', how);
    assert.deepEqual(
      (await sessionRows(app)).map(row => row.id),
      how === 'login' ? [out.json.session.id] : [],
      how
    );
  }
});

/**
 * Holds the next control.sqlite read whose callback `matches` once armed (arm()): `reached`
 * resolves when it is reached, release() lets it run. Every other read passes straight on.
 */
function holdRead(t, app, matches = () => true) {
  const db = app.control.db,
    read = db.read;
  let armed = false,
    release,
    reached;
  const gate = new Promise(resolve => (release = resolve)),
    entered = new Promise(resolve => (reached = resolve));
  db.read = function (fn, ...rest) {
    if (!armed || !matches(fn)) return read.call(this, fn, ...rest);
    armed = false;
    reached();
    return gate.then(() => read.call(this, fn, ...rest));
  };
  t.after(() => {
    db.read = read;
    release();
  });
  return { arm: () => (armed = true), reached: entered, release: () => release() };
}
// The read of the user's sessions (identity's listSessions and revokeOtherSessions).
const sessionsRead = fn => String(fn).includes('userSessions(');
/** The audit entries of `action`, as a session of `cookie` lists them. */
const entriesOf = async (port, cookie, action) =>
  (await tab(port, cookie).get(`/api/audit?action=${action}`)).json.entries;

test('signed out while its session list was read: 401, and nothing of the list is sent', async t => {
  const { app, port } = await startReal(t);
  const { cookie } = await login(port);
  const hold = holdRead(t, app, sessionsRead);
  hold.arm();
  const pending = tab(port, cookie).get('/api/account/sessions');
  await hold.reached;
  assert.equal((await tab(port, cookie).send('POST', '/api/auth/logout')).status, 204);
  hold.release();
  const answer = await pending;
  assert.deepEqual([answer.status, answer.json.code], [401, 'session_expired']);
  assert.equal(answer.body.includes('sessions'), false);
});

// Sessions spec §5.9: a revocation re-checks its own session after its read. A stolen cookie's
// "Sign out other devices", still reading when the admin signs it out, ends only what it had signed
// out before the read, while it was current, and is answered 401 with no entry of its own.
test('Sign out other devices, or one device, from a session that ends while it reads: 401, nothing more ended or recorded', async t => {
  const { app, port } = await startReal(t);
  const c = await login(port);
  const a = await login(port);
  const b = await login(port);
  const hold = holdRead(t, app, sessionsRead);
  hold.arm();
  const others = tab(port, a.cookie).send('DELETE', '/api/account/sessions');
  await hold.reached;
  const signedOut = await tab(port, b.cookie).send(
    'DELETE',
    `/api/account/sessions/${a.answer.json.session.id}`
  );
  assert.equal(signedOut.status, 204);
  hold.release();
  const answer = await others;
  assert.deepEqual([answer.status, answer.json.code], [401, 'session_expired']);
  assert.equal(answer.body.includes('revoked'), false, 'no count for an ended session');
  // c was live here and older: a signed it out before its read, while a was still current.
  assert.equal((await tab(port, c.cookie).get('/api/session')).status, 401);
  assert.equal((await tab(port, b.cookie).get('/api/session')).status, 200);
  assert.deepEqual(await entriesOf(port, b.cookie, 'session.revoked-others'), []);
  // Uptime Goblin's removal names c, the one session removed, as its target; never a, which had ended.
  assert.deepEqual(
    (await entriesOf(port, b.cookie, 'session.revoked')).map(entry => [
      entry.outcome,
      entry.detail,
      entry.target?.id ?? null,
      entry.actor?.sessionId ?? null,
    ]),
    [
      ['info', { cause: 'ended_part_way', count: 1 }, c.answer.json.session.id, null],
      ['ok', { cause: 'by_user' }, a.answer.json.session.id, b.answer.json.session.id],
    ]
  );

  // Signing out one device: e signs out d, and e's own session ends during the lookup. d, live
  // here, was signed out before the lookup, while e was current: it stays signed out, recorded
  // as Uptime Goblin's removal of d (naming e neither as its target nor as its actor); e gets 401, with
  // no entry of its own.
  const d = await login(port);
  const e = await login(port);
  const f = await login(port);
  const lookup = holdRead(t, app, fn => String(fn).includes('identityOps.session(tx'));
  lookup.arm();
  const one = tab(port, e.cookie).send(
    'DELETE',
    `/api/account/sessions/${d.answer.json.session.id}`
  );
  await lookup.reached;
  const eId = e.answer.json.session.id;
  assert.equal(
    (await tab(port, f.cookie).send('DELETE', `/api/account/sessions/${eId}`)).status,
    204
  );
  lookup.release();
  const refused = await one;
  assert.deepEqual([refused.status, refused.json.code], [401, 'session_expired']);
  assert.equal((await tab(port, d.cookie).get('/api/session')).status, 401);
  assert.deepEqual(
    (await entriesOf(port, f.cookie, 'session.revoked'))
      .slice(0, 2)
      .map(entry => [
        entry.outcome,
        entry.detail,
        entry.target?.id ?? null,
        entry.actor?.sessionId ?? null,
      ]),
    [
      // Uptime Goblin's removal names d, the session it removed, as its target.
      ['info', { cause: 'ended_part_way', count: 1 }, d.answer.json.session.id, null],
      ['ok', { cause: 'by_user' }, eId, f.answer.json.session.id],
    ]
  );
});

// The account routes take no body (`body: 'empty'`), and the pipeline reads that body after the
// session signed the request in: a client that withholds it (Content-Length: 2, then nothing)
// keeps the request waiting for up to the request timeout. A session signed out meanwhile ends
// nothing when the body then comes: not the sessions live here, which a revocation signs out
// before its first await, nor the one it names; and nothing is recorded for it.
test('Sign out other devices, or one device, from a session signed out while its body was awaited: 401, nothing ended or recorded', async t => {
  const { port } = await startReal(t);
  const sockets = [];
  t.after(() => sockets.forEach(socket => socket.destroy()));
  // Sends the request's line and headers now, with Expect: 100-continue, and its body ({}) once
  // send() is called. Uptime Goblin sends 100 Continue only when it starts to read the body, after the
  // session signed the request in and every check before the handler (`continued`).
  const withheld = (cookie, method, route) => {
    const socket = net.connect(port, '127.0.0.1');
    sockets.push(socket);
    let text = '',
      reached;
    const continued = new Promise(resolve => (reached = resolve));
    socket.on('data', chunk => {
      text += chunk.toString('latin1');
      if (text.startsWith('HTTP/1.1 100 ')) reached(true);
      else if (text.includes('\r\n\r\n')) reached(false);
    });
    socket.on('error', () => {});
    const answer = new Promise(resolve => socket.on('close', () => resolve(text)));
    const head = [
      `${method} ${route} HTTP/1.1`,
      `Host: 127.0.0.1:${port}`,
      `Cookie: ${cookie}`,
      ...browserWrite(`http://127.0.0.1:${port}`),
      'Content-Length: 2',
      'Expect: 100-continue',
      'Connection: close',
    ];
    socket.write(`${head.join('\r\n')}\r\n\r\n`);
    return { continued, send: () => socket.write('{}'), answer };
  };
  for (const which of ['others', 'one']) {
    const c = await login(port); // an older device, still signed in
    const d = await login(port); // another older device
    const a = await login(port); // a stolen cookie, say
    const b = await login(port); // the admin, signed in again
    const [aId, bId, dId] = [a, b, d].map(session => session.answer.json.session.id);
    const route = which === 'others' ? '/api/account/sessions' : `/api/account/sessions/${dId}`;
    const before = (await entriesOf(port, b.cookie, 'session.revoked')).length;
    const pending = withheld(a.cookie, 'DELETE', route);
    assert.equal(await pending.continued, true, `${which}: a's request waits for its body`);
    // The admin signs the stolen session out while its request waits for its body.
    assert.equal(
      (await tab(port, b.cookie).send('DELETE', `/api/account/sessions/${aId}`)).status,
      204,
      which
    );
    pending.send();
    const text = (await pending.answer).replace(/^HTTP\/1\.1 100 [^\r]*\r\n\r\n/, '');
    assert.match(text, /^HTTP\/1\.1 401 /, which);
    assert.match(text, /"code":"session_expired"/, which);
    assert.doesNotMatch(text, /revoked/, `${which}: no count for an ended session`);
    for (const session of [c, d, b])
      assert.equal((await tab(port, session.cookie).get('/api/session')).status, 200, which);
    // Only the admin's revocation of a: no removal by Uptime Goblin, no revocation as a's.
    const entries = await entriesOf(port, b.cookie, 'session.revoked');
    assert.deepEqual(
      entries
        .slice(0, entries.length - before)
        .map(entry => [entry.outcome, entry.detail, entry.target?.id, entry.actor?.sessionId]),
      [['ok', { cause: 'by_user' }, aId, bId]],
      which
    );
    assert.deepEqual(await entriesOf(port, b.cookie, 'session.revoked-others'), [], which);
  }
});

// The account routes check the session once more before answering: a session that ends just
// after its revocation was saved learns nothing of the result (the revocation stands).
test('Sign out other devices, or one device, answered after the session ended: 401, the revocation stands', async t => {
  const { app, port } = await startReal(t);
  const db = app.control.db,
    write = db.write;
  t.after(() => (db.write = write));
  // The next write is saved, then held before the request goes on.
  const holdAfterNextWrite = () => {
    let release, reached;
    const gate = new Promise(resolve => (release = resolve)),
      entered = new Promise(resolve => (reached = resolve));
    db.write = function (...args) {
      db.write = write;
      return write.apply(this, args).then(async result => {
        reached();
        await gate;
        return result;
      });
    };
    return { reached: entered, release: () => release() };
  };
  for (const route of ['/api/account/sessions', 'one']) {
    const older = await login(port);
    const mine = await login(port);
    const path = route === 'one' ? `/api/account/sessions/${older.answer.json.session.id}` : route;
    const hold = holdAfterNextWrite();
    const pending = tab(port, mine.cookie).send('DELETE', path);
    await hold.reached;
    assert.equal(
      (await tab(port, mine.cookie).send('POST', '/api/auth/logout')).status,
      204,
      route
    );
    hold.release();
    const answer = await pending;
    assert.deepEqual([answer.status, answer.json.code], [401, 'session_expired'], route);
    assert.equal(answer.body.includes('revoked'), false, route);
    assert.equal((await tab(port, older.cookie).get('/api/session')).status, 401, route);
  }
});

// Delivery spec A62 covers a write applied before its session ended. One whose session ends
// while it still reads must not be applied: Replace signing key checks the session again in the
// unit that would save the new key, and the public key's read after it read the document.
test('Replace signing key and Show public key whose session ends while the key is read: 401, nothing replaced, shown or logged', async t => {
  const { app, port } = await startReal(t, { webhook: 'http://127.0.0.1:1/hook' });
  const secret = async () => (await app.control.settings.get('notify', 'envWebhook')).value;
  const before = await secret();
  // The service's first read once it is called: the settings document.
  const holdService = name => {
    const hold = holdRead(t, app),
      signing = app.alerting.signing,
      original = signing[name];
    signing[name] = (...args) => {
      signing[name] = original;
      hold.arm();
      return original.apply(signing, args);
    };
    return hold;
  };
  const warned = [];
  const warn = console.warn;
  console.warn = (...args) => {
    warned.push(args.join(' '));
    warn(...args);
  };
  t.after(() => (console.warn = warn));

  let { cookie } = await login(port);
  let hold = holdService('rotate');
  const rotation = tab(port, cookie).send('POST', '/api/notifications/webhook/signing-secret', {}, [
    'Idempotency-Key: ended-rotate-0001',
  ]);
  await hold.reached;
  assert.equal((await tab(port, cookie).send('POST', '/api/auth/logout')).status, 204);
  hold.release();
  const rotated = await rotation;
  assert.deepEqual([rotated.status, rotated.json.code], [401, 'session_expired']);
  assert.deepEqual(await secret(), before, 'the key was not replaced');
  ({ cookie } = await login(port));
  assert.deepEqual(await entriesOf(port, cookie, 'signing.rotate'), []);
  assert.equal(
    warned.some(line => /signing key was replaced/.test(line)),
    false
  );
  // Signed in again, the same key replaces it: nothing was kept for the ended session.
  const again = await tab(port, cookie).send(
    'POST',
    '/api/notifications/webhook/signing-secret',
    {},
    ['Idempotency-Key: ended-rotate-0001']
  );
  assert.equal(again.status, 200);
  assert.equal(again.headers['idempotent-replayed'], undefined);
  assert.notEqual((await secret()).signingKey, before.signingKey);

  hold = holdService('publicKeys');
  const read = tab(port, cookie).get('/api/notifications/webhook/public-key');
  await hold.reached;
  assert.equal((await tab(port, cookie).send('POST', '/api/auth/logout')).status, 204);
  hold.release();
  const shown = await read;
  assert.deepEqual([shown.status, shown.json.code], [401, 'session_expired']);
  assert.equal(/KEY-----/.test(shown.body), false, 'no key for an ended session');
  // Signed in again it reads: public material only, never logged as shown.
  ({ cookie } = await login(port));
  const keys = await tab(port, cookie).get('/api/notifications/webhook/public-key');
  assert.equal(keys.status, 200);
  assert.match(keys.json.publicKey, /^-----BEGIN PUBLIC KEY-----\n/);
  assert.equal(/PRIVATE KEY/.test(keys.body), false);
  assert.equal(
    warned.some(line => /was shown/.test(line)),
    false,
    'not logged'
  );
});
