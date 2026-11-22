// The names from before the rename to Uptime Goblin (Orbit) keep working in 1.5 (lib/legacy-names.mjs):
// the ORBIT_ settings, the X-Orbit- request headers, the orbit_session cookie, orbit.lock and
// lib/cli/orbit-admin.mjs. Each new name decides alone where both are given.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  adoptLegacyDataMount,
  adoptLegacyEnvironment,
  currentVariableName,
  legacyEnvironmentNotice,
  requestHeader,
  withCurrentNames,
} from '../lib/legacy-names.mjs';
import { crossOrigin, strictCrossOrigin } from '../lib/http/pipeline.mjs';
import { browserContext } from '../lib/http/transport.mjs';
import { acquireLock, isLocked, LockHeldError } from '../lib/db/lock.mjs';
import { holdExclusive } from '../lib/db/sqlite.mjs';
import { main } from '../lib/cli/goblin-admin.mjs';
import { startOrbit } from './helpers/orbit.mjs';
import { browserHeaders, signIn } from './helpers/session.mjs';
import { freePortSync } from './helpers/net.mjs';

const repository = fileURLToPath(new URL('../', import.meta.url));
const serverFile = path.join(repository, 'server.mjs');
const password = 'legacy-names-test-password';

function temporary(t, prefix = 'goblin-legacy-') {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

test('ORBIT_X becomes GOBLIN_X while that is unset, and leaves the environment in every case', () => {
  const env = {
    ORBIT_DATA_DIR: '/srv/data',
    ORBIT_PASSWORD: 'p'.repeat(16),
    GOBLIN_TRUST_PROXY: 'loopback',
    ORBIT_TRUST_PROXY: 'loopback',
    ORBIT_MISSPELT: 'x',
    HOST: '127.0.0.1',
  };
  const result = adoptLegacyEnvironment(env);
  assert.deepEqual(result, {
    renamed: ['ORBIT_DATA_DIR', 'ORBIT_PASSWORD', 'ORBIT_MISSPELT'],
    duplicates: ['ORBIT_TRUST_PROXY'],
  });
  assert.deepEqual(env, {
    GOBLIN_DATA_DIR: '/srv/data',
    GOBLIN_PASSWORD: 'p'.repeat(16),
    GOBLIN_TRUST_PROXY: 'loopback',
    GOBLIN_MISSPELT: 'x',
    HOST: '127.0.0.1',
  });
  // An empty old value is taken as it is: empty is every reader's "default".
  const empty = { ORBIT_ALLOW_LOOPBACK: '' };
  adoptLegacyEnvironment(empty);
  assert.deepEqual(empty, { GOBLIN_ALLOW_LOOPBACK: '' });
  assert.equal(currentVariableName('ORBIT_SECRET_KEY'), 'GOBLIN_SECRET_KEY');
  assert.equal(currentVariableName('GOBLIN_SECRET_KEY'), null);

  const notice = legacyEnvironmentNotice(result);
  assert.match(notice, /^Deprecated settings: ORBIT_DATA_DIR → GOBLIN_DATA_DIR, /);
  assert.match(notice, /ORBIT_TRUST_PROXY → GOBLIN_TRUST_PROXY/);
  assert.match(notice, /no longer from 1\.7/);
  assert.match(notice, /remove the old one/);
  // Never a value.
  assert.doesNotMatch(notice, /pppp|\/srv\/data|loopback/);
  assert.equal(legacyEnvironmentNotice({ renamed: [], duplicates: [] }), null);
  assert.equal(legacyEnvironmentNotice(adoptLegacyEnvironment({ HOST: 'x' })), null);
});

test('ORBIT_X and GOBLIN_X set to different values refuse (78), naming both, never the values, and change nothing', () => {
  for (const [current, legacy] of [
    ['secret-one-value', 'secret-two-value'],
    ['', '1'],
    ['1', ''],
  ]) {
    const env = { GOBLIN_PASSWORD: current, ORBIT_PASSWORD: legacy, ORBIT_DATA_DIR: '/srv/d' };
    const before = { ...env };
    assert.throws(
      () => adoptLegacyEnvironment(env),
      error =>
        error.refusal === true &&
        /^GOBLIN_PASSWORD and ORBIT_PASSWORD are both set, to different values/.test(
          error.message
        ) &&
        !error.message.includes('secret-') &&
        !error.message.includes('/srv/d')
    );
    assert.deepEqual(env, before);
    assert.throws(() => withCurrentNames(before), { refusal: true });
  }
  // withCurrentNames copies: the given object keeps its old names.
  const given = { ORBIT_LEGACY_BASIC: '0' };
  assert.deepEqual(withCurrentNames(given), { GOBLIN_LEGACY_BASIC: '0' });
  assert.deepEqual(given, { ORBIT_LEGACY_BASIC: '0' });
});

// Under Docker Compose the container never sees ORBIT_X: compose.yaml has resolved GOBLIN_X from
// GOBLIN_X, else ORBIT_X, and passes each ORBIT_X that .env sets as GOBLIN_COMPOSE_LEGACY_X
// (compose-unset where it sets none). The contract still holds: a conflict refuses (78), an
// empty GOBLIN_ value is set (so GOBLIN_WEBHOOK_URL= beside an old ORBIT_WEBHOOK_URL refuses
// rather than delivering to the old URL), an old name gets the notice, and every
// GOBLIN_COMPOSE_LEGACY_ name leaves the environment.
test('under Compose the ORBIT_ names arrive as GOBLIN_COMPOSE_LEGACY_X: compared, refused when they differ, named in the notice, then dropped', () => {
  const unset = 'compose-unset';
  // What compose.yaml makes of a .env from 1.4.x (ORBIT_ names only).
  const old = {
    GOBLIN_PASSWORD: 'p'.repeat(16),
    GOBLIN_WEBHOOK_URL: 'https://hooks.example.com/a',
    GOBLIN_ALLOWED_HOSTS: 'goblin.example.com',
    GOBLIN_PUBLISHED_ADDRESS: '192.0.2.5',
    GOBLIN_TRUST_PROXY: '',
    GOBLIN_COMPOSE_LEGACY_PASSWORD: 'p'.repeat(16),
    GOBLIN_COMPOSE_LEGACY_WEBHOOK_URL: 'https://hooks.example.com/a',
    GOBLIN_COMPOSE_LEGACY_ALLOWED_HOSTS: 'goblin.example.com',
    GOBLIN_COMPOSE_LEGACY_BIND_ADDRESS: '192.0.2.5',
    GOBLIN_COMPOSE_LEGACY_TRUST_PROXY: unset,
  };
  const result = adoptLegacyEnvironment(old);
  assert.deepEqual(result.renamed.toSorted(), [
    'ORBIT_ALLOWED_HOSTS',
    'ORBIT_BIND_ADDRESS',
    'ORBIT_PASSWORD',
    'ORBIT_WEBHOOK_URL',
  ]);
  assert.deepEqual(old, {
    GOBLIN_PASSWORD: 'p'.repeat(16),
    GOBLIN_WEBHOOK_URL: 'https://hooks.example.com/a',
    GOBLIN_ALLOWED_HOSTS: 'goblin.example.com',
    GOBLIN_PUBLISHED_ADDRESS: '192.0.2.5',
    GOBLIN_TRUST_PROXY: '',
  });
  const notice = legacyEnvironmentNotice(result);
  assert.match(notice, /ORBIT_BIND_ADDRESS → GOBLIN_BIND_ADDRESS/);
  assert.match(notice, /ORBIT_WEBHOOK_URL → GOBLIN_WEBHOOK_URL/);
  assert.doesNotMatch(notice, /hooks\.example|pppp|192\.0\.2/);
  // A .env with the new names only: nothing to say.
  const current = { GOBLIN_WEBHOOK_URL: '', GOBLIN_COMPOSE_LEGACY_WEBHOOK_URL: unset };
  assert.equal(legacyEnvironmentNotice(adoptLegacyEnvironment(current)), null);
  assert.deepEqual(current, { GOBLIN_WEBHOOK_URL: '' });
  // Both names in .env, different: refused, naming both, never a value, nothing changed. An
  // empty GOBLIN_WEBHOOK_URL (meant to turn it off) is set, and differs from the old URL.
  for (const [env, names] of [
    [
      {
        GOBLIN_WEBHOOK_URL: '',
        GOBLIN_COMPOSE_LEGACY_WEBHOOK_URL: 'https://hooks.example.com/old',
      },
      'GOBLIN_WEBHOOK_URL and ORBIT_WEBHOOK_URL',
    ],
    [
      {
        GOBLIN_PASSWORD: 'n'.repeat(16),
        GOBLIN_COMPOSE_LEGACY_PASSWORD: 'o'.repeat(16),
      },
      'GOBLIN_PASSWORD and ORBIT_PASSWORD',
    ],
    [
      {
        GOBLIN_PUBLISHED_ADDRESS: '127.0.0.1',
        GOBLIN_COMPOSE_LEGACY_BIND_ADDRESS: '192.0.2.5',
      },
      'GOBLIN_BIND_ADDRESS and ORBIT_BIND_ADDRESS',
    ],
  ]) {
    const before = { ...env };
    assert.throws(
      () => adoptLegacyEnvironment(env),
      error =>
        error.refusal === true &&
        error.message.startsWith(`${names} are both set, to different values`) &&
        !/hooks\.example|nnnn|oooo|192\.0\.2/.test(error.message)
    );
    assert.deepEqual(env, before);
  }
  // The same value under both names: accepted, with the notice.
  const same = {
    GOBLIN_AUDIT_LOG: 'stdout',
    GOBLIN_COMPOSE_LEGACY_AUDIT_LOG: 'stdout',
  };
  assert.match(
    legacyEnvironmentNotice(adoptLegacyEnvironment(same)),
    /ORBIT_AUDIT_LOG → GOBLIN_AUDIT_LOG/
  );
  assert.deepEqual(same, { GOBLIN_AUDIT_LOG: 'stdout' });
  // compose.yaml reads an empty GOBLIN_ or ORBIT_ line of GOBLIN_BIND_ADDRESS and
  // GOBLIN_ALLOWED_HOSTS as unset (an empty one must not publish the port on every address):
  // an empty old line is not compared with the default compose.yaml put in its place.
  const empty = {
    GOBLIN_ALLOWED_HOSTS: 'localhost:4317',
    GOBLIN_PUBLISHED_ADDRESS: '127.0.0.1',
    GOBLIN_COMPOSE_LEGACY_ALLOWED_HOSTS: '',
    GOBLIN_COMPOSE_LEGACY_BIND_ADDRESS: '',
  };
  assert.equal(legacyEnvironmentNotice(adoptLegacyEnvironment(empty)), null);
  assert.deepEqual(empty, {
    GOBLIN_ALLOWED_HOSTS: 'localhost:4317',
    GOBLIN_PUBLISHED_ADDRESS: '127.0.0.1',
  });
  // A real ORBIT_X beside its compose copy (not compose.yaml's doing): the real one decides.
  const both = {
    ORBIT_LEGACY_BASIC: '1',
    GOBLIN_COMPOSE_LEGACY_LEGACY_BASIC: '0',
  };
  adoptLegacyEnvironment(both);
  assert.deepEqual(both, { GOBLIN_LEGACY_BASIC: '1' });
});

// `node server.mjs` with `env` and a clean environment, stopped once ready.
function runServer(env) {
  return new Promise(resolve => {
    const child = spawn(process.execPath, [serverFile], {
      cwd: repository,
      env: { PATH: process.env.PATH, HOST: '127.0.0.1', PORT: freePortSync(), ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '',
      stderr = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), 20000);
    child.stdout.on('data', chunk => {
      stdout += chunk;
      if (/Uptime Goblin is ready at/.test(stdout)) child.kill('SIGTERM');
    });
    child.stderr.on('data', chunk => (stderr += chunk));
    child.on('exit', code => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });
}

test('node server.mjs starts on ORBIT_ settings with one notice, and refuses (78) a conflict before anything is written', async t => {
  const base = temporary(t);
  const data = path.join(base, 'data');
  const started = await runServer({
    ORBIT_DATA_DIR: data,
    ORBIT_PASSWORD: password,
  });
  assert.equal(started.code, 0, started.stderr);
  assert.equal(
    started.stderr.match(/Deprecated settings: /g)?.length,
    1,
    `one notice: ${started.stderr}`
  );
  assert.match(started.stderr, /ORBIT_DATA_DIR → GOBLIN_DATA_DIR/);
  assert.ok(!started.stderr.includes(password));
  assert.ok(fs.existsSync(path.join(data, 'goblin.lock')), 'the ORBIT_DATA_DIR was used');

  const other = path.join(base, 'other');
  const refused = await runServer({
    GOBLIN_DATA_DIR: other,
    ORBIT_DATA_DIR: data,
    GOBLIN_PASSWORD: password,
  });
  assert.equal(refused.code, 78, refused.stderr);
  assert.match(refused.stderr, /GOBLIN_DATA_DIR and ORBIT_DATA_DIR are both set/);
  assert.match(refused.stderr, /Uptime Goblin refused to start \(exit status 78\)/);
  assert.ok(!refused.stderr.includes(other));
  assert.equal(fs.existsSync(other), false);
});

test('goblin-admin reads ORBIT_DATA_DIR as GOBLIN_DATA_DIR, with the notice, and refuses (78) a conflict', async t => {
  const base = temporary(t);
  const run = async env => {
    let out = '',
      err = '';
    const code = await main(['snapshots', '--json'], {
      env,
      stdout: text => (out += text),
      stderr: text => (err += text),
      uid: 1000,
    });
    return { code, out, err };
  };
  fs.mkdirSync(path.join(base, 'data'), { mode: 0o700 });
  const env = { ORBIT_DATA_DIR: path.join(base, 'data') };
  const listed = await run(env);
  assert.equal(listed.code, 0, listed.err);
  assert.match(listed.err, /goblin-admin snapshots: Deprecated settings: ORBIT_DATA_DIR/);
  assert.deepEqual(env, { GOBLIN_DATA_DIR: path.join(base, 'data') });

  const conflict = await run({
    ORBIT_DATA_DIR: path.join(base, 'data'),
    GOBLIN_DATA_DIR: path.join(base, 'elsewhere'),
  });
  assert.equal(conflict.code, 78);
  assert.match(conflict.err, /GOBLIN_DATA_DIR and ORBIT_DATA_DIR are both set/);
  assert.equal(conflict.out, '');
});

test('X-Goblin-Request or X-Orbit-Request passes the script-request check; a present new header decides alone', () => {
  const same = { host: 'goblin.example', origin: 'http://goblin.example' };
  for (const header of ['x-goblin-request', 'x-orbit-request']) {
    const headers = { ...same, [header]: '1' };
    assert.equal(crossOrigin({ headers }), false, header);
    assert.equal(strictCrossOrigin({ headers }), null, header);
  }
  assert.equal(crossOrigin({ headers: same }), true);
  assert.equal(strictCrossOrigin({ headers: same }), 'request-header');
  // An old header beside a refused new one cannot make it pass.
  const both = { ...same, 'x-goblin-request': '0', 'x-orbit-request': '1' };
  assert.equal(crossOrigin({ headers: both }), true);
  assert.equal(strictCrossOrigin({ headers: both }), 'request-header');
  assert.equal(requestHeader({ 'x-orbit-activity': 'background' }, 'Activity'), 'background');
  assert.equal(
    requestHeader(
      { 'x-goblin-activity': 'foreground', 'x-orbit-activity': 'background' },
      'Activity'
    ),
    'foreground'
  );
  // The web app's mark, under either name, makes a request a browser page's.
  assert.equal(browserContext({ 'x-goblin-client': 'web' }), true);
  assert.equal(browserContext({ 'x-orbit-client': 'web' }), true);
  assert.equal(browserContext({}), false);
});

test('answers name the build and version under both header names', async t => {
  const goblin = await startOrbit({ directory: temporary(t), password });
  t.after(() => goblin.close());
  const { cookie } = await signIn(goblin.url, password);
  const response = await fetch(new URL('/api/session', goblin.url), {
    headers: { ...browserHeaders(goblin.url), Cookie: cookie },
  });
  assert.equal(response.status, 200);
  assert.ok(response.headers.get('x-goblin-build'));
  assert.equal(response.headers.get('x-orbit-build'), response.headers.get('x-goblin-build'));
  assert.ok(response.headers.get('x-goblin-version'));
  assert.equal(response.headers.get('x-orbit-version'), response.headers.get('x-goblin-version'));
  // A refusal too: a 1.4.x tab reloads into the sign-in view when a 401 names another build.
  const refused = await fetch(new URL('/api/session', goblin.url));
  assert.equal(refused.status, 401);
  assert.equal(refused.headers.get('x-orbit-build'), refused.headers.get('x-goblin-build'));
  assert.equal(refused.headers.get('x-goblin-version'), null);
  assert.equal(refused.headers.get('x-orbit-version'), null);
});

test('an orbit_session cookie signs in while no goblin_session came, and is replaced by the same session under the new name', async t => {
  const goblin = await startOrbit({ directory: temporary(t), password });
  t.after(() => goblin.close());
  for (const remember of [false, true]) {
    const { cookie } = await signIn(goblin.url, password, { remember });
    const value = cookie.slice(cookie.indexOf('=') + 1);
    assert.ok(cookie.startsWith('goblin_session='), cookie);
    const response = await fetch(new URL('/api/session', goblin.url), {
      headers: { ...browserHeaders(goblin.url), Cookie: `orbit_session=${value}` },
    });
    assert.equal(response.status, 200, await response.text());
    const set = response.headers.getSetCookie();
    const renewed = set.find(line => line.startsWith('goblin_session='));
    assert.ok(renewed, JSON.stringify(set));
    assert.equal(renewed.split(';')[0], `goblin_session=${value}`);
    assert.match(renewed, /HttpOnly; SameSite=Strict/);
    if (remember) assert.match(renewed, /; Max-Age=\d+$/);
    else assert.doesNotMatch(renewed, /Max-Age/);
    assert.ok(
      set.includes('orbit_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0'),
      JSON.stringify(set)
    );
    // The new cookie alone is the same session; with it, the old one is not read at all.
    const renewedCall = await fetch(new URL('/api/session', goblin.url), {
      headers: { ...browserHeaders(goblin.url), Cookie: `goblin_session=${value}` },
    });
    assert.equal(renewedCall.status, 200);
    assert.deepEqual(renewedCall.headers.getSetCookie(), []);
    const both = await fetch(new URL('/api/session', goblin.url), {
      headers: {
        ...browserHeaders(goblin.url),
        Cookie: `goblin_session=${value}; orbit_session=not-a-session`,
      },
    });
    assert.equal(both.status, 200, 'an old cookie beside the new one is no second credential');
    const wrongNew = await fetch(new URL('/api/session', goblin.url), {
      headers: {
        ...browserHeaders(goblin.url),
        Cookie: `goblin_session=not-a-session; orbit_session=${value}`,
      },
    });
    assert.equal(wrongNew.status, 401, 'a present new cookie decides alone');
  }
  // Signing out with the old cookie ends the session and removes both cookies.
  const { cookie } = await signIn(goblin.url, password);
  const value = cookie.slice(cookie.indexOf('=') + 1);
  const out = await fetch(new URL('/api/auth/logout', goblin.url), {
    method: 'POST',
    headers: { ...browserHeaders(goblin.url), Cookie: `orbit_session=${value}` },
  });
  assert.equal(out.status, 204, await out.text());
  const set = out.headers.getSetCookie();
  assert.ok(
    set.some(line => /^goblin_session=;.*Max-Age=0/.test(line)),
    JSON.stringify(set)
  );
  assert.ok(
    set.some(line => /^orbit_session=;.*Max-Age=0/.test(line)),
    JSON.stringify(set)
  );
  const after = await fetch(new URL('/api/session', goblin.url), {
    headers: { ...browserHeaders(goblin.url), Cookie: `goblin_session=${value}` },
  });
  assert.equal(after.status, 401);
});

// The same over HTTPS (through a trusted proxy that sends X-Forwarded-Proto: https), where the
// cookies are __Host-orbit_session and __Host-goblin_session, Secure; and for a wall display's
// session (kiosk), which keeps its own lifetime (Max-Age) under the new name. The rotation is
// shared code (lib/http/pipeline.mjs), but the plan names both cases.
test('__Host-orbit_session over HTTPS and a wall display signed in by orbit_session are replaced by the same session under the new name', async t => {
  const {
    raw,
    serveAuth,
    browserWrite,
    password: harnessPassword,
  } = await import('./http-pipeline/harness.mjs');
  const viaProxy = () => [
    'Host: goblin.example',
    'X-Forwarded-For: 198.51.100.20',
    'X-Forwarded-Proto: https',
    ...browserWrite('https://goblin.example'),
  ];
  const secure = await serveAuth(t, {
    trustProxy: 'loopback',
    configuredHosts: ['goblin.example'],
  });
  const signedIn = await raw(
    secure.port,
    ['POST /api/auth/login HTTP/1.1', ...viaProxy()],
    JSON.stringify({
      login: 'admin',
      password: harnessPassword,
      remember: true,
    })
  );
  assert.equal(signedIn.status, 200, signedIn.body);
  const issued = [].concat(signedIn.headers['set-cookie'])[0];
  assert.match(issued, /^__Host-goblin_session=/);
  const value = issued.split(';')[0].slice('__Host-goblin_session='.length);
  const answer = await raw(secure.port, [
    'GET /api/session HTTP/1.1',
    ...viaProxy(),
    `Cookie: __Host-orbit_session=${value}`,
  ]);
  assert.equal(answer.status, 200, answer.body);
  const set = [].concat(answer.headers['set-cookie'] ?? []);
  const renewed = set.find(line => line.startsWith('__Host-goblin_session='));
  assert.ok(renewed, JSON.stringify(set));
  assert.equal(renewed.split(';')[0], `__Host-goblin_session=${value}`);
  assert.match(renewed, /; Path=\/; Secure; HttpOnly; SameSite=Strict; Max-Age=\d+$/);
  assert.ok(
    set.some(line =>
      /^__Host-orbit_session=; Path=\/; Secure; HttpOnly; SameSite=Strict; Max-Age=0$/.test(line)
    ),
    JSON.stringify(set)
  );
  assert.ok(!set.some(line => line.startsWith('goblin_session=')), 'not the plain-HTTP name');

  // A wall display: a display code redeemed into a kiosk session (as its page does), presented
  // under the old name.
  const { startIdentity, temporary: identityDirectory } = await import('./identity/helpers.mjs');
  const { identityOps } = await import('../lib/repo/identity.mjs');
  const { newDisplayCode } = await import('../lib/identity/secrets.mjs');
  const context = await startIdentity(t, identityDirectory(t), { password });
  const code = newDisplayCode();
  await context.db.write(tx =>
    identityOps.insertDisplay(tx, {
      id: code.id,
      name: 'Hall display',
      codeHash: code.codeHash,
      codeExpiresAt: context.clock() + 600000,
      createdAt: context.clock(),
      createdBy: 'cli:test',
    })
  );
  const display = await context.identity.redeemDisplayCode({
    code: code.code,
    client: '192.0.2.3',
    transport: 'loopback',
  });
  const kiosk = await serveAuth(t, { identity: context.identity });
  const shown = await raw(kiosk.port, [
    'GET /api/session HTTP/1.1',
    `Cookie: orbit_session=${display.issue.value}`,
    ...browserWrite(`http://127.0.0.1:${kiosk.port}`),
  ]);
  assert.equal(shown.status, 200, shown.body);
  assert.equal(shown.json.kind, 'kiosk');
  assert.equal(shown.json.session.persistent, true);
  const kioskSet = [].concat(shown.headers['set-cookie'] ?? []);
  const kioskCookie = kioskSet.find(line => line.startsWith('goblin_session='));
  assert.ok(kioskCookie, JSON.stringify(kioskSet));
  assert.equal(kioskCookie.split(';')[0], `goblin_session=${display.issue.value}`);
  assert.match(kioskCookie, /; Max-Age=\d+$/, "the display's own lifetime");
  assert.ok(
    kioskSet.includes('orbit_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0'),
    JSON.stringify(kioskSet)
  );
  // The new cookie alone is the same display session, and nothing is set again.
  const again = await raw(kiosk.port, [
    'GET /api/session HTTP/1.1',
    `Cookie: goblin_session=${display.issue.value}`,
    ...browserWrite(`http://127.0.0.1:${kiosk.port}`),
  ]);
  assert.equal(again.status, 200, again.body);
  assert.equal(again.headers['set-cookie'], undefined);
});

test('goblin.lock comes with orbit.lock: an Orbit that holds the old one keeps this release out, and isLocked sees either', t => {
  const directory = temporary(t);
  const lock = acquireLock(directory);
  assert.deepEqual(fs.readdirSync(directory).sort(), ['goblin.lock', 'orbit.lock']);
  assert.equal(isLocked(directory), true);
  lock.release();
  assert.equal(isLocked(directory), false);
  // An older release holds only orbit.lock (here: this process, as SQLite's lock).
  const old = holdExclusive(path.join(directory, 'orbit.lock'));
  try {
    assert.equal(isLocked(directory), true);
    assert.throws(
      () => acquireLock(directory),
      error => error instanceof LockHeldError && error.file.endsWith('orbit.lock')
    );
    // Nothing was kept: goblin.lock is free again.
    const probe = holdExclusive(path.join(directory, 'goblin.lock'));
    probe.release();
  } finally {
    old.release();
  }
  acquireLock(directory).release();
});

test('lib/cli/orbit-admin.mjs runs goblin-admin with the same arguments and exit status, after one deprecation line', () => {
  const run = file =>
    spawnSync(process.execPath, [path.join(repository, 'lib', 'cli', file), ...arguments_], {
      cwd: repository,
      env: { PATH: process.env.PATH },
      encoding: 'utf8',
    });
  let arguments_ = ['help'];
  const current = run('goblin-admin.mjs'),
    legacy = run('orbit-admin.mjs');
  assert.equal(current.status, 0, current.stderr);
  assert.equal(legacy.status, current.status);
  assert.equal(legacy.stdout, current.stdout);
  assert.equal(current.stderr, '');
  assert.equal(
    legacy.stderr,
    'orbit-admin is deprecated: Orbit is now Uptime Goblin, and this command is lib/cli/goblin-admin.mjs (goblin-admin). This name stops working in 1.7.\n'
  );
  arguments_ = ['no-such-command'];
  const unknown = run('goblin-admin.mjs'),
    unknownLegacy = run('orbit-admin.mjs');
  assert.equal(unknown.status, 2);
  assert.equal(unknownLegacy.status, 2);
  assert.ok(unknownLegacy.stderr.endsWith(unknown.stderr), unknownLegacy.stderr);
});

test('the container image uses a data volume mounted only at /app/data, with the notice, and refuses one beside data at the new path', () => {
  // A model of the container's two directories: what each holds (null: not there).
  const files = holds => ({
    readdirSync(directory) {
      if (!(directory in holds) || holds[directory] === null)
        throw Object.assign(new Error('missing'), { code: 'ENOENT' });
      return holds[directory];
    },
  });
  const image = { GOBLIN_DATA_DIR: '/var/lib/uptime-goblin' };
  const old = { '/app/data': ['control.sqlite', 'run'], '/var/lib/uptime-goblin': [] };
  // Only in the image (a container, the application at /app, the image's own data directory).
  for (const [what, env, options] of [
    ['outside a container', image, { appRoot: '/app', container: false }],
    ['another application directory', image, { appRoot: '/opt/uptime-goblin', container: true }],
    [
      'a data directory of its own',
      { GOBLIN_DATA_DIR: '/srv/data' },
      { appRoot: '/app', container: true },
    ],
  ]) {
    const given = { ...env };
    assert.equal(adoptLegacyDataMount(given, { ...options, files: files(old) }), null, what);
    assert.deepEqual(given, env, what);
  }
  const inImage = holds => ({ appRoot: '/app', container: true, files: files(holds) });
  // Nothing at /app/data, or nothing in it: the new path.
  for (const holds of [
    { '/var/lib/uptime-goblin': [] },
    { '/app/data': [], '/var/lib/uptime-goblin': [] },
  ]) {
    const env = { ...image };
    assert.equal(adoptLegacyDataMount(env, inImage(holds)), null);
    assert.equal(env.GOBLIN_DATA_DIR, '/var/lib/uptime-goblin');
  }
  // The old mount alone holds data: used, with the notice.
  const env = { ...image };
  const notice = adoptLegacyDataMount(env, inImage(old));
  assert.equal(env.GOBLIN_DATA_DIR, '/app/data');
  assert.match(
    notice,
    /^The data volume is mounted at \/app\/data, where the image kept its data before the rename to Uptime Goblin, and is used there\. Mount it at \/var\/lib\/uptime-goblin instead .* no longer read from 1\.7\.$/
  );
  // Both hold data: which one is meant cannot be told.
  const both = { ...image };
  assert.throws(
    () =>
      adoptLegacyDataMount(
        both,
        inImage({ '/app/data': ['control.sqlite'], '/var/lib/uptime-goblin': ['control.sqlite'] })
      ),
    error =>
      error.refusal === true &&
      /^Both \/var\/lib\/uptime-goblin and \/app\/data hold data/.test(error.message)
  );
  assert.equal(both.GOBLIN_DATA_DIR, '/var/lib/uptime-goblin', 'unchanged');
});
