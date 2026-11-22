// The admin password and sign-in sessions across upgrades and rollbacks (sessions spec §9.1):
// real 1.4.2 (test/fixtures) and 1.4.3 (the v1.4.3 tag, installTag) processes and the working
// tree on one data directory. "Script" is Basic without browser headers; "browser" is login()
// and the session cookie. The rows are the spec's: U (upgrade), R (rollback after an in-app
// change), M (a pending auth.json mirror across a rollback), F (a change made outside Orbit), P
// (a partial first start), K (kill -9 during the start, and K2 during sign-ins and password
// changes), G (no start without a password), L (orbit-admin after a code rollback to 1.4.3).
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { scryptSync, timingSafeEqual } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { setTimeout as delay } from 'node:timers/promises';
import { installRelease, installTag, skipWithoutFixtures, skipWithoutTag } from './fixtures.mjs';
import {
  endpoint,
  freePort,
  login,
  request,
  sessionRequest,
  start,
  temporary,
  waitFor,
  workingTree,
} from './harness.mjs';
import { interruptedRestore, listSnapshots } from '../../lib/db/snapshot.mjs';
import { createApp } from '../../server.mjs';
import { passwordRequiredMessage } from '../../lib/identity/index.mjs';
import { freePortSync } from '../helpers/net.mjs';
import { platformSubtest } from '../helpers/platform.mjs';

// Test values for these throwaway installations only.
const P = Object.fromEntries(
  [0, 1, 2, 3, 4, 5, 6, 7].map(n => [`P${n}`, `identity-matrix-password-${n}`])
);
const importLine = /Imported the admin password from (auth\.json|ORBIT_PASSWORD)/g;

const releases = {
  '1.4.2': {
    skip: t => skipWithoutFixtures(t),
    install: directory => installRelease('1.4.2', directory),
  },
  '1.4.3': {
    skip: t => skipWithoutTag(t, 'v1.4.3'),
    install: directory => installTag('v1.4.3', directory),
  },
};

// control.sqlite as identity left it, read without adding a -wal or -shm beside it.
function readControl(data) {
  const url = new URL(`file://${path.join(data, 'control.sqlite')}`);
  url.searchParams.set('immutable', '1');
  const db = new DatabaseSync(url, { readOnly: true });
  try {
    const settings = Object.fromEntries(
      db
        .prepare('SELECT key, value FROM identity_settings')
        .all()
        .map(row => [row.key, row.value])
    );
    const meta = Object.fromEntries(
      db
        .prepare('SELECT key, value FROM meta')
        .all()
        .map(row => [row.key, row.value])
    );
    const admin = db.prepare("SELECT * FROM users WHERE id = 'u_admin'").get();
    const sessions = db.prepare('SELECT COUNT(*) AS n FROM sessions').get().n;
    return { settings, meta, admin, sessions };
  } finally {
    db.close();
  }
}

// Every session row and the integrity check of control.sqlite, read after a clean stop.
function sessionRows(data) {
  const db = new DatabaseSync(path.join(data, 'control.sqlite'), { readOnly: true });
  try {
    return {
      rows: db.prepare('SELECT * FROM sessions').all(),
      integrity: db.prepare('PRAGMA integrity_check').get().integrity_check,
    };
  } finally {
    db.close();
  }
}

const bytesOf = file => (fs.existsSync(file) ? fs.readFileSync(file) : null);
const mode = file => fs.statSync(file).mode & 0o777;

// Whether a v1 auth record (1.4.x's auth.json) accepts `password`.
function recordAccepts(record, password) {
  const { N, r, p, keyLength } = record.parameters;
  const derived = scryptSync(
    Buffer.from(password, 'utf8'),
    Buffer.from(record.salt, 'hex'),
    keyLength,
    {
      N,
      r,
      p,
      maxmem: 64 * 1024 * 1024,
    }
  );
  return timingSafeEqual(derived, Buffer.from(record.hash, 'hex'));
}

// Script (Basic) and browser (session) sign-in with `secret`: [script status, browser status].
async function signIns(running, secret) {
  const script = (await request(running.port, 'GET', '/api/dashboard', { secret })).status;
  let browser;
  try {
    const cookie = await login(running.port, secret);
    browser = (await sessionRequest(running.port, 'GET', '/api/dashboard', { cookie })).status;
  } catch (error) {
    browser = error.response?.status ?? error.message;
  }
  return [script, browser];
}

// A 1.4.x password change through its own API (Basic).
async function legacyChange(running, from, to) {
  const response = await request(running.port, 'POST', '/api/auth/password', {
    secret: from,
    body: { currentPassword: from, password: to, confirmPassword: to },
  });
  assert.equal(response.status, 200, response.text);
  running.secret = to;
}

// An in-app change in the working tree, from a browser session: resolves the answer and the
// rotated session cookie.
async function browserChange(port, cookie, from, to) {
  const response = await sessionRequest(port, 'POST', '/api/account/password', {
    cookie,
    body: { currentPassword: from, password: to, confirmPassword: to },
  });
  assert.equal(response.status, 200, response.text);
  const rotated = (response.headers['set-cookie'] ?? [])
    .map(value => value.split(';')[0])
    // goblin_session from 1.5 on (the rename to Uptime Goblin), orbit_session before.
    .find(pair => /^(?:goblin|orbit)_session=v1\./.test(pair));
  assert.ok(rotated, 'the change rotates this session');
  return { body: response.json, cookie: rotated };
}

async function stopped(running) {
  const result = await running.stop();
  assert.equal(result.code, 0, running.output());
}

// Spawns the working tree and resolves its exit {code, output} (for starts that must refuse).
function exitOf(data, env) {
  return new Promise(resolve => {
    const child = spawn(process.execPath, [path.join(workingTree, 'server.mjs')], {
      cwd: workingTree,
      env: {
        PATH: process.env.PATH,
        HOST: '127.0.0.1',
        PORT: freePortSync(),
        ORBIT_DATA_DIR: data,
        ORBIT_LEGACY_BASIC: '1',
        ...env,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = '';
    for (const stream of [child.stdout, child.stderr])
      stream.on('data', chunk => (output += chunk));
    child.once('exit', code => resolve({ code, output }));
  });
}

// {relative path: bytes as hex} of a directory, skipping names and prefixes in `skip`.
function fingerprint(directory, skip) {
  const out = {};
  const walk = relative => {
    for (const entry of fs.readdirSync(path.join(directory, relative), { withFileTypes: true })) {
      const item = relative ? `${relative}/${entry.name}` : entry.name;
      if (skip.some(prefix => item === prefix || item.startsWith(`${prefix}/`))) continue;
      if (entry.isDirectory()) walk(item);
      else out[item] = fs.readFileSync(path.join(directory, item)).toString('hex');
    }
  };
  walk('');
  return out;
}

describe('identity across upgrades and rollbacks (§9.1)', { concurrency: 4 }, () => {
  // U1-U4: a 1.4.x install upgraded to the working tree signs in with the same password.
  for (const version of ['1.4.2', '1.4.3']) {
    it(`U${version === '1.4.2' ? 1 : 3}: ${version} with ORBIT_PASSWORD only, upgraded`, async t => {
      if (releases[version].skip(t)) return;
      const directory = temporary(t),
        data = path.join(directory, 'data'),
        app = releases[version].install(path.join(directory, 'app'));
      await stopped(await start(t, { app, data, env: { ORBIT_PASSWORD: P.P1 }, secret: P.P1 }));
      const config = bytesOf(path.join(data, 'config.json'));
      const current = await start(t, {
        app: workingTree,
        data,
        env: { ORBIT_PASSWORD: P.P1 },
        secret: P.P1,
      });
      assert.deepEqual(await signIns(current, P.P1), [200, 200]);
      await stopped(current);
      assert.equal(mode(path.join(data, 'control.sqlite')), 0o600);
      const control = readControl(data);
      assert.equal(control.settings['builtin.source'], 'env');
      assert.equal(control.meta.credentials_ever, '1');
      assert.equal(control.meta.created_by_release, undefined, 'an upgraded install');
      assert.deepEqual(bytesOf(path.join(data, 'config.json')), config, 'config.json untouched');
      assert.equal(fs.existsSync(path.join(data, 'auth.json')), false, 'env stays env (D13)');
      const pinned = listSnapshots(data).filter(item => item.pinned);
      assert.equal(pinned.length, 1);
      assert.ok(!pinned[0].files.includes('history.sqlite'), 'history left out (D24)');
    });

    it(`U${version === '1.4.2' ? 2 : 4}: ${version} changed the password in the app, upgraded`, async t => {
      if (releases[version].skip(t)) return;
      const directory = temporary(t),
        data = path.join(directory, 'data'),
        app = releases[version].install(path.join(directory, 'app'));
      const old = await start(t, { app, data, env: { ORBIT_PASSWORD: P.P1 }, secret: P.P1 });
      await legacyChange(old, P.P1, P.P2);
      await stopped(old);
      const auth = bytesOf(path.join(data, 'auth.json')),
        config = bytesOf(path.join(data, 'config.json'));
      assert.ok(auth);
      const current = await start(t, {
        app: workingTree,
        data,
        env: { ORBIT_PASSWORD: P.P1 },
        secret: P.P2,
      });
      assert.deepEqual(await signIns(current, P.P2), [200, 200]);
      assert.deepEqual(await signIns(current, P.P1), [401, 401]);
      await stopped(current);
      assert.equal(readControl(data).settings['builtin.source'], 'auth.json');
      assert.deepEqual(bytesOf(path.join(data, 'auth.json')), auth, 'auth.json byte-identical');
      assert.deepEqual(bytesOf(path.join(data, 'config.json')), config, 'config.json untouched');
    });
  }

  // R1-R3: an in-app change in the working tree, then a rollback that signs in with the new
  // password; forward again, the sessions from before the rollback still work and nothing is
  // imported (R3). If the password was changed under 1.4.x meanwhile, that change is imported
  // and every session ends (F1/F2 after an in-app change).
  for (const version of ['1.4.2', '1.4.3'])
    for (const changedUnderOld of [false, true])
      it(`${version === '1.4.2' ? 'R1' : 'R2'} then ${changedUnderOld ? (version === '1.4.2' ? 'F1' : 'F2') : 'R3'}: a browser change to P3, ${version}${changedUnderOld ? ' changes it to P4' : ''}, then the working tree again`, async t => {
        if (releases[version].skip(t)) return;
        const directory = temporary(t),
          data = path.join(directory, 'data'),
          app = releases[version].install(path.join(directory, 'app'));
        const current = await start(t, {
          app: workingTree,
          data,
          env: { ORBIT_PASSWORD: P.P1 },
          secret: P.P1,
        });
        const changed = await browserChange(
          current.port,
          await login(current.port, P.P1),
          P.P1,
          P.P3
        );
        assert.equal(changed.body.mirrorPending, false);
        await stopped(current);
        const control = bytesOf(path.join(data, 'control.sqlite'));
        assert.equal(fs.existsSync(path.join(data, 'control.sqlite-wal')), false);
        const epoch = readControl(data).admin.epoch;
        const config = bytesOf(path.join(data, 'config.json'));
        // The rollback keeps the owner's environment, which still names P1: 1.4.x prefers
        // auth.json, which the working tree mirrored.
        const old = await start(t, { app, data, env: { ORBIT_PASSWORD: P.P1 }, secret: P.P3 });
        assert.equal(
          (await request(old.port, 'GET', '/api/dashboard', { secret: P.P3 })).status,
          200
        );
        assert.equal(
          (await request(old.port, 'GET', '/api/dashboard', { secret: P.P1 })).status,
          401
        );
        if (changedUnderOld) await legacyChange(old, P.P3, P.P4);
        await stopped(old);
        assert.deepEqual(
          bytesOf(path.join(data, 'control.sqlite')),
          control,
          '1.4.x never touched it'
        );
        assert.deepEqual(bytesOf(path.join(data, 'config.json')), config);
        const auth = bytesOf(path.join(data, 'auth.json'));
        const secret = changedUnderOld ? P.P4 : P.P3;
        const again = await start(t, {
          app: workingTree,
          data,
          env: { ORBIT_PASSWORD: P.P1 },
          secret,
        });
        // The session signed in (and rotated by the change) before the rollback.
        const session = await sessionRequest(again.port, 'GET', '/api/session', {
          cookie: changed.cookie,
        });
        assert.deepEqual(await signIns(again, secret), [200, 200]);
        assert.deepEqual(await signIns(again, changedUnderOld ? P.P3 : P.P1), [401, 401]);
        await stopped(again);
        if (changedUnderOld) {
          assert.equal(session.status, 401, session.text);
          assert.equal(session.json.code, 'session_expired');
          assert.equal(again.output().match(importLine)?.length, 1, again.output());
          assert.equal(readControl(data).admin.epoch, epoch + 1);
        } else {
          assert.equal(session.status, 200, session.text);
          assert.equal(session.json.via, 'session');
          assert.doesNotMatch(again.output(), importLine);
          assert.equal(readControl(data).admin.epoch, epoch, 'no import');
        }
        // An import from auth.json takes the file as it is: no write back either way.
        assert.deepEqual(bytesOf(path.join(data, 'auth.json')), auth);
        assert.deepEqual(bytesOf(path.join(data, 'config.json')), config);
      });

  // M1-M2: the working tree cannot write auth.json when the password changes (mirror pending);
  // the rollback uses the previous password; rolling forward retries the mirror, unless the
  // password was changed under 1.4.3 meanwhile, which then wins.
  for (const changedUnder143 of [false, true])
    it(`M${changedUnder143 ? 2 : 1}: a pending auth.json mirror across a rollback to 1.4.3`, async t => {
      if (releases['1.4.3'].skip(t)) return;
      const directory = temporary(t),
        data = path.join(directory, 'data'),
        app = releases['1.4.3'].install(path.join(directory, 'app'));
      // 1.4.3 data whose auth.json holds P1.
      const setup = await start(t, { app, data, env: { ORBIT_PASSWORD: P.P0 }, secret: P.P0 });
      await legacyChange(setup, P.P0, P.P1);
      await stopped(setup);
      const authP1 = bytesOf(path.join(data, 'auth.json'));
      // The working tree in this process, with auth.json writes failing (its start line is not
      // this test's output).
      t.mock.method(console, 'log', () => {});
      const inProcess = await createApp({
        directory: data,
        host: '127.0.0.1',
        port: 0,
        password: P.P0,
        allowedHosts: '',
        webhook: '',
        trustProxy: '',
        startScheduler: false,
        identityOptions: {
          writeAuthRecord() {
            throw Object.assign(new Error('read-only file system'), { code: 'EROFS' });
          },
          log: { log() {}, info() {}, warn() {}, error() {} },
        },
      });
      let cookie;
      try {
        const { port } = await inProcess.listen();
        const changed = await browserChange(port, await login(port, P.P1), P.P1, P.P3);
        assert.equal(changed.body.mirrorPending, true);
        cookie = changed.cookie;
      } finally {
        await inProcess.close();
      }
      assert.deepEqual(bytesOf(path.join(data, 'auth.json')), authP1, 'the mirror failed');
      assert.equal(readControl(data).settings['builtin.mirrorPending'], '1');
      // 1.4.3 uses the previous password.
      const old = await start(t, { app, data, env: { ORBIT_PASSWORD: P.P0 }, secret: P.P1 });
      assert.equal(
        (await request(old.port, 'GET', '/api/dashboard', { secret: P.P1 })).status,
        200
      );
      assert.equal(
        (await request(old.port, 'GET', '/api/dashboard', { secret: P.P3 })).status,
        401
      );
      if (changedUnder143) await legacyChange(old, P.P1, P.P4);
      await stopped(old);
      const epoch = readControl(data).admin.epoch;
      const current = await start(t, {
        app: workingTree,
        data,
        env: { ORBIT_PASSWORD: P.P0 },
        secret: changedUnder143 ? P.P4 : P.P3,
      });
      const kept = await sessionRequest(current.port, 'GET', '/api/session', { cookie });
      if (!changedUnder143) {
        // M1: nothing imported (the file is the one mirrored last), the mirror retried.
        assert.deepEqual(await signIns(current, P.P3), [200, 200]);
        assert.deepEqual(await signIns(current, P.P1), [401, 401]);
        assert.equal(kept.status, 200, 'no import signs nobody out');
        await stopped(current);
        assert.doesNotMatch(current.output(), importLine);
        const control = readControl(data);
        assert.equal(control.admin.epoch, epoch);
        assert.equal(control.settings['builtin.mirrorPending'], undefined);
        const record = JSON.parse(fs.readFileSync(path.join(data, 'auth.json'), 'utf8'));
        assert.equal(recordAccepts(record, P.P3), true, 'auth.json holds P3 again');
        return;
      }
      // M2: the change under 1.4.3 is newer: imported, the pending mirror dropped.
      assert.deepEqual(await signIns(current, P.P4), [200, 200]);
      assert.deepEqual(await signIns(current, P.P3), [401, 401]);
      assert.equal(kept.status, 401);
      assert.equal(kept.json?.code, 'session_expired');
      await stopped(current);
      assert.equal(current.output().match(importLine)?.length, 1);
      const control = readControl(data);
      assert.equal(control.admin.epoch, epoch + 1);
      assert.equal(control.settings['builtin.mirrorPending'], undefined);
      const record = JSON.parse(fs.readFileSync(path.join(data, 'auth.json'), 'utf8'));
      assert.equal(recordAccepts(record, P.P4), true);
    });

  // F1-F2: a change made under 1.4.x is imported and ends every session.
  for (const version of ['1.4.2', '1.4.3'])
    it(`F${version === '1.4.2' ? 1 : 2}: a change under ${version} is imported`, async t => {
      if (releases[version].skip(t)) return;
      const directory = temporary(t),
        data = path.join(directory, 'data'),
        app = releases[version].install(path.join(directory, 'app'));
      const current = await start(t, {
        app: workingTree,
        data,
        env: { ORBIT_PASSWORD: P.P1 },
        secret: P.P1,
      });
      const cookie = await login(current.port, P.P1);
      await stopped(current);
      const epoch = readControl(data).admin.epoch;
      const old = await start(t, { app, data, env: { ORBIT_PASSWORD: P.P1 }, secret: P.P1 });
      await legacyChange(old, P.P1, P.P4);
      await stopped(old);
      const again = await start(t, {
        app: workingTree,
        data,
        env: { ORBIT_PASSWORD: P.P1 },
        secret: P.P4,
      });
      assert.deepEqual(await signIns(again, P.P4), [200, 200]);
      const refused = await sessionRequest(again.port, 'GET', '/api/session', { cookie });
      assert.equal(refused.status, 401);
      assert.equal(refused.json.code, 'session_expired');
      await stopped(again);
      assert.equal(readControl(data).admin.epoch, epoch + 1);
      assert.equal(again.output().match(importLine)?.length, 1, again.output());
    });

  // F3: the operator resets ORBIT_PASSWORD on an env-only install.
  it('F3: a new ORBIT_PASSWORD on an env-only install is imported', async t => {
    const directory = temporary(t),
      data = path.join(directory, 'data');
    const current = await start(t, {
      app: workingTree,
      data,
      env: { ORBIT_PASSWORD: P.P1 },
      secret: P.P1,
    });
    const cookie = await login(current.port, P.P1);
    await stopped(current);
    const again = await start(t, {
      app: workingTree,
      data,
      env: { ORBIT_PASSWORD: P.P5 },
      secret: P.P5,
    });
    assert.deepEqual(await signIns(again, P.P5), [200, 200]);
    assert.deepEqual(await signIns(again, P.P1), [401, 401]);
    assert.equal((await sessionRequest(again.port, 'GET', '/api/session', { cookie })).status, 401);
    await stopped(again);
  });

  // F4: 1.4.2's recovery procedure: move auth.json aside and set ORBIT_PASSWORD.
  it('F4: auth.json moved aside with a new ORBIT_PASSWORD imports the environment', async t => {
    const directory = temporary(t),
      data = path.join(directory, 'data');
    const current = await start(t, {
      app: workingTree,
      data,
      env: { ORBIT_PASSWORD: P.P1 },
      secret: P.P1,
    });
    const { cookie } = await browserChange(
      current.port,
      await login(current.port, P.P1),
      P.P1,
      P.P2
    );
    await stopped(current);
    assert.ok(fs.existsSync(path.join(data, 'auth.json')), 'the change was mirrored');
    fs.renameSync(path.join(data, 'auth.json'), path.join(directory, 'auth.json.aside'));
    const again = await start(t, {
      app: workingTree,
      data,
      env: { ORBIT_PASSWORD: P.P6 },
      secret: P.P6,
    });
    assert.deepEqual(await signIns(again, P.P6), [200, 200]);
    assert.deepEqual(await signIns(again, P.P2), [401, 401]);
    assert.equal((await sessionRequest(again.port, 'GET', '/api/session', { cookie })).status, 401);
    await stopped(again);
    const control = readControl(data);
    assert.equal(control.settings['builtin.source'], 'env');
    assert.equal(control.settings['builtin.authJsonSha256'], undefined);
    assert.equal(
      fs.existsSync(path.join(data, 'auth.json')),
      false,
      'env imports are not mirrored'
    );
  });

  // P1: a first start that partly ran (an installer rollback), then 1.4.3 changes the password.
  it('P1: a partial first start, a change under 1.4.3, then the working tree again', async t => {
    if (releases['1.4.3'].skip(t)) return;
    const directory = temporary(t),
      data = path.join(directory, 'data'),
      app = releases['1.4.3'].install(path.join(directory, 'app'));
    await stopped(await start(t, { app, data, env: { ORBIT_PASSWORD: P.P1 }, secret: P.P1 }));
    const config = bytesOf(path.join(data, 'config.json'));
    // Killed as soon as control.sqlite exists.
    const partial = spawn(process.execPath, [path.join(workingTree, 'server.mjs')], {
      cwd: workingTree,
      env: {
        PATH: process.env.PATH,
        HOST: '127.0.0.1',
        PORT: freePortSync(),
        ORBIT_DATA_DIR: data,
        ORBIT_PASSWORD: P.P1,
        ORBIT_LEGACY_BASIC: '1',
      },
      stdio: 'ignore',
    });
    const exited = new Promise(resolve => partial.once('exit', resolve));
    await waitFor(() => fs.existsSync(path.join(data, 'control.sqlite')), 'control.sqlite', 30000);
    partial.kill('SIGKILL');
    await exited;
    // A complete start with a signed-in browser, also killed.
    const full = await start(t, {
      app: workingTree,
      data,
      env: { ORBIT_PASSWORD: P.P1 },
      secret: P.P1,
    });
    const cookie = await login(full.port, P.P1);
    await full.kill();
    const old = await start(t, { app, data, env: { ORBIT_PASSWORD: P.P1 }, secret: P.P1 });
    await legacyChange(old, P.P1, P.P7);
    await stopped(old);
    const again = await start(t, {
      app: workingTree,
      data,
      env: { ORBIT_PASSWORD: P.P1 },
      secret: P.P7,
    });
    assert.deepEqual(await signIns(again, P.P7), [200, 200]);
    assert.equal((await sessionRequest(again.port, 'GET', '/api/session', { cookie })).status, 401);
    await stopped(again);
    assert.equal(listSnapshots(data).filter(item => item.pinned).length, 1, 'one pinned snapshot');
    assert.deepEqual(bytesOf(path.join(data, 'config.json')), config);
  });

  // K1: the roadmap's kill -9 loop during the first start (snapshot and migration).
  it('K1: killed ten times during its first start, the working tree then starts cleanly', async t => {
    if (releases['1.4.3'].skip(t)) return;
    const directory = temporary(t),
      data = path.join(directory, 'data'),
      app = releases['1.4.3'].install(path.join(directory, 'app'));
    const setup = await start(t, { app, data, env: { ORBIT_PASSWORD: P.P0 }, secret: P.P0 });
    await legacyChange(setup, P.P0, P.P1);
    await stopped(setup);
    const config = bytesOf(path.join(data, 'config.json')),
      auth = bytesOf(path.join(data, 'auth.json'));
    const spawnCurrent = directory =>
      spawn(process.execPath, [path.join(workingTree, 'server.mjs')], {
        cwd: workingTree,
        env: {
          PATH: process.env.PATH,
          HOST: '127.0.0.1',
          PORT: freePortSync(),
          ORBIT_DATA_DIR: directory,
          ORBIT_PASSWORD: P.P0,
          ORBIT_LEGACY_BASIC: '1',
        },
        stdio: ['ignore', 'pipe', 'ignore'],
      });
    // How long a first start takes here, measured on a copy of the same data, so the kill points
    // fall inside the start (snapshot, migration, password import) rather than after it.
    const copy = path.join(directory, 'calibration');
    fs.cpSync(data, copy, { recursive: true });
    const began = Date.now();
    const calibration = spawnCurrent(copy);
    await new Promise((resolve, reject) => {
      let output = '';
      calibration.stdout.on('data', chunk => {
        output += chunk;
        if (/(?:Orbit|Uptime Goblin) is ready/.test(output)) resolve();
      });
      calibration.once('exit', code => reject(new Error(`calibration start exited ${code}`)));
    });
    const startMs = Date.now() - began;
    calibration.kill('SIGKILL');
    // A fixed sequence of "random" points, so a failure can be replayed.
    let seed = 20260930;
    const next = () => (seed = (seed * 1103515245 + 12345) % 2 ** 31) / 2 ** 31;
    for (let i = 0; i < 10; i++) {
      const child = spawnCurrent(data);
      child.stdout.resume();
      const exited = new Promise(resolve => child.once('exit', resolve));
      await delay(Math.floor(next() * startMs));
      child.kill('SIGKILL');
      await exited;
    }
    const current = await start(t, {
      app: workingTree,
      data,
      env: { ORBIT_PASSWORD: P.P0 },
      secret: P.P1,
    });
    assert.deepEqual(await signIns(current, P.P1), [200, 200]);
    await stopped(current);
    assert.equal(listSnapshots(data).filter(item => item.pinned).length, 1);
    assert.deepEqual(
      fs.readdirSync(path.join(data, 'snapshots')).filter(name => name.startsWith('.staging-')),
      []
    );
    assert.deepEqual(bytesOf(path.join(data, 'config.json')), config);
    assert.deepEqual(bytesOf(path.join(data, 'auth.json')), auth);
  });

  // K2: kill -9 while browsers sign in, and while the password changes. A sign-in is one
  // transaction: after a restart every session whose cookie reached the browser works, and every
  // session row is complete. A password change is committed in control.sqlite before auth.json
  // is written: after a restart exactly one of the two passwords works, for scripts and browsers
  // alike, auth.json holds that one (the start retries a mirror the kill interrupted), and the
  // browser that asked for the change is still signed in only if the change did not land.
  it('K2: killed with SIGKILL during sign-ins and password changes, nothing is left half done', async t => {
    const directory = temporary(t),
      data = path.join(directory, 'data');
    // A fixed sequence of "random" kill points, so a failure can be replayed.
    let seed = 20261001;
    const next = () => (seed = (seed * 1103515245 + 12345) % 2 ** 31) / 2 ** 31;
    // A 1.5 install whose password lives in auth.json (changed in Orbit, mirrored). How long a
    // sign-in and a change take here sets the window the kill points fall in.
    const setup = await start(t, {
      app: workingTree,
      data,
      env: { ORBIT_PASSWORD: P.P0 },
      secret: P.P0,
    });
    let began = Date.now();
    const setupCookie = await login(setup.port, P.P0);
    const loginMs = Date.now() - began;
    began = Date.now();
    await browserChange(setup.port, setupCookie, P.P0, P.P1);
    const changeMs = Date.now() - began;
    await stopped(setup);
    const config = bytesOf(path.join(data, 'config.json')),
      auth = bytesOf(path.join(data, 'auth.json')),
      admin = readControl(data).admin;
    const before = sessionRows(data).rows.length;

    // Sign-ins: three at once, killed at a point within twice the time one takes. Five rounds
    // stay below the 20-session cap, so no delivered session is evicted by a later one.
    const delivered = [];
    let attempted = 0;
    for (let round = 0; round < 5; round++) {
      const running = await start(t, {
        app: workingTree,
        data,
        env: { ORBIT_PASSWORD: P.P0 },
        secret: P.P1,
      });
      const signIns = [0, 1, 2].map(() =>
        login(running.port, P.P1).then(
          cookie => delivered.push(cookie),
          () => {}
        )
      );
      attempted += signIns.length;
      await delay(Math.floor(next() * loginMs * 2));
      await running.kill();
      await Promise.all(signIns);
    }
    const afterSignIns = await start(t, {
      app: workingTree,
      data,
      env: { ORBIT_PASSWORD: P.P0 },
      secret: P.P1,
    });
    for (const cookie of delivered) {
      const session = await sessionRequest(afterSignIns.port, 'GET', '/api/session', { cookie });
      assert.equal(session.status, 200, `a delivered session works: ${session.text}`);
    }
    await stopped(afterSignIns);
    const { rows, integrity } = sessionRows(data);
    assert.equal(integrity, 'ok');
    assert.ok(
      rows.length >= before + delivered.length && rows.length <= before + attempted,
      `${rows.length} rows for ${delivered.length} delivered of ${attempted} attempted`
    );
    for (const row of rows) {
      assert.equal(row.user_id, 'u_admin');
      assert.deepEqual([row.kind, row.stage, row.via], ['interactive', 'full', 'password']);
      assert.match(row.id, /^s_[A-Za-z0-9_-]{16}$/);
      assert.match(row.token_hash, /^[0-9a-f]{64}$/);
      assert.ok(row.created_at <= row.last_seen_at && row.idle_expires_at <= row.expires_at);
    }
    t.diagnostic(`${delivered.length} of ${attempted} sign-ins answered before their kill`);
    // Sign-ins change no password: same row version, epoch and record; auth.json untouched.
    const unchanged = readControl(data);
    assert.equal(unchanged.admin.row_version, admin.row_version);
    assert.equal(unchanged.admin.epoch, admin.epoch);
    assert.equal(unchanged.admin.password, admin.password);
    assert.equal(unchanged.settings['builtin.mirrorPending'], undefined);
    assert.deepEqual(bytesOf(path.join(data, 'auth.json')), auth);

    // Password changes, each killed at a point within twice the time one takes.
    let current = P.P1,
      landedCount = 0;
    for (let round = 0; round < 6; round++) {
      const target = `identity-k2-password-${round}`;
      const running = await start(t, {
        app: workingTree,
        data,
        env: { ORBIT_PASSWORD: P.P0 },
        secret: current,
      });
      const cookie = await login(running.port, current);
      const change = sessionRequest(running.port, 'POST', '/api/account/password', {
        cookie,
        body: { currentPassword: current, password: target, confirmPassword: target },
      }).catch(() => null);
      await delay(Math.floor(next() * changeMs * 2));
      await running.kill();
      const answered = await change;
      // Started without knowing which password holds: ready once /health answers.
      const port = await freePort();
      const again = await start(t, {
        app: workingTree,
        data,
        env: { ORBIT_PASSWORD: P.P0 },
        secret: current,
        port,
        ready: async () => (await request(port, 'GET', '/health')).status === 200,
      });
      const oldWorks = (await request(port, 'GET', '/api/dashboard', { secret: current })).status;
      const newWorks = (await request(port, 'GET', '/api/dashboard', { secret: target })).status;
      assert.deepEqual(
        [oldWorks, newWorks].sort(),
        [200, 401],
        `round ${round}: exactly one password works`
      );
      const landed = newWorks === 200;
      if (answered?.status === 200) assert.ok(landed, 'a change the browser saw answered landed');
      const working = landed ? target : current;
      assert.deepEqual(await signIns(again, working), [200, 200]);
      // The changing browser's session was rotated (deleted) by a change that landed.
      const old = await sessionRequest(port, 'GET', '/api/session', { cookie });
      assert.equal(old.status, landed ? 401 : 200, old.text);
      await stopped(again);
      const record = JSON.parse(fs.readFileSync(path.join(data, 'auth.json'), 'utf8'));
      assert.equal(recordAccepts(record, working), true, `round ${round}: auth.json agrees`);
      assert.equal(readControl(data).settings['builtin.mirrorPending'], undefined);
      assert.equal(sessionRows(data).integrity, 'ok');
      current = working;
      landedCount += landed ? 1 : 0;
    }
    t.diagnostic(`${landedCount} of 6 password changes landed before their kill`);
    assert.deepEqual(bytesOf(path.join(data, 'config.json')), config);
  });

  // G1: no start without a password, also after credentials existed (D4).
  it('G1: no password source after credentials existed exits 78 and changes nothing', async t => {
    const directory = temporary(t),
      data = path.join(directory, 'data');
    await stopped(
      await start(t, { app: workingTree, data, env: { ORBIT_PASSWORD: P.P1 }, secret: P.P1 })
    );
    const skip = ['orbit.lock', 'run'];
    const before = fingerprint(data, skip);
    const refused = await exitOf(data, {});
    assert.equal(refused.code, 78, refused.output);
    // server.mjs refuses every start without a password source first, with how to set one or
    // restore auth.json.
    assert.ok(refused.output.includes(passwordRequiredMessage), refused.output);
    assert.match(refused.output, /(?:Orbit|Uptime Goblin) refused to start \(exit status 78\)/);
    assert.deepEqual(
      fingerprint(data, skip),
      before,
      'byte-identical apart from orbit.lock and run/'
    );
  });

  // L1: after the documented code rollback, restoring the pinned snapshot while 1.4.3 still
  // runs. 1.4.3 takes no orbit.lock; it would write its in-memory settings over the restored
  // config.json, and its password would come back at its next restart. orbit-admin refuses
  // (75) and changes nothing until 1.4.3 is stopped.
  it('L1: orbit-admin restore-snapshot refuses while 1.4.3 runs on the data directory', async t => {
    if (releases['1.4.3'].skip(t)) return;
    const directory = temporary(t),
      data = path.join(directory, 'data'),
      app = releases['1.4.3'].install(path.join(directory, 'app'));
    await stopped(await start(t, { app, data, env: { ORBIT_PASSWORD: P.P1 }, secret: P.P1 }));
    await stopped(
      await start(t, { app: workingTree, data, env: { ORBIT_PASSWORD: P.P1 }, secret: P.P1 })
    );
    const pinned = listSnapshots(data).find(item => item.pinned);
    const old = await start(t, { app, data, env: { ORBIT_PASSWORD: P.P1 }, secret: P.P1 });
    await legacyChange(old, P.P1, P.P2);
    const skip = ['orbit.lock', 'run'];
    const before = fingerprint(data, skip);
    const { main } = await import('../../lib/cli/orbit-admin.mjs');
    let err = '';
    // `container: false`: this is the native install's refusal. The Node 24 gate (§12 item 3)
    // runs this file in Docker, where inContainer() is true and orbit-admin would give the
    // Compose text instead (cli.test.mjs covers that one).
    const io = {
      env: {},
      uid: 1000,
      container: false,
      stdout: () => {},
      stderr: text => (err += text),
    };
    const args = ['restore-snapshot', pinned.id, '--data-dir', data];
    assert.equal(await main(args, io), 75, err);
    assert.match(
      err,
      /Orbit 1\.4\.3 is running on .* Stop Orbit first: sudo systemctl stop orbit\./
    );
    assert.deepEqual(fingerprint(data, skip), before, 'nothing restored under a live 1.4.3');
    assert.equal((await request(old.port, 'GET', '/api/dashboard', { secret: P.P2 })).status, 200);
    await stopped(old);
    assert.equal(await main(args, io), 0, err);
    assert.equal(fs.existsSync(path.join(data, 'control.sqlite')), false, 'the 1.4.x data back');
  });

  // L2: after the documented code rollback to 1.4.3, going back to the data of before the
  // upgrade (the pinned snapshot) needs orbit-admin, which is part of 1.5: 1.4.3 has none, so
  // the docs name the 1.5 copy the rollback kept (/opt/orbit.previous). Run as printed, it
  // restores the pinned snapshot, and 1.4.3 then signs in with that time's password (§16 C3).
  it('L2: after a code rollback the kept 1.5 copy’s orbit-admin restores the pinned snapshot; 1.4.3 has none', async t => {
    if (releases['1.4.3'].skip(t)) return;
    const directory = temporary(t),
      data = path.join(directory, 'data'),
      app = releases['1.4.3'].install(path.join(directory, 'app'));
    const first = await start(t, { app, data, env: { ORBIT_PASSWORD: P.P1 }, secret: P.P1 });
    await legacyChange(first, P.P1, P.P2);
    await stopped(first);
    const upgraded = await start(t, {
      app: workingTree,
      data,
      env: { ORBIT_PASSWORD: P.P1 },
      secret: P.P2,
    });
    await legacyChange(upgraded, P.P2, P.P3);
    await stopped(upgraded);
    const pinned = listSnapshots(data).find(item => item.pinned);
    // The code rollback: 1.4.3 is the installed code, and it has no orbit-admin.
    assert.equal(fs.existsSync(path.join(app, 'lib', 'cli', 'orbit-admin.mjs')), false);
    const kept = path.join(workingTree, 'lib', 'cli', 'orbit-admin.mjs');
    const restored = spawnSync(
      process.execPath,
      [kept, 'restore-snapshot', pinned.id, '--data-dir', data],
      { env: { PATH: process.env.PATH }, encoding: 'utf8' }
    );
    assert.equal(restored.status, 0, restored.stderr);
    assert.match(
      restored.stdout,
      new RegExp(`^Restored config\\.json, auth\\.json from ${pinned.id}\\.`)
    );
    const old = await start(t, { app, data, env: { ORBIT_PASSWORD: P.P1 }, secret: P.P2 });
    assert.equal((await request(old.port, 'GET', '/api/dashboard', { secret: P.P2 })).status, 200);
    assert.equal((await request(old.port, 'GET', '/api/dashboard', { secret: P.P3 })).status, 401);
    await stopped(old);
    // What the docs print for it.
    const read = name => fs.readFileSync(path.join(workingTree, name), 'utf8');
    assert.match(
      read('docs/installation.md'),
      /sudo -u orbit env GOBLIN_SECRET_KEY_FILE=\/etc\/orbit\/secret\.key node \/opt\/uptime-goblin\.failed\/lib\/cli\/goblin-admin\.mjs restore-snapshot SNAPSHOT_ID --data-dir \/var\/lib\/orbit/
    );
    assert.match(
      read('docs/installation.md'),
      /docker run --memory 1g --cpus 1 --pids-limit 256 --memory-swap 1g --pull=never --rm --user 1000:1000 --read-only --tmpfs \/tmp:size=16m,mode=1777 --cap-drop ALL --security-opt no-new-privileges:true --ulimit nofile=4096:4096 --ulimit core=0 --network none -v PROJECT_orbit-data:\/var\/lib\/uptime-goblin --mount type=bind,source="\$PWD\/orbit_secret_key",target=\/run\/secrets\/orbit_secret_key,readonly uptime-goblin:1\.5\.0 node lib\/cli\/goblin-admin\.mjs restore-snapshot SNAPSHOT_ID/
    );
    assert.match(read('docs/installation.md'), /### Rolling back 1\.5 to 1\.4\.3/);
    assert.match(
      read('docs/authentication.md'),
      /Restore it while the 1\.5 code is still installed, then roll the code back/
    );
  });

  // The orbit-admin of the 1.5 copy a code rollback kept (the working tree here), run as a
  // separate process like the owner runs it; `node` takes `--import` hooks that stand in for a
  // power loss at a chosen point (process.kill(SIGKILL), so nothing is cleaned up). It refuses
  // to change the data directory as root, as it should, so these rows run as a normal user: in
  // the Node 24 container that is `docker run --user node -e HOME=/tmp` (§12 item 3).
  const keptAdmin = (args, node = []) =>
    spawnSync(
      process.execPath,
      [...node, path.join(workingTree, 'lib/cli/orbit-admin.mjs'), ...args],
      {
        env: { PATH: process.env.PATH },
        encoding: 'utf8',
      }
    );
  // The same orbit-admin in this process as on the native install, for what depends on that
  // (`container: false`: the Node 24 gate runs this file in Docker, where inContainer() is true
  // and the kept copy would print the native install's form; cli.test.mjs covers that one).
  const nativeAdmin = async args => {
    const { main } = await import('../../lib/cli/orbit-admin.mjs');
    let out = '',
      err = '';
    const code = await main(args, {
      env: {},
      uid: 1000,
      container: false,
      stdout: text => (out += text),
      stderr: text => (err += text),
    });
    return { code, out, err };
  };
  const crashHook = (directory, name, body) => {
    const file = path.join(directory, name);
    fs.writeFileSync(file, `import fs from 'node:fs';\n${body}`);
    return ['--import', file];
  };
  // 1.4.3 (P1 → P2), the working tree (P2 → P3), then the code rollback: 1.4.3 is installed again.
  // The data directory is where the Orbit layout keeps it (var/lib/orbit, below the test's own
  // directory), as after the installer's rollback or deploy/install.sh --restore-orbit-layout,
  // the only layout 1.4.x runs on: the kept goblin-admin names the Orbit unit, account and key file
  // for it (admin-command.mjs, nativeLayout).
  async function rolledBack(t) {
    const directory = temporary(t),
      data = path.join(directory, 'var', 'lib', 'orbit'),
      app = releases['1.4.3'].install(path.join(directory, 'app'));
    const first = await start(t, { app, data, env: { ORBIT_PASSWORD: P.P1 }, secret: P.P1 });
    await legacyChange(first, P.P1, P.P2);
    await stopped(first);
    const upgraded = await start(t, {
      app: workingTree,
      data,
      env: { ORBIT_PASSWORD: P.P1 },
      secret: P.P2,
    });
    await legacyChange(upgraded, P.P2, P.P3);
    await stopped(upgraded);
    return { directory, data, app, pinned: listSnapshots(data).find(item => item.pinned) };
  }
  const authOf = file => JSON.parse(fs.readFileSync(file, 'utf8'));

  // L3: 1.4.3 knows nothing of the restore journal. After a code rollback the kept orbit-admin
  // restores a manual snapshot (with history) and is killed in step 3; systemd starts 1.4.3 on
  // the result, which takes a new password, a setting and readings. The same restore run again,
  // as the refusal and status say, deleted all of it: it took every live file for its own copy
  // (r4 upgrade-rollback finding). Now it keeps them in a snapshot of their own and names it.
  it('L3: a restore run again after 1.4.3 wrote to the half-restored directory keeps what 1.4.3 wrote', async t => {
    if (releases['1.4.3'].skip(t)) return;
    const { directory, data, app } = await rolledBack(t);
    const taken = keptAdmin(['snapshot', '--data-dir', data, '--json']);
    assert.equal(taken.status, 0, taken.stderr);
    const manual = JSON.parse(taken.stdout).id;
    const killed = keptAdmin(
      ['restore-snapshot', manual, '--data-dir', data],
      crashHook(
        directory,
        'crash-step3.mjs',
        `const stream = fs.createReadStream;
fs.createReadStream = function (file, ...rest) {
  if (/\\.restoring-pre-restore[^/]*\\/history\\.sqlite$/.test(String(file))) process.kill(process.pid, 'SIGKILL');
  return stream.call(this, file, ...rest);
};
`
      )
    );
    assert.equal(killed.signal, 'SIGKILL', killed.stderr);
    assert.equal(interruptedRestore(data)?.snapshot, manual);
    // The kept copy's status and migrate --apply name the restore that finishes it as this copy
    // runs it: /opt/orbit holds 1.4.3 now, which has no orbit-admin, so its command line failed
    // with "Cannot find module" (r7 upgrade-rollback finding). They keep the service disabled
    // until then, as the docs' rollback commands do. The line names the key file, since
    // restore-snapshot checks a keyring it brings back with the key (review F2v2).
    const finish = `with Orbit stopped and its service disabled (sudo systemctl disable --now orbit.service): sudo -u orbit env GOBLIN_SECRET_KEY_FILE=/etc/orbit/secret.key node ${path.join(workingTree, 'lib', 'cli', 'goblin-admin.mjs')} restore-snapshot ${manual} --data-dir ${data} (the native install;`;
    const told = await nativeAdmin([
      'status',
      '--data-dir',
      data,
      '--unit',
      path.join(directory, 'no.service'),
    ]);
    assert.equal(told.code, 0, told.err);
    const refused = await nativeAdmin(['migrate', '--apply', '--data-dir', data]);
    assert.equal(refused.code, 78, refused.err);
    for (const text of [told.out, refused.err]) {
      assert.ok(text.includes(finish), text);
      assert.ok(
        text.includes('Then enable and start Orbit (sudo systemctl enable --now orbit.service).'),
        text
      );
      assert.doesNotMatch(text, /\/opt\/orbit\/lib\/cli/);
    }
    // Run as printed (but for sudo: this test is the orbit user) once 1.4.3 has run, below, with
    // the key this Orbit ran with (the data directory's), never a real /etc/orbit/secret.key.
    const printed =
      /sudo -u orbit (env GOBLIN_SECRET_KEY_FILE=\/etc\/orbit\/secret\.key node \S+ restore-snapshot \S+ --data-dir \S+) \(the native install;/
        .exec(refused.err)?.[1]
        ?.replace('=/etc/orbit/secret.key ', `=${path.join(data, 'secret.key')} `);
    assert.ok(printed, refused.err);

    const site = await endpoint(t);
    const old = await start(t, { app, data, env: { ORBIT_PASSWORD: P.P1 }, secret: P.P3 });
    await legacyChange(old, P.P3, P.P4);
    const titled = await old.request('PATCH', '/api/settings', {
      body: { title: 'Changed under 1.4.3' },
    });
    assert.equal(titled.status, 200, titled.text);
    const added = await old.request('POST', '/api/services', {
      body: { type: 'http', name: 'Added under 1.4.3', group: 'L3', apiUrl: site },
    });
    assert.equal(added.status, 201, added.text);
    const service = added.json.service.id;
    await waitFor(
      async () => (await old.dashboard()).services.find(s => s.id === service)?.lastSuccess,
      '1.4.3 to record a reading'
    );
    await stopped(old);

    const again = spawnSync('bash', ['-c', printed], {
      env: { PATH: process.env.PATH },
      encoding: 'utf8',
    });
    assert.equal(again.status, 0, again.stderr);
    const kept =
      /had changed since this restore was interrupted .*?: snapshot (pre-restore-\S+) holds them\. Restore that snapshot to put them back\.$/m.exec(
        again.stdout
      )?.[1];
    assert.ok(kept, again.stdout);
    const folder = path.join(data, 'snapshots', kept);
    const manifest = JSON.parse(fs.readFileSync(path.join(folder, 'manifest.json'), 'utf8'));
    assert.deepEqual(
      manifest.files.map(file => file.name),
      ['config.json', 'auth.json', 'history.sqlite'],
      'control.sqlite, which 1.4.3 never opens, was the first attempt’s copy'
    );
    assert.ok(recordAccepts(authOf(path.join(folder, 'auth.json')), P.P4));
    const config = fs.readFileSync(path.join(folder, 'config.json'), 'utf8');
    assert.ok(config.includes('Changed under 1.4.3') && config.includes(service));
    const history = new DatabaseSync(path.join(folder, 'history.sqlite'), { readOnly: true });
    try {
      const { n } = history
        .prepare('SELECT COUNT(*) AS n FROM readings WHERE service = ?')
        .get(service);
      assert.ok(n > 0, 'the readings 1.4.3 recorded');
    } finally {
      history.close();
    }
    // The snapshot is in place, and the kept one puts 1.4.3's state back.
    assert.ok(recordAccepts(authOf(path.join(data, 'auth.json')), P.P3));
    const back = keptAdmin(['restore-snapshot', kept, '--data-dir', data]);
    assert.equal(back.status, 0, back.stderr);
    const after = await start(t, { app, data, env: { ORBIT_PASSWORD: P.P1 }, secret: P.P4 });
    const dashboard = await after.dashboard();
    assert.equal(dashboard.config.title, 'Changed under 1.4.3');
    assert.ok(dashboard.services.some(s => s.id === service));
    assert.equal(
      (await request(after.port, 'GET', '/api/dashboard', { secret: P.P3 })).status,
      401
    );
    await stopped(after);
    const read = name => fs.readFileSync(path.join(workingTree, name), 'utf8');
    assert.match(
      read('docs/installation.md'),
      /sudo systemctl disable --now orbit\.service\nsudo -u orbit env GOBLIN_SECRET_KEY_FILE=\/etc\/orbit\/secret\.key node \/opt\/uptime-goblin\.failed\/lib\/cli\/goblin-admin\.mjs restore-snapshot SNAPSHOT_ID --data-dir \/var\/lib\/orbit\nsudo systemctl enable --now orbit\.service\n/
    );
    assert.match(
      read('docs/installation.md'),
      /1\.4\.x knows nothing of the record that makes 1\.5 refuse/
    );
  });

  // L4: the second effect. auth.json was moved aside before the snapshot's copy took its place;
  // killed in between, the restore left none, and 1.4.3, which ignores the journal, started on
  // loopback without ORBIT_PASSWORD (auth.json had held the password) as the passwordless
  // preview. auth.json is now copied aside and the copy renamed over it.
  it('L4: a restore killed as it sets auth.json aside leaves 1.4.3 the current password', async t => {
    if (releases['1.4.3'].skip(t)) return;
    const { directory, data, app, pinned } = await rolledBack(t);
    const killed = keptAdmin(
      ['restore-snapshot', pinned.id, '--data-dir', data],
      crashHook(
        directory,
        'crash-auth-aside.mjs',
        `const aside = to => /\\.restoring-[^/]+\\/auth\\.json$/.test(String(to));
for (const name of ['renameSync', 'copyFileSync']) {
  const original = fs[name];
  fs[name] = function (from, to, ...rest) {
    const result = original.call(this, from, to, ...rest);
    if (aside(to)) process.kill(process.pid, 'SIGKILL');
    return result;
  };
}
`
      )
    );
    assert.equal(killed.signal, 'SIGKILL', killed.stderr);
    const port = await freePort();
    const anonymous = () =>
      request(port, 'GET', '/api/dashboard', { headers: { Authorization: undefined } });
    const old = await start(t, {
      app,
      data,
      env: { ORBIT_PASSWORD: undefined },
      port,
      ready: async () => [200, 401].includes((await anonymous()).status),
    });
    assert.equal((await anonymous()).status, 401, 'no passwordless preview');
    assert.equal((await request(port, 'GET', '/api/dashboard', { secret: P.P3 })).status, 200);
    await stopped(old);
    assert.ok(fs.existsSync(path.join(data, 'auth.json')));
    // The kept orbit-admin finishes the restore: the pinned snapshot's password.
    const again = keptAdmin(['restore-snapshot', pinned.id, '--data-dir', data]);
    assert.equal(again.status, 0, again.stderr);
    const back = await start(t, { app, data, env: { ORBIT_PASSWORD: undefined }, secret: P.P2 });
    assert.equal((await request(back.port, 'GET', '/api/dashboard', { secret: P.P3 })).status, 401);
    await stopped(back);
  });

  // L5: 1.4.3 never removes the hidden copies a restore killed while it copied leaves in the
  // data directory (only a start of 1.5 or later, or a restore, does), yet status and snapshots
  // said "the next start of Orbit" removes them. The kept orbit-admin's next restore does.
  it('L5: under 1.4.3 a restore’s leftover copies stay; status says so, and the next restore removes them', async t => {
    if (releases['1.4.3'].skip(t)) return;
    const { directory, data, app } = await rolledBack(t);
    const taken = keptAdmin(['snapshot', '--data-dir', data, '--json']);
    assert.equal(taken.status, 0, taken.stderr);
    const manual = JSON.parse(taken.stdout).id;
    const killed = keptAdmin(
      ['restore-snapshot', manual, '--data-dir', data],
      crashHook(
        directory,
        'crash-history-copy.mjs',
        `const copy = fs.copyFileSync;
fs.copyFileSync = function (from, to, mode) {
  copy.call(this, from, to, mode);
  if (String(to).endsWith('.history.sqlite.restoring')) process.kill(process.pid, 'SIGKILL');
};
`
      )
    );
    assert.equal(killed.signal, 'SIGKILL', killed.stderr);
    assert.equal(interruptedRestore(data), null, 'killed before its journal');
    const hidden = () =>
      fs
        .readdirSync(data)
        .filter(name => name.includes('.restoring'))
        .sort();
    const left = hidden();
    assert.ok(left.includes('.history.sqlite.restoring'), left.join(', '));
    const status = keptAdmin([
      'status',
      '--data-dir',
      data,
      '--unit',
      path.join(directory, 'no.service'),
    ]);
    assert.match(
      status.stdout,
      /Restore leftover: \.history\.sqlite\.restoring in the data directory \(.+\)\. .*The next start of Uptime Goblin 1\.5 or later, or the next restore-snapshot, removes it; Orbit 1\.4\.x leaves it \(delete it by hand while Uptime Goblin is stopped\)\./
    );
    for (let n = 0; n < 2; n += 1)
      await stopped(await start(t, { app, data, env: { ORBIT_PASSWORD: P.P1 }, secret: P.P3 }));
    assert.deepEqual(hidden(), left, '1.4.3 leaves them');
    const again = keptAdmin(['restore-snapshot', manual, '--data-dir', data]);
    assert.equal(again.status, 0, again.stderr);
    assert.match(
      again.stdout,
      /^Removed \.config\.json\.restoring, .*: temporary copies that an earlier restore, stopped by a crash, left in the data directory\.$/m
    );
    assert.deepEqual(hidden(), []);
    assert.match(
      fs.readFileSync(path.join(workingTree, 'docs/installation.md'), 'utf8'),
      /1\.4\.x also leaves the hidden copies of an interrupted restore .* running the kept `goblin-admin restore-snapshot` again removes them, or delete them by hand while Orbit is stopped\./
    );
  });

  // L6: after a rollback to 1.4.2 (supported, R1/F1), which keeps no run/status.json and takes
  // no orbit.lock, the kept orbit-admin said "Orbit: not running (no run/status.json)" while it
  // served, and took a snapshot under it (r7 upgrade-rollback finding). Natively on Linux it
  // finds 1.4.2 by its process: status says it runs and offline commands refuse (75). Without
  // /proc (macOS) status says it may be running, and offline commands run, as the docs say. Each
  // platform's part is a subtest registered on that platform only (test/platform-manifest.json).
  it('L6: the kept orbit-admin sees a rolled-back 1.4.2, which keeps no run/status.json', async t => {
    if (releases['1.4.2'].skip(t)) return;
    const directory = temporary(t),
      data = path.join(directory, 'data'),
      app = releases['1.4.2'].install(path.join(directory, 'app'));
    await stopped(
      await start(t, { app: workingTree, data, env: { ORBIT_PASSWORD: P.P1 }, secret: P.P1 })
    );
    const old = await start(t, { app, data, env: { ORBIT_PASSWORD: P.P1 }, secret: P.P1 });
    assert.equal((await request(old.port, 'GET', '/api/dashboard', { secret: P.P1 })).status, 200);
    assert.equal(fs.existsSync(path.join(data, 'run', 'status.json')), false, '1.4.2 keeps none');
    const unit = path.join(directory, 'no.service');
    const orbitLine = async () => {
      const result = await nativeAdmin(['status', '--data-dir', data, '--unit', unit]);
      assert.equal(result.code, 0, result.err);
      // The process line is labelled with the release it is about: Orbit for the 1.4.2 found by
      // its process (Linux), Uptime Goblin where no version is known (status.mjs).
      return result.out.split('\n').find(line => /^(Uptime Goblin|Orbit): /.test(line));
    };
    const running = await orbitLine();
    await platformSubtest(
      t,
      import.meta.url,
      'upgrade-identity.l6.linux-running',
      'on Linux: status finds 1.4.2 by its process, and offline commands refuse (75) while it runs',
      {},
      async () => {
        assert.equal(
          running,
          `Orbit: running, version 1.4.2, pid ${old.pid}, found by its process (it keeps no run/status.json, as Orbit 1.4.2 and earlier do not)`
        );
        const before = listSnapshots(data).length;
        const refused = await nativeAdmin(['snapshot', '--data-dir', data]);
        assert.equal(refused.code, 75, refused.err);
        assert.equal(
          refused.err,
          `goblin-admin snapshot: Orbit 1.4.2 is running on ${data} (process ${old.pid}, found by its process: it keeps no run/status.json, as Orbit 1.4.2 and earlier do not). Stop Orbit first: sudo systemctl stop orbit.\n`
        );
        assert.equal(listSnapshots(data).length, before, 'nothing taken under 1.4.2');
      }
    );
    await platformSubtest(
      t,
      import.meta.url,
      'upgrade-identity.l6.darwin',
      'on macOS: status says 1.4.2 may be running (there is no /proc to look for it)',
      {},
      () =>
        assert.equal(
          running,
          'Uptime Goblin: may be running (Orbit 1.4.2 and earlier keep no run/status.json and take no orbit.lock, and there is no /proc here to look for one by its process)'
        )
    );
    await stopped(old);
    await platformSubtest(
      t,
      import.meta.url,
      'upgrade-identity.l6.linux-stopped',
      'on Linux: once 1.4.2 has stopped, status says Orbit is not running',
      {},
      async () => assert.equal(await orbitLine(), 'Uptime Goblin: not running (no run/status.json)')
    );
    const taken = await nativeAdmin(['snapshot', '--data-dir', data]);
    assert.equal(taken.code, 0, taken.err);
  });

  // G2: a passwordless 1.4.2 (its loopback preview) does not start as 1.5 until it has a
  // password: Orbit always requires one. The first start with ORBIT_PASSWORD makes it the admin's.
  it('G2: 1.4.2 without a password is refused by 1.5 until ORBIT_PASSWORD is set', async t => {
    if (releases['1.4.2'].skip(t)) return;
    const directory = temporary(t),
      data = path.join(directory, 'data'),
      app = releases['1.4.2'].install(path.join(directory, 'app'));
    await stopped(await start(t, { app, data, env: { ORBIT_PASSWORD: undefined } }));
    await assert.rejects(
      start(t, { app: workingTree, data, env: { ORBIT_PASSWORD: undefined } }),
      error =>
        /exited \(78\)/.test(error.message) && error.message.includes(passwordRequiredMessage)
    );
    assert.equal(fs.existsSync(path.join(data, 'control.sqlite')), false, 'nothing written');
    const current = await start(t, { app: workingTree, data });
    const anonymous = await sessionRequest(current.port, 'GET', '/api/session');
    assert.equal(anonymous.status, 401, anonymous.text);
    assert.equal((await current.request('GET', '/api/dashboard')).status, 200);
    await stopped(current);
    assert.equal(readControl(data).meta.credentials_ever, '1');
    assert.match(current.output(), /Sign-in: built-in admin \(password from GOBLIN_PASSWORD\)/);
  });
});
