// Uptime Goblin's start and stop (sessions spec §3): the order of the start sequence, the lock, the
// read-only config.json check, refusals that change nothing (T11), the capability flags read
// from the environment, the start line, a stop requested during the start, the main block's exit
// statuses, and the restore marker that signs every session out (D25).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { createApp, startupExitCode, startLine, keyLines } from '../server.mjs';
import { main as orbitAdmin, appRoot } from '../lib/cli/goblin-admin.mjs';
import { asAdminCopy } from '../lib/admin-command.mjs';
import { checkConfigFile, parseConfig, ConfigStore } from '../lib/config.mjs';
import { acquireLock, LockHeldError } from '../lib/db/lock.mjs';
import { openControl, interruptedRestoreMessage } from '../lib/db/control.mjs';
import { passwordRequiredMessage } from '../lib/identity/index.mjs';
import { openSqlite } from '../lib/db/sqlite.mjs';
import { requireRelease } from '../lib/db/migrate.mjs';
import {
  createSnapshot,
  interruptedRestore,
  listSnapshots,
  restoreSnapshot,
} from '../lib/db/snapshot.mjs';
import { Keyring, keyFingerprint } from '../lib/keyring.mjs';
import { sql, id } from '../lib/db/sql.mjs';
import { signIn, sessionCall } from './helpers/session.mjs';
import { freePortSync } from './helpers/net.mjs';
import { supervisedEnv } from './helpers/supervised.mjs';
import { quoted } from '../lib/environment.mjs';

const serverFile = fileURLToPath(new URL('../server.mjs', import.meta.url));
const release = JSON.parse(
  fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')
).version;
// Test values for these throwaway data directories only.
const password = 'startup-test-password';
// A refusal identity raises after startControl (here from its KDF, through the tests' derive
// seam): no data refuses there now that every start without a password is refused before it.
const identityRefusal = 'identity refused this start (test)';
const refusingDerive = () => {
  throw Object.assign(new Error(identityRefusal), { refusal: true });
};
const hexKey = 'a1'.repeat(16) + 'b2'.repeat(16);
const otherKey = 'c3'.repeat(16) + 'd4'.repeat(16);

function temporary(t, prefix = 'orbit-startup-') {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

// {relative path: sha256-free hex bytes} of every file under `directory`, skipping `skip`.
function fingerprint(directory, skip = []) {
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

// createApp on loopback with the scheduler off; `options` override.
const start = (directory, options = {}) =>
  createApp({
    directory,
    host: '127.0.0.1',
    port: 0,
    password,
    allowedHosts: '',
    webhook: '',
    trustProxy: '',
    startScheduler: false,
    ...options,
  });

// A running Uptime Goblin and its base URL; closed when the test ends.
async function serve(t, directory, options) {
  const app = await start(directory, options);
  t.after(() => app.close());
  const { port } = await app.listen();
  return { app, port, url: `http://127.0.0.1:${port}` };
}

// A 1.4.x data directory: config.json (and history.sqlite, as 1.4.x leaves it).
function legacyData(t, { auth } = {}) {
  const directory = temporary(t);
  fs.writeFileSync(path.join(directory, 'config.json'), '{"services":[]}\n', { mode: 0o600 });
  const history = new DatabaseSync(path.join(directory, 'history.sqlite'));
  history.exec('CREATE TABLE readings (service TEXT, time INTEGER)');
  history.close();
  if (auth) fs.writeFileSync(path.join(directory, 'auth.json'), auth, { mode: 0o600 });
  return directory;
}

const lockIsFree = directory => {
  const lock = acquireLock(directory);
  lock.release();
  return true;
};

// Reads control.sqlite's meta without leaving -wal or -shm files behind.
function meta(directory) {
  const url = new URL(`file://${path.join(directory, 'control.sqlite')}`);
  url.searchParams.set('immutable', '1');
  const db = new DatabaseSync(url, { readOnly: true });
  try {
    return Object.fromEntries(
      db
        .prepare('SELECT key, value FROM meta')
        .all()
        .map(row => [row.key, row.value])
    );
  } finally {
    db.close();
  }
}

// Spawns `node server.mjs` with a clean environment: {child, exited}, where `exited` resolves
// {code, signal, stdout, stderr}. `onOutput(stdout)` sees the standard output as it arrives;
// `args` follow server.mjs on its command line.
function spawnServer(env, { onOutput, args = [] } = {}) {
  const child = spawn(process.execPath, [serverFile, ...args], {
    cwd: path.dirname(serverFile),
    env: { PATH: process.env.PATH, HOST: '127.0.0.1', PORT: freePortSync(), ...env },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '',
    stderr = '';
  child.stdout.on('data', chunk => {
    stdout += chunk;
    onOutput?.(stdout);
  });
  child.stderr.on('data', chunk => (stderr += chunk));
  const exited = new Promise(resolve =>
    child.once('exit', (code, signal) => resolve({ code, signal, stdout, stderr }))
  );
  return { child, exited };
}

// ---------------------------------------------------------------------------------------------
// checkConfigFile (lib/config.mjs, §3.11)

test('checkConfigFile applies the constructor rules read-only and creates nothing', async t => {
  const base = temporary(t);
  // A missing file (or directory) is fine, and nothing is created.
  const missing = path.join(base, 'not-yet');
  assert.equal(checkConfigFile(missing), false);
  assert.equal(fs.existsSync(missing), false, 'the directory is not created');
  // A valid file is accepted and never rewritten, even when the constructor would repair it.
  const directory = temporary(t);
  const file = path.join(directory, 'config.json');
  const repairable = JSON.stringify({ services: [], appearance: { timezone: 'UTC+00:00' } });
  fs.writeFileSync(file, repairable);
  const warnings = t.mock.method(console, 'warn', () => {});
  assert.equal(checkConfigFile(directory), true);
  assert.equal(fs.readFileSync(file, 'utf8'), repairable, 'repairs are not saved by the check');
  assert.equal(warnings.mock.callCount(), 0, 'nor reported: the constructor reports them');
  assert.deepEqual(fs.readdirSync(directory), ['config.json']);
  // The constructor still repairs and saves it once.
  const store = new ConfigStore(directory);
  assert.equal(store.value.appearance.timezone, 'UTC');
  assert.equal(warnings.mock.callCount(), 1);
  // A corrupt file is refused with the constructor's exact text.
  for (const text of ['{"services": [', '[]', '{"services":[{"id":"x","type":"nope"}]}']) {
    fs.writeFileSync(file, text);
    let fromConstructor;
    try {
      new ConfigStore(directory);
    } catch (error) {
      fromConstructor = error;
    }
    assert.ok(fromConstructor?.refusal);
    assert.throws(
      () => checkConfigFile(directory),
      error =>
        error.refusal === true &&
        error.message === fromConstructor.message &&
        startupExitCode(error) === 78
    );
    assert.equal(fs.readFileSync(file, 'utf8'), text);
  }
  // parseConfig is the one implementation both use.
  assert.throws(
    () => parseConfig('{', '/x/config.json'),
    /Invalid configuration file \/x\/config\.json/
  );
  // Something other than a regular file in its place (a directory, a FIFO) is not a
  // configuration a retry could read: a refusal (exit 78).
  fs.rmSync(file);
  fs.mkdirSync(file);
  assert.throws(
    () => checkConfigFile(directory),
    error =>
      error.refusal === true && /regular file/.test(error.message) && startupExitCode(error) === 78
  );
  // A read error other than ENOENT is passed on unchanged (exit 1: the start is retried).
  fs.rmSync(file, { recursive: true });
  fs.writeFileSync(file, '{"services":[]}');
  const open = fs.openSync;
  t.mock.method(fs, 'openSync', (target, ...rest) => {
    if (target === file) throw Object.assign(new Error('i/o error'), { code: 'EIO' });
    return open(target, ...rest);
  });
  assert.throws(
    () => checkConfigFile(directory),
    error => error.code === 'EIO' && error.refusal !== true && startupExitCode(error) === 1
  );
});

// ---------------------------------------------------------------------------------------------
// The start sequence

test('control.sqlite opens before ConfigStore: a new directory is recorded as created by this release', async t => {
  const directory = path.join(temporary(t), 'data');
  const app = await start(directory);
  await app.close();
  // Had config.json existed when the control database opened, this would be an upgrade.
  assert.equal(meta(directory).created_by_release, release);
  assert.ok(fs.existsSync(path.join(directory, 'config.json')));
  // An upgraded 1.4.x directory has none.
  const legacy = legacyData(t);
  const upgraded = await start(legacy);
  await upgraded.close();
  assert.equal(meta(legacy).created_by_release, undefined);
});

// Removing control.sqlite (for example to start over after a lost key) must not also take a
// directory 1.5 created for 1.4.x data, which turned legacy Basic on by default (G2).
test('removing control.sqlite keeps legacy Basic off for a directory 1.5 created, and on for 1.4.x data (G2)', async t => {
  const saved = process.env.GOBLIN_LEGACY_BASIC;
  delete process.env.GOBLIN_LEGACY_BASIC;
  t.after(() =>
    saved === undefined
      ? delete process.env.GOBLIN_LEGACY_BASIC
      : (process.env.GOBLIN_LEGACY_BASIC = saved)
  );
  const lines = [];
  t.mock.method(console, 'log', text => lines.push(String(text)));
  const basic = 'Basic ' + Buffer.from(`admin:${password}`).toString('base64');
  // A start without the legacyBasic option: its start line and a script's Basic request.
  const script = async directory => {
    const app = await start(directory);
    try {
      const { port } = await app.listen();
      const answer = await fetch(`http://127.0.0.1:${port}/api/version`, {
        headers: { Authorization: basic },
      });
      const body = await answer.json();
      return {
        status: answer.status,
        code: body.code ?? null,
        basic: /legacy Basic for scripts: (on|off)/.exec(
          lines.filter(text => text.startsWith('Sign-in:')).at(-1)
        )?.[1],
      };
    } finally {
      await app.close();
    }
  };
  const removeControl = directory => {
    for (const suffix of ['', '-wal', '-shm'])
      fs.rmSync(path.join(directory, `control.sqlite${suffix}`), { force: true });
  };
  const created = path.join(temporary(t), 'data');
  const off = { status: 401, code: 'basic_disabled', basic: 'off' };
  assert.deepEqual(await script(created), off);
  removeControl(created);
  assert.deepEqual(await script(created), off, 'still off once control.sqlite is gone');
  assert.equal(meta(created).created_by_release, release);
  assert.equal(
    JSON.parse(fs.readFileSync(path.join(created, 'created-by.json'), 'utf8')).release,
    release
  );

  const legacy = legacyData(t);
  const on = { status: 200, code: null, basic: 'on' };
  assert.deepEqual(await script(legacy), on);
  removeControl(legacy);
  assert.deepEqual(await script(legacy), on);
  assert.equal(meta(legacy).created_by_release, undefined);
  assert.equal(fs.existsSync(path.join(legacy, 'created-by.json')), false);
});

// Keyring rows in control.sqlite, read beside a running Uptime Goblin (0 without the table or file).
function keyringRows(directory) {
  const file = path.join(directory, 'control.sqlite');
  if (!fs.existsSync(file)) return 0;
  const db = new DatabaseSync(file, { readOnly: true });
  try {
    const table = db
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'keyring'")
      .get();
    return table ? db.prepare('SELECT count(*) AS n FROM keyring').get().n : 0;
  } finally {
    db.close();
  }
}

// Replaces "a start needs no encryption key until a keyring exists (D2)": every start opens
// the keyring now, creating it after identity accepted the start (delivery spec D6).
test('a start reads GOBLIN_PASSWORD and removes it from process.env; the password still signs in', async t => {
  const directory = temporary(t);
  process.env.GOBLIN_PASSWORD = password;
  t.after(() => delete process.env.GOBLIN_PASSWORD);
  // No password passed: createApp reads GOBLIN_PASSWORD, as a real start does.
  const app = await start(directory, { password: undefined });
  t.after(() => app.close());
  assert.equal(process.env.GOBLIN_PASSWORD, undefined, 'the password left process.env');
  assert.equal(app.identity.status().source, 'env');
  const { port } = await app.listen();
  const basic = secret => ({
    Authorization: `Basic ${Buffer.from(`admin:${secret}`).toString('base64')}`,
  });
  const ok = await fetch(`http://127.0.0.1:${port}/api/version`, { headers: basic(password) });
  assert.equal(ok.status, 200);
  const wrong = await fetch(`http://127.0.0.1:${port}/api/version`, { headers: basic('x') });
  assert.equal(wrong.status, 401);
});

test('a start reads GOBLIN_SECRET_KEY, removes it from process.env before identity runs, and creates the keyring with it after identity; nothing is generated', async t => {
  const directory = temporary(t);
  process.env.GOBLIN_SECRET_KEY = hexKey;
  t.after(() => delete process.env.GOBLIN_SECRET_KEY);
  const lines = [];
  for (const level of ['log', 'warn'])
    t.mock.method(console, level, (...args) => lines.push(args.join(' ')));
  // What identity sees while it starts: the environment and the keyring.
  const seen = [];
  const clock = () => {
    if (seen.length < 5)
      seen.push({ env: process.env.GOBLIN_SECRET_KEY, keyring: keyringRows(directory) });
    return Date.now();
  };
  const app = await start(directory, { identityOptions: { clock } });
  await app.close();
  assert.ok(seen.length > 0, 'identity read its clock');
  for (const entry of seen) {
    assert.equal(entry.env, undefined, 'the key left process.env before identity ran');
    assert.equal(entry.keyring, 0, 'no keyring before identity accepted the start');
  }
  assert.equal(process.env.GOBLIN_SECRET_KEY, undefined);
  assert.equal(fs.existsSync(path.join(directory, 'secret.key')), false, 'nothing generated');
  assert.ok(keyringRows(directory) > 0, 'the keyring was created');
  const control = openControl(directory, { readOnly: true, env: {} });
  try {
    await Keyring.check(control.keyringStore, { key: Buffer.from(hexKey, 'hex') });
  } finally {
    control.close();
  }
  const printed = keyFingerprint(Buffer.from(hexKey, 'hex'));
  assert.ok(lines.includes(`Encryption key: GOBLIN_SECRET_KEY · fingerprint ${printed}`));
  assert.ok(
    lines.some(line => /^GOBLIN_SECRET_KEY was removed from Uptime Goblin's environment/.test(line))
  );
  assert.ok(!lines.some(line => line.includes(hexKey)), 'the key is never printed');
  // Without the key the keyring cannot be opened: refused (78), nothing generated or changed.
  const before = fingerprint(directory, ['goblin.lock', 'orbit.lock', 'run']);
  await assert.rejects(
    start(directory),
    error => error.code === 'key_missing' && startupExitCode(error) === 78
  );
  assert.deepEqual(fingerprint(directory, ['goblin.lock', 'orbit.lock', 'run']), before);
  assert.equal(fs.existsSync(path.join(directory, 'secret.key')), false);
});

test('the start line names where the key came from, with its fingerprint, for every source', async t => {
  const lines = [];
  for (const level of ['log', 'warn'])
    t.mock.method(console, level, (...args) => lines.push(args.join(' ')));
  const keyLine = () => lines.filter(line => line.startsWith('Encryption key:')).at(-1);
  const key = Buffer.from(otherKey, 'hex'),
    printed = keyFingerprint(key);
  const keyFile = (directory, name) => {
    const file = path.join(directory, name);
    fs.writeFileSync(file, otherKey + '\n', { mode: 0o600 });
    return file;
  };
  const empty = temporary(t, 'orbit-no-secrets-');
  // No source: a new <data>/secret.key, with the warning that it travels with the data.
  const generated = temporary(t);
  await (await start(generated, { keySources: { secretsDirectory: empty } })).close();
  const own = path.join(generated, 'secret.key');
  const ownPrint = keyFingerprint(Buffer.from(fs.readFileSync(own, 'utf8').trim(), 'hex'));
  assert.equal(keyLine(), `Encryption key: a new ${own} (generated now) · fingerprint ${ownPrint}`);
  assert.ok(lines.some(line => line.startsWith(`${own} is inside the data directory`)));
  // The same directory again: the key it generated.
  await (await start(generated, { keySources: { secretsDirectory: empty } })).close();
  assert.equal(keyLine(), `Encryption key: ${own} · fingerprint ${ownPrint}`);
  // GOBLIN_SECRET_KEY_FILE naming that very file (review round 3): the key in use, which travels
  // with the data. Never "is not used … delete it", which deleted the only copy of the key and
  // made the next start exit 78; the start after this one still finds it.
  process.env.GOBLIN_SECRET_KEY_FILE = own;
  try {
    for (let round = 0; round < 2; round++) {
      const since = lines.length;
      await (await start(generated, { keySources: { secretsDirectory: empty } })).close();
      const logged = lines.slice(since);
      assert.ok(
        logged.includes(
          `Encryption key: GOBLIN_SECRET_KEY_FILE (${own}) · fingerprint ${ownPrint}`
        ),
        logged.join('\n')
      );
      assert.ok(
        logged.includes(
          `GOBLIN_SECRET_KEY_FILE (${own}) is inside the data directory, so every copy of the data directory carries the key. Keep backups of the data and of the key apart: copy the key to a file outside the data directory and set GOBLIN_SECRET_KEY_FILE to that copy. Delete ${own} only once Uptime Goblin has started with the copy: until then it is the key Uptime Goblin reads.`
        ),
        logged.join('\n')
      );
      assert.ok(!logged.some(line => /is not used/.test(line)), logged.join('\n'));
      assert.ok(fs.existsSync(own));
    }
  } finally {
    delete process.env.GOBLIN_SECRET_KEY_FILE;
  }
  // GOBLIN_SECRET_KEY_FILE.
  const fromFile = temporary(t);
  const file = keyFile(temporary(t, 'orbit-key-'), 'orbit.key');
  process.env.GOBLIN_SECRET_KEY_FILE = file;
  try {
    await (await start(fromFile, { keySources: { secretsDirectory: empty } })).close();
  } finally {
    delete process.env.GOBLIN_SECRET_KEY_FILE;
  }
  assert.equal(
    keyLine(),
    `Encryption key: GOBLIN_SECRET_KEY_FILE (${file}) · fingerprint ${printed}`
  );
  // The systemd credential and the Compose secret.
  const credentials = temporary(t, 'orbit-credentials-');
  const credential = keyFile(credentials, 'orbit-secret-key');
  await (
    await start(temporary(t), {
      keySources: { credentialsDirectory: credentials, secretsDirectory: empty },
    })
  ).close();
  assert.equal(
    keyLine(),
    `Encryption key: the systemd credential (${credential}) · fingerprint ${printed}`
  );
  const secrets = temporary(t, 'orbit-secrets-');
  const secret = keyFile(secrets, 'orbit_secret_key');
  await (await start(temporary(t), { keySources: { secretsDirectory: secrets } })).close();
  assert.equal(
    keyLine(),
    `Encryption key: the Compose secret (${secret}) · fingerprint ${printed}`
  );
  assert.ok(!lines.some(line => line.includes(otherKey)), 'never the key');
});

test('identity refusals leave no key material: no secret.key and no keyring before identity accepts', async t => {
  // A directory whose control.sqlite has no keyring (as the sessions milestone left it).
  const withoutKeyring = async () => {
    const directory = legacyData(t);
    process.env.GOBLIN_SECRET_KEY = hexKey;
    try {
      await (await start(directory)).close();
    } finally {
      delete process.env.GOBLIN_SECRET_KEY;
    }
    // Nothing is sealed without GOBLIN_WEBHOOK_URL, so the keyring rows are all there is.
    const db = openSqlite(path.join(directory, 'control.sqlite'));
    try {
      await db.write(tx => tx.run(tx.dialect.deleteFrom('keyring', sql`${id('kid')} IS NOT NULL`)));
    } finally {
      db.close();
    }
    assert.equal(keyringRows(directory), 0);
    return directory;
  };
  const refusedWithoutKey = async (directory, options, check) => {
    const before = fingerprint(directory, ['goblin.lock', 'orbit.lock', 'run']);
    await assert.rejects(
      start(directory, options),
      error => startupExitCode(error) === 78 && check(error)
    );
    assert.deepEqual(
      fingerprint(directory, ['goblin.lock', 'orbit.lock', 'run']),
      before,
      'no byte changed'
    );
    assert.equal(fs.existsSync(path.join(directory, 'secret.key')), false, 'no secret.key');
    assert.equal(keyringRows(directory), 0, 'no keyring row');
    assert.ok(lockIsFree(directory));
  };
  // A damaged stored admin record, which identity imports again from GOBLIN_PASSWORD: identity
  // refuses after startControl, before the keyring is created.
  const damaged = await withoutKeyring();
  const db = openSqlite(path.join(damaged, 'control.sqlite'));
  try {
    await db.write(tx => {
      tx.run(sql`UPDATE ${id('users')} SET ${id('password')} = ${'{"version":1}'}`);
      tx.run(tx.dialect.deleteFrom('meta', sql`${id('key')} = ${'credentials_ever'}`));
    });
  } finally {
    db.close();
  }
  await refusedWithoutKey(
    damaged,
    { identityOptions: { derive: refusingDerive } },
    error => error.message === identityRefusal
  );
  // Credentials existed, and no source is configured now: the start refuses before the lock
  // (Uptime Goblin always requires a password), so startControl's own password check is not reached.
  const guarded = await withoutKeyring();
  await refusedWithoutKey(
    guarded,
    { password: '' },
    error => error.message === passwordRequiredMessage
  );
});

test('a start on a full disk releases the space reserve before startControl, and still starts', async t => {
  const directory = temporary(t);
  // A first start holds the reserve (the real disk has room).
  await (await start(directory)).close();
  const reserve = path.join(directory, 'run', 'space-reserve');
  assert.equal(fs.statSync(reserve).size, 8 * 2 ** 20);
  // Now the disk is full: by the time startControl looks for the key (its step 2, before the
  // snapshot and the migration), the reserve is already gone.
  let reserveAtStep2 = null;
  const keySources = {
    get credentialsDirectory() {
      reserveAtStep2 ??= fs.existsSync(reserve);
      return undefined;
    },
  };
  const statfs = () => ({ type: 0, bsize: 1, blocks: 2 ** 40, bfree: 2 ** 20, bavail: 2 ** 20 });
  t.mock.method(console, 'warn', () => {});
  const { app, url } = await serve(t, directory, { keySources, storageGuard: { statfs } });
  assert.equal(reserveAtStep2, false, 'released before startControl');
  assert.equal(fs.existsSync(reserve), false);
  assert.equal(app.guard.state().full, true);
  const { cookie } = await signIn(url, password);
  const dashboard = await sessionCall(url, cookie)('/api/dashboard');
  assert.equal(dashboard.status, 200);
  assert.equal(dashboard.body.disk.full, true);
  const refused = await sessionCall(url, cookie)('/api/settings', 'PATCH', { title: 'Full' });
  assert.equal(refused.status, 503);
  assert.equal(refused.body.code, 'storage_full');
});

// A connection test whose collector waits until `release()`; `calls` counts the collections.
function heldCollector() {
  const state = { calls: 0, release: null };
  const gate = new Promise(resolve => (state.release = resolve));
  state.collector = async () => {
    state.calls += 1;
    if (state.calls === 1) await gate;
    return [{ key: 'probe', label: 'Probe', value: 1, unit: '' }];
  };
  return state;
}
const probe = {
  settings: { type: 'http', name: 'Probe', group: 'Test', apiUrl: 'http://192.0.2.1/' },
};

test('a keyed request refused with 401 is not kept: after signing in again the same key runs', async t => {
  const held = heldCollector();
  const { url } = await serve(t, temporary(t), { collector: held.collector });
  const first = await signIn(url, password);
  const key = { 'Idempotency-Key': 'retry-after-sign-in-0001' };
  const pending = sessionCall(url, first.cookie)('/api/test-service', 'POST', probe, key);
  for (let i = 0; i < 400 && held.calls === 0; i++) await new Promise(r => setTimeout(r, 5));
  assert.equal(held.calls, 1, 'the test is running');
  // Signed out while the keyed request runs: its answer is a refusal that applied nothing.
  assert.equal((await sessionCall(url, first.cookie)('/api/auth/logout', 'POST')).status, 204);
  held.release();
  const refused = await pending;
  assert.equal(refused.status, 401);
  assert.equal(refused.body.code, 'session_expired');
  assert.equal(refused.headers.get('www-authenticate'), null, 'a browser is never challenged');
  // Signed in again (a new session of the same user): the retry runs; the 401 is not replayed.
  const second = await signIn(url, password);
  const retried = await sessionCall(url, second.cookie)('/api/test-service', 'POST', probe, key);
  assert.equal(retried.status, 200, JSON.stringify(retried.body));
  assert.equal(retried.headers.get('idempotent-replayed'), null);
  assert.equal(held.calls, 2);
});

test('a keyed write retried from a new session of the same user replays its answer (D22)', async t => {
  const held = heldCollector();
  held.release();
  const { url } = await serve(t, temporary(t), { collector: held.collector });
  const first = await signIn(url, password);
  const key = { 'Idempotency-Key': 'retry-after-sign-in-0002' };
  const done = await sessionCall(url, first.cookie)('/api/test-service', 'POST', probe, key);
  assert.equal(done.status, 200);
  const second = await signIn(url, password);
  const replayed = await sessionCall(url, second.cookie)('/api/test-service', 'POST', probe, key);
  assert.equal(replayed.status, 200);
  assert.equal(replayed.headers.get('idempotent-replayed'), 'true');
  assert.equal(held.calls, 1, 'it ran once');
});

test('one Uptime Goblin per data directory: a second start is refused with exit 75 until the first stops', async t => {
  const directory = temporary(t);
  const first = await start(directory);
  await assert.rejects(
    start(directory),
    error => error instanceof LockHeldError && startupExitCode(error) === 75
  );
  assert.equal(first.lock.held, true, 'the refused start did not touch the held lock');
  await first.close();
  assert.equal(first.lock.held, false);
  // After close() resolves the same process can start Uptime Goblin on the directory again.
  const second = await start(directory);
  await second.close();
});

test('shutdown closes identity and the control database, then releases goblin.lock', async t => {
  const directory = temporary(t);
  const { app, url } = await serve(t, directory);
  const { cookie } = await signIn(url, password);
  assert.equal((await sessionCall(url, cookie)('/api/session')).status, 200);
  await app.close();
  assert.equal(app.lock.held, false);
  await assert.rejects(app.control.meta.get('instance_id'), 'the control database is closed');
  assert.ok(lockIsFree(directory));
  // close() is idempotent.
  await app.close();
  // The session is in control.sqlite: a restart keeps it.
  const { url: again } = await serve(t, directory);
  assert.equal((await sessionCall(again, cookie)('/api/session')).status, 200);
});

test('a corrupt config.json on 1.4.x data refuses (78) before control.sqlite, a snapshot or the password import exist', async t => {
  const directory = legacyData(t);
  fs.writeFileSync(path.join(directory, 'config.json'), '{"services": [');
  const before = fingerprint(directory, ['goblin.lock', 'orbit.lock']);
  await assert.rejects(
    start(directory),
    error =>
      error.refusal === true && startupExitCode(error) === 78 && /config\.json/.test(error.message)
  );
  assert.deepEqual(fingerprint(directory, ['goblin.lock', 'orbit.lock']), before, 'byte-identical');
  assert.equal(fs.existsSync(path.join(directory, 'control.sqlite')), false);
  assert.equal(fs.existsSync(path.join(directory, 'snapshots')), false);
  assert.ok(lockIsFree(directory));
});

test('every refusal through createApp exits 78, changes nothing but goblin.lock and run/, and releases the lock (T11)', async t => {
  const skip = ['goblin.lock', 'orbit.lock', 'run'];
  const refused = async (directory, options, check) => {
    const before = fingerprint(directory, skip);
    await assert.rejects(
      start(directory, options),
      error => startupExitCode(error) === 78 && check(error)
    );
    assert.deepEqual(fingerprint(directory, skip), before, 'no byte changed');
    assert.equal(fs.existsSync(path.join(directory, 'control.sqlite-wal')), false);
    assert.ok(lockIsFree(directory), 'the lock was released');
  };
  // A started 1.5 directory with a password.
  const started = async () => {
    const directory = legacyData(t);
    const app = await start(directory);
    await app.close();
    return directory;
  };
  const write = async (directory, unit) => {
    const db = openSqlite(path.join(directory, 'control.sqlite'));
    try {
      await db.write(unit);
    } finally {
      db.close();
    }
  };

  // A fence newer than this release.
  const fenced = await started();
  await write(fenced, tx =>
    requireRelease(tx, { name: 'identity.totp', minRelease: '9.0.0', reason: 'TOTP', now: 1 })
  );
  await refused(fenced, {}, error => error.code === 'fence');

  // An applied contract step this release does not know.
  const newer = await started();
  await write(newer, tx =>
    tx.run(
      tx.dialect.insert(
        'schema_migrations',
        ['id', 'component', 'kind', 'release', 'applied_at'],
        [['platform-009-drop', 'platform', 'contract', '2.0.0', 1]]
      )
    )
  );
  await refused(newer, {}, error => error.code === 'data_newer');

  // A keyring needs its key: missing, then the wrong one. Every start creates the keyring now
  // (delivery spec D6), so this directory's first start is given the key to create it with,
  // and no secret.key is generated beside it.
  process.env.GOBLIN_SECRET_KEY = hexKey;
  const keyed = await started();
  assert.equal(process.env.GOBLIN_SECRET_KEY, undefined);
  await refused(keyed, {}, error => error.code === 'key_missing');
  assert.equal(fs.existsSync(path.join(keyed, 'secret.key')), false, 'no key was generated');
  process.env.GOBLIN_SECRET_KEY = otherKey;
  try {
    await refused(keyed, {}, error => error.code === 'key_mismatch');
    assert.equal(process.env.GOBLIN_SECRET_KEY, undefined, 'a key read leaves the environment');
    // With the right key the start proceeds.
    process.env.GOBLIN_SECRET_KEY = hexKey;
    const opened = await start(keyed);
    await opened.close();
  } finally {
    delete process.env.GOBLIN_SECRET_KEY;
  }

  // Credentials existed, and neither source is configured now: refused before the lock
  // (startControl's own password check is not reached). So is a directory that never had one.
  const guarded = await started();
  await refused(guarded, { password: '' }, error => error.message === passwordRequiredMessage);
  await refused(
    legacyData(t),
    { password: '' },
    error => error.message === passwordRequiredMessage
  );

  // An invalid auth.json (refused before the lock is even taken) and a short GOBLIN_PASSWORD.
  const invalid = legacyData(t, { auth: '{}\n' });
  await refused(invalid, {}, error =>
    /Saved authentication could not be loaded/.test(error.message)
  );
  const symlinked = legacyData(t);
  fs.symlinkSync(path.join(invalid, 'auth.json'), path.join(symlinked, 'auth.json'));
  await refused(symlinked, {}, error =>
    /Saved authentication could not be loaded/.test(error.message)
  );
  const short = legacyData(t);
  await refused(short, { password: 'too short' }, error =>
    /GOBLIN_PASSWORD must be 12 to 1024/.test(error.message)
  );

  // A damaged stored admin record with no source to restore it from (credentials_ever unset,
  // as after a restore of a database that never recorded it): without a source the start
  // refuses before the lock; identity's own refusal of it is in test/identity/bootstrap.test.mjs.
  const damaged = await started();
  await write(damaged, tx => {
    tx.run(sql`UPDATE ${id('users')} SET ${id('password')} = ${'{"version":1}'}`);
    tx.run(tx.dialect.deleteFrom('meta', sql`${id('key')} = ${'credentials_ever'}`));
  });
  await refused(damaged, { password: '' }, error => error.message === passwordRequiredMessage);
  // With GOBLIN_PASSWORD identity imports it again; a refusal it raises there (from its KDF,
  // through the tests' seam) changes nothing either.
  await refused(
    damaged,
    { identityOptions: { derive: refusingDerive } },
    error => error.message === identityRefusal
  );
});

test('the capability flags come from the environment: GOBLIN_INSECURE_HTTP_SESSIONS=1 allows plain-HTTP sign-in', async t => {
  const directory = temporary(t);
  // A request forwarded by a proxy Uptime Goblin does not trust is on the http transport.
  const httpLogin = url =>
    fetch(`${url}/api/auth/login`, {
      method: 'POST',
      headers: {
        Origin: url,
        'Sec-Fetch-Site': 'same-origin',
        'X-Goblin-Request': '1',
        'X-Goblin-Client': 'web/test',
        'Content-Type': 'application/json',
        'X-Forwarded-For': '192.0.2.10',
      },
      body: JSON.stringify({ login: 'admin', password }),
    });
  {
    const { app, url } = await serve(t, directory);
    const refused = await httpLogin(url);
    assert.equal(refused.status, 403);
    assert.equal((await refused.json()).code, 'https_required');
    await app.close();
  }
  process.env.GOBLIN_INSECURE_HTTP_SESSIONS = '1';
  t.after(() => delete process.env.GOBLIN_INSECURE_HTTP_SESSIONS);
  const log = t.mock.method(console, 'log', () => {});
  const { url } = await serve(t, directory);
  const allowed = await httpLogin(url);
  assert.equal(allowed.status, 200, await allowed.clone().text());
  assert.match(
    allowed.headers.get('set-cookie'),
    /^goblin_session=v1\.[\w-]{43}; Path=\/; HttpOnly; SameSite=Strict$/
  );
  assert.equal((await allowed.json()).transport.insecure, true);
  assert.ok(
    log.mock.calls.some(call => / · plain-HTTP sessions: allowed$/.test(call.arguments[0])),
    'the start line names the opt-in'
  );
});

test('the start line names the password source and both escape hatches, and never a secret', async t => {
  const lines = [];
  t.mock.method(console, 'log', text => lines.push(String(text)));
  const line = () => lines.filter(text => text.startsWith('Sign-in:')).at(-1);
  const env = temporary(t);
  await (await start(env)).close();
  assert.equal(
    line(),
    'Sign-in: built-in admin (password from GOBLIN_PASSWORD) · legacy Basic for scripts: on · plain-HTTP sessions: refused'
  );
  await (await start(env, { legacyBasic: false, insecureHttpSessions: true })).close();
  assert.equal(
    line(),
    'Sign-in: built-in admin (password from GOBLIN_PASSWORD) · legacy Basic for scripts: off · plain-HTTP sessions: allowed'
  );
  // An in-app change moves the password to auth.json (the mirror).
  const mirrored = temporary(t);
  const { app, url } = await serve(t, mirrored);
  const { cookie } = await signIn(url, password);
  const changed = await sessionCall(url, cookie)('/api/account/password', 'POST', {
    currentPassword: password,
    password: 'startup-test-password-2',
    confirmPassword: 'startup-test-password-2',
  });
  assert.equal(changed.status, 200);
  await app.close();
  await (await start(mirrored)).close();
  assert.match(line(), /^Sign-in: built-in admin \(password from auth\.json\)/);
  // There is no "Sign-in: none" line any more: a start without a password is refused.
  await assert.rejects(start(temporary(t), { password: '' }), { message: passwordRequiredMessage });
  assert.ok(!lines.some(text => text.startsWith('Sign-in: none')));
  assert.ok(!lines.some(text => text.includes(password)), 'no password in the output');
  // startLine() itself, for an identity whose password came from auth.json.
  assert.equal(
    startLine({
      identity: { status: () => ({ source: 'auth.json' }) },
      legacyBasic: true,
      insecureHttpSessions: false,
    }),
    'Sign-in: built-in admin (password from auth.json) · legacy Basic for scripts: on · plain-HTTP sessions: refused'
  );
});

test('restoring a snapshot signs every session out, including sessions revoked since (D25)', async t => {
  const directory = legacyData(t);
  let running = await serve(t, directory);
  const revoked = (await signIn(running.url, password)).cookie;
  const other = (await signIn(running.url, password)).cookie;
  const snapshot = await createSnapshot(directory, { reason: 'manual', release });
  // Signed out after the snapshot was taken: the snapshot still holds its row.
  const logout = await sessionCall(running.url, revoked)('/api/auth/logout', 'POST');
  assert.equal(logout.status, 204);
  assert.equal((await sessionCall(running.url, other)('/api/session')).status, 200);
  await running.app.close();
  const lock = acquireLock(directory);
  try {
    await restoreSnapshot(directory, snapshot.id, { lock, release });
  } finally {
    lock.release();
  }
  running = await serve(t, directory);
  for (const cookie of [revoked, other]) {
    const answer = await sessionCall(running.url, cookie)('/api/session');
    assert.equal(answer.status, 401);
    assert.equal(answer.body.code, 'session_expired');
  }
  // The password of the snapshot's time still signs in.
  assert.equal((await signIn(running.url, password)).body.via, 'session');
  await running.app.close();
  assert.equal(JSON.parse(meta(directory).restored).snapshot, snapshot.id);
});

test('a restore killed part way: Uptime Goblin refuses (78) rather than start on the mix; running it again finishes it', async t => {
  // A power loss (here kill -9) inside restore-snapshot, after config.json was swapped and
  // before the snapshot's auth.json took its place, leaves a mix: the snapshot's settings beside
  // the current password. auth.json is never missing on the way (it is copied aside, and the
  // snapshot's renamed over it): a kill there once left none, and started on that with
  // GOBLIN_PASSWORD set (the LXC install), Uptime Goblin imported it as a password changed outside Uptime Goblin,
  // so neither the current password nor the snapshot's worked any more.
  const directory = legacyData(t);
  const first = 'startup-first-change-1',
    second = 'startup-second-change-2';
  let running = await serve(t, directory);
  const change = async (from, to) => {
    const { cookie } = await signIn(running.url, from);
    const answer = await sessionCall(running.url, cookie)('/api/account/password', 'POST', {
      currentPassword: from,
      password: to,
      confirmPassword: to,
    });
    assert.equal(answer.status, 200);
  };
  await change(password, first);
  const snapshot = await createSnapshot(directory, { reason: 'manual', release });
  await change(first, second);
  await running.app.close();

  const scratch = temporary(t, 'orbit-crash-');
  const crash = path.join(scratch, 'crash-at-rename.mjs');
  fs.writeFileSync(
    crash,
    `import fs from 'node:fs';
const rename = fs.renameSync;
fs.renameSync = function (from, to) {
  if (String(from).endsWith('.auth.json.restoring')) process.kill(process.pid, 'SIGKILL');
  return rename.call(this, from, to);
};
`
  );
  const cli = fileURLToPath(new URL('../lib/cli/goblin-admin.mjs', import.meta.url));
  const killed = spawnSync(
    process.execPath,
    ['--import', crash, cli, 'restore-snapshot', snapshot.id, '--data-dir', directory],
    { encoding: 'utf8', env: { PATH: process.env.PATH } }
  );
  assert.equal(killed.signal, 'SIGKILL', killed.stderr);
  const aside = path.join(
    directory,
    'snapshots',
    `.restoring-${interruptedRestore(directory).aside}`
  );
  assert.deepEqual(
    fs.readFileSync(path.join(directory, 'config.json')),
    fs.readFileSync(path.join(directory, 'snapshots', snapshot.id, 'config.json')),
    'killed mid-swap: config.json is the snapshot’s'
  );
  assert.deepEqual(
    fs.readFileSync(path.join(directory, 'auth.json')),
    fs.readFileSync(path.join(aside, 'auth.json')),
    'auth.json is still the current one, and a copy of it is kept aside'
  );

  // The service manager starts Uptime Goblin again: it refuses, says what to run, and changes nothing.
  const before = fingerprint(directory, ['goblin.lock', 'orbit.lock', 'run']);
  const server = spawnServer({ GOBLIN_DATA_DIR: directory, GOBLIN_PASSWORD: password });
  t.after(() => server.child.kill('SIGKILL'));
  // One that starts instead is stopped after a while, so the test fails rather than waits.
  const stop = setTimeout(() => server.child.kill('SIGKILL'), 30000);
  const refused = await server.exited;
  clearTimeout(stop);
  assert.equal(refused.code, 78, refused.stdout + refused.stderr);
  const message = interruptedRestoreMessage({ snapshot: snapshot.id });
  assert.ok(refused.stderr.includes(message), refused.stderr);
  assert.match(
    message,
    new RegExp(
      `sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret\\.key node /opt/uptime-goblin/lib/cli/goblin-admin\\.mjs restore-snapshot ${snapshot.id} --data-dir /var/lib/uptime-goblin`
    )
  );
  await assert.rejects(start(directory), { code: 'restore_interrupted', exitCode: 78 });
  assert.deepEqual(fingerprint(directory, ['goblin.lock', 'orbit.lock', 'run']), before);
  // goblin-admin migrate --apply refuses the same way, naming the copy that runs it and this
  // data directory (natively: `container: false`, as the Node 24 gate runs this in Docker).
  const err = [];
  const io = {
    env: {},
    stdout: () => {},
    stderr: text => err.push(text),
    uid: 1000,
    container: false,
  };
  assert.equal(await orbitAdmin(['migrate', '--apply', '--data-dir', directory], io), 78);
  const fromHere = asAdminCopy({ root: appRoot, dataDir: directory }, () =>
    interruptedRestoreMessage({ snapshot: snapshot.id })
  );
  assert.ok(err.join('').includes(fromHere), err.join(''));
  assert.deepEqual(fingerprint(directory, ['goblin.lock', 'orbit.lock', 'run']), before);

  // The same restore, run again, finishes it: the snapshot's password signs in again.
  assert.equal(await orbitAdmin(['restore-snapshot', snapshot.id, '--data-dir', directory], io), 0);
  running = await serve(t, directory);
  assert.equal((await signIn(running.url, first)).body.via, 'session');
  for (const old of [second, password]) {
    const answer = await fetch(new URL('/api/auth/login', running.url), {
      method: 'POST',
      headers: {
        Origin: running.url,
        'Sec-Fetch-Site': 'same-origin',
        'X-Goblin-Request': '1',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ login: 'admin', password: old }),
    });
    assert.equal(answer.status, 401);
  }
  await running.app.close();
});

test('a restore killed while it copied: goblin-admin reports its hidden full-size copies, and the next start removes them', async t => {
  // kill -9 inside restore-snapshot right after it copied history.sqlite (step 1, before its
  // journal: nothing live changed yet). The copies stayed in the data directory for ever, hidden
  // and as large as the files, history.sqlite's included, taking the space history needs.
  const directory = legacyData(t);
  const writer = new DatabaseSync(path.join(directory, 'history.sqlite'));
  writer.exec(
    "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 3000) INSERT INTO readings SELECT 'filler', i FROM n"
  );
  writer.close();
  const first = await serve(t, directory);
  await first.app.close();
  const snapshot = await createSnapshot(directory, { reason: 'manual', release });
  const historyBytes = fs.statSync(
    path.join(directory, 'snapshots', snapshot.id, 'history.sqlite')
  ).size;

  const scratch = temporary(t, 'orbit-crash-');
  const crash = path.join(scratch, 'crash-after-copy.mjs');
  fs.writeFileSync(
    crash,
    `import fs from 'node:fs';
const copy = fs.copyFileSync;
fs.copyFileSync = function (from, to, mode) {
  copy.call(this, from, to, mode);
  if (String(to).endsWith('.history.sqlite.restoring')) process.kill(process.pid, 'SIGKILL');
};
`
  );
  const cli = fileURLToPath(new URL('../lib/cli/goblin-admin.mjs', import.meta.url));
  const before = fingerprint(directory, ['goblin.lock', 'run', 'snapshots']);
  const killed = spawnSync(
    process.execPath,
    ['--import', crash, cli, 'restore-snapshot', snapshot.id, '--data-dir', directory],
    { encoding: 'utf8', env: { PATH: process.env.PATH } }
  );
  assert.equal(killed.signal, 'SIGKILL', killed.stderr);
  const hidden = () =>
    fs
      .readdirSync(directory)
      .filter(name => /^\..+\.restoring(?:-wal|-shm|-journal)?$/.test(name))
      .sort();
  assert.deepEqual(hidden(), [
    '.config.json.restoring',
    '.control.sqlite.restoring',
    '.history.sqlite.restoring',
  ]);
  assert.equal(fs.statSync(path.join(directory, '.history.sqlite.restoring')).size, historyBytes);
  const now = fingerprint(directory, ['goblin.lock', 'run', 'snapshots']);
  for (const name of hidden()) delete now[name];
  assert.deepEqual(now, before, 'nothing live changed');

  // goblin-admin status and snapshots report them.
  const run = async (...args) => {
    let out = '';
    const io = { env: {}, stdout: text => (out += text), stderr: () => {}, uid: 1000 };
    const code = await orbitAdmin([...args, '--data-dir', directory], io);
    return { code, out };
  };
  const unit = path.join(scratch, 'no.service');
  const status = JSON.parse((await run('status', '--json', '--unit', unit)).out);
  assert.equal(status.restore.interrupted, null);
  assert.deepEqual(
    status.restore.leftovers.map(item => [item.id, item.needed]),
    [
      ['.config.json.restoring', false],
      ['.control.sqlite.restoring', false],
      ['.history.sqlite.restoring', false],
    ]
  );
  assert.equal(
    status.restore.leftovers.find(item => item.id === '.history.sqlite.restoring').bytes,
    historyBytes
  );
  assert.match(
    (await run('status', '--unit', unit)).out,
    /\nRestore leftover: \.history\.sqlite\.restoring in the data directory \(.+\)\. A copy of history\.sqlite left by a snapshot restore that a crash or a power loss stopped/
  );
  const listed = JSON.parse((await run('snapshots', '--json')).out);
  assert.deepEqual(
    listed.filter(item => item.leftover).map(item => item.id),
    ['.config.json.restoring', '.control.sqlite.restoring', '.history.sqlite.restoring']
  );

  // The next start removes them and says so once.
  const warn = t.mock.method(console, 'warn', () => {});
  const second = await serve(t, directory);
  const said = warn.mock.calls.map(call => String(call.arguments[0]));
  warn.mock.restore();
  assert.deepEqual(hidden(), []);
  const line = said.filter(text => text.startsWith('Removed '));
  assert.equal(line.length, 1, said.join('\n'));
  assert.match(
    line[0],
    /^Removed \.config\.json\.restoring, \.control\.sqlite\.restoring, \.history\.sqlite\.restoring \(\d+\.\d MiB\) from the data directory: temporary copies of a snapshot's files that a restore stopped by a crash or a power loss left behind\. No restore needed them any more\.$/
  );
  await second.app.close();
  assert.deepEqual(JSON.parse((await run('status', '--json', '--unit', unit)).out).restore, {
    interrupted: null,
    leftovers: [],
    leftoverBytes: 0,
  });
});

// Runs goblin-admin restore-snapshot (with `extra` arguments) in a process of its own with
// `preload` (a module that kills it at a chosen point) and returns its spawnSync result.
function killedRestore(t, directory, id, name, preload, extra = []) {
  const scratch = temporary(t, 'orbit-crash-');
  const crash = path.join(scratch, name);
  fs.writeFileSync(crash, preload);
  const cli = fileURLToPath(new URL('../lib/cli/goblin-admin.mjs', import.meta.url));
  return spawnSync(
    process.execPath,
    ['--import', crash, cli, 'restore-snapshot', id, ...extra, '--data-dir', directory],
    { encoding: 'utf8', env: { PATH: process.env.PATH } }
  );
}

// A preload that kills the process (kill -9) as it renames a file whose name ends with `suffix`.
const killAtRename = suffix => `import fs from 'node:fs';
const rename = fs.renameSync;
fs.renameSync = function (from, to) {
  if (String(from).endsWith(${JSON.stringify(suffix)})) process.kill(process.pid, 'SIGKILL');
  return rename.call(this, from, to);
};
`;

// Starts node server.mjs on `directory` and resolves how it exited: one that starts instead of
// refusing is stopped after a while, so the test fails rather than waits.
async function refusedStart(t, directory) {
  const server = spawnServer({ GOBLIN_DATA_DIR: directory, GOBLIN_PASSWORD: password });
  t.after(() => server.child.kill('SIGKILL'));
  const stop = setTimeout(() => server.child.kill('SIGKILL'), 30000);
  const result = await server.exited;
  clearTimeout(stop);
  return result;
}

test('a restore killed after it completed, before its journal went: running it again keeps the same undo', async t => {
  // kill -9 between step 3's rename of the pre-restore folder to its final name and the
  // journal's removal. Uptime Goblin refuses (78) and says to run the same restore again; that re-run set
  // the restored files, the snapshot's own copies, aside as its undo and named it, so the
  // password and settings of before the restore were in a snapshot nothing named.
  const directory = legacyData(t);
  const changed = 'startup-changed-after-snapshot';
  let running = await serve(t, directory);
  const { cookie } = await signIn(running.url, password);
  const snapshot = await createSnapshot(directory, { reason: 'manual', release });
  const answer = await sessionCall(running.url, cookie)('/api/account/password', 'POST', {
    currentPassword: password,
    password: changed,
    confirmPassword: changed,
  });
  assert.equal(answer.status, 200);
  await running.app.close();
  // The password change wrote auth.json, which the snapshot (password from GOBLIN_PASSWORD) lacks.
  const current = fs.readFileSync(path.join(directory, 'auth.json'));
  assert.equal(fs.existsSync(path.join(directory, 'snapshots', snapshot.id, 'auth.json')), false);

  const killed = killedRestore(
    t,
    directory,
    snapshot.id,
    'crash-at-journal-removal.mjs',
    `import fs from 'node:fs';
const rm = fs.rmSync;
fs.rmSync = function (file, ...rest) {
  if (String(file).endsWith('/snapshots/.restore-in-progress.json')) process.kill(process.pid, 'SIGKILL');
  return rm.call(this, file, ...rest);
};
`
  );
  assert.equal(killed.signal, 'SIGKILL', killed.stderr);
  const first = interruptedRestore(directory);
  assert.equal(first.snapshot, snapshot.id);
  assert.ok(fs.existsSync(path.join(directory, 'snapshots', first.aside, 'manifest.json')));

  const refused = await refusedStart(t, directory);
  assert.equal(refused.code, 78, refused.stdout + refused.stderr);
  assert.ok(refused.stderr.includes(interruptedRestoreMessage({ snapshot: snapshot.id })));

  // Run again as the refusal says: it names the first attempt's snapshot as the undo, which
  // holds the password of before the restore.
  let out = '';
  const io = { env: {}, stdout: text => (out += text), stderr: () => {}, uid: 1000 };
  assert.equal(await orbitAdmin(['restore-snapshot', snapshot.id, '--data-dir', directory], io), 0);
  assert.ok(
    out.includes(`The replaced files are in snapshot ${first.aside}; restore it to undo.`),
    out
  );
  assert.deepEqual(
    fs.readFileSync(path.join(directory, 'snapshots', first.aside, 'auth.json')),
    current
  );
  assert.deepEqual(
    listSnapshots(directory)
      .filter(item => item.reason === 'pre-restore' || !item.valid)
      .map(item => item.id),
    [first.aside],
    'no second undo, and nothing left part done'
  );
  assert.equal(interruptedRestore(directory), null);
  // Uptime Goblin starts on the snapshot (its password signs in), and the undo gives the later one back.
  running = await serve(t, directory);
  assert.equal((await signIn(running.url, password)).body.via, 'session');
  await running.app.close();
  assert.equal(await orbitAdmin(['restore-snapshot', first.aside, '--data-dir', directory], io), 0);
  running = await serve(t, directory);
  assert.equal((await signIn(running.url, changed)).body.via, 'session');
  await running.app.close();
});

test('a restore killed as it made its folder leaves its journal, and running it again leaves no folder', async t => {
  // The folder was made before the journal: kill -9 in between left an empty
  // snapshots/.restoring-… and no journal. Uptime Goblin started, but `snapshots` listed the folder for
  // ever as an interrupted restore's, --verify failed, and the restore run again did not use it.
  const directory = legacyData(t);
  const running = await serve(t, directory);
  await running.app.close();
  const snapshot = await createSnapshot(directory, { reason: 'manual', release });
  const killed = killedRestore(
    t,
    directory,
    snapshot.id,
    'crash-at-mkdir.mjs',
    `import fs from 'node:fs';
const mkdir = fs.mkdirSync;
fs.mkdirSync = function (folder, ...rest) {
  const made = mkdir.call(this, folder, ...rest);
  if (String(folder).includes('/snapshots/.restoring-')) process.kill(process.pid, 'SIGKILL');
  return made;
};
`
  );
  assert.equal(killed.signal, 'SIGKILL', killed.stderr);
  const first = interruptedRestore(directory);
  assert.equal(first?.snapshot, snapshot.id, 'the journal was written first');
  const refused = await refusedStart(t, directory);
  assert.equal(refused.code, 78, refused.stdout + refused.stderr);

  const run = async (...args) => {
    let out = '';
    const io = { env: {}, stdout: text => (out += text), stderr: () => {}, uid: 1000 };
    const code = await orbitAdmin([...args, '--data-dir', directory], io);
    return { code, out };
  };
  assert.match(
    (await run('snapshots')).out,
    new RegExp(
      `\\.restoring-${first.aside}  INVALID: An interrupted restore made this folder for the files it replaces and had moved none here yet\\. Run the restore again to finish it\\.`
    )
  );
  const again = await run('restore-snapshot', snapshot.id);
  assert.equal(again.code, 0);
  assert.match(again.out, new RegExp(`The replaced files are in snapshot ${first.aside};`));
  const verified = await run('snapshots', '--verify');
  assert.equal(verified.code, 0, verified.out);
  assert.doesNotMatch(verified.out, /INVALID/);
});

test('a restore keeping history killed over a killed restore with history: Uptime Goblin refuses until both are finished, and no reading is lost', async t => {
  // kill -9 inside restore W as it put the snapshot's history.sqlite in place (the live one was
  // already set aside), then inside restore N --keep-history mid-swap, then N run again as the
  // refusal said. N's journal had replaced W's and the re-run removed it, so Uptime Goblin started without
  // history.sqlite and began an empty history, the readings of before W left in a folder that no
  // journal named (r5, §18 F4).
  const directory = legacyData(t);
  const now = Date.now();
  const writer = new DatabaseSync(path.join(directory, 'history.sqlite'));
  writer.exec(
    `WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 500) INSERT INTO readings SELECT 'probe', ${now} - i * 1000 FROM n`
  );
  writer.close();
  const probes = file => {
    const db = new DatabaseSync(file, { readOnly: true });
    try {
      return db.prepare("SELECT COUNT(*) AS n FROM readings WHERE service = 'probe'").get().n;
    } finally {
      db.close();
    }
  };
  const running = await serve(t, directory);
  await running.app.close();
  const wide = await createSnapshot(directory, { reason: 'wide', release });
  const narrow = await createSnapshot(directory, { reason: 'narrow', release });
  const live = path.join(directory, 'history.sqlite');

  const w = killedRestore(
    t,
    directory,
    wide.id,
    'crash-at-history.mjs',
    killAtRename('.history.sqlite.restoring')
  );
  assert.equal(w.signal, 'SIGKILL', w.stderr);
  assert.equal(fs.existsSync(live), false, 'W had set history.sqlite aside');
  const n = killedRestore(
    t,
    directory,
    narrow.id,
    'crash-at-config.mjs',
    killAtRename('.config.json.restoring'),
    ['--keep-history']
  );
  assert.equal(n.signal, 'SIGKILL', n.stderr);
  let refused = await refusedStart(t, directory);
  assert.equal(refused.code, 78, refused.stdout + refused.stderr);
  assert.ok(
    refused.stderr.includes(interruptedRestoreMessage({ snapshot: narrow.id, keepHistory: true }))
  );

  // N run again completes N and puts W's record back: the start still refuses, naming W.
  let out = '';
  const io = { env: {}, stdout: text => (out += text), stderr: () => {}, uid: 1000 };
  assert.equal(
    await orbitAdmin(
      ['restore-snapshot', narrow.id, '--keep-history', '--data-dir', directory],
      io
    ),
    0
  );
  assert.ok(
    out.includes(
      `An earlier restore of ${wide.id} was interrupted and also replaced history.sqlite`
    ),
    out
  );
  assert.equal(fs.existsSync(live), false);
  refused = await refusedStart(t, directory);
  assert.equal(refused.code, 78, refused.stdout + refused.stderr);
  assert.ok(refused.stderr.includes(interruptedRestoreMessage({ snapshot: wide.id })));

  // W run again finishes it: Uptime Goblin starts on its history, and its undo holds that of before W.
  out = '';
  assert.equal(await orbitAdmin(['restore-snapshot', wide.id, '--data-dir', directory], io), 0);
  const undo = /The replaced files are in snapshot (\S+); restore it to undo\./.exec(out)?.[1];
  assert.ok(undo, out);
  assert.equal(probes(path.join(directory, 'snapshots', undo, 'history.sqlite')), 500);
  const again = await serve(t, directory);
  await again.app.close();
  assert.equal(probes(live), 500);
  assert.equal(interruptedRestore(directory), null);
});

// ---------------------------------------------------------------------------------------------
// node server.mjs: exit statuses and stop signals (§3.3, §3.5)

test('node server.mjs without options: legacy Basic on for 1.4.x data, off for a new directory (G2)', async t => {
  const basic = 'Basic ' + Buffer.from(`admin:${password}`).toString('base64');
  for (const [directory, expect] of [
    [legacyData(t), 200],
    [temporary(t), 401],
  ]) {
    let port = null;
    const { child, exited } = spawnServer(
      { GOBLIN_DATA_DIR: directory, GOBLIN_PASSWORD: password },
      {
        onOutput: text =>
          (port ??= /Uptime Goblin is ready at http:\/\/127\.0\.0\.1:(\d+)/.exec(text)?.[1]),
      }
    );
    t.after(() => child.kill('SIGKILL'));
    for (let i = 0; i < 600 && !port && child.exitCode === null; i++)
      await new Promise(resolve => setTimeout(resolve, 50));
    assert.ok(port, 'the server started');
    const answer = await fetch(`http://127.0.0.1:${port}/api/dashboard`, {
      headers: { Authorization: basic },
    });
    assert.equal(answer.status, expect);
    if (expect === 401) assert.equal((await answer.json()).code, 'basic_disabled');
    child.kill('SIGTERM');
    const result = await exited;
    assert.equal(result.code, 0, result.stderr);
    assert.match(
      result.stdout,
      expect === 200 ? /legacy Basic for scripts: on/ : /legacy Basic for scripts: off/
    );
  }
});

test('node server.mjs exits 78 without an admin password and 75 while another process holds the lock', async t => {
  // A new data directory (not even created) and one that had a password: both refused, with
  // how to set one, on loopback as on any other address.
  const fresh = path.join(temporary(t), 'data');
  for (const HOST of ['127.0.0.1', '0.0.0.0']) {
    const refused = await spawnServer({ GOBLIN_DATA_DIR: fresh, HOST }).exited;
    assert.equal(refused.code, 78, refused.stdout + refused.stderr);
    assert.ok(refused.stderr.includes(passwordRequiredMessage), refused.stderr);
    assert.match(refused.stderr, /Uptime Goblin refused to start \(exit status 78\)/);
    assert.doesNotMatch(refused.stdout, /Uptime Goblin is ready/);
  }
  assert.equal(fs.existsSync(fresh), false, 'nothing was written');
  const directory = temporary(t);
  await (await start(directory)).close();
  const guarded = await spawnServer({ GOBLIN_DATA_DIR: directory }).exited;
  assert.equal(guarded.code, 78, guarded.stdout + guarded.stderr);
  assert.ok(guarded.stderr.includes(passwordRequiredMessage));
  assert.match(guarded.stderr, /Uptime Goblin refused to start \(exit status 78\)/);
  const lock = acquireLock(directory);
  try {
    const held = await spawnServer({ GOBLIN_DATA_DIR: directory, GOBLIN_PASSWORD: password })
      .exited;
    assert.equal(held.code, 75, held.stdout + held.stderr);
    assert.match(
      held.stderr,
      /Another Uptime Goblin process holds the data directory; the service manager starts Uptime Goblin again shortly\./
    );
  } finally {
    lock.release();
  }
});

test('a stop signal during the start exits 0, releases the lock and leaves no snapshot staging', async t => {
  const directory = legacyData(t);
  const { child, exited } = spawnServer({
    GOBLIN_DATA_DIR: directory,
    GOBLIN_PASSWORD: password,
    ...supervisedEnv(),
  });
  t.after(() => child.kill('SIGKILL'));
  // The start is under way once control.sqlite exists: the snapshot was taken and the migration
  // runs, and the identity bootstrap still derives the password's scrypt record.
  const began = Date.now();
  while (!fs.existsSync(path.join(directory, 'control.sqlite')) && Date.now() - began < 30000)
    await new Promise(resolve => setTimeout(resolve, 2));
  child.kill('SIGTERM');
  const result = await exited;
  assert.equal(result.code, 0, result.stdout + result.stderr);
  assert.match(result.stdout, /Uptime Goblin stopped while it was starting\./);
  assert.doesNotMatch(result.stdout, /Uptime Goblin is ready/);
  assert.doesNotMatch(result.stderr, /stopped although no stop signal/);
  assert.ok(lockIsFree(directory));
  assert.deepEqual(
    fs.readdirSync(path.join(directory, 'snapshots')).filter(name => name.startsWith('.staging-')),
    []
  );
  assert.equal(fs.existsSync(path.join(directory, 'run', 'status.json')), false);
  // The next start reuses the pinned snapshot the stopped one took.
  const app = await start(directory);
  await app.close();
  assert.equal(listSnapshots(directory).filter(item => item.pinned).length, 1);
});

// B48 (the maintainer's decision of 2026-10-11): under a service manager (--supervised, or
// GOBLIN_SUPERVISED=1) Uptime Goblin refuses to start, in server.mjs's main block before createApp(), unless
// its memory, CPU and process limits are in force in its own cgroup or GOBLIN_ALLOW_UNLIMITED names
// the ones that are not (lib/resource-limits.mjs). The server these tests spawn shares this
// process's cgroup, so what it decides is what superviseLimits() decides here: on a Mac (not
// Linux) none of the limits can be verified; under Linux it depends on the cgroup the tests run
// in. Before this change it only warned and started. A refused start here never creates its data
// directory, which the start sequence would; that is the order these tests check, not that the
// process read or wrote nothing before the check. (lib/resource-limits.mjs is imported in each
// test, so that on a tree without its new exports these tests fail one by one and the rest of
// this file still runs.)
const limitsModule = () => import('../lib/resource-limits.mjs');
const refused78 =
  'Uptime Goblin refused to start (exit status 78). Correct the problem above, then start Uptime Goblin again.';

// `spawned` (spawnServer's) once it exits, or killed after `ms`: a start that should have been
// refused but goes on serving fails its test instead of holding it.
async function exitedWithin(t, spawned, ms = 30000) {
  t.after(() => spawned.child.kill('SIGKILL'));
  const deadline = setTimeout(() => spawned.child.kill('SIGKILL'), ms);
  const result = await spawned.exited;
  clearTimeout(deadline);
  return result;
}

// Starts a supervised server that should start: resolves {port, stop()}, where stop() sends
// SIGTERM and resolves the exit (code 0 asserted). Fails when it exits or is not ready in 30 s.
async function startedServer(t, env, options = {}) {
  let port = null;
  const spawned = spawnServer(env, {
    ...options,
    onOutput: text =>
      (port ??= /Uptime Goblin is ready at http:\/\/127\.0\.0\.1:(\d+)/.exec(text)?.[1]),
  });
  t.after(() => spawned.child.kill('SIGKILL'));
  for (let i = 0; i < 600 && !port && spawned.child.exitCode === null; i++)
    await new Promise(resolve => setTimeout(resolve, 50));
  if (!port) {
    spawned.child.kill('SIGKILL');
    const result = await spawned.exited;
    assert.fail(`the server did not start: ${result.code} ${result.stdout}${result.stderr}`);
  }
  return {
    port,
    stop: async () => {
      spawned.child.kill('SIGTERM');
      const result = await spawned.exited;
      assert.equal(result.code, 0, result.stderr);
      return result;
    },
  };
}

test('a supervised start without its resource limits refuses (78) before createApp, so its data directory is never created, naming each and the two ways out; with them it starts', async t => {
  const { LIMIT_NAMES, superviseLimits } = await limitsModule();
  const expected = superviseLimits({ env: {}, supervised: true });
  // A data directory that does not exist yet: the start sequence would create it.
  const directory = path.join(temporary(t), 'data');
  if (!expected.refusal) {
    // This machine's cgroup holds all three limits (a limited container, say): the supervised
    // start goes on, says nothing of its limits, and /api/system shows them enforced. The refusal
    // is tested here wherever a limit is missing (on a Mac, every run), in
    // test/resource-limits.test.mjs over fake cgroup trees, and under real systemd
    // (test/installer/systemd.test.mjs).
    const legacy = legacyData(t);
    const server = await startedServer(
      t,
      { GOBLIN_DATA_DIR: legacy, GOBLIN_PASSWORD: password },
      { args: ['--supervised'] }
    );
    const basic = 'Basic ' + Buffer.from(`admin:${password}`).toString('base64');
    const system = await fetch(`http://127.0.0.1:${server.port}/api/system`, {
      headers: { Authorization: basic },
    });
    assert.equal(system.status, 200);
    const { resourceLimits } = await system.json();
    assert.equal(resourceLimits.supervised, true);
    for (const name of LIMIT_NAMES) assert.equal(resourceLimits.limits[name].state, 'enforced');
    const stopped = await server.stop();
    assert.doesNotMatch(stopped.stderr, /resource limits|runs without a|GOBLIN_ALLOW_UNLIMITED/);
    return;
  }
  const result = await spawnServer({
    GOBLIN_DATA_DIR: directory,
    GOBLIN_PASSWORD: password,
    GOBLIN_SUPERVISED: '1',
  }).exited;
  assert.equal(result.code, 78, result.stdout + result.stderr);
  assert.deepEqual(result.stderr.trimEnd().split('\n'), [...expected.refusal, refused78]);
  assert.match(
    expected.refusal[0],
    /^Uptime Goblin refused to start without its resource limits: /
  );
  assert.equal(result.stdout, '');
  assert.equal(fs.existsSync(directory), false, 'the start sequence never began');
  // GOBLIN_SUPERVISED=on supervises as 1 does.
  const on = await spawnServer({
    GOBLIN_DATA_DIR: directory,
    GOBLIN_PASSWORD: password,
    GOBLIN_SUPERVISED: 'on',
  }).exited;
  assert.equal(on.code, 78, on.stdout + on.stderr);
  // An override that leaves out one limit that is not in force still refuses, naming that one.
  const missing = LIMIT_NAMES.filter(name => expected.status.limits[name].state !== 'enforced');
  if (missing.length > 1) {
    const partly = await spawnServer({
      GOBLIN_DATA_DIR: directory,
      GOBLIN_PASSWORD: password,
      GOBLIN_SUPERVISED: '1',
      GOBLIN_ALLOW_UNLIMITED: missing.slice(1).join(','),
    }).exited;
    assert.equal(partly.code, 78, partly.stdout + partly.stderr);
    assert.deepEqual(partly.stderr.trimEnd().split('\n'), [
      ...superviseLimits({
        env: { GOBLIN_ALLOW_UNLIMITED: missing.slice(1).join(',') },
        supervised: true,
      }).refusal,
      refused78,
    ]);
  }
  assert.equal(fs.existsSync(directory), false);
  // Not supervised (npm start, node server.mjs): no check, as before; it starts.
  let port = null;
  const plain = spawnServer(
    { GOBLIN_DATA_DIR: directory, GOBLIN_PASSWORD: password },
    {
      onOutput: text =>
        (port ??= /Uptime Goblin is ready at http:\/\/127\.0\.0\.1:(\d+)/.exec(text)?.[1]),
    }
  );
  t.after(() => plain.child.kill('SIGKILL'));
  for (let i = 0; i < 600 && !port && plain.child.exitCode === null; i++)
    await new Promise(resolve => setTimeout(resolve, 50));
  assert.ok(port, 'the unsupervised start started');
  plain.child.kill('SIGTERM');
  const stopped = await plain.exited;
  assert.equal(stopped.code, 0, stopped.stderr);
  assert.doesNotMatch(stopped.stderr, /resource limits|GOBLIN_ALLOW_UNLIMITED/);
});

test('with GOBLIN_ALLOW_UNLIMITED naming the limits not in force, a supervised start goes on, says so, and /api/system shows it read-only', async t => {
  const { superviseLimits } = await limitsModule();
  const here = supervisedEnv().GOBLIN_ALLOW_UNLIMITED;
  // Where every limit is in force, a needless name: the start goes on and says to remove it.
  const allow = here || 'memory';
  const expected = superviseLimits({ env: { GOBLIN_ALLOW_UNLIMITED: allow }, supervised: true });
  assert.equal(expected.refusal, null);
  assert.ok(expected.warnings.length >= 1);
  const directory = legacyData(t);
  let port = null;
  const { child, exited } = spawnServer(
    {
      GOBLIN_DATA_DIR: directory,
      GOBLIN_PASSWORD: password,
      GOBLIN_SUPERVISED: '1',
      GOBLIN_ALLOW_UNLIMITED: allow,
    },
    {
      onOutput: text =>
        (port ??= /Uptime Goblin is ready at http:\/\/127\.0\.0\.1:(\d+)/.exec(text)?.[1]),
    }
  );
  t.after(() => child.kill('SIGKILL'));
  for (let i = 0; i < 600 && !port && child.exitCode === null; i++)
    await new Promise(resolve => setTimeout(resolve, 50));
  assert.ok(port, 'the server started');
  // Legacy Basic is on for 1.4.x data, so a script reads /api/system with the password.
  const basic = 'Basic ' + Buffer.from(`admin:${password}`).toString('base64');
  const system = await fetch(`http://127.0.0.1:${port}/api/system`, {
    headers: { Authorization: basic },
  });
  assert.equal(system.status, 200);
  assert.deepEqual(
    (await system.json()).resourceLimits,
    JSON.parse(JSON.stringify(expected.status))
  );
  // No route sets it: /api/system takes no write, and the setting stays what the environment said.
  for (const method of ['PUT', 'POST', 'PATCH', 'DELETE']) {
    const write = await fetch(`http://127.0.0.1:${port}/api/system`, {
      method,
      headers: {
        Authorization: basic,
        'Content-Type': 'application/json',
        'X-Goblin-Request': '1',
      },
      body:
        method === 'DELETE' ? undefined : JSON.stringify({ resourceLimits: { supervised: false } }),
    });
    assert.ok([404, 405].includes(write.status), `${method} /api/system: ${write.status}`);
  }
  const again = await fetch(`http://127.0.0.1:${port}/api/system`, {
    headers: { Authorization: basic },
  });
  assert.deepEqual(
    (await again.json()).resourceLimits,
    JSON.parse(JSON.stringify(expected.status))
  );
  child.kill('SIGTERM');
  const result = await exited;
  assert.equal(result.code, 0, result.stderr);
  // Each line, at the start, on standard error, not with Uptime Goblin's start line.
  const lines = result.stderr.split('\n');
  for (const warning of expected.warnings) assert.ok(lines.includes(warning), warning);
  assert.ok(
    result.stdout.indexOf('Uptime Goblin is ready') > -1 &&
      expected.warnings.every(warning => !result.stdout.includes(warning))
  );
});

test('a malformed GOBLIN_ALLOW_UNLIMITED refuses the start (78), supervised or not, shown escaped', async t => {
  const directory = path.join(temporary(t), 'data');
  for (const supervised of [{ GOBLIN_SUPERVISED: '1' }, {}]) {
    const { child, exited } = spawnServer({
      GOBLIN_DATA_DIR: directory,
      GOBLIN_PASSWORD: password,
      GOBLIN_ALLOW_UNLIMITED: 'cpu,\u001b[2Jall',
      ...supervised,
    });
    // A start that takes the value goes on serving: stopped after 30 s, it fails below.
    t.after(() => child.kill('SIGKILL'));
    const deadline = setTimeout(() => child.kill('SIGKILL'), 30000);
    const result = await exited;
    clearTimeout(deadline);
    assert.equal(result.code, 78, result.stdout + result.stderr);
    assert.deepEqual(result.stderr.trimEnd().split('\n'), [
      'GOBLIN_ALLOW_UNLIMITED must list the limits Uptime Goblin may run without, from memory, cpu and pids, separated by commas, each at most once and without spaces (such as cpu, or memory,cpu); it is "cpu,\\u001b[2Jall", which holds a character that is neither a lowercase letter nor a comma.',
      refused78,
    ]);
    assert.equal(fs.existsSync(directory), false);
  }
});

// The systemd unit's Environment=GOBLIN_SUPERVISED=1 is overridden by /etc/uptime-goblin.env, and the
// image's ENV by docker run -e or a Compose override, so GOBLIN_SUPERVISED=0 there, an empty value
// or a typo would turn the limits check off without naming a limit. The unit and the image start
// Uptime Goblin with --supervised, which no environment changes; GOBLIN_SUPERVISED cannot turn it off,
// and a value that is neither yes nor no refuses the start.
test('--supervised keeps a start supervised whatever GOBLIN_SUPERVISED says, and says so when it ignores an off value', async t => {
  const { superviseLimits, supervision } = await limitsModule();
  const expected = superviseLimits({ env: {}, supervised: true });
  const directory = path.join(temporary(t), 'data');
  const values = expected.refusal ? ['0', 'off', 'FALSE', 'No', '', undefined] : ['0', ''];
  for (const value of values) {
    const setting = value === undefined ? {} : { GOBLIN_SUPERVISED: value };
    const { supervised, warnings } = supervision({ argv: ['--supervised'], env: setting });
    assert.equal(supervised, true);
    assert.equal(warnings.length, value && value !== '' ? 1 : 0, String(value));
    if (warnings.length)
      assert.match(
        warnings[0],
        new RegExp(
          `^GOBLIN_SUPERVISED=${JSON.stringify(value)} is ignored: Uptime Goblin was started with --supervised, as the systemd unit and the Docker image start it, which this setting cannot turn off\\.`
        )
      );
    if (expected.refusal) {
      const result = await exitedWithin(
        t,
        spawnServer(
          { GOBLIN_DATA_DIR: directory, GOBLIN_PASSWORD: password, ...setting },
          { args: ['--supervised'] }
        ),
        10000
      );
      assert.equal(result.code, 78, `${value}: ${result.stdout}${result.stderr}`);
      assert.deepEqual(result.stderr.trimEnd().split('\n'), [
        ...warnings,
        ...expected.refusal,
        refused78,
      ]);
      assert.equal(result.stdout, '');
      assert.equal(fs.existsSync(directory), false, 'the start sequence never began');
    } else {
      const server = await startedServer(
        t,
        { GOBLIN_DATA_DIR: legacyData(t), GOBLIN_PASSWORD: password, ...setting },
        { args: ['--supervised'] }
      );
      const basic = 'Basic ' + Buffer.from(`admin:${password}`).toString('base64');
      const system = await fetch(`http://127.0.0.1:${server.port}/api/system`, {
        headers: { Authorization: basic },
      });
      assert.equal((await system.json()).resourceLimits.supervised, true);
      const stopped = await server.stop();
      for (const warning of warnings) assert.ok(stopped.stderr.split('\n').includes(warning));
    }
  }
  // Without --supervised, GOBLIN_SUPERVISED decides, as before: 0 is not supervised.
  assert.deepEqual(supervision({ argv: [], env: { GOBLIN_SUPERVISED: '0' } }), {
    supervised: false,
    warnings: [],
  });
  assert.deepEqual(supervision({ argv: [], env: { GOBLIN_SUPERVISED: 'on' } }), {
    supervised: true,
    warnings: [],
  });
});

test('a GOBLIN_SUPERVISED that is neither yes nor no refuses the start (78), with --supervised or without, shown escaped', async t => {
  const { supervisedSetting } = await limitsModule();
  const directory = path.join(temporary(t), 'data');
  for (const value of [
    'bogus',
    'enabled',
    ' 1',
    '1 ',
    '2',
    'yes\nGOBLIN_FAKE=1',
    '\u001b[2Jon',
    '\uff4f\uff4e', // fullwidth "on"
    'o\u200bn',
  ]) {
    let message;
    assert.throws(
      () => supervisedSetting(value),
      error => error.refusal === true && Boolean((message = error.message))
    );
    assert.equal(
      message,
      `GOBLIN_SUPERVISED must be 1 or 0 (true, yes or on; false, no or off), or empty; it is ${quoted(value)}.`
    );
    assert.doesNotMatch(message, /[\u0000-\u001f]/, 'no control character reaches the log');
    for (const args of [[], ['--supervised']]) {
      const result = await exitedWithin(
        t,
        spawnServer(
          { GOBLIN_DATA_DIR: directory, GOBLIN_PASSWORD: password, GOBLIN_SUPERVISED: value },
          { args }
        ),
        10000
      );
      assert.equal(
        result.code,
        78,
        `${JSON.stringify(value)} ${args}: ${result.stdout}${result.stderr}`
      );
      assert.deepEqual(result.stderr.trimEnd().split('\n'), [message, refused78]);
      assert.equal(fs.existsSync(directory), false, 'the start sequence never began');
    }
  }
});

// Legacy Basic is on by default for installs upgraded from 1.4.x, so a value of
// GOBLIN_LEGACY_BASIC that is neither yes nor no (a typo meant as off) refuses the start instead
// of leaving that default on (the maintainer's decision, 2026-11-12), before anything is written.
test('a GOBLIN_LEGACY_BASIC that is neither yes nor no refuses the start (78), naming the accepted values, before anything is written', async t => {
  const { legacyBasicSetting } = await import('../lib/environment.mjs');
  for (const [text, value] of [
    ['1', true],
    ['On', true],
    ['no', false],
    ['0', false],
    ['', null],
    [undefined, null],
  ])
    assert.equal(legacyBasicSetting(text), value, String(text));
  const directory = path.join(temporary(t), 'data');
  for (const value of ['maybe', 'of', 'disabled', ' 0', '2', 'no\nGOBLIN_FAKE=1', '\u001b[2Joff']) {
    const message = `GOBLIN_LEGACY_BASIC must be 1 or 0 (true, yes or on; false, no or off), or empty for the default; it is ${quoted(value)}.`;
    assert.throws(
      () => legacyBasicSetting(value),
      error => error.refusal === true && error.message === message
    );
    assert.doesNotMatch(message, /[\u0000-\u001f]/, 'no control character reaches the log');
    const result = await exitedWithin(
      t,
      spawnServer({
        GOBLIN_DATA_DIR: directory,
        GOBLIN_PASSWORD: password,
        GOBLIN_LEGACY_BASIC: value,
      }),
      10000
    );
    assert.equal(result.code, 78, `${JSON.stringify(value)}: ${result.stdout}${result.stderr}`);
    assert.deepEqual(result.stderr.trimEnd().split('\n'), [message, refused78]);
    assert.doesNotMatch(result.stderr, /the default applies/);
    assert.equal(fs.existsSync(directory), false, 'nothing was written');
  }
  // createApp refuses it the same way when it is called directly, also with `legacyBasic`
  // given, and the control database's features refuse it too (the backstop).
  const saved = process.env.GOBLIN_LEGACY_BASIC;
  t.after(() =>
    saved === undefined
      ? delete process.env.GOBLIN_LEGACY_BASIC
      : (process.env.GOBLIN_LEGACY_BASIC = saved)
  );
  process.env.GOBLIN_LEGACY_BASIC = 'maybe';
  for (const legacyBasic of [undefined, true])
    await assert.rejects(
      createApp({ directory, password, port: 0, startScheduler: false, legacyBasic }),
      error => error.refusal === true && /^GOBLIN_LEGACY_BASIC must be 1 or 0/.test(error.message)
    );
  assert.equal(fs.existsSync(directory), false, 'nothing was written');
  const { createFeatures } = await import('../lib/features.mjs');
  assert.throws(
    () => createFeatures({ env: { GOBLIN_LEGACY_BASIC: 'maybe' }, release: '1.5.0' }),
    error => error.refusal === true && /^GOBLIN_LEGACY_BASIC must be 1 or 0/.test(error.message)
  );
});

test('server.mjs refuses (78) any argument but one --supervised, shown escaped, before createApp', async t => {
  const { supervision } = await limitsModule();
  const directory = path.join(temporary(t), 'data');
  for (const args of [
    ['--supervise'],
    ['--supervised=1'],
    ['--Supervised'],
    ['--supervised', '--supervised'],
    ['--supervised', 'x'],
    ['-s'],
    [''],
    ['\u001b[2J--supervised\nGOBLIN_FAKE'],
    ['a', 'b', 'c', 'd', 'e', 'f'],
  ]) {
    let message;
    assert.throws(
      () => supervision({ argv: args, env: {} }),
      error => error.refusal === true && Boolean((message = error.message))
    );
    assert.match(
      message,
      /^server\.mjs takes no argument but --supervised, which the systemd unit and the Docker image give it; it was given ".*"(, ".*")*( and \d+ more)?\.$/
    );
    assert.doesNotMatch(message, /[\u0000-\u001f]/);
    const result = await exitedWithin(
      t,
      spawnServer(
        { GOBLIN_DATA_DIR: directory, GOBLIN_PASSWORD: password, GOBLIN_SUPERVISED: '1' },
        { args }
      ),
      10000
    );
    assert.equal(result.code, 78, `${JSON.stringify(args)}: ${result.stdout}${result.stderr}`);
    assert.deepEqual(result.stderr.trimEnd().split('\n'), [message, refused78]);
    assert.equal(fs.existsSync(directory), false, 'the start sequence never began');
  }
  assert.match(
    (() => {
      try {
        supervision({ argv: ['a', 'b', 'c', 'd', 'e', 'f'], env: {} });
      } catch (e) {
        return e.message;
      }
    })(),
    /it was given "a", "b", "c", "d" and 2 more\.$/
  );
});

// goblin-admin reads both keys from its own environment, never from /etc/uptime-goblin.env: the command
// line the rewrap warning prints names the file this start read and the old key's file.
test('the warning for data keys only the previous key opens prints a rotate line with both key files', () => {
  const warning = (key, directory = '/var/lib/uptime-goblin') =>
    keyLines(
      { fingerprint: '0123456789abcdef', warnings: [], needsRewrap: true, ...key },
      directory
    ).warnings.find(line => line.startsWith('Some data keys open only'));
  assert.equal(
    warning({ source: 'file', file: '/srv/orbit/key' }),
    'Some data keys open only with GOBLIN_SECRET_KEY_PREVIOUS; run, with Uptime Goblin stopped: sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=/srv/orbit/key GOBLIN_SECRET_KEY_PREVIOUS_FILE=OLD_KEY_FILE node /opt/uptime-goblin/lib/cli/goblin-admin.mjs key rotate --data-dir /var/lib/uptime-goblin (the native install; Docker Compose and other installs: docs/installation.md#goblin-admin).'
  );
  // Another source: the installer's key file, as the docs give it.
  assert.match(
    warning({
      source: 'credentials',
      file: '/run/credentials/uptime-goblin.service/orbit-secret-key',
    }),
    /: sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=\/etc\/uptime-goblin\/secret\.key GOBLIN_SECRET_KEY_PREVIOUS_FILE=OLD_KEY_FILE node /
  );
  // Started with GOBLIN_SECRET_KEY_PREVIOUS_FILE: that file, not the placeholder (docs audit,
  // keys 19).
  assert.equal(
    warning({ source: 'file', file: '/srv/orbit/key', previousFile: '/srv/orbit/old.key' }),
    'Some data keys open only with GOBLIN_SECRET_KEY_PREVIOUS; run, with Uptime Goblin stopped: sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=/srv/orbit/key GOBLIN_SECRET_KEY_PREVIOUS_FILE=/srv/orbit/old.key node /opt/uptime-goblin/lib/cli/goblin-admin.mjs key rotate --data-dir /var/lib/uptime-goblin (the native install; Docker Compose and other installs: docs/installation.md#goblin-admin).'
  );
});

test('startupExitCode: 75 for a held lock, 78 for refusals, 1 for everything else', () => {
  assert.equal(startupExitCode(new LockHeldError('/x/goblin.lock')), 75);
  assert.equal(startupExitCode(Object.assign(new Error('x'), { refusal: true })), 78);
  assert.equal(startupExitCode(new SyntaxError('x')), 78);
  assert.equal(startupExitCode(Object.assign(new Error('x'), { code: 'EIO' })), 1);
  assert.equal(startupExitCode(undefined), 1);
});

// ---------------------------------------------------------------------------------------------
// The audit at start (audit spec §5.6, §9.1 H).

const auditActions = directory => {
  const db = new DatabaseSync(path.join(directory, 'control.sqlite'), { readOnly: true });
  try {
    return db
      .prepare('SELECT action, detail FROM audit_log ORDER BY seq')
      .all()
      .map(row => ({ action: row.action, detail: row.detail && JSON.parse(row.detail) }));
  } finally {
    db.close();
  }
};
const inboxSequence = directory => {
  const db = new DatabaseSync(path.join(directory, 'control.sqlite'), { readOnly: true });
  try {
    return db.prepare("SELECT seq FROM sqlite_sequence WHERE name = 'audit_inbox'").get()?.seq ?? 0;
  } finally {
    db.close();
  }
};
// The audit's own write units fail as a full disk makes them fail (reads pass).
const failingAuditWrites = () => (db, purpose) =>
  purpose === 'read'
    ? db
    : new Proxy(db, {
        get(target, property) {
          const value = target[property];
          if (property === 'write')
            return () =>
              Promise.reject(
                Object.assign(new Error('database or disk is full'), {
                  code: 'SQLITE_FULL',
                  class: 'full',
                })
              );
          return typeof value === 'function' ? value.bind(target) : value;
        },
      });

test('start never fails on the audit: with every audit write failing Uptime Goblin starts and answers, its rows go to stderr, and the next start writes them', async t => {
  const errors = [];
  t.mock.method(console, 'error', (...args) => errors.push(args.join(' ')));
  for (const level of ['log', 'warn', 'info']) t.mock.method(console, level, () => {});
  const unwritten = () =>
    errors
      .filter(line => line.startsWith('{"orbit":"audit.unwritten"'))
      .map(line => JSON.parse(line).row?.action);
  // A new directory: nothing can be written; Uptime Goblin starts and answers all the same.
  const fresh = temporary(t);
  const first = await serve(t, fresh, { audit: { wrapDb: failingAuditWrites() } });
  assert.equal((await fetch(`${first.url}/api/version`)).status, 401, 'it answers');
  await first.app.close();
  assert.deepEqual(auditActions(fresh), []);
  assert.ok(unwritten().includes('system.start'), JSON.stringify(unwritten()));
  // Writes work again: the next start writes what could not be (the bootstrap row waited in the
  // inbox, the upgrade marker never moved).
  await (await serve(t, fresh)).app.close();
  const recovered = auditActions(fresh).map(row => row.action);
  for (const action of ['account.bootstrap', 'system.upgrade', 'system.start'])
    assert.ok(recovered.includes(action), `${action}: ${JSON.stringify(recovered)}`);

  // An existing install changed while stopped: the drift row goes to stderr, and is written by
  // the next start that can.
  const file = path.join(fresh, 'config.json');
  const config = JSON.parse(fs.readFileSync(file, 'utf8'));
  config.title = 'Edited while stopped';
  fs.writeFileSync(file, JSON.stringify(config, null, 2));
  const before = auditActions(fresh).length;
  const failing = await serve(t, fresh, { audit: { wrapDb: failingAuditWrites() } });
  assert.equal((await fetch(`${failing.url}/api/version`)).status, 401, 'it answers');
  await failing.app.close();
  assert.equal(auditActions(fresh).length, before, 'nothing written');
  assert.ok(unwritten().includes('config.changed-outside'), JSON.stringify(unwritten()));
  await (await serve(t, fresh)).app.close();
  const outside = auditActions(fresh).filter(row => row.action === 'config.changed-outside');
  assert.equal(outside.length, 1);
  assert.ok(outside[0].detail.diff.some(change => change.path === 'title'));
});

test("on an existing install the audit attaches before identity: its rows are chained in identity's unit, never through the inbox", async t => {
  for (const level of ['log', 'warn', 'info', 'error']) t.mock.method(console, level, () => {});
  const directory = temporary(t);
  await (await start(directory, { password: 'first-password-0001' })).close();
  // The first start's bootstrap row went through the inbox (no keyring existed yet).
  const first = inboxSequence(directory);
  assert.ok(first >= 1);
  // A new GOBLIN_PASSWORD is imported at the next start: identity's row, in its own unit.
  await (await start(directory, { password: 'second-password-0002' })).close();
  assert.equal(inboxSequence(directory), first, 'no row went through the inbox');
  const imported = auditActions(directory).find(
    row => row.action === 'account.password.changed-outside'
  );
  assert.equal(imported?.detail.source, 'env');
});

test('a start that fails after the audit began closes it first: a row being written is written before control.sqlite closes', async t => {
  const errors = [];
  t.mock.method(console, 'error', (...args) => errors.push(args.join(' ')));
  for (const level of ['log', 'warn', 'info']) t.mock.method(console, level, () => {});
  const directory = temporary(t);
  // The delivery service's new signing key is recorded as a system row (§5.3). Its write
  // is held, and the start is stopped meanwhile (as a stop signal during the start does).
  const stop = new AbortController();
  let release;
  const held = new Promise(resolve => (release = resolve));
  const wrapDb = (db, purpose) =>
    purpose !== 'system'
      ? db
      : new Proxy(db, {
          get(target, property) {
            const value = target[property];
            if (property === 'write')
              return async (...args) => {
                stop.abort(new Error('stopped while starting'));
                setTimeout(release, 200);
                await held;
                return value.apply(target, args);
              };
            return typeof value === 'function' ? value.bind(target) : value;
          },
        });
  await assert.rejects(
    start(directory, {
      webhook: 'http://127.0.0.1:9/hook',
      signal: stop.signal,
      audit: { wrapDb },
    }),
    /stopped while starting/
  );
  assert.ok(lockIsFree(directory), 'everything released');
  // Written before the database closed, not lost to a closed database.
  assert.ok(
    auditActions(directory).some(row => row.action === 'signing.created'),
    JSON.stringify(auditActions(directory))
  );
  assert.deepEqual(
    errors.filter(line => line.startsWith('{"orbit":"audit.unwritten"')),
    [],
    'nothing went to stderr'
  );
});

// ---------------------------------------------------------------------------------------------
// Startup files that are not what Uptime Goblin keeps there

test('node server.mjs refuses (78) at once, writing nothing but goblin.lock, when history.sqlite, control.sqlite or goblin.lock is a FIFO or a directory, or snapshots/ is a file', async t => {
  const fifo = file => assert.equal(spawnSync('mkfifo', [file]).status, 0);
  for (const [what, make, expected] of [
    [
      'a FIFO history.sqlite',
      data => fifo(path.join(data, 'history.sqlite')),
      /history\.sqlite is not a regular file/,
    ],
    [
      'a history.sqlite directory',
      data => fs.mkdirSync(path.join(data, 'history.sqlite')),
      /history\.sqlite is not a regular file/,
    ],
    // A read-only open of it waited for a writer for good, holding goblin.lock.
    [
      'a FIFO control.sqlite',
      data => fifo(path.join(data, 'control.sqlite')),
      /control\.sqlite is not a regular file/,
    ],
    [
      'a FIFO goblin.lock',
      data => fifo(path.join(data, 'goblin.lock')),
      /goblin\.lock is not a regular file\. Remove it/,
    ],
    [
      'a goblin.lock directory',
      data => fs.mkdirSync(path.join(data, 'goblin.lock')),
      /goblin\.lock is not a regular file\. Remove it/,
    ],
    [
      'a file at snapshots/',
      data => fs.writeFileSync(path.join(data, 'snapshots'), 'x'),
      /snapshots is not a directory/,
    ],
  ]) {
    const directory = temporary(t);
    make(directory);
    const before = fs.readdirSync(directory).sort();
    const { child, exited } = spawnServer({
      GOBLIN_DATA_DIR: directory,
      GOBLIN_PASSWORD: password,
    });
    const deadline = setTimeout(() => child.kill('SIGKILL'), 15000);
    const result = await exited;
    clearTimeout(deadline);
    assert.equal(result.code, 78, `${what}: ${result.stdout}${result.stderr}`);
    assert.match(result.stderr, expected, what);
    assert.match(result.stderr, /Uptime Goblin refused to start \(exit status 78\)/, what);
    // Nothing was created but goblin.lock (and only where it was missing): no control.sqlite,
    // no generated key, no snapshot.
    assert.deepEqual(
      fs
        .readdirSync(directory)
        .filter(name => name !== 'goblin.lock' && name !== 'orbit.lock')
        .sort(),
      before.filter(name => name !== 'goblin.lock' && name !== 'orbit.lock'),
      what
    );
  }
});

test('node server.mjs refuses (78) at once, writing nothing but goblin.lock, for a FIFO beside a database or a link to nothing or a loop in place of one, goblin.lock or snapshots/', async t => {
  const fifo = file => assert.equal(spawnSync('mkfifo', [file]).status, 0);
  // [what, start once first (so that the databases exist), make it, the refusal]
  const cases = [
    ...['control.sqlite', 'history.sqlite'].flatMap(name =>
      [false, true].map(first => [
        `a FIFO ${name}-journal${first ? ' after a start' : ''}`,
        first,
        data => fifo(path.join(data, `${name}-journal`)),
        new RegExp(`${name.replace('.', '\\.')}-journal is not a regular file`),
      ])
    ),
    [
      'a FIFO control.sqlite-wal after a start',
      true,
      data => fifo(path.join(data, 'control.sqlite-wal')),
      /control\.sqlite-wal is not a regular file/,
    ],
    [
      'a FIFO goblin.lock-journal',
      false,
      data => fifo(path.join(data, 'goblin.lock-journal')),
      /goblin\.lock-journal is not a regular file\. Remove it with Uptime Goblin stopped, then/,
    ],
    // A link to an unmounted volume whose mount point exists: a new control database was
    // created through it, and the start went on with empty data.
    ...['control.sqlite', 'history.sqlite'].map(name => [
      `a ${name} link to nothing, after a start`,
      true,
      (data, elsewhere) => {
        fs.rmSync(path.join(data, name));
        fs.symlinkSync(path.join(elsewhere, name), path.join(data, name));
      },
      new RegExp(`${name.replace('.', '\\.')} is a symbolic link to nothing that exists`),
    ]),
    [
      'a control.sqlite loop',
      false,
      data => fs.symlinkSync('control.sqlite', path.join(data, 'control.sqlite')),
      /control\.sqlite is not a regular file/,
    ],
    [
      'a goblin.lock link to nothing',
      false,
      (data, elsewhere) =>
        fs.symlinkSync(path.join(elsewhere, 'goblin.lock'), path.join(data, 'goblin.lock')),
      /The data-directory lock .*goblin\.lock is a symbolic link to nothing that exists\. Remove it/,
    ],
    [
      'a snapshots/ link to nothing',
      false,
      (data, elsewhere) =>
        fs.symlinkSync(path.join(elsewhere, 'snapshots'), path.join(data, 'snapshots')),
      /snapshots is a symbolic link to no directory/,
    ],
    [
      'a snapshots/ loop',
      false,
      data => fs.symlinkSync('snapshots', path.join(data, 'snapshots')),
      /snapshots is a symbolic link to no directory/,
    ],
  ];
  // fingerprint() with what is not a regular file named by its kind, never opened.
  const entries = (directory, relative = '', out = {}) => {
    for (const entry of fs.readdirSync(path.join(directory, relative), { withFileTypes: true })) {
      const item = path.join(relative, entry.name),
        full = path.join(directory, item);
      if (entry.isDirectory()) entries(directory, item, out);
      else if (entry.isSymbolicLink()) out[item] = `link to ${fs.readlinkSync(full)}`;
      else if (entry.isFIFO()) out[item] = 'FIFO';
      else out[item] = fs.readFileSync(full).toString('hex');
    }
    return out;
  };
  for (const [what, first, make, expected] of cases) {
    const directory = temporary(t),
      elsewhere = temporary(t);
    if (first) await (await start(directory)).close();
    make(directory, elsewhere);
    const before = entries(directory);
    const { child, exited } = spawnServer({
      GOBLIN_DATA_DIR: directory,
      GOBLIN_PASSWORD: password,
    });
    const deadline = setTimeout(() => child.kill('SIGKILL'), 15000);
    const result = await exited;
    clearTimeout(deadline);
    assert.equal(result.code, 78, `${what}: ${result.stdout}${result.stderr}`);
    assert.match(result.stderr, expected, what);
    assert.match(result.stderr, /Uptime Goblin refused to start \(exit status 78\)/, what);
    // Nothing written: no database, key or snapshot created or changed (goblin.lock aside, which
    // a start creates where it is missing), and nothing created where a link points.
    const after = entries(directory);
    delete before['goblin.lock'];
    delete before['orbit.lock'];
    delete after['goblin.lock'];
    delete after['orbit.lock'];
    assert.deepEqual(after, before, what);
    assert.deepEqual(fs.readdirSync(elsewhere), [], what);
  }
});

test('a start that fails on a damaged database logs SQLite’s reason on one line, without control characters', async t => {
  // SQLite's "malformed database schema (<name>)" quotes a name from control.sqlite itself. The
  // main block printed it as it was: an escape sequence and a forged "[orbit] …" line in the
  // service log, repeated at every retry of the start.
  const directory = temporary(t);
  await (await start(directory)).close();
  const db = new DatabaseSync(path.join(directory, 'control.sqlite'), { defensive: false });
  db.exec('PRAGMA writable_schema=ON');
  db.prepare("INSERT INTO sqlite_master VALUES ('table', ?, 'x', 0, 'CREATE TABLE broken(')").run(
    'x\u001b[2J\n[orbit] FORGED-SCHEMA-LINE'
  );
  db.close();
  const result = await refusedStart(t, directory);
  assert.equal(result.code, 1, result.stderr);
  assert.ok(
    !/[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/.test(result.stderr),
    JSON.stringify(result.stderr)
  );
  assert.equal(
    result.stderr,
    'malformed database schema (x[2J[orbit] FORGED-SCHEMA-LINE)\nUptime Goblin could not start (exit status 1); it will be started again.\n'
  );
});

test('a relative GOBLIN_DATA_DIR, file:X included, is used as the absolute directory it names', async t => {
  // node:sqlite reads a relative 'file:X/…' as a URI naming X/…: every file Uptime Goblin makes must be
  // under the literal file:X, and the paths it prints are absolute, so a printed command line
  // works wherever it is pasted.
  const base = temporary(t);
  const child = spawn(process.execPath, [serverFile], {
    cwd: base,
    env: {
      PATH: process.env.PATH,
      HOST: '127.0.0.1',
      PORT: freePortSync(),
      GOBLIN_DATA_DIR: 'file:X',
      GOBLIN_PASSWORD: password,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  t.after(() => child.kill('SIGKILL'));
  let output = '';
  const ready = await new Promise(resolve => {
    const timer = setTimeout(() => resolve(false), 15000);
    const read = chunk => {
      output += chunk;
      if (/Uptime Goblin is ready/.test(output)) {
        clearTimeout(timer);
        resolve(true);
      }
    };
    child.stdout.on('data', read);
    child.stderr.on('data', read);
    child.on('exit', () => resolve(false));
  });
  assert.ok(ready, output);
  const stopped = new Promise(resolve => child.once('exit', code => resolve(code)));
  child.kill('SIGTERM');
  assert.equal(await stopped, 0);
  const literal = path.join(base, 'file:X');
  assert.ok(output.includes(`Encryption key: a new ${literal}/secret.key`), output);
  assert.equal(fs.existsSync(path.join(base, 'X')), false, 'nothing under X/');
  for (const name of ['config.json', 'control.sqlite', 'history.sqlite', 'secret.key'])
    assert.ok(fs.statSync(path.join(literal, name)).isFile(), name);
});

test('a trigger or view planted in control.sqlite or history.sqlite refuses the start (78) having written nothing but goblin.lock', async t => {
  for (const [file, statement] of [
    [
      'control.sqlite',
      "CREATE TRIGGER synthetic_keep AFTER UPDATE ON meta BEGIN UPDATE meta SET value = '1' WHERE key = 'session_seq'; END",
    ],
    ['history.sqlite', 'CREATE VIEW "synthetic\u001b[2Jview" AS SELECT 1'],
  ]) {
    const directory = temporary(t);
    await (await start(directory)).close();
    // Uptime Goblin creates neither: a trigger runs inside Uptime Goblin's own writes (this one undid every
    // session revocation), and the start went on.
    const db = new DatabaseSync(path.join(directory, file));
    db.exec(statement);
    db.close();
    const before = fingerprint(directory, ['goblin.lock', 'orbit.lock']);
    await assert.rejects(
      start(directory),
      error =>
        error.code === 'schema_planted' &&
        startupExitCode(error) === 78 &&
        error.message.startsWith(`${file} holds `) &&
        !/[\u0000-\u001f]/.test(error.message),
      file
    );
    assert.deepEqual(
      fingerprint(directory, ['goblin.lock', 'orbit.lock']),
      before,
      `${file}: nothing but goblin.lock written`
    );
  }
});

test('a trigger whose catalog row spells its type another way refuses the start (78) too', async t => {
  // SQLite compares a catalog row's type without regard to case and only up to a NUL, so these
  // triggers run inside Uptime Goblin's writes (the first undid every session revocation), and the
  // start, which matched type = 'trigger', went on.
  for (const [file, statement, name, type] of [
    [
      'control.sqlite',
      "CREATE TRIGGER synthetic_keep AFTER UPDATE ON meta BEGIN UPDATE meta SET value = '1' WHERE key = 'session_seq'; END",
      'synthetic_keep',
      "'TRIGGER'",
    ],
    [
      'history.sqlite',
      'CREATE TRIGGER synthetic_wipe AFTER INSERT ON readings BEGIN DELETE FROM readings; END',
      'synthetic_wipe',
      "'trigger' || char(0)",
    ],
  ]) {
    const directory = temporary(t);
    await (await start(directory)).close();
    const db = new DatabaseSync(path.join(directory, file), { defensive: false });
    db.exec(statement);
    db.exec('PRAGMA writable_schema=ON');
    db.exec(`UPDATE sqlite_master SET type = ${type} WHERE name = '${name}'`);
    db.exec('PRAGMA writable_schema=OFF');
    db.close();
    const before = fingerprint(directory, ['goblin.lock', 'orbit.lock']);
    await assert.rejects(
      start(directory),
      error =>
        error.code === 'schema_planted' &&
        startupExitCode(error) === 78 &&
        error.message.startsWith(`${file} holds catalog entry ${name} of type "`) &&
        !/[\u0000-\u001f]/.test(error.message),
      file
    );
    assert.deepEqual(
      fingerprint(directory, ['goblin.lock', 'orbit.lock']),
      before,
      `${file}: nothing written`
    );
  }
});

test('a config.json symbolic link to a missing file refuses the start (78) and is left in place', async t => {
  const directory = temporary(t);
  const target = path.join(temporary(t), 'unmounted', 'config.json');
  const file = path.join(directory, 'config.json');
  fs.symlinkSync(target, file);
  for (const read of [() => checkConfigFile(directory), () => new ConfigStore(directory)])
    assert.throws(
      read,
      error =>
        error.refusal === true &&
        startupExitCode(error) === 78 &&
        /config\.json: it is a symbolic link to a file that does not exist/.test(error.message)
    );
  await assert.rejects(start(directory), error => startupExitCode(error) === 78);
  assert.equal(fs.readlinkSync(file), target, 'the link is kept, not replaced by default settings');
  assert.equal(fs.existsSync(target), false);
  // Such a directory holds older data: it is never taken for one this release created.
  fs.rmSync(path.join(directory, 'goblin.lock'), { force: true });
  const control = openControl(directory, { release });
  t.after(() => control.close());
  assert.equal(control.fresh, false);
});

test('a start tightens a config.json others can read to 0600 (never through a link) and warns about a data directory open to others', async t => {
  const directory = temporary(t);
  await (await start(directory)).close();
  const file = path.join(directory, 'config.json');
  fs.chmodSync(file, 0o644);
  fs.chmodSync(directory, 0o755);
  const warnings = [];
  t.mock.method(console, 'warn', (...args) => warnings.push(args.join(' ')));
  await (await start(directory)).close();
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.ok(
    warnings.includes(
      `The data directory ${directory} is open to other users of this host (mode 0755), so its files are protected only by their own modes. Make it private: chmod 700 ${directory}`
    ),
    warnings.join('\n')
  );
  // A private directory is not mentioned.
  fs.chmodSync(directory, 0o700);
  warnings.length = 0;
  await (await start(directory)).close();
  assert.ok(!warnings.some(line => line.includes('is open to other users')));
  // A config.json that is a symbolic link keeps its target's mode: the operator chose it.
  const target = path.join(temporary(t), 'config.json');
  fs.renameSync(file, target);
  fs.chmodSync(target, 0o644);
  fs.symlinkSync(target, file);
  new ConfigStore(directory);
  assert.equal(fs.statSync(target).mode & 0o777, 0o644);
});

test('a stop never waits on what replaced run/status.json, and the start never changes the mode of a linked run/', async t => {
  const directory = temporary(t);
  await (await start(directory)).close();
  // run/ linked to a directory Uptime Goblin did not make: its mode is the operator's.
  const elsewhere = path.join(temporary(t), 'run');
  fs.mkdirSync(elsewhere, { mode: 0o755 });
  fs.chmodSync(elsewhere, 0o755);
  fs.rmSync(path.join(directory, 'run'), { recursive: true, force: true });
  fs.symlinkSync(elsewhere, path.join(directory, 'run'));
  const { child, exited } = spawnServer(
    { GOBLIN_DATA_DIR: directory, GOBLIN_PASSWORD: password },
    {
      onOutput: stdout => {
        if (!stdout.includes('Uptime Goblin is ready') || child.replaced) return;
        child.replaced = true;
        // A FIFO in place of the record: reading it by its path waited for a writer for good,
        // so the stop never finished and the service manager had to kill Uptime Goblin.
        const record = path.join(elsewhere, 'status.json');
        fs.rmSync(record);
        assert.equal(spawnSync('mkfifo', [record]).status, 0);
        child.kill('SIGTERM');
      },
    }
  );
  const deadline = setTimeout(() => child.kill('SIGKILL'), 15000);
  const result = await exited;
  clearTimeout(deadline);
  assert.equal(child.replaced, true, result.stdout + result.stderr);
  assert.deepEqual([result.code, result.signal], [0, null], result.stdout + result.stderr);
  assert.ok(fs.statSync(path.join(elsewhere, 'status.json')).isFIFO(), 'left as it was');
  assert.equal(fs.statSync(elsewhere).mode & 0o777, 0o755);
});

test('a config.json that is a symbolic link loop is a refusal (78), not a start to retry', async t => {
  const directory = temporary(t);
  const file = path.join(directory, 'config.json');
  fs.symlinkSync(file, file);
  assert.throws(
    () => checkConfigFile(directory),
    error =>
      startupExitCode(error) === 78 && /config\.json: it must be a regular file/.test(error.message)
  );
});

// The maintainer's decision of 2026-11-12: the 1.5 upgrade never turns plain-HTTP sign-in on silently.
// compose.yaml passes GOBLIN_INSECURE_HTTP_SESSIONS=compose-default while .env does not set it:
// on a port it publishes beyond loopback with no trusted proxy that refuses the start (78)
// before anything is written, as the other environment refusals do; on loopback Uptime Goblin starts
// with plain-HTTP sign-in on, behind a trusted proxy with it off, and 1 or 0 decide as written.
test('compose-default on a port Compose publishes beyond loopback with no trusted proxy refuses the start (78) before anything is written; otherwise Uptime Goblin starts and the start line says what applies', async t => {
  const { insecureHttpSessionsSetting } = await import('../lib/environment.mjs');
  const directory = path.join(temporary(t), 'data');
  const compose = published => ({
    GOBLIN_DATA_DIR: directory,
    GOBLIN_PASSWORD: password,
    GOBLIN_INSECURE_HTTP_SESSIONS: 'compose-default',
    GOBLIN_PUBLISHED_ADDRESS: published,
  });
  for (const [published, trust] of [
    ['192.0.2.5', undefined],
    ['0.0.0.0', ''],
    ['[2001:db8::1]', 'off'],
    ['localhost', undefined],
    ['192.0.2.5\nGOBLIN_FAKE=1', undefined],
  ]) {
    const env = {
      ...compose(published),
      ...(trust === undefined ? {} : { GOBLIN_TRUST_PROXY: trust }),
    };
    const message = insecureHttpSessionsSetting(env).refusal;
    assert.ok(
      message.startsWith(`Docker Compose publishes Uptime Goblin on ${quoted(published, 64)} `)
    );
    assert.doesNotMatch(message, /[\u0000-\u001f]/, 'no control character reaches the log');
    const result = await exitedWithin(t, spawnServer(env));
    assert.equal(result.code, 78, `${JSON.stringify(published)}: ${result.stdout}${result.stderr}`);
    assert.deepEqual(result.stderr.trimEnd().split('\n'), [message, refused78]);
    assert.equal(fs.existsSync(directory), false, 'nothing was written');
  }
  // createApp refuses it the same way when it is called directly, also with
  // `insecureHttpSessions` given; the control database's features read it as off, never throw.
  const names = ['GOBLIN_INSECURE_HTTP_SESSIONS', 'GOBLIN_PUBLISHED_ADDRESS', 'GOBLIN_TRUST_PROXY'];
  const saved = Object.fromEntries(names.map(name => [name, process.env[name]]));
  t.after(() => {
    for (const name of names)
      if (saved[name] === undefined) delete process.env[name];
      else process.env[name] = saved[name];
  });
  process.env.GOBLIN_INSECURE_HTTP_SESSIONS = 'compose-default';
  process.env.GOBLIN_PUBLISHED_ADDRESS = '192.0.2.5';
  delete process.env.GOBLIN_TRUST_PROXY;
  for (const insecureHttpSessions of [undefined, true])
    await assert.rejects(
      createApp({ directory, password, port: 0, startScheduler: false, insecureHttpSessions }),
      error =>
        startupExitCode(error) === 78 &&
        /^Docker Compose publishes Uptime Goblin on "192\.0\.2\.5" \(GOBLIN_BIND_ADDRESS\)/.test(
          error.message
        )
    );
  assert.equal(fs.existsSync(directory), false, 'nothing was written');
  const { createFeatures } = await import('../lib/features.mjs');
  const features = createFeatures({
    env: {
      GOBLIN_INSECURE_HTTP_SESSIONS: 'compose-default',
      GOBLIN_PUBLISHED_ADDRESS: '192.0.2.5',
    },
    release: '1.5.0',
  });
  assert.equal(await features.enabled('insecureHttpSessions'), false);
  assert.deepEqual(features.warnings, []);
  for (const name of names) delete process.env[name];

  // Uptime Goblin starts where Compose's default decides, or a value decides as written.
  const startLine = async env => {
    const server = await startedServer(t, env);
    const { stdout, stderr } = await server.stop();
    return { line: stdout.split('\n').find(text => text.startsWith('Sign-in:')), stderr };
  };
  const loopback = await startLine(compose('127.0.0.1'));
  assert.match(loopback.line, / · plain-HTTP sessions: allowed$/);
  assert.doesNotMatch(loopback.stderr, /Plain-HTTP sign-in is allowed/);
  const proxied = await startLine({ ...compose('192.0.2.5'), GOBLIN_TRUST_PROXY: '192.0.2.1' });
  assert.match(proxied.line, / · plain-HTTP sessions: refused$/);
  const chosen = await startLine({ ...compose('192.0.2.5'), GOBLIN_INSECURE_HTTP_SESSIONS: '1' });
  assert.match(chosen.line, / · plain-HTTP sessions: allowed$/);
  assert.match(
    chosen.stderr,
    /^Plain-HTTP sign-in is allowed \(GOBLIN_INSECURE_HTTP_SESSIONS\) and Docker Compose publishes Uptime Goblin on "192\.0\.2\.5" \(GOBLIN_BIND_ADDRESS\)/m
  );
  const refused = await startLine({ ...compose('192.0.2.5'), GOBLIN_INSECURE_HTTP_SESSIONS: '0' });
  assert.match(refused.line, / · plain-HTTP sessions: refused$/);
});
