// goblin-admin (lib/cli/goblin-admin.mjs and lib/cli/commands/*): exit statuses, the lock and
// root rules, and each command against real data directories.
import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { createCipheriv, hkdfSync, randomBytes } from 'node:crypto';
import { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { main, commands, exitCodes, appRoot } from '../../lib/cli/goblin-admin.mjs';
import { asAdminCopy } from '../../lib/admin-command.mjs';
import { checkUnit } from '../../lib/cli/commands/status.mjs';
import { inContainer as runsInContainer } from '../../lib/cli/common.mjs';
import { acquireLock } from '../../lib/db/lock.mjs';
import {
  openControl,
  startControl,
  controlSteps,
  planFromScratch,
  interruptedRestoreMessage,
} from '../../lib/db/control.mjs';
import { requireRelease } from '../../lib/db/migrate.mjs';
import { listSnapshots, restoreSnapshot } from '../../lib/db/snapshot.mjs';
import { Keyring, keyFingerprint, memoryKeyringStore } from '../../lib/keyring.mjs';
import { createAudit } from '../../lib/audit/index.mjs';
import { planUnit, writePlan } from '../../lib/audit/writer.mjs';
import { temporary, fingerprint } from './helpers.mjs';
import { freePortSync } from '../helpers/net.mjs';
import { platformSubtest, platformTest } from '../helpers/platform.mjs';

const script = fileURLToPath(new URL('../../lib/cli/goblin-admin.mjs', import.meta.url));
const release = JSON.parse(
  fs.readFileSync(new URL('../../package.json', import.meta.url), 'utf8')
).version;
const hexKey = 'a1'.repeat(16) + 'b2'.repeat(16);
const otherKey = 'c3'.repeat(16) + 'd4'.repeat(16);

// A /proc in which no process runs: status and offline commands find no Uptime Goblin by its process
// (orbitServerProcess), on every platform (macOS has no /proc). Tests of that look-up give one.
const noProcesses = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-no-proc-'));
after(() => fs.rmSync(noProcesses, { recursive: true, force: true }));

// Runs goblin-admin in-process; resolves {code, out, err, json()}. As on a native install unless
// `container` (the Node 24 gate itself runs in Docker, where inContainer() is true).
async function admin(
  args,
  {
    env = {},
    uid = 1000,
    directory,
    secrets,
    credentials,
    container = false,
    proc = noProcesses,
    stdin,
  } = {}
) {
  let out = '',
    err = '';
  const code = await main(args, {
    env,
    uid,
    container,
    proc,
    ...(stdin ? { stdin } : {}),
    stdout: text => (out += text),
    stderr: text => (err += text),
    clock: () => Date.UTC(2026, 8, 29, 12),
    keySources: directory
      ? {
          credentialsDirectory: credentials ?? path.join(directory, 'no-credentials'),
          secretsDirectory: secrets ?? path.join(directory, 'no-secrets'),
        }
      : {},
  });
  return { code, out, err, json: () => JSON.parse(out) };
}
const withDir = (directory, ...args) => [...args, '--data-dir', directory];

// A data directory as a started 1.5 leaves it: migrated control database, keyring, 1.x files.
async function started(t, { key = hexKey } = {}) {
  const directory = temporary(t);
  fs.writeFileSync(path.join(directory, 'config.json'), '{"services":[]}\n');
  const lock = acquireLock(directory);
  try {
    const result = await startControl(directory, {
      lock,
      credentialConfigured: true,
      release,
      env: { GOBLIN_SECRET_KEY: key },
      keySources: {
        credentialsDirectory: path.join(directory, 'no-credentials'),
        secretsDirectory: path.join(directory, 'no-secrets'),
      },
    });
    result.control.close();
  } finally {
    lock.release();
  }
  return directory;
}

test('usage, help and unknown commands', async () => {
  const none = await admin([]);
  assert.equal(none.code, exitCodes.usage);
  assert.match(none.out, /Usage: goblin-admin <command>/);
  for (const name of Object.keys(commands)) assert.match(none.out, new RegExp(`\\n  ${name} `));
  assert.equal((await admin(['help'])).code, 0);
  const unknown = await admin(['frobnicate']);
  assert.equal(unknown.code, exitCodes.usage);
  assert.match(unknown.err, /unknown command "frobnicate"/);
  const bad = await admin(['snapshots', '--no-such-option']);
  assert.equal(bad.code, exitCodes.usage);
  assert.match(bad.err, /Usage: goblin-admin snapshots/);
  const help = await admin(['migrate', '--help']);
  assert.equal(help.code, 0);
  assert.match(help.out, /--plan \| --apply/);
  assert.deepEqual(exitCodes, {
    ok: 0,
    failed: 1,
    usage: 2,
    unverified: 3,
    locked: 75,
    refused: 78,
  });
  // Every command module declares what goblin-admin needs.
  for (const [name, load] of Object.entries(commands)) {
    const command = await load();
    assert.ok(['read', 'online', 'offline'].includes(command.kind), name);
    assert.equal(typeof command.run, 'function', name);
    assert.equal(typeof command.summary, 'string', name);
  }
});

test('commands that write refuse to run as root; read-only ones may', async t => {
  const directory = temporary(t);
  const refused = await admin(withDir(directory, 'snapshot'), { uid: 0 });
  assert.equal(refused.code, exitCodes.usage);
  assert.match(refused.err, /must not run as root/);
  assert.equal((await admin(withDir(directory, 'migrate', '--apply'), { uid: 0 })).code, 2);
  assert.equal((await admin(withDir(directory, 'key', 'rotate'), { uid: 0 })).code, 2);
  assert.equal((await admin(withDir(directory, 'snapshots'), { uid: 0 })).code, 0);
  assert.equal((await admin(withDir(directory, 'migrate', '--plan'), { uid: 0 })).code, 0);
  assert.equal((await admin(withDir(directory, 'key', 'status'), { uid: 0, directory })).code, 0);
  assert.deepEqual(fs.readdirSync(directory), [], 'read-only commands created nothing');
});

test('the root refusal names a command that works as it is: there is no goblin-admin on the PATH', async t => {
  const refused = await admin(
    withDir('/var/lib/uptime-goblin', 'restore-snapshot', 'pre-upgrade-x'),
    {
      uid: 0,
    }
  );
  assert.equal(
    refused.err,
    `goblin-admin restore-snapshot changes the data directory, so it must not run as root (files would become root's). Run it as the user Uptime Goblin runs as (uptime-goblin for the native install): sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key node ${script} restore-snapshot pre-upgrade-x --data-dir /var/lib/uptime-goblin\n`
  );
  // Without --data-dir (GOBLIN_DATA_DIR, which sudo would drop) the directory is named, quoted.
  const spaced = path.join(temporary(t), "data dir's");
  fs.mkdirSync(spaced);
  const fromEnv = await admin(['snapshot'], { uid: 0, env: { GOBLIN_DATA_DIR: spaced } });
  assert.equal(fromEnv.code, exitCodes.usage);
  const suggested = fromEnv.err.slice(fromEnv.err.indexOf('sudo -u uptime-goblin ')).trim();
  assert.equal(
    suggested,
    `sudo -u uptime-goblin node ${script} snapshot --data-dir '${spaced.replaceAll("'", `'\\''`)}'`
  );
  // The same words, run as this (non-root) user, do what was asked.
  const ran = spawnSync('bash', ['-c', suggested.replace(/^sudo -u uptime-goblin /, '')], {
    encoding: 'utf8',
  });
  assert.equal(ran.status, 0, ran.stderr);
  assert.equal(listSnapshots(spaced).length, 1);
  // A key command finds the key only in its own environment, which sudo -u uptime-goblin empties: the
  // line names the key files it was given, else the installer's, as every key command line
  // goblin-admin prints does (A7 item 1; review round 4: it named none, so the printed line was
  // refused again, and a reset with --use-data-dir-key from it made <data>/secret.key the key).
  const keyLine = async (args, env = {}) => {
    const refused = await admin(withDir('/var/lib/uptime-goblin', 'key', ...args), { uid: 0, env });
    assert.equal(refused.code, exitCodes.usage, refused.err);
    return refused.err.slice(refused.err.indexOf('sudo -u uptime-goblin ')).trim();
  };
  assert.equal(
    await keyLine(['rotate'], { GOBLIN_SECRET_KEY_FILE: '/srv/keys/orbit key' }),
    `sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE='/srv/keys/orbit key' node ${script} key rotate --data-dir /var/lib/uptime-goblin`
  );
  assert.equal(
    await keyLine(['rotate']),
    `sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key node ${script} key rotate --data-dir /var/lib/uptime-goblin`
  );
  assert.equal(
    await keyLine(['rewrap'], { GOBLIN_SECRET_KEY_FILE: '/etc/uptime-goblin/secret.key' }),
    `sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key GOBLIN_SECRET_KEY_PREVIOUS_FILE=OLD_KEY_FILE node ${script} key rewrap --data-dir /var/lib/uptime-goblin`
  );
  assert.equal(
    await keyLine(['rotate'], {
      GOBLIN_SECRET_KEY_FILE: '/etc/uptime-goblin/secret.key',
      GOBLIN_SECRET_KEY_PREVIOUS_FILE: '/root/old.key',
    }),
    `sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key GOBLIN_SECRET_KEY_PREVIOUS_FILE=/root/old.key node ${script} key rotate --data-dir /var/lib/uptime-goblin`
  );
  assert.equal(
    await keyLine(['reset', '--confirm-lost-key', '--use-data-dir-key'], {
      GOBLIN_SECRET_KEY: hexKey,
    }),
    `sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key node ${script} key reset --confirm-lost-key --use-data-dir-key --data-dir /var/lib/uptime-goblin`,
    'a key given as a value is never printed: the line names the installer’s key file'
  );
});

// The root refusal comes before a command checks its arguments, and its command line quoted
// each word for the shell only: a line break, an escape or a direction override in an argument
// (restore-snapshot's id, key's action) reached the terminal raw, and a line break started a
// forged log line. Then such a word became a placeholder in the line, <argument-2>, which a shell
// reads as redirections: pasted in a folder holding a file named argument-2, the line ran with
// its words shifted and wrote its output to a file named --data-dir. Now no line is printed;
// each such word is named escaped on a line of its own.
test('the root refusal prints no argument raw and no command line with one it cannot print: it names that argument escaped', async t => {
  const raw =
    /[\u0000-\u0009\u000b-\u001f\u{7f}-\u{9f}\u{2028}\u{2029}\u{202a}-\u{202e}\u{2066}-\u{2069}]/u;
  const holds =
    'a control character, a Unicode line or paragraph separator, or a text-direction embedding, override or isolate';
  const head = name =>
    `goblin-admin ${name} changes the data directory, so it must not run as root (files would become root's). Run it as the user Uptime Goblin runs as (uptime-goblin for the native install), with sudo -u uptime-goblin. No command line is printed here: it would hold a word that cannot be shown as a shell word.\n`;
  const directory = temporary(t);
  const forged = 'x\u001b[2J\n[orbit] FORGED\u{202e}';
  const refused = await admin(withDir(directory, 'restore-snapshot', forged), { uid: 0 });
  assert.equal(refused.code, exitCodes.usage);
  assert.equal(refused.out, '');
  assert.ok(!raw.test(refused.err), JSON.stringify(refused.err));
  for (const line of refused.err.split('\n'))
    assert.ok(!line.startsWith('[orbit]'), `no line of the argument stands alone: ${line}`);
  assert.equal(
    refused.err,
    head('restore-snapshot') +
      `Argument 2 given to goblin-admin holds ${holds} (it holds U+001B); escaped, it is "x\\u001b[2J\\n[orbit] FORGED\\u202e".\n`
  );
  // Nothing to paste: no command line, and no < or > that a shell would take for a redirection.
  assert.doesNotMatch(refused.err, /sudo -u uptime-goblin (env|node) /);
  assert.doesNotMatch(refused.err, /[<>]/);
  // A key command too; a line separator alone is held as well.
  const key = await admin(withDir('/var/lib/uptime-goblin', 'key', 'rot\u{2028}ate'), { uid: 0 });
  assert.equal(key.code, exitCodes.usage);
  assert.ok(!raw.test(key.err), JSON.stringify(key.err));
  assert.equal(
    key.err,
    head('key') +
      `Argument 2 given to goblin-admin holds ${holds} (it holds U+2028); escaped, it is "rot\\u2028ate".\n`
  );
  assert.doesNotMatch(key.err, /sudo -u uptime-goblin (env|node) |[<>]/);
  // An argument it can print still gets the whole line, quoted for the shell.
  const plain = await admin(withDir(directory, 'restore-snapshot', 'manual 1'), { uid: 0 });
  assert.equal(plain.code, exitCodes.usage);
  assert.equal(
    plain.err,
    `goblin-admin restore-snapshot changes the data directory, so it must not run as root (files would become root's). Run it as the user Uptime Goblin runs as (uptime-goblin for the native install): sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key node ${script} restore-snapshot 'manual 1' --data-dir ${directory}\n`
  );
});

test('status reports the process, the control database, snapshots and the service binary', async t => {
  const empty = temporary(t);
  const missingUnit = path.join(empty, 'uptime-goblin.service');
  const first = await admin(withDir(empty, 'status', '--json', '--unit', missingUnit));
  assert.equal(first.code, 0);
  const report = first.json();
  assert.deepEqual(report.process, { running: false, statusFile: 'absent' });
  assert.equal(report.control, null);
  assert.deepEqual(report.service, { unit: missingUnit, found: false });
  const text = await admin(withDir(empty, 'status', '--unit', missingUnit));
  assert.match(text.out, /Uptime Goblin: not running \(no run\/status\.json\)/);
  assert.match(text.out, /Control database: none yet/);

  const directory = await started(t);
  fs.mkdirSync(path.join(directory, 'run'));
  fs.writeFileSync(
    path.join(directory, 'run', 'status.json'),
    JSON.stringify({
      version: release,
      build: 'abc',
      pid: process.pid,
      nonce: 'hidden',
      phase: 'ready',
      startedAt: 1,
    })
  );
  const unit = path.join(directory, 'uptime-goblin.service');
  fs.writeFileSync(
    unit,
    `[Service]\nExecStart=${process.execPath} /opt/uptime-goblin/current/server.mjs\n`
  );
  // A 1.5 Uptime Goblin holds goblin.lock while it runs (see the next test for how status tells).
  const lock = acquireLock(directory);
  t.after(() => lock.release());
  const running = (await admin(withDir(directory, 'status', '--json', '--unit', unit))).json();
  assert.equal(running.process.running, true);
  assert.equal(running.process.phase, 'ready');
  assert.equal('nonce' in running.process, false, 'the nonce is never shown');
  assert.deepEqual(running.control.pending, []);
  assert.equal(running.control.lastVersion, release);
  assert.equal(running.control.createdByRelease, null, 'config.json existed: an upgrade');
  assert.equal(running.control.keyring, true);
  assert.equal(running.snapshots.count, 1);
  assert.equal(running.snapshots.pinned.length, 1);
  assert.equal(running.service.ok, true);
  assert.match(running.service.version, /^v\d+\./);
  const human = await admin(withDir(directory, 'status', '--unit', unit));
  assert.match(human.out, /Uptime Goblin: running, version .* phase ready/);
  assert.match(human.out, /Keyring: present/);
  assert.match(human.out, /Service binary: .*node/);
});

test('status tells whether Uptime Goblin runs as offline commands do: goblin.lock for 1.5, the process for 1.4.x, and in a container it says when it cannot tell', async t => {
  // Under Docker, run/status.json names a process id of Uptime Goblin's own container; goblin-admin runs
  // in another (`docker compose run`, or the kept 1.5 image after a Compose rollback), where that
  // id is missing or any process at all, goblin-admin itself included under --init. So status
  // answers as withLock refuses (runningOrbit): a 1.5 record by goblin.lock, which every 1.5
  // holds while it runs, seen from any container; a 1.4.x record natively by its process, and in
  // a container not at all.
  const directory = await started(t);
  const unit = path.join(directory, 'no.service');
  const record = path.join(directory, 'run', 'status.json');
  fs.mkdirSync(path.dirname(record), { recursive: true });
  const write = value => fs.writeFileSync(record, JSON.stringify({ build: 'abc', ...value }));
  const status = async (container = false) => {
    const json = await admin(withDir(directory, 'status', '--json', '--unit', unit), {
      container,
    });
    assert.equal(json.code, 0, json.err);
    const text = await admin(withDir(directory, 'status', '--unit', unit), { container });
    return {
      process: json.json().process,
      // Labelled with the name of the release it is about: Orbit for 1.4.x.
      line: text.out.split('\n').find(line => /^(?:Uptime Goblin|Orbit): /.test(line)),
    };
  };
  const gone = 2 ** 22 + 17;

  // 1.5: the lock answers, wherever the record's process id points (this process, as under
  // --init; a process that is gone, as without it). With the lock free the recorded Uptime Goblin is
  // not running; whether an Uptime Goblin that records nothing (1.4.2) runs is told natively by its
  // process (none here), and in a container cannot be.
  const unseen14 =
    "Orbit 1.4.2 and earlier keep no run/status.json and take no orbit.lock, and another container's processes cannot be seen from here";
  for (const container of [false, true])
    for (const pid of [process.pid, gone]) {
      write({ version: release, pid, startedAt: 1 });
      const crashed = await status(container);
      assert.equal(crashed.process.running, container ? null : false, `${container} ${pid}`);
      assert.equal(crashed.process.stale, true);
      assert.equal(
        crashed.line,
        container
          ? `Uptime Goblin: may be running (${unseen14}); run/status.json is left by Uptime Goblin ${release} build abc, pid ${pid}, started 1970-01-01 00:00:00 UTC, which is not running`
          : `Uptime Goblin: not running, version ${release} build abc, pid ${pid}, phase stopped, started 1970-01-01 00:00:00 UTC`
      );
      const lock = acquireLock(directory);
      try {
        const up = await status(container);
        assert.equal(up.process.running, true, `${container} ${pid}`);
        assert.match(
          up.line,
          new RegExp(`^Uptime Goblin: running, version .* pid ${pid}, phase ready`)
        );
      } finally {
        lock.release();
      }
    }

  // 1.4.x takes no lock. In a container its process is out of sight, whatever the id names.
  for (const pid of [gone, process.pid]) {
    write({ version: '1.4.3', pid, startedAt: 1 });
    const unseen = await status(true);
    assert.equal(unseen.process.running, null);
    assert.equal(
      unseen.process.uncertain,
      "another container's processes cannot be seen from here"
    );
    assert.equal(
      unseen.line,
      `Orbit: may be running (another container's processes cannot be seen from here), version 1.4.3 build abc, pid ${pid}, phase unknown, started 1970-01-01 00:00:00 UTC`
    );
  }
  // A record without a release is taken for 1.4.x, as offline commands take it.
  write({ pid: gone });
  assert.equal((await status(true)).process.running, null);
  // Natively the process is checked: gone, or this process (not Uptime Goblin), is not running; a live
  // server.mjs is.
  for (const pid of [gone, process.pid]) {
    write({ version: '1.4.3', pid });
    assert.equal((await status()).process.running, false, String(pid));
  }
  const fake = path.join(temporary(t), 'server.mjs');
  fs.writeFileSync(fake, 'setInterval(() => {}, 1000);\n');
  const child = spawn(process.execPath, [fake], { stdio: 'ignore' });
  t.after(() => child.kill('SIGKILL'));
  await new Promise(resolve => child.once('spawn', resolve));
  write({ version: '1.4.3', pid: child.pid });
  assert.equal((await status()).process.running, true);
  // A live process that is not Uptime Goblin (its id reused after a reboot) does not count where /proc
  // shows command lines (Linux), as for offline commands; on macOS it is taken for Uptime Goblin. One
  // subtest per platform, each registered there only (test/platform-manifest.json).
  write({ version: '1.4.3', pid: process.ppid });
  const reused = (await status()).process.running;
  await platformSubtest(
    t,
    import.meta.url,
    'db-cli.status.reused-pid.linux',
    'on Linux: a live process that is not Uptime Goblin, named by a 1.4.x record, is not taken for Uptime Goblin (/proc shows its command line)',
    {},
    () => assert.equal(reused, false)
  );
  await platformSubtest(
    t,
    import.meta.url,
    'db-cli.status.reused-pid.darwin',
    'on macOS: a live process named by a 1.4.x record is taken for Uptime Goblin (there is no /proc to show its command line)',
    {},
    () => assert.equal(reused, true)
  );

  // No record: the lock held means a start not yet serving, or an offline goblin-admin command.
  // Free, no 1.5 runs; natively no process runs Uptime Goblin on it either, and in a container that
  // cannot be told (1.4.2 keeps no record: see the next test).
  fs.rmSync(record);
  assert.deepEqual((await status()).process, { running: false, statusFile: 'absent' });
  assert.deepEqual((await status(true)).process, {
    running: null,
    uncertain: unseen14,
    statusFile: 'absent',
  });
  assert.equal((await status(true)).line, `Uptime Goblin: may be running (${unseen14})`);
  for (const container of [false, true]) {
    const lock = acquireLock(directory);
    try {
      const held = await status(container);
      assert.equal(held.process.running, null);
      assert.equal(
        held.line,
        'Uptime Goblin: may be running (goblin.lock is held but there is no run/status.json: Uptime Goblin is starting, or a goblin-admin command is changing the data directory)'
      );
    } finally {
      lock.release();
    }
  }
});

// A /proc holding the given processes: {pid: {argv, env, cwd}} (cmdline and environ are
// NUL-separated, cwd a link), as Linux shows them to orbitServerProcess.
function fakeProc(t, processes) {
  const proc = temporary(t);
  for (const [pid, { argv, env = {}, cwd = '/' }] of Object.entries(processes)) {
    const base = path.join(proc, pid);
    fs.mkdirSync(base);
    fs.writeFileSync(path.join(base, 'cmdline'), argv.map(arg => `${arg}\0`).join(''));
    fs.writeFileSync(
      path.join(base, 'environ'),
      Object.entries(env)
        .map(([key, value]) => `${key}=${value}\0`)
        .join('')
    );
    fs.symlinkSync(cwd, path.join(base, 'cwd'));
  }
  return proc;
}

test('an Uptime Goblin that keeps no run/status.json (1.4.2) is found by its process: status says it runs and offline commands refuse', async t => {
  // 1.4.2 writes no run/status.json and takes no goblin.lock, and a rollback to it is supported:
  // status said "Uptime Goblin: not running (no run/status.json)" while it served, and snapshot ran
  // under it (r7 upgrade-rollback finding). A server.mjs whose data directory is this one is it.
  const directory = await started(t);
  const unit = path.join(directory, 'no.service');
  const app = temporary(t);
  fs.writeFileSync(path.join(app, 'package.json'), '{"version":"1.4.2"}\n');
  const server = path.join(app, 'server.mjs');
  const node = '/usr/bin/node';
  const status = async (proc, options = {}) => {
    const json = await admin(withDir(directory, 'status', '--json', '--unit', unit), {
      proc,
      ...options,
    });
    assert.equal(json.code, 0, json.err);
    const text = await admin(withDir(directory, 'status', '--unit', unit), { proc, ...options });
    return {
      process: json.json().process,
      // Labelled with the name of the release it is about: Orbit for 1.4.x.
      line: text.out.split('\n').find(line => /^(?:Uptime Goblin|Orbit): /.test(line)),
    };
  };
  const snapshots = () => listSnapshots(directory).length;
  const found = (pid, version = '1.4.2') =>
    `Orbit: running, version ${version}, pid ${pid}, found by its process (it keeps no run/status.json, as Orbit 1.4.2 and earlier do not)`;

  // As systemd runs it (the unit's GOBLIN_DATA_DIR), by a relative GOBLIN_DATA_DIR from its
  // working directory, or with none (data/ beside server.mjs, here a link to the directory).
  fs.symlinkSync(directory, path.join(app, 'data'));
  for (const [pid, entry] of [
    [4242, { argv: [node, server], env: { GOBLIN_DATA_DIR: directory, NODE_ENV: 'production' } }],
    [
      4243,
      {
        argv: [node, '--max-old-space-size=256', 'server.mjs'],
        env: { GOBLIN_DATA_DIR: path.basename(directory) },
        cwd: path.dirname(directory),
      },
    ],
    [4244, { argv: [node, 'server.mjs'], env: { GOBLIN_DATA_DIR: '' }, cwd: app }],
  ]) {
    const proc = fakeProc(t, { [pid]: entry });
    const seen = await status(proc);
    assert.deepEqual(seen.process, {
      running: true,
      unrecorded: { pid, version: entry.cwd === app || entry.argv[1] === server ? '1.4.2' : null },
      statusFile: 'absent',
    });
    const before = snapshots();
    for (const args of [['snapshot'], ['migrate', '--apply'], ['restore-snapshot', 'x']]) {
      const refused = await admin(withDir(directory, ...args), { directory, proc });
      assert.equal(refused.code, exitCodes.locked, args.join(' '));
      // Found by its process alone, it is a release before 1.4.3: Orbit, which runs as
      // orbit.service (it reads only the Orbit layout).
      const who = seen.process.unrecorded.version ? 'Orbit 1.4.2' : 'Orbit';
      assert.equal(
        refused.err,
        `goblin-admin ${args[0]}: ${who} is running on ${directory} (process ${pid}, found by its process: it keeps no run/status.json, as Orbit 1.4.2 and earlier do not). Stop Orbit first: sudo systemctl stop orbit.\n`
      );
    }
    assert.equal(snapshots(), before, 'nothing taken under it');
  }
  assert.equal(
    (
      await status(
        fakeProc(t, { 4242: { argv: [node, server], env: { GOBLIN_DATA_DIR: directory } } })
      )
    ).line,
    found(4242)
  );
  // A record a crash left (its Uptime Goblin is not running) does not hide it.
  const record = path.join(directory, 'run', 'status.json');
  fs.mkdirSync(path.dirname(record), { recursive: true });
  fs.writeFileSync(record, JSON.stringify({ version: release, build: 'abc', pid: 2 ** 22 + 17 }));
  const behind = await status(
    fakeProc(t, { 4242: { argv: [node, server], env: { GOBLIN_DATA_DIR: directory } } })
  );
  assert.equal(behind.process.running, true);
  assert.equal(
    behind.line,
    `${found(4242)}; run/status.json is left by Uptime Goblin ${release} build abc, pid ${2 ** 22 + 17}, started unknown, which is not running`
  );
  fs.rmSync(record);

  // Another data directory, another program, or none: not running, and the command runs.
  const elsewhere = fakeProc(t, {
    4242: { argv: [node, server], env: { GOBLIN_DATA_DIR: temporary(t) } },
    4245: { argv: [node, path.join(app, 'other.mjs')], env: { GOBLIN_DATA_DIR: directory } },
    4246: { argv: ['server.mjs'], env: { GOBLIN_DATA_DIR: directory } },
  });
  assert.deepEqual((await status(elsewhere)).process, { running: false, statusFile: 'absent' });
  assert.equal((await status(elsewhere)).line, 'Uptime Goblin: not running (no run/status.json)');
  const taken = await admin(withDir(directory, 'snapshot', '--json'), {
    directory,
    proc: elsewhere,
  });
  assert.equal(taken.code, 0, taken.err);
  fs.rmSync(taken.json().path, { recursive: true });

  // Where it cannot be looked for, status does not claim "not running"; offline commands run,
  // as the docs say (stop 1.4.2 first).
  const why = 'Orbit 1.4.2 and earlier keep no run/status.json and take no orbit.lock, and';
  const noProc = await status(path.join(directory, 'no-proc'));
  assert.deepEqual(noProc.process, {
    running: null,
    uncertain: `${why} there is no /proc here to look for one by its process`,
    statusFile: 'absent',
  });
  assert.equal(noProc.line, `Uptime Goblin: may be running (${noProc.process.uncertain})`);
  const contained = await status(fakeProc(t, { 4242: { argv: [node, server], env: {} } }), {
    container: true,
  });
  assert.equal(
    contained.process.uncertain,
    `${why} another container's processes cannot be seen from here`
  );
  if (process.getuid?.() !== 0) {
    // Another user's server.mjs (its environment cannot be read).
    const hidden = fakeProc(t, { 4247: { argv: [node, server], env: {} } });
    const environ = path.join(hidden, '4247', 'environ');
    fs.chmodSync(environ, 0);
    try {
      const unread = await status(hidden);
      assert.equal(unread.process.running, null);
      assert.equal(
        unread.process.uncertain,
        `${why} process 4247 runs a server.mjs as another user, whose data directory cannot be read from here (run this as the user Uptime Goblin runs as, or as root)`
      );
      const ran = await admin(withDir(directory, 'snapshot', '--json'), {
        directory,
        proc: hidden,
      });
      assert.equal(ran.code, 0, ran.err);
    } finally {
      fs.chmodSync(environ, 0o600);
    }
  }
});

// The same with Linux's own /proc: a real server.mjs process started with GOBLIN_DATA_DIR, as
// systemd starts 1.4.2. Linux only: registered there alone (test/platform-manifest.json).
platformTest(
  import.meta.url,
  'db-cli.proc-server-found',
  'a running server.mjs with this data directory is found in /proc (Linux)',
  {},
  async t => {
    const directory = await started(t);
    const app = temporary(t);
    fs.writeFileSync(path.join(app, 'package.json'), '{"version":"1.4.2"}\n');
    fs.writeFileSync(path.join(app, 'server.mjs'), 'setInterval(() => {}, 1000);\n');
    const child = spawn(process.execPath, [path.join(app, 'server.mjs')], {
      stdio: 'ignore',
      env: { PATH: process.env.PATH, GOBLIN_DATA_DIR: directory },
    });
    t.after(() => child.kill('SIGKILL'));
    await new Promise(resolve => child.once('spawn', resolve));
    const unit = path.join(directory, 'no.service');
    const seen = await admin(withDir(directory, 'status', '--json', '--unit', unit), {
      proc: '/proc',
    });
    assert.deepEqual(seen.json().process, {
      running: true,
      unrecorded: { pid: child.pid, version: '1.4.2' },
      statusFile: 'absent',
    });
    const refused = await admin(withDir(directory, 'snapshot'), { directory, proc: '/proc' });
    assert.equal(refused.code, exitCodes.locked, refused.err);
    child.kill('SIGKILL');
    await new Promise(resolve => child.once('exit', resolve));
    const gone = await admin(withDir(directory, 'status', '--json', '--unit', unit), {
      proc: '/proc',
    });
    assert.equal(gone.json().process.running, false);
    assert.equal(
      (await admin(withDir(directory, 'snapshot'), { directory, proc: '/proc' })).code,
      0
    );
  }
);

test('checkUnit explains why systemd could not start Uptime Goblin', t => {
  const directory = temporary(t);
  const unit = body => {
    const file = path.join(directory, `u${Math.random()}.service`);
    fs.writeFileSync(file, body);
    return checkUnit(file);
  };
  assert.equal(unit('[Service]\nUser=orbit\n').problem, 'no ExecStart=');
  assert.match(unit('ExecStart=node server.mjs\n').problem, /absolute path/);
  assert.match(unit('ExecStart=/nowhere/node server.mjs\n').problem, /does not exist/);
  const fake = path.join(directory, 'old-node');
  fs.writeFileSync(fake, '#!/bin/sh\necho v18.19.0\n', { mode: 0o755 });
  assert.match(unit(`ExecStart=-${fake} server.mjs\n`).problem, /Node 18; Uptime Goblin needs 24/);
  const silent = path.join(directory, 'not-node');
  fs.writeFileSync(silent, '#!/bin/sh\necho hello\n', { mode: 0o755 });
  assert.match(unit(`ExecStart=${silent}\n`).problem, /did not report a Node version/);
});

test('migrate --plan (read-only) and --apply (offline, with a snapshot)', async t => {
  const directory = temporary(t);
  fs.writeFileSync(path.join(directory, 'config.json'), '{}\n');
  const before = fingerprint(directory);
  const plan = await admin(withDir(directory, 'migrate', '--plan', '--json'));
  assert.equal(plan.code, 0);
  assert.equal(plan.json().exists, false);
  assert.deepEqual(
    plan.json().steps.map(step => step.id),
    planFromScratch().map(step => step.id)
  );
  assert.equal(plan.json().steps.length, controlSteps.length);
  const human = await admin(withDir(directory, 'migrate', '--plan'));
  assert.match(human.out, /No control database yet/);
  assert.match(human.out, /CREATE TABLE "meta"/);
  assert.deepEqual(fingerprint(directory), before, '--plan wrote nothing');
  assert.equal((await admin(withDir(directory, 'migrate'))).code, 2);
  assert.equal((await admin(withDir(directory, 'migrate', '--plan', '--apply'))).code, 2);

  const applied = await admin(withDir(directory, 'migrate', '--apply'));
  assert.equal(applied.code, 0, applied.err);
  assert.match(applied.out, /Snapshot pre-upgrade-.* taken\./);
  assert.match(applied.out, /\[1\/6\] platform-001-control-tables/);
  assert.match(applied.out, /\[2\/6\] alerting-001-outbox/);
  assert.match(applied.out, /\[4\/6\] audit-001-log/);
  assert.match(applied.out, /\[5\/6\] identity-001-builtin-admin/);
  assert.match(applied.out, /\[6\/6\] identity-002-displays/);
  assert.match(applied.out, /Applied 6 step\(s\)\./);
  const [snapshot] = listSnapshots(directory);
  assert.equal(snapshot.pinned, true);
  const again = await admin(withDir(directory, 'migrate', '--apply', '--json'));
  assert.deepEqual(again.json().applied, []);
  assert.equal(again.json().snapshot, null);
  assert.match((await admin(withDir(directory, 'migrate', '--plan'))).out, /Nothing to migrate/);
  // An empty directory needs no snapshot.
  const fresh = temporary(t);
  const quiet = await admin(withDir(fresh, 'migrate', '--apply', '--json'));
  assert.equal(quiet.json().snapshot, null);
  assert.equal(listSnapshots(fresh).length, 0);
});

test('offline commands exit 75 while Uptime Goblin holds goblin.lock; refusals exit 78', async t => {
  const directory = await started(t);
  const lock = acquireLock(directory);
  t.after(() => lock.release());
  for (const args of [
    ['snapshot'],
    ['migrate', '--apply'],
    ['restore-snapshot', 'manual-1.5.0-20260101T000000Z'],
    ['snapshots', '--delete', 'manual-1.5.0-20260101T000000Z'],
    ['key', 'rotate'],
  ]) {
    const result = await admin(withDir(directory, ...args), { directory });
    assert.equal(result.code, exitCodes.locked, args.join(' '));
    assert.equal(
      result.err,
      `goblin-admin ${args[0]}: Uptime Goblin (or another goblin-admin command) is using ${path.resolve(directory)}. Stop Uptime Goblin first: sudo systemctl stop uptime-goblin\n`
    );
    // In a container (`docker compose run`) there is no systemctl; Compose stops Uptime Goblin.
    const contained = await admin(withDir(directory, ...args), { directory, container: true });
    assert.equal(contained.code, exitCodes.locked, args.join(' '));
    assert.equal(
      contained.err,
      `goblin-admin ${args[0]}: Uptime Goblin (or another goblin-admin command) is using ${path.resolve(directory)}. Stop it first (docker compose stop uptime-goblin)\n`
    );
  }
  // Read-only commands work while it runs.
  assert.equal((await admin(withDir(directory, 'snapshots'))).code, 0);
  assert.equal((await admin(withDir(directory, 'check-data'))).code, 0);
  lock.release();

  // Data from a newer release: --plan and --apply refuse with 78 and change nothing.
  const control = openControl(directory, { release, env: {} });
  await control.db.write(tx =>
    requireRelease(tx, { name: 'identity.totp', minRelease: '9.0.0', reason: 'TOTP', now: 1 })
  );
  control.close();
  const before = fingerprint(directory, ['goblin.lock', 'orbit.lock']);
  const plan = await admin(withDir(directory, 'migrate', '--plan'));
  assert.equal(plan.code, exitCodes.refused);
  assert.match(plan.out, /Refused: This data needs Uptime Goblin ≥ 9\.0\.0 \(TOTP\)/);
  const apply = await admin(withDir(directory, 'migrate', '--apply'));
  assert.equal(apply.code, exitCodes.refused);
  assert.match(apply.err, /needs Uptime Goblin ≥ 9\.0\.0/);
  assert.deepEqual(
    fingerprint(directory, ['goblin.lock', 'orbit.lock']),
    before,
    'a refusal changes no byte'
  );
  const check = await admin(withDir(directory, 'check-data'));
  assert.equal(check.code, 1);
  assert.match(check.out, /PROBLEM: This data needs Uptime Goblin ≥ 9\.0\.0/);
});

test('offline commands exit 75 while run/status.json names a live Uptime Goblin: 1.4.x takes no lock', async t => {
  // 1.4.x never takes goblin.lock. One left running (after a code rollback) would write its
  // in-memory settings back over a restored config.json, and its password would come back at
  // its next restart: the record it keeps while it runs (1.4.3 and later) is checked too.
  const directory = await started(t);
  const fake = path.join(temporary(t), 'server.mjs');
  fs.writeFileSync(fake, 'setInterval(() => {}, 1000);\n');
  const child = spawn(process.execPath, [fake], { stdio: 'ignore' });
  t.after(() => child.kill('SIGKILL'));
  await new Promise(resolve => child.once('spawn', resolve));
  const record = path.join(directory, 'run', 'status.json');
  fs.mkdirSync(path.dirname(record), { recursive: true });
  fs.writeFileSync(record, JSON.stringify({ pid: child.pid, version: '1.4.3', nonce: 'x' }));
  const before = fingerprint(directory, ['goblin.lock', 'orbit.lock']);
  for (const args of [
    ['restore-snapshot', listSnapshots(directory).find(item => item.pinned).id],
    ['migrate', '--apply'],
    ['snapshot'],
  ]) {
    const result = await admin(withDir(directory, ...args), { directory });
    assert.equal(result.code, exitCodes.locked, args.join(' '));
    assert.equal(
      result.err,
      `goblin-admin ${args[0]}: Orbit 1.4.3 is running on ${directory} (process ${child.pid}, named by run/status.json). Stop Orbit first: sudo systemctl stop orbit. If no Orbit runs (the record is left from a crash), remove ${record} and run this command again.\n`
    );
  }
  assert.deepEqual(
    fingerprint(directory, ['goblin.lock', 'orbit.lock']),
    before,
    'nothing changed'
  );
  assert.equal((await admin(withDir(directory, 'snapshots'))).code, 0, 'reading still works');
  // Stopped (the record outlives a crash, naming a process that is gone): the command runs.
  child.kill('SIGKILL');
  await new Promise(resolve => child.once('exit', resolve));
  assert.equal((await admin(withDir(directory, 'snapshot'))).code, 0);
  // A live process that is not Uptime Goblin (its id reused after a reboot) does not count where
  // /proc shows command lines (Linux); elsewhere it is taken for Uptime Goblin, and the message says
  // what to do. One subtest per platform, each registered there only.
  fs.writeFileSync(record, JSON.stringify({ pid: process.ppid, version: '1.4.3' }));
  const reused = await admin(withDir(directory, 'snapshot'));
  await platformSubtest(
    t,
    import.meta.url,
    'db-cli.offline.reused-pid.linux',
    'on Linux: a live process that is not Uptime Goblin, named by the record, does not stop the command (/proc shows its command line)',
    {},
    () => assert.equal(reused.code, 0)
  );
  await platformSubtest(
    t,
    import.meta.url,
    'db-cli.offline.reused-pid.darwin',
    'on macOS: a live process named by the record is taken for Uptime Goblin, and the command exits 75 (there is no /proc to show its command line)',
    {},
    () => assert.equal(reused.code, exitCodes.locked)
  );
});

test('in a container, a 1.4.x record on the data volume refuses offline commands: its process is out of sight', async t => {
  // Under Docker, 1.4.3 in the Uptime Goblin container writes its own process id into run/status.json;
  // `docker compose run` starts goblin-admin in another container, where that id is missing or
  // names another process (goblin-admin itself, under --init). 1.4.x takes no goblin.lock, so the
  // record is all there is: it refuses until 1.4.x is stopped (which removes it) or the record
  // of a crash is removed by hand. A 1.5 record is left to goblin.lock (§16 C4).
  const directory = await started(t);
  const record = path.join(directory, 'run', 'status.json');
  fs.mkdirSync(path.dirname(record), { recursive: true });
  const pinned = listSnapshots(directory).find(item => item.pinned).id;
  const before = fingerprint(directory, ['goblin.lock', 'orbit.lock', 'run']);
  for (const pid of [2 ** 22 + 17, process.pid]) {
    fs.writeFileSync(record, JSON.stringify({ pid, version: '1.4.3', nonce: 'x' }));
    for (const args of [['restore-snapshot', pinned], ['migrate', '--apply'], ['snapshot']]) {
      const result = await admin(withDir(directory, ...args), { directory, container: true });
      assert.equal(result.code, exitCodes.locked, `${pid} ${args.join(' ')}`);
      assert.equal(
        result.err,
        `goblin-admin ${args[0]}: Orbit 1.4.3 may be running on ${directory}: run/status.json names it, and from inside a container goblin-admin cannot see another container's processes. Stop it first (docker compose stop uptime-goblin). If no Uptime Goblin runs (the record is left from a crash), remove ${record} and run this command again.\n`
      );
    }
    // Natively the same record names a process that is gone (or this one): not running.
    if (pid !== process.pid) {
      const native = await admin(withDir(directory, 'snapshot', '--json'), { directory });
      assert.equal(native.code, 0, native.err);
      fs.rmSync(native.json().path, { recursive: true });
    }
  }
  assert.deepEqual(
    fingerprint(directory, ['goblin.lock', 'orbit.lock', 'run']),
    before,
    'nothing changed'
  );
  assert.equal(
    (await admin(withDir(directory, 'snapshots'), { container: true })).code,
    0,
    'reading still works'
  );
  // A record without a release is taken for 1.4.x; one of 1.5 or later, whose Uptime Goblin would hold
  // goblin.lock while it runs, is left from a crash; no record at all, and the command runs.
  fs.writeFileSync(record, JSON.stringify({ pid: 7 }));
  assert.equal((await admin(withDir(directory, 'snapshot'), { container: true })).code, 75);
  fs.writeFileSync(record, JSON.stringify({ pid: 7, version: release }));
  assert.equal((await admin(withDir(directory, 'snapshot'), { container: true })).code, 0);
  fs.rmSync(record);
  assert.equal((await admin(withDir(directory, 'snapshot'), { container: true })).code, 0);
});

test('restore-snapshot over a damaged control.sqlite finishes, says so, and the directory starts', async t => {
  // A disk error damaged control.sqlite: Uptime Goblin cannot start on it, and restoring a snapshot is
  // the way back. The restore stopped on the damaged file, leaving its journal, so Uptime Goblin refused
  // to start and the re-run its refusal asked for stopped the same way (§16 C10).
  const directory = await started(t);
  const taken = await admin(withDir(directory, 'snapshot', '--json'));
  assert.equal(taken.code, 0, taken.err);
  const { id } = taken.json();
  const control = path.join(directory, 'control.sqlite');
  const handle = fs.openSync(control, 'r+');
  fs.writeSync(handle, Buffer.from('this is no SQLite header at all'), 0, 31, 0);
  fs.closeSync(handle);
  const restored = await admin(withDir(directory, 'restore-snapshot', id), { directory });
  assert.equal(restored.code, 0, restored.err);
  const aside = listSnapshots(directory).find(item => item.reason === 'pre-restore').id;
  // The keyring of the file it replaced cannot be read, so nothing shows whether the key Uptime Goblin
  // uses opens the one it brought back (review F2v2: it said nothing of the key, and after a key
  // change Uptime Goblin then refused to start): it says so, after the damage, with the line that checks.
  assert.equal(
    restored.out,
    `Restored config.json, control.sqlite from ${id}.\n` +
      'control.sqlite could not be opened (file is not a database), so it was moved aside as it was, with any -wal and -shm files beside it.\n' +
      "The restored control.sqlite holds the keyring of the snapshot's time, and the keyring of the control.sqlite this restore replaced could not be read to compare it with: if the encryption key changed since (key rotate, key rewrap or key reset), it opens only with the older key and Uptime Goblin refuses to start with the current one (key_mismatch). No encryption key reached this command to tell which (it reads the key from its own environment, as the key commands do). " +
      `Before you start Uptime Goblin, check it with the key Uptime Goblin uses: sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key node ${script} key status --data-dir ${directory} (the native install; Docker Compose and other installs: docs/installation.md#goblin-admin). If that says the key does not match this data, start Uptime Goblin with the older key, or move this data to the current key with key rotate, the older key given as GOBLIN_SECRET_KEY_PREVIOUS_FILE (docs/installation.md#snapshots).\n` +
      `The replaced files are in snapshot ${aside}. It cannot be restored as a whole, because control.sqlite in it is damaged; copy its other files back by hand if you need them.\n`
  );
  // Nothing is left half done: the next start opens the restored control database.
  const lock = acquireLock(directory);
  try {
    const result = await startControl(directory, {
      lock,
      credentialConfigured: true,
      release,
      env: { GOBLIN_SECRET_KEY: hexKey },
      keySources: {
        credentialsDirectory: path.join(directory, 'no-credentials'),
        secretsDirectory: path.join(directory, 'no-secrets'),
      },
    });
    result.control.close();
  } finally {
    lock.release();
  }
});

test('status and snapshots report the copies an interrupted restore left; restore-snapshot removes them', async t => {
  // A restore stopped by a crash leaves copies of the snapshot's files under hidden names in the
  // data directory, as large as the files (history.sqlite included). Nothing reported them, and
  // only a restore that copied the same file again ever replaced one.
  const directory = await started(t);
  const history = new DatabaseSync(path.join(directory, 'history.sqlite'));
  history.exec(
    "CREATE TABLE readings (service TEXT, time INTEGER); INSERT INTO readings VALUES ('a', 1)"
  );
  history.close();
  const taken = await admin(withDir(directory, 'snapshot', '--json'));
  assert.equal(taken.code, 0, taken.err);
  const { id } = taken.json();
  const unit = path.join(directory, 'no.service');
  const copy = path.join(directory, '.history.sqlite.restoring');
  const statusOf = async () =>
    (await admin(withDir(directory, 'status', '--json', '--unit', unit))).json().restore;
  assert.deepEqual(await statusOf(), { interrupted: null, leftovers: [], leftoverBytes: 0 });

  // 1. Stopped while it copied (step 1): no journal, and nothing uses the copy. Only Uptime Goblin 1.5
  // and later remove it at a start: after a code rollback 1.4.x leaves it, which status says.
  fs.copyFileSync(path.join(directory, 'snapshots', id, 'history.sqlite'), copy);
  const bytes = fs.statSync(copy).size;
  const problem =
    'A copy of history.sqlite left by a snapshot restore that a crash or a power loss stopped; nothing uses it (unless a restore is running now). The next start of Uptime Goblin 1.5 or later, or the next restore-snapshot, removes it; Orbit 1.4.x leaves it (delete it by hand while Uptime Goblin is stopped).';
  assert.deepEqual(await statusOf(), {
    interrupted: null,
    leftovers: [
      {
        id: '.history.sqlite.restoring',
        names: ['.history.sqlite.restoring'],
        bytes,
        needed: false,
        problem,
      },
    ],
    leftoverBytes: bytes,
  });
  const text = await admin(withDir(directory, 'status', '--unit', unit));
  assert.ok(
    text.out.includes(
      `\nRestore leftover: .history.sqlite.restoring in the data directory (${(bytes / 1024).toFixed(1)} KiB). ${problem}\n`
    ),
    text.out
  );
  const listed = await admin(withDir(directory, 'snapshots', '--json'));
  assert.equal(listed.code, 0);
  const entry = listed.json().find(item => item.leftover);
  assert.deepEqual(
    [entry.id, entry.valid, entry.pinned, entry.interrupted, entry.bytes, entry.needed],
    ['.history.sqlite.restoring', false, false, true, bytes, false]
  );
  assert.match(
    (await admin(withDir(directory, 'snapshots'))).out,
    /\n\.history\.sqlite\.restoring \(in the data directory\) {2}\S+ \S+ UTC {2}\S+ KiB {2}LEFTOVER: A copy of history\.sqlite left by/
  );
  assert.equal((await admin(withDir(directory, 'snapshots', '--verify'))).code, 1);
  // The next restore removes it first, and says so.
  const restored = await admin(withDir(directory, 'restore-snapshot', id));
  assert.equal(restored.code, 0, restored.err);
  assert.ok(
    restored.out.includes(
      `Removed .history.sqlite.restoring (${(bytes / 1024).toFixed(1)} KiB): temporary copies that an earlier restore, stopped by a crash, left in the data directory.\n`
    ),
    restored.out
  );
  assert.equal(fs.existsSync(copy), false);
  assert.deepEqual(await statusOf(), { interrupted: null, leftovers: [], leftoverBytes: 0 });

  // 2. Interrupted mid-swap: the journal names history.sqlite, so its copy is kept, and status
  // says which restore to run again.
  const lock = acquireLock(directory);
  const rename = fs.renameSync;
  fs.renameSync = function (from, to) {
    if (String(from) === copy) throw new Error('power lost');
    return rename.call(this, from, to);
  };
  try {
    await assert.rejects(restoreSnapshot(directory, id, { lock, release }), {
      message: 'power lost',
    });
  } finally {
    fs.renameSync = rename;
    lock.release();
  }
  const interrupted = await statusOf();
  assert.equal(interrupted.interrupted.snapshot, id);
  assert.deepEqual(
    interrupted.leftovers.map(item => [item.id, item.needed]),
    [['.history.sqlite.restoring', true]]
  );
  const said = (await admin(withDir(directory, 'status', '--unit', unit))).out;
  // Its command line names the copy that runs and its data directory (after a code rollback,
  // the kept 1.5 copy: /opt/uptime-goblin then holds 1.4.x, which has no goblin-admin), and since that
  // copy is not /opt/uptime-goblin, the service is kept disabled until the restore has finished.
  const fromHere = asAdminCopy({ root: appRoot, dataDir: directory }, () =>
    interruptedRestoreMessage({ snapshot: id })
  );
  assert.ok(said.includes(`\nRestore interrupted: ${fromHere}\n`), said);
  assert.ok(
    said.includes(
      `with Uptime Goblin stopped and its service disabled (sudo systemctl disable --now uptime-goblin.service): sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key node ${script} restore-snapshot ${id} --data-dir ${directory} (the native install;`
    ),
    said
  );
  assert.match(
    said,
    /\. Then enable and start Uptime Goblin \(sudo systemctl enable --now uptime-goblin\.service\)\.\n/
  );
  assert.doesNotMatch(said, /\/opt\/uptime-goblin\/lib\/cli/);
  // So does migrate --apply's refusal, and in a container (the image's paths) both keep the
  // native install's form and the docs pointer.
  const refusedHere = await admin(withDir(directory, 'migrate', '--apply'));
  assert.equal(refusedHere.code, exitCodes.refused);
  assert.equal(refusedHere.err, `goblin-admin migrate: ${fromHere}\n`);
  const inContainer = await admin(withDir(directory, 'status', '--unit', unit), {
    container: true,
  });
  assert.ok(
    inContainer.out.includes(
      `\nRestore interrupted: ${interruptedRestoreMessage({ snapshot: id })}\n`
    ),
    inContainer.out
  );
  assert.match(
    inContainer.out,
    /sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=\/etc\/uptime-goblin\/secret\.key node \/opt\/uptime-goblin\/lib\/cli\/goblin-admin\.mjs restore-snapshot /
  );
  const refusedThere = await admin(withDir(directory, 'migrate', '--apply'), { container: true });
  assert.equal(
    refusedThere.err,
    `goblin-admin migrate: ${interruptedRestoreMessage({ snapshot: id })}\n`
  );
  // The command as printed (without sudo: this test is the uptime-goblin user) finishes the restore. It
  // names the key file, since restore-snapshot checks a keyring it brings back with the key
  // (review F2v2): here the test's own, never a real /etc/uptime-goblin/secret.key.
  const keyFile = path.join(directory, '..', `${path.basename(directory)}.key`);
  fs.writeFileSync(keyFile, `${hexKey}\n`, { mode: 0o600 });
  t.after(() => fs.rmSync(keyFile, { force: true }));
  const printed =
    /sudo -u uptime-goblin (env GOBLIN_SECRET_KEY_FILE=\/etc\/uptime-goblin\/secret\.key node \S+ restore-snapshot \S+ --data-dir \S+) \(the native install;/
      .exec(refusedHere.err)?.[1]
      ?.replace('=/etc/uptime-goblin/secret.key ', `=${keyFile} `);
  assert.ok(printed, refusedHere.err);
  // Run from the 1.5 copy kept after a code rollback, status must not promise that the
  // installed 1.4.x refuses: it does not check the journal.
  assert.match(
    said,
    /Uptime Goblin 1\.5 and later will not start on it; Orbit 1\.4\.x, after a code rollback, does not check, so keep it stopped as well\./
  );
  assert.ok(
    said.includes(
      `A copy of history.sqlite made by the interrupted restore of ${id}. Run that restore again, with Uptime Goblin stopped, to finish it (restore-snapshot ${id}); it replaces this copy. Uptime Goblin 1.5 and later will not start until then (Orbit 1.4.x does not check: keep it stopped too).`
    ),
    said
  );
  const again = spawnSync('bash', ['-c', printed], {
    encoding: 'utf8',
    env: { PATH: process.env.PATH },
  });
  assert.equal(again.status, 0, again.stderr);
  assert.doesNotMatch(again.stdout, /^Removed \./m, 'its own copy was replaced, not a leftover');
  assert.deepEqual(await statusOf(), { interrupted: null, leftovers: [], leftoverBytes: 0 });
  assert.doesNotMatch((await admin(withDir(directory, 'status', '--unit', unit))).out, /Restore/);
});

test('snapshot, snapshots --verify and restore-snapshot round trip', async t => {
  const directory = await started(t);
  const taken = await admin(withDir(directory, 'snapshot', '--reason', 'before-change', '--json'));
  assert.equal(taken.code, 0, taken.err);
  const { id } = taken.json();
  assert.match(id, /^before-change-/);
  fs.writeFileSync(path.join(directory, 'config.json'), '{"services":["changed"]}\n');
  const listed = await admin(withDir(directory, 'snapshots', '--verify'));
  assert.equal(listed.code, 0);
  assert.match(listed.out, new RegExp(`${id} .* verified`));
  assert.match(listed.out, /\[pinned\]/);
  // A damaged snapshot makes --verify fail.
  fs.appendFileSync(path.join(directory, 'snapshots', id, 'config.json'), ' ');
  const damaged = await admin(withDir(directory, 'snapshots', '--verify', '--json'));
  assert.equal(damaged.code, 1);
  assert.equal(damaged.json().find(item => item.id === id).verified, false);
  assert.equal((await admin(withDir(directory, 'restore-snapshot', id))).code, 1);
  // Restore the pinned one, keeping history, and see the replaced files set aside.
  const pinned = listSnapshots(directory).find(item => item.pinned);
  const restored = await admin(withDir(directory, 'restore-snapshot', pinned.id, '--keep-history'));
  assert.equal(restored.code, 0, restored.err);
  assert.match(restored.out, /Removed \(absent in the snapshot\): control\.sqlite/);
  assert.match(restored.out, /restore it to undo/);
  assert.equal(fs.existsSync(path.join(directory, 'control.sqlite')), false);
  assert.equal(fs.readFileSync(path.join(directory, 'config.json'), 'utf8'), '{"services":[]}\n');
  assert.equal((await admin(withDir(directory, 'restore-snapshot'))).code, 2);
  assert.equal((await admin(withDir(directory, 'restore-snapshot', 'no-such-id'))).code, 1);
});

// BR-4: snapshots were deleted by hand (rm -r), which skipped the pinned snapshot's guard and
// could remove one an interrupted restore still needed.
test('snapshots --delete deletes a snapshot with Uptime Goblin stopped: a pinned one only with --force, never one an interrupted restore needs', async t => {
  const directory = await started(t);
  const pinned = listSnapshots(directory).find(item => item.pinned);
  assert.ok(pinned, 'the first start pinned its snapshot');
  const taken = await admin(withDir(directory, 'snapshot', '--reason', 'spare', '--json'));
  assert.equal(taken.code, 0, taken.err);
  const { id } = taken.json();
  // Usage errors, before goblin.lock is taken.
  for (const [args, said] of [
    [['--delete'], /Option '--delete' argument/],
    [
      ['--delete', '../escape'],
      /--delete takes the id of a snapshot as goblin-admin snapshots lists it; "\.\.\/escape" is not one\./,
    ],
    [['--delete', `.restoring-${id}`], /is not one\./],
    [['--force'], /--force goes only with --delete <id>\./],
    [['--verify', '--delete', id], /--verify and --delete cannot be given together\./],
    [['--delete', id, '--delete', id], /--delete is given more than once\./],
  ]) {
    const result = await admin(withDir(directory, 'snapshots', ...args));
    assert.equal(result.code, exitCodes.usage, args.join(' '));
    assert.match(result.err, said, args.join(' '));
  }
  // It changes the data directory: never as root (listing still may).
  const root = await admin(withDir(directory, 'snapshots', '--delete', id), { uid: 0 });
  assert.equal(root.code, exitCodes.usage);
  assert.match(
    root.err,
    /goblin-admin snapshots changes the data directory, so it must not run as root/
  );
  assert.match(root.err, new RegExp(`snapshots --delete ${id} --data-dir `));
  // The pinned snapshot only with --force.
  const refused = await admin(withDir(directory, 'snapshots', '--delete', pinned.id));
  assert.equal(refused.code, exitCodes.failed);
  assert.equal(
    refused.err,
    `goblin-admin snapshots: ${pinned.id} is pinned: it is the way back to Orbit 1.4.x. Delete it with --force if you are sure.\n`
  );
  // One an interrupted restore needs: not even with --force.
  const journal = path.join(directory, 'snapshots', '.restore-in-progress.json');
  fs.writeFileSync(
    journal,
    JSON.stringify({ snapshot: id, aside: 'pre-restore-1.5.0-20200101T000000Z', files: [] })
  );
  const needed = await admin(withDir(directory, 'snapshots', '--delete', id, '--force'));
  assert.equal(needed.code, exitCodes.failed);
  assert.equal(
    needed.err,
    `goblin-admin snapshots: ${id} was not deleted: the interrupted restore of ${id} needs it. Run that restore again to finish it (goblin-admin restore-snapshot ${id}), then delete the snapshot.\n`
  );
  fs.rmSync(journal);
  assert.deepEqual(
    listSnapshots(directory)
      .map(item => item.id)
      .sort(),
    [id, pinned.id].sort(),
    'nothing deleted yet'
  );
  const deleted = await admin(withDir(directory, 'snapshots', '--delete', id));
  assert.equal(deleted.code, 0, deleted.err);
  assert.equal(deleted.out, `Deleted snapshot ${id}.\n`);
  assert.equal(fs.existsSync(path.join(directory, 'snapshots', id)), false);
  const again = await admin(withDir(directory, 'snapshots', '--delete', id));
  assert.equal(again.code, exitCodes.failed);
  assert.equal(again.err, `goblin-admin snapshots: There is no snapshot ${id}\n`);
  const forced = await admin(
    withDir(directory, 'snapshots', '--delete', pinned.id, '--force', '--json')
  );
  assert.equal(forced.code, 0, forced.err);
  assert.deepEqual(forced.json(), { deleted: pinned.id });
  assert.deepEqual(listSnapshots(directory), []);
  assert.equal((await admin(withDir(directory, 'snapshots'))).out, 'No snapshots.\n');
});

// BR-5: verification ran quick_check only, which passes a copy whose index disagrees with its
// table (the writable_schema index-definition swap); integrity_check finds it.
test('snapshots --verify and restore-snapshot refuse a snapshot whose index disagrees with its table', async t => {
  const directory = await started(t);
  const taken = await admin(withDir(directory, 'snapshot', '--json'));
  assert.equal(taken.code, 0, taken.err);
  const { id } = taken.json();
  const copy = new DatabaseSync(path.join(directory, 'snapshots', id, 'control.sqlite'), {
    defensive: false,
  });
  copy.exec('CREATE TABLE swapped (a INTEGER, b INTEGER); CREATE INDEX swapped_a ON swapped (a)');
  const insert = copy.prepare('INSERT INTO swapped VALUES (?, ?)');
  for (let n = 1; n <= 50; n += 1) insert.run(n, 1000 - n);
  copy.exec('PRAGMA writable_schema=ON');
  copy.exec(
    "UPDATE sqlite_master SET sql = 'CREATE INDEX swapped_a ON swapped (b)' WHERE name = 'swapped_a'"
  );
  copy.close();
  await rehash(directory, id, 'control.sqlite');
  const verified = await admin(withDir(directory, 'snapshots', '--verify', '--json'));
  assert.equal(verified.code, 1, verified.err);
  const [problem, ...more] = verified.json().find(item => item.id === id).problems;
  assert.deepEqual(more, []);
  assert.match(problem, /^control\.sqlite: row \d+ missing from index swapped_a/);
  const before = fingerprint(directory, ['snapshots']);
  const refused = await admin(withDir(directory, 'restore-snapshot', id), {
    env: { GOBLIN_SECRET_KEY: hexKey },
    directory,
  });
  assert.equal(refused.code, exitCodes.failed);
  assert.match(
    refused.err,
    new RegExp(
      `^goblin-admin restore-snapshot: Snapshot ${id} cannot be restored: control\\.sqlite: row \\d+ missing from index swapped_a`
    )
  );
  assert.deepEqual(fingerprint(directory, ['snapshots']), before, 'nothing restored');
});

// Restoring a snapshot taken before 1.5 first ran (the pinned pre-upgrade one, as the rollback
// docs say to) removes control.sqlite, and with it the waiting notifications, their history and
// the sealed webhook signing key: the next start makes a new key pair, whose public key
// receivers that check signatures do not have, and only a start log line said so (review round
// 2). The restore says so; one that keeps control.sqlite says nothing of it.
// Docs audit (audit 9): the audit log goes with that file too, and the next start lists no
// restore, so the line says so and where the old log stays.
test('restore-snapshot says what removing control.sqlite takes: the audit log, sessions, waiting notifications, history, the signing key', async t => {
  const directory = await started(t);
  const pinned = listSnapshots(directory).find(item => item.pinned);
  const restored = await admin(withDir(directory, 'restore-snapshot', pinned.id));
  assert.equal(restored.code, 0, restored.err);
  const said =
    "control.sqlite held Uptime Goblin 1.5's audit log, its sessions, its waiting notifications, its delivery history and the webhook signing key. The audit log starts again, empty, at the next start, and Check integrity will list no restore: the old log is kept only in the pre-restore snapshot named below. Those notifications will not be sent. With a webhook set, Uptime Goblin 1.5 makes a new signing key when it next starts. Give its public key (Configure → Notifications → Show public key) to receivers that check X-Goblin-Signature: until they have it, they reject every request.";
  const lines = restored.out.trimEnd().split('\n');
  const removed = lines.indexOf('Removed (absent in the snapshot): control.sqlite.');
  assert.ok(removed >= 0, restored.out);
  assert.equal(lines[removed + 1], said, restored.out);
  assert.equal(fs.existsSync(path.join(directory, 'control.sqlite')), false);
  // Undone: the pre-restore snapshot holds control.sqlite, so nothing is removed or said.
  const aside = /The replaced files are in snapshot (\S+); restore it to undo\./.exec(
    restored.out
  )?.[1];
  assert.ok(aside, restored.out);
  const undone = await admin(withDir(directory, 'restore-snapshot', aside));
  assert.equal(undone.code, 0, undone.err);
  assert.ok(fs.existsSync(path.join(directory, 'control.sqlite')));
  assert.doesNotMatch(undone.out, /Removed \(absent|control\.sqlite held/);
});

test('check-data finds tables the registry does not know', async t => {
  const directory = await started(t);
  const clean = await admin(withDir(directory, 'check-data', '--json'));
  assert.equal(clean.code, 0);
  assert.deepEqual(clean.json().problems, []);
  assert.match(clean.json().notes.join(), /No history database yet/);
  const db = new DatabaseSync(path.join(directory, 'control.sqlite'));
  db.exec('CREATE TABLE stray (x)');
  db.close();
  const history = new DatabaseSync(path.join(directory, 'history.sqlite'));
  history.exec('CREATE TABLE readings (service TEXT, time INTEGER); CREATE TABLE other (y)');
  history.close();
  const drift = await admin(withDir(directory, 'check-data'));
  assert.equal(drift.code, 1);
  assert.match(drift.out, /PROBLEM: control\.sqlite has an unregistered table stray/);
  assert.match(drift.out, /PROBLEM: history\.sqlite has an unregistered table other/);
  assert.match(
    drift.out,
    /history\.sqlite has not been opened by Uptime Goblin 1\.5 or later yet \(its events table lacks the columns 1\.5 adds\)/
  );
  assert.deepEqual(
    fs.readdirSync(directory).filter(name => /-(wal|shm)$/.test(name)),
    [],
    'read-only checks leave no side files'
  );
});

test('check-data reports a trigger or view Uptime Goblin does not create, in either database', async t => {
  const directory = await started(t);
  // A planted trigger runs under Uptime Goblin's own writes: this one would undo every session
  // revocation. Neither it nor a view was listed by the drift check.
  const db = new DatabaseSync(path.join(directory, 'control.sqlite'));
  db.exec(
    "CREATE TRIGGER keep_sessions AFTER UPDATE ON meta BEGIN UPDATE meta SET value = '1' WHERE key = 'session_seq'; END; CREATE VIEW \"seen\u001b[2J\" AS SELECT 1"
  );
  db.close();
  const history = new DatabaseSync(path.join(directory, 'history.sqlite'));
  history.exec(
    'CREATE TABLE readings (service TEXT, time INTEGER); CREATE VIEW recent AS SELECT 1'
  );
  // A table Uptime Goblin does not create, named to clear the terminal and forge a line of its own.
  history.exec('CREATE TABLE "t\u001b[2J\n[orbit] FORGED-TABLE-LINE" (x)');
  history.close();
  const control = new DatabaseSync(path.join(directory, 'control.sqlite'));
  control.exec('CREATE TABLE "c\u001b[2J\n[orbit] FORGED-CONTROL-TABLE" (x)');
  control.close();
  const found = await admin(withDir(directory, 'check-data'));
  assert.equal(found.code, 1);
  assert.match(
    found.out,
    /PROBLEM: control\.sqlite has a trigger Uptime Goblin does not create: keep_sessions/
  );
  assert.match(
    found.out,
    /PROBLEM: control\.sqlite has a view Uptime Goblin does not create: seen\[2J/
  );
  assert.match(
    found.out,
    /PROBLEM: history\.sqlite has a view Uptime Goblin does not create: recent/
  );
  assert.doesNotMatch(found.out, /\u001b/, 'a saved name is printed without control characters');
  for (const line of found.out.split('\n')) assert.ok(!line.startsWith('[orbit]'), line);
  assert.match(
    found.out,
    /history\.sqlite has an unregistered table t\[2J\[orbit\] FORGED-TABLE-LINE/
  );
  assert.match(
    found.out,
    /control\.sqlite has an unregistered table c\[2J\[orbit\] FORGED-CONTROL/
  );
  const json = (await admin(withDir(directory, 'check-data', '--json'))).json();
  assert.deepEqual(json.control.triggers, ['keep_sessions']);
  assert.deepEqual(json.history.views, ['recent']);
});

test('a snapshot whose database holds a trigger or view is damaged: verify names it and restore-snapshot refuses it', async t => {
  const directory = await started(t);
  const made = await admin(withDir(directory, 'snapshot', '--json'), {
    env: { GOBLIN_SECRET_KEY: hexKey },
    directory,
  });
  assert.equal(made.code, 0, made.err);
  const id = made.json().id;
  // A trigger put into the snapshot's copy, its manifest made to match: restoring it brought
  // the trigger into every write Uptime Goblin makes, and nothing but check-data said so.
  const folder = path.join(directory, 'snapshots', id);
  const copy = path.join(folder, 'control.sqlite');
  const db = new DatabaseSync(copy);
  db.exec(
    "CREATE TRIGGER keep_sessions AFTER UPDATE ON meta BEGIN UPDATE meta SET value = '1' WHERE key = 'session_seq'; END"
  );
  db.close();
  const manifestFile = path.join(folder, 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));
  const entry = manifest.files.find(file => file.name === 'control.sqlite');
  const bytes = fs.readFileSync(copy);
  entry.bytes = bytes.length;
  entry.sha256 = (await import('node:crypto')).createHash('sha256').update(bytes).digest('hex');
  fs.writeFileSync(manifestFile, JSON.stringify(manifest));
  const listed = await admin(withDir(directory, 'snapshots', '--verify'));
  assert.equal(listed.code, 1, listed.err);
  assert.match(
    listed.out,
    new RegExp(
      `${id} .*DAMAGED: control\\.sqlite holds trigger keep_sessions, which Uptime Goblin never creates`
    )
  );
  const before = fingerprint(directory, ['goblin.lock', 'orbit.lock']);
  const restore = await admin(withDir(directory, 'restore-snapshot', id));
  assert.equal(restore.code, 1, restore.err);
  assert.match(restore.err, /cannot be restored: control\.sqlite holds trigger keep_sessions/);
  assert.deepEqual(
    fingerprint(directory, ['goblin.lock', 'orbit.lock']),
    before,
    'nothing changed'
  );
});

// A trigger in `file` whose catalog row says `type` (SQL): SQLite compares the type without
// regard to case and only up to a NUL, so it runs inside Uptime Goblin's writes like any other.
function plantDisguised(file, type) {
  const db = new DatabaseSync(file, { defensive: false });
  try {
    db.exec(
      "CREATE TRIGGER keep_sessions AFTER UPDATE ON meta BEGIN UPDATE meta SET value = '1' WHERE key = 'session_seq'; END"
    );
    db.exec('PRAGMA writable_schema=ON');
    db.exec(`UPDATE sqlite_master SET type = ${type} WHERE name = 'keep_sessions'`);
    db.exec('PRAGMA writable_schema=OFF');
  } finally {
    db.close();
  }
}

test('check-data reports a trigger whose catalog row says TRIGGER, and any other row that is not a table or an index', async t => {
  const directory = await started(t);
  // A catalog that matched type = 'trigger' did not list this trigger: check-data exited 0. A
  // virtual table is a table SQLite does not write as one either.
  plantDisguised(path.join(directory, 'control.sqlite'), "'TRIGGER'");
  const history = new DatabaseSync(path.join(directory, 'history.sqlite'));
  history.exec('CREATE VIRTUAL TABLE spatial USING rtree(id, a, b)');
  history.close();
  const found = await admin(withDir(directory, 'check-data'));
  assert.equal(found.code, 1);
  assert.match(
    found.out,
    /PROBLEM: control\.sqlite has a catalog entry keep_sessions of type "TRIGGER" that Uptime Goblin does not create/
  );
  assert.match(
    found.out,
    /PROBLEM: history\.sqlite has a catalog entry spatial of type "table" that Uptime Goblin does not create/
  );
  const json = (await admin(withDir(directory, 'check-data', '--json'))).json();
  assert.deepEqual(json.control.triggers, []);
  assert.deepEqual(json.control.others, [{ type: 'TRIGGER', name: 'keep_sessions' }]);
  assert.deepEqual(json.history.others, [{ type: 'table', name: 'spatial' }]);
});

test('a snapshot whose database holds a trigger its catalog row spells another way is damaged: verify names it and restore-snapshot refuses it', async t => {
  const directory = await started(t);
  const made = await admin(withDir(directory, 'snapshot', '--json'), {
    env: { GOBLIN_SECRET_KEY: hexKey },
    directory,
  });
  assert.equal(made.code, 0, made.err);
  const id = made.json().id;
  // Verified and restored as it was, the restore undid every later session revocation.
  const folder = path.join(directory, 'snapshots', id);
  const copy = path.join(folder, 'control.sqlite');
  plantDisguised(copy, "'trigger' || char(0)");
  const manifestFile = path.join(folder, 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));
  const entry = manifest.files.find(file => file.name === 'control.sqlite');
  const bytes = fs.readFileSync(copy);
  entry.bytes = bytes.length;
  entry.sha256 = (await import('node:crypto')).createHash('sha256').update(bytes).digest('hex');
  fs.writeFileSync(manifestFile, JSON.stringify(manifest));
  const listed = await admin(withDir(directory, 'snapshots', '--verify'));
  assert.equal(listed.code, 1, listed.err);
  assert.match(
    listed.out,
    new RegExp(
      `${id} .*DAMAGED: control\\.sqlite holds catalog entry keep_sessions of type "trigger\\\\u0000", which Uptime Goblin never creates`
    )
  );
  const before = fingerprint(directory, ['goblin.lock', 'orbit.lock']);
  const restore = await admin(withDir(directory, 'restore-snapshot', id));
  assert.equal(restore.code, 1, restore.err);
  assert.match(
    restore.err,
    /cannot be restored: control\.sqlite holds catalog entry keep_sessions of type "trigger\\u0000"/
  );
  assert.deepEqual(
    fingerprint(directory, ['goblin.lock', 'orbit.lock']),
    before,
    'nothing changed'
  );
});

test('key status, rewrap after a master-key change, rotate, and reset only for a lost key', async t => {
  const directory = await started(t);
  const run = (args, env = {}) => admin(withDir(directory, 'key', ...args), { env, directory });
  const ok = await run(['status', '--json'], { GOBLIN_SECRET_KEY: hexKey });
  assert.equal(ok.code, 0);
  assert.equal(ok.json().matches, true);
  assert.equal(ok.json().keyring.length, 4);
  assert.equal(ok.json().key.source, 'env');
  // No key in this command's environment is not a lost key: Uptime Goblin may have one this command
  // cannot see (natively GOBLIN_SECRET_KEY_FILE in /etc/uptime-goblin.env). Never PROBLEM or a reset.
  const missing = await run(['status']);
  assert.equal(missing.code, 1);
  assert.match(
    missing.out,
    /^Master key: not found by this command\. No encryption key reached this command \(checked GOBLIN_SECRET_KEY, GOBLIN_SECRET_KEY_FILE, .*\)\. goblin-admin reads the key from its own environment, not from \/etc\/uptime-goblin\.env, which only systemd reads for Uptime Goblin\. Run it with the key file Uptime Goblin uses \(GOBLIN_SECRET_KEY_FILE in \/etc\/uptime-goblin\.env\): sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=\/etc\/uptime-goblin\/secret\.key node \S+ key status --data-dir \S+ \(the native install; Docker Compose and other installs: docs\/installation\.md#goblin-admin\)\. If Uptime Goblin loads the key as a systemd credential \(LoadCredential=orbit-secret-key:…\), run the command in a transient service that loads the same credential instead \(sudo systemd-run … -p LoadCredential=…: docs\/installation\.md#goblin-admin\); never make the credential's file readable by uptime-goblin\.$/m
  );
  assert.match(missing.out, /^Not checked: whether the key opens the keyring\./m);
  assert.doesNotMatch(missing.out, /PROBLEM|key reset/);
  assert.equal((await run(['status', '--json'])).json().notFound.checked.length, 5);
  const wrong = await run(['status'], { GOBLIN_SECRET_KEY: otherKey });
  assert.equal(wrong.code, 1);
  assert.match(wrong.out, /does not match this data/);
  assert.equal((await run([])).code, 2);
  assert.equal((await run(['explode'])).code, 2);
  assert.equal((await run(['rewrap', '--purpose', 'seal'], { GOBLIN_SECRET_KEY: hexKey })).code, 2);

  // A new master key, with the old one as the previous key: rewrap, then the old one is done.
  const moving = await run(['rewrap'], {
    GOBLIN_SECRET_KEY: otherKey,
    GOBLIN_SECRET_KEY_PREVIOUS: hexKey,
  });
  assert.equal(moving.code, 0, moving.err);
  assert.match(moving.out, /Rewrapped 4 data key\(s\)/);
  assert.match((await run(['rewrap'], { GOBLIN_SECRET_KEY: otherKey })).out, /nothing to do/);
  assert.equal((await run(['status'], { GOBLIN_SECRET_KEY: otherKey })).code, 0);

  // Rotate: new keys for one purpose, and bad purposes are refused.
  const rotated = await run(['rotate', '--purpose', 'seal', '--json'], {
    GOBLIN_SECRET_KEY: otherKey,
  });
  assert.equal(rotated.code, 0, rotated.err);
  assert.equal(rotated.json().retired.length, 1);
  assert.equal(
    (await run(['rotate', '--purpose', 'nope'], { GOBLIN_SECRET_KEY: otherKey })).code,
    2
  );
  const status = (await run(['status', '--json'], { GOBLIN_SECRET_KEY: otherKey })).json();
  assert.equal(status.keyring.length, 5);
  assert.equal(status.keyring.filter(item => item.retiredAt).length, 1);

  // Reset: refused without confirmation, refused when the key is not lost, then done.
  assert.equal((await run(['reset'])).code, 2);
  const notLost = await run(['reset', '--confirm-lost-key'], { GOBLIN_SECRET_KEY: otherKey });
  assert.equal(notLost.code, 1);
  assert.match(notLost.err, /nothing is lost/);
  const reset = await run(['reset', '--confirm-lost-key', '--json'], { GOBLIN_SECRET_KEY: hexKey });
  assert.equal(reset.code, 0, reset.err);
  assert.equal(reset.json().discarded, 5);
  assert.equal((await run(['status'], { GOBLIN_SECRET_KEY: hexKey })).code, 0);
  // With no key configured at all, reset makes <data>/secret.key the key only when told to:
  // Uptime Goblin may read a key this command cannot see, and a reset under another one would leave it
  // refusing to start.
  const unseen = await run(['reset', '--confirm-lost-key']);
  assert.equal(unseen.code, 2, unseen.err);
  assert.match(
    unseen.err,
    /No encryption key reached this command .* add --use-data-dir-key to make \S+secret\.key the key\. No key was written and the keyring was not changed\.$/m
  );
  assert.equal(fs.existsSync(path.join(directory, 'secret.key')), false);
  assert.equal(
    (await run(['status'], { GOBLIN_SECRET_KEY: hexKey })).code,
    0,
    'the keyring is as it was'
  );
  const generated = await run(['reset', '--confirm-lost-key', '--use-data-dir-key', '--json']);
  assert.equal(generated.code, 0, generated.err);
  assert.equal(generated.json().source, 'generated');
  assert.ok(fs.existsSync(path.join(directory, 'secret.key')));
  const control = openControl(directory, { release, env: {} });
  t.after(() => control.close());
  const key = Buffer.from(
    fs.readFileSync(path.join(directory, 'secret.key'), 'utf8').trim(),
    'hex'
  );
  assert.equal((await Keyring.check(control.keyringStore, { key })).keys, 4);
});

test('key reset takes <data>/secret.key only with --use-data-dir-key; in a container the texts name the Compose files', async t => {
  const directory = await started(t);
  const own = path.join(path.resolve(directory), 'secret.key');
  const run = (args, options = {}) =>
    admin(withDir(directory, 'key', ...args), { directory, ...options });
  // --use-data-dir-key belongs to reset alone.
  for (const action of ['status', 'rotate', 'rewrap'])
    assert.equal((await run([action, '--use-data-dir-key'])).code, 2, action);
  // A data-directory key that opens the keyring: nothing is lost, and nothing changes.
  fs.writeFileSync(own, `${hexKey}\n`, { mode: 0o600 });
  const before = fingerprint(directory, ['goblin.lock', 'orbit.lock']);
  const opens = await run(['reset', '--confirm-lost-key']);
  assert.equal(opens.code, 1, opens.err);
  assert.match(
    opens.err,
    /The key in \S+secret\.key opens this keyring, so nothing is lost: give Uptime Goblin that key \(natively, copy it to \/etc\/uptime-goblin\/secret\.key, root:uptime-goblin 0440, which GOBLIN_SECRET_KEY_FILE in \/etc\/uptime-goblin\.env names\), or use goblin-admin key rotate\./
  );
  // One that does not: refused without the flag (Uptime Goblin may read another key), then reset.
  fs.writeFileSync(own, `${otherKey}\n`);
  const stale = await run(['reset', '--confirm-lost-key']);
  assert.equal(stale.code, 2, stale.err);
  assert.match(
    stale.err,
    /^goblin-admin key: The only key that reached this command is \S+secret\.key, in the data directory\. /
  );
  assert.match(
    stale.err,
    /sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=\/etc\/uptime-goblin\/secret\.key node /
  );
  assert.deepEqual(fingerprint(directory, ['goblin.lock', 'orbit.lock']), {
    ...before,
    'secret.key': fingerprint(directory)['secret.key'],
  });
  // In a container the way to give it the key is the Compose override, not sudo.
  fs.rmSync(own);
  const boxed = await run(['reset', '--confirm-lost-key'], { container: true });
  assert.equal(boxed.code, 2, boxed.err);
  assert.match(
    boxed.err,
    /docker compose -f compose\.yaml -f compose\.secret\.yaml run --rm --no-deps uptime-goblin node lib\/cli\/goblin-admin\.mjs key reset --confirm-lost-key\. Only for an Uptime Goblin that has no other key source/
  );
  assert.doesNotMatch(boxed.err, /sudo/);
  const boxedStatus = await run(['status'], { container: true });
  assert.equal(boxedStatus.code, 1);
  assert.match(boxedStatus.out, /COMPOSE_FILE=compose\.yaml:compose\.secret\.yaml in \.env/);
  // With the flag: generated in the data directory and made the key.
  const generated = await run(['reset', '--confirm-lost-key', '--use-data-dir-key', '--json']);
  assert.equal(generated.code, 0, generated.err);
  assert.equal(generated.json().source, 'generated');
  assert.equal(generated.json().file, own);
  // A key given to the command wins over the flag, as it would for Uptime Goblin: the source order.
  fs.rmSync(own);
  const given = await run(['reset', '--confirm-lost-key', '--use-data-dir-key', '--json'], {
    env: { GOBLIN_SECRET_KEY: hexKey },
  });
  assert.equal(given.code, 0, given.err);
  assert.equal(given.json().source, 'env');
  assert.ok(!fs.existsSync(own));
});

// Review of 9a7d6e5: the check of compose.secret.yaml runs this in the 1.5 image (with the
// Compose secret mounted when orbit_secret_key exists). It names the recipe from the keys tried
// on the keyring, never from which files exist, and only reads: it runs while Uptime Goblin holds
// goblin.lock, and as root.
test('key compose-check: the recipe from the keys tried on the keyring, and why; read-only, also while Uptime Goblin runs', async t => {
  const directory = await started(t);
  const secrets = temporary(t);
  const own = path.join(directory, 'secret.key'),
    secret = path.join(secrets, 'orbit_secret_key');
  const check = (options = {}) =>
    admin(withDir(directory, 'key', 'compose-check', ...(options.json ? ['--json'] : [])), {
      directory,
      secrets,
      container: true,
      ...options,
    });
  const put = (file, hex) => {
    fs.rmSync(file, { force: true });
    if (hex) fs.writeFileSync(file, `${hex}\n`, { mode: 0o400 });
  };
  const print = hex => keyFingerprint(Buffer.from(hex, 'hex'));
  const before = fingerprint(directory, ['goblin.lock', 'orbit.lock']);
  // The keyring is sealed with hexKey. Neither file there: no key here opens the data.
  const restore = await check();
  assert.equal(restore.code, 0, restore.err);
  assert.equal(restore.out.split('\n')[0], 'RESTORE');
  // The secret that opens it, beside an older key left in the volume: KEEP, and (A67) the line
  // that deletes that key, alone on the third line so that it is copied whole.
  put(secret, hexKey);
  put(own, otherKey);
  const keep = await check();
  assert.equal(keep.code, 0, keep.err);
  assert.deepEqual(keep.out.split('\n'), [
    'KEEP',
    `The Compose secret orbit_secret_key (${secret}, fingerprint ${print(hexKey)}) opens this data: keep orbit_secret_key and COMPOSE_FILE, make no key and copy none. ${own} (fingerprint ${print(otherKey)}) is there too: an older key, which Uptime Goblin does not use and which opens none of this data's keys (as after key rewrap). Every copy of the volume carries it: once Uptime Goblin runs with orbit_secret_key (COMPOSE_FILE in .env, then docker compose up -d), the line below deletes it, only while Uptime Goblin's key opens every data key and that file opens none.`,
    'docker compose exec uptime-goblin node lib/cli/goblin-admin.mjs key remove-data-copy --unused',
    '',
  ]);
  // A copy of the secret's key in the volume (the copy recipe stopped before its last line): that
  // last line.
  put(own, hexKey);
  assert.deepEqual((await check()).out.split('\n').slice(2), [
    'docker compose exec uptime-goblin node lib/cli/goblin-admin.mjs key remove-data-copy',
    '',
  ]);
  // The keys the other way round: MOVE (the volume's key put in a new file, the old one aside).
  put(secret, otherKey);
  put(own, hexKey);
  assert.deepEqual((await check({ json: true })).json(), {
    verdict: 'MOVE',
    reason: `The Compose secret orbit_secret_key (${secret}, fingerprint ${print(otherKey)}) does not open this data, and ${own} (fingerprint ${print(hexKey)}) does: take the MOVE recipe of compose.secret.yaml, which puts that key in a new orbit_secret_key and keeps the current one as orbit_secret_key.unused, then start Uptime Goblin with docker compose up -d --force-recreate.`,
    secret: print(otherKey),
    volume: print(hexKey),
    command: null,
  });
  put(secret, null);
  // Read-only: as root, and while Uptime Goblin holds goblin.lock.
  assert.equal((await check({ uid: 0 })).out.split('\n')[0], 'COPY');
  const lock = acquireLock(directory);
  try {
    const running = await check();
    assert.equal(running.code, 0, running.err);
    assert.equal(running.out.split('\n')[0], 'COPY');
  } finally {
    lock.release();
  }
  // A secret it cannot read as a key: exit status 1, nothing compared.
  fs.writeFileSync(secret, 'not a key\n', { mode: 0o400 });
  const unreadable = await check();
  assert.equal(unreadable.code, 1);
  assert.equal(unreadable.out, '');
  assert.match(
    unreadable.err,
    /^goblin-admin key: The Compose secret \(.+\) must be 32 random bytes .* Nothing was compared: make no key and copy none until this check can read it as a key\.\n$/
  );
  put(secret, null);
  put(own, null);
  assert.deepEqual(
    fingerprint(directory, ['goblin.lock', 'orbit.lock']),
    before,
    'it changed nothing'
  );
  // Nothing sealed yet (a data directory 1.5 has not run on): NEW.
  const fresh = temporary(t);
  const none = await admin(withDir(fresh, 'key', 'compose-check'), { directory: fresh });
  assert.equal(none.out.split('\n')[0], 'NEW');
  assert.deepEqual(fs.readdirSync(fresh), []);
  assert.match((await admin(['key', '--help'])).out, /^compose-check$/m);
});

// Every command that reads the master key reads it as Uptime Goblin's start does (resolveKey's
// readKeyFile; compose-check's own reads too): a key file that is a FIFO, or a link to one, is
// opened without waiting and refused by what it is. A blocking open waited for a writer for
// good, the offline commands with goblin.lock held.
test('goblin-admin never waits on a key file that is a FIFO or a link to one: the key commands and verify-audit refuse at once, naming it, and change nothing', async t => {
  const entryPoint = new URL('../../lib/cli/goblin-admin.mjs', import.meta.url).href;
  const sources = {
    file: 'GOBLIN_SECRET_KEY_FILE',
    previous: 'GOBLIN_SECRET_KEY_PREVIOUS_FILE',
    credential: 'The systemd credential',
    secret: 'The Compose secret',
    own: 'The data-directory key',
  };
  for (const [where, label] of Object.entries(sources)) {
    const directory = await started(t);
    const keys = temporary(t),
      credentials = path.join(keys, 'credentials'),
      secrets = path.join(keys, 'secrets');
    fs.mkdirSync(credentials);
    fs.mkdirSync(secrets);
    const entry = {
      file: path.join(keys, 'key'),
      previous: path.join(keys, 'previous'),
      credential: path.join(credentials, 'orbit-secret-key'),
      secret: path.join(secrets, 'orbit_secret_key'),
      own: path.join(directory, 'secret.key'),
    }[where];
    const env = {
      ...(where === 'file' ? { GOBLIN_SECRET_KEY_FILE: entry } : {}),
      ...(where === 'previous'
        ? { GOBLIN_SECRET_KEY: hexKey, GOBLIN_SECRET_KEY_PREVIOUS_FILE: entry }
        : {}),
    };
    // [arguments, exit status, the stream and the start of the line that names the file]
    const runs = [
      [['key', 'status'], exitCodes.failed, 'out', 'PROBLEM: '],
      [['key', 'rewrap'], exitCodes.refused, 'err', 'goblin-admin key: '],
      [['key', 'rotate'], exitCodes.refused, 'err', 'goblin-admin key: '],
      [['key', 'reset', '--confirm-lost-key'], exitCodes.refused, 'err', 'goblin-admin key: '],
      [['key', 'remove-data-copy'], exitCodes.failed, 'err', 'goblin-admin key: '],
      [['verify-audit'], exitCodes.failed, 'err', 'goblin-admin verify-audit: '],
      // The check of compose.secret.yaml reads the Compose secret and <data>/secret.key only.
      ...(where === 'secret' || where === 'own'
        ? [[['key', 'compose-check'], exitCodes.failed, 'err', 'goblin-admin key: ']]
        : []),
    ];
    const before = fingerprint(directory, ['goblin.lock', 'orbit.lock', 'secret.key']);
    for (const linked of [false, true]) {
      const fifo = linked ? path.join(keys, 'target.fifo') : entry;
      const name = `${where}${linked ? ' (a link to a FIFO)' : ''}`;
      fs.rmSync(entry, { force: true });
      fs.rmSync(fifo, { force: true });
      assert.equal(spawnSync('mkfifo', [fifo]).status, 0);
      if (linked) fs.symlinkSync(fifo, entry);
      // In a child with a deadline: a blocking open would hang this process for good. It prints
      // each command's outcome as it ends, so a hang shows which command it was.
      const child = spawnSync(
        process.execPath,
        [
          '--input-type=module',
          '-e',
          `import { main } from ${JSON.stringify(entryPoint)};
           const [runs, env, credentialsDirectory, secretsDirectory, proc] = JSON.parse(process.argv[1]);
           for (const args of runs) {
             let out = '', err = '';
             const code = await main(args, {
               env: { ...env },
               uid: 1000,
               container: false,
               proc,
               stdout: text => (out += text),
               stderr: text => (err += text),
               keySources: { credentialsDirectory, secretsDirectory },
             });
             console.log(JSON.stringify({ code, out, err }));
           }`,
          JSON.stringify([
            runs.map(([args]) => withDir(directory, ...args)),
            env,
            credentials,
            secrets,
            noProcesses,
          ]),
        ],
        { encoding: 'utf8', timeout: 10_000, killSignal: 'SIGKILL' }
      );
      const results = child.stdout.split('\n').filter(Boolean).map(JSON.parse);
      assert.equal(
        child.error,
        undefined,
        `${name}: goblin-admin ${runs[results.length]?.[0].join(' ')} must return before the deadline`
      );
      assert.equal(child.status, 0, `${name}: ${child.stderr}`);
      assert.equal(results.length, runs.length);
      for (const [index, [args, code, stream, start]] of runs.entries()) {
        const result = results[index],
          command = `${name}: goblin-admin ${args.join(' ')}`;
        assert.equal(result.code, code, `${command}: ${result.out}${result.err}`);
        assert.ok(
          result[stream]
            .split('\n')
            .some(line => line.startsWith(`${start}${label} (${entry}) is not a file.`)),
          `${command}: ${result.out}${result.err}`
        );
      }
      assert.ok(fs.statSync(fifo).isFIFO(), `${name}: the FIFO is left as it was`);
      assert.equal(fs.lstatSync(entry).isSymbolicLink(), linked, `${name}: so is the entry`);
    }
    fs.rmSync(entry, { force: true });
    assert.deepEqual(
      fingerprint(directory, ['goblin.lock', 'orbit.lock', 'secret.key']),
      before,
      `${where}: nothing changed`
    );
    // The keyring as it was: the key it was sealed with still opens every data key.
    const status = await admin(withDir(directory, 'key', 'status'), {
      env: { GOBLIN_SECRET_KEY: hexKey },
      directory,
    });
    assert.equal(status.code, 0, status.out + status.err);
    assert.match(status.out, /^The key opens every data key\.$/m);
  }
});

// A66: the Compose copy and MOVE recipes ended with docker compose exec uptime-goblin rm
// /app/data/secret.key, and their lines run one by one when a block is pasted whole: in the
// COPY state (Uptime Goblin running without the override, the start under it failed for want of a key
// file) or in a container that had just mounted another key, that rm deleted the only key that
// opens the data. key remove-data-copy takes its place: it runs beside a live Uptime Goblin (goblin.lock
// held) and deletes <data>/secret.key only while the key it is given, Uptime Goblin's own under docker
// compose exec, comes from another file, holds the same key and opens the data.
test('key remove-data-copy deletes <data>/secret.key only while another file holds the same key and opens the data; otherwise it says why and deletes nothing', async t => {
  const directory = await started(t);
  const secrets = temporary(t);
  const own = path.join(directory, 'secret.key'),
    secret = path.join(secrets, 'orbit_secret_key');
  const print = hex => keyFingerprint(Buffer.from(hex, 'hex'));
  const put = (file, hex, mode = 0o400) => {
    fs.rmSync(file, { force: true });
    if (hex) fs.writeFileSync(file, `${hex}\n`, { mode });
  };
  const remove = (options = {}) =>
    admin(withDir(directory, 'key', 'remove-data-copy', ...(options.json ? ['--json'] : [])), {
      directory,
      secrets,
      container: true,
      ...options,
    });
  // Each refusal: exit status 1, why, "Nothing was deleted.", the line to run instead (if any)
  // alone on the last line, and the volume as it was.
  const kept = async (expected, options = {}, command = null) => {
    const before = fingerprint(directory, ['goblin.lock', 'orbit.lock']);
    const result = await remove(options);
    assert.equal(result.code, exitCodes.failed, result.out + result.err);
    assert.equal(result.out, '');
    assert.equal(
      result.err,
      `goblin-admin key: ${expected} Nothing was deleted.\n${command ? `${command}\n` : ''}`
    );
    assert.deepEqual(
      fingerprint(directory, ['goblin.lock', 'orbit.lock']),
      before,
      'nothing changed'
    );
    return result;
  };
  const lock = acquireLock(directory);
  t.after(() => lock.release());
  const check = `Run the check of compose.secret.yaml (docs/installation.md#encryption-key) and take what it says.`;

  // The COPY state: Uptime Goblin runs with the key it generated, and no Compose secret is mounted (the
  // MOVE or copy block pasted there: its start failed, the bind source missing). The key Uptime Goblin
  // is given is that file itself.
  put(own, hexKey, 0o600);
  await kept(
    `The key this command is given is ${own} itself: no other key source reached it (checked GOBLIN_SECRET_KEY, GOBLIN_SECRET_KEY_FILE, ${path.join(directory, 'no-credentials', 'orbit-secret-key')}, ${secret}, ${own}), so that file is not a copy. Under Docker Compose, Uptime Goblin has the Compose secret only once it runs with compose.secret.yaml (COMPOSE_FILE=compose.yaml:compose.secret.yaml in .env, then docker compose up -d), and this command must run in its container: the line below.`,
    {},
    'docker compose exec uptime-goblin node lib/cli/goblin-admin.mjs key remove-data-copy'
  );
  // Natively it names the key file to give it.
  await kept(
    `The key this command is given is ${own} itself: no other key source reached it (checked GOBLIN_SECRET_KEY, GOBLIN_SECRET_KEY_FILE, ${path.join(directory, 'no-credentials', 'orbit-secret-key')}, ${secret}, ${own}), so that file is not a copy. Give this command the key file Uptime Goblin uses, as the line below does (the native install; Docker Compose and other installs: docs/installation.md#goblin-admin).`,
    { container: false },
    `sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key node ${script} key remove-data-copy --data-dir ${directory}`
  );
  // The MOVE state: a container that mounts the new key C, which does not open the data (A66:
  // the exec reached such a container within its second of life, and rm deleted A).
  put(secret, otherKey);
  await kept(
    `The Compose secret (${secret}) (fingerprint ${print(otherKey)}) does not open this data, so ${own} may be the only key that does. ${check}`
  );
  // Neither opens it, though the bytes are the same.
  put(own, otherKey, 0o600);
  await kept(
    `The Compose secret (${secret}) (fingerprint ${print(otherKey)}) does not open this data, so ${own} may be the only key that does. ${check}`
  );
  // After key rewrap: the secret opens the data, and <data>/secret.key is another, older key,
  // which opens none of the data keys: the line with --unused (A67).
  put(secret, hexKey);
  await kept(
    `${own} (fingerprint ${print(otherKey)}) is not a copy of the key this command is given, the Compose secret (${secret}) (fingerprint ${print(hexKey)}): it deletes only a copy of that key. ${own} opens none of this data's keys, which the Compose secret (${secret}) opens: it is an older key, which Uptime Goblin does not use. Delete it with the line below.`,
    {},
    'docker compose exec uptime-goblin node lib/cli/goblin-admin.mjs key remove-data-copy --unused'
  );
  // A data-directory file that is not a key, beside a secret that opens the data.
  fs.rmSync(own);
  fs.writeFileSync(own, 'not a key\n', { mode: 0o600 });
  await kept(
    `The data-directory key (${own}) must be 32 random bytes written as 64 hexadecimal digits or in base64 (for example the output of "openssl rand -hex 32"). It may be the only key that opens this data.`
  );
  // The source is that very file: by its path, a hard link, a symbolic link.
  put(own, hexKey, 0o600);
  put(secret, null);
  const outside = temporary(t);
  const sameFile = label =>
    `${label} is ${own} itself (its path, a link or a mount of that file), so deleting it would delete the key Uptime Goblin reads. Copy the key to a file outside the data directory and make that the key's source first.`;
  await kept(sameFile(`GOBLIN_SECRET_KEY_FILE (${own})`), {
    env: { GOBLIN_SECRET_KEY_FILE: own },
  });
  const hard = path.join(outside, 'hard.key');
  fs.linkSync(own, hard);
  await kept(sameFile(`GOBLIN_SECRET_KEY_FILE (${hard})`), {
    env: { GOBLIN_SECRET_KEY_FILE: hard },
  });
  fs.rmSync(hard);
  const soft = path.join(outside, 'soft.key');
  fs.symlinkSync(own, soft);
  await kept(sameFile(`GOBLIN_SECRET_KEY_FILE (${soft})`), {
    env: { GOBLIN_SECRET_KEY_FILE: soft },
  });
  fs.rmSync(soft);
  // A systemd credential: systemd may load it from that file, which no process can see.
  const credentials = temporary(t);
  put(path.join(credentials, 'orbit-secret-key'), hexKey);
  await kept(
    `The systemd credential (${path.join(credentials, 'orbit-secret-key')}) is a copy systemd makes at each start, and this command cannot see whether LoadCredential= loads it from ${own}. Once the credential no longer comes from ${own} and Uptime Goblin has started with it, delete ${own} by hand.`,
    { credentials, container: false }
  );
  // A Compose secret it cannot read as a key: nothing compared.
  fs.writeFileSync(secret, 'not a key\n', { mode: 0o400 });
  const garbled = await remove();
  assert.equal(garbled.code, exitCodes.failed);
  assert.match(
    garbled.err,
    /^goblin-admin key: The Compose secret \(.+\) must be 32 random bytes .* Nothing was deleted\.\n$/
  );
  assert.equal(fs.readFileSync(own, 'utf8'), `${hexKey}\n`);
  // <data>/secret.key a symbolic link: no key of its own, never deleted.
  put(secret, hexKey);
  fs.rmSync(own);
  fs.symlinkSync(secret, own);
  await kept(`${own} is not a regular file, so it is no key Uptime Goblin generated.`);
  fs.rmSync(own);
  // Nothing there.
  await kept(`There is no ${own}.`);
  // As root: it changes the data directory, so it refuses and prints the command that works.
  put(own, hexKey, 0o600);
  const root = await remove({ uid: 0, container: false });
  assert.equal(root.code, exitCodes.usage);
  assert.match(
    root.err,
    new RegExp(
      `must not run as root .*: sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key node ${script.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} key remove-data-copy --data-dir `
    )
  );
  assert.ok(fs.existsSync(own));
  // The Compose secret deleted on the host while the command runs: in a container on an OrbStack
  // host a stat still shows it for some tens of milliseconds, while opening it again fails. The
  // message names the secret, which changed, not the volume's copy, which did not.
  const { openSync } = fs;
  let opens = 0;
  const open = t.mock.method(fs, 'openSync', (file, ...rest) => {
    if (file === secret && ++opens > 1)
      throw Object.assign(new Error(`ENOENT: no such file or directory, open '${file}'`), {
        code: 'ENOENT',
      });
    return openSync(file, ...rest);
  });
  try {
    const changed = `The Compose secret (${secret}) changed while this command checked it (it was deleted, replaced or given another key, or can no longer be read), so it is no lasting copy of the key.`;
    await kept(
      `${changed} Put orbit_secret_key back if it was removed, start Uptime Goblin again (docker compose up -d), then run this command again.`
    );
    assert.equal(opens, 2, 'read when found, and opened again before a deletion');
    opens = 0;
    await kept(
      `${changed} Run this command again once that file holds the key Uptime Goblin uses.`,
      {
        container: false,
      }
    );
  } finally {
    open.mock.restore();
  }
  assert.equal(fs.readFileSync(own, 'utf8'), `${hexKey}\n`);

  // The copy recipe's end: the Compose secret holds the same key (copied byte for byte) and
  // opens the data, while Uptime Goblin runs (goblin.lock held): the volume's copy goes, the secret stays.
  const deleted = await remove({ json: true });
  assert.equal(deleted.code, 0, deleted.err);
  assert.deepEqual(deleted.json(), {
    deleted: own,
    source: 'secrets',
    file: secret,
    fingerprint: print(hexKey),
  });
  assert.equal(fs.existsSync(own), false);
  assert.equal(fs.readFileSync(secret, 'utf8'), `${hexKey}\n`, 'the secret, byte for byte');
  // The same key written another way (base64) is the same key.
  fs.writeFileSync(own, `${Buffer.from(hexKey, 'hex').toString('base64')}\n`, { mode: 0o600 });
  const again = await remove();
  assert.equal(again.code, 0, again.err);
  assert.equal(
    again.out,
    `Deleted ${own}: the Compose secret (${secret}) holds the same key (fingerprint ${print(hexKey)}) and opens this data. Keep a backup of that key apart from the data.\n`
  );
  // GOBLIN_SECRET_KEY_FILE outside the data directory and GOBLIN_SECRET_KEY are other sources too.
  put(secret, null);
  const keyFile = path.join(outside, 'orbit.key');
  put(keyFile, hexKey);
  put(own, hexKey, 0o600);
  assert.equal((await remove({ env: { GOBLIN_SECRET_KEY_FILE: keyFile } })).code, 0);
  assert.equal(fs.existsSync(own), false);
  put(own, hexKey, 0o600);
  assert.equal((await remove({ env: { GOBLIN_SECRET_KEY: hexKey } })).code, 0);
  assert.equal(fs.existsSync(own), false);

  // No keyring yet: nothing tells whether the key opens the data.
  const fresh = temporary(t);
  put(path.join(fresh, 'secret.key'), hexKey, 0o600);
  put(secret, hexKey);
  const unsealed = await admin(withDir(fresh, 'key', 'remove-data-copy'), {
    directory: fresh,
    secrets,
    container: true,
  });
  assert.equal(unsealed.code, exitCodes.failed);
  assert.equal(
    unsealed.err,
    `goblin-admin key: This data has no keyring yet, so this command cannot check that the Compose secret (${secret}) opens it. Start Uptime Goblin with that key once, then run this command again. Nothing was deleted.\n`
  );
  assert.ok(fs.existsSync(path.join(fresh, 'secret.key')));
  const { kindFor } = await commands.key();
  assert.equal(kindFor({}, ['remove-data-copy']), 'online');
  assert.match((await admin(['key', '--help'])).out, /^remove-data-copy$/m);
});

// A67: after key rewrap moved the data to another key, the older <data>/secret.key stayed in
// every copy of the data directory: the start warning said it "is not used" and to delete it, with
// no command; key remove-data-copy keeps it on purpose (it is no copy); the check said only that
// Uptime Goblin does not use it, and compose.secret.yaml "keep that file". key remove-data-copy --unused
// deletes it only while the key this command is given (Uptime Goblin's own under docker compose exec)
// comes from another source and opens every data key, and the file holds another key that opens
// none. The lines Uptime Goblin's start warning and the check print are run here as printed.
test('key remove-data-copy --unused deletes an older key only while the key it is given opens every data key and that file opens none; the lines Uptime Goblin prints run as printed', async t => {
  const { resolveKey } = await import('../../lib/keyring.mjs');
  const directory = await started(t);
  const secrets = temporary(t);
  const own = path.join(directory, 'secret.key'),
    secret = path.join(secrets, 'orbit_secret_key');
  const print = hex => keyFingerprint(Buffer.from(hex, 'hex'));
  const put = (file, hex, mode = 0o400) => {
    fs.rmSync(file, { force: true });
    if (hex) fs.writeFileSync(file, `${hex}\n`, { mode });
  };
  const unused = (options = {}, extra = []) =>
    admin(withDir(directory, 'key', 'remove-data-copy', '--unused', ...extra), {
      directory,
      secrets,
      container: true,
      ...options,
    });
  const kept = async (expected, options = {}, command = null) => {
    const before = fingerprint(directory);
    const result = await unused(options);
    assert.equal(result.code, exitCodes.failed, result.out + result.err);
    assert.equal(result.out, '');
    assert.equal(
      result.err,
      `goblin-admin key: ${expected} Nothing was deleted.\n${command ? `${command}\n` : ''}`
    );
    assert.deepEqual(fingerprint(directory), before, 'nothing changed');
  };
  const check = `Run the check of compose.secret.yaml (docs/installation.md#encryption-key) and take what it says.`;
  // The data is sealed with hexKey, the key Uptime Goblin generated (A); the key change to the Compose
  // secret (B, otherKey) has not run yet.
  put(own, hexKey, 0o600);
  put(secret, otherKey);
  {
    const lock = acquireLock(directory);
    try {
      await kept(
        `The Compose secret (${secret}) (fingerprint ${print(otherKey)}) does not open every data key, so ${own} may be the key that opens some of them. ${check}`
      );
      await kept(
        `GOBLIN_SECRET_KEY_FILE (${secret}) (fingerprint ${print(otherKey)}) does not open every data key, so ${own} may be the key that opens some of them. Give this command the key file Uptime Goblin uses, and finish a key change with goblin-admin key rewrap first (docs/installation.md#goblin-admin).`,
        { container: false, env: { GOBLIN_SECRET_KEY_FILE: secret } }
      );
    } finally {
      lock.release();
    }
  }
  // The key change, as docs/installation.md#goblin-admin gives it: B wraps every data key now.
  const rewrap = await admin(withDir(directory, 'key', 'rewrap'), {
    directory,
    secrets,
    env: { GOBLIN_SECRET_KEY_PREVIOUS_FILE: own },
  });
  assert.equal(rewrap.code, 0, rewrap.err);
  const lock = acquireLock(directory);
  t.after(() => lock.release());

  // What Uptime Goblin's start says in its container: A is an older key, and the line to delete it.
  const warnings = resolveKey({
    env: {},
    directory,
    keyringExists: true,
    credentialsDirectory: path.join(directory, 'no-credentials'),
    secretsDirectory: secrets,
  }).warnings;
  const composeLine =
    'docker compose exec uptime-goblin node lib/cli/goblin-admin.mjs key remove-data-copy --unused';
  assert.deepEqual(warnings, [
    `${own} (fingerprint ${print(hexKey)}) is an older key, which Uptime Goblin does not use: the key comes from the Compose secret (${secret}) (fingerprint ${print(otherKey)}), as after goblin-admin key rewrap, and every copy of the data directory carries it. This line deletes it only while the key it is given opens every data key and ${own} opens none, and otherwise says why and deletes nothing: ${composeLine}`,
  ]);
  // The check's third line is the same line.
  const keep = await admin(withDir(directory, 'key', 'compose-check'), {
    directory,
    secrets,
    container: true,
  });
  assert.equal(keep.out.split('\n')[0], 'KEEP');
  assert.equal(keep.out.split('\n')[2], composeLine);
  const printed = composeLine.split(' node lib/cli/goblin-admin.mjs ')[1].split(' ');

  // Each refusal keeps it, with why. The COPY state (Uptime Goblin runs without the override): the key
  // this command is given is that file.
  await kept(
    `The key this command is given is ${own} itself: no other key source reached it (checked GOBLIN_SECRET_KEY, GOBLIN_SECRET_KEY_FILE, ${path.join(directory, 'no-credentials', 'orbit-secret-key')}, ${path.join(directory, 'no-secrets', 'orbit_secret_key')}, ${own}), so that file is the key in use, not an older one. Under Docker Compose, Uptime Goblin has the Compose secret only once it runs with compose.secret.yaml (COMPOSE_FILE=compose.yaml:compose.secret.yaml in .env, then docker compose up -d), and this command must run in its container: the line below.`,
    { secrets: path.join(directory, 'no-secrets') },
    composeLine
  );
  // GOBLIN_SECRET_KEY_PREVIOUS_FILE naming it: Uptime Goblin reads it at every start.
  await kept(
    `${own} is the file GOBLIN_SECRET_KEY_PREVIOUS_FILE names (its path, a link or a mount of that file), which Uptime Goblin reads at every start, so deleting it would stop Uptime Goblin from starting. Once every data key opens with the Compose secret (${secret}) (goblin-admin key rewrap), remove GOBLIN_SECRET_KEY_PREVIOUS_FILE, start Uptime Goblin again, then run this command again.`,
    { env: { GOBLIN_SECRET_KEY_PREVIOUS_FILE: own } }
  );
  // A Compose secret that does not open the data (a new key made by mistake).
  const third = 'e5'.repeat(16) + 'f6'.repeat(16);
  put(secret, third);
  await kept(
    `The Compose secret (${secret}) (fingerprint ${print(third)}) does not open every data key, so ${own} may be the key that opens some of them. ${check}`
  );
  put(secret, otherKey);
  // A copy of the key in use is no older key: the line without --unused.
  put(own, otherKey, 0o600);
  await kept(
    `${own} holds the same key as the Compose secret (${secret}) (fingerprint ${print(otherKey)}): it is a copy of that key, not an older one, and --unused deletes only an older key. Delete a copy with the line below.`,
    {},
    'docker compose exec uptime-goblin node lib/cli/goblin-admin.mjs key remove-data-copy'
  );
  put(own, hexKey, 0o600);
  // As root: refused, with the line that works (--unused kept).
  const root = await unused({ uid: 0, container: false });
  assert.equal(root.code, exitCodes.usage);
  assert.match(
    root.err,
    new RegExp(
      `must not run as root .*: sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key node ${script.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} key remove-data-copy --unused --data-dir `
    )
  );
  // --unused belongs to remove-data-copy alone.
  const misplaced = await admin(withDir(directory, 'key', 'status', '--unused'), { directory });
  assert.equal(misplaced.code, exitCodes.usage);
  assert.equal(misplaced.err, 'goblin-admin key: --unused applies to key remove-data-copy only.\n');
  assert.equal(fs.readFileSync(own, 'utf8'), `${hexKey}\n`, 'every refusal kept it');

  // The line as printed, in Uptime Goblin's container (goblin.lock held: Uptime Goblin runs): A goes, B stays,
  // and nothing else changes but control.sqlite, which gains the command's audit entry (audit
  // spec §7.2).
  const database = ['control.sqlite', 'control.sqlite-wal', 'control.sqlite-shm'];
  const before = fingerprint(directory, ['secret.key', ...database]);
  const deleted = await admin(withDir(directory, ...printed), {
    directory,
    secrets,
    container: true,
  });
  assert.equal(deleted.code, 0, deleted.err);
  assert.equal(
    deleted.out,
    `Deleted ${own}, an older key (fingerprint ${print(hexKey)}) that opens none of this data's keys: the Compose secret (${secret}) (fingerprint ${print(otherKey)}) opens them all. A backup or a snapshot (goblin-admin snapshots) of the data from before the key changed still needs that older key. Keep a backup of the key Uptime Goblin uses apart from the data.\n`
  );
  assert.equal(fs.existsSync(own), false);
  assert.equal(fs.readFileSync(secret, 'utf8'), `${otherKey}\n`);
  assert.deepEqual(fingerprint(directory, database), before);
  assert.deepEqual(
    auditTables(directory)
      .rows.filter(row => row.action === 'key.remove-data-copy')
      .map(row => JSON.parse(row.detail)),
    [{ unused: true }]
  );

  // Natively: Uptime Goblin runs with GOBLIN_SECRET_KEY_FILE (B) outside the data directory, and its start
  // warning gives the native line with that file; run as printed, with this test's directories.
  const keyFile = path.join(temporary(t), 'orbit.key');
  put(keyFile, otherKey);
  put(own, hexKey, 0o600);
  const [native] = resolveKey({
    env: { GOBLIN_SECRET_KEY_FILE: keyFile },
    directory,
    keyringExists: true,
    credentialsDirectory: path.join(directory, 'no-credentials'),
    secretsDirectory: path.join(directory, 'no-secrets'),
  }).warnings;
  // The warning ends with the line alone; which install it is for comes before it. The shell
  // reads the whole line as exactly these words (nothing stripped from it first), and they run
  // here with this test's data directory in place of /var/lib/uptime-goblin.
  const nativeLine = `sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=${keyFile} node /opt/uptime-goblin/lib/cli/goblin-admin.mjs key remove-data-copy --unused --data-dir /var/lib/uptime-goblin`;
  assert.ok(
    native.endsWith(
      `. This line (the native install; Docker Compose and other installs: docs/installation.md#goblin-admin) deletes it only while the key it is given opens every data key and ${own} opens none, and otherwise says why and deletes nothing: ${nativeLine}`
    ),
    native
  );
  const words = shellWords(nativeLine, 'sudo');
  assert.deepEqual(words.slice(0, 6), [
    '-u',
    'uptime-goblin',
    'env',
    `GOBLIN_SECRET_KEY_FILE=${keyFile}`,
    'node',
    '/opt/uptime-goblin/lib/cli/goblin-admin.mjs',
  ]);
  assert.deepEqual(words.slice(6), [
    'key',
    'remove-data-copy',
    '--unused',
    '--data-dir',
    '/var/lib/uptime-goblin',
  ]);
  const nativeRun = await admin(withDir(directory, ...words.slice(6, -2), '--json'), {
    directory,
    env: { GOBLIN_SECRET_KEY_FILE: keyFile },
  });
  assert.equal(nativeRun.code, 0, nativeRun.err);
  assert.deepEqual(nativeRun.json(), {
    deleted: own,
    source: 'file',
    file: keyFile,
    fingerprint: print(otherKey),
    deletedFingerprint: print(hexKey),
  });
  assert.equal(fs.existsSync(own), false);
  assert.match((await admin(['key', '--help'])).out, /With --unused: delete an older key there/);
  assert.match((await admin(['key', '--help'])).out, /remove-data-copy \[--unused\]/);
});

// The words the shell reads from `line`, run whole, in sh and, where there is one, in zsh, both
// as a script and as a line pasted at an interactive prompt (zsh -f: no startup files). Pasted,
// zsh reads `#` as a word, not a comment (interactivecomments is off by default), so a note
// after the command could not hide behind one. `program` (sudo, docker) is a stub on an otherwise
// empty PATH that prints its arguments, so nothing else runs. A syntax error, a word too many or
// another program fails here.
function shellWords(line, program) {
  const bin = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-words-'));
  try {
    const stub = path.join(bin, program);
    fs.writeFileSync(stub, `#!/bin/sh\nfor word do printf '%s\\0' "$word"; done\n`, {
      mode: 0o755,
    });
    const zsh = fs.existsSync('/bin/zsh');
    const runs = [
      ['/bin/sh', ['-c', line]],
      ...(zsh ? [['/bin/zsh', ['-f', '-c', line]]] : []),
      ...(zsh ? [['/bin/zsh', ['-f', '-i', '-s'], `${line}\n`]] : []),
    ];
    let words = null;
    for (const [shell, args, input] of runs) {
      const how = `${shell} ${args.join(' ')}`;
      const result = spawnSync(shell, args, {
        env: { PATH: bin, PS1: '', PROMPT: '', HOME: bin },
        input,
        encoding: 'utf8',
      });
      assert.equal(result.status, 0, `${how}: ${result.stderr}`);
      // An interactive zsh writes its (empty) prompts to stderr, and nothing else.
      assert.doesNotMatch(result.stderr, /[a-z]/i, how);
      const read = result.stdout.split('\0').slice(0, -1);
      if (words) assert.deepEqual(read, words, how);
      words = read;
    }
    return words;
  } finally {
    fs.rmSync(bin, { recursive: true, force: true });
  }
}

// P3 of a review of the 1.5.0-dev.1 milestone: the native remove-data-copy line ended in "(the native install;
// …)", so the whole line, copied as printed, failed in sh and zsh, and the refusals put the line
// inside a sentence that ended in a full stop. Each line is now the command alone: the shell reads
// all of it as exactly its words, and the CLI's own refusal line runs as printed.
test('every remove-data-copy line Uptime Goblin prints is the command alone: the shell reads all of it as its words, and the line a refusal prints runs as printed', async t => {
  const { removeDataKeyLine } = await import('../../lib/keyring.mjs');
  const odd = path.join(temporary(t), "a key's file");
  for (const unused of [false, true]) {
    const args = ['key', 'remove-data-copy', ...(unused ? ['--unused'] : [])];
    assert.deepEqual(shellWords(removeDataKeyLine({ compose: true, unused }), 'docker'), [
      'compose',
      'exec',
      'uptime-goblin',
      'node',
      'lib/cli/goblin-admin.mjs',
      ...args,
    ]);
    for (const keyFile of [null, odd])
      assert.deepEqual(shellWords(removeDataKeyLine({ unused, keyFile }), 'sudo'), [
        '-u',
        'uptime-goblin',
        'env',
        `GOBLIN_SECRET_KEY_FILE=${keyFile ?? '/etc/uptime-goblin/secret.key'}`,
        'node',
        '/opt/uptime-goblin/lib/cli/goblin-admin.mjs',
        ...args,
        '--data-dir',
        '/var/lib/uptime-goblin',
      ]);
  }

  // A native install whose key moved to GOBLIN_SECRET_KEY_FILE (B) with key rewrap.
  const directory = await started(t);
  const own = path.join(directory, 'secret.key');
  const keyFile = path.join(temporary(t), 'orbit.key');
  const print = hex => keyFingerprint(Buffer.from(hex, 'hex'));
  const put = (file, hex, mode = 0o400) => {
    fs.rmSync(file, { force: true });
    fs.writeFileSync(file, `${hex}\n`, { mode });
  };
  put(own, hexKey, 0o600);
  put(keyFile, otherKey);
  const env = { GOBLIN_SECRET_KEY_FILE: keyFile };
  const rewrap = await admin(withDir(directory, 'key', 'rewrap'), {
    directory,
    env: { ...env, GOBLIN_SECRET_KEY_PREVIOUS_FILE: own },
  });
  assert.equal(rewrap.code, 0, rewrap.err);
  const lock = acquireLock(directory);
  t.after(() => lock.release());

  // Each refusal's last line, run whole in sh as printed: sudo is a stub that drops "-u orbit",
  // so the rest runs as this user, with this checkout's goblin-admin and data directory.
  const asPrinted = line => {
    const bin = temporary(t);
    fs.writeFileSync(
      path.join(bin, 'sudo'),
      '#!/bin/sh\nif [ "$1" = -u ]; then shift 2; fi\nexec "$@"\n',
      { mode: 0o755 }
    );
    return spawnSync('/bin/sh', ['-c', line], {
      env: { PATH: [bin, path.dirname(process.execPath), '/usr/bin', '/bin'].join(':') },
      encoding: 'utf8',
    });
  };
  const refusal = async (extra, command) => {
    const result = await admin(withDir(directory, 'key', 'remove-data-copy', ...extra), {
      directory,
      env,
    });
    assert.equal(result.code, exitCodes.failed, result.out + result.err);
    const lines = result.err.split('\n');
    assert.equal(lines.at(-1), '', 'the message ends with a newline');
    assert.match(
      lines.at(-3),
      /Delete (it|a copy) with the line below \(the native install; Docker Compose and other installs: docs\/installation\.md#goblin-admin\)\. Nothing was deleted\.$/
    );
    assert.equal(lines.at(-2), command, 'the last line is the command alone');
    return command;
  };
  const line = extra =>
    `sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=${keyFile} node ${script} key remove-data-copy${extra} --data-dir ${directory}`;
  const runs = process.getuid?.() !== 0;

  // A copy of B, with --unused: the line without it, which deletes the copy.
  put(own, otherKey, 0o600);
  const copyLine = await refusal(['--unused'], line(''));
  assert.deepEqual(shellWords(copyLine, 'sudo').slice(-4), [
    'key',
    'remove-data-copy',
    '--data-dir',
    directory,
  ]);
  if (runs) {
    const copied = asPrinted(copyLine);
    assert.equal(copied.status, 0, copied.stdout + copied.stderr);
    assert.match(
      copied.stdout,
      new RegExp(`^Deleted ${own.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}: `)
    );
    assert.equal(fs.existsSync(own), false);
  }

  // The older key A, without --unused: the line with it, which deletes A.
  put(own, hexKey, 0o600);
  const olderLine = await refusal([], line(' --unused'));
  if (runs) {
    const older = asPrinted(olderLine);
    assert.equal(older.status, 0, older.stdout + older.stderr);
    assert.equal(
      older.stdout,
      `Deleted ${own}, an older key (fingerprint ${print(hexKey)}) that opens none of this data's keys: GOBLIN_SECRET_KEY_FILE (${keyFile}) (fingerprint ${print(otherKey)}) opens them all. A backup or a snapshot (goblin-admin snapshots) of the data from before the key changed still needs that older key. Keep a backup of the key Uptime Goblin uses apart from the data.\n`
    );
    assert.equal(fs.existsSync(own), false);
    assert.equal(fs.readFileSync(keyFile, 'utf8'), `${otherKey}\n`, 'B stays');
  } else t.diagnostic('as root, goblin-admin refuses to run: the printed lines were parsed only');
});

test('key commands need a migrated control database with a keyring', async t => {
  const directory = temporary(t);
  const none = await admin(withDir(directory, 'key', 'rotate'), { directory });
  assert.equal(none.code, 1);
  assert.match(none.err, /no control database yet/);
  const control = openControl(directory, { release, env: {} });
  await control.migrate();
  control.close();
  const empty = await admin(withDir(directory, 'key', 'rotate'), {
    env: { GOBLIN_SECRET_KEY: hexKey },
    directory,
  });
  assert.equal(empty.code, 1);
  assert.equal(
    empty.err.trim(),
    'goblin-admin key: There is no keyring yet: start Uptime Goblin once first.'
  );
  const rewrap = await admin(withDir(directory, 'key', 'rewrap'), {
    env: { GOBLIN_SECRET_KEY: hexKey },
    directory,
  });
  assert.equal(rewrap.code, 1);
  assert.match(rewrap.err, /There is no keyring yet: start Uptime Goblin once first\./);
  const status = await admin(withDir(directory, 'key', 'status'), { directory });
  assert.equal(status.code, 0);
  // Every start creates the keyring (delivery spec D6): until then, say what the next one does.
  assert.ok(
    status.out
      .split('\n')
      .includes(
        'Keyring: none yet. Uptime Goblin creates it at its next start, with the key from GOBLIN_SECRET_KEY_FILE or another configured source, or a new secret.key in the data directory.'
      ),
    status.out
  );
  assert.ok(
    status.out
      .split('\n')
      .includes(
        `Master key: none in this command's environment. Unless Uptime Goblin has one of its own (natively GOBLIN_SECRET_KEY_FILE in /etc/uptime-goblin.env, which this command does not read), its next start generates ${path.join(path.resolve(directory), 'secret.key')}; set GOBLIN_SECRET_KEY_FILE to keep the key outside the data directory.`
      ),
    status.out
  );
  // With a key configured, it is named instead.
  const configured = await admin(withDir(directory, 'key', 'status'), {
    env: { GOBLIN_SECRET_KEY: hexKey },
    directory,
  });
  // Named as Uptime Goblin's start line names it (docs audit, keys 23), not by the internal code `env`.
  assert.match(configured.out, /^Master key: GOBLIN_SECRET_KEY, fingerprint [0-9a-f]{16}$/m);
  assert.doesNotMatch(configured.out, /The next start generates/);
  const human = await admin(withDir(directory, 'status'), { directory });
  assert.match(human.out, /^Keyring: none yet$/m);
  // key status never generates a key.
  assert.equal(fs.existsSync(path.join(directory, 'secret.key')), false);
  // reset creates the keyring, and says that every start needs the key from now on.
  const reset = await admin(withDir(directory, 'key', 'reset', '--confirm-lost-key'), {
    env: { GOBLIN_SECRET_KEY: hexKey },
    directory,
  });
  assert.equal(reset.code, 0, reset.err);
  assert.match(reset.out, /From now on Uptime Goblin needs this key at every start\./);
  const present = await admin(withDir(directory, 'key', 'status'), { directory });
  assert.equal(present.code, 1, 'with a keyring the key is required');
  assert.match(present.out, /Keyring: 4 data keys/);
});

// ---------------------------------------------------------------------------------------------
// The key commands on a native install, where only the service has the key: systemd reads
// /etc/uptime-goblin.env (root's alone; here Node's --env-file plays EnvironmentFile=) and `sudo -u
// orbit` starts a clean environment (here: PATH and HOME only). Each command line is taken as
// printed, from the docs or from Uptime Goblin's own refusals, with the installer's paths mapped into
// this test's directories; after each, Uptime Goblin must still start.

const serverScript = path.join(appRoot, 'server.mjs');

// Starts Uptime Goblin with `envFile` as its environment file, stops it once it serves, and resolves
// {code, stdout, stderr} (a refusal exits by itself).
function startOnce(envFile, data) {
  return new Promise(resolve => {
    const child = spawn(process.execPath, [`--env-file=${envFile}`, serverScript], {
      cwd: appRoot,
      env: {
        PATH: process.env.PATH,
        HOST: '127.0.0.1',
        PORT: freePortSync(),
        GOBLIN_DATA_DIR: data,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '',
      stderr = '',
      stopping = false;
    child.stdout.on('data', chunk => {
      stdout += chunk;
      if (!stopping && /Uptime Goblin is ready at /.test(stdout)) {
        stopping = true;
        child.kill('SIGTERM');
      }
    });
    child.stderr.on('data', chunk => (stderr += chunk));
    child.once('exit', code => resolve({ code, stdout, stderr }));
  });
}

test('the documented key command lines, and those Uptime Goblin prints, see the key only the service is given: status, rotate, a key change and a lost key leave Uptime Goblin starting', async t => {
  const base = fs.realpathSync(temporary(t));
  const data = path.join(base, 'data'),
    etc = path.join(base, 'etc'),
    keyFile = path.join(etc, 'secret.key'),
    oldKeyFile = path.join(etc, 'old.key'),
    envFile = path.join(base, 'orbit.env');
  fs.mkdirSync(data, { mode: 0o700 });
  fs.mkdirSync(etc);
  const envLines = `GOBLIN_PASSWORD=startup-test-password\nGOBLIN_SECRET_KEY_FILE=${keyFile}\n`;
  fs.writeFileSync(envFile, envLines, { mode: 0o600 });
  const writeKey = (file, hex) => {
    fs.rmSync(file, { force: true });
    fs.writeFileSync(file, `${hex}\n`, { mode: 0o440 });
  };
  const fingerprintOf = hex => keyFingerprint(Buffer.from(hex, 'hex'));
  const started = async expect => {
    const result = await startOnce(envFile, data);
    assert.equal(result.code, 0, result.stdout + result.stderr);
    assert.ok(
      result.stdout.includes(
        `Encryption key: GOBLIN_SECRET_KEY_FILE (${keyFile}) · fingerprint ${fingerprintOf(expect)}`
      ),
      result.stdout
    );
    assert.ok(!fs.existsSync(path.join(data, 'secret.key')), 'no key in the data directory');
  };
  // A command line as printed, run the way `sudo -u uptime-goblin` runs it.
  const quote = text => `'${text}'`;
  const run = line => {
    // As printed, a line holds nothing a shell reads as a redirection (the previous key's
    // placeholder was <old-key-file>).
    assert.doesNotMatch(line, /[<>]/, line);
    const mapped = line
      .replace(/^sudo -u uptime-goblin /, '')
      .replaceAll('/opt/uptime-goblin/', `${appRoot}/`)
      .replaceAll(/\/var\/lib\/uptime-goblin(?=\s|$)/g, quote(data))
      .replaceAll('/etc/uptime-goblin/secret.key', quote(keyFile))
      .replaceAll('=OLD_KEY_FILE ', `=${quote(oldKeyFile)} `);
    assert.doesNotMatch(mapped, /\/etc\/orbit|\/var\/lib|\/opt\/uptime-goblin|</, mapped);
    const result = spawnSync('sh', ['-c', mapped], {
      env: { PATH: process.env.PATH, HOME: base },
      encoding: 'utf8',
    });
    return { code: result.status, out: result.stdout, err: result.stderr };
  };
  // The command line a message prints (up to the pointer for other installs).
  const printed = (text, action) => {
    const line = new RegExp(
      `sudo -u uptime-goblin (?:env \\S+ (?:\\S+ )?)?node \\S+ key ${action}[^(]*?--data-dir \\S+`
    ).exec(text)?.[0];
    assert.ok(line, `no key ${action} command line in: ${text}`);
    return line;
  };
  const read = name => fs.readFileSync(path.join(appRoot, name), 'utf8');
  const documented = (name, action) => {
    const line = new RegExp(
      `^sudo -u uptime-goblin .*node /opt/uptime-goblin/lib/cli/goblin-admin\\.mjs key ${action} .*--data-dir /var/lib/uptime-goblin$`,
      'm'
    ).exec(read(name))?.[0];
    assert.ok(line, `${name} documents no native key ${action} command line`);
    return line;
  };

  writeKey(keyFile, hexKey);
  await started(hexKey);

  // Run as root, a key command that changes the data refuses and prints the line to use, with
  // the key files it was given (review round 4: it dropped them, so that line was refused again,
  // and a reset with --use-data-dir-key from it generated <data>/secret.key and re-keyed the
  // data under it: the next start exited 78 key_mismatch). Each printed line works as printed.
  const asRoot = async (args, env) => {
    const refused = await admin([...args, '--data-dir', data], { uid: 0, env });
    assert.equal(refused.code, exitCodes.usage, refused.err);
    assert.match(refused.err, /must not run as root/);
    return refused.err;
  };
  const rootRotate = run(
    printed(await asRoot(['key', 'rotate'], { GOBLIN_SECRET_KEY_FILE: keyFile }), 'rotate')
  );
  assert.equal(rootRotate.code, 0, rootRotate.out + rootRotate.err);
  assert.match(rootRotate.out, /^New data keys for seal, sessions, login, audit;/m);
  writeKey(oldKeyFile, hexKey);
  const rootRewrap = run(
    printed(await asRoot(['key', 'rewrap'], { GOBLIN_SECRET_KEY_FILE: keyFile }), 'rewrap')
  );
  assert.equal(rootRewrap.code, 0, rootRewrap.out + rootRewrap.err);
  fs.rmSync(oldKeyFile);
  const rootUntouched = fingerprint(data, ['goblin.lock', 'orbit.lock']);
  const rootReset = run(
    printed(
      await asRoot(['key', 'reset', '--confirm-lost-key', '--use-data-dir-key'], {
        GOBLIN_SECRET_KEY_FILE: keyFile,
      }),
      'reset --confirm-lost-key --use-data-dir-key'
    )
  );
  assert.equal(rootReset.code, 1, rootReset.out + rootReset.err);
  assert.match(rootReset.err, /opens this keyring, so nothing is lost/);
  assert.deepEqual(
    fingerprint(data, ['goblin.lock', 'orbit.lock']),
    rootUntouched,
    'no key generated'
  );
  await started(hexKey);

  // docs/installation.md#goblin-admin: status, then rotate with Uptime Goblin stopped.
  const status = run(documented('docs/installation.md', 'status'));
  assert.equal(status.code, 0, status.out + status.err);
  assert.match(status.out, /^The key opens every data key\.$/m);
  const rotated = run(documented('docs/installation.md', 'rotate'));
  assert.equal(rotated.code, 0, rotated.out + rotated.err);
  assert.match(rotated.out, /^New data keys for seal, sessions, login, audit;/m);
  await started(hexKey);

  // Without the key file (the form documented before): nothing reports a lost key, and nothing
  // changes the data directory.
  const bare = action =>
    run(
      `sudo -u uptime-goblin node /opt/uptime-goblin/lib/cli/goblin-admin.mjs key ${action} --data-dir /var/lib/uptime-goblin`
    );
  const before = fingerprint(data, ['goblin.lock', 'orbit.lock']);
  const unseen = bare('status');
  assert.equal(unseen.code, 1, unseen.out + unseen.err);
  assert.match(unseen.out, /^Master key: not found by this command\./m);
  assert.doesNotMatch(unseen.out + unseen.err, /PROBLEM|key reset/);
  const stuck = bare('rotate');
  assert.equal(stuck.code, 1, stuck.out + stuck.err);
  assert.match(stuck.err, /No encryption key reached this command/);
  assert.doesNotMatch(stuck.err, /key reset/);
  const refusedReset = bare('reset --confirm-lost-key');
  assert.equal(refusedReset.code, 2, refusedReset.out + refusedReset.err);
  assert.match(refusedReset.err, / No key was written and the keyring was not changed\.$/m);
  assert.deepEqual(
    fingerprint(data, ['goblin.lock', 'orbit.lock']),
    before,
    'no key generated, nothing changed but goblin.lock'
  );
  await started(hexKey);
  // The command lines they print work as printed (the reset's finds that nothing is lost). The
  // script spawned here sees a container when the Node 24 gate runs in Docker, and then names
  // the Compose files instead (the in-process test above covers that text).
  if (runsInContainer()) {
    for (const text of [unseen.out, stuck.err, refusedReset.err])
      assert.match(text, /compose\.secret\.yaml/);
  } else {
    assert.equal(run(printed(unseen.out, 'status')).code, 0);
    assert.equal(run(printed(stuck.err, 'rotate')).code, 0);
    const printedReset = run(printed(refusedReset.err, 'reset --confirm-lost-key'));
    assert.equal(printedReset.code, 1, printedReset.out + printedReset.err);
    assert.match(printedReset.err, /The configured key opens this keyring, so nothing is lost/);
  }
  await started(hexKey);

  // A key change: a new key in place, refused with key_mismatch; the command line it prints,
  // with the old key in a file of its own, moves the data to the new key.
  fs.renameSync(keyFile, oldKeyFile);
  writeKey(keyFile, otherKey);
  const mismatch = await startOnce(envFile, data);
  assert.equal(mismatch.code, 78, mismatch.stdout + mismatch.stderr);
  assert.match(mismatch.stderr, /does not match this data/);
  const moved = run(printed(mismatch.stderr, 'rotate'));
  assert.equal(moved.code, 0, moved.out + moved.err);
  fs.rmSync(oldKeyFile);
  await started(otherKey);

  // An environment file that lost its GOBLIN_SECRET_KEY_FILE line: key_missing, and the reset
  // line it prints names the key file, which still opens the data: nothing is lost.
  fs.writeFileSync(envFile, 'GOBLIN_PASSWORD=startup-test-password\n');
  const missing = await startOnce(envFile, data);
  assert.equal(missing.code, 78, missing.stdout + missing.stderr);
  const notLost = run(printed(missing.stderr, 'reset --confirm-lost-key'));
  assert.equal(notLost.code, 1, notLost.out + notLost.err);
  assert.match(notLost.err, /opens this keyring, so nothing is lost/);
  fs.writeFileSync(envFile, envLines);
  await started(otherKey);

  // The key truly lost (a backup restored on a new host): exit 78, ENOENT. docs/troubleshooting.md
  // 'Lost encryption key': step 2 puts a new key in place (here without sudo install), step 3's
  // command line resets the keyring under it, and Uptime Goblin starts with that key.
  fs.rmSync(keyFile);
  const lost = await startOnce(envFile, data);
  assert.equal(lost.code, 78, lost.stdout + lost.stderr);
  assert.ok(
    lost.stderr.includes(`GOBLIN_SECRET_KEY_FILE (${keyFile}) cannot be read: ENOENT.`),
    lost.stderr
  );
  // The troubleshooting row for this message says the file is missing, and to restore it from
  // the key's own backup, before any reset.
  const guide = read('docs/troubleshooting.md');
  assert.match(
    guide,
    /^\| 78, "… cannot be read: ENOENT" \(`key_file_unreadable`\) \| The key file is not there: .*Restore the file from the separate backup of the key .*Only if the key is truly lost: \[lost encryption key\]/m
  );
  // Step 2 puts the new key in place with the owner and mode the service needs, and never sends
  // the admin to the installer, which refuses data whose key is missing.
  const lostKey = guide.split('## Lost encryption key')[1].split('\n## ')[0];
  const step2 = /^2\. [\s\S]*?(?=^3\. )/m.exec(lostKey)?.[0] ?? '';
  assert.match(
    step2,
    /install -o root -g uptime-goblin -m 0440 \/dev\/stdin \/etc\/uptime-goblin\/secret\.key/
  );
  assert.doesNotMatch(step2, /run the installer/i);
  const thirdKey = 'e5'.repeat(16) + 'f6'.repeat(16);
  writeKey(keyFile, thirdKey);
  const step3 = /^3\. .*?`(sudo -u uptime-goblin [^`]*key reset --confirm-lost-key[^`]*)`/m.exec(
    lostKey
  )?.[1];
  assert.ok(step3, 'Lost encryption key, step 3, names the native command line');
  const reset = run(step3);
  assert.equal(reset.code, 0, reset.out + reset.err);
  assert.ok(reset.out.includes(`(${keyFile})`), reset.out);
  await started(thirdKey);
});

test('the script runs as a program: exit statuses reach the shell', t => {
  const directory = temporary(t);
  const env = { ...process.env, GOBLIN_DATA_DIR: directory };
  const run = args => spawnSync(process.execPath, [script, ...args], { env, encoding: 'utf8' });
  assert.equal(run(['help']).status, 0);
  assert.equal(run([]).status, 2);
  assert.equal(run(['nothing']).status, 2);
  const snapshots = run(['snapshots', '--json']);
  assert.equal(snapshots.status, 0, snapshots.stderr);
  assert.deepEqual(JSON.parse(snapshots.stdout), []);
  // Files it creates are private (umask 077).
  const applied = run(['migrate', '--apply']);
  assert.equal(applied.status, 0, applied.stderr);
  assert.equal(fs.statSync(path.join(directory, 'control.sqlite')).mode & 0o077, 0);
});

// ---- The audit log (audit spec §7, §9.1 O) ---------------------------------------------------

// Writes `n` audit rows into a started directory as Uptime Goblin would (its own units, the key the
// directory was started with) and returns the checkpoint lines Uptime Goblin printed (its journal).
// `oneUnit` writes them all in one unit (one line), for a large log in little time.
// Each call starts a minute after the one before, as successive runs of Uptime Goblin would.
let auditMinute = 0;
async function auditRows(directory, n, { key = hexKey, oneUnit = false } = {}) {
  const control = openControl(directory, { release, env: {} });
  const lines = [];
  const minute = auditMinute++;
  try {
    const keyring = await Keyring.open(control.keyringStore, { key: Buffer.from(key, 'hex') });
    const audit = createAudit({
      db: control.db,
      out: line => lines.push(line),
      err: () => {},
      clock: () => Date.UTC(2026, 8, 29, 11, minute, lines.length),
    });
    await audit.attach({ keyring, instanceId: await control.meta.instanceId() });
    if (oneUnit) {
      const kid = keyring.activeKid('audit');
      await control.db.write(tx => {
        const events = Array.from({ length: n }, (_, i) => ({
          action: 'system.stop',
          outcome: 'info',
          at: Date.UTC(2026, 8, 29, 11, minute, i),
          detail: { uptimeMs: i },
        }));
        const now = Date.UTC(2026, 8, 29, 12);
        const mac = data => keyring.hmac('audit', data, kid).mac;
        writePlan(tx, planUnit(tx, events, { kid, mac, now, clock: () => now }), now);
      });
    } else
      for (let i = 1; i <= n; i++)
        await audit.append({ action: 'system.stop', outcome: 'info', detail: { uptimeMs: i } });
    await audit.idle();
  } finally {
    control.close();
  }
  return lines;
}
// The audit_log and audit_inbox rows of a directory, read without changing it.
function auditTables(directory) {
  const db = new DatabaseSync(path.join(directory, 'control.sqlite'), { readOnly: true });
  try {
    return {
      rows: db
        .prepare('SELECT seq, action, outcome, actor_name, detail FROM audit_log ORDER BY seq')
        .all(),
      inbox: db.prepare('SELECT id FROM audit_inbox').all(),
    };
  } finally {
    db.close();
  }
}
// A trigger that aborts every insert into `table` (a disk or database that refuses them).
function refuseInserts(directory, table) {
  const db = new DatabaseSync(path.join(directory, 'control.sqlite'));
  try {
    db.exec(
      `CREATE TRIGGER refuse_${table} BEFORE INSERT ON ${table} BEGIN SELECT RAISE(ABORT, 'refused by the test'); END`
    );
  } finally {
    db.close();
  }
  return () => {
    const again = new DatabaseSync(path.join(directory, 'control.sqlite'));
    try {
      again.exec(`DROP TRIGGER refuse_${table}`);
    } finally {
      again.close();
    }
  };
}
const osUser = (() => {
  try {
    return os.userInfo().username;
  } catch {
    return `uid:${process.getuid()}`;
  }
})();

test('verify-audit: intact, CHANGED and not fully checked, as text and JSON, with exit statuses 0, 1 and 3', async t => {
  const directory = await started(t);
  const verify = (args = [], env = { GOBLIN_SECRET_KEY: hexKey }) =>
    admin(withDir(directory, 'verify-audit', ...args), { env, directory });
  const empty = await verify();
  assert.equal(empty.code, 0, empty.err);
  assert.equal(empty.out, 'Audit log: empty. There is nothing to check yet.\n');
  await auditRows(directory, 1234, { oneUnit: true });
  const intact = await verify();
  assert.equal(intact.code, exitCodes.ok, intact.err);
  assert.match(
    intact.out,
    /^Audit log: intact\. 1,234 entries checked \(#1, 2026-09-29 11:00:00 UTC, to #1,234, 2026-09-29 11:\d\d:\d\d UTC\)\.\n$/
  );
  const json = (await verify(['--json'])).json();
  assert.equal(json.result, 'intact');
  assert.equal(json.rows.checked, 1234);
  assert.equal(json.keyChecked, true);
  // No key: only the links are checked, and the line that gives the key is printed.
  const nokey = await verify([], {});
  assert.equal(nokey.code, exitCodes.unverified);
  assert.match(
    nokey.out,
    /^Audit log: not fully checked\.\nNo encryption key reached this command, so the signatures were not checked \(only the links between entries\)\. Run it with the key file Uptime Goblin uses: sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=\/etc\/uptime-goblin\/secret\.key node \S+ verify-audit --data-dir \S+ \(the native install; Docker Compose and other installs: docs\/installation\.md#goblin-admin\)\.\n$/
  );
  assert.equal((await verify(['--json'], {})).json().keyChecked, false);
  // A wrong key checks nothing either, and says so.
  const wrong = await verify([], { GOBLIN_SECRET_KEY: otherKey });
  assert.equal(wrong.code, exitCodes.unverified);
  assert.match(wrong.err, /does not open this data \(key_mismatch\)/);
  // A row edited: CHANGED, exit 1.
  const db = new DatabaseSync(path.join(directory, 'control.sqlite'));
  db.prepare('UPDATE audit_log SET detail = ? WHERE seq = 1000').run('{"uptimeMs":1}');
  db.close();
  const changed = await verify();
  assert.equal(changed.code, exitCodes.failed);
  assert.match(
    changed.out,
    /^Audit log: CHANGED at entry #1,000 \(2026-09-29 11:\d\d:\d\d UTC\)\. Entry #1,000 does not match its signature: it was changed\. Entry #1,000 cannot be trusted; the others were checked\.\n$/
  );
  assert.equal((await verify(['--json'])).json().problem.code, 'hash_mismatch');
  assert.equal(
    (await admin(withDir(directory, 'verify-audit', 'extra'), { directory })).code,
    exitCodes.usage
  );
});

// Independent review A1: the walk started after seq 0, so a copy of an entry that someone with the
// database put at seq 0 or -1, with another detail and a made-up hash, read intact through the
// command, also against the whole journal. It reads CHANGED at its own seq now, exit 1.
test('Independent review A1: verify-audit: a row at seq 0 or below reads CHANGED at its seq (exit 1), also with --checkpoints and without the key', async t => {
  const directory = await started(t);
  const lines = await auditRows(directory, 3);
  const env = () => ({ GOBLIN_SECRET_KEY: hexKey });
  const journal = path.join(directory, '..', `${path.basename(directory)}-journal.txt`);
  t.after(() => fs.rmSync(journal, { force: true }));
  fs.writeFileSync(journal, lines.join('\n') + '\n');
  const verify = (args, options = { env: env() }) =>
    admin(withDir(directory, 'verify-audit', ...args), { directory, ...options });
  const before = await verify(['--checkpoints', journal]);
  assert.equal(before.code, exitCodes.ok, before.err);
  for (const seq of [0, -1]) {
    const db = new DatabaseSync(path.join(directory, 'control.sqlite'));
    try {
      const columns = db
        .prepare('SELECT name FROM pragma_table_info(?) ORDER BY cid')
        .all('audit_log')
        .map(row => row.name);
      const chosen = columns.map(name =>
        name === 'seq' ? '?' : name === 'detail' ? '?' : name === 'hash' ? '?' : `"${name}"`
      );
      db.prepare(
        `INSERT INTO audit_log (${columns.map(name => `"${name}"`).join(', ')}) SELECT ${chosen.join(', ')} FROM audit_log WHERE seq = 1`
      ).run(
        ...columns
          .filter(name => ['seq', 'detail', 'hash'].includes(name))
          .map(name =>
            name === 'seq' ? seq : name === 'detail' ? '{"uptimeMs":999}' : 'f'.repeat(64)
          )
      );
    } finally {
      db.close();
    }
    const changed = await verify(['--checkpoints', journal]);
    assert.equal(changed.code, exitCodes.failed, changed.out);
    assert.match(
      changed.out,
      new RegExp(
        `^Audit log: CHANGED at entry #${seq} \\(2026-09-29 11:\\d\\d:\\d\\d UTC\\)\\. Entry #${seq} does not follow the entry before it: an entry was changed, inserted or removed\\. Entries from #${seq} on cannot be trusted\\.\\nJournal: 3 checkpoint lines; 3 match;`
      )
    );
    const json = (await verify(['--checkpoints', journal, '--json'])).json();
    assert.equal(json.result, 'broken');
    assert.deepEqual([json.problem.code, json.problem.seq], ['link_broken', seq]);
    assert.equal(json.rows.first.seq, seq);
    // Without the key the seq alone tells: CHANGED, not "not fully checked".
    const nokey = await verify([], { env: {} });
    assert.equal(nokey.code, exitCodes.failed, nokey.out);
    assert.match(nokey.out, new RegExp(`^Audit log: CHANGED at entry #${seq} `));
  }
});

// Review round 2: the wrap binds neither a keyring row's retired_at nor its presence. With any
// purpose left without an active key (one UPDATE by someone with the database but not the key)
// the command checked no signature, said the key did not open the data, and missed a rewritten
// entry; with no keyring row at all it did the same.
test('verify-audit: a keyring whose keys were retired or deleted is still used: a rewritten entry reads CHANGED, entries whose key is gone key_lost', async t => {
  const directory = await started(t);
  await auditRows(directory, 5);
  const verify = (args = []) =>
    admin(withDir(directory, 'verify-audit', ...args), {
      env: { GOBLIN_SECRET_KEY: hexKey },
      directory,
    });
  const sqlite = statement => {
    const db = new DatabaseSync(path.join(directory, 'control.sqlite'));
    try {
      db.exec(statement);
    } finally {
      db.close();
    }
  };
  assert.equal((await verify()).code, exitCodes.ok);
  // A purpose without an active key changes nothing that verification reads.
  sqlite("UPDATE keyring SET retired_at = 1 WHERE purpose = 'seal'");
  const other = await verify();
  assert.equal(other.code, exitCodes.ok, other.out + other.err);
  assert.equal(other.err, '');
  // Every audit key retired, and an entry rewritten.
  sqlite("UPDATE keyring SET retired_at = 1 WHERE purpose = 'audit'");
  sqlite(`UPDATE audit_log SET detail = '{"uptimeMs":99}' WHERE seq = 3`);
  const changed = await verify();
  assert.equal(changed.code, exitCodes.failed, changed.out + changed.err);
  assert.match(
    changed.out,
    /^Audit log: CHANGED at entry #3 \([^)]+\)\. Entry #3 does not match its signature: it was changed\./
  );
  assert.equal(changed.err, '');
  // The audit keys deleted, then every key: the entries are signed with keys the keyring does
  // not hold, and no key reset recorded their loss.
  for (const statement of ["DELETE FROM keyring WHERE purpose = 'audit'", 'DELETE FROM keyring']) {
    sqlite(statement);
    const lost = await verify(['--json']);
    assert.equal(lost.code, exitCodes.failed, statement);
    assert.equal(lost.json().keyChecked, true, statement);
    assert.equal(lost.json().problem.code, 'key_lost', statement);
    assert.equal(lost.json().problem.seq, 1, statement);
  }
});

// Review round 1: the anchor lines take their values from stored rows, which someone with the
// database but not the key can set to anything, also in rows whose signature no longer matches.
// Printed raw, an escape sequence in them could erase the CHANGED line above and print "intact"
// in its place, or write to the clipboard (OSC 52).
test('verify-audit: control characters in stored anchor values never reach the terminal; a number that is not one reads #?', async t => {
  const directory = await started(t);
  await auditRows(directory, 5, { oneUnit: true });
  const erase = '\u001b[1A\u001b[2K\r';
  const db = new DatabaseSync(path.join(directory, 'control.sqlite'));
  const relabel = db.prepare('UPDATE audit_log SET action = ?, detail = ? WHERE seq = ?');
  relabel.run(
    'system.restore',
    JSON.stringify({
      cause: 'snapshot',
      snapshot: `${erase}${erase}Audit log: intact. 5 entries checked.\u001b[8m‮`,
      at: Date.UTC(2026, 8, 29, 11),
      restoredHead: { seq: 2, hash: 'a'.repeat(64) },
    }),
    3
  );
  relabel.run(
    'system.upgrade',
    JSON.stringify({
      release: 'x',
      entries: [{ to: '\u001b]52;c;ZXZpbA==\u0007 evil', at: 1 }],
      markerLost: false,
    }),
    4
  );
  relabel.run(
    'key.reset',
    JSON.stringify({ lostKeyIds: ['k'], head: { seq: `${erase}1`, hash: 'b'.repeat(64) } }),
    5
  );
  db.close();
  for (const keyed of [true, false]) {
    const env = keyed ? { GOBLIN_SECRET_KEY: hexKey } : {};
    const result = await admin(withDir(directory, 'verify-audit'), { env, directory });
    assert.equal(result.code, keyed ? exitCodes.failed : exitCodes.unverified);
    assert.doesNotMatch(result.out, /[\p{Cf}]|[^\P{Cc}\n]/u, JSON.stringify(result.out));
    const lines = result.out.trimEnd().split('\n');
    assert.match(
      lines[0],
      keyed ? /^Audit log: CHANGED at entry #3 / : /^Audit log: not fully checked\.$/
    );
    assert.ok(
      lines.includes(
        'Restored from snapshot [1A[2K[1A[2KAudit log: intact. 5 entries checked.[8m on 2026-09-29 11:00:00 UTC; the log continues from entry #2.'
      ),
      result.out
    );
    assert.ok(
      lines.includes(
        'Uptime Goblin ]52;c;ZXZpbA== evil opened this data on 1970-01-01 00:00:00 UTC and wrote no audit entries.'
      ),
      result.out
    );
    assert.ok(
      lines.some(line =>
        /^goblin-admin key reset on .* replaced the keys that signed entries up to #\?\.$/.test(
          line
        )
      ),
      result.out
    );
  }
});

test('verify-audit --checkpoints: a journal file and stdin, prefixed lines, a forged line, the counts and the coverage; a restore with a journal from before it is not fully checked', async t => {
  const directory = await started(t);
  const lines = await auditRows(directory, 5);
  // resolveKey takes the key out of the environment it reads: a new one for each run.
  const env = () => ({ GOBLIN_SECRET_KEY: hexKey });
  const journal = path.join(directory, '..', `${path.basename(directory)}-journal.txt`);
  t.after(() => fs.rmSync(journal, { force: true }));
  const forged = JSON.stringify({ ...JSON.parse(lines.at(-1)), mac: 'f'.repeat(64) });
  // As journalctl -o cat and docker compose logs print them: some lines with a prefix.
  fs.writeFileSync(
    journal,
    [
      `orbit-1  | ${lines[0]}`,
      ...lines.slice(1, 3),
      'Uptime Goblin listens on http://0.0.0.0:3000',
      forged,
    ].join('\n') + '\n'
  );
  const fromFile = await admin(withDir(directory, 'verify-audit', '--checkpoints', journal), {
    env: env(),
    directory,
  });
  assert.equal(fromFile.code, 0, fromFile.err);
  const [, counts, coverage] = fromFile.out.split('\n');
  assert.equal(
    counts,
    'Journal: 4 checkpoint lines; 3 match; 0 could not be checked because of a restore; 1 not written by this Uptime Goblin (--json lists them).'
  );
  assert.match(
    coverage,
    /^Entries after #3 \(2026-09-29 11:\d\d:02 UTC\) are covered by no journal checkpoint\.$/
  );
  const listedRun = await admin(
    withDir(directory, 'verify-audit', '--checkpoints', journal, '--json'),
    { env: env(), directory }
  );
  const listed = listedRun.json();
  assert.deepEqual(listed.journal.foreignLines, [{ seq: 5, time: JSON.parse(lines.at(-1)).time }]);
  // stdin, as the program reads it inside Uptime Goblin's container.
  const piped = spawnSync(
    process.execPath,
    [script, 'verify-audit', '--checkpoints', '-', '--data-dir', directory],
    {
      input: lines.join('\n'),
      env: {
        PATH: process.env.PATH,
        GOBLIN_SECRET_KEY: hexKey,
        CREDENTIALS_DIRECTORY: path.join(directory, 'none'),
      },
      encoding: 'utf8',
    }
  );
  assert.equal(piped.status, 0, piped.stderr);
  assert.match(
    piped.stdout,
    /^Journal: 5 checkpoint lines; 5 match; 0 could not be checked because of a restore; 0 not written by this Uptime Goblin \(--json lists them\)\.\nEvery entry is covered by a journal checkpoint\.$/m
  );
  assert.equal(
    (
      await admin(
        withDir(directory, 'verify-audit', '--checkpoints', path.join(directory, 'missing.txt')),
        { env: env(), directory }
      )
    ).code,
    exitCodes.usage
  );
  // A snapshot restore: the lines from before it cannot be checked against the restored log.
  const snapshot = await admin(withDir(directory, 'snapshot', '--json'), { env: env(), directory });
  assert.equal(snapshot.code, 0, snapshot.err);
  const id = snapshot.json().id;
  const later = await auditRows(directory, 3);
  const restored = await admin(withDir(directory, 'restore-snapshot', id), {
    env: env(),
    directory,
  });
  assert.equal(restored.code, 0, restored.err);
  const afterRestore = await auditRows(directory, 1);
  fs.writeFileSync(journal, [...lines, ...later, ...afterRestore].join('\n'));
  const across = await admin(withDir(directory, 'verify-audit', '--checkpoints', journal), {
    env: env(),
    directory,
  });
  assert.equal(across.code, exitCodes.unverified, across.out);
  assert.match(
    across.out,
    new RegExp(
      `^Audit log: not fully checked\\.\\n3 checkpoint lines that Uptime Goblin printed before the data was restored from snapshot ${id} on .* could not be checked against the restored log\\.`
    )
  );
  assert.match(
    across.out,
    new RegExp(`^Restored from snapshot ${id} on .*; the log continues from entry #5\\.$`, 'm')
  );
  const afterOnly = path.join(directory, '..', `${path.basename(directory)}-after.txt`);
  t.after(() => fs.rmSync(afterOnly, { force: true }));
  fs.writeFileSync(afterOnly, afterRestore.join('\n'));
  assert.equal(
    (
      await admin(withDir(directory, 'verify-audit', '--checkpoints', afterOnly), {
        env: env(),
        directory,
      })
    ).code,
    0
  );
  assert.equal(
    (await admin(withDir(directory, 'verify-audit'), { env: env(), directory })).code,
    0,
    'the database alone is intact'
  );
});

// Integration (the independent check's finding 1): with the database alone, someone cuts the
// entries a rotated audit key signed, puts the head back, deletes that key and makes the older
// one active again. The journal's lines under the deleted key can be this Uptime Goblin's: not fully
// checked (exit 3), never intact; --json names the key ids.
test('verify-audit --checkpoints: lines under a key the keyring does not hold (a rotated audit key deleted with its entries) are not fully checked, never intact', async t => {
  const directory = await started(t);
  const env = () => ({ GOBLIN_SECRET_KEY: hexKey });
  const lines = await auditRows(directory, 3);
  const rotate = await admin(withDir(directory, 'key', 'rotate', '--purpose', 'audit'), {
    env: env(),
    directory,
  });
  assert.equal(rotate.code, 0, rotate.err);
  const later = await auditRows(directory, 3);
  const journal = path.join(directory, '..', `${path.basename(directory)}-journal.txt`);
  t.after(() => fs.rmSync(journal, { force: true }));
  fs.writeFileSync(journal, [...lines, ...later].join('\n') + '\n');
  const verify = (...args) =>
    admin(withDir(directory, 'verify-audit', '--checkpoints', journal, ...args), {
      env: env(),
      directory,
    });
  assert.equal((await verify()).code, 0, 'intact before the cut');
  const db = new DatabaseSync(path.join(directory, 'control.sqlite'));
  let rotated;
  try {
    rotated = db
      .prepare("SELECT kid FROM keyring WHERE purpose = 'audit' AND retired_at IS NULL")
      .get().kid;
    const older = db
      .prepare(
        "SELECT kid FROM keyring WHERE purpose = 'audit' AND retired_at IS NOT NULL ORDER BY created_at DESC"
      )
      .get().kid;
    db.prepare('DELETE FROM audit_log WHERE key_id = ?').run(rotated);
    const last = db.prepare('SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1').get();
    db.prepare('UPDATE audit_head SET seq = ?, hash = ?, key_id = ?').run(
      last.seq,
      last.hash,
      older
    );
    db.prepare('DELETE FROM keyring WHERE kid = ?').run(rotated);
    db.prepare('UPDATE keyring SET retired_at = NULL WHERE kid = ?').run(older);
  } finally {
    db.close();
  }
  assert.equal(
    (await admin(withDir(directory, 'verify-audit'), { env: env(), directory })).code,
    0,
    'the database alone is intact, as for any cut whose head is rewritten'
  );
  const cut = await verify();
  assert.equal(cut.code, exitCodes.unverified, cut.out);
  assert.match(
    cut.out,
    /^Audit log: not fully checked\.\n3 checkpoint lines are signed with keys the keyring does not hold, and no key reset recorded their loss, so they could not be checked: they are another Uptime Goblin's, this Uptime Goblin's from before a restore of older data or the removal of control\.sqlite \(which takes the whole audit log with it\), or this Uptime Goblin's signed with a key since removed from the keyring, perhaps together with the entries it signed\.\nJournal: 6 checkpoint lines; 3 match; 0 could not be checked because of a restore; 3 not written by this Uptime Goblin \(--json lists them\)\.\n/
  );
  const json = (await verify('--json')).json();
  assert.equal(json.result, 'incomplete');
  assert.deepEqual(json.unverifiable, [{ reason: 'unknown_key', lines: 3, keyIds: [rotated] }]);
  assert.equal(json.journal.foreignLines.length, 3);
});

test('verify-audit runs while another process holds goblin.lock (kind read) and writes nothing', async t => {
  const directory = await started(t);
  await auditRows(directory, 3);
  const before = fingerprint(directory);
  const lock = acquireLock(directory);
  t.after(() => lock.release());
  const result = await admin(withDir(directory, 'verify-audit'), {
    env: { GOBLIN_SECRET_KEY: hexKey },
    directory,
  });
  assert.equal(result.code, 0, result.err);
  assert.deepEqual(fingerprint(directory), before);
  const fresh = temporary(t);
  assert.equal(
    (await admin(withDir(fresh, 'verify-audit'), { directory: fresh })).code,
    exitCodes.failed
  );
});

test('key rows: rotate, rewrap and remove-data-copy append under the key with the CLI user; a failure after the keyring opened is a failed row; a wrong key writes nothing; the log verifies', async t => {
  const directory = await started(t);
  const run = (args, env = { GOBLIN_SECRET_KEY: hexKey }) =>
    admin(withDir(directory, 'key', ...args), { env, directory });
  assert.equal((await run(['rotate', '--purpose', 'seal'])).code, 0);
  assert.equal(
    (await run(['rotate', '--purpose', 'seal'], { GOBLIN_SECRET_KEY: hexKey, SUDO_USER: 'dana' }))
      .code,
    0
  );
  assert.equal(
    (
      await run(['rotate', '--purpose', 'seal'], {
        GOBLIN_SECRET_KEY: hexKey,
        SUDO_USER: 'not a user!',
      })
    ).code,
    0
  );
  assert.equal(
    (await run(['rewrap'], { GOBLIN_SECRET_KEY: otherKey, GOBLIN_SECRET_KEY_PREVIOUS: hexKey }))
      .code,
    0
  );
  // A key that does not open the keyring writes nothing; nor does a usage error.
  assert.notEqual((await run(['rotate'], { GOBLIN_SECRET_KEY: hexKey })).code, 0);
  assert.equal(
    (await run(['rotate', '--purpose', 'nope'], { GOBLIN_SECRET_KEY: otherKey })).code,
    2
  );
  // A failure once the keyring is open: the keys cannot be saved.
  const allow = refuseInserts(directory, 'keyring');
  const failed = await run(['rotate', '--purpose', 'seal'], { GOBLIN_SECRET_KEY: otherKey });
  allow();
  assert.equal(failed.code, 1);
  // remove-data-copy (online): <data>/secret.key is a copy of the key the command is given.
  fs.writeFileSync(path.join(directory, 'secret.key'), `${otherKey}\n`, { mode: 0o600 });
  const keyFile = path.join(directory, '..', `${path.basename(directory)}.key`);
  fs.writeFileSync(keyFile, `${otherKey}\n`, { mode: 0o600 });
  t.after(() => fs.rmSync(keyFile, { force: true }));
  const removed = await run(['remove-data-copy'], { GOBLIN_SECRET_KEY_FILE: keyFile });
  assert.equal(removed.code, 0, removed.err);
  const { rows, inbox } = auditTables(directory);
  assert.deepEqual(
    rows.map(row => [row.action, row.outcome, row.actor_name]),
    [
      ['key.rotate', 'ok', `cli:${osUser}`],
      ['key.rotate', 'ok', `cli:dana (sudo as ${osUser})`],
      ['key.rotate', 'ok', `cli:${osUser}`],
      ['key.rewrap', 'ok', `cli:${osUser}`],
      ['key.rotate', 'failed', `cli:${osUser}`],
      ['key.remove-data-copy', 'ok', `cli:${osUser}`],
    ]
  );
  assert.deepEqual(JSON.parse(rows[0].detail).purposes, ['seal']);
  assert.equal(JSON.parse(rows[3].detail).rewrapped, 4 + 3);
  assert.deepEqual(JSON.parse(rows[4].detail), { code: 'poison' });
  assert.deepEqual(JSON.parse(rows[5].detail), { unused: false });
  assert.deepEqual(inbox, []);
  const verified = await admin(withDir(directory, 'verify-audit', '--json'), {
    env: { GOBLIN_SECRET_KEY: otherKey },
    directory,
  });
  assert.equal(verified.code, 0, verified.out);
  assert.equal(verified.json().rows.checked, 6);
});

test('row not written: a key command whose entry cannot be written says so on stderr and keeps its exit status', async t => {
  const directory = await started(t);
  const allow = refuseInserts(directory, 'audit_log');
  const rotated = await admin(withDir(directory, 'key', 'rotate', '--purpose', 'seal'), {
    env: { GOBLIN_SECRET_KEY: hexKey },
    directory,
  });
  allow();
  assert.equal(rotated.code, 0, rotated.err);
  assert.equal(
    rotated.err,
    'goblin-admin key rotate: the audit entry for this command could not be written (poison); the command itself succeeded.\n'
  );
  assert.deepEqual(auditTables(directory).rows, []);
});

test("key reset writes key.reset in the reset's own unit; a reset whose entry fails leaves the keyring as it was and exits 1", async t => {
  const directory = await started(t);
  await auditRows(directory, 2);
  const before = await (async () => {
    const control = openControl(directory, { readOnly: true, release, env: {} });
    try {
      return await control.keyringStore.list();
    } finally {
      control.close();
    }
  })();
  const lost = before.filter(row => row.purpose === 'audit').map(row => row.kid);
  const allow = refuseInserts(directory, 'audit_log');
  const refused = await admin(withDir(directory, 'key', 'reset', '--confirm-lost-key'), {
    env: { GOBLIN_SECRET_KEY: otherKey },
    directory,
  });
  allow();
  assert.equal(refused.code, 1);
  assert.match(
    refused.err,
    / The keyring was not changed: the keys and their audit entry are saved together\.\n$/
  );
  assert.equal(
    (
      await admin(withDir(directory, 'key', 'status'), {
        env: { GOBLIN_SECRET_KEY: hexKey },
        directory,
      })
    ).code,
    0,
    'the old keys are still there'
  );
  const reset = await admin(withDir(directory, 'key', 'reset', '--confirm-lost-key'), {
    env: { GOBLIN_SECRET_KEY: otherKey },
    directory,
  });
  assert.equal(reset.code, 0, reset.err);
  const { rows } = auditTables(directory);
  assert.deepEqual(
    rows.map(row => row.action),
    ['system.stop', 'system.stop', 'key.reset']
  );
  const detail = JSON.parse(rows[2].detail);
  assert.deepEqual(detail.lostKeyIds, lost);
  assert.equal(detail.head.seq, 2);
  const verified = await admin(withDir(directory, 'verify-audit'), {
    env: { GOBLIN_SECRET_KEY: otherKey },
    directory,
  });
  assert.equal(verified.code, exitCodes.unverified);
  assert.match(
    verified.out,
    /^Entries #1–#2 were signed with keys that goblin-admin key reset removed on .*; their links were checked\.$/m
  );
  assert.match(
    verified.out,
    /^goblin-admin key reset on .* replaced the keys that signed entries up to #2\.$/m
  );
});

// A reset with --use-data-dir-key and no other key generates <data>/secret.key before the
// reset's unit; when key.reset cannot be written the keyring stays as it was, but the generated
// file stays too. The message said "Nothing was changed".
test('a reset whose entry fails after generating <data>/secret.key says the keyring was not changed and names the file it left', async t => {
  const directory = await started(t);
  const own = path.join(directory, 'secret.key');
  assert.equal(fs.existsSync(own), false);
  const allow = refuseInserts(directory, 'audit_log');
  const refused = await admin(
    withDir(directory, 'key', 'reset', '--confirm-lost-key', '--use-data-dir-key'),
    { directory }
  );
  allow();
  assert.equal(refused.code, 1, refused.err);
  assert.ok(
    refused.err.endsWith(
      ` The keyring was not changed: the keys and their audit entry are saved together. ${own}, which this reset generated, stays; a reset run again with --use-data-dir-key uses it.\n`
    ),
    refused.err
  );
  assert.doesNotMatch(refused.err, /Nothing was changed/);
  assert.ok(fs.existsSync(own), 'the generated key file is there, as the message says');
  assert.equal(
    (
      await admin(withDir(directory, 'key', 'status'), {
        env: { GOBLIN_SECRET_KEY: hexKey },
        directory,
      })
    ).code,
    0,
    'the old keys are still there'
  );
  // Run again, the reset takes that file.
  const again = await admin(
    withDir(directory, 'key', 'reset', '--confirm-lost-key', '--use-data-dir-key', '--json'),
    { directory }
  );
  assert.equal(again.code, 0, again.err);
  assert.equal(again.json().source, 'data-directory');
  assert.equal(again.json().file, own);
});

test('no CLI rows: migrate --apply, snapshot and restore-snapshot write no audit row and leave the inbox empty', async t => {
  const directory = await started(t);
  const env = () => ({ GOBLIN_SECRET_KEY: hexKey });
  const none = { rows: [], inbox: [] };
  assert.equal(
    (await admin(withDir(directory, 'migrate', '--apply'), { env: env(), directory })).code,
    0
  );
  assert.deepEqual(auditTables(directory), none, 'after migrate --apply');
  const snapshot = await admin(withDir(directory, 'snapshot', '--json'), { env: env(), directory });
  assert.equal(snapshot.code, 0, snapshot.err);
  assert.deepEqual(auditTables(directory), none, 'after snapshot');
  const restored = await admin(withDir(directory, 'restore-snapshot', snapshot.json().id), {
    env: env(),
    directory,
  });
  assert.equal(restored.code, 0, restored.err);
  assert.deepEqual(auditTables(directory), none, 'after restore-snapshot');
});

test('status never follows a symlinked run/status.json, shows only the fields Uptime Goblin writes, and prints no control characters from it or control.sqlite', async t => {
  const directory = await started(t);
  const missingUnit = path.join(directory, 'no-uptime-goblin.service');
  const run = path.join(directory, 'run');
  fs.mkdirSync(run);
  // The uptime-goblin account owns run/; status may run as root, and printed the whole linked file.
  const other = path.join(temporary(t), 'other.json');
  fs.writeFileSync(other, JSON.stringify({ registry: 'SYNTH-OTHER-FILE-CANARY' }), { mode: 0o600 });
  fs.symlinkSync(other, path.join(run, 'status.json'));
  const linked = await admin(withDir(directory, 'status', '--json', '--unit', missingUnit));
  assert.ok(!linked.out.includes('SYNTH-OTHER-FILE-CANARY'), linked.out);
  assert.equal(linked.json().process.statusFile, 'absent');
  fs.rmSync(path.join(run, 'status.json'));
  // Nor through a linked run/: its status.json could be any file so named that root can read.
  const elsewhere = temporary(t);
  fs.writeFileSync(
    path.join(elsewhere, 'status.json'),
    JSON.stringify({ version: '1.5.0', build: 'SYNTH-LINKED-RUN-CANARY', pid: 4242 }),
    { mode: 0o600 }
  );
  fs.renameSync(run, `${run}.kept`);
  fs.symlinkSync(elsewhere, run);
  const linkedRun = await admin(withDir(directory, 'status', '--json', '--unit', missingUnit));
  assert.ok(!linkedRun.out.includes('SYNTH-LINKED-RUN-CANARY'), linkedRun.out);
  assert.equal(linkedRun.json().process.statusFile, 'absent');
  fs.rmSync(run);
  fs.renameSync(`${run}.kept`, run);
  fs.writeFileSync(
    path.join(run, 'status.json'),
    JSON.stringify({
      version: '1.5.0',
      build: 'b\u001b[2J\n[orbit] FORGED-STATUS-LINE',
      pid: 2 ** 22 + 17,
      nonce: 'f'.repeat(32),
      startedAt: 1,
      reason: 'r\u001b[31m' + 'R'.repeat(5000),
      extra: 'SYNTH-EXTRA-FIELD',
    })
  );
  // Text from control.sqlite: a release name and a fence row that a damaged or crafted
  // database holds.
  const db = new DatabaseSync(path.join(directory, 'control.sqlite'));
  db.prepare("UPDATE meta SET value = ? WHERE key = 'last_version'").run(
    '1.5.0\u001b[2J\n[orbit] FORGED-META-LINE'
  );
  db.prepare(
    'INSERT INTO schema_fences (name, min_release, reason, set_at) VALUES (?, ?, ?, ?)'
  ).run('f\u001b[31m', '9.9.9', 'x\u001b[2J\n[orbit] FORGED-FENCE-LINE', 1);
  db.close();
  // A snapshot folder whose manifest says it is pinned: its name is listed among the pinned.
  const pinned = 'p\u001b[2J\n[orbit] FORGED-PINNED-LINE';
  fs.mkdirSync(path.join(directory, 'snapshots', pinned), { recursive: true });
  fs.writeFileSync(
    path.join(directory, 'snapshots', pinned, 'manifest.json'),
    JSON.stringify({
      format: 1,
      id: pinned,
      reason: 'pre-upgrade',
      createdAt: 1,
      pinned: true,
      files: [],
    })
  );
  const json = (await admin(withDir(directory, 'status', '--json', '--unit', missingUnit))).json();
  assert.equal(json.process.extra, undefined, 'a field Uptime Goblin does not write is not shown');
  assert.equal('nonce' in json.process, false);
  assert.equal(json.process.reason.length, 100, 'cut to one short line');
  const text = await admin(withDir(directory, 'status', '--unit', missingUnit));
  assert.equal(text.code, 0, text.err);
  assert.ok(!/[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/.test(text.out), JSON.stringify(text.out));
  for (const line of text.out.split('\n'))
    assert.ok(!line.startsWith('[orbit]'), `no line of saved text stands alone: ${line}`);
  assert.match(text.out, /build b\[2J\[orbit\] FORGED-STATUS-LINE/);
  assert.match(
    text.out,
    /Refused: This data needs Uptime Goblin ≥ 9\.9\.9 \(x\[2J\[orbit\] FORGED-FENCE-LINE\)/
  );
  assert.match(text.out, /\(pinned: .*p\[2J\[orbit\] FORGED-PINNED-LINE/);
});

test('snapshots prints no control characters from folder names, the file names a manifest lists or a damaged manifest', async t => {
  const directory = await started(t);
  const root = path.join(directory, 'snapshots');
  const [snapshot] = listSnapshots(directory);
  // A file name with an escape sequence and a line break in a manifest.
  const manifestFile = path.join(root, snapshot.id, 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));
  manifest.files.push({
    name: 'n\u001b[2J\n[orbit] FORGED-FILE-LINE',
    bytes: 0,
    sha256: 'a'.repeat(64),
  });
  fs.writeFileSync(manifestFile, JSON.stringify(manifest));
  // A folder whose name carries an escape sequence, holding a copy of a valid manifest: --verify
  // stopped at it ("is not a snapshot id") and listed nothing.
  const odd = 'x\u001b[31mRED';
  fs.cpSync(path.join(root, snapshot.id), path.join(root, odd), { recursive: true });
  // A time past what a date can hold: the listing printed nothing (RangeError) instead.
  fs.writeFileSync(
    path.join(root, odd, 'manifest.json'),
    JSON.stringify({ ...manifest, id: odd, createdAt: 9e15 })
  );
  const broken = 'manual-1.5.0-20260101T000000Z';
  fs.mkdirSync(path.join(root, broken));
  fs.writeFileSync(path.join(root, broken, 'manifest.json'), 'SYNTH-MANIFEST-CANARY {');
  const listed = await admin(withDir(directory, 'snapshots', '--verify'));
  assert.equal(listed.code, 1, listed.err);
  assert.ok(
    !/[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/.test(listed.out),
    JSON.stringify(listed.out)
  );
  for (const line of listed.out.split('\n')) assert.ok(!line.startsWith('[orbit]'), line);
  assert.ok(!listed.out.includes('SYNTH-MANIFEST-CANARY'), 'a manifest is never quoted');
  assert.match(listed.out, new RegExp(`${broken}  INVALID: manifest\\.json is not valid JSON`));
  assert.match(
    listed.out,
    new RegExp(
      `${snapshot.id} .*DAMAGED: n\\[2J\\[orbit\\] FORGED-FILE-LINE is not a file snapshots manage`
    )
  );
  assert.match(
    listed.out,
    /x\[31mRED  unknown  .*DAMAGED: its folder name is not a snapshot id, so restore-snapshot cannot use it/
  );
  // Restoring it is refused with the same problems, printed the same way.
  const restore = await admin(withDir(directory, 'restore-snapshot', snapshot.id));
  assert.equal(restore.code, 1, restore.err);
  assert.match(
    restore.err,
    /cannot be restored: n\[2J\[orbit\] FORGED-FILE-LINE is not a file snapshots manage/
  );
  assert.ok(
    !/[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/.test(restore.err),
    JSON.stringify(restore.err)
  );
  for (const line of restore.err.split('\n')) assert.ok(!line.startsWith('[orbit]'), line);
});

// Text a terminal would act on, and a line a forged value would start.
const assertOneLineEach = (text, what) => {
  assert.ok(
    !/[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/.test(text),
    `${what}: ${JSON.stringify(text)}`
  );
  for (const line of text.split('\n')) assert.ok(!line.startsWith('[orbit]'), `${what}: ${line}`);
};
// SQLite's own text about a damaged database quotes the database's schema names. A hand edit or
// a crafted restore can put any name there: writable_schema, with defensive mode off.
const forgedSchemaRow = (file, name) => {
  const db = new DatabaseSync(file, { defensive: false });
  try {
    db.exec('PRAGMA writable_schema=ON');
    db.prepare("INSERT INTO sqlite_master VALUES ('table', ?, 'x', 0, 'CREATE TABLE broken(')").run(
      name
    );
  } finally {
    db.close();
  }
};
// The manifest of snapshot `id` made to match its (altered) copy of `name`.
const rehash = async (directory, id, name) => {
  const folder = path.join(directory, 'snapshots', id);
  const manifestFile = path.join(folder, 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));
  const entry = manifest.files.find(file => file.name === name);
  const bytes = fs.readFileSync(path.join(folder, name));
  entry.bytes = bytes.length;
  entry.sha256 = (await import('node:crypto')).createHash('sha256').update(bytes).digest('hex');
  fs.writeFileSync(manifestFile, JSON.stringify(manifest));
};

test('restore-snapshot prints no control characters from SQLite about a damaged database, a journal or a kept snapshot’s manifest', async t => {
  const directory = await started(t);
  const run = (...args) =>
    admin(withDir(directory, ...args), { env: { GOBLIN_SECRET_KEY: hexKey }, directory });
  // 1. A snapshot's copy whose quick_check quotes a table name: NULL in a NOT NULL column of
  // "t<ESC>[2J<LF>[orbit] FORGED-CHECK-LINE". snapshots --verify printed it cleaned, the problems
  // themselves (--json, and restore-snapshot's refusal) held it as it was.
  const made = await run('snapshot', '--json');
  assert.equal(made.code, 0, made.err);
  const damagedId = made.json().id;
  const table = 't\u001b[2J\n[orbit] FORGED-CHECK-LINE';
  const copy = new DatabaseSync(path.join(directory, 'snapshots', damagedId, 'control.sqlite'), {
    defensive: false,
  });
  copy.exec(`CREATE TABLE "${table}" (c); INSERT INTO "${table}" VALUES (NULL)`);
  copy.exec('PRAGMA writable_schema=ON');
  copy
    .prepare(
      `UPDATE sqlite_master SET sql = 'CREATE TABLE "' || name || '" (c NOT NULL)' WHERE name = ?`
    )
    .run(table);
  copy.close();
  await rehash(directory, damagedId, 'control.sqlite');
  const verified = await run('snapshots', '--verify', '--json');
  assert.equal(verified.code, 1, verified.err);
  assert.deepEqual(verified.json().find(item => item.id === damagedId).problems, [
    'control.sqlite: NULL value in t[2J[orbit] FORGED-CHECK-LINE.c',
  ]);
  const refused = await run('restore-snapshot', damagedId);
  assert.equal(refused.code, 1, refused.err);
  assert.equal(
    refused.err,
    `goblin-admin restore-snapshot: Snapshot ${damagedId} cannot be restored: control.sqlite: NULL value in t[2J[orbit] FORGED-CHECK-LINE.c\n`
  );

  // 2. A live control.sqlite that cannot be opened, SQLite saying why with a schema name: the
  // restore moves it aside and said so with that name as it was.
  const good = await run('snapshot', '--reason', 'good', '--json');
  assert.equal(good.code, 0, good.err);
  const goodId = good.json().id;
  forgedSchemaRow(path.join(directory, 'control.sqlite'), 'x\u001b[2J\n[orbit] FORGED-SCHEMA-LINE');
  const restored = await run('restore-snapshot', goodId);
  assert.equal(restored.code, 0, restored.err);
  assertOneLineEach(restored.out, 'over a damaged control.sqlite');
  assert.match(
    restored.out,
    /\ncontrol\.sqlite could not be opened \(malformed database schema \(x\[2J\[orbit\] FORGED-SCHEMA-LINE\)\), so it was moved aside as it was/
  );

  // 3. A journal of an interrupted restore whose files name something no restore replaces: it
  // was carried on into the next restore's journal, printed as it was ("also replaced …"), and
  // kept Uptime Goblin from starting until a restore finished a file that no restore touches.
  const root = path.join(directory, 'snapshots');
  const journal = path.join(root, '.restore-in-progress.json');
  const asideId = 'pre-restore-1.5.0-20200101T000000Z';
  fs.writeFileSync(
    journal,
    JSON.stringify({
      snapshot: damagedId,
      aside: asideId,
      files: ['x\u001b[2J\n[orbit] FORGED-JOURNAL-LINE'],
      keepHistory: false,
      copies: {},
      absent: [],
    })
  );
  const carried = await run('restore-snapshot', goodId);
  assert.equal(carried.code, 0, carried.err);
  assertOneLineEach(carried.out, 'after a journal naming another file');
  assert.doesNotMatch(carried.out, /An earlier restore/);
  assert.equal(fs.existsSync(journal), false, 'no journal is left to refuse the start');

  // 4. The same restore run again after an attempt that finished a snapshot of files that had
  // changed (`kept`): that snapshot's manifest names its files, and the restore printed them.
  const keptId = 'pre-restore-1.5.0-20200101T000001Z';
  fs.mkdirSync(path.join(root, `.restoring-${asideId}`), { mode: 0o700 });
  fs.mkdirSync(path.join(root, keptId), { mode: 0o700 });
  fs.writeFileSync(
    path.join(root, keptId, 'manifest.json'),
    JSON.stringify({
      format: 1,
      id: keptId,
      reason: 'pre-restore',
      release: '1.5.0',
      fromRelease: null,
      createdAt: 1,
      pinned: false,
      files: [{ name: 'k\u001b[2J\n[orbit] FORGED-KEPT-LINE', bytes: 0, sha256: '0'.repeat(64) }],
      absent: [],
      excluded: [],
      damaged: [{ name: 'd\u001b[31m\n[orbit] FORGED-DAMAGED-LINE', problem: 'p' }],
    })
  );
  fs.writeFileSync(
    journal,
    JSON.stringify({
      snapshot: goodId,
      aside: asideId,
      files: ['config.json'],
      keepHistory: false,
      copies: {},
      kept: [keptId],
      absent: [],
    })
  );
  const again = await run('restore-snapshot', goodId);
  assert.equal(again.code, 0, again.err);
  assertOneLineEach(again.out, 'with a kept snapshot');
  assert.match(
    again.out,
    /\nk\[2J\[orbit\] FORGED-KEPT-LINE had changed since this restore was interrupted .* because d\[31m\[orbit\] FORGED-DAMAGED-LINE in it is damaged/
  );
  assert.equal(fs.existsSync(journal), false);
});

test('every goblin-admin command prints a failure on one line without control characters, SQLite’s text about a damaged database included', async t => {
  const directory = await started(t);
  forgedSchemaRow(path.join(directory, 'control.sqlite'), 'x\u001b[2J\n[orbit] FORGED-SCHEMA-LINE');
  for (const args of [
    ['status'],
    ['check-data'],
    ['migrate', '--plan'],
    ['migrate', '--apply'],
    ['key', 'status'],
    ['verify-audit'],
    ['snapshot'],
  ]) {
    const result = await admin(withDir(directory, ...args), {
      env: { GOBLIN_SECRET_KEY: hexKey },
      directory,
    });
    assert.equal(result.code, exitCodes.failed, `${args.join(' ')}: ${result.err}`);
    assert.equal(
      result.err,
      `goblin-admin ${args[0]}: malformed database schema (x[2J[orbit] FORGED-SCHEMA-LINE)\n`,
      args.join(' ')
    );
  }
});

test('snapshot refuses (78), writing nothing to snapshots/, when a file it copies is a link to nothing; left out with --no-history, history.sqlite is kept, never removed by the restore', async t => {
  // An unmounted volume: history.sqlite a link to a file that is not there. The snapshot took
  // it for absent (exit 0), and restoring it once the volume was back moved history.sqlite out
  // of the data directory, so the next start began an empty history.
  const directory = await started(t);
  const history = path.join(directory, 'history.sqlite');
  const db = new DatabaseSync(history);
  db.exec(
    "CREATE TABLE readings (service TEXT, time INTEGER); INSERT INTO readings VALUES ('a', 1)"
  );
  db.close();
  const volume = temporary(t);
  fs.renameSync(history, path.join(volume, 'kept.sqlite'));
  fs.symlinkSync(path.join(volume, 'history.sqlite'), history);
  const before = listSnapshots(directory).map(item => item.id);
  const refused = await admin(withDir(directory, 'snapshot'));
  assert.equal(refused.code, exitCodes.refused, refused.err);
  assert.match(
    refused.err,
    /^goblin-admin snapshot: No snapshot was taken: .*history\.sqlite is a symbolic link to nothing that exists\. Nothing was written to snapshots\/\./
  );
  assert.deepEqual(
    listSnapshots(directory).map(item => item.id),
    before
  );
  assert.deepEqual(
    fs.readdirSync(path.join(directory, 'snapshots')).filter(name => name.startsWith('.')),
    []
  );
  // Left out, it is not read: recorded as left out, so the restore keeps the link as it is.
  const left = await admin(withDir(directory, 'snapshot', '--no-history', '--json'));
  assert.equal(left.code, 0, left.err);
  const manifest = JSON.parse(
    fs.readFileSync(path.join(directory, 'snapshots', left.json().id, 'manifest.json'), 'utf8')
  );
  assert.deepEqual(manifest.excluded, ['history.sqlite']);
  assert.ok(!manifest.absent.includes('history.sqlite'), JSON.stringify(manifest.absent));
  fs.renameSync(path.join(volume, 'kept.sqlite'), path.join(volume, 'history.sqlite'));
  const restored = await admin(withDir(directory, 'restore-snapshot', left.json().id));
  assert.equal(restored.code, 0, restored.err);
  assert.doesNotMatch(restored.out, /Removed/);
  assert.equal(fs.readlinkSync(history), path.join(volume, 'history.sqlite'));
});

test('migrate --apply on 1.4.x data whose files are all links to nothing refuses (78), writing nothing but goblin.lock; once the volume is back it takes the pinned snapshot', async t => {
  // Read as no data, migrate --apply took no snapshot, created and migrated control.sqlite and
  // exited 0: the start that followed once the volume was mounted had nothing pending, so the
  // pinned pre-upgrade snapshot (the way back to 1.4.x) was never taken.
  const directory = temporary(t);
  const volume = temporary(t);
  for (const name of ['config.json', 'history.sqlite'])
    fs.symlinkSync(path.join(volume, name), path.join(directory, name));
  const refused = await admin(withDir(directory, 'migrate', '--apply'));
  assert.equal(refused.code, exitCodes.refused, refused.err);
  assert.equal(
    refused.err,
    `goblin-admin migrate: No snapshot was taken: ${path.join(directory, 'config.json')} is a symbolic link to nothing that exists. Nothing was written to snapshots/. Put the file back in its place (mount the volume a link points to), or move what is there out of the data directory, then take the snapshot again.\n`
  );
  assert.equal(refused.out, '');
  assert.deepEqual(
    fs
      .readdirSync(directory)
      .filter(name => name !== 'goblin.lock' && name !== 'orbit.lock')
      .sort(),
    ['config.json', 'history.sqlite'],
    'no control.sqlite, no snapshots/'
  );
  assert.deepEqual(fs.readdirSync(volume), [], 'nothing created through the links');
  // The volume is back: the snapshot is taken, pinned, before the migration.
  fs.writeFileSync(path.join(volume, 'config.json'), '{"services":[]}\n');
  const history = new DatabaseSync(path.join(volume, 'history.sqlite'));
  history.exec('CREATE TABLE readings (service TEXT, time INTEGER)');
  history.close();
  const applied = await admin(withDir(directory, 'migrate', '--apply', '--json'));
  assert.equal(applied.code, 0, applied.err);
  const [snapshot] = listSnapshots(directory);
  assert.equal(applied.json().snapshot, snapshot.id);
  assert.equal(snapshot.pinned, true);
  assert.equal(snapshot.reason, 'pre-upgrade');

  // Only history.sqlite, a link to nothing: left out of the snapshot (recorded as left out, so
  // a restore keeps it), which is still taken, pinned, before control.sqlite is created.
  const alone = temporary(t);
  fs.symlinkSync(path.join(temporary(t), 'history.sqlite'), path.join(alone, 'history.sqlite'));
  const kept = await admin(withDir(alone, 'migrate', '--apply', '--json'));
  assert.equal(kept.code, 0, kept.err);
  const [only] = listSnapshots(alone);
  assert.equal(kept.json().snapshot, only.id);
  assert.equal(only.pinned, true);
  const manifest = JSON.parse(
    fs.readFileSync(path.join(alone, 'snapshots', only.id, 'manifest.json'), 'utf8')
  );
  assert.deepEqual(manifest.files, []);
  assert.deepEqual(manifest.excluded, ['history.sqlite']);
});

test('key status and key rotate print no control characters from a keyring row', async t => {
  // kid and purpose are saved data: key status lists every row before it checks the key, and
  // key rotate names the kids it retired. A crafted row wrote an escape sequence and a forged
  // line. These rows are wrapped under the key, as one with the key's holder writes them.
  const directory = await started(t);
  const key = Buffer.from(hexKey, 'hex');
  const wrapped = (kid, purpose) => {
    const iv = randomBytes(12);
    const cipher = createCipheriv(
      'aes-256-gcm',
      Buffer.from(hkdfSync('sha256', key, Buffer.alloc(0), 'orbit/kek-wrap/v1', 32)),
      iv
    );
    cipher.setAAD(Buffer.from(`orbit-keyring-v1|${kid}|${purpose}`));
    const ct = Buffer.concat([cipher.update(randomBytes(32)), cipher.final()]);
    return ['w1', ...[iv, ct, cipher.getAuthTag()].map(part => part.toString('base64url'))].join(
      '.'
    );
  };
  const forgedKid = 'k\u001b[2J\n[orbit] FORGED-KID-LINE';
  const forgedPurpose = 'p\u001b[31m\n[orbit] FORGED-PURPOSE';
  const sealKid = 's\u009b2J\u2028[orbit] FORGED-SEAL-KID\u{202e}';
  const db = new DatabaseSync(path.join(directory, 'control.sqlite'));
  const insert = db.prepare(
    'INSERT INTO keyring (kid, purpose, wrapped, created_at, retired_at) VALUES (?, ?, ?, ?, NULL)'
  );
  const later = Date.UTC(2030, 0, 1);
  insert.run(forgedKid, forgedPurpose, wrapped(forgedKid, forgedPurpose), later);
  // The newest unretired seal key: the active one, which key rotate --purpose seal retires.
  insert.run(sealKid, 'seal', wrapped(sealKid, 'seal'), later + 1);
  db.close();
  // A new object each time: the command removes GOBLIN_SECRET_KEY from it once read.
  const env = () => ({ GOBLIN_SECRET_KEY: hexKey });
  const clean = (result, what) => {
    assert.ok(
      !/[\u0000-\u0009\u000b-\u001f\u007f-\u009f\u2028\u2029]/.test(result.out),
      `${what}: ${JSON.stringify(result.out)}`
    );
    for (const line of result.out.split('\n'))
      assert.ok(
        !line.startsWith('[orbit]'),
        `${what}: no line of saved text stands alone: ${line}`
      );
  };
  const status = await admin(withDir(directory, 'key', 'status'), { env: env(), directory });
  assert.equal(status.code, 0, status.err);
  clean(status, 'key status');
  assert.match(status.out, /^Keyring: 6 data keys$/m);
  assert.match(
    status.out,
    /^ {2}k\[2J\[orbit\] FORGED-KID-LINE {2}p\[31m\[orbit\] FORGED-PURPOSE {2}created 2030-01-01 00:00:00 UTC$/m
  );
  assert.match(status.out, /^ {2}s2J\[orbit\] FORGED-SEAL-KID {2}seal {6}created /m);
  assert.match(status.out, /^The key opens every data key\.$/m);
  // --json keeps the values as they are saved, whole, but writes every control character, line
  // or paragraph separator and direction override in them as an escape (\n for the line break,
  // \u for the others): JSON.stringify left the C1 controls, U+2028 and U+202E raw, which
  // reached the terminal.
  const listed = await admin(withDir(directory, 'key', 'status', '--json'), {
    env: env(),
    directory,
  });
  assert.equal(listed.code, 0, listed.err);
  assert.ok(
    !/[\u0000-\u0009\u000b-\u001f\u{7f}-\u{9f}\u{2028}\u{2029}\u{202a}-\u{202e}\u{2066}-\u{2069}]/u.test(
      listed.out
    ),
    JSON.stringify(listed.out)
  );
  assert.match(listed.out, /"kid": "s\\u009b2J\\u2028\[orbit\] FORGED-SEAL-KID\\u202e"/);
  const json = listed.json();
  assert.ok(json.keyring.some(row => row.kid === forgedKid && row.purpose === forgedPurpose));
  assert.ok(json.keyring.some(row => row.kid === sealKid && row.purpose === 'seal'));
  const rotated = await admin(withDir(directory, 'key', 'rotate', '--purpose', 'seal'), {
    env: env(),
    directory,
  });
  assert.equal(rotated.code, 0, rotated.err);
  clean(rotated, 'key rotate');
  assert.match(
    rotated.out,
    /^New data keys for seal; retired s2J\[orbit\] FORGED-SEAL-KID \(they still open older values\)\.$/m
  );
});

// What a terminal or a log reader acts on: C0 controls but the line break, DEL and C1 controls,
// the line and paragraph separators, and the direction embeddings, overrides and isolates.
const rawCharacter =
  /[\u0000-\u0009\u000b-\u001f\u{7f}-\u{9f}\u{2028}\u{2029}\u{202a}-\u{202e}\u{2066}-\u{2069}]/u;

// verify-audit --json lists the key ids of journal lines signed with a key the keyring does not
// hold, and anyone could have added such a line to the journal. JSON.stringify left the C1
// controls, U+2028 and U+202E in them raw.
test('verify-audit --json writes a journal line’s key id whole, its control characters as \\u escapes', async t => {
  const directory = await started(t);
  const kid = 'k\u009b2J\u{2028}[orbit] FORGED\u{202e}';
  const journal = path.join(directory, '..', `${path.basename(directory)}-forged-journal.txt`);
  t.after(() => fs.rmSync(journal, { force: true }));
  // As a log holds it: one line, its characters written as JSON escapes.
  const line = JSON.stringify({
    orbit: 'audit.checkpoint',
    v: 1,
    instance: 'another',
    seq: 5,
    time: Date.UTC(2026, 8, 29),
    hash: '0'.repeat(64),
    key_id: kid,
    reason: 'commit',
    mac: '0'.repeat(64),
  }).replace(
    /[\u{9b}\u{2028}\u{202e}]/gu,
    c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`
  );
  fs.writeFileSync(journal, `${line}\n`);
  const result = await admin(
    withDir(directory, 'verify-audit', '--checkpoints', journal, '--json'),
    {
      env: { GOBLIN_SECRET_KEY: hexKey },
      directory,
    }
  );
  assert.equal(result.code, exitCodes.unverified, result.err);
  assert.ok(!rawCharacter.test(result.out), JSON.stringify(result.out));
  assert.match(result.out, /"k\\u009b2J\\u2028\[orbit\] FORGED\\u202e"/);
  assert.deepEqual(result.json().unverifiable, [
    { reason: 'unknown_key', lines: 1, keyIds: [kid] },
  ]);
});

// snapshots/ as a link to nothing (an unmounted volume, which may hold the pinned way back to
// 1.4.x), a loop of links or a file: the start refuses it (snapshots_not_directory). goblin-admin
// read the first as no snapshots ("No snapshots.", "Snapshots: 0"), a loop as an interrupted
// restore whose record cannot be read (migrate --apply refused with that, status reported it),
// and failed with mkdir's or scandir's raw ENOENT, ELOOP or ENOTDIR. Each now says what the
// start says, writing nothing but goblin.lock.
test('goblin-admin refuses (78) a snapshots/ that is a link to nothing, a loop of links or a file, writing nothing but goblin.lock; status reports it', async t => {
  const volume = temporary(t);
  const kinds = {
    dangling: snapshots => fs.symlinkSync(path.join(volume, 'snapshots'), snapshots),
    loop: snapshots => fs.symlinkSync(snapshots, snapshots),
    file: snapshots => fs.writeFileSync(snapshots, 'not a directory\n'),
  };
  for (const [kind, make] of Object.entries(kinds)) {
    const prepare = () => {
      const directory = temporary(t);
      fs.writeFileSync(path.join(directory, 'config.json'), '{"services":[]}\n');
      make(path.join(directory, 'snapshots'));
      return directory;
    };
    const message =
      kind === 'file'
        ? /snapshots is not a directory\. Uptime Goblin keeps its snapshots there: move it out of the data directory with Uptime Goblin stopped, then start Uptime Goblin \(or run the command\) again\./
        : /snapshots is a symbolic link to no directory \(it names a missing one, or a loop of links\)\. Uptime Goblin keeps its snapshots there: point it at a directory, or remove it with Uptime Goblin stopped, then start Uptime Goblin \(or run the command\) again\./;
    for (const args of [
      ['snapshots'],
      ['snapshots', '--verify'],
      ['snapshot'],
      ['migrate', '--apply'],
      ['migrate', '--apply', '--no-snapshot'],
      ['restore-snapshot', 'manual-1.5.0-20260101T000000Z'],
    ]) {
      const directory = prepare();
      const what = `${kind}: ${args.join(' ')}`;
      const result = await admin(withDir(directory, ...args));
      assert.equal(result.code, exitCodes.refused, `${what}: ${result.err}`);
      assert.ok(
        result.err.startsWith(`goblin-admin ${args[0]}: ${path.join(directory, 'snapshots')} `),
        `${what}: ${result.err}`
      );
      assert.match(result.err, message, what);
      assert.doesNotMatch(result.err, /interrupted|ENOENT|ELOOP|ENOTDIR/, what);
      assert.equal(result.out, '', what);
      assert.deepEqual(
        fs
          .readdirSync(directory)
          .filter(name => name !== 'goblin.lock' && name !== 'orbit.lock')
          .sort(),
        ['config.json', 'snapshots'],
        what
      );
    }
    assert.deepEqual(fs.readdirSync(volume), [], 'nothing made through the link');
    // status reports it as the start refuses it; whether a restore was interrupted cannot be
    // told, since its record is kept in snapshots/.
    const directory = prepare();
    const status = await admin(withDir(directory, 'status'));
    assert.equal(status.code, 0, status.err);
    assert.match(status.out, new RegExp(`^Snapshots: PROBLEM: .*${message.source}$`, 'm'), kind);
    assert.match(
      status.out,
      /^Restore interrupted: cannot be told \(a restore keeps its record in snapshots\/\)\.$/m
    );
    assert.doesNotMatch(status.out, /^Snapshots: \d|was interrupted part way/m, kind);
    const json = (await admin(withDir(directory, 'status', '--json'))).json();
    assert.equal(json.snapshots.count, null, kind);
    assert.match(json.snapshots.problem, message, kind);
    assert.deepEqual([json.restore.interrupted, json.restore.unknown], [null, true], kind);
  }
});

// check-data decided with fs.existsSync whether history.sqlite exists: a link to nothing or a
// loop of links read as none, so it reported "No history database yet. No drift found." (exit
// 0) for data the start refuses (78). control.sqlite was refused already.
test('check-data refuses (78) a history.sqlite that is a link to nothing or a loop of links, as the start does', async t => {
  for (const kind of ['dangling', 'loop']) {
    const directory = await started(t);
    const history = path.join(directory, 'history.sqlite');
    fs.rmSync(history, { force: true });
    if (kind === 'loop') fs.symlinkSync(history, history);
    else fs.symlinkSync(path.join(directory, 'unmounted', 'history.sqlite'), history);
    const before = fingerprint(directory, ['history.sqlite']);
    const result = await admin(withDir(directory, 'check-data'));
    assert.equal(result.code, exitCodes.refused, `${kind}: ${result.err}`);
    assert.equal(
      result.err,
      `goblin-admin check-data: ${history} ${kind === 'loop' ? 'is not a regular file' : 'is a symbolic link to nothing that exists'}\n`
    );
    assert.equal(result.out, '', kind);
    assert.deepEqual(fingerprint(directory, ['history.sqlite']), before, kind);
    assert.equal(fs.existsSync(path.join(directory, 'unmounted')), false, kind);
  }
});

// A relative --data-dir or GOBLIN_DATA_DIR (data) was checked as given, before path.resolve: from
// a working directory whose path holds a line break or U+202E, status printed the resolved path
// raw ("Data directory: …"), and the key commands refused <data>/secret.key by the rule for key
// paths. The resolved path is checked too, as a start checks it.
test('a relative data directory is checked as resolved against the working directory (exit 2), never printed raw', t => {
  const base = temporary(t);
  for (const [name, character] of [
    ['U+000A', '\n'],
    ['U+202E', '\u{202e}'],
    ['U+2028', '\u{2028}'],
  ]) {
    const cwd = path.join(base, `w${character}[orbit] FORGED`);
    fs.mkdirSync(cwd);
    for (const [args, env, label] of [
      [['status', '--data-dir', 'data'], {}, '--data-dir'],
      [['key', 'status', '--data-dir', 'data'], {}, '--data-dir'],
      [['status'], { GOBLIN_DATA_DIR: 'data' }, 'GOBLIN_DATA_DIR'],
    ]) {
      const what = `${name}: ${args.join(' ')} ${JSON.stringify(env)}`;
      const result = spawnSync(process.execPath, [script, ...args], {
        cwd,
        env: { PATH: process.env.PATH, ...env },
        encoding: 'utf8',
        timeout: 20000,
      });
      assert.equal(result.status, exitCodes.usage, `${what}: ${result.stderr}`);
      assert.equal(result.stdout, '', what);
      assert.match(
        result.stderr,
        new RegExp(
          `^goblin-admin ${args[0]}: ${label} must not contain a control character, .* \\(it holds U\\+${name.slice(2)}\\); it is "data", resolved against the working directory to ".*"\\.\\n$`
        ),
        what
      );
      assert.ok(!rawCharacter.test(result.stderr), `${what}: ${JSON.stringify(result.stderr)}`);
      assert.equal(fs.existsSync(path.join(cwd, 'data')), false, what);
    }
  }
});

// Neither --data-dir nor GOBLIN_DATA_DIR: the data directory is data/ beside Uptime Goblin, whose own
// path (where Uptime Goblin is installed) may hold such a character too. It is checked by the same rule
// and named as what it is, not as a variable nobody set; status printed it raw.
test('the default data directory beside Uptime Goblin is checked by the same rule (exit 2), named as such', async () => {
  for (const [name, character] of [
    ['U+000A', '\n'],
    ['U+202E', '\u{202e}'],
  ]) {
    const root = path.join(os.tmpdir(), `orbit${character}[orbit] FORGED`, 'app');
    for (const args of [['status'], ['key', 'status']]) {
      let out = '',
        err = '';
      const code = await main(args, {
        env: {},
        uid: 1000,
        root,
        container: false,
        proc: noProcesses,
        stdout: text => (out += text),
        stderr: text => (err += text),
      });
      const what = `${name}: ${args.join(' ')}`;
      assert.equal(code, exitCodes.usage, `${what}: ${err}${out}`);
      assert.equal(out, '', what);
      assert.match(
        err,
        new RegExp(
          `^goblin-admin ${args[0]}: The data directory beside Uptime Goblin must not contain a control character, .* \\(it holds U\\+${name.slice(2)}\\); it is "[^"\\n]*"\\.\\n$`
        ),
        what
      );
      assert.ok(!rawCharacter.test(err), `${what}: ${JSON.stringify(err)}`);
      assert.equal(fs.existsSync(path.dirname(root)), false, what);
    }
  }
});

// The key files given to goblin-admin are printed in command lines (the refusal to run as root,
// messages that name a key command) before lib/keyring.mjs reads them by its rule for key paths:
// a path with a line break or U+202E, as given or resolved against the working directory, was
// printed raw. And an unknown command's name was quoted with JSON.stringify, which leaves the C1
// controls and direction overrides raw.
test('a key file path or a command name with a control character or U+202E is never printed raw (exit 2)', async t => {
  const directory = await started(t);
  for (const [variable, uid] of [
    ['GOBLIN_SECRET_KEY_FILE', 0],
    ['GOBLIN_SECRET_KEY_PREVIOUS_FILE', 0],
    ['GOBLIN_SECRET_KEY_FILE', 1000],
  ]) {
    const what = `${variable}, uid ${uid}`;
    const result = await admin(withDir(directory, 'key', 'rotate', '--purpose', 'seal'), {
      env: { [variable]: '/etc/uptime-goblin/x\n[orbit] FORGED\u{202e}/key' },
      uid,
      directory,
    });
    assert.equal(result.code, exitCodes.usage, `${what}: ${result.err}`);
    assert.equal(
      result.err,
      `goblin-admin key: ${variable} must be a path without a control character, a Unicode line or paragraph separator, or a text-direction embedding, override or isolate (it holds U+000A); it is "/etc/uptime-goblin/x\\n[orbit] FORGED\\u202e/key".\n`,
      what
    );
  }
  const cwd = path.join(temporary(t), 'w\n[orbit] FORGED');
  fs.mkdirSync(cwd);
  const relative = spawnSync(process.execPath, [script, 'key', 'status', '--data-dir', directory], {
    cwd,
    env: { PATH: process.env.PATH, GOBLIN_SECRET_KEY_FILE: 'key' },
    encoding: 'utf8',
    timeout: 20000,
  });
  assert.equal(relative.status, exitCodes.usage, relative.stderr);
  assert.match(
    relative.stderr,
    /^goblin-admin key: GOBLIN_SECRET_KEY_FILE must be a path without .* \(it holds U\+000A\); it is "key", resolved against the working directory to ".*"\.\n$/
  );
  assert.ok(!rawCharacter.test(relative.stderr), JSON.stringify(relative.stderr));
  const unknown = await admin(['frob\u009b2J\u{202e}nicate']);
  assert.equal(unknown.code, exitCodes.usage);
  assert.equal(
    unknown.err,
    'goblin-admin: unknown command "frob\\u009b2J\\u202enicate". Run goblin-admin help.\n'
  );
});

// ---------------------------------------------------------------------------------------------
// Arguments are input too: exact, checked before a key is read or goblin.lock is taken.

test('arguments are exact: an empty, unusable or repeated option, extra arguments and options the action does not take exit 2', async t => {
  const directory = await started(t);
  const refused = async (args, pattern, options) => {
    const result = await admin(args, options);
    assert.equal(result.code, exitCodes.usage, `${JSON.stringify(args)}: ${result.err}`);
    assert.match(result.err, pattern, JSON.stringify(args));
    assert.ok(!/[\u0000-\u0009\u000b-\u001f\u007f]/.test(result.err), JSON.stringify(result.err));
    return result;
  };
  // An empty --data-dir fell back to $GOBLIN_DATA_DIR or ./data; a repeated one kept the last.
  await refused(['status', '--data-dir', ''], /--data-dir needs a directory\./);
  await refused(
    ['check-data', '--data-dir', directory, '--data-dir', '/nonexistent'],
    /--data-dir is given more than once\./
  );
  await refused(
    withDir(directory, 'snapshot', '--reason', 'a', '--reason', 'b'),
    /--reason is given more than once/
  );
  await refused(
    ['status', '--data-dir', `${directory}\n[orbit] FORGED`],
    /--data-dir must not contain a control character, .* \(it holds U\+000A\)\./
  );
  await refused(
    ['status'],
    /GOBLIN_DATA_DIR must not contain a control character, .* \(it holds U\+001B\)\./,
    {
      env: { GOBLIN_DATA_DIR: `${directory}\u001b[2J` },
    }
  );
  // A line separator or a direction override too, as in a key path: a start took such a data
  // directory once and then refused its own <data>/secret.key at every start. The refusal names
  // the character by its code point and never prints it.
  for (const [character, name] of [
    ['\u2028', 'U\\+2028'],
    ['\u202e', 'U\\+202E'],
    ['\u2069', 'U\\+2069'],
  ])
    for (const [args, env] of [
      [['status', '--data-dir', `${directory}${character}x`], {}],
      [['check-data'], { GOBLIN_DATA_DIR: `${directory}${character}x` }],
    ]) {
      const result = await refused(
        args,
        new RegExp(`must not contain a control character, .* \\(it holds ${name}\\)\\.$`, 'm'),
        { env }
      );
      assert.ok(!result.err.includes(character), JSON.stringify(result.err));
    }
  // Extra positionals were ignored.
  for (const command of [
    ['status'],
    ['snapshots'],
    ['check-data'],
    ['migrate', '--plan'],
    ['snapshot'],
    ['verify-audit'],
  ])
    await refused(
      withDir(directory, ...command, 'junk'),
      /takes no arguments; "junk" is one too many\./
    );
  await refused(
    withDir(directory, 'restore-snapshot', 'a', 'b'),
    /takes at most 1 argument; "b" is one too many\./
  );
  await refused(withDir(directory, 'key', 'status', 'extra'), /takes at most 1 argument/);
  // Options the action does not take were ignored.
  await refused(
    withDir(directory, 'key', 'status', '--confirm-lost-key'),
    /^goblin-admin key: --confirm-lost-key applies to key reset only\.\n$/
  );
  await refused(
    withDir(directory, 'key', 'status', '--purpose', 'audit'),
    /--purpose applies to key rotate only\./
  );
  await refused(
    withDir(directory, 'key', 'compose-check', '--use-data-dir-key'),
    /--use-data-dir-key applies to key reset only\./
  );
  await refused(
    withDir(directory, 'migrate', '--plan', '--no-snapshot'),
    /--no-snapshot applies to migrate --apply only\./
  );
  // An unknown option is shown escaped.
  const escaped = await refused(
    ['status', '--\u001b[31mred'],
    /Unknown option '--\\u001b\[31mred'/
  );
  assert.ok(!escaped.err.includes('\u001b'));
});

test('a data directory that does not exist is never reported clean: read commands exit 1, status reports it and exits 1', async t => {
  const missing = path.join(temporary(t), 'no-such-data');
  for (const command of [
    ['check-data'],
    ['snapshots'],
    ['migrate', '--plan'],
    ['key', 'status'],
    ['verify-audit'],
    ['key', 'remove-data-copy'],
    ['snapshot'],
  ]) {
    const result = await admin(withDir(missing, ...command));
    assert.equal(result.code, exitCodes.failed, `${command.join(' ')}: ${result.out}${result.err}`);
    assert.match(result.err, /no-such-data does not exist\./);
    assert.doesNotMatch(result.out, /No drift found|No snapshots|Nothing to migrate/);
    assert.equal(fs.existsSync(missing), false, command.join(' '));
  }
  const status = await admin(withDir(missing, 'status', '--unit', path.join(missing, 'x.service')));
  assert.equal(status.code, exitCodes.failed);
  assert.match(status.out, /^Data directory: .*no-such-data \(missing\)$/m);
  const file = path.join(temporary(t), 'a-file');
  fs.writeFileSync(file, 'x');
  const notDirectory = await admin(withDir(file, 'snapshots'));
  assert.equal(notDirectory.code, exitCodes.failed);
  assert.match(notDirectory.err, /a-file is not a directory\./);
});

test('snapshot --reason and key rotate --purpose are checked before goblin.lock: a repeated purpose never makes two keys', async t => {
  const directory = await started(t);
  const env = { GOBLIN_SECRET_KEY: hexKey };
  // Held by "Uptime Goblin": a check made after the lock would answer 75.
  const lock = acquireLock(directory);
  try {
    const reason = await admin(withDir(directory, 'snapshot', '--reason', 'Bad Reason\u001b[2J'), {
      directory,
    });
    assert.equal(reason.code, exitCodes.usage, reason.err);
    assert.match(
      reason.err,
      /--reason takes a lower-case word .*; "Bad Reason\\u001b\[2J" is not one\./
    );
    const twice = await admin(
      withDir(directory, 'key', 'rotate', '--purpose', 'audit', '--purpose', 'audit'),
      { env, directory }
    );
    assert.equal(twice.code, exitCodes.usage, twice.err);
    assert.match(twice.err, /--purpose audit is given more than once\./);
    const unknown = await admin(withDir(directory, 'key', 'rotate', '--purpose', 'x\u001b[2J'), {
      env,
      directory,
    });
    assert.equal(unknown.code, exitCodes.usage, unknown.err);
    assert.match(
      unknown.err,
      /Unknown key purpose "x\\u001b\[2J" \(one of seal, sessions, login, audit\)\./
    );
  } finally {
    lock.release();
  }
  const rotated = await admin(withDir(directory, 'key', 'rotate', '--purpose', 'audit', '--json'), {
    env,
    directory,
  });
  assert.equal(rotated.code, 0, rotated.err);
  assert.equal(rotated.json().active.length, 1);
});

test('Keyring.rotate leaves exactly one active key per purpose, whatever purposes it is given', async () => {
  const store = memoryKeyringStore();
  const key = Buffer.from(hexKey, 'hex');
  const keyring = await Keyring.open(store, { key });
  const result = await keyring.rotate({ purposes: ['audit', 'audit', 'seal', 'audit'] });
  assert.equal(result.retired.length, 2);
  assert.equal(result.active.length, 2);
  const active = purpose =>
    store.rows.filter(row => row.purpose === purpose && row.retired_at == null);
  assert.equal(active('audit').length, 1);
  assert.equal(active('seal').length, 1);
  await keyring.rotate({ purposes: ['audit'] });
  assert.equal(active('audit').length, 1, 'a later rotation retires every older audit key');
});

test('restore-snapshot and snapshots --verify never wait on a FIFO in place of a live file or beside a database', async t => {
  const directory = await started(t);
  const root = path.join(directory, 'snapshots');
  const [snapshot] = listSnapshots(directory);
  const fifo = file => assert.equal(spawnSync('mkfifo', [file]).status, 0);
  // In a child with a deadline: copying or hashing a FIFO waits for a writer for good, here
  // with goblin.lock held and, once the restore began, its journal making every start refuse.
  const run = (...args) =>
    spawnSync(process.execPath, [script, ...args, '--data-dir', directory], {
      encoding: 'utf8',
      timeout: 5000,
      killSignal: 'SIGKILL',
      env: { PATH: process.env.PATH, GOBLIN_SECRET_KEY: hexKey },
    });
  const restoreLeftNothing = what => {
    assert.ok(!fs.existsSync(path.join(root, '.restore-in-progress.json')), what);
    assert.deepEqual(
      fs.readdirSync(root).filter(name => name.startsWith('.')),
      [],
      `${what}: no folder or journal of a restore`
    );
    assert.deepEqual(
      fs.readdirSync(directory).filter(name => name.includes('.restoring')),
      [],
      `${what}: no copies beside the live files`
    );
  };
  // The documented way out of "config.json … must be a regular file" stopped on that very file.
  const config = path.join(directory, 'config.json');
  fs.renameSync(config, `${config}.kept`);
  fifo(config);
  const live = run('restore-snapshot', snapshot.id);
  assert.equal(live.signal, null, 'restore-snapshot waited on the FIFO');
  assert.equal(live.status, 1, live.stderr);
  assert.match(
    live.stderr,
    /was not restored: .*config\.json is not a regular file, so it cannot be set aside\. No file was replaced or set aside\. Move it out of the data directory, then restore again\./
  );
  restoreLeftNothing('config.json');
  fs.rmSync(config);
  fs.renameSync(`${config}.kept`, config);
  // A FIFO in place of a live database's journal: SQLite's read of the database waited on it.
  const journal = path.join(directory, 'control.sqlite-journal');
  fifo(journal);
  const beside = run('restore-snapshot', snapshot.id);
  assert.equal(beside.signal, null, 'restore-snapshot waited on the journal');
  assert.equal(beside.status, 1, beside.stderr);
  assert.match(
    beside.stderr,
    /control\.sqlite-journal is not a regular file, so it cannot be set aside/
  );
  restoreLeftNothing('control.sqlite-journal');
  fs.rmSync(journal);
  // One beside a snapshot's copy of control.sqlite (the first, pre-upgrade, one has none): --verify
  // reports it instead of waiting on it.
  const manual = await admin(withDir(directory, 'snapshot', '--json'), {
    env: { GOBLIN_SECRET_KEY: hexKey },
    directory,
  });
  assert.equal(manual.code, 0, manual.err);
  fifo(path.join(root, manual.json().id, 'control.sqlite-journal'));
  const verified = run('snapshots', '--verify');
  assert.equal(verified.signal, null, 'snapshots --verify waited on the journal');
  assert.equal(verified.status, 1, verified.stderr);
  assert.match(
    verified.stdout,
    new RegExp(
      `${manual.json().id} .*DAMAGED: control\\.sqlite: .*control\\.sqlite-journal is not a regular file`
    )
  );
});

test(
  'status --unit and verify-audit --checkpoints never wait on a FIFO and refuse oversized input',
  { timeout: 120000 },
  async t => {
    const directory = await started(t);
    const fifo = path.join(temporary(t), 'u.fifo');
    assert.equal(spawnSync('mkfifo', [fifo]).status, 0);
    for (const args of [
      ['status', '--unit', fifo],
      ['verify-audit', '--checkpoints', fifo],
    ]) {
      const run = spawnSync(process.execPath, [script, ...args, '--data-dir', directory], {
        encoding: 'utf8',
        timeout: 5000,
        killSignal: 'SIGKILL',
        env: { PATH: process.env.PATH, GOBLIN_SECRET_KEY: hexKey },
      });
      assert.equal(run.signal, null, `${args[0]} waited on the FIFO`);
      if (args[0] === 'status') {
        assert.equal(run.status, 0, run.stderr);
        assert.match(run.stdout, /Service binary: PROBLEM: .*u\.fifo is not a regular file/);
      } else {
        assert.equal(run.status, exitCodes.usage, run.stderr);
        assert.match(run.stderr, /could not read the journal .*u\.fifo \(not a regular file\)/);
      }
    }
    const unit = path.join(temporary(t), 'big.service');
    fs.writeFileSync(
      unit,
      'ExecStart=/usr/bin/node /opt/uptime-goblin/server.mjs\n' + '#'.repeat(70 * 1024)
    );
    const big = await admin(withDir(directory, 'status', '--unit', unit));
    assert.match(big.out, /Service binary: PROBLEM: .*big\.service is larger than 65536 bytes/);
    // A journal on stdin that never ends stops at 512 MiB (it was read whole into one string).
    const chunk = Buffer.alloc(2 ** 20, 'x');
    // It ends after 600 MiB, past the cap: without the cap the command reads it all and goes on
    // to check it, so this fails instead of reading for ever.
    let sent = 0;
    const endless = new Readable({
      read() {
        if (sent >= 600 * 2 ** 20) return this.push(null);
        sent += chunk.length;
        this.push(chunk);
      },
    });
    const piped = await admin(withDir(directory, 'verify-audit', '--checkpoints', '-'), {
      env: { GOBLIN_SECRET_KEY: hexKey },
      directory,
      stdin: endless,
    });
    endless.destroy();
    assert.equal(piped.code, exitCodes.usage, piped.err);
    assert.match(piped.err, /the journal on standard input is larger than 512 MiB/);
    assert.ok(sent <= 520 * 2 ** 20, `${sent} bytes read`);
  }
);

test('verify-audit keeps only checkpoint lines: one after a line longer than any checkpoint still counts', async t => {
  const directory = await started(t);
  const lines = await auditRows(directory, 2);
  const journal = path.join(temporary(t), 'journal.txt');
  fs.writeFileSync(
    journal,
    [lines[0], 'y'.repeat(200 * 1024) + lines[1].slice(0, 40), lines[1]].join('\n')
  );
  const result = await admin(withDir(directory, 'verify-audit', '--checkpoints', journal), {
    env: { GOBLIN_SECRET_KEY: hexKey },
    directory,
  });
  assert.equal(result.code, 0, result.err);
  assert.match(result.out, /^Journal: 2 checkpoint lines; 2 match;/m);
});

test('status as root runs the unit binary only when root alone can change it and its directory', async t => {
  const directory = await started(t);
  const bin = temporary(t);
  fs.chmodSync(bin, 0o777);
  const marker = path.join(bin, 'ran');
  const binary = path.join(bin, 'node');
  fs.writeFileSync(binary, `#!/bin/sh\ntouch '${marker}'\necho v24.0.0\n`, { mode: 0o755 });
  const unit = path.join(bin, 'uptime-goblin.service');
  fs.writeFileSync(unit, `ExecStart=${binary} /opt/uptime-goblin/server.mjs\n`);
  const asRoot = await admin(withDir(directory, 'status', '--unit', unit), { uid: 0 });
  assert.match(
    asRoot.out,
    /Service binary: PROBLEM: .*node was not run as root: it or a directory above it is not root's alone/
  );
  assert.equal(fs.existsSync(marker), false, 'the binary was not run');
  // A link in a directory another user controls, to a program root alone controls: root runs
  // the program the link names when checked, never the link, which its owner could point at
  // their own program between the check and the run.
  const sh = fs.realpathSync('/bin/sh');
  const link = path.join(bin, 'linked-node');
  fs.symlinkSync('/bin/sh', link);
  const linkedUnit = path.join(bin, 'linked.service');
  fs.writeFileSync(linkedUnit, `ExecStart=${link} /opt/uptime-goblin/server.mjs\n`);
  const ran = [];
  const linked = checkUnit(linkedUnit, {
    uid: 0,
    run: file => {
      ran.push(file);
      // The owner repoints the link meanwhile; what runs is already decided.
      fs.rmSync(link);
      fs.symlinkSync(binary, link);
      return { stdout: 'v24.0.0\n' };
    },
  });
  if (fs.statSync(sh).uid === 0) {
    assert.deepEqual(ran, [sh]);
    assert.equal(linked.ok, true, JSON.stringify(linked));
  } else assert.deepEqual(ran, [], 'a program root does not own is never run as root');
  // Root's program in root's directory is not enough: a directory further up that another user
  // can change lets them swap the whole directory below it. (A test cannot make root-owned files,
  // so the owners are reported: the binary and its directory root's, the one above not.)
  const above = path.join(bin, 'above'),
    below = path.join(above, 'below'),
    deep = path.join(below, 'node');
  fs.mkdirSync(below, { recursive: true });
  fs.writeFileSync(deep, '#!/bin/sh\necho v24.0.0\n', { mode: 0o755 });
  const deepUnit = path.join(bin, 'deep.service');
  fs.writeFileSync(deepUnit, `ExecStart=${deep}\n`);
  const rootOwned = new Set([fs.realpathSync(deep), fs.realpathSync(below)]);
  const lstat = file => {
    const stat = fs.lstatSync(file);
    return rootOwned.has(file) ? { uid: 0, mode: stat.mode & ~0o022 } : stat;
  };
  const ranDeep = [];
  const refused = checkUnit(deepUnit, { uid: 0, lstat, run: file => ranDeep.push(file) });
  assert.deepEqual(ranDeep, [], 'not run as root');
  assert.match(
    refused.problem,
    /was not run as root: it or a directory above it is not root's alone/
  );
  // Not root: run, as before.
  const asUser = await admin(withDir(directory, 'status', '--unit', unit), { uid: 1000 });
  assert.match(asUser.out, /Service binary: .*node \(v24\.0\.0\)$/m);
  assert.equal(fs.existsSync(marker), true);
});

test('status shows a version found by /proc only when it is a release version, and a status.json version that is not one cannot stop it', async t => {
  const directory = await started(t);
  const base = temporary(t);
  const evil = path.join(base, 'evil');
  fs.mkdirSync(evil);
  fs.writeFileSync(path.join(evil, 'server.mjs'), '');
  fs.writeFileSync(
    path.join(evil, 'package.json'),
    JSON.stringify({ version: '1.4.2\u001b]52;c;cHduZWQ=\u0007\u001b[2J' })
  );
  const proc = path.join(base, 'proc', '4242');
  fs.mkdirSync(proc, { recursive: true });
  fs.writeFileSync(
    path.join(proc, 'cmdline'),
    ['node', path.join(evil, 'server.mjs'), ''].join('\0')
  );
  fs.symlinkSync(evil, path.join(proc, 'cwd'));
  fs.writeFileSync(path.join(proc, 'environ'), [`GOBLIN_DATA_DIR=${directory}`, ''].join('\0'));
  const found = await admin(
    withDir(directory, 'status', '--unit', path.join(base, 'none.service')),
    {
      uid: 0,
      proc: path.join(base, 'proc'),
    }
  );
  assert.match(found.out, /^Orbit: running, version \?, pid 4242, found by its process/m);
  assert.ok(
    !/[\u0000-\u0009\u000b-\u001f\u007f-\u009f]/.test(found.out),
    JSON.stringify(found.out)
  );
  // A record whose version is not a release version: shown as unknown, the command goes on.
  fs.mkdirSync(path.join(directory, 'run'), { recursive: true });
  fs.writeFileSync(
    path.join(directory, 'run', 'status.json'),
    JSON.stringify({ version: 'banana', build: 'abc', pid: 2 ** 22 + 9, nonce: 'f'.repeat(32) })
  );
  const banana = await admin(
    withDir(directory, 'status', '--unit', path.join(base, 'none.service'))
  );
  assert.equal(banana.code, 0, banana.err);
  assert.match(banana.out, /version \? build abc/);
});
