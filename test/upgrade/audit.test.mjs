// The audit trail across upgrades, rollbacks, restores and key events (audit spec §10.1, 13
// rows), in real processes on one data directory: 1.4.2 (test/fixtures), 1.4.3 (tag v1.4.3)
// and the two 1.5 milestones (1.5.0-dev.0 and 1.5.0-dev.1) from the private history
// (TEST_HISTORY, test/upgrade/history.mjs) or TEST_TAG_TREES (node test/upgrade/export-tag.mjs
// <version> <dir>), and the working tree (WT).
// Every WT start keeps its standard output (the journal); "verify" is orbit-admin verify-audit
// --checkpoints <that journal> --json with the key the start used, "verify without the
// journal" the same without --checkpoints.
//
//   U1-U4  1.4.2, 1.4.3, 1.5.0-dev.0, 1.5.0-dev.1 → WT: the step, the first rows, verify intact
//   R1-R4  WT → 1.5.0-dev.1, 1.5.0-dev.0, 1.4.3, 1.4.2 (changes made there) → WT: what changed is
//          recorded, every build that opened the data named, verify intact
//   S1     a snapshot restore: the anchor in the sign-out unit; the journal from before it is
//          "not fully checked", never CHANGED
//   S3     a whole-file restore of control.sqlite: the same, with cause control_file
//   K1     kill -9 during the first WT start on 1.5.0-dev.1 data: one upgrade row, one start row
//   K3     the key file lost, orbit-admin key reset: the anchor; earlier rows unverifiable
//   K4     the keyring's audit key deleted by hand: CHANGED (key_lost)
//
// Like the other upgrade suites it skips without the fixtures unless TEST_REQUIRE lists fixtures,
// and without the private history unless it lists history.
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { setTimeout as delay } from 'node:timers/promises';
import { installRelease, installTag, skipWithoutFixtures, skipWithoutTag } from './fixtures.mjs';
import { login, password, sessionRequest, start, temporary, workingTree } from './harness.mjs';
import { listSnapshots } from '../../lib/db/snapshot.mjs';
import { freePortSync } from '../helpers/net.mjs';

const working = JSON.parse(fs.readFileSync(path.join(workingTree, 'package.json'), 'utf8')).version;
const admin = path.join(workingTree, 'lib', 'cli', 'orbit-admin.mjs');
// Test values for these throwaway installations only.
const second = 'audit-upgrade-password-2';

const releases = {
  '1.4.2': { skip: t => skipWithoutFixtures(t), install: dir => installRelease('1.4.2', dir) },
  '1.4.3': { skip: t => skipWithoutTag(t, 'v1.4.3'), install: dir => installTag('v1.4.3', dir) },
  // The milestones by their versions, installed from the commits the private history gives.
  '1.5.0-dev.0': {
    skip: t => skipWithoutTag(t, '1.5.0-dev.0'),
    install: dir => installTag('1.5.0-dev.0', dir),
  },
  '1.5.0-dev.1': {
    skip: t => skipWithoutTag(t, '1.5.0-dev.1'),
    install: dir => installTag('1.5.0-dev.1', dir),
  },
};
const versionOf = {
  '1.4.2': '1.4.2',
  '1.4.3': '1.4.3',
  '1.5.0-dev.0': '1.5.0-dev.0',
  '1.5.0-dev.1': '1.5.0-dev.1',
};

/** A world: a data directory, and each release installed once when asked for. */
function world(t) {
  const directory = temporary(t, 'orbit-audit-upgrade-');
  const apps = new Map();
  return {
    directory,
    data: path.join(directory, 'data'),
    app(release) {
      if (!apps.has(release))
        apps.set(release, releases[release].install(path.join(directory, `app-${release}`)));
      return apps.get(release);
    },
  };
}
function skipFor(t, ...names) {
  return names.some(name => releases[name].skip(t));
}

// A WT start: its journal is kept on the world for verify.
async function wt(t, w, { env = {}, secret = password } = {}) {
  const running = await start(t, { app: workingTree, data: w.data, env, secret });
  (w.journals ??= []).push(running);
  return running;
}
async function stopped(running) {
  const result = await running.stop();
  assert.equal(result.code, 0, running.output());
}

// control.sqlite read after Orbit stopped, without leaving -wal or -shm beside it.
function readControl(data, query, ...params) {
  const url = new URL(`file://${path.join(data, 'control.sqlite')}`);
  url.searchParams.set('immutable', '1');
  const db = new DatabaseSync(url, { readOnly: true });
  try {
    return db.prepare(query).all(...params);
  } finally {
    db.close();
  }
}
const auditRows = data =>
  readControl(data, 'SELECT * FROM audit_log ORDER BY seq').map(row => ({
    ...row,
    detail: row.detail === null ? null : JSON.parse(row.detail),
  }));
const applied = data =>
  readControl(data, 'SELECT id FROM schema_migrations ORDER BY id').map(row => row.id);
const checkpoints = journal =>
  journal
    .split('\n')
    .filter(line => line.startsWith('{"orbit":"audit.checkpoint"'))
    .map(line => JSON.parse(line));

/**
 * orbit-admin verify-audit --json over `data`, with `journal` (text) as --checkpoints when given,
 * and the key env `env` (default: Orbit's generated <data>/secret.key, found by itself).
 * Resolves {code, result}.
 */
function verify(w, { journal = null, env = {} } = {}) {
  const args = [admin, 'verify-audit', '--json', '--data-dir', w.data];
  if (journal !== null) {
    const file = path.join(w.directory, `journal-${randomBytes(4).toString('hex')}.txt`);
    fs.writeFileSync(file, journal);
    args.push('--checkpoints', file);
  }
  const run = spawnSync(process.execPath, args, {
    env: { PATH: process.env.PATH, ...env },
    encoding: 'utf8',
  });
  let result = null;
  try {
    result = JSON.parse(run.stdout);
  } catch {}
  assert.ok(
    result,
    `verify-audit printed no JSON (exit ${run.status}): ${run.stdout}${run.stderr}`
  );
  return { code: run.status, result };
}
const journalOf = w => (w.journals ?? []).map(running => running.journal()).join('');

// orbit-admin of a release (`app`), as a separate process.
const adminOf = (app, args, env = {}) =>
  spawnSync(process.execPath, [path.join(app, 'lib', 'cli', 'orbit-admin.mjs'), ...args], {
    env: { PATH: process.env.PATH, ...env },
    encoding: 'utf8',
  });

// A settings change and a sign-in on a 1.5 release (session) or 1.4.x (Basic).
async function someRows(running) {
  const cookie = await login(running.port, running.secret);
  const changed = await sessionRequest(running.port, 'PATCH', '/api/settings', {
    cookie,
    body: { title: `Lab ${randomBytes(3).toString('hex')}` },
  });
  assert.equal(changed.status, 200, changed.text);
  return cookie;
}
async function browserChange(running, cookie, to) {
  const response = await sessionRequest(running.port, 'POST', '/api/account/password', {
    cookie,
    body: { currentPassword: running.secret, password: to, confirmPassword: to },
  });
  assert.equal(response.status, 200, response.text);
  running.secret = to;
}

function assertIntact({ code, result }, what) {
  assert.equal(result.result, 'intact', `${what}: ${JSON.stringify(result)}`);
  assert.equal(code, 0, what);
  assert.equal(result.problem, null, what);
}

describe(
  'the audit trail across upgrades, rollbacks, restores and key events (§10.1)',
  { concurrency: 4 },
  () => {
    for (const [row, release] of [
      ['U1', '1.4.2'],
      ['U2', '1.4.3'],
    ])
      it(`${row}: ${release} with a password and a source → WT: the first rows, a checkpoint per unit, verify intact`, async t => {
        if (skipFor(t, release)) return;
        const w = world(t);
        const old = await start(t, { app: w.app(release), data: w.data });
        const source = await old.request('POST', '/api/services', {
          body: {
            type: 'http',
            name: 'Upgraded',
            group: 'Audit',
            apiUrl: 'https://api.example.test',
          },
        });
        assert.equal(source.status, 201, source.text);
        await stopped(old);
        const config = fs.readFileSync(path.join(w.data, 'config.json'));
        const authFile = path.join(w.data, 'auth.json');
        const auth = fs.existsSync(authFile) ? fs.readFileSync(authFile) : null;
        const current = await wt(t, w);
        assert.deepEqual(fs.readFileSync(path.join(w.data, 'config.json')), config);
        assert.deepEqual(fs.existsSync(authFile) ? fs.readFileSync(authFile) : null, auth);
        await someRows(current);
        await stopped(current);
        assert.ok(applied(w.data).includes('audit-001-log'));
        const rows = auditRows(w.data);
        const actions = rows.map(item => item.action);
        assert.ok(!actions.includes('audit.gap'), JSON.stringify(actions));
        // The bootstrap row (written to the inbox before the keyring existed) comes first.
        assert.equal(actions[0], 'account.bootstrap');
        const upgrade = rows.find(item => item.action === 'system.upgrade');
        assert.equal(upgrade.detail.entries.length, 1);
        assert.deepEqual(
          [upgrade.detail.entries[0].from, upgrade.detail.entries[0].to],
          [null, working]
        );
        assert.equal(rows.find(item => item.action === 'system.start').detail.first, true);
        assert.ok(actions.includes('session.login') && actions.includes('settings.update'));
        // One checkpoint line per unit: each names a row, the last one the last row.
        const lines = checkpoints(current.journal());
        assert.ok(lines.length >= 5, `${lines.length} lines`);
        for (const line of lines)
          assert.equal(rows.find(item => item.seq === line.seq)?.hash, line.hash, `#${line.seq}`);
        assert.equal(lines.at(-1).seq, rows.at(-1).seq);
        const checked = verify(w, { journal: journalOf(w) });
        assertIntact(checked, row);
        assert.equal(checked.result.journal.matched, lines.length);
      });

    it('U3: 1.5.0-dev.0 with a session cookie → WT: its three steps, the cookie works, only the newest build is named', async t => {
      if (skipFor(t, '1.5.0-dev.0')) return;
      const w = world(t);
      const old = await start(t, { app: w.app('1.5.0-dev.0'), data: w.data });
      const cookie = await login(old.port);
      await stopped(old);
      const before = applied(w.data);
      const current = await wt(t, w);
      assert.equal(
        (await sessionRequest(current.port, 'GET', '/api/session', { cookie })).status,
        200
      );
      await stopped(current);
      assert.deepEqual(
        applied(w.data)
          .filter(id => !before.includes(id))
          .sort(),
        // identity-002-displays (display codes, B6) also applies to these older builds.
        ['alerting-001-outbox', 'audit-001-log', 'identity-002-displays']
      );
      const upgrade = auditRows(w.data).find(item => item.action === 'system.upgrade');
      assert.deepEqual(
        upgrade.detail.entries.map(entry => [entry.from, entry.to]),
        [[versionOf['1.5.0-dev.0'], working]]
      );
      assertIntact(verify(w, { journal: journalOf(w) }), 'U3');
    });

    it('U4: 1.5.0-dev.1 → WT: the audit step then the displays step, the pre-upgrade snapshot, attached before identity, no snapshot row', async t => {
      if (skipFor(t, '1.5.0-dev.1')) return;
      const w = world(t);
      const old = await start(t, { app: w.app('1.5.0-dev.1'), data: w.data });
      await someRows(old);
      await stopped(old);
      const before = applied(w.data);
      const snapshots = listSnapshots(w.data).length;
      const current = await wt(t, w);
      await stopped(current);
      assert.deepEqual(
        applied(w.data).filter(id => !before.includes(id)),
        // The audit step first; identity-002-displays (display codes, B6) follows it.
        ['audit-001-log', 'identity-002-displays']
      );
      assert.ok(listSnapshots(w.data).length > snapshots, 'the pre-upgrade snapshot');
      assert.ok(listSnapshots(w.data).some(item => item.reason === 'pre-upgrade'));
      // A keyring existed: identity's rows were chained in its own units, none went through the
      // inbox.
      assert.deepEqual(
        readControl(w.data, "SELECT seq FROM sqlite_sequence WHERE name = 'audit_inbox'"),
        []
      );
      const rows = auditRows(w.data);
      const upgrade = rows.find(item => item.action === 'system.upgrade');
      assert.deepEqual(
        upgrade.detail.entries.map(entry => [entry.from, entry.to]),
        [[versionOf['1.5.0-dev.1'], working]]
      );
      assert.ok(
        !rows.some(item => item.action === 'data.snapshot'),
        'the marker took its baseline'
      );
      assertIntact(verify(w, { journal: journalOf(w) }), 'U4');
    });

    for (const [row, release] of [
      ['R1', '1.5.0-dev.1'],
      ['R2', '1.5.0-dev.0'],
    ])
      it(`${row}: WT → ${release} (a password and a setting changed in-app) → WT: both builds named, the changes recorded`, async t => {
        if (skipFor(t, release)) return;
        const w = world(t);
        const first = await wt(t, w);
        await someRows(first);
        await stopped(first);
        const count = auditRows(w.data).length;
        const old = await start(t, { app: w.app(release), data: w.data });
        const cookie = await login(old.port);
        const setting = await sessionRequest(old.port, 'PATCH', '/api/settings', {
          cookie,
          body: { title: `Changed under ${release}` },
        });
        assert.equal(setting.status, 200, setting.text);
        await browserChange(old, cookie, second);
        await stopped(old);
        assert.equal(auditRows(w.data).length, count, `${release} writes no audit row`);
        // Its orbit-admin sees the step as a newer release's and the tables as unregistered
        // (expected: they wait for the next upgrade, §10.2).
        if (release === '1.5.0-dev.1') {
          const status = adminOf(w.app(release), ['status', '--json', '--data-dir', w.data]);
          assert.match(status.stdout, /audit-001-log/, status.stdout + status.stderr);
          const check = adminOf(w.app(release), ['check-data', '--data-dir', w.data]);
          assert.equal(check.status, 1, check.stdout + check.stderr);
          assert.match(check.stdout + check.stderr, /audit_log/);
        }
        const again = await wt(t, w, { secret: second });
        await stopped(again);
        const rows = auditRows(w.data).slice(count);
        const upgrade = rows.find(item => item.action === 'system.upgrade');
        assert.deepEqual(
          upgrade.detail.entries.map(entry => entry.to),
          [versionOf[release], working]
        );
        const outside = rows.find(item => item.action === 'config.changed-outside');
        assert.ok(outside.detail.diff.some(change => change.path === 'title'));
        const password = rows.find(item => item.action === 'account.password.changed-outside');
        assert.equal(password.detail.source, 'control.sqlite');
        assertIntact(verify(w, { journal: journalOf(w) }), row);
      });

    for (const [row, release] of [
      ['R3', '1.4.3'],
      ['R4', '1.4.2'],
    ])
      it(`${row}: WT → ${release} (a setting and the password changed) → WT: recorded as changed outside, no upgrade row`, async t => {
        if (skipFor(t, release)) return;
        const w = world(t);
        const first = await wt(t, w);
        await someRows(first);
        await stopped(first);
        const history = readControl(w.data, "SELECT value FROM meta WHERE key = 'upgrade_history'");
        const old = await start(t, { app: w.app(release), data: w.data });
        assert.equal(
          (
            await old.request('PATCH', '/api/settings', {
              body: { title: `Changed under ${release}` },
            })
          ).status,
          200
        );
        const changed = await old.request('POST', '/api/auth/password', {
          body: { currentPassword: password, password: second, confirmPassword: second },
        });
        assert.equal(changed.status, 200, changed.text);
        old.secret = second;
        await stopped(old);
        const count = auditRows(w.data).length;
        const again = await wt(t, w, { secret: second });
        await stopped(again);
        const rows = auditRows(w.data).slice(count);
        assert.ok(rows.find(item => item.action === 'config.changed-outside'));
        assert.equal(
          rows.find(item => item.action === 'account.password.changed-outside').detail.source,
          'auth.json'
        );
        assert.ok(
          !rows.some(item => item.action === 'system.upgrade'),
          '1.4.x never opens control.sqlite'
        );
        // So docs/security.md never says every release that opened the data is recorded: it
        // names the 1.4.x limit spec §12 accepts (review round 1), since a 1.4.x run that
        // changed neither the settings nor the password leaves no trace at all.
        const guide = fs.readFileSync(path.join(workingTree, 'docs', 'security.md'), 'utf8');
        const auditGuide = guide.split('\n## Audit log\n')[1].split('\n## ')[0];
        assert.doesNotMatch(auditGuide, /every release that opened the data/);
        assert.match(auditGuide, /every 1\.5 release that opened `control\.sqlite`/);
        assert.match(
          auditGuide,
          /A run of 1\.4\.x after a rollback never opens `control\.sqlite` and is not named: it shows only through the changes it made to `config\.json` and the admin password[^\n]*one that changed neither[^\n]*leaves no trace in the log/
        );
        assert.deepEqual(
          readControl(w.data, "SELECT value FROM meta WHERE key = 'upgrade_history'"),
          history
        );
        assertIntact(verify(w, { journal: journalOf(w) }), row);
      });

    it('S1: a snapshot restore is anchored in the sign-out unit; the journal from before it is not fully checked, never CHANGED', async t => {
      if (skipFor(t)) return;
      const w = world(t);
      const first = await wt(t, w);
      await someRows(first);
      await stopped(first);
      const head = auditRows(w.data).at(-1);
      const snapshot = adminOf(workingTree, ['snapshot', '--json', '--data-dir', w.data]);
      assert.equal(snapshot.status, 0, snapshot.stdout + snapshot.stderr);
      const id = listSnapshots(w.data).find(item => item.reason === 'manual').id;
      const middle = await wt(t, w);
      await someRows(middle);
      await stopped(middle);
      const restored = adminOf(workingTree, ['restore-snapshot', id, '--data-dir', w.data]);
      assert.equal(restored.status, 0, restored.stdout + restored.stderr);
      const last = await wt(t, w);
      await stopped(last);
      const rows = auditRows(w.data);
      const anchor = rows.find(item => item.action === 'system.restore');
      assert.deepEqual(
        [anchor.detail.cause, anchor.detail.snapshot, anchor.detail.restoredHead],
        ['snapshot', id, { seq: head.seq, hash: head.hash }]
      );
      assert.equal(anchor.seq, head.seq + 1, 'the next row of the restored chain');
      const signOut = rows.find(item => item.action === 'session.revoked-restore');
      assert.equal(signOut.detail.cause, 'snapshot');
      const snapshots = rows
        .filter(item => item.action === 'data.snapshot')
        .map(item => item.target_id);
      assert.ok(snapshots.includes(id), JSON.stringify(snapshots));
      assert.ok(
        listSnapshots(w.data)
          .filter(item => item.reason === 'pre-restore')
          .every(item => snapshots.includes(item.id))
      );
      const alone = verify(w);
      assertIntact(alone, 'S1 without the journal');
      assert.ok(alone.result.anchors.some(item => item.action === 'system.restore'));
      const whole = verify(w, { journal: journalOf(w) });
      assert.equal(whole.result.result, 'incomplete', JSON.stringify(whole.result));
      assert.equal(whole.code, 3);
      assert.ok(whole.result.unverifiable.some(item => item.reason === 'restore_unchecked'));
      assert.equal(whole.result.problem, null, 'never CHANGED');
      assertIntact(verify(w, { journal: last.journal() }), 'S1 with the lines after the restore');
    });

    it('S3: a whole-file restore of control.sqlite is anchored in the bootstrap unit (control_file)', async t => {
      if (skipFor(t)) return;
      const w = world(t);
      const first = await wt(t, w);
      await someRows(first);
      await stopped(first);
      const aside = path.join(w.directory, 'control.sqlite.copy');
      fs.copyFileSync(path.join(w.data, 'control.sqlite'), aside);
      const middle = await wt(t, w);
      await someRows(middle);
      await stopped(middle);
      for (const suffix of ['', '-wal', '-shm'])
        fs.rmSync(path.join(w.data, `control.sqlite${suffix}`), { force: true });
      fs.copyFileSync(aside, path.join(w.data, 'control.sqlite'));
      const last = await wt(t, w);
      await stopped(last);
      const rows = auditRows(w.data);
      const anchor = rows.find(item => item.action === 'system.restore');
      assert.equal(anchor.detail.cause, 'control_file');
      const signOut = rows.find(item => item.action === 'session.revoked-restore');
      assert.deepEqual([signOut.detail.cause, signOut.seq], ['control_file', anchor.seq + 1]);
      assertIntact(verify(w), 'S3 without the journal');
      const whole = verify(w, { journal: journalOf(w) });
      assert.equal(whole.result.result, 'incomplete', JSON.stringify(whole.result));
      assert.equal(whole.code, 3);
      assert.equal(whole.result.problem, null, 'never CHANGED');
    });

    it('K1: killed during its first start on 1.5.0-dev.1 data, WT then starts cleanly: one upgrade row, one start row', async t => {
      if (skipFor(t, '1.5.0-dev.1')) return;
      const w = world(t);
      const old = await start(t, { app: w.app('1.5.0-dev.1'), data: w.data });
      await stopped(old);
      // The killed starts never listen (their port is taken), so none of them may record a
      // system.start, whenever the kill lands.
      const taken = net.createServer();
      await new Promise(resolve => taken.listen(0, '127.0.0.1', resolve));
      t.after(() => new Promise(resolve => taken.close(resolve)));
      const spawnCurrent = () =>
        spawn(process.execPath, [path.join(workingTree, 'server.mjs')], {
          cwd: workingTree,
          env: {
            PATH: process.env.PATH,
            HOST: '127.0.0.1',
            PORT: String(taken.address().port),
            ORBIT_DATA_DIR: w.data,
            ORBIT_PASSWORD: password,
            ORBIT_LEGACY_BASIC: '1',
          },
          stdio: ['ignore', 'pipe', 'ignore'],
        });
      // How long a start takes here, measured on a copy of the same data.
      const copy = path.join(w.directory, 'calibration');
      fs.cpSync(w.data, copy, { recursive: true });
      const began = Date.now();
      const calibration = spawn(process.execPath, [path.join(workingTree, 'server.mjs')], {
        cwd: workingTree,
        env: {
          PATH: process.env.PATH,
          HOST: '127.0.0.1',
          PORT: freePortSync(),
          ORBIT_DATA_DIR: copy,
          ORBIT_PASSWORD: password,
        },
        stdio: ['ignore', 'pipe', 'ignore'],
      });
      await new Promise((resolve, reject) => {
        let output = '';
        calibration.stdout.on('data', chunk => {
          output += chunk;
          if (/(?:Orbit|Uptime Goblin) is ready/.test(output)) resolve();
        });
        calibration.once('exit', code => reject(new Error(`calibration exited ${code}`)));
      });
      const startMs = Date.now() - began;
      calibration.kill('SIGKILL');
      let seed = 20261003;
      const next = () => (seed = (seed * 1103515245 + 12345) % 2 ** 31) / 2 ** 31;
      let journal = '';
      for (let i = 0; i < 10; i++) {
        const child = spawnCurrent();
        child.stdout.on('data', chunk => (journal += chunk));
        const exited = new Promise(resolve => child.once('exit', resolve));
        await delay(Math.floor(next() * startMs));
        child.kill('SIGKILL');
        await exited;
      }
      const current = await wt(t, w);
      await stopped(current);
      assert.equal(applied(w.data).filter(id => id === 'audit-001-log').length, 1);
      const rows = auditRows(w.data);
      assert.equal(rows.filter(item => item.action === 'system.upgrade').length, 1);
      assert.equal(rows.filter(item => item.action === 'system.start').length, 1);
      assertIntact(verify(w, { journal: journal + journalOf(w) }), 'K1');
    });

    it('K3: a lost key reset with orbit-admin: its anchor; the earlier rows unverifiable, their links checked', async t => {
      if (skipFor(t)) return;
      const w = world(t);
      const keyFile = path.join(w.directory, 'orbit-secret.key');
      fs.writeFileSync(keyFile, randomBytes(32).toString('hex'), { mode: 0o600 });
      const first = await wt(t, w, { env: { ORBIT_SECRET_KEY_FILE: keyFile } });
      await someRows(first);
      await stopped(first);
      const before = auditRows(w.data).at(-1).seq;
      fs.rmSync(keyFile);
      const newKey = path.join(w.directory, 'orbit-secret-new.key');
      fs.writeFileSync(newKey, randomBytes(32).toString('hex'), { mode: 0o600 });
      const reset = adminOf(
        workingTree,
        ['key', 'reset', '--confirm-lost-key', '--data-dir', w.data],
        {
          ORBIT_SECRET_KEY_FILE: newKey,
        }
      );
      assert.equal(reset.status, 0, reset.stdout + reset.stderr);
      const after = await wt(t, w, { env: { ORBIT_SECRET_KEY_FILE: newKey } });
      await someRows(after);
      await stopped(after);
      const rows = auditRows(w.data);
      const anchor = rows.find(item => item.action === 'key.reset');
      assert.equal(anchor.seq, before + 1);
      assert.equal(anchor.actor_type, 'cli');
      const checked = verify(w, { journal: journalOf(w), env: { ORBIT_SECRET_KEY_FILE: newKey } });
      assert.equal(checked.result.result, 'incomplete', JSON.stringify(checked.result));
      assert.equal(checked.code, 3);
      assert.equal(checked.result.problem, null);
      const unverifiable = checked.result.unverifiable.find(item => item.reason === 'key_reset');
      assert.ok(unverifiable && unverifiable.to <= before && unverifiable.anchorSeq === anchor.seq);
      assert.ok(checked.result.anchors.some(item => item.action === 'key.reset'));
    });

    it('K4: the keyring audit key deleted by hand: Orbit starts with a new one, and the check says CHANGED (key_lost)', async t => {
      if (skipFor(t)) return;
      const w = world(t);
      const first = await wt(t, w);
      await someRows(first);
      await stopped(first);
      const db = new DatabaseSync(path.join(w.data, 'control.sqlite'));
      try {
        db.exec("DELETE FROM keyring WHERE purpose = 'audit'");
      } finally {
        db.close();
      }
      const again = await wt(t, w);
      await stopped(again);
      const checked = verify(w);
      assert.equal(checked.result.result, 'broken', JSON.stringify(checked.result));
      assert.equal(checked.result.problem.code, 'key_lost');
      assert.equal(checked.code, 1);
    });
  }
);
