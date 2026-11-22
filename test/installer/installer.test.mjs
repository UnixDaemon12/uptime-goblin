// deploy/install.sh against a fake systemctl (test/installer/fake-bin): manifest-driven
// installs, verification of the new process (C5), automatic code rollback, the unresolved Node
// path and the checks that run before anything on the host changes.
import test from 'node:test';
import { pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { setTimeout as delay } from 'node:timers/promises';
import { DatabaseSync } from 'node:sqlite';
import { createFeatures } from '../../lib/features.mjs';
import { computeBuild } from '../../lib/healthcheck.mjs';
import { passwordRequiredMessage, startControl } from '../../lib/db/control.mjs';
import {
  authRecordBytes,
  checkBootstrapPassword,
  readAuthRecord,
} from '../../lib/identity/password.mjs';
import { acquireLock } from '../../lib/db/lock.mjs';
import { keyFingerprint } from '../../lib/keyring.mjs';
import { LIMITS_REFUSAL } from '../../lib/resource-limits.mjs';
import { connectionsPerClient, trustedProxies } from '../../lib/throttle.mjs';
import { legacyBasicSetting, listenPort } from '../../lib/environment.mjs';
import { readManifest } from '../../scripts/check.mjs';
import {
  freePort,
  makeFreshHost,
  makeHost,
  makeSource,
  repository,
  required,
  temporary,
  testPassword,
} from './helpers.mjs';
import { supervisedEnv } from '../helpers/supervised.mjs';

const manifest = readManifest(repository);

function tree(directory, skip = new Set(['node_modules'])) {
  const files = [];
  const walk = relative => {
    for (const entry of fs.readdirSync(path.join(directory, relative), { withFileTypes: true })) {
      const item = relative ? `${relative}/${entry.name}` : entry.name;
      if (skip.has(item)) continue;
      if (entry.isDirectory()) walk(item);
      else files.push(item);
    }
  };
  walk('');
  return files.sort();
}

function writeSums(source) {
  const lines = [...manifest, 'deploy/install.sh', 'deploy/uptime-goblin.service'].map(
    file =>
      `${createHash('sha256')
        .update(fs.readFileSync(path.join(source, file)))
        .digest('hex')}  ${file}`
  );
  fs.writeFileSync(path.join(source, 'SHA256SUMS'), lines.join('\n') + '\n');
}

const ok = result => `installer exited ${result.status}:\n${result.output}`;

// The real server.mjs runs supervised under the unit (--supervised, GOBLIN_SUPERVISED=1), and
// refuses to start where the cgroup it runs in does not hold its limits, as on a Mac
// (lib/resource-limits.mjs): /etc/uptime-goblin.env names exactly those this machine lacks
// (test/helpers/supervised.mjs).
const allowWhatThisMachineLacks = host =>
  fs.appendFileSync(
    host.path('etc/uptime-goblin.env'),
    `GOBLIN_ALLOW_UNLIMITED=${supervisedEnv().GOBLIN_ALLOW_UNLIMITED}\n`
  );

test('install, upgrade, then roll back upgrades that do not serve', async t => {
  const host = await makeHost(t);
  // A 1.4.2 unit whose resolved Node binary has since been removed by a Node upgrade.
  fs.mkdirSync(host.path('etc/systemd/system'), { recursive: true });
  fs.writeFileSync(
    host.path('etc/systemd/system/uptime-goblin.service'),
    '[Service]\nExecStart=/nonexistent/node-v22.9.0/bin/node /opt/uptime-goblin/server.mjs\nRestart=on-failure\n'
  );

  await t.test('a fresh install proves the new process serves', async () => {
    const source = makeSource(t, { version: '1.4.3-test.1', mode: 'ok' });
    writeSums(source);
    const result = await host.install(source);
    assert.equal(result.status, 0, ok(result));
    assert.match(
      result.stderr,
      /starts Node from \/nonexistent\/node-v22\.9\.0\/bin\/node, which no longer exists/
    );
    assert.match(
      result.stdout,
      /Orbit 1\.4\.3-test\.1 \(build [0-9a-f]{12}\) is serving as process \d+/
    );
    assert.match(result.stdout, /tabs opened before 1\.4\.3 need one manual reload/);
    const unit = fs.readFileSync(host.path('etc/systemd/system/uptime-goblin.service'), 'utf8');
    // The unresolved path: a symlink here, like /usr/bin/node managed by the package manager.
    // --supervised: /etc/uptime-goblin.env, which overrides the unit's Environment=, cannot turn it off.
    assert.match(
      unit,
      new RegExp(`^ExecStart=${host.node} /opt/uptime-goblin/server\\.mjs --supervised$`, 'm')
    );
    assert.ok(!unit.includes(fs.realpathSync(process.execPath)));
    for (const line of [
      'Restart=always',
      'RestartSec=5',
      'RestartPreventExitStatus=78',
      'Environment=GOBLIN_SUPERVISED=1',
    ])
      assert.match(unit, new RegExp(`^${line}$`, 'm'));
    // Exactly the manifest, readable by the service account, plus the locked dependencies.
    assert.deepEqual(tree(host.path('opt/uptime-goblin')), manifest);
    assert.ok(fs.existsSync(host.path('opt/uptime-goblin/node_modules/nodemailer/package.json')));
    for (const file of manifest)
      assert.equal(fs.statSync(host.path(`opt/uptime-goblin/${file}`)).mode & 0o777, 0o644, file);
    assert.equal(fs.statSync(host.path('opt/uptime-goblin/public/shared')).mode & 0o777, 0o755);
    assert.equal(fs.statSync(host.path('var/lib/uptime-goblin')).mode & 0o777, 0o700);
    assert.ok(!fs.existsSync(host.path('opt/uptime-goblin.previous')));
    assert.ok(!fs.existsSync(host.path('opt/uptime-goblin.new')));
    const status = host.status();
    assert.equal(status.version, '1.4.3-test.1');
    assert.equal(status.build, computeBuild(host.path('opt/uptime-goblin')));
    assert.equal(status.pid, host.state().pid);
    const journal = fs.readFileSync(path.join(host.env.FAKE_SYSTEMD_DIR, 'journal.log'), 'utf8');
    assert.match(journal, /supervised=1/);
  });

  await t.test('an upgrade keeps the previous code for a rollback', async () => {
    const before = host.status();
    const source = makeSource(t, { version: '1.4.3-test.2', mode: 'ok', change: 'two' });
    const result = await host.install(source);
    assert.equal(result.status, 0, ok(result));
    assert.match(result.stdout, /The previous version is kept in \/opt\/uptime-goblin\.previous/);
    assert.doesNotMatch(result.output, /no longer exists/);
    assert.equal(host.installedVersion(), '1.4.3-test.2');
    assert.equal(host.installedVersion('opt/uptime-goblin.previous'), '1.4.3-test.1');
    const status = host.status();
    assert.equal(status.version, '1.4.3-test.2');
    assert.notEqual(status.pid, before.pid);
    assert.notEqual(status.build, before.build);
  });

  const failures = [
    {
      mode: 'crash',
      timeout: 3,
      reason: /has no running process|has not written run\/status\.json yet/,
      log: /fake orbit: simulated crash/,
    },
    {
      mode: 'refuse',
      timeout: 60,
      reason: /uptime-goblin\.service failed \(exit-code\) and systemd will not restart it/,
      log: /fake orbit: refusing to start/,
      fast: true,
    },
    {
      mode: 'stale-version',
      timeout: 60,
      reason: /the service runs Orbit 0\.0\.1, expected 1\.4\.3-test\.9/,
      fast: true,
    },
    { mode: 'mismatch', timeout: 2, reason: /a different Uptime Goblin process is answering/ },
    { mode: 'foreign-status', timeout: 2, reason: /belongs to process 1, not the service's/ },
    { mode: 'hang', timeout: 2, reason: /has not written run\/status\.json yet/ },
  ];
  for (const failure of failures)
    await t.test(`a failed upgrade (${failure.mode}) restores the previous code`, async () => {
      const source = makeSource(t, { version: '1.4.3-test.9', mode: failure.mode });
      const result = await host.install(source, ['--verify-timeout', String(failure.timeout)]);
      assert.equal(result.status, 1, ok(result));
      assert.match(result.stderr, failure.reason);
      assert.match(result.stderr, /Uptime Goblin 1\.4\.3-test\.9 did not start correctly/);
      assert.match(
        result.stderr,
        /Restoring the previous version from \/opt\/uptime-goblin\.previous/
      );
      assert.match(result.stderr, /The previous version is running again/);
      if (failure.log) assert.match(result.stderr, failure.log, 'the service log is shown');
      // No failed start gets a resource-limit recommendation from the installer (F-02-R2).
      assert.doesNotMatch(result.stderr, /refused to start because a memory, CPU or process limit/);
      if (failure.fast) assert.ok(result.ms < 30000, `took ${result.ms} ms`);
      // No nonce is ever printed.
      assert.doesNotMatch(result.output, /[0-9a-f]{32}/);
      assert.equal(host.installedVersion(), '1.4.3-test.2');
      assert.equal(host.installedVersion('opt/uptime-goblin.failed'), '1.4.3-test.9');
      assert.ok(!fs.existsSync(host.path('opt/uptime-goblin.previous')));
      assert.equal(host.status().version, '1.4.3-test.2');
      assert.equal(host.status().pid, host.state().pid);
      assert.equal(host.systemctl('is-active', 'uptime-goblin.service').status, 0);
    });

  await t.test('the next upgrade starts from the restored version', async () => {
    const source = makeSource(t, { version: '1.4.3-test.3', mode: 'ok' });
    const result = await host.install(source);
    assert.equal(result.status, 0, ok(result));
    assert.equal(host.installedVersion('opt/uptime-goblin.previous'), '1.4.3-test.2');
    assert.equal(host.status().version, '1.4.3-test.3');
  });
});

test('a failed first install says there is nothing to roll back', async t => {
  const host = await makeHost(t);
  const source = makeSource(t, { version: '1.4.3-test.1', mode: 'crash' });
  const result = await host.install(source, ['--verify-timeout', '2']);
  assert.equal(result.status, 1, ok(result));
  assert.match(result.stderr, /fake orbit: simulated crash/);
  assert.match(result.stderr, /There is no previous version to restore/);
  assert.doesNotMatch(result.stderr, /refused to start because a memory, CPU or process limit/);
  assert.ok(!fs.existsSync(host.path('opt/uptime-goblin.previous')));
});

// A supervised Uptime Goblin refuses to start (78) while a memory, CPU or process limit is not in force,
// and says why in its own lines (lib/resource-limits.mjs): a first line that begins with
// LIMITS_REFUSAL, a line for each limit it names and a last line with the two ways out, which
// names GOBLIN_ALLOW_UNLIMITED. After such a start the installer shows the service status and the
// last 50 lines of its log as the journal returns them, those lines among them, unchanged, then
// rolls back, or says there is nothing to restore, as after any failed start. It draws no
// conclusion from the log and recommends nothing of its own: a line there may be an earlier
// start's, and the installer does not establish which start wrote it (Codex review F-02-R2; the
// paragraph of its own that named GOBLIN_ALLOW_UNLIMITED is gone). The stand-in (fake-server.mjs,
// refuse-limits) prints the arguments it was started with and a refusal for a CPU limit alone,
// then exits 78 before it listens. The fake journalctl is a model of the journal, not journald
// (test/installer/systemd.test.mjs runs the real one), and notes each read it is asked for.
// The stand-in's refusal, line by line as the service logs it: the three lines of fake-server.mjs,
// a model of superviseLimits's refusal for a CPU limit alone, whose CPU line names the stand-in.
const serviceRefusal = [
  `${LIMITS_REFUSAL} under a service manager (started with --supervised or GOBLIN_SUPERVISED=1) it starts only where its own cgroup holds its memory, CPU time and processes to a limit, and here its CPU limit is not in force.`,
  `CPU limit: none (fake orbit, refuse-limits: no cgroup was read). Under Docker, give cpus in compose.yaml or compose.override.yaml (docker run --cpus), or, where the kernel cannot limit CPU time, a CPU set (cpuset: '0') that Docker applies; under systemd, CPUQuota= in uptime-goblin.service or a drop-in (an empty CPUQuota= lifts it); in an LXC, its host must delegate the cpu controller to the container.`,
  `To start Uptime Goblin, apply each limit named above (docs/installation.md, "Resource limits", has the steps for Docker, systemd and LXC hosts), or, on a platform that cannot apply it, set GOBLIN_ALLOW_UNLIMITED=cpu in Uptime Goblin's environment (/etc/uptime-goblin.env for the systemd unit, .env for Docker Compose): Uptime Goblin then starts without that limit and says so at every start.`,
];
// One refusal as a start logs it: its three lines, in their order.
const refusalBlock = serviceRefusal.join('\n');
const times = (text, part) => text.split(part).length - 1;
// The recommendation the installer no longer prints, by any of its sentences. The service's own
// last line is none of them: it names GOBLIN_ALLOW_UNLIMITED=cpu and says "without that limit".
const recommendation =
  /refused to start because a memory, CPU or process limit|add GOBLIN_ALLOW_UNLIMITED with the limits the log names|Uptime Goblin then starts without those limits and says so at every start/;
// What a failed start's output holds of refusals: `count` of them, as many as the journal read
// returned, each whole and as logged (the three lines together, and each line as many times),
// and nothing the installer adds of its own: none of the sentences above, and
// GOBLIN_ALLOW_UNLIMITED only where those refusals name it. Other installer wording is not
// screened here.
const refusalsAsLogged = (result, count) => {
  assert.equal(times(result.output, refusalBlock), count, ok(result));
  for (const line of serviceRefusal) assert.equal(times(result.output, line), count, ok(result));
  assert.doesNotMatch(result.output, recommendation);
  assert.equal(
    times(result.output, 'GOBLIN_ALLOW_UNLIMITED'),
    count * times(refusalBlock, 'GOBLIN_ALLOW_UNLIMITED'),
    ok(result)
  );
};
// The one journal read the installer makes after a failed start: the last 50 lines, with no
// cursor, position or time window.
const ordinaryRead = '--unit=uptime-goblin.service --lines=50 --no-pager';
const readsDuring = async (host, run) => {
  const before = host.journalctlCalls().length;
  const result = await run();
  return { result, reads: host.journalctlCalls().slice(before) };
};

test('a start refused for want of a resource limit: the status, the log as the journal gives it and the rollback, and no recommendation from the installer', async t => {
  const fresh = await makeHost(t);
  const upgraded = await makeHost(t);

  await t.test(
    'a first install: the refusal in the log shown, and nothing to restore',
    async () => {
      const { result, reads } = await readsDuring(fresh, () =>
        fresh.install(makeSource(t, { version: '1.4.3-test.1', mode: 'refuse-limits' }), [
          '--verify-timeout',
          '60',
        ])
      );
      assert.equal(result.status, 1, ok(result));
      assert.ok(result.ms < 30000, `took ${result.ms} ms`);
      assert.match(
        result.stderr,
        /uptime-goblin\.service failed \(exit-code\) and systemd will not restart it/
      );
      // What the installed server.mjs was started with: the unit's ExecStart, --supervised. It
      // refused before it listened, so it wrote no run/status.json.
      assert.match(fresh.journal(), /^fake orbit arguments: \["--supervised"\]$/m);
      assert.equal(fresh.status(), null);
      // The status, then the service's own refusal as it logged it, once (the journal of a first
      // install holds this start's lines alone), after its arguments, then nothing to restore.
      assert.match(result.stderr, /uptime-goblin\.service - fake\s+Active: failed/);
      refusalsAsLogged(result, 1);
      const heading = result.stderr.indexOf('Service status and recent log:');
      const shown = result.stderr.indexOf(refusalBlock);
      assert.ok(heading !== -1 && heading < shown, ok(result));
      const started = result.stderr.indexOf('fake orbit arguments: ["--supervised"]');
      assert.ok(started !== -1 && started < shown, 'in the order logged');
      assert.ok(
        result.stderr.indexOf('There is no previous version to restore.') > shown,
        'the log comes first'
      );
      assert.deepEqual(reads, [ordinaryRead]);
      assert.doesNotMatch(result.stderr, /Restoring the previous version/);
      assert.ok(!fs.existsSync(fresh.path('opt/uptime-goblin.previous')));
    }
  );

  await t.test(
    'an upgrade: the refusal in the log shown, then the previous version restored',
    async () => {
      const legacy = await upgraded.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }));
      assert.equal(legacy.status, 0, ok(legacy));
      const { result, reads } = await readsDuring(upgraded, () =>
        upgraded.install(
          makeSource(t, { version: '1.4.3-test.2', mode: 'refuse-limits', change: 'two' }),
          ['--verify-timeout', '60']
        )
      );
      assert.equal(result.status, 1, ok(result));
      assert.ok(result.ms < 30000, `took ${result.ms} ms`);
      assert.match(upgraded.journal(), /^fake orbit arguments: \["--supervised"\]$/m);
      assert.match(result.stderr, /uptime-goblin\.service - fake\s+Active: failed/);
      // This start's refusal, once: the journal holds the served version's lines and this start's.
      refusalsAsLogged(result, 1);
      assert.ok(
        result.stderr.indexOf('Restoring the previous version from /opt/uptime-goblin.previous') >
          result.stderr.indexOf(refusalBlock),
        'the log comes before the rollback'
      );
      assert.deepEqual(reads, [ordinaryRead]);
      assert.match(result.stderr, /The previous version is running again/);
      assert.equal(upgraded.installedVersion(), '1.4.3-test.1');
      assert.equal(upgraded.installedVersion('opt/uptime-goblin.failed'), '1.4.3-test.2');
      assert.ok(!fs.existsSync(upgraded.path('opt/uptime-goblin.previous')));
      assert.equal(upgraded.status().version, '1.4.3-test.1');
      assert.equal(upgraded.status().pid, upgraded.state().pid);
      assert.equal(upgraded.systemctl('is-active', 'uptime-goblin.service').status, 0);
    }
  );

  await t.test(
    'a refusal of an earlier start, in the same second: in the log shown, and still no recommendation',
    async () => {
      // An earlier start's refusal and this start's generic failure in one second (Codex reviews
      // F-02-R1 and F-02-R2). The fake systemctl notes every entry at one fixed, synthetic time
      // (FAKE_JOURNAL_MS), so a whole-second window holds both, and a rule that took the refusals
      // of this second for this start's would take the earlier one. The installer reads no window:
      // the earlier refusal is among the last 50 lines it shows, and it says nothing of it. Nothing
      // waits for a second to pass.
      const second = 1767225600;
      const env = { FAKE_JOURNAL_MS: String(second * 1000 + 500) };
      const same = await makeHost(t);
      const legacy = await same.install(
        makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }),
        [],
        env
      );
      assert.equal(legacy.status, 0, ok(legacy));
      const refused = await same.install(
        makeSource(t, { version: '1.4.3-test.2', mode: 'refuse-limits', change: 'two' }),
        ['--verify-timeout', '60'],
        env
      );
      assert.equal(refused.status, 1, ok(refused));
      refusalsAsLogged(refused, 1);
      const { result, reads } = await readsDuring(same, () =>
        same.install(
          makeSource(t, { version: '1.4.3-test.3', mode: 'refuse', change: 'three' }),
          ['--verify-timeout', '60'],
          env
        )
      );
      assert.equal(result.status, 1, ok(result));
      assert.match(result.stderr, /fake orbit: refusing to start/);
      // The journal's one refusal is the earlier start's, and the 50 lines reach back past it: it
      // is shown once, as logged, before this start's own failure.
      refusalsAsLogged(result, 1);
      assert.ok(
        result.stderr.indexOf(refusalBlock) <
          result.stderr.indexOf('fake orbit: refusing to start'),
        'the earlier refusal is in the log shown'
      );
      assert.deepEqual(reads, [ordinaryRead]);
      assert.match(
        result.stderr,
        /Restoring the previous version from \/opt\/uptime-goblin\.previous/
      );
      assert.match(result.stderr, /The previous version is running again/);
      assert.equal(same.installedVersion(), '1.4.3-test.1');
      assert.equal(same.installedVersion('opt/uptime-goblin.failed'), '1.4.3-test.3');
      assert.equal(same.systemctl('is-active', 'uptime-goblin.service').status, 0);
      // The fixture is that case: every note at the one time, and the whole-second window holds the
      // earlier refusal beside this start's failure.
      const notes = fs
        .readFileSync(path.join(same.env.FAKE_SYSTEMD_DIR, 'journal.times'), 'utf8')
        .trim()
        .split('\n');
      assert.ok(
        notes.length > 1 && notes.every(note => note.startsWith(`${env.FAKE_JOURNAL_MS} `)),
        notes.join('\n')
      );
      const wholeSecond = same.journalctl(
        '--unit=uptime-goblin.service',
        `--since=@${second}`,
        '--no-pager',
        '--output=cat'
      );
      assert.equal(wholeSecond.status, 0, wholeSecond.stderr);
      assert.equal(times(wholeSecond.stdout, refusalBlock), 1, wholeSecond.stdout);
      assert.match(wholeSecond.stdout, /fake orbit: refusing to start/);
    }
  );
});

// What a journal read can hand the installer besides this start's own lines (Codex review
// F-02-R2): an earlier start's refusal that the journal stored after this start's lines; an
// older window returned without an error, as a reader may go on from an older entry where the one
// it looked for is gone; a read that fails after its lines; an empty read. Whatever the log seems
// to say about which start refused, the installer shows what the read returned, unchanged, with
// the status, rolls back or says there is nothing to restore, and recommends nothing; it makes no
// other read (no cursor, position or time window). The fake journalctl returns these as
// FAKE_JOURNALCTL_FAULT and FAKE_JOURNALCTL_LATE say (fake-bin/journalctl): a model of what a
// journal can return, not evidence of journald's behaviour. Each case expects as many refusals as
// the lines its read returns hold, each as logged: an earlier start's where the read returns it,
// two where it returns two, and none from an empty read.
test("a failed start whose log holds an earlier start's refusal, stored late or returned stale, or whose log read fails or is empty: the status, the log as returned and the rollback, and no recommendation", async t => {
  const given = (host, env, ...args) =>
    spawnSync(path.join(host.base, 'bin', 'journalctl'), args, {
      env: { ...host.env, ...env },
      encoding: 'utf8',
    });
  // What every case checks: the status and what the read returned are shown, `refusals` refusals
  // among it as logged and nothing of the installer's about them, no other read, and the
  // previous version restored and running.
  const failedUpgrade = async (host, { version, mode, env, log, refusals }) => {
    const { result, reads } = await readsDuring(host, () =>
      host.install(
        makeSource(t, { version, mode, change: version }),
        ['--verify-timeout', '60'],
        env
      )
    );
    assert.equal(result.status, 1, ok(result));
    assert.ok(result.ms < 30000, `took ${result.ms} ms`);
    assert.ok(
      result.stderr.includes(`Uptime Goblin ${version} did not start correctly.`),
      ok(result)
    );
    assert.match(result.stderr, /uptime-goblin\.service - fake\s+Active: failed/);
    assert.match(result.stderr, log, 'what the read returned is shown');
    refusalsAsLogged(result, refusals);
    assert.deepEqual(reads, [ordinaryRead], 'no other read');
    assert.match(
      result.stderr,
      /Restoring the previous version from \/opt\/uptime-goblin\.previous/
    );
    assert.match(result.stderr, /The previous version is running again/);
    assert.equal(host.installedVersion(), '1.4.3-test.1');
    assert.equal(host.installedVersion('opt/uptime-goblin.failed'), version);
    assert.equal(host.status().version, '1.4.3-test.1');
    assert.equal(host.status().pid, host.state().pid);
    assert.equal(host.systemctl('is-active', 'uptime-goblin.service').status, 0);
    return result;
  };

  await t.test(
    'a first install whose log read fails: the status and the lines it gave, and nothing to restore',
    async () => {
      const fresh = await makeHost(t);
      const { result, reads } = await readsDuring(fresh, () =>
        fresh.install(
          makeSource(t, { version: '1.4.3-test.1', mode: 'refuse-limits' }),
          ['--verify-timeout', '60'],
          { FAKE_JOURNALCTL_FAULT: 'fail' }
        )
      );
      assert.equal(result.status, 1, ok(result));
      assert.ok(result.ms < 30000, `took ${result.ms} ms`);
      assert.match(fresh.journal(), /^fake orbit arguments: \["--supervised"\]$/m);
      assert.match(result.stderr, /uptime-goblin\.service - fake\s+Active: failed/);
      // The lines the read gave before its error: this start's alone, its refusal among them, once.
      refusalsAsLogged(result, 1);
      assert.match(
        result.stderr,
        /fake journalctl: Failed to iterate through journal: Bad message/
      );
      assert.ok(
        result.stderr.indexOf('fake journalctl: Failed to iterate') >
          result.stderr.indexOf(refusalBlock),
        'the lines the read gave, then its error'
      );
      assert.deepEqual(reads, [ordinaryRead]);
      assert.match(result.stderr, /There is no previous version to restore\./);
      assert.doesNotMatch(result.stderr, /Restoring the previous version/);
      assert.ok(!fs.existsSync(fresh.path('opt/uptime-goblin.previous')));
    }
  );

  await t.test(
    "an earlier start's refusal stored after this start's lines: shown last, no recommendation",
    async () => {
      // No start refused on this host: the model adds the earlier start's refusal, its three lines
      // as the stand-in logs them, to a read that succeeds, after this start's lines, as a journal
      // that stored it late would return it (fake-bin/journalctl prints FAKE_JOURNALCTL_LATE as it
      // is given, its line breaks included). This start failed for another reason.
      const host = await makeHost(t);
      const legacy = await host.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }));
      assert.equal(legacy.status, 0, ok(legacy));
      const env = { FAKE_JOURNALCTL_LATE: refusalBlock };
      const result = await failedUpgrade(host, {
        version: '1.4.3-test.2',
        mode: 'refuse',
        env,
        log: /fake orbit: refusing to start/,
        refusals: 1,
      });
      assert.ok(
        result.stderr.indexOf(refusalBlock) >
          result.stderr.lastIndexOf('fake orbit: refusing to start'),
        'after this start'
      );
      assert.ok(!host.journal().includes(LIMITS_REFUSAL), 'only the read holds it');
      const read = given(host, env, '--unit=uptime-goblin.service', '--lines=50', '--no-pager');
      assert.equal(read.status, 0, read.stderr);
      assert.ok(read.stdout.trimEnd().endsWith(refusalBlock), read.stdout);
    }
  );

  // On one host: a version that serves, then an earlier start refused for want of a resource
  // limit and rolled back, whose refusal is in the journal as it logged it, once; then each case.
  const host = await makeHost(t);
  const legacy = await host.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }));
  assert.equal(legacy.status, 0, ok(legacy));
  const earlier = await host.install(
    makeSource(t, { version: '1.4.3-test.2', mode: 'refuse-limits', change: 'earlier' }),
    ['--verify-timeout', '60']
  );
  assert.equal(earlier.status, 1, ok(earlier));
  assert.equal(times(host.journal(), refusalBlock), 1, host.journal());
  const first = host.journal().split('\n')[0];

  await t.test(
    'an older window returned without an error: the earlier refusal shown, no recommendation',
    async () => {
      // The whole journal from its first line: one refusal, the earlier start's, the only one so
      // far (this start fails for another reason), before this start's failure.
      const env = { FAKE_JOURNALCTL_FAULT: 'stale' };
      const result = await failedUpgrade(host, {
        version: '1.4.3-test.3',
        mode: 'refuse',
        env,
        log: /fake orbit: refusing to start/,
        refusals: 1,
      });
      assert.ok(result.stderr.includes(first), first);
      assert.ok(
        result.stderr.indexOf(refusalBlock) <
          result.stderr.indexOf('fake orbit: refusing to start'),
        'the earlier refusal is in the window shown'
      );
      const read = given(host, env, '--unit=uptime-goblin.service', '--lines=50', '--no-pager');
      assert.equal(read.status, 0, read.stderr);
      assert.ok(read.stdout.startsWith(`${first}\n`), read.stdout);
      assert.equal(times(read.stdout, refusalBlock), 1, read.stdout);
    }
  );

  await t.test(
    'a read that fails after its lines: those lines and the error shown, no recommendation',
    async () => {
      // The last 50 lines reach back past the earlier start's refusal on this host, so the read
      // gives two refusals, each as logged: the earlier start's, then this start's after its own
      // first line; then the error.
      const result = await failedUpgrade(host, {
        version: '1.4.3-test.4',
        mode: 'refuse-limits',
        env: { FAKE_JOURNALCTL_FAULT: 'fail' },
        log: /fake journalctl: Failed to iterate through journal: Bad message/,
        refusals: 2,
      });
      const start = result.stderr.indexOf('fake orbit 1.4.3-test.4 starting (refuse-limits)');
      assert.ok(
        start !== -1 && result.stderr.indexOf(refusalBlock) < start,
        'the earlier refusal first'
      );
      assert.ok(result.stderr.lastIndexOf(refusalBlock) > start, "then this start's");
      assert.ok(
        result.stderr.indexOf('fake journalctl: Failed to iterate') >
          result.stderr.lastIndexOf(refusalBlock),
        'then the error'
      );
    }
  );

  await t.test(
    'an empty read: no log lines, the status and the rollback, no recommendation',
    async () => {
      await failedUpgrade(host, {
        version: '1.4.3-test.5',
        mode: 'refuse-limits',
        env: { FAKE_JOURNALCTL_FAULT: 'missing' },
        log: /^-- No entries --$/m,
        refusals: 0,
      });
      // The read returned none of the lines this start logged: no line of a refusal is shown
      // (refusals: 0), although the journal holds this start's.
      assert.ok(host.journal().includes(refusalBlock), 'the service logged its refusal');
    }
  );
});

// A supervised Uptime Goblin (the unit's --supervised) refuses to start where /etc/uptime-goblin.env holds an
// GOBLIN_ALLOW_UNLIMITED or GOBLIN_SUPERVISED this release refuses (lib/resource-limits.mjs), so
// the installer says so before anything changes, as for HOST and PORT. A GOBLIN_SUPERVISED=0
// there is taken: Uptime Goblin ignores it, with a line. (What the installer shows after a start refused
// for want of a resource limit is in the two tests above.)
test('a GOBLIN_ALLOW_UNLIMITED in /etc/uptime-goblin.env that this release refuses refuses the upgrade before anything changes', async t => {
  const host = await makeHost(t);
  const legacy = await host.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }));
  assert.equal(legacy.status, 0, ok(legacy));
  const next = makeSource(t, { version: '1.5.0-test.1', mode: 'ok' });
  const envFile = host.path('etc/uptime-goblin.env');
  const original = fs.readFileSync(envFile, 'utf8');
  for (const [value, shown, problem] of [
    ['all', '"all"', 'in which "all" is not one of them'],
    ['cpu,cpu', '"cpu,cpu"', 'which names cpu twice'],
    [
      '"cpu, pids"',
      '"cpu, pids"',
      'which holds a character that is neither a lowercase letter nor a comma',
    ],
  ]) {
    fs.writeFileSync(envFile, `${original}GOBLIN_ALLOW_UNLIMITED=${value}\n`);
    const before = hostState(host);
    const result = await host.install(next, ['--verify-timeout', '5']);
    assert.equal(result.status, 1, ok(result));
    assert.equal(
      result.stderr.trim(),
      `This release of Uptime Goblin would refuse to start with /etc/uptime-goblin.env (exit status 78): GOBLIN_ALLOW_UNLIMITED must list the limits Uptime Goblin may run without, from memory, cpu and pids, separated by commas, each at most once and without spaces (such as cpu, or memory,cpu); it is ${shown}, ${problem}. Correct it in /etc/uptime-goblin.env (sudoedit /etc/uptime-goblin.env), then run this installer again. Nothing was changed.`,
      value
    );
    assert.deepEqual(hostState(host), before, 'nothing on the host changed');
  }
  // A list it takes goes through.
  fs.writeFileSync(envFile, `${original}GOBLIN_ALLOW_UNLIMITED=cpu\n`);
  const passed = await host.install(next);
  assert.equal(passed.status, 0, ok(passed));
  assert.equal(host.status().version, '1.5.0-test.1');
});

test('a GOBLIN_SUPERVISED in /etc/uptime-goblin.env that is neither yes nor no refuses the upgrade before anything changes', async t => {
  const host = await makeHost(t);
  const legacy = await host.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }));
  assert.equal(legacy.status, 0, ok(legacy));
  const next = makeSource(t, { version: '1.5.0-test.1', mode: 'ok' });
  const envFile = host.path('etc/uptime-goblin.env');
  const original = fs.readFileSync(envFile, 'utf8');
  for (const [value, shown] of [
    ['bogus', '"bogus"'],
    ['enabled', '"enabled"'],
    ['"1 "', '"1 "'],
  ]) {
    fs.writeFileSync(envFile, `${original}GOBLIN_SUPERVISED=${value}\n`);
    const before = hostState(host);
    const result = await host.install(next, ['--verify-timeout', '5']);
    assert.equal(result.status, 1, ok(result));
    assert.equal(
      result.stderr.trim(),
      `This release of Uptime Goblin would refuse to start with /etc/uptime-goblin.env (exit status 78): GOBLIN_SUPERVISED must be 1 or 0 (true, yes or on; false, no or off), or empty; it is ${shown}. Correct it in /etc/uptime-goblin.env (sudoedit /etc/uptime-goblin.env), then run this installer again. Nothing was changed.`,
      value
    );
    assert.deepEqual(hostState(host), before, 'nothing on the host changed');
  }
  fs.writeFileSync(envFile, `${original}GOBLIN_SUPERVISED=0\n`);
  const passed = await host.install(next);
  assert.equal(passed.status, 0, ok(passed));
  assert.equal(host.status().version, '1.5.0-test.1');
  assert.match(
    fs.readFileSync(host.path('etc/systemd/system/uptime-goblin.service'), 'utf8'),
    /^ExecStart=\S+ \/opt\/uptime-goblin\/server\.mjs --supervised$/m
  );
});

// Legacy Basic is on by default for installs upgraded from 1.4.x, so this release refuses to
// start on a GOBLIN_LEGACY_BASIC that is neither yes nor no (a typo meant as off), and the
// installer says so before an upgrade stops the running Uptime Goblin.
test('a GOBLIN_LEGACY_BASIC in /etc/uptime-goblin.env that is neither yes nor no refuses the upgrade before anything changes', async t => {
  const host = await makeHost(t);
  const legacy = await host.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }));
  assert.equal(legacy.status, 0, ok(legacy));
  const next = makeSource(t, { version: '1.5.0-test.1', mode: 'ok' });
  const envFile = host.path('etc/uptime-goblin.env');
  const original = fs.readFileSync(envFile, 'utf8');
  for (const [value, shown] of [
    ['of', '"of"'],
    ['disabled', '"disabled"'],
    ['"0 "', '"0 "'],
  ]) {
    fs.writeFileSync(envFile, `${original}GOBLIN_LEGACY_BASIC=${value}\n`);
    const before = hostState(host);
    const result = await host.install(next, ['--verify-timeout', '5']);
    assert.equal(result.status, 1, ok(result));
    assert.equal(
      result.stderr.trim(),
      `This release of Uptime Goblin would refuse to start with /etc/uptime-goblin.env (exit status 78): GOBLIN_LEGACY_BASIC must be 1 or 0 (true, yes or on; false, no or off), or empty for the default; it is ${shown}. Correct it in /etc/uptime-goblin.env (sudoedit /etc/uptime-goblin.env), then run this installer again. Nothing was changed.`,
      value
    );
    assert.deepEqual(hostState(host), before, 'nothing on the host changed');
  }
  fs.writeFileSync(envFile, `${original}GOBLIN_LEGACY_BASIC=off\n`);
  const passed = await host.install(next);
  assert.equal(passed.status, 0, ok(passed));
  assert.equal(host.status().version, '1.5.0-test.1');
});

// The message this release refuses to start with for `value` (its own check, `check`).
const refusal = (check, value) => {
  try {
    check(value);
  } catch (error) {
    assert.equal(error.refusal, true, value);
    return error.message;
  }
  assert.fail(`${value} is accepted`);
};

// GOBLIN_MAX_CONNECTIONS_PER_CLIENT (new in 1.5) and GOBLIN_TRUST_PROXY (1.5 refuses ranges, the
// IPv4-embedding and NAT64 prefixes and a value naming no proxy that 1.4.3 took) refuse the start
// (exit status 78) before anything is written. The installer did not check either in
// /etc/uptime-goblin.env, so such an upgrade stopped Uptime Goblin, failed to start it and rolled back (review
// INST-3). It now judges both by the release's own rules (lib/throttle.mjs, shared with Uptime Goblin)
// before anything changes; GOBLIN_TRUST_PROXY not when --trust-proxy replaces it.
test('a GOBLIN_MAX_CONNECTIONS_PER_CLIENT or GOBLIN_TRUST_PROXY in /etc/uptime-goblin.env that this release refuses refuses the upgrade before anything changes; --trust-proxy replaces the file value', async t => {
  const host = await makeHost(t);
  const legacy = await host.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }));
  assert.equal(legacy.status, 0, ok(legacy));
  const next = makeSource(t, { version: '1.5.0-test.1', mode: 'ok' });
  const envFile = host.path('etc/uptime-goblin.env');
  const original = fs.readFileSync(envFile, 'utf8');
  const refused = problems =>
    `This release of Uptime Goblin would refuse to start with /etc/uptime-goblin.env (exit status 78): ${problems.join(' ')} Correct ${problems.length > 1 ? 'them' : 'it'} in /etc/uptime-goblin.env (sudoedit /etc/uptime-goblin.env), then run this installer again. Nothing was changed.`;
  for (const [line, problem] of [
    ['GOBLIN_MAX_CONNECTIONS_PER_CLIENT=300', refusal(connectionsPerClient, '300')],
    ['GOBLIN_MAX_CONNECTIONS_PER_CLIENT=64 # raised', refusal(connectionsPerClient, '64 # raised')],
    ['GOBLIN_TRUST_PROXY=0.0.0.0/0', refusal(trustedProxies, '0.0.0.0/0')],
    ['GOBLIN_TRUST_PROXY=64:ff9b::/96', refusal(trustedProxies, '64:ff9b::/96')],
    ['GOBLIN_TRUST_PROXY=192.0.2.0/24/extra', refusal(trustedProxies, '192.0.2.0/24/extra')],
    // Only commas and blanks: no proxy named, yet not off (review CFG-4).
    ['GOBLIN_TRUST_PROXY=" , "', refusal(trustedProxies, ' , ')],
  ]) {
    fs.writeFileSync(envFile, `${original}${line}\n`);
    const before = hostState(host);
    const result = await host.install(next, ['--verify-timeout', '5']);
    assert.equal(result.status, 1, ok(result));
    assert.equal(result.stderr.trim(), refused([problem]), line);
    assert.deepEqual(hostState(host), before, 'nothing on the host changed');
    assert.equal(host.installedVersion(), '1.4.3-test.1');
  }
  assert.match(refusal(trustedProxies, ','), /^GOBLIN_TRUST_PROXY names no proxy: /);
  // Both at once, with PORT: each reason, in one message.
  fs.writeFileSync(
    envFile,
    `${original}PORT=04317\nGOBLIN_MAX_CONNECTIONS_PER_CLIENT=7\nGOBLIN_TRUST_PROXY=::/0\n`
  );
  const both = await host.install(next, ['--verify-timeout', '5']);
  assert.equal(both.status, 1, ok(both));
  assert.equal(
    both.stderr.trim(),
    refused([
      refusal(listenPort, '04317'),
      refusal(connectionsPerClient, '7'),
      refusal(trustedProxies, '::/0'),
    ])
  );
  // --trust-proxy replaces the file's GOBLIN_TRUST_PROXY (rewritten in place), so that value is not
  // judged; --trust-proxy itself is (a value naming no proxy exits 2, before anything is read).
  fs.writeFileSync(envFile, `${original}GOBLIN_TRUST_PROXY=0.0.0.0/0\n`);
  const noProxy = await host.install(next, ['--trust-proxy', ',']);
  assert.equal(noProxy.status, 2, ok(noProxy));
  assert.match(
    noProxy.stderr,
    /GOBLIN_TRUST_PROXY names no proxy[\s\S]*Invalid --trust-proxy value/
  );
  const replacedBy = await host.install(next, [
    '--trust-proxy',
    'loopback',
    '--proxy-proto-checked',
  ]);
  assert.equal(replacedBy.status, 0, ok(replacedBy));
  assert.equal(host.installedVersion(), '1.5.0-test.1');
  const env = fs.readFileSync(envFile, 'utf8');
  assert.match(env, /^GOBLIN_TRUST_PROXY=loopback$/m);
  assert.doesNotMatch(env, /0\.0\.0\.0\/0/);
  // Values it takes go through.
  fs.writeFileSync(
    envFile,
    `${env}GOBLIN_MAX_CONNECTIONS_PER_CLIENT=64\nGOBLIN_TRUST_PROXY=192.0.2.10,loopback\n`
  );
  const passed = await host.install(next, ['--verify-timeout', '5']);
  assert.equal(passed.status, 0, ok(passed));
});

// Uptime Goblin always requires an admin password and refuses every start without one (exit status 78):
// auth.json in the data directory, or else a non-empty GOBLIN_PASSWORD. Without either, an upgrade
// stopped Uptime Goblin, failed to start it and rolled back, and an install over an existing
// /etc/uptime-goblin.env left Uptime Goblin down with nothing to restore. The installer refuses such an install
// before anything changes, working GOBLIN_PASSWORD out as systemd gives it (as it does HOST and
// PORT), with the instructions of Uptime Goblin's own refusal. It never prints the value.
const passwordFix =
  'Set GOBLIN_PASSWORD (12 to 1024 characters) in /etc/uptime-goblin.env (sudoedit /etc/uptime-goblin.env), and let no drop-in (sudo systemctl edit uptime-goblin) empty or remove it, then run this installer again. If Uptime Goblin had a password before, restore /var/lib/uptime-goblin/auth.json from a backup instead, or set GOBLIN_PASSWORD: it becomes the admin password and signs out every session.';
const passwordStop = where =>
  `This release of Uptime Goblin would refuse to start (exit status 78): Uptime Goblin needs an admin password, and none is set: /var/lib/uptime-goblin has no auth.json, and GOBLIN_PASSWORD ${where}. ${passwordFix} Nothing was changed.`;
const withoutPassword = host => {
  const file = host.path('etc/uptime-goblin.env');
  const text = fs.readFileSync(file, 'utf8');
  const without = text.replace(`GOBLIN_PASSWORD=${testPassword}\n`, '');
  assert.notEqual(without, text);
  fs.writeFileSync(file, without);
  return without;
};
// auth.json as Uptime Goblin writes it (a v1 scrypt record), of a synthetic salt and hash that no password
// gives: the reader checks the record's form, never a password. `size` pads it with trailing
// spaces, which JSON allows, to exactly that many bytes.
const validAuthJson = size => {
  const bytes = authRecordBytes({
    salt: 'a'.repeat(64),
    hash: 'b'.repeat(128),
    passwordChangedAt: 1790000000000,
  });
  return size === undefined
    ? bytes
    : Buffer.concat([bytes, Buffer.alloc(size - bytes.length, ' ')]);
};

test('an install or upgrade that would give Uptime Goblin no admin password is refused before anything changes, unless auth.json or GOBLIN_PASSWORD reaches Uptime Goblin', async t => {
  const source = makeSource(t, { version: '1.5.0-test.1', mode: 'ok' });
  const nowhere = 'is set nowhere that systemd reads for Uptime Goblin';
  // The instructions are Uptime Goblin's own (lib/db/control.mjs passwordRequiredMessage).
  for (const words of [
    'Uptime Goblin needs an admin password, and none is set: ',
    'Set GOBLIN_PASSWORD (12 to 1024 characters) in ',
    'If Uptime Goblin had a password before, restore ',
    'or set GOBLIN_PASSWORD: it becomes the admin password and signs out every session.',
  ]) {
    assert.ok(passwordRequiredMessage.includes(words), words);
    assert.ok(passwordStop(nowhere).includes(words), words);
  }
  // On a host without Uptime Goblin, nothing at all changes: no code, data, key, unit or service call
  // that changes anything (the preflights only ask systemd what it would give Uptime Goblin).
  const untouched = (host, env) => {
    if (env === null) assert.ok(!fs.existsSync(host.path('etc/uptime-goblin.env')));
    else assert.equal(fs.readFileSync(host.path('etc/uptime-goblin.env'), 'utf8'), env);
    for (const file of [
      'opt/uptime-goblin',
      'var/lib/uptime-goblin',
      'etc/uptime-goblin',
      'etc/systemd/system/uptime-goblin.service',
    ])
      assert.ok(!fs.existsSync(host.path(file)), file);
    assert.equal(
      host
        .calls()
        .split('\n')
        .filter(line => line && !/^(show|show-environment)( |$)/.test(line))
        .join('\n'),
      ''
    );
  };
  const refused = async (host, message, env) => {
    const result = await host.install(source, ['--verify-timeout', '5']);
    assert.equal(result.status, 1, ok(result));
    assert.equal(result.stderr.trim(), message);
    assert.equal(result.stdout, '');
    assert.doesNotMatch(result.output, new RegExp(testPassword));
    untouched(host, env);
  };
  const installs = async host => {
    const result = await host.install(source, ['--verify-timeout', '5']);
    assert.equal(result.status, 0, ok(result));
    assert.equal(host.installedVersion(), '1.5.0-test.1');
    return result;
  };
  const dropIn = (host, name, text) => {
    fs.mkdirSync(host.path('etc/systemd/system/uptime-goblin.service.d'), { recursive: true });
    fs.writeFileSync(host.path(`etc/systemd/system/uptime-goblin.service.d/${name}`), text);
  };

  // A first install over an /etc/uptime-goblin.env without GOBLIN_PASSWORD, and a data directory without
  // auth.json: Uptime Goblin would never start, and there is nothing to roll back to.
  const bare = await makeHost(t);
  let env = withoutPassword(bare);
  await refused(bare, passwordStop(nowhere), env);
  // Empty, as .env.example has it (GOBLIN_PASSWORD=''): no password either.
  env += "GOBLIN_PASSWORD=''\n";
  fs.writeFileSync(bare.path('etc/uptime-goblin.env'), env);
  await refused(
    bare,
    passwordStop(
      'is empty for Uptime Goblin (EnvironmentFile=/etc/uptime-goblin.env in /etc/systemd/system/uptime-goblin.service)'
    ),
    env
  );
  // A valid auth.json in the data directory holds the password: the install goes on. (One that
  // Uptime Goblin's start refuses does not: see the next test.)
  fs.mkdirSync(bare.path('var/lib/uptime-goblin'), { recursive: true, mode: 0o700 });
  fs.writeFileSync(bare.path('var/lib/uptime-goblin/auth.json'), validAuthJson(), { mode: 0o600 });
  await installs(bare);

  // GOBLIN_PASSWORD in /etc/uptime-goblin.env (as makeHost writes it): the install goes on.
  await installs(await makeHost(t));

  // GOBLIN_PASSWORD from a drop-in (Environment=, which /etc/uptime-goblin.env does not override when it
  // does not set the name): the install goes on.
  const fromDropIn = await makeHost(t);
  withoutPassword(fromDropIn);
  dropIn(fromDropIn, 'password.conf', `[Service]\nEnvironment=GOBLIN_PASSWORD=${testPassword}\n`);
  await installs(fromDropIn);

  // One that this release (as 1.4.x) refuses at its start: under 12 characters, or only spaces.
  // The installer runs Uptime Goblin's own check (checkBootstrapPassword), names where systemd takes the
  // value from, and never prints it.
  const orbitRefusal =
    'GOBLIN_PASSWORD must be 12 to 1024 characters and not only spaces. Choose a longer password and restart.';
  for (const value of ['short-pw-11', ' '.repeat(12)])
    assert.throws(() => checkBootstrapPassword(value), { message: orbitRefusal });
  const notAccepted = from =>
    `This release of Uptime Goblin would refuse to start (exit status 78) with "${orbitRefusal}": /var/lib/uptime-goblin has no auth.json, and the GOBLIN_PASSWORD that systemd would give Uptime Goblin (${from}) is not one Uptime Goblin accepts. ${passwordFix} Nothing was changed.`;
  const short = await makeHost(t);
  const shortEnv = withoutPassword(short) + 'GOBLIN_PASSWORD=short-pw-11\n';
  fs.writeFileSync(short.path('etc/uptime-goblin.env'), shortEnv);
  const shortResult = await short.install(source, ['--verify-timeout', '5']);
  assert.equal(shortResult.status, 1, ok(shortResult));
  assert.equal(
    shortResult.stderr.trim(),
    notAccepted(
      'EnvironmentFile=/etc/uptime-goblin.env in /etc/systemd/system/uptime-goblin.service'
    )
  );
  assert.doesNotMatch(shortResult.output, /short-pw-11/);
  untouched(short, shortEnv);
  const spaces = await makeHost(t);
  env = withoutPassword(spaces);
  dropIn(spaces, 'password.conf', '[Service]\nEnvironment="GOBLIN_PASSWORD=            "\n');
  await refused(
    spaces,
    notAccepted('Environment= in /etc/systemd/system/uptime-goblin.service.d/password.conf'),
    env
  );
  // With a password Uptime Goblin accepts in its place, the install goes on.
  fs.writeFileSync(
    short.path('etc/uptime-goblin.env'),
    shortEnv.replace('GOBLIN_PASSWORD=short-pw-11\n', `GOBLIN_PASSWORD=${testPassword}\n`)
  );
  await installs(short);

  // Where a drop-in would decide GOBLIN_PASSWORD in a way the installer does not read (here, from
  // systemd's own environment), it cannot tell: it stops, changing nothing. GOBLIN_PASSWORD in
  // /etc/uptime-goblin.env decides it (an EnvironmentFile= counts after PassEnvironment=).
  const unknown = why =>
    `Whether Uptime Goblin would have an admin password could not be checked: ${why}. Uptime Goblin refuses to start without one (exit status 78). ${passwordFix} Nothing was changed.`;
  const passed = await makeHost(t);
  env = withoutPassword(passed);
  dropIn(passed, 'pass.conf', '[Service]\nPassEnvironment=GOBLIN_PASSWORD\n');
  await refused(
    passed,
    unknown(
      "PassEnvironment= in /etc/systemd/system/uptime-goblin.service.d/pass.conf passes GOBLIN_PASSWORD from the environment of systemd's own process, which this installer does not read"
    ),
    env
  );
  fs.appendFileSync(passed.path('etc/uptime-goblin.env'), `GOBLIN_PASSWORD=${testPassword}\n`);
  await installs(passed);
  // A drop-in line that would remove it, but whose value the installer cannot tell, decides it
  // whatever /etc/uptime-goblin.env says: only removing that line lets the install go on.
  const unsetSpecifier = await makeHost(t);
  env = fs.readFileSync(unsetSpecifier.path('etc/uptime-goblin.env'), 'utf8');
  dropIn(unsetSpecifier, 'unset.conf', '[Service]\nUnsetEnvironment=GOBLIN_PASSWORD=%i\n');
  await refused(
    unsetSpecifier,
    unknown(
      'UnsetEnvironment= in /etc/systemd/system/uptime-goblin.service.d/unset.conf removes GOBLIN_PASSWORD with a specifier, which this installer does not expand'
    ),
    env
  );
  fs.rmSync(unsetSpecifier.path('etc/systemd/system/uptime-goblin.service.d/unset.conf'));
  await installs(unsetSpecifier);

  // A drop-in that removes it refuses, naming the drop-in, also on a new install, whose
  // /etc/uptime-goblin.env the installer would write with a random GOBLIN_PASSWORD; without that drop-in
  // the new install goes on, and the password it writes is never printed.
  const fresh = await makeFreshHost(t);
  dropIn(fresh, 'unset.conf', '[Service]\nUnsetEnvironment=GOBLIN_PASSWORD\n');
  await refused(
    fresh,
    passwordStop(
      'is removed for Uptime Goblin (UnsetEnvironment= in /etc/systemd/system/uptime-goblin.service.d/unset.conf)'
    ),
    null
  );
  fs.rmSync(fresh.path('etc/systemd/system/uptime-goblin.service.d/unset.conf'));
  const created = await installs(fresh);
  const written = /^GOBLIN_PASSWORD=(.+)$/m.exec(
    fs.readFileSync(fresh.path('etc/uptime-goblin.env'), 'utf8')
  )?.[1];
  assert.ok(written && written.length >= 12, 'the installer wrote a random GOBLIN_PASSWORD');
  assert.ok(!created.output.includes(written));

  // An upgrade whose /etc/uptime-goblin.env lost its password: Uptime Goblin keeps running the release it has.
  const upgrade = await makeHost(t);
  const legacy = await upgrade.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }));
  assert.equal(legacy.status, 0, ok(legacy));
  withoutPassword(upgrade);
  const before = hostState(upgrade);
  const stopped = await upgrade.install(source, ['--verify-timeout', '5']);
  assert.equal(stopped.status, 1, ok(stopped));
  assert.equal(stopped.stderr.trim(), passwordStop(nowhere));
  assert.deepEqual(hostState(upgrade), before, 'nothing on the host changed');
  assert.equal(upgrade.installedVersion(), '1.4.3-test.1');
  assert.equal(upgrade.systemctl('is-active', 'uptime-goblin.service').status, 0, 'still serving');
});

// auth.json is read, as root, by this release's own reader, the one Uptime Goblin's start reads it with
// (readAuthRecord in lib/identity/password.mjs): never through a symbolic link, never waiting on a FIFO, only a
// regular file of at most 8192 bytes that holds a valid v1 record; and while it is there Uptime Goblin
// ignores GOBLIN_PASSWORD. The installer once checked only that something was there, so a
// directory, a link, a FIFO, an empty file or {} passed, and the install changed the code, the
// unit and the service before Uptime Goblin refused to start (exit status 78), on a first install with
// nothing to restore (AUTH-REMEDIATION F6). It now runs the same reader before anything changes.
const authRefusal =
  'Saved authentication could not be loaded. Restore a valid auth.json backup before starting Uptime Goblin.';
const authJsonStop = `This release of Uptime Goblin would refuse to start (exit status 78) with "${authRefusal}": /var/lib/uptime-goblin/auth.json is a symbolic link, not a regular file, larger than 8192 bytes or not a valid password record, and while it is there Uptime Goblin ignores GOBLIN_PASSWORD. Restore /var/lib/uptime-goblin/auth.json from a backup, or move it out of /var/lib/uptime-goblin and set GOBLIN_PASSWORD (12 to 1024 characters) in /etc/uptime-goblin.env (sudoedit /etc/uptime-goblin.env): it becomes the admin password and signs out every session. Then run this installer again. Nothing was changed.`;
// What is at <data>/auth.json, as lstat sees it: never followed, opened for writing or re-moded.
const authJsonState = host => {
  const file = host.path('var/lib/uptime-goblin/auth.json');
  const stat = fs.lstatSync(file);
  return {
    mode: stat.mode,
    size: stat.size,
    mtimeMs: stat.mtimeMs,
    bytes: stat.isFile() && stat.mode & 0o400 ? fs.readFileSync(file).toString('hex') : null,
    link: stat.isSymbolicLink() ? fs.readlinkSync(file) : null,
  };
};

test('an auth.json that Uptime Goblin would refuse at its start stops an install or upgrade before anything changes, whatever GOBLIN_PASSWORD is; a valid one goes on', async t => {
  const source = makeSource(t, { version: '1.5.0-test.1', mode: 'ok' });
  assert.equal(validAuthJson().length < 8192, true);
  // Each puts something other than a usable auth.json at `file` (`host` for files beside it).
  const cases = [
    ['a directory', file => fs.mkdirSync(file)],
    [
      'a symbolic link to a valid record',
      (file, host) => {
        const target = path.join(host.base, 'elsewhere-auth.json');
        fs.writeFileSync(target, validAuthJson(), { mode: 0o600 });
        fs.symlinkSync(target, file);
      },
    ],
    [
      'a symbolic link to nothing',
      (file, host) => fs.symlinkSync(path.join(host.base, 'missing.json'), file),
    ],
    ['a FIFO', file => assert.equal(spawnSync('mkfifo', [file]).status, 0)],
    ['an empty file', file => fs.writeFileSync(file, '', { mode: 0o600 })],
    ['{}', file => fs.writeFileSync(file, '{}\n', { mode: 0o600 })],
    [
      'a cut-off record',
      file => fs.writeFileSync(file, validAuthJson().subarray(0, 60), { mode: 0o600 }),
    ],
    [
      'a record with other scrypt parameters',
      file => {
        const record = JSON.parse(validAuthJson().toString('utf8'));
        record.parameters.N = 16384;
        fs.writeFileSync(file, JSON.stringify(record) + '\n', { mode: 0o600 });
      },
    ],
    [
      'a valid record padded past 8192 bytes',
      file => fs.writeFileSync(file, validAuthJson(8193), { mode: 0o600 }),
    ],
  ];
  // Nothing changes: no code, key, unit or service call that changes anything, /etc/uptime-goblin.env as
  // it was, and auth.json neither followed, written nor re-moded.
  const untouched = (host, env, auth) => {
    assert.equal(fs.readFileSync(host.path('etc/uptime-goblin.env'), 'utf8'), env);
    for (const file of [
      'opt/uptime-goblin',
      'etc/uptime-goblin',
      'etc/systemd/system/uptime-goblin.service',
    ])
      assert.ok(!fs.existsSync(host.path(file)), file);
    assert.deepEqual(fs.readdirSync(host.path('var/lib/uptime-goblin')), ['auth.json']);
    assert.deepEqual(authJsonState(host), auth);
    assert.equal(
      host
        .calls()
        .split('\n')
        .filter(line => line && !/^(show|show-environment)( |$)/.test(line))
        .join('\n'),
      ''
    );
  };
  for (const [name, make] of cases) {
    // With GOBLIN_PASSWORD in /etc/uptime-goblin.env (as makeHost writes it): Uptime Goblin would ignore it.
    const host = await makeHost(t);
    const data = host.path('var/lib/uptime-goblin');
    fs.mkdirSync(data, { recursive: true, mode: 0o700 });
    make(path.join(data, 'auth.json'), host);
    // Uptime Goblin's own start refuses it (exit status 78), never reaching GOBLIN_PASSWORD.
    assert.throws(
      () => readAuthRecord(data),
      error => error.refusal === true && error.message === authRefusal,
      name
    );
    const env = fs.readFileSync(host.path('etc/uptime-goblin.env'), 'utf8');
    const auth = authJsonState(host);
    const result = await host.install(source, ['--verify-timeout', '5'], {}, { timeout: 120000 });
    assert.equal(result.status, 1, `${name}: ${ok(result)}`);
    assert.equal(result.stderr.trim(), authJsonStop, name);
    assert.equal(result.stdout, '', name);
    assert.doesNotMatch(result.output, new RegExp(testPassword), name);
    untouched(host, env, auth);
  }

  // Without GOBLIN_PASSWORD too, it is auth.json that Uptime Goblin would refuse, not a missing password.
  const bare = await makeHost(t);
  const bareEnv = withoutPassword(bare);
  fs.mkdirSync(bare.path('var/lib/uptime-goblin'), { recursive: true, mode: 0o700 });
  fs.writeFileSync(bare.path('var/lib/uptime-goblin/auth.json'), '{}\n', { mode: 0o600 });
  const bareAuth = authJsonState(bare);
  const bareResult = await bare.install(source, ['--verify-timeout', '5']);
  assert.equal(bareResult.status, 1, ok(bareResult));
  assert.equal(bareResult.stderr.trim(), authJsonStop);
  untouched(bare, bareEnv, bareAuth);
  // A valid record in its place: the install goes on, with no GOBLIN_PASSWORD.
  fs.writeFileSync(bare.path('var/lib/uptime-goblin/auth.json'), validAuthJson(), { mode: 0o600 });
  const installed = await bare.install(source, ['--verify-timeout', '5']);
  assert.equal(installed.status, 0, ok(installed));
  assert.equal(bare.installedVersion(), '1.5.0-test.1');

  // A valid record of exactly 8192 bytes goes on too, and while it is there a GOBLIN_PASSWORD
  // that Uptime Goblin would refuse on its own is ignored, as Uptime Goblin's start ignores it.
  const edge = await makeHost(t);
  const edgeEnv = withoutPassword(edge) + 'GOBLIN_PASSWORD=short-pw-11\n';
  fs.writeFileSync(edge.path('etc/uptime-goblin.env'), edgeEnv);
  fs.mkdirSync(edge.path('var/lib/uptime-goblin'), { recursive: true, mode: 0o700 });
  fs.writeFileSync(edge.path('var/lib/uptime-goblin/auth.json'), validAuthJson(8192), {
    mode: 0o600,
  });
  const { readBuiltinSources } = await import('../../lib/identity/bootstrap.mjs');
  assert.equal(
    readBuiltinSources({ directory: edge.path('var/lib/uptime-goblin'), password: 'short-pw-11' })
      .configured,
    true
  );
  const edgeResult = await edge.install(source, ['--verify-timeout', '5']);
  assert.equal(edgeResult.status, 0, ok(edgeResult));
  assert.equal(edge.installedVersion(), '1.5.0-test.1');
  assert.doesNotMatch(edgeResult.output, /short-pw-11/);

  // An upgrade from a running 1.4.x whose auth.json Uptime Goblin would refuse: nothing on the host
  // changes, and the release it has keeps serving.
  for (const [name, make] of [cases[0], cases[1], cases[5]]) {
    const upgrade = await makeHost(t);
    const legacy = await upgrade.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }));
    assert.equal(legacy.status, 0, ok(legacy));
    const file = upgrade.path('var/lib/uptime-goblin/auth.json');
    fs.rmSync(file, { force: true });
    make(file, upgrade);
    const before = hostState(upgrade);
    const auth = authJsonState(upgrade);
    const stopped = await upgrade.install(
      source,
      ['--verify-timeout', '5'],
      {},
      { timeout: 120000 }
    );
    assert.equal(stopped.status, 1, `${name}: ${ok(stopped)}`);
    assert.equal(stopped.stderr.trim(), authJsonStop, name);
    assert.deepEqual(hostState(upgrade), before, `${name}: nothing on the host changed`);
    assert.deepEqual(authJsonState(upgrade), auth, name);
    assert.equal(upgrade.installedVersion(), '1.4.3-test.1');
    assert.equal(
      upgrade.systemctl('is-active', 'uptime-goblin.service').status,
      0,
      'still serving'
    );
  }
});

// An auth.json that cannot be opened at all (here: mode 0000 for an account that is not root)
// tells nothing about the password: Uptime Goblin's start fails with that error (exit status 1, retried),
// and the installer stops as "could not be checked", changing nothing. Root reads such a file, so
// this case cannot be made as root.
test(
  'an auth.json the installer cannot open stops an install before anything changes, as could not be checked',
  { skip: process.getuid?.() === 0 && 'root reads a file of mode 0000' },
  async t => {
    const source = makeSource(t, { version: '1.5.0-test.1', mode: 'ok' });
    const host = await makeHost(t);
    const data = host.path('var/lib/uptime-goblin');
    fs.mkdirSync(data, { recursive: true, mode: 0o700 });
    fs.writeFileSync(path.join(data, 'auth.json'), validAuthJson(), { mode: 0o000 });
    assert.throws(
      () => readAuthRecord(data),
      error => error.code === 'EACCES' && error.refusal !== true
    );
    const env = fs.readFileSync(host.path('etc/uptime-goblin.env'), 'utf8');
    const auth = authJsonState(host);
    const result = await host.install(source, ['--verify-timeout', '5']);
    assert.equal(result.status, 1, ok(result));
    assert.equal(
      result.stderr.trim(),
      `Whether Uptime Goblin would have an admin password could not be checked: /var/lib/uptime-goblin/auth.json cannot be checked (EACCES). Uptime Goblin refuses to start without one (exit status 78). ${passwordFix} Nothing was changed.`
    );
    assert.equal(fs.readFileSync(host.path('etc/uptime-goblin.env'), 'utf8'), env);
    for (const file of [
      'opt/uptime-goblin',
      'etc/uptime-goblin',
      'etc/systemd/system/uptime-goblin.service',
    ])
      assert.ok(!fs.existsSync(host.path(file)), file);
    assert.deepEqual(authJsonState(host), auth);
  }
);

// The password step reads auth.json as root, and root reads a file the uptime-goblin account cannot: an
// auth.json copied in from a backup as root (root:root 0600) passed it, and every start of Uptime Goblin,
// which runs as the uptime-goblin account, then failed (EACCES, exit status 1, retried), so an upgrade
// stopped Uptime Goblin and rolled back to code that cannot read it either, and an install with no
// previous version left Uptime Goblin down (review INST-1). The installer now tries it as the orbit
// account (runuser) once the data directory is that account's, before the service stops. The fake
// runuser takes the data directory for the uptime-goblin account's and a path listed in root-owned for
// root's (test/installer/fake-bin/runuser.cjs).
const authJsonUnreadable =
  '/var/lib/uptime-goblin/auth.json cannot be read by the uptime-goblin account, which Uptime Goblin runs as, so Uptime Goblin would fail to start (exit status 1), and systemd would start it again every 5 seconds. Give it to that account: sudo chown uptime-goblin:uptime-goblin /var/lib/uptime-goblin/auth.json && sudo chmod 0600 /var/lib/uptime-goblin/auth.json, then run this installer again. Uptime Goblin was not stopped, and its code and settings were not changed.';

test('an auth.json the uptime-goblin account cannot read stops an install or upgrade before Uptime Goblin stops, and goes on once that account can read it', async t => {
  const host = await makeHost(t);
  const first = await host.install(makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }));
  assert.equal(first.status, 0, ok(first));
  const file = host.path('var/lib/uptime-goblin/auth.json'),
    owners = path.join(host.env.FAKE_SYSTEMD_DIR, 'root-owned'),
    checks = () =>
      fs
        .readFileSync(path.join(host.env.FAKE_SYSTEMD_DIR, 'runuser.log'), 'utf8')
        .trimEnd()
        .split('\n');
  // Copied in as root from a backup: root:root 0600. Root (the password step) reads it.
  fs.rmSync(file, { force: true });
  fs.writeFileSync(file, validAuthJson(), { mode: 0o600 });
  fs.writeFileSync(owners, `${file}\n`);
  const next = makeSource(t, { version: '1.5.0-test.2', mode: 'ok' });
  // hostState less its calls: the key step before this check reads the unit (systemctl cat).
  const state = () => ({ ...hostState(host), calls: undefined }),
    changing = (calls, since = '') =>
      calls
        .slice(since.length)
        .split('\n')
        .filter(line => line && !/^(is-active|show|show-environment|cat)( |$)/.test(line));
  const before = state(),
    calls = host.calls(),
    auth = authJsonState(host);
  const result = await host.install(next, ['--verify-timeout', '5']);
  assert.equal(result.status, 1, ok(result));
  assert.equal(result.stderr.trim(), authJsonUnreadable);
  assert.doesNotMatch(result.stdout, /Installing Uptime Goblin/);
  assert.deepEqual(state(), before, 'Uptime Goblin was not stopped, and nothing of it changed');
  assert.deepEqual(changing(host.calls(), calls), [], 'no service call that changes anything');
  assert.deepEqual(authJsonState(host), auth, 'auth.json neither written nor re-moded');
  assert.equal(host.installedVersion(), '1.5.0-test.1');
  assert.equal(host.systemctl('is-active', 'uptime-goblin.service').status, 0, 'still serving');
  assert.equal(checks().at(-1), `-u uptime-goblin -- test -r ${file}`, 'checked as orbit');
  // Root's, but readable by every account (0644): the uptime-goblin account reads it, and the install goes
  // on.
  fs.chmodSync(file, 0o644);
  const readable = await host.install(next, ['--verify-timeout', '5']);
  assert.equal(readable.status, 0, ok(readable));
  assert.equal(host.installedVersion(), '1.5.0-test.2');
  // Given to the uptime-goblin account, as the message says (the chown is the tests' fake): it goes on.
  fs.chmodSync(file, 0o600);
  fs.writeFileSync(owners, '');
  const third = makeSource(t, { version: '1.5.0-test.3', mode: 'ok' });
  const passed = await host.install(third, ['--verify-timeout', '5']);
  assert.equal(passed.status, 0, ok(passed));
  assert.equal(host.installedVersion(), '1.5.0-test.3');
  assert.equal(checks().at(-1), `-u uptime-goblin -- test -r ${file}`);

  // With no previous version (a data directory restored on a new host, its auth.json copied in as
  // root): refused before any code, unit or service changes, and /etc/uptime-goblin.env as it was.
  const fresh = await makeHost(t);
  const data = fresh.path('var/lib/uptime-goblin'),
    freshFile = path.join(data, 'auth.json');
  fs.mkdirSync(data, { recursive: true, mode: 0o700 });
  fs.writeFileSync(freshFile, validAuthJson(), { mode: 0o600 });
  fs.writeFileSync(path.join(fresh.env.FAKE_SYSTEMD_DIR, 'root-owned'), `${freshFile}\n`);
  const env = fs.readFileSync(fresh.path('etc/uptime-goblin.env'), 'utf8'),
    freshAuth = authJsonState(fresh);
  const refused = await fresh.install(next, ['--verify-timeout', '5']);
  assert.equal(refused.status, 1, ok(refused));
  assert.equal(refused.stderr.trim(), authJsonUnreadable);
  assert.equal(fs.readFileSync(fresh.path('etc/uptime-goblin.env'), 'utf8'), env);
  for (const left of ['opt/uptime-goblin', 'etc/systemd/system/uptime-goblin.service'])
    assert.ok(!fs.existsSync(fresh.path(left)), left);
  assert.deepEqual(authJsonState(fresh), freshAuth);
  assert.deepEqual(changing(fresh.calls()), [], 'no service call that changes anything');
});

// Review INST-RUNUSER-1: runuser exits 1 also for errors of its own, before it runs test (a PAM
// session it cannot open, as in some unprivileged containers), 126 or 127 when test cannot be
// run, and dies on a signal. Each was reported as a file the uptime-goblin account cannot read, with a
// chown that does not help. Now each refuses with runuser's own words, changing nothing, for
// auth.json and the key files alike; only test's own "no" (status 1, nothing said) is unreadable.
test('a failure of runuser itself is reported as such, never as a file the uptime-goblin account cannot read', async t => {
  const host = await makeHost(t);
  const first = await host.install(makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }));
  assert.equal(first.status, 0, ok(first));
  const auth = host.path('var/lib/uptime-goblin/auth.json'),
    key = host.path('etc/uptime-goblin/secret.key'),
    fails = path.join(host.env.FAKE_SYSTEMD_DIR, 'runuser-fails');
  fs.rmSync(auth, { force: true });
  fs.writeFileSync(auth, validAuthJson(), { mode: 0o600 });
  const next = makeSource(t, { version: '1.5.0-test.2', mode: 'ok' });
  const pam = 'runuser: cannot open session: Permission denied',
    kept = 'Uptime Goblin was not stopped, and its code and settings were not changed.',
    authCheck = '/var/lib/uptime-goblin/auth.json: runuser (from util-linux)',
    keyCheck = 'GOBLIN_SECRET_KEY_FILE (/etc/uptime-goblin/secret.key): runuser (from util-linux)';
  for (const [failure, file, said] of [
    [{ status: 1, stderr: pam }, auth, `${authCheck} exited with status 1 (${pam}). ${kept}`],
    [{ status: 126 }, auth, `${authCheck} exited with status 126. ${kept}`],
    [{ signal: 'SIGKILL' }, auth, `${authCheck} was stopped by SIGKILL. ${kept}`],
    [
      { status: 1, stderr: pam },
      key,
      `${keyCheck} exited with status 1 (${pam}). Uptime Goblin was not changed.`,
    ],
  ]) {
    fs.writeFileSync(fails, JSON.stringify({ path: file, ...failure }));
    const before = { ...hostState(host), calls: undefined },
      text = authJsonState(host);
    const result = await host.install(next, ['--verify-timeout', '5']);
    assert.equal(result.status, 1, ok(result));
    assert.equal(
      result.stderr.trim(),
      `Could not check that the uptime-goblin account can read ${said}`,
      JSON.stringify(failure)
    );
    assert.doesNotMatch(result.stdout, /Installing Uptime Goblin/);
    assert.deepEqual({ ...hostState(host), calls: undefined }, before, 'nothing changed');
    assert.deepEqual(authJsonState(host), text);
    assert.equal(host.installedVersion(), '1.5.0-test.1');
  }
  // Once runuser works, the same files pass and the install goes on.
  fs.rmSync(fails);
  const passed = await host.install(next, ['--verify-timeout', '5']);
  assert.equal(passed.status, 0, ok(passed));
  assert.equal(host.installedVersion(), '1.5.0-test.2');
});

test('a service-unit write failure leaves the running release and rollback copy untouched', async t => {
  const host = await makeHost(t);
  for (const version of ['1.4.3-test.1', '1.4.3-test.2'])
    assert.equal((await host.install(makeSource(t, { version, mode: 'ok' }))).status, 0);
  const before = host.status();
  const unit = fs.readFileSync(host.path('etc/systemd/system/uptime-goblin.service'), 'utf8');
  // `systemctl cat` (the encryption-key step reads the unit) and `systemctl show` (the HOST/PORT
  // step reads its drop-ins) change nothing.
  const changing = () =>
    host
      .calls()
      .split('\n')
      .filter(line => !/^(cat|show|show-environment)( |$)/.test(line))
      .join('\n');
  const calls = changing();
  const source = makeSource(t, { version: '1.4.3-test.9', mode: 'ok' });
  const result = await host.install(source, [], { FAKE_UNIT_WRITE_FAIL: '1' });
  assert.equal(result.status, 1, ok(result));
  assert.match(result.stderr, /simulated service-unit write failure/);
  assert.equal(host.installedVersion(), '1.4.3-test.2');
  assert.equal(host.installedVersion('opt/uptime-goblin.previous'), '1.4.3-test.1');
  assert.deepEqual(host.status(), before);
  assert.equal(changing(), calls, 'the running service was never stopped');
  assert.equal(
    fs.readFileSync(host.path('etc/systemd/system/uptime-goblin.service'), 'utf8'),
    unit
  );
  assert.deepEqual(fs.readdirSync(host.path('etc/systemd/system')), ['uptime-goblin.service']);
  assert.ok(!fs.existsSync(host.path('opt/uptime-goblin.new')));
  assert.equal(host.systemctl('is-active', 'uptime-goblin.service').status, 0);
});

test('a service-unit publication failure after the code switch restores the previous release', async t => {
  const host = await makeHost(t);
  assert.equal(
    (await host.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }))).status,
    0
  );
  const unit = fs.readFileSync(host.path('etc/systemd/system/uptime-goblin.service'), 'utf8');
  const source = makeSource(t, { version: '1.4.3-test.9', mode: 'ok' });
  const result = await host.install(source, [], { FAKE_UNIT_RENAME_FAIL: '1' });
  assert.equal(result.status, 1, ok(result));
  assert.match(result.stderr, /simulated service-unit publication failure/);
  assert.match(result.stderr, /The previous version is running again/);
  assert.equal(host.installedVersion(), '1.4.3-test.1');
  assert.equal(host.installedVersion('opt/uptime-goblin.failed'), '1.4.3-test.9');
  assert.equal(host.status().version, '1.4.3-test.1');
  assert.equal(host.status().pid, host.state().pid);
  assert.equal(
    fs.readFileSync(host.path('etc/systemd/system/uptime-goblin.service'), 'utf8'),
    unit
  );
  assert.deepEqual(fs.readdirSync(host.path('etc/systemd/system')), ['uptime-goblin.service']);
  assert.equal(host.systemctl('is-active', 'uptime-goblin.service').status, 0);
  assert.doesNotMatch(result.stderr, /Type=simple/, 'no rollback unit swap was attempted');
});

// Only the publication fails here, so a move of rollback.service would succeed: the old unit,
// which was never replaced, must still be the one on disk (not this release's unit as Type=simple).
test('a rollback after a failed unit publication leaves the old unit on disk', async t => {
  const host = await makeHost(t);
  assert.equal(
    (await host.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }))).status,
    0
  );
  const unit = fs.readFileSync(host.path('etc/systemd/system/uptime-goblin.service'), 'utf8');
  const source = makeSource(t, { version: '1.4.3-test.9', mode: 'ok' });
  const result = await host.install(source, [], { FAKE_UNIT_RENAME_FAIL: 'publish' });
  assert.equal(result.status, 1, ok(result));
  assert.match(result.stderr, /simulated service-unit publication failure/);
  assert.match(result.stderr, /The previous version is running again/);
  assert.doesNotMatch(result.stderr, /Type=simple/);
  assert.equal(host.installedVersion(), '1.4.3-test.1');
  assert.equal(
    fs.readFileSync(host.path('etc/systemd/system/uptime-goblin.service'), 'utf8'),
    unit
  );
  assert.deepEqual(fs.readdirSync(host.path('etc/systemd/system')), ['uptime-goblin.service']);
});

test('a failed rollback unit reload still restarts and verifies the loaded service', async t => {
  const host = await makeHost(t);
  assert.equal(
    (await host.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }))).status,
    0
  );
  const calls = host.calls();
  const source = makeSource(t, { version: '1.4.3-test.9', mode: 'ok' });
  const result = await host.install(source, [], { FAKE_SYSTEMD_FAIL_ALWAYS: 'daemon-reload' });
  assert.equal(result.status, 1, ok(result));
  assert.equal(host.installedVersion(), '1.4.3-test.1');
  assert.equal(host.installedVersion('opt/uptime-goblin.failed'), '1.4.3-test.9');
  assert.match(result.stderr, /WARNING: systemd could not reload its unit files during rollback/);
  assert.match(result.stderr, /The previous version is running again/);
  assert.match(host.calls().slice(calls.length), /restart --no-block uptime-goblin\.service/);
  assert.equal(host.systemctl('is-active', 'uptime-goblin.service').status, 0);
  assert.equal(host.status().version, '1.4.3-test.1');
  assert.equal(host.status().pid, host.state().pid);
});

test('a failed rollback restart reports restoration without claiming recovery', async t => {
  const host = await makeHost(t);
  assert.equal(
    (await host.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }))).status,
    0
  );
  const source = makeSource(t, { version: '1.4.3-test.9', mode: 'ok' });
  const result = await host.install(source, [], { FAKE_SYSTEMD_FAIL_ALWAYS: 'restart' });
  assert.equal(result.status, 1, ok(result));
  assert.equal(host.installedVersion(), '1.4.3-test.1');
  assert.equal(host.installedVersion('opt/uptime-goblin.failed'), '1.4.3-test.9');
  assert.match(result.stderr, /previous code was restored, but its service could not be restarted/);
  assert.doesNotMatch(result.stderr, /The previous version is running again/);
  assert.equal(host.systemctl('is-active', 'uptime-goblin.service').status, 3);
});

// The new unit is Type=notify; a release before it never reports ready, so a rollback keeps the
// new unit (limits, sandbox, --supervised) but as Type=simple.
test('a rollback keeps the new unit as Type=simple for the restored release', async t => {
  const host = await makeHost(t);
  const unit = () => fs.readFileSync(host.path('etc/systemd/system/uptime-goblin.service'), 'utf8');
  assert.equal(
    (await host.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }))).status,
    0
  );
  const installed = unit();
  for (const line of ['Type=notify', 'NotifyAccess=all', 'TimeoutStartSec=infinity'])
    assert.match(installed, new RegExp(`^${line}$`, 'm'));
  const source = makeSource(t, { version: '1.4.3-test.3', mode: 'crash' });
  const result = await host.install(source, ['--verify-timeout', '5']);
  assert.equal(result.status, 1, ok(result));
  assert.match(result.stderr, /The previous version is running again/);
  assert.equal(
    unit(),
    installed
      .replace(/^Type=notify$/m, 'Type=simple')
      .replace(/^NotifyAccess=all\n/m, '')
      .replace(/^TimeoutStartSec=infinity\n/m, '')
  );
  // The next upgrade writes the Type=notify unit again.
  const again = await host.install(makeSource(t, { version: '1.4.3-test.4', mode: 'ok' }));
  assert.equal(again.status, 0, ok(again));
  assert.equal(unit(), installed);
});

test('a nonterminating legacy rollback probe is killed within the verification budget', async t => {
  const host = await makeHost(t);
  assert.equal((await host.install(makeSource(t, { version: '1.4.2', mode: 'ok' }))).status, 0);
  // An old probe may outlive its HTTP idle timeout (for example with a trickling response).
  // This stand-in ignores SIGTERM and eventually exits successfully; neither behavior may
  // turn an expired verification budget into a successful legacy-health report.
  fs.appendFileSync(
    host.path('opt/uptime-goblin/lib/healthcheck.mjs'),
    `\nif (process.argv.includes('--wait')) {
      fs.writeFileSync(${JSON.stringify(host.path('var/lib/uptime-goblin/legacy-probe.pid'))}, String(process.pid));
      process.on('SIGTERM', () => {});
      await new Promise(resolve => setTimeout(resolve, 5000));
      fs.writeFileSync(${JSON.stringify(host.path('var/lib/uptime-goblin/legacy-probe-completed'))}, 'yes');
    }\n`
  );
  const source = makeSource(t, { version: '1.4.3-test.9', mode: 'crash' });
  const result = await host.install(source, ['--verify-timeout', '1']);
  assert.equal(result.status, 1, ok(result));
  assert.match(result.stderr, /Legacy health check exceeded its 1 second verification deadline/);
  assert.match(result.stderr, /legacy health check did not pass/);
  assert.doesNotMatch(result.stderr, /legacy health check answered/);
  assert.equal(host.installedVersion(), '1.4.2');
  assert.ok(!fs.existsSync(host.path('var/lib/uptime-goblin/legacy-probe-completed')));
  const probePid = Number(
    fs.readFileSync(host.path('var/lib/uptime-goblin/legacy-probe.pid'), 'utf8')
  );
  assert.throws(() => process.kill(probePid, 0), { code: 'ESRCH' });
});

test('a systemd management failure after the code switch restores the previous release', async t => {
  const host = await makeHost(t);
  const previous = makeSource(t, { version: '1.4.3-test.1', mode: 'ok' });
  assert.equal((await host.install(previous)).status, 0);
  for (const command of ['daemon-reload', 'enable']) {
    const source = makeSource(t, { version: '1.4.3-test.9', mode: 'ok' });
    const result = await host.install(source, [], { FAKE_SYSTEMD_FAIL_ONCE: command });
    assert.equal(result.status, 1, ok(result));
    assert.match(result.stderr, new RegExp(`simulated ${command} failure`));
    assert.match(result.stderr, /The previous version is running again/);
    assert.equal(host.installedVersion(), '1.4.3-test.1');
    assert.equal(host.installedVersion('opt/uptime-goblin.failed'), '1.4.3-test.9');
    assert.equal(host.status().version, '1.4.3-test.1');
    assert.equal(host.status().pid, host.state().pid);
  }
});

test('reinstalling the same release preserves the older rollback copy', async t => {
  const host = await makeHost(t);
  const first = makeSource(t, { version: '1.4.3-test.1', mode: 'ok' });
  const second = makeSource(t, { version: '1.4.3-test.2', mode: 'ok' });
  for (const source of [first, second, second]) {
    const installed = await host.install(source);
    assert.equal(installed.status, 0, ok(installed));
    assert.ok(!fs.existsSync(host.path('opt/uptime-goblin.reinstall')));
  }
  assert.equal(host.installedVersion('opt/uptime-goblin.previous'), '1.4.3-test.1');
  const failed = await host.install(second, [], { FAKE_SYSTEMD_FAIL_ONCE: 'enable' });
  assert.equal(failed.status, 1, ok(failed));
  assert.match(failed.stderr, /The previous version is running again/);
  assert.equal(host.installedVersion(), '1.4.3-test.2');
  assert.equal(host.installedVersion('opt/uptime-goblin.previous'), '1.4.3-test.1');
  assert.equal(host.status().version, '1.4.3-test.2');
  assert.ok(!fs.existsSync(host.path('opt/uptime-goblin.reinstall')));
});

test('rollback does not declare success when an unrelated process answers on the port', async t => {
  const host = await makeHost(t);
  const old = makeSource(t, { version: '1.4.3-test.1', mode: 'ok' });
  assert.equal((await host.install(old)).status, 0);
  host.systemctl('stop', 'uptime-goblin.service');
  const unrelated = http.createServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end('{"status":"ok"}');
  });
  await new Promise(resolve => unrelated.listen(host.port, '127.0.0.1', resolve));
  t.after(
    () =>
      new Promise(resolve => {
        unrelated.closeAllConnections();
        unrelated.close(resolve);
      })
  );
  const failed = await host.install(makeSource(t, { version: '1.4.3-test.9', mode: 'crash' }), [
    '--verify-timeout',
    '1',
  ]);
  assert.equal(failed.status, 1, ok(failed));
  assert.equal(host.installedVersion(), '1.4.3-test.1');
  assert.doesNotMatch(failed.stderr, /The previous version is running again/);
  assert.match(failed.stderr, /previous version could not be verified/);
});

test('the installed Uptime Goblin passes verification (real server.mjs)', async t => {
  const host = await makeHost(t);
  allowWhatThisMachineLacks(host);
  const source = makeSource(t, { version: '1.4.3-test.1' });
  const result = await host.install(source, ['--verify-timeout', '60']);
  assert.equal(result.status, 0, ok(result));
  const status = host.status();
  assert.equal(status.version, '1.4.3-test.1');
  assert.equal(status.pid, host.state().pid);
  assert.deepEqual(status.listen, { host: '127.0.0.1', port: host.port });
  const health = await fetch(`http://127.0.0.1:${host.port}/health`, {
    headers: { Host: `localhost:${host.port}` },
  });
  assert.deepEqual(await health.json(), { status: 'ok' });
  // The public check reveals nothing about the release; the status file names it.
  assert.equal(health.headers.get('x-orbit-build'), null);
  assert.match(status.build, /^[0-9a-f]{12}$/);
  // A clean stop removes the status file (C3).
  host.systemctl('stop', 'uptime-goblin.service');
  assert.equal(host.status(), null);
});

// The owner's real starting point: 1.4.2, installed by its own installer (resolved Node path,
// Restart=on-failure, /health behind sign-in). The rollback target's own healthcheck verifies it.
const release142 = path.join(
  repository,
  'test/fixtures/releases/orbit-homelab-1.4.2-runtime.tar.gz'
);
const fixtureMissing = fs.existsSync(release142)
  ? false
  : 'the 1.4.2 release fixture is missing (test/fixtures/releases)';
if (fixtureMissing && required('fixtures'))
  test('the 1.4.2 release fixture is present (TEST_REQUIRE=fixtures)', () =>
    assert.fail(fixtureMissing));

test(
  'an upgrade from a real 1.4.2 install rolls back to 1.4.2, then succeeds',
  { skip: fixtureMissing },
  async t => {
    const host = await makeHost(t);
    allowWhatThisMachineLacks(host);
    fs.mkdirSync(host.path('opt/uptime-goblin/node_modules'), { recursive: true });
    const extracted = spawnSync('tar', ['-xzf', release142, '-C', host.path('opt/uptime-goblin')], {
      encoding: 'utf8',
    });
    assert.equal(extracted.status, 0, extracted.stderr);
    fs.cpSync(
      path.join(repository, 'node_modules/nodemailer'),
      host.path('opt/uptime-goblin/node_modules/nodemailer'),
      { recursive: true }
    );
    fs.mkdirSync(host.path('var/lib/uptime-goblin'), { recursive: true, mode: 0o700 });
    fs.mkdirSync(host.path('etc/systemd/system'), { recursive: true });
    fs.writeFileSync(
      host.path('etc/systemd/system/uptime-goblin.service'),
      [
        '[Service]',
        'WorkingDirectory=/opt/uptime-goblin',
        'Environment=GOBLIN_DATA_DIR=/var/lib/uptime-goblin',
        'EnvironmentFile=/etc/uptime-goblin.env',
        `ExecStart=${fs.realpathSync(process.execPath)} /opt/uptime-goblin/server.mjs`,
        'Restart=on-failure',
        '',
      ].join('\n')
    );
    assert.equal(host.systemctl('start', 'uptime-goblin.service').status, 0);
    let answered = false;
    for (let i = 0; i < 100 && !answered; i++) {
      answered = await fetch(`http://127.0.0.1:${host.port}/health`).then(
        () => true,
        () => false
      );
      if (!answered) await delay(100);
    }
    assert.ok(answered, '1.4.2 is serving');
    assert.equal(host.installedVersion(), '1.4.2');

    const failed = await host.install(makeSource(t, { version: '1.4.3-test.9', mode: 'crash' }), [
      '--verify-timeout',
      '3',
    ]);
    assert.equal(failed.status, 1, ok(failed));
    assert.match(failed.stderr, /previous code was restored and its legacy health check answered/);
    assert.match(failed.stderr, /process identity is unverified/);
    assert.doesNotMatch(failed.stderr, /The previous version is running again/);
    assert.equal(host.installedVersion(), '1.4.2');
    assert.equal(host.systemctl('is-active', 'uptime-goblin.service').status, 0);
    // The restored 1.4.2 runs under the new unit, which it ignores harmlessly.
    const unit = fs.readFileSync(host.path('etc/systemd/system/uptime-goblin.service'), 'utf8');
    assert.match(unit, /^Restart=always$/m);

    const upgraded = await host.install(makeSource(t, { version: '1.4.3-test.10' }), [
      '--verify-timeout',
      '60',
    ]);
    assert.equal(upgraded.status, 0, ok(upgraded));
    assert.equal(host.installedVersion('opt/uptime-goblin.previous'), '1.4.2');
    assert.equal(host.status().version, '1.4.3-test.10');
    assert.equal(host.status().pid, host.state().pid);
  }
);

test('problems are refused before anything on the host changes', async t => {
  const host = await makeHost(t);
  const unchanged = async (source, args, pattern, env) => {
    const result = await host.install(source, args, env);
    assert.notEqual(result.status, 0, ok(result));
    assert.match(result.stderr, pattern);
    assert.equal(host.calls(), '', 'systemctl was not called');
    assert.ok(!fs.existsSync(host.path('opt/uptime-goblin')));
    assert.ok(!fs.existsSync(host.path('var/lib/uptime-goblin')));
  };
  let source = makeSource(t, { mode: 'ok' });
  fs.appendFileSync(path.join(source, 'deploy/manifest.txt'), 'lib/ghost.mjs\n');
  await unchanged(source, [], /Missing application file: lib\/ghost\.mjs/);

  source = makeSource(t, { mode: 'ok' });
  fs.appendFileSync(path.join(source, 'deploy/manifest.txt'), '../etc/passwd\n');
  await unchanged(source, [], /Invalid manifest entry: \.\.\/etc\/passwd/);

  source = makeSource(t, { mode: 'ok' });
  fs.writeFileSync(
    path.join(source, 'deploy/manifest.txt'),
    manifest.filter(file => file !== 'lib/healthcheck.mjs').join('\n') + '\n'
  );
  await unchanged(source, [], /deploy\/manifest\.txt must list lib\/healthcheck\.mjs/);

  source = makeSource(t, { mode: 'ok' });
  writeSums(source);
  fs.appendFileSync(path.join(source, 'public/app.js'), '\n// tampered\n');
  await unchanged(source, [], /public\/app\.js: checksum mismatch[\s\S]*do not match SHA256SUMS/);

  source = makeSource(t, { mode: 'ok' });
  await unchanged(source, ['--verify-timeout', '0'], /--verify-timeout takes 1 to 1800 seconds/);
  await unchanged(source, ['--frobnicate'], /Unknown option: --frobnicate/);

  // Node older than 24 (or without node:sqlite).
  const oldNode = path.join(temporary(t, 'orbit-old-node-'), 'node');
  fs.writeFileSync(oldNode, '#!/bin/sh\n[ "$1" = --version ] && echo v22.9.0\nexit 1\n', {
    mode: 0o755,
  });
  await unchanged(source, [], /Node\.js 24\+ with SQLite is required .*v22\.9\.0/, {
    PATH: host.env.PATH.replace(host.nodeBin, path.dirname(oldNode)),
  });

  // No node at all.
  if (!['/usr/bin/node', '/bin/node', '/usr/sbin/node', '/sbin/node'].some(fs.existsSync))
    await unchanged(source, [], /Install Node\.js 24 or newer first/, {
      PATH: host.env.PATH.replace(host.nodeBin + path.delimiter, ''),
    });

  // Running the installed copy would move the installer's own tree away mid-install.
  for (const tree of ['opt/uptime-goblin', 'opt/uptime-goblin.reinstall']) {
    const inside = host.path(tree);
    fs.cpSync(source, inside, { recursive: true });
    const result = await host.install(inside, []);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Run the installer from a staging directory/);
    assert.equal(host.calls(), '');
  }
});

// ---------------------------------------------------------------------------------------------
// The 1.5 sign-in checks (sessions spec §3.12, D27): the proxy preflight on the upgrade from
// 1.4.x, and insecure-HTTP detection for installs that listen on the network without a proxy.

const preflightTail =
  'On a network you trust you can instead allow sign-in over plain HTTP (the password and the sign-in cookie then cross it unencrypted): run this installer again with --allow-insecure-http, which adds GOBLIN_INSECURE_HTTP_SESSIONS=1 to /etc/uptime-goblin.env where neither that file nor anything else systemd would give Uptime Goblin says yes or no, or set GOBLIN_INSECURE_HTTP_SESSIONS=1 there yourself. If you have checked the proxy yourself, run again with --proxy-proto-checked. Nothing was changed.';
const preflightText = (version, seen) =>
  `Uptime Goblin 1.5 signs browsers in with a cookie and must know whether the browser uses HTTPS. The running Orbit ${version} has ${seen} (GOBLIN_TRUST_PROXY=loopback). Before upgrading: add proxy_set_header X-Forwarded-Proto $scheme; to Orbit's nginx location, reload nginx, open Orbit through nginx once, then run this installer again.${
    seen.startsWith('not recorded')
      ? ` Orbit ${version} forgets what it saw each time it starts (a reboot, or a backup that stops and starts it): open Orbit through nginx after its last start.`
      : ''
  } ${preflightTail}`;
// A stopped 1.4.3 removes its record (a crash leaves one that no longer changes): browsing
// through nginx cannot help until it runs again.
const preflightStopped = version =>
  `Uptime Goblin 1.5 signs browsers in with a cookie and must know whether the browser uses HTTPS. Orbit ${version} is not running, and it clears its record of what your reverse proxy sends when it stops (GOBLIN_TRUST_PROXY=loopback). Before upgrading: start it (sudo systemctl start uptime-goblin), open Orbit through nginx once, then run this installer again without stopping Orbit. ${preflightTail}`;
// 1.4.2 and earlier keep no record: browsing and running the installer again can never pass.
const preflightBefore143 = version =>
  `Uptime Goblin 1.5 signs browsers in with a cookie and must know whether the browser uses HTTPS. The running Orbit ${version} does not record what your reverse proxy sends; only 1.4.3 and later do (GOBLIN_TRUST_PROXY=loopback). Before upgrading: upgrade to 1.4.3 first, open Orbit through nginx once, then run this installer again; or make sure Orbit's nginx location has proxy_set_header X-Forwarded-Proto $scheme; and run this installer again with --proxy-proto-checked. ${preflightTail}`;

// What a refused install must leave exactly as it was.
function hostState(host) {
  const hashes = directory =>
    Object.fromEntries(
      tree(directory).map(file => [
        file,
        createHash('sha256')
          .update(fs.readFileSync(path.join(directory, file)))
          .digest('hex'),
      ])
    );
  return {
    env: fs.readFileSync(host.path('etc/uptime-goblin.env'), 'utf8'),
    app: hashes(host.path('opt/uptime-goblin')),
    unit: fs.readFileSync(host.path('etc/systemd/system/uptime-goblin.service'), 'utf8'),
    // Every systemctl call that could change something (the preflights ask is-active, and which
    // drop-ins and environment systemd gives Uptime Goblin: show, show-environment).
    calls: host
      .calls()
      .split('\n')
      .filter(line => !/^(is-active|show|show-environment)( |$)/.test(line))
      .join('\n'),
    service: host.state(),
    previous: fs.existsSync(host.path('opt/uptime-goblin.previous')),
  };
}

// Rewrites run/status.json as the running 1.4.x would after seeing (or not seeing) the proxy.
function observe(host, change) {
  const file = host.path('var/lib/uptime-goblin/run/status.json');
  const status = JSON.parse(fs.readFileSync(file, 'utf8'));
  fs.writeFileSync(file, JSON.stringify(change(status)));
}

test('the upgrade from 1.4.x behind a proxy is refused, changing nothing, until 1.4.x saw X-Forwarded-Proto: https', async t => {
  const host = await makeHost(t);
  const legacy = await host.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }), [
    '--trust-proxy',
    'loopback',
  ]);
  assert.equal(legacy.status, 0, ok(legacy));
  assert.match(
    fs.readFileSync(host.path('etc/uptime-goblin.env'), 'utf8'),
    /^GOBLIN_TRUST_PROXY=loopback$/m
  );
  const next = makeSource(t, { version: '1.5.0-test.1', mode: 'ok' });
  const refused = async (args, seen) => {
    const before = hostState(host);
    const result = await host.install(next, args);
    assert.equal(result.status, 1, ok(result));
    assert.equal(result.stderr.trim(), preflightText('1.4.3-test.1', seen));
    assert.doesNotMatch(result.stdout, /Preparing pinned application dependencies/);
    assert.deepEqual(hostState(host), before, 'nothing on the host changed');
    assert.equal(host.installedVersion(), '1.4.3-test.1');
    assert.equal(host.systemctl('is-active', 'uptime-goblin.service').status, 0, 'still serving');
  };
  const notRecorded = 'not recorded what your reverse proxy sends';
  // The fake 1.4.3 recorded nothing (null): nobody browsed through the proxy yet.
  assert.equal(host.status().observed.forwardedProto, null);
  await refused([], notRecorded);
  // --trust-proxy given again on the command line is the same setting.
  await refused(['--trust-proxy', 'loopback'], notRecorded);
  // The proxy sends http (or X-Forwarded-For without a protocol).
  observe(host, status => ({ ...status, observed: { forwardedProto: 'http' } }));
  await refused([], 'recorded X-Forwarded-Proto: http');
  // A record of another release (an older process's file) proves nothing.
  observe(host, status => ({ ...status, version: '1.4.2', observed: { forwardedProto: 'https' } }));
  await refused([], notRecorded);
  // A missing or unreadable status file.
  const statusFile = host.path('var/lib/uptime-goblin/run/status.json');
  const saved = fs.readFileSync(statusFile, 'utf8');
  fs.writeFileSync(statusFile, '{not json');
  await refused([], notRecorded);
  fs.rmSync(statusFile);
  await refused([], notRecorded);
  fs.writeFileSync(statusFile, saved);

  // Stopped (a habit before upgrading, or a backup that stops Uptime Goblin and installs before starting
  // it): 1.4.3 removed its record, so the message is not about nginx. A record a crash left
  // (it names a process that is gone) is no different.
  assert.equal(host.systemctl('stop', 'uptime-goblin.service').status, 0);
  assert.equal(host.status(), null, '1.4.3 removes its record when it stops');
  for (const left of [null, { version: '1.4.3-test.1', pid: 2 ** 22 + 17, observed: {} }]) {
    if (left) fs.writeFileSync(statusFile, JSON.stringify(left));
    const before = hostState(host);
    const result = await host.install(next);
    assert.equal(result.status, 1, ok(result));
    assert.equal(result.stderr.trim(), preflightStopped('1.4.3-test.1'));
    assert.deepEqual(hostState(host), before, 'nothing on the host changed');
    assert.notEqual(
      host.systemctl('is-active', 'uptime-goblin.service').status,
      0,
      'still stopped'
    );
  }
  // Started again, it records afresh: what nginx sends is the question again.
  fs.rmSync(statusFile);
  assert.equal(host.systemctl('start', 'uptime-goblin.service').status, 0);
  for (let i = 0; i < 100 && !host.status(); i++) await delay(50);
  assert.equal(host.status().observed.forwardedProto, null);
  await refused([], notRecorded);

  // https recorded by the installed release: the upgrade proceeds.
  observe(host, status => ({
    ...status,
    version: '1.4.3-test.1',
    observed: { forwardedProto: 'https' },
  }));
  const upgraded = await host.install(next);
  assert.equal(upgraded.status, 0, ok(upgraded));
  assert.equal(host.installedVersion(), '1.5.0-test.1');
  assert.match(
    upgraded.stdout,
    /Sign in as admin with the same password\. Reload Uptime Goblin tabs that were open before this upgrade once\./
  );
  assert.doesNotMatch(upgraded.stdout, /tabs opened before 1\.4\.3 need one manual reload/);
  // A later 1.5 upgrade skips the check: signing in already proves the proxy.
  const later = await host.install(makeSource(t, { version: '1.5.1-test.1', mode: 'ok' }));
  assert.equal(later.status, 0, ok(later));
  assert.equal(host.status().observed.forwardedProto, null);
  assert.doesNotMatch(later.stdout, /Sign in as admin with the same password/);
});

test('--trust-proxy off on the upgrade from 1.4.x behind a proxy names no proxy: the preflight lets it through', async t => {
  const host = await makeHost(t);
  const legacy = await host.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }), [
    '--trust-proxy',
    'loopback',
  ]);
  assert.equal(legacy.status, 0, ok(legacy));
  // The installer took "off" for a proxy named off, so the preflight asked what that proxy
  // sends and refused the upgrade that turns proxy trust off.
  const next = makeSource(t, { version: '1.5.0-test.1', mode: 'ok' });
  const upgraded = await host.install(next, ['--trust-proxy', 'off']);
  assert.equal(upgraded.status, 0, ok(upgraded));
  assert.doesNotMatch(upgraded.stderr, /reverse proxy sends/);
  assert.equal(host.installedVersion(), '1.5.0-test.1');
  assert.match(
    fs.readFileSync(host.path('etc/uptime-goblin.env'), 'utf8'),
    /^GOBLIN_TRUST_PROXY=$/m
  );
});

// systemd starts Uptime Goblin without the installer's environment, but node --env-file, with which the
// installer checks that Uptime Goblin serves, keeps a HOST or PORT already set over the file's. Run as
// root without sudo, with sudo -E or from a wrapper that exports them, those checks probed that
// address instead of Uptime Goblin's: a working upgrade was rolled back, and the restored release was
// reported "could not be verified" (one before 1.4.3: its legacy health check "did not pass", or
// "answered" when something there answered it). The installer now removes both from its
// environment before anything else.
test("HOST and PORT in the installer's own environment never reach its checks: after the start and after a rollback they probe the address systemd gives Uptime Goblin", async t => {
  const host = await makeHost(t);
  const legacy = await host.install(makeSource(t, { version: '1.4.2', mode: 'ok' }));
  assert.equal(legacy.status, 0, ok(legacy));
  // Nothing listens there: a check that probed it would fail.
  const elsewhere = { HOST: '::1', PORT: String(await freePort()) };
  // A failed upgrade from 1.4.2: the restored release's own (legacy) health check.
  const toLegacy = await host.install(
    makeSource(t, { version: '1.4.3-test.8', mode: 'crash' }),
    ['--verify-timeout', '3'],
    elsewhere
  );
  assert.equal(toLegacy.status, 1, ok(toLegacy));
  assert.match(
    toLegacy.stderr,
    /The previous code was restored and its legacy health check answered/
  );
  assert.doesNotMatch(toLegacy.stderr, /legacy health check did not pass/);
  assert.equal(host.installedVersion(), '1.4.2');
  // The check after the start.
  const upgraded = await host.install(
    makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }),
    ['--verify-timeout', '5'],
    elsewhere
  );
  assert.equal(upgraded.status, 0, ok(upgraded));
  assert.match(
    upgraded.stdout,
    /Uptime Goblin 1\.4\.3-test\.1 is running and will start automatically/
  );
  assert.equal(host.installedVersion(), '1.4.3-test.1');
  // The check after a rollback to a release with the process-nonce contract.
  const rolledBack = await host.install(
    makeSource(t, { version: '1.4.3-test.9', mode: 'crash' }),
    ['--verify-timeout', '3'],
    elsewhere
  );
  assert.equal(rolledBack.status, 1, ok(rolledBack));
  assert.match(rolledBack.stderr, /The previous version is running again/);
  assert.doesNotMatch(rolledBack.stderr, /could not be verified/);
  assert.equal(host.installedVersion(), '1.4.3-test.1');
  assert.equal(host.status().version, '1.4.3-test.1');
});

// systemd gives Uptime Goblin what /etc/uptime-goblin.env sets, but a drop-in can add an EnvironmentFile= read
// after it, set a name the file does not set (Environment=, PassEnvironment=, or systemd's own
// environment) or remove one (UnsetEnvironment=). The checks that Uptime Goblin serves read the file
// alone: with a drop-in whose EnvironmentFile= set PORT, the check after the start probed another
// port than Uptime Goblin's, a working upgrade was rolled back and the restored release was reported as
// "could not be verified". Now HOST and PORT are worked out as systemd gives them, and where they
// differ from the file, or cannot be told, the upgrade is refused before anything changes.
test('HOST and PORT that systemd takes from a drop-in or its own environment are compared with /etc/uptime-goblin.env before anything changes', async t => {
  const host = await makeHost(t);
  const first = await host.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }));
  assert.equal(first.status, 0, ok(first));
  const envFile = host.path('etc/uptime-goblin.env');
  const original = fs.readFileSync(envFile, 'utf8');
  const withoutPort = original.replace(`PORT=${host.port}\n`, '');
  const withoutHost = original.replace('HOST=127.0.0.1\n', '');
  assert.notEqual(withoutPort, original);
  assert.notEqual(withoutHost, original);
  const dropIns = host.path('etc/systemd/system/uptime-goblin.service.d');
  fs.mkdirSync(dropIns, { recursive: true });
  const dropIn = path.join(dropIns, 'port.conf');
  const where = '/etc/systemd/system/uptime-goblin.service.d/port.conf';
  const managerFile = path.join(host.env.FAKE_SYSTEMD_DIR, 'manager.env');
  const other = await freePort();
  fs.writeFileSync(host.path('etc/uptime-goblin/port.env'), `PORT=${other}\n`);
  fs.writeFileSync(host.path('etc/uptime-goblin/bad-port.env'), `PORT=0${other}\n`);
  // Files this installer does not read: larger than 1 MiB (the PORT on its last line), and a FIFO.
  // systemd reads them, also when a drop-in names them with "-": with
  // EnvironmentFile=-/etc/uptime-goblin/big.env a working upgrade was rolled back, and the restored
  // release "could not be verified", as with any drop-in that set PORT.
  fs.writeFileSync(
    host.path('etc/uptime-goblin/big.env'),
    `${'#'.repeat(1023)}\n`.repeat(1024) + `PORT=${other}\n`
  );
  assert.ok(fs.statSync(host.path('etc/uptime-goblin/big.env')).size > 2 ** 20);
  assert.equal(spawnSync('mkfifo', [host.path('etc/uptime-goblin/fifo.env')]).status, 0);
  const fix =
    'Set HOST and PORT in /etc/uptime-goblin.env alone (sudoedit /etc/uptime-goblin.env): no drop-in (sudo systemctl edit uptime-goblin), file that one names, or systemd environment (sudo systemctl unset-environment HOST PORT) should set, pass or remove them. Then run this installer again. Nothing was changed.';
  const differs = details =>
    `systemd would give Uptime Goblin another HOST or PORT than /etc/uptime-goblin.env gives, and this installer checks that Uptime Goblin serves, after it starts it (and after a rollback), at the HOST and PORT in /etc/uptime-goblin.env alone: ${details.join('; ')}. ${fix}`;
  const unchecked = why =>
    `HOST and PORT as systemd would give them to Uptime Goblin could not be checked: ${why}. This installer checks that Uptime Goblin serves, after it starts it (and after a rollback), at the HOST and PORT in /etc/uptime-goblin.env alone. ${fix}`;
  // The symptom: with this drop-in in effect Uptime Goblin serves on the other port.
  fs.writeFileSync(dropIn, '[Service]\nEnvironmentFile=/etc/uptime-goblin/port.env\n');
  assert.equal(host.systemctl('restart', 'uptime-goblin.service').status, 0);
  for (let i = 0; i < 100 && host.status()?.listen?.port !== other; i++) await delay(50);
  assert.equal(host.status().listen.port, other);
  const fileSetsPort = `PORT is "${other}" for systemd (EnvironmentFile=/etc/uptime-goblin/port.env in ${where}) and "${host.port}" in /etc/uptime-goblin.env`;
  for (const [conf, env, manager, message] of [
    // An EnvironmentFile= read after /etc/uptime-goblin.env.
    [
      '[Service]\nEnvironmentFile=/etc/uptime-goblin/port.env\n',
      original,
      '',
      differs([fileSetsPort]),
    ],
    // As systemd reads a unit file: CRLF line ends, a line continued past a comment, a key with
    // blanks around it; a comment and a [Unit] section do not count.
    [
      '[Service]\r\n# EnvironmentFile=/etc/uptime-goblin/bad-port.env\r\n  EnvironmentFile = \\\r\n; a comment\r\n/etc/uptime-goblin/port.env\r\n[Unit]\r\nEnvironmentFile=/etc/uptime-goblin/bad-port.env\r\n',
      original,
      '',
      differs([fileSetsPort]),
    ],
    // A line that is not UTF-8, or a section header without its ], ends the file there for
    // systemd: the EnvironmentFile=/etc/uptime-goblin.env after it does not count.
    [
      '[Service]\nEnvironmentFile=/etc/uptime-goblin/port.env\nX-Note=\xff\nEnvironmentFile=/etc/uptime-goblin.env\n',
      original,
      '',
      differs([fileSetsPort]),
    ],
    [
      '[Service]\nEnvironmentFile=/etc/uptime-goblin/port.env\n[Service\nEnvironmentFile=/etc/uptime-goblin.env\n',
      original,
      '',
      differs([fileSetsPort]),
    ],
    // A value this release refuses.
    [
      '[Service]\nEnvironmentFile=/etc/uptime-goblin/bad-port.env\n',
      original,
      '',
      differs([
        `PORT is "0${other}" for systemd (EnvironmentFile=/etc/uptime-goblin/bad-port.env in ${where}; this release refuses it) and "${host.port}" in /etc/uptime-goblin.env`,
      ]),
    ],
    // A name the file does not set: Environment= (with quotes and an escape) or systemd's own
    // environment.
    [
      `[Service]\nEnvironment="A=1 2" "PORT=\\x3${String(other)[0]}${String(other).slice(1)}"\n`,
      withoutPort,
      '',
      differs([
        `PORT is "${other}" for systemd (Environment= in ${where}) and unset in /etc/uptime-goblin.env`,
      ]),
    ],
    [
      '[Service]\nEnvironment=HOST=::1\n',
      withoutHost,
      '',
      differs([
        `HOST is "::1" for systemd (Environment= in ${where}) and unset in /etc/uptime-goblin.env`,
      ]),
    ],
    [
      '',
      withoutPort,
      `PORT=${other}\n`,
      differs([
        `PORT is "${other}" for systemd (systemd's own environment, as systemctl show-environment shows it) and unset in /etc/uptime-goblin.env`,
      ]),
    ],
    // Removed: UnsetEnvironment= with the name, or with the value systemd would pass.
    [
      '[Service]\nUnsetEnvironment=PORT\n',
      original,
      '',
      differs([
        `PORT is unset for systemd (UnsetEnvironment= in ${where}) and "${host.port}" in /etc/uptime-goblin.env`,
      ]),
    ],
    [
      `[Service]\nUnsetEnvironment=A PORT=${host.port}\n`,
      original,
      '',
      differs([
        `PORT is unset for systemd (UnsetEnvironment= in ${where}) and "${host.port}" in /etc/uptime-goblin.env`,
      ]),
    ],
    // An empty EnvironmentFile= drops /etc/uptime-goblin.env itself.
    [
      '[Service]\nEnvironmentFile=\nEnvironmentFile=-/etc/uptime-goblin/none.env\n',
      original,
      '',
      differs([
        `PORT is unset for systemd (set nowhere that systemd reads for Uptime Goblin) and "${host.port}" in /etc/uptime-goblin.env`,
      ]),
    ],
    // What this installer cannot tell.
    [
      '[Service]\nPassEnvironment=PORT\n',
      withoutPort,
      '',
      unchecked(
        `PassEnvironment= in ${where} passes PORT from the environment of systemd's own process, which this installer does not read`
      ),
    ],
    [
      '[Service]\nEnvironment=PORT=%i\n',
      withoutPort,
      '',
      unchecked(
        `Environment= in ${where} sets PORT with a specifier, which this installer does not expand`
      ),
    ],
    [
      '[Service]\nEnvironmentFile=/etc/uptime-goblin/%N.env\n',
      original,
      '',
      unchecked(
        `EnvironmentFile=/etc/uptime-goblin/%N.env in ${where} names its file with a specifier, which this installer does not expand`
      ),
    ],
    [
      '[Service]\nEnvironmentFile=-/etc/uptime-goblin/*.env\n',
      original,
      '',
      unchecked(
        `EnvironmentFile=-/etc/uptime-goblin/*.env in ${where} names its files by a pattern, which this installer does not expand`
      ),
    ],
    // A file systemd could not read stops Uptime Goblin's start altogether.
    [
      '[Service]\nEnvironmentFile=/etc/uptime-goblin/missing.env\n',
      original,
      '',
      `systemd would not start Uptime Goblin: EnvironmentFile=/etc/uptime-goblin/missing.env in ${where} names a file that cannot be read (ENOENT). Correct the drop-in (sudo systemctl edit uptime-goblin) or the file, then run this installer again. Nothing was changed.`,
    ],
    // A file this installer does not read cannot be told, named with "-" or without.
    ...['-', ''].flatMap(dash => [
      [
        `[Service]\nEnvironmentFile=${dash}/etc/uptime-goblin/big.env\n`,
        original,
        '',
        unchecked(
          `EnvironmentFile=${dash}/etc/uptime-goblin/big.env in ${where} names a file that is larger than 1 MiB, which this installer does not read`
        ),
      ],
      [
        `[Service]\nEnvironmentFile=${dash}/etc/uptime-goblin/fifo.env\n`,
        original,
        '',
        unchecked(
          `EnvironmentFile=${dash}/etc/uptime-goblin/fifo.env in ${where} names a file that is not a regular file, which this installer does not read`
        ),
      ],
    ]),
  ]) {
    fs.writeFileSync(envFile, env, { mode: 0o600 });
    // Each character one byte, so \xff is the byte 0xff.
    if (conf) fs.writeFileSync(dropIn, Buffer.from(conf, 'latin1'));
    else fs.rmSync(dropIn, { force: true });
    fs.writeFileSync(managerFile, manager);
    const before = hostState(host);
    // Bounded: without the check the upgrade waits for a verification that cannot pass.
    const result = await host.install(makeSource(t, { version: '1.4.3-test.2', mode: 'ok' }), [
      '--verify-timeout',
      '5',
    ]);
    assert.equal(result.status, 1, ok(result));
    assert.equal(result.stderr.trim(), message, JSON.stringify(conf));
    assert.deepEqual(hostState(host), before, 'nothing on the host changed');
    assert.equal(host.installedVersion(), '1.4.3-test.1');
  }
  fs.rmSync(host.path('etc/uptime-goblin/big.env'));
  fs.rmSync(host.path('etc/uptime-goblin/fifo.env'));
  // A drop-in written since systemd last read the unit files is not in the list it shows yet
  // (need-daemon-reload holds that list: none).
  fs.writeFileSync(envFile, original, { mode: 0o600 });
  fs.writeFileSync(managerFile, '');
  fs.writeFileSync(dropIn, '[Service]\nEnvironmentFile=/etc/uptime-goblin/port.env\n');
  const reload = path.join(host.env.FAKE_SYSTEMD_DIR, 'need-daemon-reload');
  fs.writeFileSync(reload, '');
  const stale = hostState(host);
  const unread = await host.install(makeSource(t, { version: '1.4.3-test.2', mode: 'ok' }));
  assert.equal(unread.status, 1, ok(unread));
  assert.equal(
    unread.stderr.trim(),
    'systemd has not read the drop-ins of uptime-goblin.service as they are now (NeedDaemonReload=yes): the files in its drop-in directories are not those it read last, which are the ones it lists. So this installer cannot tell which HOST and PORT systemd will give Uptime Goblin after the daemon-reload this installer runs. Run sudo systemctl daemon-reload, then run this installer again. Nothing was changed.'
  );
  assert.deepEqual(hostState(host), stale, 'nothing on the host changed');
  assert.equal(host.installedVersion(), '1.4.3-test.1');
  assert.equal(host.systemctl('daemon-reload').status, 0);
  // Where systemd gives Uptime Goblin what the file sets, the upgrade goes ahead: Environment= for a name
  // the file sets (EnvironmentFile= outranks it, also with a specifier), a missing file named
  // with "-", UnsetEnvironment= with another value, a file that sets the same PORT (also while
  // NeedDaemonReload=yes, for unit files changed elsewhere than in the drop-ins it lists).
  let version = 2;
  for (const [conf, read] of [
    [`[Service]\nEnvironment=PORT=${other} HOST=::1\n`, null],
    ['[Service]\nEnvironment=PORT=%i\nEnvironmentFile=-/etc/uptime-goblin/missing.env\n', null],
    [`[Service]\nUnsetEnvironment=PORT=${other}\n`, null],
    ['[Service]\nEnvironmentFile=/etc/uptime-goblin/same.env\n', where],
  ]) {
    fs.writeFileSync(host.path('etc/uptime-goblin/same.env'), `PORT=${host.port}\n`);
    fs.writeFileSync(dropIn, conf);
    if (read !== null) fs.writeFileSync(reload, read);
    const next = `1.4.3-test.${++version}`;
    const result = await host.install(makeSource(t, { version: next, mode: 'ok' }), [
      '--verify-timeout',
      '10',
    ]);
    assert.equal(result.status, 0, `${JSON.stringify(conf)}\n${ok(result)}`);
    assert.equal(host.installedVersion(), next);
    assert.equal(host.status().listen.port, host.port);
  }
});

// The drop-in reader emulates part of systemd's unit-file parser, and systemd 257 read six forms
// otherwise (round-4 verification of the boundary checkpoint, each run under real systemd 257.13
// with /proc/<pid>/environ read back): a NUL, which ends the line for systemd; a UTF-8 byte order
// mark at the start of a line other than the first, which systemd drops; LF then CR after a line
// that a backslash continues, one line end for systemd; a section header with a quote, a
// backslash or a control character, at which systemd stops reading the file; an
// EnvironmentFile= path with a .. component (systemd ignores it), or with a slash at its end
// (systemd reads the path without it); and PassEnvironment=P\ORT, which systemd reads as PORT.
// With each the preflight passed while systemd gave Uptime Goblin another PORT, so a working upgrade was
// rolled back and the restored release "could not be verified". A drop-in holding any of them is
// refused now, naming the drop-in and the form, before anything changes. (The fake systemctl
// gives Uptime Goblin what /etc/uptime-goblin.env sets, so without the refusal these upgrades went ahead here.)
// A form is refused as a whole, also an input of it that the reader read as systemd does
// (/etc/./x, /etc//x; LF CR LF after a continued line, where both end it with an empty line).
// Fixer round 1 of the boundary lane, under real systemd 257.13: systemd ignores an
// EnvironmentFile= value of 4096 bytes or more, its "-" included ("Failed to resolve unit
// specifiers"), and the length rule measured the path without its "-": with
// EnvironmentFile=-<a 4095-byte path>, the reader read that file and the preflight passed while
// systemd ignored the line and gave Uptime Goblin another PORT.
test('a drop-in holding a form this installer cannot verify that it reads as systemd does refuses the upgrade, naming the drop-in and the form, changing nothing', async t => {
  const host = await makeHost(t);
  const first = await host.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }));
  assert.equal(first.status, 0, ok(first));
  const dropIns = host.path('etc/systemd/system/uptime-goblin.service.d');
  fs.mkdirSync(dropIns, { recursive: true });
  const dropIn = path.join(dropIns, 'port.conf');
  const where = '/etc/systemd/system/uptime-goblin.service.d/port.conf';
  const other = await freePort();
  fs.writeFileSync(host.path('etc/uptime-goblin/port.env'), `PORT=${other}\n`);
  const unverifiable = form =>
    `HOST and PORT as systemd would give them to Uptime Goblin could not be checked: the drop-in ${where} holds ${form}, and this installer cannot verify that it reads that form as systemd does. Remove that from the drop-in (sudo systemctl edit uptime-goblin, or edit the file), then run this installer again. Nothing was changed.`;
  const header = 'a section header with a quote, a backslash or a control character in it';
  const notNormal =
    'an EnvironmentFile= path that is not in normal form (a . or .. component, two slashes in a row or a slash at its end) or is longer than systemd takes (a component of more than 255 bytes, or 4096 bytes or more, a leading - included)';
  // An absolute path in normal form, of `length` bytes, every component at most 255 bytes.
  const longPath = length => {
    let at = '/etc/uptime-goblin';
    while (at.length + 256 < length) at += `/${'a'.repeat(255)}`;
    const long = `${at}/${'p'.repeat(length - at.length - 1)}`;
    assert.ok(long.length === length && long.split('/').every(part => part.length <= 255));
    return long;
  };
  for (const [conf, form] of [
    // systemd 257 gave PORT=other with each of these; the reader found none.
    [`[Service]\nEnvironment=FOO=a\0Environment=PORT=${other}\n`, 'a NUL character'],
    [
      `[Service]\n\xef\xbb\xbfEnvironment=PORT=${other}\n`,
      'a UTF-8 byte order mark other than at its very start',
    ],
    [
      `[Service]\nEnvironment=FOO=1 \\\n\rPORT=${other}\n`,
      'a line feed followed by a carriage return after a line that a backslash continues',
    ],
    // ... also after a comment inside the continued line.
    [
      `[Service]\nEnvironment=FOO=1 \\\n# a comment\n\rPORT=${other}\n`,
      'a line feed followed by a carriage return after a line that a backslash continues',
    ],
    // systemd stops reading at the header: the EnvironmentFile=/etc/uptime-goblin.env after it, which
    // gives back the file's PORT, does not count.
    ...['"', "'", '\\', '\t', '\x01', '\x7f'].map(c => [
      `[Service]\nEnvironmentFile=/etc/uptime-goblin/port.env\n[Bad${c}H]\n[Service]\nEnvironmentFile=/etc/uptime-goblin.env\n`,
      header,
    ]),
    // systemd ignores a path with a .. component, so the one before counts.
    [
      '[Service]\nEnvironmentFile=/etc/uptime-goblin/port.env\nEnvironmentFile=/etc/../etc/uptime-goblin.env\n',
      notNormal,
    ],
    // systemd reads /etc/uptime-goblin/port.env/ as /etc/uptime-goblin/port.env (the reader found no such file
    // and, with "-", read nothing); /etc/./x and /etc//x it reads as /etc/x.
    ['[Service]\nEnvironmentFile=-/etc/uptime-goblin/port.env/\n', notNormal],
    ['[Service]\nEnvironmentFile=/etc/uptime-goblin/./port.env\n', notNormal],
    ['[Service]\nEnvironmentFile=/etc//orbit/port.env\n', notNormal],
    // systemd ignores a component of more than 255 bytes (the reader said it would not start).
    [`[Service]\nEnvironmentFile=/etc/uptime-goblin/${'a'.repeat(256)}\n`, notNormal],
    // systemd ignores a value of 4096 bytes or more: a path of 4096 bytes (the reader said it
    // would not start), and "-" with a path of 4095 bytes, whose file the reader read on a host
    // (here, under the test root, it cannot open that path and, with "-", went ahead).
    [`[Service]\nEnvironmentFile=${longPath(4096)}\n`, notNormal],
    [`[Service]\nEnvironmentFile=-${longPath(4095)}\n`, notNormal],
    // systemd unquotes PassEnvironment= without C escapes: P\ORT passes PORT.
    ['[Service]\nPassEnvironment=P\\ORT\n', 'a PassEnvironment= value with a backslash in it'],
  ]) {
    fs.writeFileSync(dropIn, Buffer.from(conf, 'latin1'));
    const before = hostState(host);
    const result = await host.install(makeSource(t, { version: '1.4.3-test.2', mode: 'ok' }), [
      '--verify-timeout',
      '5',
    ]);
    assert.equal(result.status, 1, `${JSON.stringify(conf)}\n${ok(result)}`);
    assert.equal(result.stderr.trim(), unverifiable(form), JSON.stringify(conf));
    assert.deepEqual(hostState(host), before, 'nothing on the host changed');
    assert.equal(host.installedVersion(), '1.4.3-test.1');
  }
  // Read as systemd 257 reads them, and so not refused: a byte order mark at the very start (a
  // first line starting with one is not a comment for systemd, so the backslash ending it
  // continues it into the next line, the [Service] header included, and the EnvironmentFile=
  // after it, whose specifier would refuse the upgrade, is outside any section; the reader took
  // that line for a comment); LF then CR, and CRLF line ends with an empty line, after a line
  // that a backslash does not continue or that the empty line ends; a section header with blanks
  // or bytes beyond ASCII; a relative EnvironmentFile= path, which systemd ignores; a backslash
  // in Environment=, an escape; an EnvironmentFile= value of 4095 bytes, "-" included, also one
  // written with %% that is 4095 bytes once %% is % (systemd 257 reads both; the files are
  // missing here, so with "-" nothing is read).
  let version = 2;
  for (const conf of [
    '\xef\xbb\xbf#c \\\n[Service]\nEnvironmentFile=-/etc/uptime-goblin/%N.env\n',
    `\xef\xbb\xbf[Service]\nEnvironment=FOO=1\n\rEnvironment=FOO=2\n`,
    `[Service]\r\nEnvironment=FOO=1 \\\r\n\r\nEnvironment=FOO=2\r\n`,
    '[Service]\n[X-Uptime Goblin Note \xc3\xa9]\nEnvironment=FOO=1\n',
    `[Service]\nEnvironmentFile=-etc/../orbit/port.env\nEnvironment=FOO=\\x41\n`,
    `[Service]\nEnvironmentFile=-${longPath(4094)}\n`,
    `[Service]\nEnvironmentFile=-${longPath(4093)}%%\n`,
  ]) {
    fs.writeFileSync(dropIn, Buffer.from(conf, 'latin1'));
    const next = `1.4.3-test.${++version}`;
    const result = await host.install(makeSource(t, { version: next, mode: 'ok' }), [
      '--verify-timeout',
      '10',
    ]);
    assert.equal(result.status, 0, `${JSON.stringify(conf)}\n${ok(result)}`);
    assert.equal(host.installedVersion(), next);
    assert.equal(host.status().listen.port, host.port);
  }
});

// systemd lists no drop-in for a unit it has not loaded (systemd 257: LoadState=not-found, an
// empty DropInPaths and NeedDaemonReload=no, also with a drop-in for it on disk), so on a first
// install the check read none. Once the installer had written the unit and run daemon-reload,
// a drop-in that set PORT applied: Uptime Goblin served on that port, the check after the start probed
// the PORT in /etc/uptime-goblin.env, and the install failed with nothing to restore (round-3 finding,
// reproduced under real systemd 257). The drop-ins on disk are read then, as systemd will find
// them: uptime-goblin.service.d, then service.d, each in the order of its search path; of names ending
// in .conf, none hidden, the first of each; sorted by name.
test('a first install reads the drop-ins on disk, which systemd lists for no unit it has not loaded: one that gives another HOST or PORT refuses it, changing nothing', async t => {
  const fix =
    'Set HOST and PORT in /etc/uptime-goblin.env alone (sudoedit /etc/uptime-goblin.env): no drop-in (sudo systemctl edit uptime-goblin), file that one names, or systemd environment (sudo systemctl unset-environment HOST PORT) should set, pass or remove them. Then run this installer again. Nothing was changed.';
  const differs = detail =>
    `systemd would give Uptime Goblin another HOST or PORT than /etc/uptime-goblin.env gives, and this installer checks that Uptime Goblin serves, after it starts it (and after a rollback), at the HOST and PORT in /etc/uptime-goblin.env alone: ${detail}. ${fix}`;
  const source = makeSource(t, { version: '1.5.0-test.1', mode: 'ok' });
  const other = await freePort();
  const write = (host, file, text) => {
    fs.mkdirSync(path.dirname(host.path(file)), { recursive: true });
    fs.writeFileSync(host.path(file), text);
  };
  // Every file of the host, with its content, and every systemctl call that could change
  // something (show, show-environment and is-active only read). The installer's lock file in
  // /run, empty and held only while a run lasts, is no change.
  const everything = host => ({
    files: Object.fromEntries(
      tree(
        host.root,
        new Set(['node_modules', 'run/uptime-goblin-install.lock', 'run/orbit-install.lock'])
      ).map(file => [
        file,
        createHash('sha256')
          .update(fs.readFileSync(host.path(file)))
          .digest('hex'),
      ])
    ),
    calls: host
      .calls()
      .split('\n')
      .filter(line => !/^(is-active|show|show-environment)( |$)/.test(line))
      .join('\n'),
    service: host.state(),
  });
  // A drop-in that adds an EnvironmentFile= setting another PORT, and one that drops every
  // EnvironmentFile= before it but /etc/uptime-goblin.env. (PORT=4317 is Uptime Goblin's default, so on a first
  // install only another value differs: UnsetEnvironment=PORT would not.)
  const port = '[Service]\nEnvironmentFile=/etc/orbit-port.env\n';
  const reset = '[Service]\nEnvironmentFile=\nEnvironmentFile=/etc/uptime-goblin.env\n';
  const sets = where =>
    differs(
      `PORT is "${other}" for systemd (EnvironmentFile=/etc/orbit-port.env in ${where}) and "4317" in /etc/uptime-goblin.env`
    );
  for (const [files, message] of [
    // The case of the finding: a drop-in of uptime-goblin.service in /etc.
    [
      { 'etc/systemd/system/uptime-goblin.service.d/port.conf': port },
      sets('/etc/systemd/system/uptime-goblin.service.d/port.conf'),
    ],
    // service.d applies to every service, also in /run.
    [
      { 'run/systemd/system/service.d/port.conf': port },
      sets('/run/systemd/system/service.d/port.conf'),
    ],
    // In the order of their names, whatever their directory: 10-reset.conf, then 20-port.conf.
    [
      {
        'usr/lib/systemd/system/uptime-goblin.service.d/10-reset.conf': reset,
        'etc/systemd/system/service.d/20-port.conf': port,
      },
      sets('/etc/systemd/system/service.d/20-port.conf'),
    ],
    // Of two files with the same name, the one in /run outranks the one in /usr/lib, and one in
    // uptime-goblin.service.d (even in /usr/lib) one in service.d (even in /etc).
    [
      {
        'run/systemd/system/uptime-goblin.service.d/port.conf': port,
        'usr/lib/systemd/system/uptime-goblin.service.d/port.conf': '[Service]\n',
      },
      sets('/run/systemd/system/uptime-goblin.service.d/port.conf'),
    ],
    [
      {
        'usr/lib/systemd/system/uptime-goblin.service.d/port.conf': port,
        'etc/systemd/system/service.d/port.conf': '[Service]\n',
      },
      sets('/usr/lib/systemd/system/uptime-goblin.service.d/port.conf'),
    ],
    // systemd 257 lists a directory named .conf among the drop-ins too; it is read as one.
    [
      { 'run/systemd/system/uptime-goblin.service.d/directory.conf/': '' },
      `HOST and PORT as systemd would give them to Uptime Goblin could not be checked: the drop-in /run/systemd/system/uptime-goblin.service.d/directory.conf cannot be read (not a regular file). This installer checks that Uptime Goblin serves, after it starts it (and after a rollback), at the HOST and PORT in /etc/uptime-goblin.env alone. ${fix}`,
    ],
  ]) {
    const host = await makeFreshHost(t);
    write(host, 'etc/orbit-port.env', `PORT=${other}\n`);
    for (const [file, text] of Object.entries(files))
      if (file.endsWith('/')) fs.mkdirSync(host.path(file), { recursive: true });
      else write(host, file, text);
    assert.match(
      host.systemctl('show', 'uptime-goblin.service', '--property=LoadState,DropInPaths').stdout,
      /^LoadState=not-found\nDropInPaths=\n$/
    );
    const before = everything(host);
    const result = await host.install(source, ['--verify-timeout', '5']);
    assert.equal(result.status, 1, ok(result));
    assert.equal(result.stderr.trim(), message, JSON.stringify(files));
    assert.deepEqual(everything(host), before, 'nothing on the host changed');
  }
  // The same files with the other names, or in the other places, give Uptime Goblin the PORT in
  // /etc/uptime-goblin.env, and the install goes ahead: 10-port.conf, then 20-reset.conf; the file in /run
  // empty; and hidden names, which systemd skips (a directory among them: read, it would refuse
  // the install, as the directory above does). (Under systemd 257, Debian 13, the drop-ins
  // these rules give for a layout of such files, a directory named .conf among them, were the
  // DropInPaths systemd showed once the unit was loaded.)
  const host = await makeFreshHost(t);
  write(host, 'etc/orbit-port.env', `PORT=${other}\n`);
  for (const [file, text] of Object.entries({
    'etc/systemd/system/service.d/10-port.conf': port,
    'usr/lib/systemd/system/uptime-goblin.service.d/20-reset.conf': reset,
    'run/systemd/system/uptime-goblin.service.d/port.conf': '[Service]\n',
    'usr/lib/systemd/system/uptime-goblin.service.d/port.conf': port,
    'run/systemd/system/uptime-goblin.service.d/.port.conf': port,
  }))
    write(host, file, text);
  fs.mkdirSync(host.path('run/systemd/system/uptime-goblin.service.d/.hidden.conf'));
  const result = await host.install(source, ['--verify-timeout', '10']);
  assert.equal(result.status, 0, ok(result));
  assert.ok(host.wroteDefaultPort(), 'the installer wrote PORT=4317');
  assert.equal(host.installedVersion(), '1.5.0-test.1');
  assert.equal(host.status().listen.port, host.port);
});

// 1.4.3 read PORT with Number(), so PORT=04317 served on 4317; 1.5 refuses it (exit 78). The
// upgrade went ahead, 1.5 refused to start, and the rollback to the 1.4.3 that then served was
// reported as "could not be verified": the verifier is the new release's healthcheck, which
// reads PORT by the same rule. Now HOST and PORT, as systemd passes them (the last assignment;
// the next test has how the file is read), are checked by this release's rules before anything
// changes.
// The check read the file as lines ending in LF, with JavaScript's blanks: a line ending in CRLF
// set nothing, and PORT=04317 there passed it with the same result (round 3); a PORT ending in a
// vertical tab or a no-break space was read without it, which systemd passes and 1.5 refuses.
// And where node --env-file, which the check after the start reads the file with, reads HOST or
// PORT otherwise than systemd (`export PORT=…`, which systemd ignores; a CR alone, which ends a
// line for systemd only), that check would probe another port: refused too.
test('a HOST or PORT in /etc/uptime-goblin.env that this release refuses (PORT=04317, which 1.4.3 read as 4317) refuses the upgrade before anything changes', async t => {
  const host = await makeHost(t);
  const legacy = await host.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }));
  assert.equal(legacy.status, 0, ok(legacy));
  const next = makeSource(t, { version: '1.5.0-test.1', mode: 'ok' });
  const envFile = host.path('etc/uptime-goblin.env');
  const original = fs.readFileSync(envFile, 'utf8');
  const leading = `0${host.port}`;
  const portProblem = `PORT must be a whole number from 1 to 65535, written in digits without a leading zero; it is "${leading}".`;
  const hostProblem =
    'HOST must be an IP address or a host name, without spaces, brackets or a port (such as 127.0.0.1, 0.0.0.0 or ::1); it is "[::1]".';
  const refusal = problems =>
    `This release of Uptime Goblin would refuse to start with /etc/uptime-goblin.env (exit status 78): ${problems.join(' ')} Correct ${problems.length > 1 ? 'them' : 'it'} in /etc/uptime-goblin.env (sudoedit /etc/uptime-goblin.env), then run this installer again. Nothing was changed.`;
  const withPort = (text, value) => text.replace(`PORT=${host.port}\n`, `PORT=${value}\n`);
  const portIs = shown =>
    `PORT must be a whole number from 1 to 65535, written in digits without a leading zero; it is ${shown}.`;
  const differs = details =>
    `systemd, which starts Uptime Goblin, and node --env-file, with which this installer checks that Uptime Goblin serves after it starts it (and after a rollback), read /etc/uptime-goblin.env differently: ${details.join('; ')}. Correct the file (sudoedit /etc/uptime-goblin.env): end each line with a line feed (a carriage return alone ends a line for systemd, not for Node), write no export before a name, and write HOST and PORT without quotes or backslashes. Then run this installer again. Nothing was changed.`;
  for (const [text, message] of [
    [withPort(original, leading), refusal([portProblem])],
    // systemd passes the last assignment, and strips blanks around = and one pair of quotes.
    [`${original}PORT = "${leading}"\n`, refusal([portProblem])],
    [original.replace('HOST=127.0.0.1\n', 'HOST=[::1]\n'), refusal([hostProblem])],
    [
      withPort(original.replace('HOST=127.0.0.1\n', 'HOST=[::1]\n'), leading),
      refusal([hostProblem, portProblem]),
    ],
    // systemd ends a line at CRLF, and at a CR alone (the later PORT is the one it passes).
    [withPort(original, leading).replaceAll('\n', '\r\n'), refusal([portProblem])],
    [withPort(original, `${host.port}\rPORT=${leading}`), refusal([portProblem])],
    // Its blanks are spaces and tabs: it passes a vertical tab or a no-break space at the end.
    [withPort(original, `${host.port}\v`), refusal([portIs(`"${host.port}\\u000b"`)])],
    [withPort(original, `${host.port} `), refusal([portIs(`"${host.port} "`)])],
    // Read otherwise by node --env-file: `export PORT=…`, which systemd ignores, and a CR alone,
    // which Node drops, so that HOST runs on into the PORT line.
    [
      `${original}export PORT=${leading}\n`,
      differs([`PORT is "${host.port}" for systemd and "${leading}" for node --env-file`]),
    ],
    [
      original.replace('HOST=127.0.0.1\n', 'HOST=127.0.0.1\r'),
      differs([
        `HOST is "127.0.0.1" for systemd and "127.0.0.1PORT=${host.port}" for node --env-file`,
        `PORT is "${host.port}" for systemd and unset for node --env-file`,
      ]),
    ],
  ]) {
    fs.writeFileSync(envFile, text);
    const before = hostState(host);
    // Bounded: without the check the upgrade waits for a verification that cannot pass.
    const result = await host.install(next, ['--verify-timeout', '5']);
    assert.equal(result.status, 1, ok(result));
    assert.equal(result.stderr.trim(), message, JSON.stringify(text));
    assert.deepEqual(hostState(host), before, 'nothing on the host changed');
    assert.equal(host.installedVersion(), '1.4.3-test.1');
  }
  // An /etc/uptime-goblin.env that cannot be read is refused too, never taken for one without HOST/PORT.
  fs.rmSync(envFile);
  fs.mkdirSync(envFile);
  const calls = host.calls();
  const unreadable = await host.install(next, ['--verify-timeout', '5']);
  assert.equal(unreadable.status, 1, ok(unreadable));
  assert.equal(
    unreadable.stderr.trim(),
    '/etc/uptime-goblin.env cannot be read (EISDIR). Nothing was changed.'
  );
  assert.equal(host.calls(), calls, 'systemctl was not called');
  assert.equal(host.installedVersion(), '1.4.3-test.1');
  fs.rmdirSync(envFile);
  // An earlier assignment that a later one overrides is not what Uptime Goblin gets: the upgrade proceeds.
  fs.writeFileSync(envFile, `PORT=${leading}\n${original}`, { mode: 0o600 });
  const upgraded = await host.install(next);
  assert.equal(upgraded.status, 0, ok(upgraded));
  assert.equal(host.installedVersion(), '1.5.0-test.1');
  // The same file with CRLF line ends: systemd and node --env-file read it alike, so the upgrade
  // proceeds, and the key step sees its GOBLIN_SECRET_KEY_FILE line (it appended another one,
  // and would have generated a key had /etc/uptime-goblin/secret.key not been there).
  const crlf = `PORT=${leading}\n${original}`.replaceAll('\n', '\r\n');
  assert.match(crlf, /^GOBLIN_SECRET_KEY_FILE=\/etc\/uptime-goblin\/secret\.key\r$/m);
  fs.writeFileSync(envFile, crlf, { mode: 0o600 });
  const again = await host.install(makeSource(t, { version: '1.5.0-test.2', mode: 'ok' }));
  assert.equal(again.status, 0, ok(again));
  assert.equal(host.installedVersion(), '1.5.0-test.2');
  assert.equal(fs.readFileSync(envFile, 'utf8'), crlf);
});

// The checks above read /etc/uptime-goblin.env one line at a time, but systemd reads a value on into the
// next line after a quote that is still open or a backslash at the end of a line (systemd before
// 254 also a comment line ending in a backslash), takes a backslash outside quotes as an escape
// and reads quotes around any part of a value ("51"848 is 51848). So with an open quote or a
// final backslash, the check (as node --env-file does) took a later line for PORT where systemd
// passes an earlier one: the upgrade went ahead, and its verifier would probe a port Uptime Goblin does
// not listen on. A quote closed on a later line was refused naming a PORT "for systemd" that
// systemd never reads, and `PORT=\…` or a partly quoted PORT, which systemd passes as a valid
// port, was refused as one this release would refuse to start with. The steps that rewrite the
// file line by line also changed a line inside such a value (--trust-proxy below). Now the file
// is read with systemd's own parser; a file whose setting or comment runs on into the next line
// is refused, and so is one systemd would not read at all (a NUL, or a name or value that is not
// UTF-8: systemd then does not start Uptime Goblin), all before anything changes.
test("/etc/uptime-goblin.env is read with systemd's own parser: a setting or comment that runs on into the next line, or a file systemd would not read, refuses the upgrade before anything changes", async t => {
  const host = await makeHost(t);
  const legacy = await host.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }));
  assert.equal(legacy.status, 0, ok(legacy));
  const next = makeSource(t, { version: '1.5.0-test.1', mode: 'ok' });
  const envFile = host.path('etc/uptime-goblin.env');
  const original = fs.readFileSync(envFile, 'utf8');
  assert.ok(original.endsWith('\n'));
  // The line after the original's last one, as an editor counts lines.
  const after = original.split('\n').length;
  const other = String(host.port + 1);
  const joined = where =>
    `/etc/uptime-goblin.env continues a setting or a comment onto the next line: ${where}. This installer rewrites the file line by line, and node --env-file, with which it checks that Uptime Goblin serves after it starts it, reads such lines otherwise than systemd. Put each setting on a line of its own (sudoedit /etc/uptime-goblin.env): close each quote on the line that opens it, and end no line, a comment included, with a backslash. Then run this installer again. Nothing was changed.`;
  const unread = what =>
    `systemd would not read /etc/uptime-goblin.env, and so would not start Uptime Goblin: the file holds ${what}. Correct it (sudoedit /etc/uptime-goblin.env), then run this installer again. Nothing was changed.`;
  const differs = details =>
    `systemd, which starts Uptime Goblin, and node --env-file, with which this installer checks that Uptime Goblin serves after it starts it (and after a rollback), read /etc/uptime-goblin.env differently: ${details}. Correct the file (sudoedit /etc/uptime-goblin.env): end each line with a line feed (a carriage return alone ends a line for systemd, not for Node), write no export before a name, and write HOST and PORT without quotes or backslashes. Then run this installer again. Nothing was changed.`;
  const port = String(host.port);
  for (const [text, message] of [
    // systemd: PORT stays the original, X takes the rest of the file. The check read PORT=other,
    // as node --env-file does, and let the upgrade through.
    [
      `${original}X="abc\nPORT=${other}\n`,
      joined(`a quote still open at the end of lines ${after}, ${after + 1}`),
    ],
    // systemd: X=abcPORT=other, PORT the original. Let through the same way.
    [`${original}X=abc\\\nPORT=${other}\n`, joined(`a backslash at the end of line ${after}`)],
    // systemd and Node: PORT the original, X holds the PORT line. The check refused it with
    // `PORT is "<other>" for systemd`.
    [
      `${original}X="\nPORT=${other}\n"\n`,
      joined(`a quote still open at the end of lines ${after}, ${after + 1}`),
    ],
    // systemd before 254 takes the next line into the comment; 257 reads it.
    [
      `${original}# old port \\\nPORT=${other}\n`,
      joined(
        `a comment that ends in a backslash on line ${after}, which systemd before version 254 continues`
      ),
    ],
    // Open at the end of a file without a final line end: a line added after it would join it.
    [`${original}X='abc`, joined(`a quote still open at the end of line ${after}`)],
    [
      `${original}A="a\nb"\nB=b\\\nc\n#c\\\nD=d\n`,
      joined(
        `a quote still open at the end of line ${after}; a backslash at the end of line ${after + 2}; a comment that ends in a backslash on line ${after + 4}, which systemd before version 254 continues`
      ),
    ],
    // CRLF is one line end for an editor; systemd ends the line at the CR and skips the LF.
    [`${original}X=abc\\\r\nPORT=${other}\r\n`, joined(`a backslash at the end of line ${after}`)],
    // systemd refuses the whole file (the unit then fails to start, the rollback's too).
    [Buffer.from(`${original}X=a\0b\n`), unread(`a NUL character (line ${after})`)],
    [
      Buffer.concat([Buffer.from(`${original}X=caf`), Buffer.from([0xe9, 0x0a])]),
      unread(`a name or a value that is not valid UTF-8 (line ${after})`),
    ],
    [
      `${original}X=\uffff\nY=\ufdd0\n`,
      unread(`a name or a value that is not valid UTF-8 (lines ${after}, ${after + 1})`),
    ],
    // A backslash outside quotes takes the next character as it is, and quotes may close mid-value:
    // systemd passes the original PORT both times, which Node reads otherwise.
    [
      original.replace(`PORT=${port}\n`, `PORT=\\${port}\n`),
      differs(`PORT is "${port}" for systemd and "\\\\${port}" for node --env-file`),
    ],
    [
      original.replace(`PORT=${port}\n`, `PORT="${port.slice(0, 2)}"${port.slice(2)}\n`),
      differs(`PORT is "${port}" for systemd and "${port.slice(0, 2)}" for node --env-file`),
    ],
  ]) {
    fs.writeFileSync(envFile, text);
    const bytes = fs.readFileSync(envFile);
    const before = hostState(host);
    const result = await host.install(next, ['--verify-timeout', '5']);
    assert.equal(result.status, 1, ok(result));
    assert.equal(result.stderr.trim(), message, JSON.stringify(String(text)));
    assert.deepEqual(hostState(host), before, 'nothing on the host changed');
    assert.ok(fs.readFileSync(envFile).equals(bytes), '/etc/uptime-goblin.env is unchanged');
    assert.equal(host.installedVersion(), '1.4.3-test.1');
  }
  // A comment systemd does not check (a Latin-1 é) and a value quoted and escaped on its own
  // line read alike for both: the upgrade proceeds.
  fs.writeFileSync(
    envFile,
    Buffer.concat([
      Buffer.from(original),
      Buffer.from('# caf'),
      Buffer.from([0xe9, 0x0a]),
      Buffer.from('X="a \\"b\\" c"\n'),
    ]),
    { mode: 0o600 }
  );
  const upgraded = await host.install(next);
  assert.equal(upgraded.status, 0, ok(upgraded));
  assert.equal(host.installedVersion(), '1.5.0-test.1');

  // A step that rewrites the file (--trust-proxy here) changed the line inside the quote: X then
  // held GOBLIN_TRUST_PROXY=loopback, and systemd passed no GOBLIN_TRUST_PROXY at all.
  const quotedLine = `${original}X="\nGOBLIN_TRUST_PROXY=10.0.0.1\n"\n`;
  fs.writeFileSync(envFile, quotedLine, { mode: 0o600 });
  const before = hostState(host);
  const rewrite = await host.install(makeSource(t, { version: '1.5.0-test.2', mode: 'ok' }), [
    '--trust-proxy',
    'loopback',
  ]);
  assert.equal(rewrite.status, 1, ok(rewrite));
  assert.equal(
    rewrite.stderr.trim(),
    joined(`a quote still open at the end of lines ${after}, ${after + 1}`)
  );
  assert.deepEqual(hostState(host), before, 'nothing on the host changed');
  assert.equal(fs.readFileSync(envFile, 'utf8'), quotedLine);
  assert.equal(host.installedVersion(), '1.5.0-test.1');
});

// run/status.json is the uptime-goblin account's too: the preflight reads it as root, so only as a
// regular file. A link (even to a record of https) or a FIFO (which held the installer) is no
// record.
test('the proxy preflight reads run/status.json only as a regular file: a link (of it or of run/), even to an https record, or a FIFO is no record', async t => {
  const host = await makeHost(t);
  const legacy = await host.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }), [
    '--trust-proxy',
    'loopback',
  ]);
  assert.equal(legacy.status, 0, ok(legacy));
  const next = makeSource(t, { version: '1.5.0-test.1', mode: 'ok' });
  const statusFile = host.path('var/lib/uptime-goblin/run/status.json');
  const recorded = JSON.stringify({
    ...JSON.parse(fs.readFileSync(statusFile, 'utf8')),
    observed: { forwardedProto: 'https' },
  });
  const refused = async () => {
    const before = hostState(host);
    const result = await host.install(next, [], {}, { timeout: 30000 });
    assert.equal(result.status, 1, ok(result));
    assert.equal(
      result.stderr.trim(),
      preflightText('1.4.3-test.1', 'not recorded what your reverse proxy sends')
    );
    assert.deepEqual(hostState(host), before, 'nothing on the host changed');
    assert.equal(host.installedVersion(), '1.4.3-test.1');
  };
  const elsewhere = path.join(host.base, 'status.json');
  fs.writeFileSync(elsewhere, recorded);
  fs.rmSync(statusFile);
  fs.symlinkSync(elsewhere, statusFile);
  await refused();
  fs.rmSync(statusFile);
  assert.equal(spawnSync('mkfifo', [statusFile]).status, 0);
  await refused();
  // A linked run/ is no record either: its status.json could be any file root can read.
  const run = path.dirname(statusFile),
    linkedRun = path.join(host.base, 'linked-run');
  fs.mkdirSync(linkedRun);
  fs.writeFileSync(path.join(linkedRun, 'status.json'), recorded);
  fs.renameSync(run, `${run}.kept`);
  fs.symlinkSync(linkedRun, run);
  await refused();
  fs.rmSync(run);
  fs.renameSync(`${run}.kept`, run);
  // The same record as the regular file 1.4.3 writes: the upgrade proceeds.
  fs.rmSync(statusFile);
  fs.writeFileSync(statusFile, recorded, { mode: 0o600 });
  const upgraded = await host.install(next);
  assert.equal(upgraded.status, 0, ok(upgraded));
  assert.equal(host.installedVersion(), '1.5.0-test.1');
});

test('the proxy preflight: an install of 1.4.2, which keeps no record, is told to go to 1.4.3 first or check by hand', async t => {
  const host = await makeHost(t);
  const legacy = await host.install(makeSource(t, { version: '1.4.2', mode: 'ok' }), [
    '--trust-proxy',
    'loopback',
  ]);
  assert.equal(legacy.status, 0, ok(legacy));
  // 1.4.2 writes no run/status.json (only 1.4.3 does).
  fs.rmSync(host.path('var/lib/uptime-goblin/run/status.json'), { force: true });
  const next = makeSource(t, { version: '1.5.0-test.1', mode: 'ok' });
  for (let i = 0; i < 2; i++) {
    const before = hostState(host);
    const refused = await host.install(next);
    assert.equal(refused.status, 1, ok(refused));
    assert.equal(refused.stderr.trim(), preflightBefore143('1.4.2'));
    assert.deepEqual(hostState(host), before, 'nothing on the host changed');
  }
  // Even a record naming 1.4.2 (left by something else) cannot help, but the ways out work:
  // 1.4.3 first (which records the proxy), or the owner's own check.
  const via143 = await host.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }));
  assert.equal(via143.status, 0, ok(via143));
  observe(host, status => ({ ...status, observed: { forwardedProto: 'https' } }));
  const upgraded = await host.install(next);
  assert.equal(upgraded.status, 0, ok(upgraded));
  assert.equal(host.installedVersion(), '1.5.0-test.1');
  const checked = await makeHost(t);
  assert.equal(
    (
      await checked.install(makeSource(t, { version: '1.4.2', mode: 'ok' }), [
        '--trust-proxy',
        'loopback',
      ])
    ).status,
    0
  );
  const byHand = await checked.install(next, ['--proxy-proto-checked']);
  assert.equal(byHand.status, 0, ok(byHand));
});

test('the proxy preflight: --proxy-proto-checked, GOBLIN_INSECURE_HTTP_SESSIONS=1, --allow-insecure-http and a staged 1.4.x skip it', async t => {
  const host = await makeHost(t);
  const install = async (version, args = []) => {
    const result = await host.install(makeSource(t, { version, mode: 'ok' }), args);
    assert.equal(result.status, 0, ok(result));
    assert.equal(host.installedVersion(), version);
    return result;
  };
  await install('1.4.3-test.1', ['--trust-proxy', 'loopback']);
  // A staged release below 1.5.0 needs no proof: it still signs in with Basic.
  await install('1.4.3-test.2');
  // The owner checked the proxy by hand.
  await install('1.5.0-test.1', ['--proxy-proto-checked']);
  // Back to 1.4.x (a later 1.5 → 1.4 install is never checked; an older release takes
  // --allow-downgrade), then the opt-in on a trusted network: plain-HTTP sign-in does not need the
  // proxy's protocol.
  await install('1.4.3-test.3', ['--allow-downgrade']);
  fs.appendFileSync(host.path('etc/uptime-goblin.env'), 'GOBLIN_INSECURE_HTTP_SESSIONS=yes\n');
  await install('1.5.0-test.2');
  // --allow-insecure-http chooses that opt-in in the same run, where /etc/uptime-goblin.env does not
  // decide; where it says no, the option is not applied and the preflight still runs.
  const chosen = await makeHost(t);
  const legacy = await chosen.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }), [
    '--trust-proxy',
    'loopback',
  ]);
  assert.equal(legacy.status, 0, ok(legacy));
  const original = fs.readFileSync(chosen.path('etc/uptime-goblin.env'), 'utf8');
  fs.appendFileSync(chosen.path('etc/uptime-goblin.env'), 'GOBLIN_INSECURE_HTTP_SESSIONS=0\n');
  const before = hostState(chosen);
  const declined = await chosen.install(makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }), [
    '--allow-insecure-http',
  ]);
  assert.equal(declined.status, 1, ok(declined));
  assert.equal(
    declined.stderr.trim(),
    preflightText('1.4.3-test.1', 'not recorded what your reverse proxy sends')
  );
  assert.deepEqual(hostState(chosen), before, 'nothing on the host changed');
  fs.writeFileSync(chosen.path('etc/uptime-goblin.env'), original);
  const allowed = await chosen.install(makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }), [
    '--allow-insecure-http',
  ]);
  assert.equal(allowed.status, 0, ok(allowed));
  assert.equal(chosen.installedVersion(), '1.5.0-test.1');
  assert.match(
    fs.readFileSync(chosen.path('etc/uptime-goblin.env'), 'utf8'),
    /^GOBLIN_INSECURE_HTTP_SESSIONS=1$/m
  );
  // Without a trusted proxy there is nothing to check (direct and loopback installs).
  const direct = await makeHost(t);
  const first = await direct.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }));
  assert.equal(first.status, 0, ok(first));
  const second = await direct.install(makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }));
  assert.equal(second.status, 0, ok(second));
  assert.match(second.stdout, /Sign in as admin with the same password/);
  // An unknown option is still refused, and --proxy-proto-checked takes no value.
  assert.equal(
    (await direct.install(makeSource(t, { mode: 'ok' }), ['--proxy-proto-checked=1'])).status,
    2
  );
});

test('an install that allows a public host without a trusted proxy is told that browser sign-in through the proxy is refused', async t => {
  const lockout =
    'WARNING: GOBLIN_ALLOWED_HOSTS names a public host but GOBLIN_TRUST_PROXY is not set. Behind a reverse proxy, every client then shares one sign-in lockout';
  const fix =
    'Re-run with --trust-proxy loopback (proxy on this host) or --trust-proxy <proxy address>, and make the proxy send X-Forwarded-For and X-Forwarded-Proto (nginx: proxy_set_header X-Forwarded-Proto $scheme;).';
  const source = makeSource(t, { version: '1.5.0-test.1', mode: 'ok' });
  const host = await makeFreshHost(t);
  const plain = await host.install(source, ['--allowed-hosts', 'goblin.example']);
  assert.equal(plain.status, 0, ok(plain));
  assert.ok(host.wroteDefaultPort(), 'the installer wrote PORT=4317');
  // The tunnel goes to the PORT in /etc/uptime-goblin.env: here the free port the test gave it.
  assert.ok(
    plain.stderr.includes(
      `${lockout}, and Uptime Goblin cannot tell that browsers use HTTPS, so it refuses their sign-in through the proxy. ${fix} Until then, sign in through ssh -L ${host.port}:127.0.0.1:${host.port} and http://localhost:${host.port}, or add GOBLIN_INSECURE_HTTP_SESSIONS=1 to /etc/uptime-goblin.env on a network you trust (the password and the sign-in cookie then cross it unencrypted).`
    ),
    ok(plain)
  );
  // With plain-HTTP sessions allowed, sign-in works: only the shared lockout remains.
  fs.appendFileSync(host.path('etc/uptime-goblin.env'), 'GOBLIN_INSECURE_HTTP_SESSIONS=1\n');
  const allowed = await host.install(source);
  assert.ok(allowed.stderr.includes(`${lockout}. ${fix}\n`), ok(allowed));
  // A trusted proxy: no warning.
  const trusted = await host.install(source, ['--trust-proxy', 'loopback']);
  assert.doesNotMatch(trusted.stderr, /names a public host/);

  // The ssh tunnel reaches Uptime Goblin only where it listens, at its PORT: to 127.0.0.1 when Uptime Goblin
  // listens there or on every address, to [::1] or localhost when HOST names that (a tunnel to
  // the loopback is a browser on the Uptime Goblin host to Uptime Goblin). An install made with --listen
  // <address> listens on no loopback address, and a tunnel to that address is plain HTTP to
  // Uptime Goblin, so the warning does not offer the tunnel there (docs audit, install-changelog 5).
  // Uptime Goblin refuses to start: nothing listens.
  const refusing = makeSource(t, { version: '1.5.0-test.1', mode: 'refuse' });
  const inClear =
    'on a network you trust (the password and the sign-in cookie then cross it unencrypted)';
  for (const [listen, target] of [
    ['192.0.2.20', null],
    ['0.0.0.0', '127.0.0.1'],
    ['::1', '[::1]'],
    ['localhost', 'localhost'],
  ]) {
    const network = await makeHost(t);
    fs.writeFileSync(
      network.path('etc/uptime-goblin.env'),
      `HOST=${listen}\nPORT=${network.port}\nGOBLIN_ALLOWED_HOSTS=goblin.example\nGOBLIN_INSECURE_HTTP_SESSIONS=0\nGOBLIN_PASSWORD=${testPassword}\n`
    );
    const result = await network.install(refusing, ['--verify-timeout', '2']);
    const warned = result.stderr.split('\n').find(line => line.startsWith(lockout));
    assert.ok(warned, ok(result));
    const until = warned.slice(warned.indexOf(' Until then, '));
    // [::1] is quoted for zsh, which would take its brackets for a file pattern.
    const forward =
      target === '[::1]'
        ? `'${network.port}:[::1]:${network.port}'`
        : `${network.port}:${target}:${network.port}`;
    if (target)
      assert.equal(
        until,
        ` Until then, sign in through ssh -L ${forward} and http://localhost:${network.port}, or add GOBLIN_INSECURE_HTTP_SESSIONS=1 to /etc/uptime-goblin.env ${inClear}.`,
        listen
      );
    else
      assert.equal(
        until,
        ` Until then, add GOBLIN_INSECURE_HTTP_SESSIONS=1 to /etc/uptime-goblin.env ${inClear}: Uptime Goblin listens on 192.0.2.20, so an ssh tunnel to 127.0.0.1 does not reach it, and one to 192.0.2.20 is plain HTTP to Uptime Goblin.`,
        listen
      );
  }
});

// The maintainer's decision (2026-11-12): an upgrade never turns plain-HTTP sign-in on by itself. An
// install that listens on the network without a trusted proxy stops before anything changes,
// unless /etc/uptime-goblin.env already decides (GOBLIN_INSECURE_HTTP_SESSIONS read as yes or no) or the
// operator chooses plain HTTP with --allow-insecure-http, which adds the line with a comment that
// says who chose it and that passwords cross the network in clear. (The 1.5 installer once added
// that line itself, and added it again after it was removed.)
const insecureComment = who =>
  new RegExp(
    `^# Added by the Uptime Goblin installer on \\d{4}-\\d{2}-\\d{2} because ${who} ran it with --allow-insecure-http: sign-in over plain HTTP, so passwords and the sign-in cookie cross the network in clear\\. Set it to 0 once Uptime Goblin is served over HTTPS\\.$`
  );
const insecureWarning =
  'WARNING: --allow-insecure-http added GOBLIN_INSECURE_HTTP_SESSIONS=1 to /etc/uptime-goblin.env: Uptime Goblin allows sign-in over plain HTTP, so your network can see the sign-in cookie, the password each time you sign in or change it, and the password of every script that signs in with HTTP Basic. Serve Uptime Goblin over HTTPS, then set GOBLIN_INSECURE_HTTP_SESSIONS=0 in /etc/uptime-goblin.env and restart Uptime Goblin (sudo systemctl restart uptime-goblin.service).';
const plainHttpStop = (host, existing) =>
  `Uptime Goblin would listen on ${host} (${existing ? 'HOST in /etc/uptime-goblin.env' : '--listen'}) with no reverse proxy it trusts (GOBLIN_TRUST_PROXY), so browsers and scripts would sign in over plain HTTP, and the network would see each password and sign-in cookie. Uptime Goblin 1.5 allows that only when you choose it. Either serve Uptime Goblin over HTTPS through a reverse proxy: ${
    existing
      ? 'set HOST=127.0.0.1 in /etc/uptime-goblin.env (sudoedit /etc/uptime-goblin.env) and run this installer again with --trust-proxy loopback for a proxy on this host, or run it again with --trust-proxy <proxy address> for one on another host'
      : 'run this installer again without --listen (Uptime Goblin then listens on 127.0.0.1) and with --trust-proxy loopback for a proxy on this host, or with --trust-proxy <proxy address> for one on another host'
  }, and make the proxy send X-Forwarded-Proto (nginx: proxy_set_header X-Forwarded-Proto $scheme;). Or, on a network you trust, run this installer again with --allow-insecure-http, which adds GOBLIN_INSECURE_HTTP_SESSIONS=1 to /etc/uptime-goblin.env: passwords then cross the network in clear.${
    existing
      ? ' To keep sign-in over plain HTTP refused instead, add GOBLIN_INSECURE_HTTP_SESSIONS=0 to /etc/uptime-goblin.env.'
      : ''
  } Nothing was changed.`;

test('an install listening on the network without a trusted proxy stops, changing nothing, until /etc/uptime-goblin.env decides or --allow-insecure-http chooses plain HTTP', async t => {
  // The service refuses to start (exit 78), so nothing listens on 0.0.0.0 during the test;
  // /etc/uptime-goblin.env is complete before the service starts.
  const source = makeSource(t, { version: '1.5.0-test.1', mode: 'refuse' });
  const envOf = host => fs.readFileSync(host.path('etc/uptime-goblin.env'), 'utf8');
  // Nothing on a host that had no Uptime Goblin: no settings, code, data, unit or service call that
  // changes anything (the preflights only ask systemd what it would give Uptime Goblin).
  const untouched = host => {
    for (const file of [
      'etc/uptime-goblin.env',
      'opt/uptime-goblin',
      'var/lib/uptime-goblin',
      'etc/uptime-goblin',
    ])
      assert.ok(!fs.existsSync(host.path(file)), file);
    assert.equal(
      host
        .calls()
        .split('\n')
        .filter(line => line && !/^(show|show-environment)( |$)/.test(line))
        .join('\n'),
      ''
    );
  };

  // A new install on 0.0.0.0 without --trust-proxy stops before anything is written.
  const fresh = await makeFreshHost(t);
  const stopped = await fresh.install(source, ['--listen', '0.0.0.0', '--verify-timeout', '2']);
  assert.equal(stopped.status, 1, ok(stopped));
  assert.equal(stopped.stderr.trim(), plainHttpStop('0.0.0.0', false));
  assert.equal(stopped.stdout, '');
  untouched(fresh);
  // So does one on a network address.
  const other = await makeFreshHost(t);
  const address = await other.install(source, ['--listen', '192.0.2.20', '--verify-timeout', '2']);
  assert.equal(address.stderr.trim(), plainHttpStop('192.0.2.20', false));
  untouched(other);

  // --allow-insecure-http: the line, with its comment (who chose it, passwords in clear), and the
  // warning. sudo names who ran it; then the encryption key's lines (delivery spec §4.5).
  const chosen = await fresh.install(
    source,
    ['--listen', '0.0.0.0', '--allow-insecure-http', '--verify-timeout', '2'],
    { SUDO_USER: 'operator1' }
  );
  assert.ok(fresh.wroteDefaultPort(), 'the installer wrote PORT=4317');
  assert.match(
    chosen.stdout,
    /^Created private settings in \/etc\/uptime-goblin\.env\. Sign in as admin with GOBLIN_PASSWORD from that file\.$/m
  );
  assert.match(
    chosen.stdout,
    /^Updated GOBLIN_INSECURE_HTTP_SESSIONS in \/etc\/uptime-goblin\.env\.$/m
  );
  assert.ok(chosen.stderr.includes(insecureWarning), ok(chosen));
  const lines = envOf(fresh).trimEnd().split('\n');
  assert.match(lines.at(-4), insecureComment('operator1'));
  assert.deepEqual(lines.slice(-3), ['GOBLIN_INSECURE_HTTP_SESSIONS=1', keyComment, keyLine]);
  assert.match(lines[0], /^HOST=0\.0\.0\.0$/);
  assert.equal(fs.statSync(fresh.path('etc/uptime-goblin.env')).mode & 0o777, 0o600);
  // The file decides from now on: the next run neither stops nor adds anything.
  const once = envOf(fresh);
  const again = await fresh.install(source, ['--verify-timeout', '2']);
  assert.doesNotMatch(again.output, /plain HTTP|GOBLIN_INSECURE_HTTP_SESSIONS/, ok(again));
  assert.equal(envOf(fresh), once);
  // A SUDO_USER that is no plain account name is not written into the file.
  const odd = await makeFreshHost(t);
  await odd.install(
    source,
    ['--listen', '0.0.0.0', '--allow-insecure-http', '--verify-timeout', '2'],
    { SUDO_USER: 'x\nGOBLIN_TRUST_PROXY=0.0.0.0/0' }
  );
  assert.match(envOf(odd).split('\n').at(-5), insecureComment('root'));
  assert.doesNotMatch(envOf(odd), /GOBLIN_TRUST_PROXY/);

  // With --trust-proxy the proxy decides the transport: no stop, nothing added.
  const proxied = await makeFreshHost(t);
  const behind = await proxied.install(source, [
    '--listen',
    '0.0.0.0',
    '--trust-proxy',
    'loopback',
    '--verify-timeout',
    '2',
  ]);
  assert.doesNotMatch(behind.output, /GOBLIN_INSECURE_HTTP_SESSIONS|plain HTTP/);
  assert.doesNotMatch(envOf(proxied), /GOBLIN_INSECURE_HTTP_SESSIONS/);

  // An upgrade of a 1.4.x install whose /etc/uptime-goblin.env listens on the network (as 1.4.x signed
  // browsers in over plain HTTP with Basic) stops with nothing changed: the installer no longer
  // turns plain-HTTP sign-in on for it.
  const legacy = await makeHost(t);
  const installed = await legacy.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }));
  assert.equal(installed.status, 0, ok(installed));
  fs.writeFileSync(
    legacy.path('etc/uptime-goblin.env'),
    envOf(legacy).replace('HOST=127.0.0.1', 'HOST=0.0.0.0')
  );
  const before = hostState(legacy);
  const upgrade = await legacy.install(makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }));
  assert.equal(upgrade.status, 1, ok(upgrade));
  assert.equal(upgrade.stderr.trim(), plainHttpStop('0.0.0.0', true));
  assert.deepEqual(hostState(legacy), before, 'nothing on the host changed');
  assert.equal(legacy.installedVersion(), '1.4.3-test.1');

  // An existing decision is kept, and the run goes on: =1, =0 (any value Uptime Goblin reads as yes or
  // no, the last line that sets it counting), and --allow-insecure-http changes neither (with =0
  // it says it was not applied). Only the encryption key's lines are added.
  const keyLines = `${keyComment}\n${keyLine}\n`;
  for (const [line, allow, notApplied] of [
    ['GOBLIN_INSECURE_HTTP_SESSIONS=1', false, false],
    ['GOBLIN_INSECURE_HTTP_SESSIONS=yes', true, false],
    ['GOBLIN_INSECURE_HTTP_SESSIONS=0', false, false],
    ['GOBLIN_INSECURE_HTTP_SESSIONS = off', true, true],
    ['GOBLIN_INSECURE_HTTP_SESSIONS=1\nGOBLIN_INSECURE_HTTP_SESSIONS=0', true, true],
  ]) {
    const decided = await makeHost(t);
    const text = envOf(decided).replace('HOST=127.0.0.1', 'HOST=0.0.0.0') + line + '\n';
    fs.writeFileSync(decided.path('etc/uptime-goblin.env'), text);
    const result = await decided.install(source, [
      ...(allow ? ['--allow-insecure-http'] : []),
      '--verify-timeout',
      '2',
    ]);
    assert.doesNotMatch(result.output, /Uptime Goblin would listen on/, line);
    assert.equal(envOf(decided), text + keyLines, line);
    const note =
      'Not applied: --allow-insecure-http adds GOBLIN_INSECURE_HTTP_SESSIONS=1 only to an /etc/uptime-goblin.env that does not set it, and yours turns it off, so sign-in over plain HTTP stays refused. To allow it, set that line to 1 (sudoedit /etc/uptime-goblin.env) and restart Uptime Goblin (sudo systemctl restart uptime-goblin.service).';
    assert.equal(result.stderr.includes(note), notApplied, `${line}: ${ok(result)}`);
    assert.doesNotMatch(result.stderr, /WARNING: --allow-insecure-http/, line);
  }

  // Lines that decide nothing: none at all (a removed line is never added again), a
  // commented-out one, an empty value (unset to Uptime Goblin) or one Uptime Goblin reads as neither yes nor no.
  // The run stops, changing nothing; with --allow-insecure-http the line is added after them,
  // where it is the one that counts.
  for (const line of [
    '',
    '# GOBLIN_INSECURE_HTTP_SESSIONS=1\n',
    'GOBLIN_INSECURE_HTTP_SESSIONS=\n',
    'GOBLIN_INSECURE_HTTP_SESSIONS=maybe\n',
  ]) {
    const open = await makeHost(t);
    const text = envOf(open).replace('HOST=127.0.0.1', 'HOST=0.0.0.0') + line;
    fs.writeFileSync(open.path('etc/uptime-goblin.env'), text);
    const result = await open.install(source, ['--verify-timeout', '2']);
    assert.equal(result.status, 1, ok(result));
    assert.equal(result.stderr.trim(), plainHttpStop('0.0.0.0', true), JSON.stringify(line));
    assert.equal(envOf(open), text);
    assert.ok(!fs.existsSync(open.path('opt/uptime-goblin')));
    const allowed = await open.install(source, ['--allow-insecure-http', '--verify-timeout', '2']);
    assert.ok(allowed.stderr.includes(insecureWarning), ok(allowed));
    const after = envOf(open).slice(text.length).split('\n');
    assert.match(after[0], insecureComment('root'));
    assert.deepEqual(after.slice(1), ['GOBLIN_INSECURE_HTTP_SESSIONS=1', keyComment, keyLine, '']);
  }

  // A loopback listener (the default) is the loopback transport: nothing is added, and nothing
  // stops it. --allow-insecure-http adds the line there too: it is the operator's choice (a
  // proxy on this host that does not say HTTPS is plain HTTP to Uptime Goblin).
  for (const local of ['127.0.0.1', '127.0.1.1', '::1', 'localhost']) {
    const host = await makeHost(t);
    fs.writeFileSync(
      host.path('etc/uptime-goblin.env'),
      envOf(host).replace('HOST=127.0.0.1', `HOST=${local}`)
    );
    const before = envOf(host);
    const result = await host.install(source, ['--verify-timeout', '2']);
    assert.doesNotMatch(
      result.output,
      /Uptime Goblin would listen on|GOBLIN_INSECURE_HTTP_SESSIONS/,
      local
    );
    assert.equal(envOf(host), before + keyLines, local);
  }
  const local = await makeHost(t);
  const before15 = envOf(local);
  const chosenLocal = await local.install(source, [
    '--allow-insecure-http',
    '--verify-timeout',
    '2',
  ]);
  assert.ok(chosenLocal.stderr.includes(insecureWarning), ok(chosenLocal));
  assert.match(
    envOf(local).slice(before15.length),
    /^# Added by the Uptime Goblin installer on .*\nGOBLIN_INSECURE_HTTP_SESSIONS=1\n/
  );
});

// Installers of earlier 1.5 pre-releases added GOBLIN_INSECURE_HTTP_SESSIONS=1 by themselves, under
// this comment, to an install that listened on the network without a trusted proxy (the 1.5 test
// installs). No one chose that line, so it decides nothing; a =1 without this comment on the line
// just before it is still a decision. Every install that holds it stops, changing nothing, until
// it is decided: on the network, and also on loopback and behind a trusted proxy, where the
// installer once let it through with a warning and the line stayed in force (review CFG-1, INST-1,
// tests/F1, bar/PRE-RELEASE-OPTIN-KEPT): a client that reaches an Uptime Goblin on the network directly,
// or a proxy on this host that relays plain HTTP, would still sign in over plain HTTP under it.
const preReleaseComment =
  '# Added by the Orbit 1.5 installer: keeps plain-HTTP sign-in working as in 1.4.x. Set it to 0 once Orbit is served over HTTPS.';
const preReleasePair = `${preReleaseComment}\nGOBLIN_INSECURE_HTTP_SESSIONS=1\n`;
const replaced = (text, from, to) => {
  assert.ok(text.includes(from), from);
  return text.replace(from, to);
};
// `line`: the line of the =1, as an editor counts it (the comment is the line before).
const preReleaseStop = line =>
  `/etc/uptime-goblin.env sets GOBLIN_INSECURE_HTTP_SESSIONS=1 on line ${line} under the comment that an earlier Orbit 1.5 pre-release installer wrote with it on line ${line - 1} ("# Added by the Orbit 1.5 installer: keeps plain-HTTP sign-in working as in 1.4.x. …"): that installer allowed sign-in over plain HTTP by itself, so this one does not take the line for your choice, and stops until you decide. To refuse sign-in over plain HTTP, set line ${line} to GOBLIN_INSECURE_HTTP_SESSIONS=0 (sudoedit /etc/uptime-goblin.env): browsers and scripts then sign in only over HTTPS, through a reverse proxy that GOBLIN_TRUST_PROXY names (it must send X-Forwarded-Proto; nginx: proxy_set_header X-Forwarded-Proto $scheme;), or from the Uptime Goblin computer itself. To keep it, on a network you trust (the password and the sign-in cookie then cross it unencrypted), remove the comment on line ${line - 1} or put a comment of your own in its place (sudoedit /etc/uptime-goblin.env), or run this installer again with --allow-insecure-http, which replaces that comment with one that names who chose it. Nothing was changed.`;
const keptWarning = () =>
  replaced(
    insecureWarning,
    'added GOBLIN_INSECURE_HTTP_SESSIONS=1 to /etc/uptime-goblin.env:',
    'kept GOBLIN_INSECURE_HTTP_SESSIONS=1 in /etc/uptime-goblin.env, which an earlier 1.5 pre-release installer had added, as your choice:'
  );

test('the GOBLIN_INSECURE_HTTP_SESSIONS=1 that an earlier 1.5 pre-release installer added by itself decides nothing: every install that holds it stops, on the network, on loopback and behind a trusted proxy, until it is decided or --allow-insecure-http records the choice', async t => {
  // The service refuses to start (exit 78), so nothing listens on 0.0.0.0 during the test.
  const source = makeSource(t, { version: '1.5.0-test.1', mode: 'refuse' });
  const envOf = host => fs.readFileSync(host.path('etc/uptime-goblin.env'), 'utf8');
  const keyLines = `${keyComment}\n${keyLine}\n`;
  const network = (host, extra) => {
    const text = envOf(host).replace('HOST=127.0.0.1', 'HOST=0.0.0.0') + extra;
    fs.writeFileSync(host.path('etc/uptime-goblin.env'), text);
    return text;
  };
  const lineOf = (text, line) => text.split('\n').lastIndexOf(line) + 1;
  // Stopped, nothing changed, the line and its comment named, whatever else the file says.
  const stops = async (host, text, args = []) => {
    const result = await host.install(source, [...args, '--verify-timeout', '2']);
    assert.equal(result.status, 1, ok(result));
    assert.equal(
      result.stderr.trim(),
      preReleaseStop(lineOf(text, 'GOBLIN_INSECURE_HTTP_SESSIONS=1'))
    );
    assert.equal(result.stdout, '');
    assert.equal(envOf(host), text);
    assert.ok(!fs.existsSync(host.path('opt/uptime-goblin')));
  };

  // As a pre-release installer left it, on the network without a trusted proxy.
  const host = await makeHost(t);
  const text = network(host, preReleasePair);
  await stops(host, text);
  // --allow-insecure-http keeps the line where it is and puts its own comment (who chose it,
  // passwords in clear) in place of the pre-release one, with its warning.
  const chosen = await host.install(source, ['--allow-insecure-http', '--verify-timeout', '2'], {
    SUDO_USER: 'operator1',
  });
  assert.match(
    chosen.stdout,
    /^Updated GOBLIN_INSECURE_HTTP_SESSIONS in \/etc\/uptime-goblin\.env\.$/m
  );
  assert.ok(chosen.stderr.includes(keptWarning()), ok(chosen));
  assert.doesNotMatch(chosen.stderr, /pre-release installer, under its comment|stops until/);
  const lines = envOf(host).trimEnd().split('\n');
  assert.deepEqual(lines.slice(0, -4), text.trimEnd().split('\n').slice(0, -2));
  assert.match(lines.at(-4), insecureComment('operator1'));
  assert.deepEqual(lines.slice(-3), ['GOBLIN_INSECURE_HTTP_SESSIONS=1', keyComment, keyLine]);
  assert.ok(!envOf(host).includes(preReleaseComment));
  // A decision from now on: the next run neither stops nor changes anything.
  const once = envOf(host);
  const again = await host.install(source, ['--verify-timeout', '2']);
  assert.doesNotMatch(again.output, /plain HTTP|GOBLIN_INSECURE_HTTP_SESSIONS/, ok(again));
  assert.equal(envOf(host), once);

  // On loopback, behind a proxy /etc/uptime-goblin.env trusts, and with --trust-proxy: stopped the same
  // way (the installer once went on there, warning, and the line stayed in force).
  const local = await makeHost(t);
  const localText = envOf(local) + preReleasePair;
  fs.writeFileSync(local.path('etc/uptime-goblin.env'), localText);
  await stops(local, localText);
  const proxied = await makeHost(t);
  await stops(proxied, network(proxied, `GOBLIN_TRUST_PROXY=loopback\n${preReleasePair}`));
  const option = await makeHost(t);
  await stops(option, network(option, preReleasePair), ['--trust-proxy', '192.0.2.10']);

  // Decisions the installer keeps, changing only the key's lines, behind a trusted proxy on the
  // network and on loopback alike: the three ways to decide that the message names (the line set
  // to 0; the comment removed, or a comment of one's own in its place, which keeps the 1), a =1
  // whose line just before it is not exactly that comment, and a later line that sets it again
  // (the last one counts).
  for (const [extra, proxy] of [
    [`${preReleaseComment}\nGOBLIN_INSECURE_HTTP_SESSIONS=0\n`, true],
    ['GOBLIN_INSECURE_HTTP_SESSIONS=1\n', true],
    ['# kept on purpose: the test network\nGOBLIN_INSECURE_HTTP_SESSIONS=1\n', true],
    [`${preReleaseComment}\nGOBLIN_INSECURE_HTTP_SESSIONS=0\n`, false],
    ['GOBLIN_INSECURE_HTTP_SESSIONS=1\n', false],
    [`${preReleaseComment}\n# kept on purpose\nGOBLIN_INSECURE_HTTP_SESSIONS=1\n`, false],
    [`${preReleaseComment} \nGOBLIN_INSECURE_HTTP_SESSIONS=1\n`, false],
    [`${preReleasePair}GOBLIN_INSECURE_HTTP_SESSIONS=0\n`, false],
    [`${preReleasePair}GOBLIN_INSECURE_HTTP_SESSIONS=yes\n`, false],
  ]) {
    const decided = await makeHost(t);
    const before = proxy
      ? network(decided, `GOBLIN_TRUST_PROXY=loopback\n${extra}`)
      : network(decided, extra);
    const result = await decided.install(source, ['--verify-timeout', '2']);
    assert.doesNotMatch(result.output, /Uptime Goblin would listen on|pre-release/, extra);
    assert.equal(envOf(decided), before + keyLines, extra);
  }
  // --allow-insecure-http on loopback records the choice there too.
  const chosenLocal = await makeHost(t);
  const chosenText = envOf(chosenLocal) + preReleasePair;
  fs.writeFileSync(chosenLocal.path('etc/uptime-goblin.env'), chosenText);
  const recorded = await chosenLocal.install(source, [
    '--allow-insecure-http',
    '--verify-timeout',
    '2',
  ]);
  assert.ok(recorded.stderr.includes(keptWarning()), ok(recorded));
  assert.ok(!envOf(chosenLocal).includes(preReleaseComment));
  assert.match(
    envOf(chosenLocal).slice(chosenText.length - preReleasePair.length),
    /^# Added by the Uptime Goblin installer on .*\nGOBLIN_INSECURE_HTTP_SESSIONS=1\n/
  );
  // The warning-only path is gone: nothing says the line was kept without a decision.
  for (const result of [chosen, again, recorded])
    assert.doesNotMatch(result.output, /not chosen by anyone/);
});

test('the proxy preflight: the =1 that an earlier 1.5 pre-release installer added by itself stops the upgrade from 1.4.x before it; --allow-insecure-http lets it through, and records the choice', async t => {
  const host = await makeHost(t);
  const legacy = await host.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }), [
    '--trust-proxy',
    'loopback',
  ]);
  assert.equal(legacy.status, 0, ok(legacy));
  // A pre-release installer's line, kept by its rollback to 1.4.3.
  fs.appendFileSync(host.path('etc/uptime-goblin.env'), preReleasePair);
  const text = fs.readFileSync(host.path('etc/uptime-goblin.env'), 'utf8');
  const next = makeSource(t, { version: '1.5.0-test.1', mode: 'ok' });
  const before = hostState(host);
  const refused = await host.install(next);
  assert.equal(refused.status, 1, ok(refused));
  // The plain-HTTP step stops it before the proxy preflight, as on every other path.
  assert.equal(
    refused.stderr.trim(),
    preReleaseStop(text.split('\n').lastIndexOf('GOBLIN_INSECURE_HTTP_SESSIONS=1') + 1)
  );
  assert.doesNotMatch(refused.stderr, /must know whether the browser uses HTTPS/);
  assert.deepEqual(hostState(host), before, 'nothing on the host changed');
  const allowed = await host.install(next, ['--allow-insecure-http']);
  assert.equal(allowed.status, 0, ok(allowed));
  assert.equal(host.installedVersion(), '1.5.0-test.1');
  const env = fs.readFileSync(host.path('etc/uptime-goblin.env'), 'utf8');
  assert.ok(!env.includes(preReleaseComment));
  assert.equal(env.match(/^GOBLIN_INSECURE_HTTP_SESSIONS=/gm).length, 1);
  assert.match(
    env,
    /^# Added by the Uptime Goblin installer on .*\nGOBLIN_INSECURE_HTTP_SESSIONS=1\n/m
  );
});

// The plain-HTTP step, the proxy preflight and the checks of the settings this release refuses to
// start with read /etc/uptime-goblin.env alone (review INST-2), while a drop-in or systemd's own
// environment can set them too: a drop-in that named a trusted proxy or decided plain HTTP was
// refused, one that removed the file's proxy or decision was not, and one with a value this
// release refuses passed, so the upgrade stopped Uptime Goblin and rolled back. Each is now worked out as
// systemd gives it to Uptime Goblin, as HOST, PORT and GOBLIN_PASSWORD are, and the install stops, changing
// nothing, where the installer cannot tell.
test('the plain-HTTP step, the proxy preflight and the settings this release refuses take each value as systemd would give it to Uptime Goblin, and stop where the installer cannot tell', async t => {
  // The service refuses to start (exit 78), so nothing listens on 0.0.0.0 during the test.
  const source = makeSource(t, { version: '1.5.0-test.1', mode: 'refuse' });
  const envOf = host => fs.readFileSync(host.path('etc/uptime-goblin.env'), 'utf8');
  const keyLines = `${keyComment}\n${keyLine}\n`;
  const dropIn = (host, name, text) => {
    fs.mkdirSync(host.path('etc/systemd/system/uptime-goblin.service.d'), { recursive: true });
    fs.writeFileSync(host.path(`etc/systemd/system/uptime-goblin.service.d/${name}`), text);
    return `/etc/systemd/system/uptime-goblin.service.d/${name}`;
  };
  // A host listening on the network, with `extra` in /etc/uptime-goblin.env and the drop-in `conf`.
  const prepare = async (extra, conf) => {
    const host = await makeHost(t);
    const text = envOf(host).replace('HOST=127.0.0.1', 'HOST=0.0.0.0') + extra;
    fs.writeFileSync(host.path('etc/uptime-goblin.env'), text);
    const where = dropIn(host, 'settings.conf', `[Service]\n${conf}\n`);
    return { host, text, where };
  };
  const unchanged = (host, text, result) => {
    assert.equal(result.status, 1, ok(result));
    assert.equal(result.stdout, '');
    assert.equal(envOf(host), text);
    assert.ok(!fs.existsSync(host.path('opt/uptime-goblin')));
  };

  // A drop-in names a trusted proxy, or decides plain HTTP: the install goes on (it stopped).
  for (const conf of [
    'Environment=GOBLIN_TRUST_PROXY=192.0.2.10',
    'Environment=GOBLIN_INSECURE_HTTP_SESSIONS=0',
  ]) {
    const { host, text } = await prepare('', conf);
    const result = await host.install(source, ['--verify-timeout', '2']);
    assert.doesNotMatch(result.output, /Uptime Goblin would listen on|could not be checked/, conf);
    assert.equal(envOf(host), text + keyLines, conf);
  }
  // --allow-insecure-http adds GOBLIN_INSECURE_HTTP_SESSIONS=1 only where systemd would give Uptime Goblin
  // no yes or no: a drop-in's 0 stays in force (systemd reads EnvironmentFile= after
  // Environment=, so a line added to /etc/uptime-goblin.env would override it), and the installer says
  // the option was not applied, naming the drop-in; with a drop-in's 1 nothing is added.
  // So too for a 0 from systemd's own environment.
  for (const [conf, notApplied, manager] of [
    ['Environment=GOBLIN_INSECURE_HTTP_SESSIONS=0', true],
    ['Environment=GOBLIN_INSECURE_HTTP_SESSIONS=1', false],
    ['', true, 'GOBLIN_INSECURE_HTTP_SESSIONS=0\n'],
  ]) {
    const { host, text, where } = await prepare('', conf);
    if (manager) fs.writeFileSync(path.join(host.env.FAKE_SYSTEMD_DIR, 'manager.env'), manager);
    const from = manager
      ? "systemd's own environment, as systemctl show-environment shows it"
      : `Environment= in ${where}`;
    const result = await host.install(source, ['--allow-insecure-http', '--verify-timeout', '2']);
    assert.doesNotMatch(result.output, /Uptime Goblin would listen on|could not be checked/, conf);
    assert.equal(envOf(host), text + keyLines, conf);
    assert.doesNotMatch(
      result.output,
      /WARNING: --allow-insecure-http|Updated GOBLIN_INSECURE_HTTP_SESSIONS/,
      conf
    );
    const note = `Not applied: --allow-insecure-http adds GOBLIN_INSECURE_HTTP_SESSIONS=1 to /etc/uptime-goblin.env only where systemd would give Uptime Goblin no yes or no for it, and it would give Uptime Goblin one that turns it off (${from}), so sign-in over plain HTTP stays refused. To allow it, set it to 1 there (a drop-in: sudo systemctl edit uptime-goblin) and restart Uptime Goblin (sudo systemctl restart uptime-goblin.service).`;
    assert.equal(result.stderr.includes(note), notApplied, `${conf}: ${ok(result)}`);
  }
  // The warning about a public host without a trusted proxy takes the proxy as systemd would give
  // it to Uptime Goblin: one that a drop-in names counts.
  const proxiedByDropIn = await prepare(
    'GOBLIN_ALLOWED_HOSTS=goblin.example\n',
    'Environment=GOBLIN_TRUST_PROXY=192.0.2.10'
  );
  const quiet = await proxiedByDropIn.host.install(source, ['--verify-timeout', '2']);
  assert.doesNotMatch(quiet.output, /Uptime Goblin would listen on|names a public host/, ok(quiet));
  // A drop-in removes the file's proxy or decision, or a file read after /etc/uptime-goblin.env empties
  // the proxy that --trust-proxy would write there: systemd would give Uptime Goblin none, so it stops.
  for (const [extra, conf, args] of [
    ['GOBLIN_TRUST_PROXY=loopback\n', 'UnsetEnvironment=GOBLIN_TRUST_PROXY', []],
    ['GOBLIN_INSECURE_HTTP_SESSIONS=1\n', 'UnsetEnvironment=GOBLIN_INSECURE_HTTP_SESSIONS', []],
    ['', 'EnvironmentFile=/etc/orbit-proxy.env', ['--trust-proxy', 'loopback']],
  ]) {
    const { host, text } = await prepare(extra, conf);
    fs.writeFileSync(host.path('etc/orbit-proxy.env'), 'GOBLIN_TRUST_PROXY=\n');
    const result = await host.install(source, [...args, '--verify-timeout', '2']);
    unchanged(host, text, result);
    assert.equal(result.stderr.trim(), plainHttpStop('0.0.0.0', true), conf);
  }

  // Where a drop-in would decide one in a way the installer cannot read, it stops, naming it.
  const unknown = (key, why) =>
    `${key} as systemd would give it to Uptime Goblin could not be checked: ${why}. This installer judges it by this release's own rules before anything changes. Set ${key} in /etc/uptime-goblin.env alone, if anywhere (sudoedit /etc/uptime-goblin.env): no drop-in (sudo systemctl edit uptime-goblin), file that one names, or systemd environment (sudo systemctl unset-environment ${key}) should set, pass or remove it. Then run this installer again. Nothing was changed.`;
  const passes = (where, key) =>
    `PassEnvironment= in ${where} passes ${key} from the environment of systemd's own process, which this installer does not read`;
  for (const [key, conf, why] of [
    ['GOBLIN_TRUST_PROXY', 'PassEnvironment=GOBLIN_TRUST_PROXY', passes],
    [
      'GOBLIN_INSECURE_HTTP_SESSIONS',
      'UnsetEnvironment=GOBLIN_INSECURE_HTTP_SESSIONS=%i',
      where =>
        `UnsetEnvironment= in ${where} removes GOBLIN_INSECURE_HTTP_SESSIONS with a specifier, which this installer does not expand`,
    ],
    ['GOBLIN_LEGACY_BASIC', 'PassEnvironment=GOBLIN_LEGACY_BASIC', passes],
    [
      'GOBLIN_MAX_CONNECTIONS_PER_CLIENT',
      'Environment=GOBLIN_MAX_CONNECTIONS_PER_CLIENT=%i',
      where =>
        `Environment= in ${where} sets GOBLIN_MAX_CONNECTIONS_PER_CLIENT with a specifier, which this installer does not expand`,
    ],
  ]) {
    const { host, text, where } = await prepare('', conf);
    const result = await host.install(source, ['--verify-timeout', '2']);
    unchanged(host, text, result);
    assert.equal(result.stderr.trim(), unknown(key, why(where, key)), conf);
  }
  // Where systemctl show-environment fails, a setting that neither /etc/uptime-goblin.env nor a drop-in
  // sets could come from systemd's own environment: the first of the six stops the install.
  const silent = await prepare('', '');
  const failed = await silent.host.install(source, ['--verify-timeout', '2'], {
    FAKE_SYSTEMD_FAIL_ALWAYS: 'show-environment',
  });
  unchanged(silent.host, silent.text, failed);
  assert.equal(
    failed.stderr.trim(),
    unknown('GOBLIN_LEGACY_BASIC', 'systemctl show-environment did not answer (exit status 1)')
  );
  // Set in /etc/uptime-goblin.env, which systemd reads after PassEnvironment=, it is decided.
  const decided = await prepare(
    'GOBLIN_TRUST_PROXY=loopback\n',
    'PassEnvironment=GOBLIN_TRUST_PROXY'
  );
  const through = await decided.host.install(source, ['--verify-timeout', '2']);
  assert.doesNotMatch(
    through.output,
    /could not be checked|Uptime Goblin would listen on/,
    ok(through)
  );
  assert.equal(envOf(decided.host), decided.text + keyLines);

  // A value this release refuses to start with, from a drop-in or systemd's own environment: the
  // install stops, changing nothing, with Uptime Goblin's reason and where systemd takes the value from.
  const refusedWith = (problem, from) =>
    `This release of Uptime Goblin would refuse to start with the settings systemd would give it (exit status 78): ${problem} systemd would give it to Uptime Goblin from ${from}. Correct it there (a drop-in: sudo systemctl edit uptime-goblin; systemd's own environment: sudo systemctl unset-environment), or set it in /etc/uptime-goblin.env alone (sudoedit /etc/uptime-goblin.env), then run this installer again. Nothing was changed.`;
  for (const [conf, check, value] of [
    ['Environment=GOBLIN_LEGACY_BASIC=of', legacyBasicSetting, 'of'],
    ['Environment=GOBLIN_MAX_CONNECTIONS_PER_CLIENT=7', connectionsPerClient, '7'],
    ['Environment=GOBLIN_TRUST_PROXY=0.0.0.0/0', trustedProxies, '0.0.0.0/0'],
    ['Environment=GOBLIN_TRUST_PROXY=,', trustedProxies, ','],
  ]) {
    const { host, text, where } = await prepare('', conf);
    const result = await host.install(source, ['--verify-timeout', '2']);
    unchanged(host, text, result);
    assert.equal(
      result.stderr.trim(),
      refusedWith(refusal(check, value), `Environment= in ${where}`),
      conf
    );
  }
  const manager = await prepare('', '');
  fs.writeFileSync(
    path.join(manager.host.env.FAKE_SYSTEMD_DIR, 'manager.env'),
    'GOBLIN_MAX_CONNECTIONS_PER_CLIENT=300\n'
  );
  const fromManager = await manager.host.install(source, ['--verify-timeout', '2']);
  unchanged(manager.host, manager.text, fromManager);
  assert.equal(
    fromManager.stderr.trim(),
    refusedWith(
      refusal(connectionsPerClient, '300'),
      "systemd's own environment, as systemctl show-environment shows it"
    )
  );

  // The proxy preflight of the upgrade from 1.4.x: a proxy that a drop-in names is checked, and
  // plain HTTP that a drop-in allows skips it.
  const legacy = await makeHost(t);
  const installed = await legacy.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }));
  assert.equal(installed.status, 0, ok(installed));
  dropIn(legacy, 'proxy.conf', '[Service]\nEnvironment=GOBLIN_TRUST_PROXY=loopback\n');
  const next = makeSource(t, { version: '1.5.0-test.1', mode: 'ok' });
  const before = hostState(legacy);
  const checked = await legacy.install(next);
  assert.equal(checked.status, 1, ok(checked));
  assert.equal(
    checked.stderr.trim(),
    preflightText('1.4.3-test.1', 'not recorded what your reverse proxy sends')
  );
  assert.deepEqual(hostState(legacy), before, 'nothing on the host changed');
  dropIn(legacy, 'plain.conf', '[Service]\nEnvironment=GOBLIN_INSECURE_HTTP_SESSIONS=1\n');
  const skipped = await legacy.install(next);
  assert.equal(skipped.status, 0, ok(skipped));
  assert.equal(legacy.installedVersion(), '1.5.0-test.1');
});

// An earlier 1.5 pre-release build opens the settings field of its HMAC secret without checking
// it, and 1.5 builds before this release kept the webhook's Ed25519 private key there: started on
// such data, it signs with the private key's text and shows it under Show signing secret (review
// INST-4). This release moves such a key out at its start, but a failed start may stop before
// that, and the key stays in the data without a webhook, for the earlier build to take once
// GOBLIN_WEBHOOK_URL is set (AUTH-REMEDIATION F3). So after a failed start the installer never
// starts such a build, whatever systemd would give Uptime Goblin for GOBLIN_WEBHOOK_URL: it stops the
// service, keeps this release in /opt/uptime-goblin and the earlier build in /opt/uptime-goblin.previous, and says
// how to go on. The stand-in server plays both builds; the installer tells the earlier one by its
// version and its lib/ (the reveal route, and no public-key route), as it would a real one.
test('a failed upgrade never starts an earlier 1.5 pre-release build, with or without a webhook: the service stays stopped with this release in /opt/uptime-goblin; other releases roll back as before', async t => {
  // `routes`: the earlier build's reveal route in place of the public-key route (as those builds
  // have it), 'neither' (a build whose reveal route is put together at run time) or 'both'.
  const earlier = (version = '1.5.0-test.0', routes = 'reveal') => {
    const source = makeSource(t, { version, mode: 'ok' });
    const file = path.join(source, 'lib/http/routes/notifications.mjs');
    const publicKey = "'/api/notifications/webhook/public-key'";
    const text = fs.readFileSync(file, 'utf8');
    fs.writeFileSync(
      file,
      routes === 'both'
        ? `${text}\n// '/api/notifications/webhook/signing-secret/reveal'\n`
        : replaced(
            text,
            publicKey,
            routes === 'reveal'
              ? "'/api/notifications/webhook/signing-secret/reveal'"
              : "'/api/notifications/webhook/signing-key'"
          )
    );
    if (routes === 'both') assert.ok(text.includes(publicKey));
    return source;
  };
  const failing = makeSource(t, { version: '1.5.0-test.1', mode: 'refuse' });
  const url = 'http://receiver.example/hook?token=hook-token-123';
  const notStarted = which =>
    `The upgrade to 1.5.0-test.1 was not rolled back: the previous version in /opt/uptime-goblin.previous${which}. Uptime Goblin 1.5.0-test.1 keeps the webhook's private signing keys where such a build cannot read them, so on data that Uptime Goblin 1.5.0-test.1 has run on such a build shows no signing secret and sends webhooks unsigned; but a private key that a 1.5 build from before Uptime Goblin 1.5.0-test.1 kept in the field of that HMAC secret leaves it only at a start of Uptime Goblin 1.5.0-test.1 that gets that far, and such a build takes a key still there for its secret: it signs with the key's text and shows it under Show signing secret, also once GOBLIN_WEBHOOK_URL is set later. The service is stopped, and /opt/uptime-goblin still holds Uptime Goblin 1.5.0-test.1. Fix the problem above, then run the installer again. To go back to the earlier build instead, first restore Uptime Goblin's data from before this upgrade (a snapshot or a backup), then swap the two copies, make the unit Type=simple (such a build never reports ready to this release's Type=notify unit, so a start would wait for good; the next upgrade writes Type=notify again) and start it: sudo mv /opt/uptime-goblin /opt/uptime-goblin.1.5.0-test.1 && sudo mv /opt/uptime-goblin.previous /opt/uptime-goblin && sudo mv /opt/uptime-goblin.1.5.0-test.1 /opt/uptime-goblin.previous && sudo sed -i -e 's/^Type=notify$/Type=simple/' /etc/systemd/system/uptime-goblin.service && sudo systemctl daemon-reload && sudo systemctl start uptime-goblin.service. Data from before this upgrade can hold such a key too. If an earlier build that signs with an HMAC secret runs, or ran before this upgrade, on data that a 1.5 build from before Uptime Goblin 1.5.0-test.1 that signs with Ed25519 ran on (this data or data from before this upgrade alike), press Replace signing key twice once Uptime Goblin 1.5.0-test.1 runs again (with GOBLIN_WEBHOOK_URL set), and give receivers the new public key.`;
  const preRelease = version =>
    `, Uptime Goblin ${version}, is an earlier 1.5 pre-release build that signs webhooks with an HMAC secret (or cannot be told apart from one by its files)`;
  const unread =
    ' (whose version is not one this installer can read) cannot be told apart from an earlier 1.5 pre-release build that signs webhooks with an HMAC secret';
  const conf = text => host => {
    fs.mkdirSync(host.path('etc/systemd/system/uptime-goblin.service.d'), { recursive: true });
    fs.writeFileSync(
      host.path('etc/systemd/system/uptime-goblin.service.d/webhook.conf'),
      `[Service]\n${text}\n`
    );
  };
  const inFile = host =>
    fs.appendFileSync(host.path('etc/uptime-goblin.env'), `GOBLIN_WEBHOOK_URL=${url}\n`);
  // Installs `previous`, applies `set`, then the release that fails to start.
  const upgrade = async (previous, ...set) => {
    const host = await makeHost(t);
    const first = await host.install(previous);
    assert.equal(first.status, 0, ok(first));
    for (const change of set) change(host);
    const calls = host.calls().length;
    const result = await host.install(failing, ['--verify-timeout', '5']);
    assert.equal(result.status, 1, ok(result));
    assert.ok(!result.output.includes('hook-token-123'), 'the webhook URL is never printed');
    return { host, result, calls: host.calls().slice(calls) };
  };

  // Without a webhook (none set, or one a drop-in removes), with one in /etc/uptime-goblin.env, from a
  // drop-in, or passed from systemd's own environment (which the installer cannot read): not
  // restored, not started. So too for an earlier build whose lib/ holds neither route, or both:
  // only this release's public-key route without the reveal route tells a build apart from the
  // earlier ones.
  const none = () => {};
  const unreadable = host => {
    const file = host.path('opt/uptime-goblin/package.json');
    fs.writeFileSync(
      file,
      JSON.stringify({ ...JSON.parse(fs.readFileSync(file, 'utf8')), version: 'unknown' })
    );
  };
  for (const [set, which, change, routes] of [
    [none, preRelease('1.5.0-test.0')],
    [conf('UnsetEnvironment=GOBLIN_WEBHOOK_URL'), preRelease('1.5.0-test.0'), inFile],
    [inFile, preRelease('1.5.0-test.0')],
    [conf(`Environment=GOBLIN_WEBHOOK_URL=${url}`), preRelease('1.5.0-test.0')],
    [conf('PassEnvironment=GOBLIN_WEBHOOK_URL'), preRelease('1.5.0-test.0')],
    // A version the installer cannot read: told apart by its files only.
    [inFile, unread, unreadable],
    [none, unread, unreadable],
    [inFile, preRelease('1.5.0-test.0'), null, 'neither'],
    [inFile, preRelease('1.5.0-test.0'), null, 'both'],
    [none, preRelease('1.5.0-test.0'), null, 'neither'],
  ]) {
    const { host, result, calls } = await upgrade(
      earlier(undefined, routes),
      set,
      ...(change ? [change] : [])
    );
    assert.ok(result.stderr.trimEnd().endsWith(notStarted(which)), ok(result));
    assert.doesNotMatch(result.stderr, /Restoring the previous version|rolled back\.$/m);
    assert.equal(host.installedVersion(), '1.5.0-test.1');
    assert.ok(fs.existsSync(host.path('opt/uptime-goblin.previous/server.mjs')));
    assert.ok(!fs.existsSync(host.path('opt/uptime-goblin.failed')));
    assert.notEqual(
      host.systemctl('is-active', 'uptime-goblin.service').status,
      0,
      'the service is stopped'
    );
    assert.equal(calls.trimEnd().split('\n').at(-1), 'stop uptime-goblin.service', calls);
  }

  // With this release's signing in an earlier 1.5 build, or with 1.4.x, which keeps no signing
  // key: rolled back as before, with a webhook or without one.
  for (const [previous, ...set] of [
    [makeSource(t, { version: '1.5.0-test.0', mode: 'ok' }), inFile],
    [makeSource(t, { version: '1.5.0-test.0', mode: 'ok' })],
    [makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }), inFile],
    [makeSource(t, { version: '1.4.3-test.1', mode: 'ok' })],
  ]) {
    const { host, result } = await upgrade(previous, ...set);
    const version = JSON.parse(
      fs.readFileSync(path.join(previous, 'package.json'), 'utf8')
    ).version;
    assert.ok(
      result.stderr.includes(
        `The previous version is running again; the upgrade to 1.5.0-test.1 was rolled back.`
      ),
      ok(result)
    );
    assert.doesNotMatch(result.stderr, /was not rolled back/);
    assert.equal(host.installedVersion(), version);
  }
});

// Review R2 (OD12/OD27: a documented, tested manual restore path): where the installer neither
// restores nor starts an earlier 1.5 pre-release build, the way back it prints works. Its
// commands, replayed as printed on the scratch host (each path under GOBLIN_INSTALL_ROOT, the
// host's mv and systemctl), put the earlier build in /opt/uptime-goblin, keep the new release in
// /opt/uptime-goblin.previous, and start the earlier build, which serves at HOST:PORT. (Restoring the data
// first, the step before them, is goblin-admin restore-snapshot or a backup, tested on their own.)
test('the way back the installer prints after it keeps an earlier 1.5 pre-release build stopped starts that build when replayed as printed', async t => {
  const previous = makeSource(t, { version: '1.5.0-test.0', mode: 'ok' });
  const routes = path.join(previous, 'lib/http/routes/notifications.mjs');
  fs.writeFileSync(
    routes,
    replaced(
      fs.readFileSync(routes, 'utf8'),
      "'/api/notifications/webhook/public-key'",
      "'/api/notifications/webhook/signing-secret/reveal'"
    )
  );
  const host = await makeHost(t);
  const first = await host.install(previous);
  assert.equal(first.status, 0, ok(first));
  const failing = makeSource(t, { version: '1.5.0-test.1', mode: 'refuse' });
  const result = await host.install(failing, ['--verify-timeout', '5']);
  assert.equal(result.status, 1, ok(result));
  assert.match(result.stderr, /The upgrade to 1\.5\.0-test\.1 was not rolled back/);
  assert.notEqual(host.systemctl('is-active', 'uptime-goblin.service').status, 0, 'stopped');
  // The commands as printed, run one after another as `&&` would run them.
  const printed =
    /make the unit Type=simple \(.+?\) and start it: (sudo .+? uptime-goblin\.service)\. /.exec(
      result.stderr
    );
  assert.ok(printed, ok(result));
  const commands = printed[1].split(' && ').map(command => command.split(' '));
  assert.deepEqual(
    commands.map(([sudo, tool]) => `${sudo} ${tool}`),
    ['sudo mv', 'sudo mv', 'sudo mv', 'sudo sed', 'sudo systemctl', 'sudo systemctl']
  );
  const unitFile = host.path('etc/systemd/system/uptime-goblin.service');
  assert.match(fs.readFileSync(unitFile, 'utf8'), /^Type=notify$/m);
  for (const [, tool, ...args] of commands) {
    if (tool === 'sed') {
      // GNU sed -i -e 's/^Type=notify$/Type=simple/' FILE, as the host's sed would run it.
      assert.deepEqual(args, [
        '-i',
        '-e',
        "'s/^Type=notify$/Type=simple/'",
        '/etc/systemd/system/uptime-goblin.service',
      ]);
      const text = fs.readFileSync(unitFile, 'utf8');
      fs.writeFileSync(unitFile, text.replace(/^Type=notify$/gm, 'Type=simple'));
      continue;
    }
    const paths = args.map(arg => host.path(arg.replace(/^\//, '')));
    const run =
      tool === 'mv'
        ? spawnSync('mv', paths, { env: host.env, encoding: 'utf8' })
        : host.systemctl(...args);
    assert.equal(run.status, 0, `${tool} ${args.join(' ')}: ${run.stderr}`);
  }
  assert.match(fs.readFileSync(unitFile, 'utf8'), /^Type=simple$/m);
  assert.doesNotMatch(fs.readFileSync(unitFile, 'utf8'), /^Type=notify$/m);
  assert.equal(host.installedVersion(), '1.5.0-test.0');
  assert.equal(host.installedVersion('opt/uptime-goblin.previous'), '1.5.0-test.1');
  assert.ok(!fs.existsSync(host.path('opt/uptime-goblin.1.5.0-test.1')));
  // The earlier build serves where the install listens, as its own process.
  let status = null;
  for (let i = 0; i < 100 && status?.version !== '1.5.0-test.0'; i++) {
    await delay(100);
    status = host.status();
  }
  assert.equal(status?.version, '1.5.0-test.0');
  assert.deepEqual(status.listen, { host: '127.0.0.1', port: host.port });
  assert.equal(status.pid, host.state().pid);
  const health = await fetch(`http://127.0.0.1:${host.port}/health?instance=${status.nonce}`);
  assert.deepEqual(await health.json(), { status: 'ok', instance: 'match' });
  assert.equal(host.systemctl('is-active', 'uptime-goblin.service').status, 0);
});

// systemd's EnvironmentFile= takes the last assignment of a key and allows blanks around the =.
// The plain-HTTP step read the first line starting with `KEY=`: with HOST=0.0.0.0 appended to
// an install that listened on loopback, Uptime Goblin listened on the network but the step judged it
// loopback (r7 upgrade-rollback finding). An update rewrote the first assignment, which the last
// still overrode, and the preflight did not see a `KEY = value` line at all. (The step that
// judges plain HTTP now stops such an install instead of adding a line: see the test above.)
test('the installer reads /etc/uptime-goblin.env as systemd does: the last assignment counts, blanks around = allowed', async t => {
  // The service refuses to start (exit 78), so nothing listens on 0.0.0.0 during the test.
  const source = makeSource(t, { version: '1.5.0-test.1', mode: 'refuse' });
  const envOf = host => fs.readFileSync(host.path('etc/uptime-goblin.env'), 'utf8');
  // The value systemd gives Uptime Goblin: the last assignment, blanks and one pair of quotes stripped.
  const effective = (text, key) => {
    let found = null;
    for (const line of text.split('\n')) {
      const match = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
      if (match?.[1] === key) found = match[2].trim().replace(/^(["'])(.*)\1$/, '$2');
    }
    return found;
  };
  const upgrade = async (change, args = []) => {
    const host = await makeHost(t);
    fs.writeFileSync(host.path('etc/uptime-goblin.env'), change(envOf(host)));
    const result = await host.install(source, [...args, '--verify-timeout', '2']);
    return { host, result, env: envOf(host) };
  };

  // On the network by the last line, or by a line with blanks around the =, with no trusted
  // proxy by the last line: the plain-HTTP step stops, changing nothing.
  for (const change of [
    text => `${text}HOST=0.0.0.0\n`,
    text => text.replace('HOST=127.0.0.1', 'HOST = "0.0.0.0"'),
    // A later empty GOBLIN_TRUST_PROXY turns proxy trust off.
    text =>
      `${text.replace('HOST=127.0.0.1', 'HOST=0.0.0.0')}GOBLIN_TRUST_PROXY=loopback\nGOBLIN_TRUST_PROXY=\n`,
  ]) {
    const host = await makeHost(t);
    const text = change(envOf(host));
    fs.writeFileSync(host.path('etc/uptime-goblin.env'), text);
    const result = await host.install(source, ['--verify-timeout', '2']);
    assert.equal(result.status, 1, ok(result));
    assert.equal(result.stderr.trim(), plainHttpStop('0.0.0.0', true));
    assert.equal(envOf(host), text);
    assert.ok(!fs.existsSync(host.path('opt/uptime-goblin')));
  }
  // Decided by the last line that sets it, with blanks around the =: the run goes on.
  for (const [line, value] of [
    ['GOBLIN_INSECURE_HTTP_SESSIONS = 1\n', '1'],
    ['GOBLIN_INSECURE_HTTP_SESSIONS=\nGOBLIN_INSECURE_HTTP_SESSIONS = "0"\n', '0'],
  ]) {
    const { result, env } = await upgrade(text => `${text}HOST=0.0.0.0\n${line}`);
    assert.doesNotMatch(result.output, /Uptime Goblin would listen on/, ok(result));
    assert.equal(effective(env, 'GOBLIN_INSECURE_HTTP_SESSIONS'), value);
  }
  // Back on loopback by the last line, or behind a proxy by the last line: nothing is added.
  for (const change of [
    text => `${text.replace('HOST=127.0.0.1', 'HOST=0.0.0.0')}HOST=127.0.0.1\n`,
    text =>
      `${text.replace('HOST=127.0.0.1', 'HOST=0.0.0.0')}GOBLIN_TRUST_PROXY=\nGOBLIN_TRUST_PROXY=loopback\n`,
  ]) {
    const { result, env } = await upgrade(change);
    assert.doesNotMatch(result.output, /plain HTTP|GOBLIN_INSECURE_HTTP_SESSIONS/);
    assert.equal(effective(env, 'GOBLIN_INSECURE_HTTP_SESSIONS'), null);
  }
  // --trust-proxy rewrites the assignment that counts (the last), so it takes effect; an
  // assignment that already says the same with blanks or quotes is left as it is.
  const updated = await upgrade(
    text => `${text}GOBLIN_TRUST_PROXY=10.0.0.1\n# proxy trust off for now\nGOBLIN_TRUST_PROXY=\n`,
    ['--trust-proxy', 'loopback']
  );
  assert.match(updated.result.stdout, /Updated GOBLIN_TRUST_PROXY in \/etc\/uptime-goblin\.env\./);
  assert.equal(effective(updated.env, 'GOBLIN_TRUST_PROXY'), 'loopback');
  assert.match(
    updated.env,
    /^GOBLIN_TRUST_PROXY=10\.0\.0\.1\n# proxy trust off for now\nGOBLIN_TRUST_PROXY=loopback\n/m
  );
  const same = await upgrade(
    text => `${text}GOBLIN_TRUST_PROXY = 'loopback'\n`,
    ['--trust-proxy', 'loopback']
  );
  assert.doesNotMatch(same.result.stdout, /Updated GOBLIN_TRUST_PROXY/);
  assert.match(same.env, /^GOBLIN_TRUST_PROXY = 'loopback'$/m);

  // The proxy preflight reads it the same way: `GOBLIN_TRUST_PROXY = loopback` is a trusted
  // proxy, so the upgrade from 1.4.x waits until 1.4.x saw https.
  const proxied = await makeHost(t);
  const legacy = await proxied.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }));
  assert.equal(legacy.status, 0, ok(legacy));
  fs.appendFileSync(proxied.path('etc/uptime-goblin.env'), 'GOBLIN_TRUST_PROXY = loopback\n');
  const before = hostState(proxied);
  const refused = await proxied.install(makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }));
  assert.equal(refused.status, 1, ok(refused));
  assert.equal(
    refused.stderr.trim(),
    preflightText('1.4.3-test.1', 'not recorded what your reverse proxy sends')
  );
  assert.deepEqual(hostState(proxied), before, 'nothing on the host changed');
});

// ---------------------------------------------------------------------------------------------
// The encryption key (delivery spec §4.5): picked in the order Uptime Goblin picks it, checked against
// existing data before anything changes, provisioned as /etc/uptime-goblin/secret.key otherwise.

const keyComment =
  "# Added by the Uptime Goblin 1.5 installer: the encryption key for Uptime Goblin's sealed settings. Back it up separately.";
const keyLine = 'GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key';
const keyA = 'a1'.repeat(16) + 'b2'.repeat(16);
const keyB = 'c3'.repeat(16) + 'd4'.repeat(16);
const syncLog = host => {
  try {
    return fs
      .readFileSync(path.join(host.env.FAKE_SYSTEMD_DIR, 'sync.log'), 'utf8')
      .trimEnd()
      .split('\n');
  } catch {
    return [];
  }
};
const envText = host => fs.readFileSync(host.path('etc/uptime-goblin.env'), 'utf8');
// What a refused install must leave exactly as it was, the encryption key's places included.
// A link or a FIFO is described, not opened (reading a FIFO would wait for a writer).
function keyState(host) {
  const describe = file => {
    const stat = fs.lstatSync(file);
    if (stat.isSymbolicLink()) return `link to ${fs.readlinkSync(file)}`;
    if (!stat.isFile()) return 'not a regular file';
    return createHash('sha256').update(fs.readFileSync(file)).digest('hex');
  };
  const hashes = directory =>
    fs.existsSync(directory)
      ? Object.fromEntries(
          tree(directory, new Set()).map(file => [file, describe(path.join(directory, file))])
        )
      : null;
  return {
    env: envText(host),
    etcOrbit: hashes(host.path('etc/uptime-goblin')),
    data: hashes(host.path('var/lib/uptime-goblin')),
    app: hashes(host.path('opt/uptime-goblin')),
    unit: fs.existsSync(host.path('etc/systemd/system/uptime-goblin.service'))
      ? fs.readFileSync(host.path('etc/systemd/system/uptime-goblin.service'), 'utf8')
      : null,
    calls: host
      .calls()
      .split('\n')
      .filter(line => !/^(is-active|cat|show|show-environment)( |$)/.test(line))
      .join('\n'),
    service: host.state(),
  };
}
// A control.sqlite with a keyring made with `key`, in the host's data directory (as Uptime Goblin 1.5
// leaves it); no key file is left behind.
async function keyringData(host, key = keyA) {
  const data = host.path('var/lib/uptime-goblin');
  fs.mkdirSync(data, { recursive: true, mode: 0o700 });
  const lock = acquireLock(data);
  try {
    const started = await startControl(data, {
      lock,
      credentialConfigured: true,
      keyring: 'deferred',
      env: { GOBLIN_SECRET_KEY: key },
      keySources: { credentialsDirectory: '/nonexistent', secretsDirectory: '/nonexistent' },
    });
    await started.createKeyring();
    started.control.close();
  } finally {
    lock.release();
  }
}
const fingerprintOf = hex => keyFingerprint(Buffer.from(hex, 'hex'));
// A host as the 1.4.3 installer left it (no key provisioned), running a fake 1.4.3.
async function legacyHost(t, args = []) {
  const host = await makeHost(t);
  const legacy = await host.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }), args);
  assert.equal(legacy.status, 0, ok(legacy));
  fs.rmSync(host.path('etc/uptime-goblin'), { recursive: true, force: true });
  fs.writeFileSync(
    host.path('etc/uptime-goblin.env'),
    envText(host).replace(`${keyComment}\n${keyLine}\n`, '')
  );
  fs.rmSync(path.join(host.env.FAKE_SYSTEMD_DIR, 'sync.log'), { force: true });
  return host;
}

test('a new install creates /etc/uptime-goblin/secret.key (0440 in 0750), synced before it is named in /etc/uptime-goblin.env', async t => {
  const host = await makeHost(t);
  const before = envText(host);
  const result = await host.install(makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }));
  assert.equal(result.status, 0, ok(result));
  const file = host.path('etc/uptime-goblin/secret.key');
  assert.match(fs.readFileSync(file, 'utf8'), /^[0-9a-f]{64}\n$/);
  assert.equal(fs.statSync(file).mode & 0o777, 0o440);
  assert.equal(fs.statSync(host.path('etc/uptime-goblin')).mode & 0o777, 0o750);
  assert.equal(envText(host), `${before}${keyComment}\n${keyLine}\n`);
  assert.match(
    result.stdout,
    /^Created the encryption key \/etc\/uptime-goblin\/secret\.key\. Back it up separately from \/var\/lib\/uptime-goblin: without it Uptime Goblin cannot open what it has sealed\.$/m
  );
  // The temporary file is synced before the rename, /etc/uptime-goblin after it, and only then is the
  // key named in /etc/uptime-goblin.env.
  const syncs = syncLog(host);
  assert.equal(syncs.length, 2, syncs.join('\n'));
  assert.match(
    syncs[0],
    new RegExp(`^${host.path('etc/uptime-goblin/')}\\.secret\\.key\\.\\w+ key=no env=no$`)
  );
  assert.equal(syncs[1], `${host.path('etc/uptime-goblin')} key=yes env=no`);
  assert.deepEqual(
    fs.readdirSync(host.path('etc/uptime-goblin')),
    ['secret.key'],
    'no temporary file'
  );
  // Running it again changes nothing: the key and the line are kept, nothing is synced.
  const key = fs.readFileSync(file, 'utf8'),
    env = envText(host);
  const again = await host.install(makeSource(t, { version: '1.5.0-test.2', mode: 'ok' }));
  assert.equal(again.status, 0, ok(again));
  assert.equal(fs.readFileSync(file, 'utf8'), key);
  assert.equal(envText(host), env);
  assert.equal(syncLog(host).length, 2);
  assert.doesNotMatch(again.output, /Created the encryption key|Updated GOBLIN_SECRET_KEY_FILE/);
});

test('a key the host already has is kept: GOBLIN_SECRET_KEY (with a warning), GOBLIN_SECRET_KEY_FILE, /etc/uptime-goblin/secret.key', async t => {
  const source = makeSource(t, { version: '1.5.0-test.1', mode: 'ok' });
  // GOBLIN_SECRET_KEY in the environment file: kept, with the /proc warning.
  const inEnv = await makeHost(t);
  fs.appendFileSync(inEnv.path('etc/uptime-goblin.env'), `GOBLIN_SECRET_KEY=${keyA}\n`);
  const env = envText(inEnv);
  let result = await inEnv.install(source);
  assert.equal(result.status, 0, ok(result));
  assert.equal(envText(inEnv), env);
  assert.ok(!fs.existsSync(inEnv.path('etc/uptime-goblin')));
  assert.ok(
    result.stderr.includes(
      "WARNING: GOBLIN_SECRET_KEY in /etc/uptime-goblin.env puts the key in Uptime Goblin's process environment, which root and the uptime-goblin user can read in /proc/<pid>/environ. Move it to a file: see 'Encryption key' in docs/installation.md."
    ),
    ok(result)
  );
  // GOBLIN_SECRET_KEY_FILE naming an existing file: kept as it is. The group uptime-goblin reads it, as
  // Uptime Goblin must (a root-only one is refused: see the test of keys the uptime-goblin account cannot read).
  const named = await makeHost(t);
  const keyFile = path.join(named.root, 'srv-orbit.key');
  fs.writeFileSync(keyFile, `${keyB}\n`, { mode: 0o440 });
  fs.appendFileSync(named.path('etc/uptime-goblin.env'), 'GOBLIN_SECRET_KEY_FILE=/srv-orbit.key\n');
  const namedEnv = envText(named);
  result = await named.install(source);
  assert.equal(result.status, 0, ok(result));
  assert.equal(envText(named), namedEnv);
  assert.ok(!fs.existsSync(named.path('etc/uptime-goblin')));
  assert.deepEqual(syncLog(named), []);
  // /etc/uptime-goblin/secret.key from an earlier install whose env line was lost: named again.
  const kept = await makeHost(t);
  fs.mkdirSync(kept.path('etc/uptime-goblin'), { mode: 0o750 });
  fs.writeFileSync(kept.path('etc/uptime-goblin/secret.key'), `${keyA}\n`, { mode: 0o440 });
  const keptEnv = envText(kept);
  result = await kept.install(source);
  assert.equal(result.status, 0, ok(result));
  assert.equal(envText(kept), `${keptEnv}${keyComment}\n${keyLine}\n`);
  assert.equal(fs.readFileSync(kept.path('etc/uptime-goblin/secret.key'), 'utf8'), `${keyA}\n`);
  assert.doesNotMatch(result.output, /Created the encryption key/);
});

test('a systemd credential named orbit-secret-key is kept and no line is added', async t => {
  // An installed unit to which the admin added a credential drop-in.
  const host = await legacyHost(t);
  const credential = path.join(host.root, 'etc/orbit-credential.key');
  fs.writeFileSync(credential, `${keyA}\n`, { mode: 0o400 });
  fs.mkdirSync(host.path('etc/systemd/system/uptime-goblin.service.d'), { recursive: true });
  fs.writeFileSync(
    host.path('etc/systemd/system/uptime-goblin.service.d/key.conf'),
    '[Service]\nLoadCredential=orbit-secret-key:/etc/orbit-credential.key\n'
  );
  const env = envText(host);
  const result = await host.install(makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }));
  assert.equal(result.status, 0, ok(result));
  assert.equal(envText(host), env, 'a GOBLIN_SECRET_KEY_FILE line would outrank the credential');
  assert.ok(!fs.existsSync(host.path('etc/uptime-goblin')));
  assert.match(
    result.stdout,
    /^Encryption key: the systemd credential orbit-secret-key \(\/etc\/orbit-credential\.key\)\.$/m
  );
  // An encrypted credential cannot be read by the installer: kept, and said so.
  fs.writeFileSync(
    host.path('etc/systemd/system/uptime-goblin.service.d/key.conf'),
    '[Service]\nLoadCredentialEncrypted=orbit-secret-key:/etc/orbit-credential.cred\n'
  );
  const encrypted = await host.install(makeSource(t, { version: '1.5.0-test.2', mode: 'ok' }));
  assert.equal(encrypted.status, 0, ok(encrypted));
  assert.match(
    encrypted.stdout,
    /could not be checked against the data; Uptime Goblin checks it at start/
  );
  assert.equal(envText(host), env);
  // An empty LoadCredential= clears the list, as systemd reads it: then a key is created.
  fs.writeFileSync(
    host.path('etc/systemd/system/uptime-goblin.service.d/key.conf'),
    '[Service]\nLoadCredential=orbit-secret-key:/etc/orbit-credential.key\nLoadCredential=\n'
  );
  const cleared = await host.install(makeSource(t, { version: '1.5.0-test.3', mode: 'ok' }));
  assert.equal(cleared.status, 0, ok(cleared));
  assert.match(cleared.stdout, /Created the encryption key/);
});

// systemd ends a line at LF, CR or CRLF, in /etc/uptime-goblin.env and in a unit's drop-ins alike. The
// installer split both on LF alone, so a line ending in CRLF set nothing for it: an install on
// 0.0.0.0 got no GOBLIN_INSECURE_HTTP_SESSIONS line (1.5 then refused the plain-HTTP sign-in
// 1.4.x allowed), the key in GOBLIN_SECRET_KEY went unseen and another was generated, a
// LoadCredential= drop-in went unseen and a key was generated whose GOBLIN_SECRET_KEY_FILE line
// Uptime Goblin takes before the credential, and the proxy preflight saw no GOBLIN_TRUST_PROXY.
test('/etc/uptime-goblin.env and a drop-in with CRLF line ends are read as systemd reads them', async t => {
  // The service refuses to start (exit 78), so nothing listens on 0.0.0.0 during the test;
  // /etc/uptime-goblin.env is complete before the service starts.
  const host = await makeHost(t);
  const lf =
    envText(host).replace('HOST=127.0.0.1', 'HOST=0.0.0.0') + `GOBLIN_SECRET_KEY=${keyA}\n`;
  fs.writeFileSync(host.path('etc/uptime-goblin.env'), lf.replaceAll('\n', '\r\n'));
  const source = makeSource(t, { version: '1.5.0-test.1', mode: 'refuse' });
  // HOST=0.0.0.0 on a CRLF line is on the network: without a decision, the plain-HTTP step
  // stops, changing nothing.
  const stopped = await host.install(source, ['--verify-timeout', '2']);
  assert.equal(stopped.status, 1, ok(stopped));
  assert.equal(stopped.stderr.trim(), plainHttpStop('0.0.0.0', true));
  assert.equal(envText(host), lf.replaceAll('\n', '\r\n'));
  const result = await host.install(source, ['--allow-insecure-http', '--verify-timeout', '2']);
  assert.ok(result.stderr.includes(insecureWarning), ok(result));
  assert.ok(
    result.stderr.includes(
      "WARNING: GOBLIN_SECRET_KEY in /etc/uptime-goblin.env puts the key in Uptime Goblin's process environment"
    ),
    ok(result)
  );
  assert.doesNotMatch(result.output, /Created the encryption key/);
  assert.ok(!fs.existsSync(host.path('etc/uptime-goblin')));
  // The rewrite that added the line ends every line with LF: systemd passes the same values.
  assert.ok(envText(host).startsWith(lf), envText(host));
  const added = envText(host).slice(lf.length).split('\n');
  assert.match(added[0], insecureComment('root'));
  assert.deepEqual(added.slice(1), ['GOBLIN_INSECURE_HTTP_SESSIONS=1', '']);

  // A LoadCredential= drop-in with CRLF line ends: kept, and no line is added.
  const legacy = await legacyHost(t);
  fs.writeFileSync(path.join(legacy.root, 'etc/orbit-credential.key'), `${keyA}\n`, {
    mode: 0o400,
  });
  fs.mkdirSync(legacy.path('etc/systemd/system/uptime-goblin.service.d'), { recursive: true });
  fs.writeFileSync(
    legacy.path('etc/systemd/system/uptime-goblin.service.d/key.conf'),
    '[Service]\r\nLoadCredential=orbit-secret-key:/etc/orbit-credential.key\r\n'
  );
  const env = envText(legacy);
  const kept = await legacy.install(makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }));
  assert.equal(kept.status, 0, ok(kept));
  assert.equal(envText(legacy), env);
  assert.ok(!fs.existsSync(legacy.path('etc/uptime-goblin')));
  assert.match(
    kept.stdout,
    /^Encryption key: the systemd credential orbit-secret-key \(\/etc\/orbit-credential\.key\)\.$/m
  );

  // GOBLIN_TRUST_PROXY on a CRLF line names a proxy: the upgrade from 1.4.x waits for https.
  const proxied = await makeHost(t);
  const installed = await proxied.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }), [
    '--trust-proxy',
    'loopback',
  ]);
  assert.equal(installed.status, 0, ok(installed));
  fs.writeFileSync(
    proxied.path('etc/uptime-goblin.env'),
    envText(proxied).replaceAll('\n', '\r\n')
  );
  const before = hostState(proxied);
  const refused = await proxied.install(makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }));
  assert.equal(refused.status, 1, ok(refused));
  assert.equal(
    refused.stderr.trim(),
    preflightText('1.4.3-test.1', 'not recorded what your reverse proxy sends')
  );
  assert.deepEqual(hostState(proxied), before, 'nothing on the host changed');
  assert.equal(proxied.installedVersion(), '1.4.3-test.1');
  // GOBLIN_INSECURE_HTTP_SESSIONS=1 on a CRLF line skips the preflight, as on an LF line.
  fs.appendFileSync(proxied.path('etc/uptime-goblin.env'), 'GOBLIN_INSECURE_HTTP_SESSIONS=1\r\n');
  const insecure = await proxied.install(makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }));
  assert.equal(insecure.status, 0, ok(insecure));
  assert.equal(proxied.installedVersion(), '1.5.0-test.1');
});

// The step that names a new key in /etc/uptime-goblin.env split the file on LF alone, so a file with
// CRLF line ends kept its CRs and got two lines ending in LF: every other rewrite of the file
// ends each line with LF (systemd reads the three line ends alike).
test('adding the key line to an /etc/uptime-goblin.env with CRLF line ends leaves every line ending in LF, as the other rewrites do', async t => {
  const host = await legacyHost(t);
  const lf = envText(host);
  assert.ok(!lf.includes('\r'));
  fs.writeFileSync(host.path('etc/uptime-goblin.env'), lf.replaceAll('\n', '\r\n'));
  const result = await host.install(makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }));
  assert.equal(result.status, 0, ok(result));
  assert.match(result.stdout, /^Created the encryption key \/etc\/uptime-goblin\/secret\.key\./m);
  assert.match(result.stdout, /^Updated GOBLIN_SECRET_KEY_FILE in \/etc\/uptime-goblin\.env\.$/m);
  assert.equal(envText(host), `${lf}${keyComment}\n${keyLine}\n`);
});

test('a systemd credential set in uptime-goblin.service itself is refused, changing nothing: the installer replaces that file', async t => {
  const unitFile = host => host.path('etc/systemd/system/uptime-goblin.service');
  const line = 'LoadCredential=orbit-secret-key:/etc/orbit-credential.key';
  const refusal =
    /^The systemd credential orbit-secret-key is set in \/etc\/systemd\/system\/uptime-goblin\.service itself \(LoadCredential=orbit-secret-key:\/etc\/orbit-credential\.key\), which this installer replaces with its own uptime-goblin\.service, so Uptime Goblin would lose its key\. Move that line into a drop-in \(sudo systemctl edit uptime-goblin\), then run this installer again\. Nothing was changed\.$/m;
  // A 1.4.3 host (the 1.4.x upgrade: the key would be generated in /var/lib/uptime-goblin) and a 1.5
  // host whose data has a keyring (the 1.5 upgrade: every start would refuse, key_missing).
  const legacy = await legacyHost(t);
  const current = await legacyHost(t);
  await keyringData(current);
  for (const host of [legacy, current]) {
    fs.writeFileSync(path.join(host.root, 'etc/orbit-credential.key'), `${keyA}\n`, {
      mode: 0o400,
    });
    fs.writeFileSync(
      unitFile(host),
      fs.readFileSync(unitFile(host), 'utf8').replace('[Service]\n', `[Service]\n${line}\n`)
    );
    const before = keyState(host);
    const result = await host.install(makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }));
    assert.equal(result.status, 1, ok(result));
    assert.match(result.stderr, refusal);
    assert.doesNotMatch(result.stdout, /Preparing pinned application dependencies/);
    assert.deepEqual(keyState(host), before, 'nothing on the host changed');
    assert.ok(fs.readFileSync(unitFile(host), 'utf8').includes(line), 'the unit keeps it');
    assert.ok(!fs.existsSync(host.path('var/lib/uptime-goblin/secret.key')), 'no key generated');
  }
  // In a drop-in as well (the same assignment), it survives the new unit: accepted.
  fs.mkdirSync(legacy.path('etc/systemd/system/uptime-goblin.service.d'), { recursive: true });
  fs.writeFileSync(
    legacy.path('etc/systemd/system/uptime-goblin.service.d/key.conf'),
    `[Service]\n${line}\n`
  );
  const env = envText(legacy);
  const both = await legacy.install(makeSource(t, { version: '1.5.0-test.2', mode: 'ok' }));
  assert.equal(both.status, 0, ok(both));
  assert.match(
    both.stdout,
    /^Encryption key: the systemd credential orbit-secret-key \(\/etc\/orbit-credential\.key\)\.$/m
  );
  assert.equal(envText(legacy), env, 'no GOBLIN_SECRET_KEY_FILE line, which would outrank it');
  assert.ok(!fs.readFileSync(unitFile(legacy), 'utf8').includes('LoadCredential'), 'new unit');
  assert.ok(!fs.existsSync(legacy.path('var/lib/uptime-goblin/secret.key')));
  // Moved to a drop-in that a 1.5 install then reads: accepted, and checked against the data.
  fs.mkdirSync(current.path('etc/systemd/system/uptime-goblin.service.d'), { recursive: true });
  fs.writeFileSync(
    current.path('etc/systemd/system/uptime-goblin.service.d/key.conf'),
    `[Service]\n${line}\n`
  );
  fs.writeFileSync(
    unitFile(current),
    fs.readFileSync(unitFile(current), 'utf8').replace(`${line}\n`, '')
  );
  const moved = await current.install(makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }));
  assert.equal(moved.status, 0, ok(moved));
  // A drop-in that clears the unit's credential (LoadCredential=) leaves none to lose: the
  // installer goes on as without one.
  const cleared = await legacyHost(t);
  fs.writeFileSync(
    unitFile(cleared),
    fs.readFileSync(unitFile(cleared), 'utf8').replace('[Service]\n', `[Service]\n${line}\n`)
  );
  fs.mkdirSync(cleared.path('etc/systemd/system/uptime-goblin.service.d'), { recursive: true });
  fs.writeFileSync(
    cleared.path('etc/systemd/system/uptime-goblin.service.d/key.conf'),
    '[Service]\nLoadCredential=\n'
  );
  const none = await cleared.install(makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }));
  assert.equal(none.status, 0, ok(none));
  assert.match(none.stdout, /Created the encryption key/);
});

// SetCredential= carries the key itself. The refusal of one in uptime-goblin.service printed it (to
// stderr, and so into whatever keeps the install's output), a drop-in holding it (mode 0644 when
// made with systemctl edit) passed without the warning GOBLIN_SECRET_KEY gets, and its key was
// never checked against the data although the installer had it (delivery spec A48).
const keyDropIn = host => host.path('etc/systemd/system/uptime-goblin.service.d/key.conf');
function writeKeyDropIn(host, lines) {
  fs.mkdirSync(path.dirname(keyDropIn(host)), { recursive: true });
  fs.writeFileSync(keyDropIn(host), `[Service]\n${lines.join('\n')}\n`);
}
const hasLine = (text, line) => text.split('\n').includes(line);
const setLabel =
  'the systemd credential orbit-secret-key (SetCredential= in /etc/systemd/system/uptime-goblin.service.d/key.conf)';
const setWarning =
  "WARNING: SetCredential=orbit-secret-key in /etc/systemd/system/uptime-goblin.service.d/key.conf keeps Uptime Goblin's encryption key in plain text: a drop-in made with sudo systemctl edit can be read by every local account (mode 0644), and systemd's manual says not to use SetCredential= for secrets. Put the key in a file only root can read and name it instead (LoadCredential=orbit-secret-key:/etc/credstore/orbit-secret-key), or encrypt it (SetCredentialEncrypted=), then remove the SetCredential= line: see 'Encryption key' in docs/installation.md.";
const setMismatch = `The encryption key from ${setLabel} (fingerprint ${fingerprintOf(keyB)}) does not open Uptime Goblin's data in /var/lib/uptime-goblin. Restore the key that data was created with (see 'Encryption key' in docs/installation.md) and run this installer again. Nothing was changed.`;
// An install that must refuse with `message` (a whole line of stderr), changing nothing and
// printing no key. Its release may be older than the one installed by then: --allow-downgrade
// lets it reach the key check.
async function refusedWith(t, host, message) {
  const before = keyState(host);
  const result = await host.install(makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }), [
    '--allow-downgrade',
  ]);
  assert.equal(result.status, 1, ok(result));
  assert.ok(hasLine(result.stderr, message), result.stderr);
  assert.doesNotMatch(result.stdout, /Preparing pinned application dependencies/);
  assert.deepEqual(keyState(host), before, 'nothing on the host changed');
  for (const key of [keyA, keyB]) assert.ok(!result.output.includes(key), 'no key is printed');
  return result;
}

test('a SetCredential= in uptime-goblin.service itself is refused without printing its value', async t => {
  const unitFile = host => host.path('etc/systemd/system/uptime-goblin.service');
  // An encrypted credential is no secret without the host's key, but long: not printed either.
  const sealed = Buffer.from(`made-up sealed credential ${keyA}`).toString('base64');
  for (const [setting, value] of [
    ['SetCredential', keyA],
    ['SetCredentialEncrypted', sealed],
  ]) {
    const host = await legacyHost(t);
    await keyringData(host);
    fs.writeFileSync(
      unitFile(host),
      fs
        .readFileSync(unitFile(host), 'utf8')
        .replace('[Service]\n', `[Service]\n${setting}=orbit-secret-key:${value}\n`)
    );
    const result = await refusedWith(
      t,
      host,
      `The systemd credential orbit-secret-key is set in /etc/systemd/system/uptime-goblin.service itself (${setting}=orbit-secret-key:…), which this installer replaces with its own uptime-goblin.service, so Uptime Goblin would lose its key. Move that line into a drop-in (sudo systemctl edit uptime-goblin), then run this installer again. Nothing was changed.`
    );
    assert.ok(!result.output.includes(value), `the ${setting} value is not printed`);
  }
});

test('a SetCredential= key in a drop-in is checked against the data before anything changes, never printed, and warned about', async t => {
  const host = await legacyHost(t);
  await keyringData(host);
  const env = envText(host);
  // The wrong key, also when written with the "\n" escape systemd undoes ("<key>\n").
  writeKeyDropIn(host, [`SetCredential=orbit-secret-key:${keyB}`]);
  await refusedWith(t, host, setMismatch);
  writeKeyDropIn(host, [`SetCredential=orbit-secret-key:${keyB}\\n`]);
  await refusedWith(t, host, setMismatch);
  // No key at all: Uptime Goblin would refuse to start (key_invalid), after the old one was stopped.
  writeKeyDropIn(host, ['SetCredential=orbit-secret-key:not-a-key']);
  await refusedWith(
    t,
    host,
    `The encryption key from ${setLabel} is not valid: ${setLabel} must be 32 random bytes written as 64 hexadecimal digits or in base64 (for example the output of "openssl rand -hex 32"). Nothing was changed.`
  );
  // The key that opens the data: kept as it is, named, and warned about.
  writeKeyDropIn(host, [`SetCredential=orbit-secret-key:${keyA}`]);
  const result = await host.install(makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }));
  assert.equal(result.status, 0, ok(result));
  assert.ok(hasLine(result.stdout, `Encryption key: ${setLabel}.`), result.stdout);
  assert.ok(hasLine(result.stderr, setWarning), result.stderr);
  assert.ok(!result.output.includes(keyA), 'the key is not printed');
  assert.equal(envText(host), env, 'no GOBLIN_SECRET_KEY_FILE line, which would outrank it');
  assert.ok(!fs.existsSync(host.path('etc/uptime-goblin')));
});

test('SetCredential= is read in the order systemd reads it: a LoadCredential= file outranks it, a missing one falls back to it, an empty SetCredential= clears it', async t => {
  const host = await legacyHost(t);
  await keyringData(host);
  fs.writeFileSync(path.join(host.root, 'etc/credential.key'), `${keyA}\n`, { mode: 0o400 });
  let version = 0;
  const install = () =>
    host.install(makeSource(t, { version: `1.5.0-test.${++version}`, mode: 'ok' }));
  // A LoadCredential= file outranks SetCredential= wherever it comes: its key is the one
  // checked, and the plain-text key beside it is still warned about.
  writeKeyDropIn(host, [
    'LoadCredential=orbit-secret-key:/etc/credential.key',
    `SetCredential=orbit-secret-key:${keyB}`,
  ]);
  const outranked = await install();
  assert.equal(outranked.status, 0, ok(outranked));
  assert.ok(
    hasLine(
      outranked.stdout,
      'Encryption key: the systemd credential orbit-secret-key (/etc/credential.key).'
    ),
    outranked.stdout
  );
  assert.ok(hasLine(outranked.stderr, setWarning), outranked.stderr);
  // A LoadCredential= file that is not there: systemd passes the SetCredential= value instead.
  writeKeyDropIn(host, [
    `SetCredential=orbit-secret-key:${keyB}`,
    'LoadCredential=orbit-secret-key:/etc/missing.key',
  ]);
  await refusedWith(t, host, setMismatch);
  writeKeyDropIn(host, [
    `SetCredential=orbit-secret-key:${keyA}`,
    'LoadCredential=orbit-secret-key:/etc/missing.key',
  ]);
  const fallback = await install();
  assert.equal(fallback.status, 0, ok(fallback));
  assert.ok(hasLine(fallback.stdout, `Encryption key: ${setLabel}.`), fallback.stdout);
  // An empty SetCredential= clears what came before it: no key is left for the keyring.
  writeKeyDropIn(host, [`SetCredential=orbit-secret-key:${keyA}`, 'SetCredential=']);
  await refusedWith(
    t,
    host,
    "Uptime Goblin's data in /var/lib/uptime-goblin is encrypted with a key that is not on this host (no GOBLIN_SECRET_KEY, GOBLIN_SECRET_KEY_FILE, systemd credential, /etc/uptime-goblin/secret.key or /var/lib/uptime-goblin/secret.key). Restore /etc/uptime-goblin/secret.key from your backup where the uptime-goblin account can read it (sudo install -d -o root -g uptime-goblin -m 0750 /etc/uptime-goblin, then sudo install -o root -g uptime-goblin -m 0440 KEY_BACKUP_FILE /etc/uptime-goblin/secret.key, with KEY_BACKUP_FILE replaced by the path of your backup) and run this installer again. Only if the key is truly lost: see 'Lost encryption key' in docs/troubleshooting.md. Nothing was changed."
  );
  // ImportCredential= outranks it with what the credential stores hold, which the installer
  // does not read: not checked, still warned about.
  writeKeyDropIn(host, ['ImportCredential=orbit-*', `SetCredential=orbit-secret-key:${keyB}`]);
  const imported = await install();
  assert.equal(imported.status, 0, ok(imported));
  assert.ok(
    hasLine(
      imported.stdout,
      'Encryption key: the systemd credential orbit-secret-key (SetCredential). It could not be checked against the data; Uptime Goblin checks it at start.'
    ),
    imported.stdout
  );
  assert.ok(hasLine(imported.stderr, setWarning), imported.stderr);
  // An encrypted value is no plain text: no warning.
  writeKeyDropIn(host, ['SetCredentialEncrypted=orbit-secret-key:c2VhbGVk']);
  const sealed = await install();
  assert.equal(sealed.status, 0, ok(sealed));
  assert.doesNotMatch(sealed.stderr, /WARNING: SetCredential/);
  // GOBLIN_SECRET_KEY_FILE outranks every credential, but the plain-text key is still there.
  fs.writeFileSync(path.join(host.root, 'srv-orbit.key'), `${keyA}\n`, { mode: 0o440 });
  fs.appendFileSync(host.path('etc/uptime-goblin.env'), 'GOBLIN_SECRET_KEY_FILE=/srv-orbit.key\n');
  writeKeyDropIn(host, [`SetCredential=orbit-secret-key:${keyB}`]);
  const outrankedByFile = await install();
  assert.equal(outrankedByFile.status, 0, ok(outrankedByFile));
  assert.ok(hasLine(outrankedByFile.stderr, setWarning), outrankedByFile.stderr);
  assert.ok(!outrankedByFile.output.includes(keyB), 'the key is not printed');
});

test('a key Uptime Goblin generated in the data directory is copied to /etc/uptime-goblin, synced before the rename and the env line', async t => {
  const host = await makeHost(t);
  fs.mkdirSync(host.path('var/lib/uptime-goblin'), { recursive: true, mode: 0o700 });
  await keyringData(host, keyA);
  fs.writeFileSync(host.path('var/lib/uptime-goblin/secret.key'), `${keyA}\n`, { mode: 0o600 });
  const result = await host.install(makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }));
  assert.equal(result.status, 0, ok(result));
  assert.equal(fs.readFileSync(host.path('etc/uptime-goblin/secret.key'), 'utf8'), `${keyA}\n`);
  assert.equal(fs.statSync(host.path('etc/uptime-goblin/secret.key')).mode & 0o777, 0o440);
  assert.ok(envText(host).endsWith(`${keyComment}\n${keyLine}\n`));
  // A67: the message gives the line that deletes the data directory's copy, which checks that
  // it is one (it said only "then delete /var/lib/uptime-goblin/secret.key").
  const removal =
    /^Copied the encryption key to \/etc\/uptime-goblin\/secret\.key\. Back that file up separately\. Once Uptime Goblin has started, delete \/var\/lib\/uptime-goblin\/secret\.key, which would otherwise travel with every backup of the data directory, with this line, which deletes it only while \/etc\/uptime-goblin\/secret\.key holds the same key and opens the data: (sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=\/etc\/uptime-goblin\/secret\.key node \/opt\/uptime-goblin\/lib\/cli\/goblin-admin\.mjs key remove-data-copy --data-dir \/var\/lib\/uptime-goblin)$/m.exec(
      result.stdout
    );
  assert.ok(removal, result.stdout);
  const syncs = syncLog(host);
  assert.match(syncs[0], /\.secret\.key\.\w+ key=no env=no$/);
  assert.equal(syncs[1], `${host.path('etc/uptime-goblin')} key=yes env=no`);
  // The data-directory copy is left for the admin to delete once the backup is made.
  assert.ok(fs.existsSync(host.path('var/lib/uptime-goblin/secret.key')));
  // That line, run as printed (as the uptime-goblin account, here this test's user; the host's paths
  // under the test's root, and this tree's goblin-admin in place of /opt/uptime-goblin's): it deletes the
  // copy, and only it, while Uptime Goblin runs (goblin.lock held).
  const { main } = await import('../../lib/cli/goblin-admin.mjs');
  const words = removal[1].split(' ');
  assert.deepEqual(words.slice(0, 5), [
    'sudo',
    '-u',
    'uptime-goblin',
    'env',
    'GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key',
  ]);
  const onHost = word => (word.startsWith('/') ? host.path(word.slice(1)) : word);
  const args = words.slice(7).map(onHost);
  let out = '',
    err = '';
  const lock = acquireLock(host.path('var/lib/uptime-goblin'));
  try {
    const code = await main(args, {
      env: { GOBLIN_SECRET_KEY_FILE: onHost('/etc/uptime-goblin/secret.key') },
      uid: 1000,
      container: false,
      keySources: {
        credentialsDirectory: host.path('nonexistent'),
        secretsDirectory: host.path('nonexistent'),
      },
      stdout: text => (out += text),
      stderr: text => (err += text),
    });
    assert.equal(code, 0, err);
  } finally {
    lock.release();
  }
  assert.match(
    out,
    /^Deleted \S+\/var\/lib\/uptime-goblin\/secret\.key: GOBLIN_SECRET_KEY_FILE \(\S+\/etc\/uptime-goblin\/secret\.key\) holds the same key/
  );
  assert.equal(fs.existsSync(host.path('var/lib/uptime-goblin/secret.key')), false);
  assert.equal(fs.readFileSync(host.path('etc/uptime-goblin/secret.key'), 'utf8'), `${keyA}\n`);
});

// The uptime-goblin account owns /var/lib/uptime-goblin and can replace any file there with a symbolic link at
// any moment: to /etc/shadow, say, between the installer's check of secret.key and its copy (a
// process of that account can wait for root's read, which changes the file's access time, as
// the review's probe did under real root). /etc/uptime-goblin/secret.key, which the uptime-goblin group reads,
// must then hold the key that was checked, never the target. Here the swap is made as npm ci
// runs, between the two.
test('a data-directory key swapped for a symbolic link after the installer checked it: /etc/uptime-goblin/secret.key holds the checked key, never the target', async t => {
  const host = await makeHost(t);
  await keyringData(host, keyA);
  const key = host.path('var/lib/uptime-goblin/secret.key');
  fs.writeFileSync(key, `${keyA}\n`, { mode: 0o600 });
  // Stands for /etc/shadow or an ssh host key: outside the data directory, root's alone.
  const rootOnly = path.join(host.base, 'root-only.txt');
  fs.writeFileSync(rootOnly, 'ROOT-ONLY-MARKER\n', { mode: 0o600 });
  const bin = path.join(host.base, 'bin');
  fs.renameSync(path.join(bin, 'npm'), path.join(bin, 'npm-offline'));
  fs.writeFileSync(
    path.join(bin, 'npm'),
    '#!/bin/sh\nln -sfn "$SWAP_TARGET" "$SWAP_LINK" || exit 1\nexec "$(dirname "$0")/npm-offline" "$@"\n',
    { mode: 0o755 }
  );
  const result = await host.install(makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }), [], {
    SWAP_TARGET: rootOnly,
    SWAP_LINK: key,
  });
  assert.equal(result.status, 0, ok(result));
  assert.equal(fs.readlinkSync(key), rootOnly, 'the swap happened, after the check');
  const copied = fs.readFileSync(host.path('etc/uptime-goblin/secret.key'), 'utf8');
  assert.doesNotMatch(copied, /ROOT-ONLY-MARKER/);
  assert.equal(copied, `${keyA}\n`);
  assert.equal(fs.statSync(host.path('etc/uptime-goblin/secret.key')).mode & 0o777, 0o440);
  assert.ok(envText(host).endsWith(`${keyComment}\n${keyLine}\n`));
  assert.match(
    result.stdout,
    /^Copied the encryption key to \/etc\/uptime-goblin\/secret\.key\. /m
  );
  assert.deepEqual(
    fs.readdirSync(host.path('etc/uptime-goblin')),
    ['secret.key'],
    'no temporary file'
  );
});

test('the key copied out of the data directory is never written beside the private copy of control.sqlite', async t => {
  const source = makeSource(t, { version: '1.5.0-test.1', mode: 'ok' });
  const host = await makeHost(t);
  await keyringData(host, keyA);
  fs.writeFileSync(host.path('var/lib/uptime-goblin/secret.key'), `${keyA}\n`, { mode: 0o600 });
  // Every node the installer starts loads this: it notes a data.key written while the copy of
  // control.sqlite it was checked against is still in the same private directory, which a run
  // killed at that moment would have left in /tmp together.
  const marker = path.join(host.base, 'beside');
  const hook = path.join(host.base, 'beside-hook.mjs');
  fs.writeFileSync(
    hook,
    `import fs from 'node:fs';
     import path from 'node:path';
     import { syncBuiltinESMExports } from 'node:module';
     const write = fs.writeFileSync;
     fs.writeFileSync = function (file, ...rest) {
       if (typeof file === 'string' && path.basename(file) === 'data.key' && fs.existsSync(path.join(path.dirname(file), 'copy')))
         write(${JSON.stringify(marker)}, 'beside');
       return write.call(this, file, ...rest);
     };
     syncBuiltinESMExports();`
  );
  const installed = await host.install(source, [], {
    NODE_OPTIONS: `--import=${pathToFileURL(hook).href}`,
  });
  assert.equal(installed.status, 0, ok(installed));
  assert.equal(fs.readFileSync(host.path('etc/uptime-goblin/secret.key'), 'utf8'), `${keyA}\n`);
  assert.equal(fs.existsSync(marker), false, 'data.key was written beside the copy of the data');
});

// A SetCredential= drop-in puts the key itself in the unit's text, which the installer saves
// (systemctl cat) in the same private directory as the copy of control.sqlite it checks the key
// against: until a run ended, both were there, so a run killed meanwhile (the EXIT trap does not
// run on SIGKILL) left the key and a copy of the data it opens together in /tmp.
test('the unit text, with a SetCredential= key, is gone before the installer copies control.sqlite beside it', async t => {
  const host = await legacyHost(t);
  await keyringData(host);
  writeKeyDropIn(host, [`SetCredential=orbit-secret-key:${keyA}`]);
  // Every node the installer starts loads this: when the copy of control.sqlite is opened, it
  // notes each file beside the copy's directory that holds the key.
  const marker = path.join(host.base, 'beside');
  const hook = path.join(host.base, 'unit-hook.mjs');
  fs.writeFileSync(
    hook,
    `import fs from 'node:fs';
     import path from 'node:path';
     import { syncBuiltinESMExports } from 'node:module';
     const open = fs.openSync;
     fs.openSync = function (file, ...rest) {
       if (typeof file === 'string' && file.endsWith(path.join('copy', 'control.sqlite'))) {
         const directory = path.dirname(path.dirname(file));
         for (const name of fs.readdirSync(directory)) {
           const entry = path.join(directory, name);
           if (fs.statSync(entry).isFile() && fs.readFileSync(entry, 'utf8').includes(${JSON.stringify(keyA)}))
             fs.appendFileSync(${JSON.stringify(marker)}, name + '\\n');
         }
       }
       return open.call(this, file, ...rest);
     };
     syncBuiltinESMExports();`
  );
  const result = await host.install(makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }), [], {
    NODE_OPTIONS: `--import=${pathToFileURL(hook).href}`,
  });
  assert.equal(result.status, 0, ok(result));
  assert.ok(hasLine(result.stdout, `Encryption key: ${setLabel}.`), result.stdout);
  assert.ok(!result.output.includes(keyA), 'the key is not printed');
  assert.equal(
    fs.existsSync(marker) ? fs.readFileSync(marker, 'utf8') : '',
    '',
    'a file holding the key was beside the copy of the data'
  );
});

// copyData checks the size before it copies (the test below) and again while it copies, since
// the uptime-goblin account's Uptime Goblin may still be writing the file. Here every read of control.sqlite is
// 1 MiB more, as from a file that keeps growing, and the copy's writes are dropped, so the test
// writes nothing: the copy must stop at 1 GiB, and the installer refuse with nothing changed.
test('a control.sqlite that grows past 1 GiB while the installer copies it is refused with nothing changed', async t => {
  const source = makeSource(t, { version: '1.5.0-test.1', mode: 'ok' });
  const host = await makeHost(t);
  await keyringData(host, keyA);
  fs.writeFileSync(host.path('var/lib/uptime-goblin/secret.key'), `${keyA}\n`, { mode: 0o600 });
  const hook = path.join(host.base, 'grow-hook.mjs');
  fs.writeFileSync(
    hook,
    `import fs from 'node:fs';
     import path from 'node:path';
     import { syncBuiltinESMExports } from 'node:module';
     const data = path.join('var', 'lib', 'uptime-goblin', 'control.sqlite');
     const copy = path.join('copy', 'control.sqlite');
     const growing = new Map(), dropped = new Set();
     const { openSync, readSync, writeSync, closeSync } = fs;
     fs.openSync = function (file, ...rest) {
       const descriptor = openSync.call(this, file, ...rest);
       if (typeof file === 'string' && file.endsWith(data)) growing.set(descriptor, 0);
       if (typeof file === 'string' && file.endsWith(copy)) dropped.add(descriptor);
       return descriptor;
     };
     // 1 MiB more at each read, up to 1100 MiB (then the end, so that a copy without the check
     // ends too, and the test fails instead of hanging).
     fs.readSync = function (descriptor, buffer, ...rest) {
       if (!growing.has(descriptor) || rest.length) return readSync.call(this, descriptor, buffer, ...rest);
       const reads = growing.get(descriptor);
       growing.set(descriptor, reads + 1);
       return reads < 1100 ? buffer.length : 0;
     };
     fs.writeSync = function (descriptor, buffer, ...rest) {
       if (!dropped.has(descriptor)) return writeSync.call(this, descriptor, buffer, ...rest);
       const [offset = 0, length = buffer.length - offset] = rest;
       return length;
     };
     fs.closeSync = function (descriptor) {
       growing.delete(descriptor);
       dropped.delete(descriptor);
       return closeSync.call(this, descriptor);
     };
     syncBuiltinESMExports();`
  );
  const before = keyState(host);
  const result = await host.install(
    source,
    [],
    { NODE_OPTIONS: `--import=${pathToFileURL(hook).href}` },
    { timeout: 120000 }
  );
  assert.equal(result.status, 1, ok(result));
  assert.equal(
    result.stderr.trim(),
    '/var/lib/uptime-goblin/control.sqlite grew past 1 GiB while the installer copied it. Nothing was changed.'
  );
  assert.doesNotMatch(result.stdout, /Preparing pinned application dependencies/);
  assert.deepEqual(keyState(host), before, 'nothing on the host changed');
});

test('a control.sqlite or control.sqlite-wal larger than 1 GiB is refused before the installer copies it to /tmp', async t => {
  const source = makeSource(t, { version: '1.5.0-test.1', mode: 'ok' });
  const host = await makeHost(t);
  await keyringData(host, keyA);
  const data = host.path('var/lib/uptime-goblin');
  fs.writeFileSync(path.join(data, 'secret.key'), `${keyA}\n`, { mode: 0o600 });
  for (const name of ['control.sqlite-wal', 'control.sqlite']) {
    // Sparse: as large as it says, without the disk space. Copied whole into /tmp (often memory)
    // to check the key, it could fill it.
    const file = path.join(data, name);
    const kept = fs.existsSync(file) ? fs.readFileSync(file) : null;
    const descriptor = fs.openSync(file, 'w', 0o600);
    fs.ftruncateSync(descriptor, 2 ** 30 + 1);
    fs.closeSync(descriptor);
    const before = keyState(host);
    const result = await host.install(source, [], {}, { timeout: 60000 });
    assert.equal(result.status, 1, ok(result));
    assert.match(
      result.stderr,
      new RegExp(
        `^/var/lib/uptime-goblin/${name.replace('.', '\\.')} is larger than 1 GiB, more than the installer copies`
      )
    );
    assert.deepEqual(keyState(host), before, `${name}: nothing on the host changed`);
    if (kept) fs.writeFileSync(file, kept, { mode: 0o600 });
    else fs.rmSync(file);
  }
});

test('a secret.key, control.sqlite or control.sqlite-wal in the data directory that is a symbolic link or not a regular file is refused with nothing changed, never followed or waited on', async t => {
  const source = makeSource(t, { version: '1.5.0-test.1', mode: 'ok' });
  const refusedAs = async (host, name, what) => {
    const before = keyState(host);
    // Bounded: before the fix, a FIFO held the installer for good.
    const result = await host.install(source, [], {}, { timeout: 30000 });
    assert.equal(result.status, 1, ok(result));
    assert.equal(
      result.stderr.trim(),
      `/var/lib/uptime-goblin/${name} is ${what}, which Uptime Goblin never makes. The installer runs as root, so in /var/lib/uptime-goblin, which the uptime-goblin account controls, it reads regular files only and never follows a link. Find out what put it there and put the real file in its place, then run this installer again. Nothing was changed.`
    );
    assert.doesNotMatch(result.stdout, /Preparing pinned application dependencies/);
    assert.deepEqual(keyState(host), before, 'nothing on the host changed');
    assert.ok(!fs.existsSync(host.path('etc/uptime-goblin')), 'no key provisioned');
  };
  // secret.key linked to a key outside the data directory, even the one that opens the data,
  // and then a link to nothing (never taken for "no key here").
  const linked = await makeHost(t);
  await keyringData(linked, keyA);
  const outside = path.join(linked.base, 'outside.key');
  fs.writeFileSync(outside, `${keyA}\n`, { mode: 0o600 });
  fs.symlinkSync(outside, linked.path('var/lib/uptime-goblin/secret.key'));
  await refusedAs(linked, 'secret.key', 'a symbolic link');
  fs.rmSync(outside);
  await refusedAs(linked, 'secret.key', 'a symbolic link');

  // secret.key as a FIFO, in data without a keyring yet: never waited on.
  const fifo = await makeHost(t);
  fs.mkdirSync(fifo.path('var/lib/uptime-goblin'), { recursive: true, mode: 0o700 });
  assert.equal(spawnSync('mkfifo', [fifo.path('var/lib/uptime-goblin/secret.key')]).status, 0);
  await refusedAs(fifo, 'secret.key', 'not a regular file');

  // control.sqlite as a link to the real database moved out of the data directory, then a
  // control.sqlite-wal that is a link.
  const db = await makeHost(t);
  await keyringData(db, keyA);
  const data = db.path('var/lib/uptime-goblin');
  fs.writeFileSync(path.join(data, 'secret.key'), `${keyA}\n`, { mode: 0o600 });
  const moved = path.join(db.base, 'control.sqlite');
  fs.renameSync(path.join(data, 'control.sqlite'), moved);
  fs.symlinkSync(moved, path.join(data, 'control.sqlite'));
  await refusedAs(db, 'control.sqlite', 'a symbolic link');
  fs.rmSync(path.join(data, 'control.sqlite'));
  fs.renameSync(moved, path.join(data, 'control.sqlite'));
  const wal = path.join(db.base, 'elsewhere-wal');
  fs.writeFileSync(wal, 'not a write-ahead log\n', { mode: 0o600 });
  fs.symlinkSync(wal, path.join(data, 'control.sqlite-wal'));
  await refusedAs(db, 'control.sqlite-wal', 'a symbolic link');
  // With the real files in place the same host installs, copying the key it checked as Uptime Goblin
  // writes one (64 hex digits), here from a key in base64.
  fs.rmSync(path.join(data, 'control.sqlite-wal'));
  fs.writeFileSync(
    path.join(data, 'secret.key'),
    `${Buffer.from(keyA, 'hex').toString('base64')}\n`,
    { mode: 0o600 }
  );
  const installed = await db.install(source);
  assert.equal(installed.status, 0, ok(installed));
  assert.equal(fs.readFileSync(db.path('etc/uptime-goblin/secret.key'), 'utf8'), `${keyA}\n`);
});

// Review round 3: a key file that /etc/uptime-goblin.env or a credential names inside /var/lib/uptime-goblin was
// accepted without a word, and read as root with a plain open, which followed a link the orbit
// account made (to any file root can read) and waited for good on a FIFO; systemd reads such a
// credential as root at every start. Now every one is refused before it is opened, and no key
// file anywhere is waited on.
test('a key file, previous key file or systemd credential in /var/lib/uptime-goblin is refused before it is opened, with nothing changed; no key file is waited on', async t => {
  const source = makeSource(t, { version: '1.5.0-test.1', mode: 'ok' });
  const head = (label, how = 'is in', reader = 'this installer, which runs as root,') =>
    `${label} ${how} /var/lib/uptime-goblin, Uptime Goblin's data directory, which the uptime-goblin account controls: every copy of the data directory would carry the key, and ${reader} would read a file there that the uptime-goblin account can replace at any moment with a link to another file or a FIFO.`;
  const copyOut = what =>
    `Remove ${what} and run this installer again: it then copies /var/lib/uptime-goblin/secret.key to /etc/uptime-goblin/secret.key (root:uptime-goblin, mode 0440), unless that file is already there, and names it in /etc/uptime-goblin.env. Nothing was changed.`;
  const moveOut =
    'Move the key to a file outside /var/lib/uptime-goblin that the uptime-goblin account can read (root:uptime-goblin, mode 0440, as /etc/uptime-goblin/secret.key is), name that file instead, then run this installer again. Nothing was changed.';
  const envLine =
    'the GOBLIN_SECRET_KEY_FILE line from /etc/uptime-goblin.env (sudoedit /etc/uptime-goblin.env)';
  const refused = async (host, text) => {
    const before = keyState(host);
    // Bounded: before the fix, a FIFO held the installer for good.
    const result = await host.install(source, [], {}, { timeout: 30000 });
    assert.equal(result.status, 1, ok(result));
    assert.equal(result.stderr.trim(), text);
    assert.doesNotMatch(result.stdout, /Preparing pinned application dependencies/);
    assert.deepEqual(keyState(host), before, 'nothing on the host changed');
    return result;
  };
  // Stands for /etc/shadow: outside the data directory, root's alone, not a key.
  const rootOnly = host => {
    const file = path.join(host.base, 'root-only.txt');
    fs.writeFileSync(file, 'ROOT-ONLY-MARKER\n', { mode: 0o600 });
    return file;
  };

  // GOBLIN_SECRET_KEY_FILE naming the key Uptime Goblin generated there (the right key for the data).
  const host = await makeHost(t);
  await keyringData(host, keyA);
  const data = host.path('var/lib/uptime-goblin');
  fs.writeFileSync(path.join(data, 'secret.key'), `${keyA}\n`, { mode: 0o600 });
  const env = envText(host);
  fs.appendFileSync(
    host.path('etc/uptime-goblin.env'),
    'GOBLIN_SECRET_KEY_FILE=/var/lib/uptime-goblin/secret.key\n'
  );
  const fileHead = head('GOBLIN_SECRET_KEY_FILE (/var/lib/uptime-goblin/secret.key)');
  await refused(host, `${fileHead} ${copyOut(envLine)}`);
  // The uptime-goblin account's link to another file in its place: refused the same, never followed.
  fs.rmSync(path.join(data, 'secret.key'));
  fs.symlinkSync(rootOnly(host), path.join(data, 'secret.key'));
  const linked = await refused(host, `${fileHead} ${copyOut(envLine)}`);
  assert.doesNotMatch(linked.output, /not valid/, 'the target was never read');
  // A FIFO in its place: refused at once, never waited on.
  fs.rmSync(path.join(data, 'secret.key'));
  assert.equal(spawnSync('mkfifo', [path.join(data, 'secret.key')]).status, 0);
  await refused(host, `${fileHead} ${copyOut(envLine)}`);
  // Another file in the data directory, and a directory on the way that is the uptime-goblin account's
  // link to a directory outside it.
  fs.rmSync(path.join(data, 'secret.key'));
  fs.writeFileSync(path.join(data, 'secret.key'), `${keyA}\n`, { mode: 0o600 });
  fs.mkdirSync(path.join(host.base, 'elsewhere'));
  fs.writeFileSync(path.join(host.base, 'elsewhere/orbit.key'), `${keyA}\n`, { mode: 0o440 });
  fs.symlinkSync(path.join(host.base, 'elsewhere'), path.join(data, 'keys'));
  fs.writeFileSync(
    host.path('etc/uptime-goblin.env'),
    `${env}GOBLIN_SECRET_KEY_FILE=/var/lib/uptime-goblin/keys/orbit.key\n`
  );
  await refused(
    host,
    `${head('GOBLIN_SECRET_KEY_FILE (/var/lib/uptime-goblin/keys/orbit.key)')} ${moveOut}`
  );
  // A key file outside it that is a link into it (root's link, the uptime-goblin account's file).
  fs.symlinkSync(path.join(data, 'secret.key'), host.path('etc/orbit-key.key'));
  fs.writeFileSync(
    host.path('etc/uptime-goblin.env'),
    `${env}GOBLIN_SECRET_KEY_FILE=/etc/orbit-key.key\n`
  );
  await refused(
    host,
    `${head('GOBLIN_SECRET_KEY_FILE (/etc/orbit-key.key)', 'leads, through a link, into')} ${copyOut(envLine)}`
  );
  // /etc/uptime-goblin/secret.key as such a link.
  fs.mkdirSync(host.path('etc/uptime-goblin'), { mode: 0o750 });
  fs.symlinkSync(path.join(data, 'secret.key'), host.path('etc/uptime-goblin/secret.key'));
  fs.writeFileSync(host.path('etc/uptime-goblin.env'), env);
  await refused(
    host,
    `${head('/etc/uptime-goblin/secret.key', 'leads, through a link, into')} ${copyOut('the link /etc/uptime-goblin/secret.key (sudo rm /etc/uptime-goblin/secret.key)')}`
  );
  // The previous key there.
  fs.rmSync(host.path('etc/uptime-goblin'), { recursive: true });
  fs.writeFileSync(path.join(data, 'old.key'), `${keyB}\n`, { mode: 0o600 });
  fs.writeFileSync(
    host.path('etc/uptime-goblin.env'),
    `${env}GOBLIN_SECRET_KEY_PREVIOUS_FILE=/var/lib/uptime-goblin/old.key\n`
  );
  await refused(
    host,
    `${head('GOBLIN_SECRET_KEY_PREVIOUS_FILE (/var/lib/uptime-goblin/old.key)')} ${moveOut}`
  );
  // The fix the first refusal gives: without the line, the key is copied out of the data
  // directory (as a regular file, step 5) and named, and the install goes on.
  fs.writeFileSync(host.path('etc/uptime-goblin.env'), env);
  const fixed = await host.install(source);
  assert.equal(fixed.status, 0, ok(fixed));
  assert.equal(fs.readFileSync(host.path('etc/uptime-goblin/secret.key'), 'utf8'), `${keyA}\n`);
  assert.ok(envText(host).endsWith(`${keyComment}\n${keyLine}\n`));

  // A systemd credential loaded from there, which systemd reads as root at every start.
  const credential = await legacyHost(t);
  await keyringData(credential, keyA);
  fs.writeFileSync(credential.path('var/lib/uptime-goblin/secret.key'), `${keyA}\n`, {
    mode: 0o600,
  });
  fs.mkdirSync(credential.path('etc/systemd/system/uptime-goblin.service.d'), { recursive: true });
  fs.writeFileSync(
    credential.path('etc/systemd/system/uptime-goblin.service.d/key.conf'),
    '[Service]\nLoadCredential=orbit-secret-key:/var/lib/uptime-goblin/secret.key\n'
  );
  await refused(
    credential,
    `${head('The systemd credential orbit-secret-key (/var/lib/uptime-goblin/secret.key)', 'is in', 'systemd (as root, at every start of Uptime Goblin) and this installer')} ${copyOut('the LoadCredential line for orbit-secret-key from its drop-in (sudo systemctl edit uptime-goblin)')}`
  );
  // Encrypted: the installer cannot read it, but systemd reads the file as root all the same.
  fs.writeFileSync(
    credential.path('etc/systemd/system/uptime-goblin.service.d/key.conf'),
    '[Service]\nLoadCredentialEncrypted=orbit-secret-key:/var/lib/uptime-goblin/orbit.cred\n'
  );
  await refused(
    credential,
    `${head('The systemd credential orbit-secret-key (/var/lib/uptime-goblin/orbit.cred)', 'is in', 'systemd (as root, at every start of Uptime Goblin)')} Move the credential to a file outside /var/lib/uptime-goblin that only root can read (in /etc/credstore, say), name that file in the drop-in instead (sudo systemctl edit uptime-goblin), then run this installer again. Nothing was changed.`
  );

  // A key file outside the data directory that is a FIFO: no key, said at once.
  const fifo = await makeHost(t);
  assert.equal(spawnSync('mkfifo', [fifo.path('srv-orbit.key')]).status, 0);
  fs.appendFileSync(fifo.path('etc/uptime-goblin.env'), 'GOBLIN_SECRET_KEY_FILE=/srv-orbit.key\n');
  await refused(
    fifo,
    'GOBLIN_SECRET_KEY_FILE (/srv-orbit.key) is not a regular file, so it holds no key. Name the key file itself, then run this installer again. Nothing was changed.'
  );
});

test('a key that does not open the data, or data whose key is nowhere, is refused with nothing changed', async t => {
  const source = makeSource(t, { version: '1.5.0-test.1', mode: 'ok' });
  const refused = async (host, pattern) => {
    const before = keyState(host);
    const result = await host.install(source);
    assert.equal(result.status, 1, ok(result));
    assert.match(result.stderr, pattern);
    assert.doesNotMatch(result.stdout, /Preparing pinned application dependencies/);
    assert.deepEqual(keyState(host), before, 'nothing on the host changed');
    return result;
  };
  const mismatch = label =>
    new RegExp(
      `^The encryption key from ${label.replace(/[()/.]/g, '\\$&')} \\(fingerprint ${fingerprintOf(keyB)}\\) does not open Uptime Goblin's data in /var/lib/uptime-goblin\\. Restore the key that data was created with \\(see 'Encryption key' in docs/installation\\.md\\) and run this installer again\\. Nothing was changed\\.$`,
      'm'
    );
  // A keyring and no key anywhere.
  const lost = await makeHost(t);
  await keyringData(lost);
  await refused(
    lost,
    /^Uptime Goblin's data in \/var\/lib\/uptime-goblin is encrypted with a key that is not on this host \(no GOBLIN_SECRET_KEY, GOBLIN_SECRET_KEY_FILE, systemd credential, \/etc\/uptime-goblin\/secret\.key or \/var\/lib\/uptime-goblin\/secret\.key\)\. Restore \/etc\/uptime-goblin\/secret\.key from your backup where the uptime-goblin account can read it \(sudo install -d -o root -g uptime-goblin -m 0750 \/etc\/uptime-goblin, then sudo install -o root -g uptime-goblin -m 0440 KEY_BACKUP_FILE \/etc\/uptime-goblin\/secret\.key, with KEY_BACKUP_FILE replaced by the path of your backup\) and run this installer again\. Only if the key is truly lost: see 'Lost encryption key' in docs\/troubleshooting\.md\. Nothing was changed\.$/m
  );
  // A stale /etc/uptime-goblin/secret.key (a reinstall over restored data).
  fs.mkdirSync(lost.path('etc/uptime-goblin'), { mode: 0o750 });
  fs.writeFileSync(lost.path('etc/uptime-goblin/secret.key'), `${keyB}\n`, { mode: 0o440 });
  await refused(lost, mismatch('/etc/uptime-goblin/secret.key'));
  // The right key there: the install goes on and names it.
  fs.rmSync(lost.path('etc/uptime-goblin/secret.key'));
  fs.writeFileSync(lost.path('etc/uptime-goblin/secret.key'), `${keyA}\n`, { mode: 0o440 });
  const right = await lost.install(source);
  assert.equal(right.status, 0, ok(right));
  assert.ok(envText(lost).endsWith(`${keyLine}\n`));

  // GOBLIN_SECRET_KEY_FILE naming a wrong key, or a file that is not there.
  const named = await makeHost(t);
  await keyringData(named);
  // Readable by the group uptime-goblin, so that the install with the previous key below can go on.
  fs.writeFileSync(path.join(named.root, 'wrong.key'), `${keyB}\n`, { mode: 0o440 });
  fs.appendFileSync(named.path('etc/uptime-goblin.env'), 'GOBLIN_SECRET_KEY_FILE=/wrong.key\n');
  await refused(named, mismatch('GOBLIN_SECRET_KEY_FILE (/wrong.key)'));
  fs.writeFileSync(
    named.path('etc/uptime-goblin.env'),
    envText(named).replace('/wrong.key', '/gone.key')
  );
  await refused(
    named,
    /^GOBLIN_SECRET_KEY_FILE in \/etc\/uptime-goblin\.env names \/gone\.key, which does not exist\. Restore the key file from your backup where the uptime-goblin account can read it \(sudo install -o root -g uptime-goblin -m 0440 KEY_BACKUP_FILE \/gone\.key, with KEY_BACKUP_FILE replaced by the path of your backup\), or remove the line to let the installer create a new key for data that has none yet, then run this installer again\. Nothing was changed\.$/m
  );
  // The previous key (a key change in progress) is accepted with the new one.
  fs.writeFileSync(
    named.path('etc/uptime-goblin.env'),
    `${envText(named).replace('/gone.key', '/wrong.key')}GOBLIN_SECRET_KEY_PREVIOUS=${keyA}\n`
  );
  const moving = await named.install(source);
  assert.equal(moving.status, 0, ok(moving));

  // A systemd credential drop-in the admin added to the installed unit, with the wrong key.
  const credential = await legacyHost(t);
  await keyringData(credential);
  fs.writeFileSync(path.join(credential.root, 'etc/credential.key'), keyB, { mode: 0o400 });
  fs.mkdirSync(credential.path('etc/systemd/system/uptime-goblin.service.d'), { recursive: true });
  fs.writeFileSync(
    credential.path('etc/systemd/system/uptime-goblin.service.d/key.conf'),
    '[Service]\nLoadCredential=orbit-secret-key:/etc/credential.key\n'
  );
  await refused(
    credential,
    mismatch('the systemd credential orbit-secret-key (/etc/credential.key)')
  );
  fs.rmSync(path.join(credential.root, 'etc/credential.key'));
  fs.writeFileSync(path.join(credential.root, 'etc/credential.key'), keyA, { mode: 0o400 });
  const credentialed = await credential.install(source);
  assert.equal(credentialed.status, 0, ok(credentialed));

  // GOBLIN_SECRET_KEY in the environment file that does not parse.
  const invalid = await makeHost(t);
  fs.appendFileSync(invalid.path('etc/uptime-goblin.env'), 'GOBLIN_SECRET_KEY=not-a-key\n');
  await refused(
    invalid,
    /^The encryption key from GOBLIN_SECRET_KEY in \/etc\/uptime-goblin\.env is not valid: .* Nothing was changed\.$/m
  );
});

// Uptime Goblin opens its key file as the uptime-goblin account; the key step reads it as root. A key restored
// the way docs/installation.md backed it up (sudo install -m 600 …) is root's alone: the upgrade
// stopped Uptime Goblin, 1.5 exited 78 (key_file_unreadable, EACCES), and the code it rolled back to
// failed the same way, leaving Uptime Goblin down (review round 2). The fake runuser reads the file modes
// as a host where the installer's chown made them root:uptime-goblin would (test/installer/fake-bin).
test('a key file the uptime-goblin account cannot read: /etc/uptime-goblin/secret.key goes back to root:uptime-goblin 0440, any other is refused before Uptime Goblin stops', async t => {
  const host = await makeHost(t);
  const first = await host.install(makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }));
  assert.equal(first.status, 0, ok(first));
  const home = host.path('etc/uptime-goblin'),
    key = host.path('etc/uptime-goblin/secret.key');
  const mode = file => fs.statSync(file).mode & 0o7777;
  const text = fs.readFileSync(key, 'utf8'),
    env = envText(host);
  // Restored from that backup, in a directory made private too.
  fs.chmodSync(key, 0o600);
  fs.chmodSync(home, 0o700);
  const repaired = await host.install(makeSource(t, { version: '1.5.0-test.2', mode: 'ok' }));
  assert.equal(repaired.status, 0, ok(repaired));
  assert.match(
    repaired.stdout,
    /^Gave \/etc\/uptime-goblin\/secret\.key to root:uptime-goblin, mode 0440, in \/etc\/uptime-goblin \(root:uptime-goblin, mode 0750\), so that the uptime-goblin account Uptime Goblin runs as can read it\.$/m
  );
  assert.deepEqual([mode(key), mode(home)], [0o440, 0o750]);
  assert.equal(fs.readFileSync(key, 'utf8'), text, 'the same key');
  assert.equal(envText(host), env, 'no line added');
  assert.equal(host.installedVersion(), '1.5.0-test.2');
  const checks = () =>
    fs.readFileSync(path.join(host.env.FAKE_SYSTEMD_DIR, 'runuser.log'), 'utf8').trimEnd();
  assert.equal(
    checks().split('\n').at(-1),
    `-u uptime-goblin -- test -r ${key}`,
    'checked as orbit'
  );
  // Once it is right, nothing is said.
  const again = await host.install(makeSource(t, { version: '1.5.0-test.3', mode: 'ok' }));
  assert.equal(again.status, 0, ok(again));
  assert.doesNotMatch(again.output, /Gave \/etc\/uptime-goblin/);

  // Any other key file Uptime Goblin opens is not the installer's to change: one the uptime-goblin account
  // cannot read is refused before Uptime Goblin stops, with the fix, and nothing changes.
  const next = makeSource(t, { version: '1.5.0-test.4', mode: 'ok' });
  const refused = async (file, label) => {
    const before = { ...keyState(host), mode: mode(host.path(file)) };
    const result = await host.install(next);
    assert.equal(result.status, 1, ok(result));
    assert.equal(
      result.stderr.trim(),
      `${label} cannot be read by the uptime-goblin account, which Uptime Goblin runs as, so Uptime Goblin would refuse to start (exit status 78, key_file_unreadable). Let the group uptime-goblin read it: sudo chown root:uptime-goblin ${file} && sudo chmod 0440 ${file}, in a directory the uptime-goblin account can enter (as /etc/uptime-goblin is, root:uptime-goblin 0750), then run this installer again. Uptime Goblin was not changed.`
    );
    assert.doesNotMatch(result.stdout, /Installing Uptime Goblin/);
    assert.deepEqual(
      { ...keyState(host), mode: mode(host.path(file)) },
      before,
      'nothing changed, and Uptime Goblin was not stopped'
    );
  };
  const named = file =>
    fs.writeFileSync(
      host.path('etc/uptime-goblin.env'),
      env.replace(`${keyLine}\n`, `GOBLIN_SECRET_KEY_FILE=${file}\n`)
    );
  // GOBLIN_SECRET_KEY_FILE naming a root-only file.
  fs.writeFileSync(host.path('srv-orbit.key'), text, { mode: 0o600 });
  named('/srv-orbit.key');
  await refused('/srv-orbit.key', 'GOBLIN_SECRET_KEY_FILE (/srv-orbit.key)');
  // The fix the message gives (the chown is the tests' fake): the install goes on.
  fs.chmodSync(host.path('srv-orbit.key'), 0o440);
  let passed = await host.install(next);
  assert.equal(passed.status, 0, ok(passed));
  assert.equal(host.installedVersion(), '1.5.0-test.4');
  // A file the group can read, in a directory the uptime-goblin account cannot enter.
  fs.mkdirSync(host.path('keys'), { mode: 0o700 });
  fs.writeFileSync(host.path('keys/orbit.key'), text, { mode: 0o440 });
  named('/keys/orbit.key');
  await refused('/keys/orbit.key', 'GOBLIN_SECRET_KEY_FILE (/keys/orbit.key)');
  // The decrypt-only previous key, which Uptime Goblin opens too.
  fs.writeFileSync(host.path('old.key'), `${keyA}\n`, { mode: 0o600 });
  fs.writeFileSync(
    host.path('etc/uptime-goblin.env'),
    `${env}GOBLIN_SECRET_KEY_PREVIOUS_FILE=/old.key\n`
  );
  await refused('/old.key', 'GOBLIN_SECRET_KEY_PREVIOUS_FILE (/old.key)');
  // /etc/uptime-goblin/secret.key as a link to a root-only file: the link is left as it is, and refused.
  fs.writeFileSync(host.path('root-only.key'), text, { mode: 0o600 });
  fs.rmSync(key);
  fs.symlinkSync(host.path('root-only.key'), key);
  fs.writeFileSync(host.path('etc/uptime-goblin.env'), env);
  await refused(
    '/etc/uptime-goblin/secret.key',
    'GOBLIN_SECRET_KEY_FILE (/etc/uptime-goblin/secret.key)'
  );
  assert.equal(mode(host.path('root-only.key')), 0o600, 'never given away through a link');
  // Back to the installer's own file, root-only again: given back, and the install goes on.
  fs.rmSync(key);
  fs.writeFileSync(key, text, { mode: 0o600 });
  passed = await host.install(next);
  assert.equal(passed.status, 0, ok(passed));
  assert.equal(mode(key), 0o440);
});

test('a copy of control.sqlite that cannot be read refuses: never taken for data without a keyring', async t => {
  const host = await makeHost(t);
  await keyringData(host);
  // Torn mid-page, as a copy taken while Uptime Goblin writes can be.
  const file = host.path('var/lib/uptime-goblin/control.sqlite');
  const settle = new DatabaseSync(file);
  settle.exec('PRAGMA wal_checkpoint(TRUNCATE)');
  settle.close();
  for (const extra of ['-wal', '-shm']) fs.rmSync(file + extra, { force: true });
  fs.truncateSync(file, Math.floor(fs.statSync(file).size / 2) + 100);
  const before = keyState(host);
  const result = await host.install(makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }));
  assert.equal(result.status, 1, ok(result));
  assert.match(
    result.stderr,
    /^Could not tell whether Uptime Goblin's data in \/var\/lib\/uptime-goblin has an encryption keyring \(\w+\)\. Nothing was changed\. Run the installer again; if this repeats, stop Uptime Goblin first \(systemctl stop uptime-goblin\), then run it again\.$/m
  );
  assert.deepEqual(keyState(host), before, 'nothing changed, no key generated');
  assert.ok(!fs.existsSync(host.path('etc/uptime-goblin')));
});

test('The reference deploy wrapper invocation on a 1.4.3 install provisions the key', async t => {
  const wrapperArgs = ['--trust-proxy', 'loopback', '--allow-loopback'];
  for (const checked of [false, true]) {
    const host = await legacyHost(t, wrapperArgs);
    assert.ok(!fs.existsSync(host.path('etc/uptime-goblin')));
    // What the wrapper does: --proxy-proto-checked when 1.4.3 recorded https; without it the
    // installer reads the same record itself.
    if (!checked) observe(host, status => ({ ...status, observed: { forwardedProto: 'https' } }));
    const result = await host.install(
      makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }),
      checked ? [...wrapperArgs, '--proxy-proto-checked'] : wrapperArgs
    );
    assert.equal(result.status, 0, ok(result));
    const env = envText(host);
    assert.match(env, /^GOBLIN_TRUST_PROXY=loopback$/m);
    assert.match(env, /^GOBLIN_ALLOW_LOOPBACK=1$/m);
    assert.ok(env.endsWith(`${keyComment}\n${keyLine}\n`), env);
    assert.match(
      fs.readFileSync(host.path('etc/uptime-goblin/secret.key'), 'utf8'),
      /^[0-9a-f]{64}\n$/
    );
    assert.match(
      result.stdout,
      /^Encryption key: \/etc\/uptime-goblin\/secret\.key\. Back it up separately from \/var\/lib\/uptime-goblin\.$/m
    );
    assert.equal(host.installedVersion(), '1.5.0-test.1');
  }
});

// An installer run the test can watch and signal while it runs: `waitFor` resolves once its
// output matches, `signal` sends one to the installer's shell alone (not to the commands it
// started), and `exited` resolves with its status once it ends and its output is read. Its own
// process group, so that anything left of it is killed when the test ends.
function startInstaller(t, host, source, args = []) {
  const child = spawn('bash', [path.join(source, 'deploy/install.sh'), ...args], {
    env: host.env,
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: true,
  });
  let stdout = '',
    stderr = '';
  const waiters = new Set();
  const check = () => {
    for (const waiter of waiters)
      if (waiter.pattern.test(stdout + stderr)) {
        waiters.delete(waiter);
        waiter.done();
      }
  };
  child.stdout.on('data', chunk => ((stdout += chunk), check()));
  child.stderr.on('data', chunk => ((stderr += chunk), check()));
  const started = Date.now();
  const closed = new Promise(resolve => child.on('close', resolve));
  const exited = new Promise(resolve =>
    child.on('exit', async status => {
      const ms = Date.now() - started;
      // A command the shell started can keep the pipes open after it ends.
      await Promise.race([closed, delay(2000)]);
      resolve({ status, ms, stdout, stderr, output: stdout + stderr });
    })
  );
  t.after(() => {
    try {
      process.kill(-child.pid, 'SIGKILL');
    } catch {}
  });
  return {
    pid: child.pid,
    output: () => stdout + stderr,
    signal: name => process.kill(child.pid, name),
    exited,
    waitFor: (pattern, ms = 60000) =>
      new Promise((resolve, reject) => {
        const timer = setTimeout(
          () => reject(new Error(`no ${pattern} within ${ms} ms:\n${stdout + stderr}`)),
          ms
        );
        waiters.add({ pattern, done: () => (clearTimeout(timer), resolve()) });
        check();
      }),
  };
}

test('an older release over a newer one is refused before anything changes, unless --allow-downgrade is given (IUR-05)', async t => {
  const host = await makeHost(t);
  const newer = makeSource(t, { version: '1.4.3-test.2', mode: 'ok' });
  const first = await host.install(newer);
  assert.equal(first.status, 0, ok(first));
  const older = makeSource(t, { version: '1.4.3-test.1', mode: 'ok', change: 'older' });
  const calls = host.calls(),
    pid = host.state().pid;
  const refused = await host.install(older);
  assert.equal(refused.status, 2, ok(refused));
  assert.match(
    refused.stderr,
    /^Uptime Goblin 1\.4\.3-test\.2 is installed, and this release, 1\.4\.3-test\.1, is older\. Nothing was changed\. .* run this installer again with --allow-downgrade\.$/m
  );
  assert.doesNotMatch(refused.stdout, /Preparing|Installing/);
  assert.equal(host.calls(), calls, 'systemctl was not called');
  assert.equal(host.installedVersion(), '1.4.3-test.2');
  assert.ok(!fs.existsSync(host.path('opt/uptime-goblin.previous')));
  assert.ok(!fs.existsSync(host.path('opt/uptime-goblin.new')));
  assert.equal(host.state().pid, pid, 'the running service was not touched');
  // A pre-release is older than its release, as Uptime Goblin orders them (compareReleases).
  const release = makeSource(t, { version: '1.4.3', mode: 'ok', change: 'release' });
  const upgraded = await host.install(release);
  assert.equal(upgraded.status, 0, ok(upgraded));
  const back = await host.install(newer);
  assert.equal(back.status, 2, ok(back));
  assert.match(
    back.stderr,
    /^Uptime Goblin 1\.4\.3 is installed, and this release, 1\.4\.3-test\.2, is older\./m
  );
  // With the option it goes on, says so, and keeps the newer copy as the previous version.
  const allowed = await host.install(older, ['--allow-downgrade']);
  assert.equal(allowed.status, 0, ok(allowed));
  assert.match(
    allowed.stderr,
    /^WARNING: --allow-downgrade: installing Uptime Goblin 1\.4\.3-test\.1 over the newer Uptime Goblin 1\.4\.3\. /m
  );
  assert.equal(host.installedVersion(), '1.4.3-test.1');
  assert.equal(host.installedVersion('opt/uptime-goblin.previous'), '1.4.3');
  assert.equal(host.status().version, '1.4.3-test.1');
  // The same release again, and a newer one, need no option and get no warning.
  for (const source of [older, newer]) {
    const result = await host.install(source);
    assert.equal(result.status, 0, ok(result));
    assert.doesNotMatch(result.output, /downgrade|is older/);
  }
  // An installed version that is not a release: warned about, and the install goes on.
  const pkgFile = host.path('opt/uptime-goblin/package.json');
  const pkg = JSON.parse(fs.readFileSync(pkgFile, 'utf8'));
  fs.writeFileSync(pkgFile, JSON.stringify({ ...pkg, version: 'local build' }) + '\n');
  const unknown = await host.install(release);
  assert.equal(unknown.status, 0, ok(unknown));
  assert.match(
    unknown.stderr,
    /^WARNING: the installed version \(local\\ build in \/opt\/uptime-goblin\/package\.json\) is not a release this installer can compare, so it cannot tell whether Uptime Goblin 1\.4\.3 is older\. Going on\.$/m
  );
  assert.equal(host.installedVersion(), '1.4.3');
  // An installed tree without a version at all is warned about the same way, not skipped silently.
  const current = JSON.parse(fs.readFileSync(pkgFile, 'utf8'));
  delete current.version;
  fs.writeFileSync(pkgFile, JSON.stringify(current) + '\n');
  const none = await host.install(release);
  assert.equal(none.status, 0, ok(none));
  assert.match(
    none.stderr,
    /^WARNING: \S*\/opt\/uptime-goblin has no readable release version \(package\.json missing, unreadable or without one\), so this installer cannot tell whether Uptime Goblin 1\.4\.3 is older\. Going on\.$/m
  );
  assert.equal(host.installedVersion(), '1.4.3');
});

test('a second installer run while one is in progress stops before anything changes; the lock goes with the run (IUR-06)', async t => {
  const host = await makeHost(t);
  const first = await host.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }));
  assert.equal(first.status, 0, ok(first));
  // The first run waits for a release that never serves.
  const running = startInstaller(
    t,
    host,
    makeSource(t, { version: '1.4.3-test.2', mode: 'hang', change: 'hang' }),
    ['--verify-timeout', '30']
  );
  await running.waitFor(/Verifying that Uptime Goblin 1\.4\.3-test\.2 is serving/);
  const second = await host.install(
    makeSource(t, { version: '1.4.3-test.3', mode: 'ok', change: 'three' }),
    [],
    {},
    { timeout: 60000 }
  );
  assert.equal(second.status, 1, ok(second));
  assert.match(
    second.stderr,
    /^Another Uptime Goblin installer run is in progress on this host; wait for it to finish, then run this again\. Nothing was changed\.$/m
  );
  assert.doesNotMatch(second.stdout, /Preparing|Installing/);
  // The first run's switch stands as it made it.
  assert.equal(host.installedVersion(), '1.4.3-test.2');
  assert.equal(host.installedVersion('opt/uptime-goblin.previous'), '1.4.3-test.1');
  // Once the first run has ended, however it ended, the next one goes ahead.
  running.signal('SIGTERM');
  const ended = await running.exited;
  assert.equal(ended.status, 1, ended.output);
  const third = await host.install(
    makeSource(t, { version: '1.4.3-test.3', mode: 'ok', change: 'three' })
  );
  assert.equal(third.status, 0, ok(third));
  assert.equal(host.installedVersion(), '1.4.3-test.3');
});

test('SIGINT or SIGTERM during the verify wait restores the previous version at once; SIGHUP does not end the installer (IUR-04)', async t => {
  const host = await makeHost(t);
  const first = await host.install(makeSource(t, { version: '1.4.3-test.1', mode: 'ok' }));
  assert.equal(first.status, 0, ok(first));
  const timeout = 30;

  // SIGINT, as Ctrl-C sends it, to the installer's shell during the wait.
  const interrupted = startInstaller(
    t,
    host,
    makeSource(t, { version: '1.4.3-test.2', mode: 'hang', change: 'two' }),
    ['--verify-timeout', String(timeout)]
  );
  await interrupted.waitFor(/Verifying that Uptime Goblin 1\.4\.3-test\.2 is serving/);
  await delay(500);
  const sent = Date.now();
  interrupted.signal('SIGINT');
  const result = await interrupted.exited;
  assert.equal(result.status, 1, result.output);
  assert.ok(Date.now() - sent < (timeout * 1000) / 2, `ended ${Date.now() - sent} ms after SIGINT`);
  assert.match(result.stderr, /^The installer received SIGINT\. /m);
  assert.match(
    result.stderr,
    /^Uptime Goblin 1\.4\.3-test\.2 was not verified: the installer received SIGINT\. Service status and recent log:$/m
  );
  assert.match(
    result.stderr,
    /The previous version is running again; the upgrade to 1\.4\.3-test\.2 was rolled back\./
  );
  assert.equal(host.installedVersion(), '1.4.3-test.1');
  assert.equal(host.installedVersion('opt/uptime-goblin.failed'), '1.4.3-test.2');
  assert.equal(host.status().version, '1.4.3-test.1');
  assert.equal(host.status().pid, host.state().pid);
  assert.ok(!fs.existsSync(host.path('opt/uptime-goblin.new')));

  // SIGHUP, as a dropped SSH session sends it: the installer goes on, writing to its log, and a
  // SIGTERM after it rolls back as SIGINT did.
  const log = host.path('run/uptime-goblin-install.log');
  const hungUp = startInstaller(
    t,
    host,
    makeSource(t, { version: '1.4.3-test.3', mode: 'hang', change: 'three' }),
    ['--verify-timeout', String(timeout)]
  );
  await hungUp.waitFor(/Verifying that Uptime Goblin 1\.4\.3-test\.3 is serving/);
  await delay(500);
  hungUp.signal('SIGHUP');
  const still = await Promise.race([hungUp.exited, delay(1500).then(() => 'running')]);
  assert.equal(still, 'running', `the installer ended on SIGHUP: ${JSON.stringify(still)}`);
  assert.match(
    fs.readFileSync(log, 'utf8'),
    /^The installer received SIGHUP \(its terminal went away\) and goes on; its output follows\.$/m
  );
  assert.equal(host.installedVersion(), '1.4.3-test.3', 'still waiting on the new release');
  const termSent = Date.now();
  hungUp.signal('SIGTERM');
  const after = await hungUp.exited;
  assert.equal(after.status, 1, after.output);
  assert.ok(
    Date.now() - termSent < (timeout * 1000) / 2,
    `ended ${Date.now() - termSent} ms after SIGTERM`
  );
  const written = fs.readFileSync(log, 'utf8');
  assert.match(
    written,
    /^Uptime Goblin 1\.4\.3-test\.3 was not verified: the installer received SIGTERM\./m
  );
  assert.match(
    written,
    /The previous version is running again; the upgrade to 1\.4\.3-test\.3 was rolled back\./
  );
  assert.doesNotMatch(after.output, /rolled back/, 'nothing after the hangup went to the terminal');
  assert.equal(host.installedVersion(), '1.4.3-test.1');
  assert.equal(host.status().version, '1.4.3-test.1');
});
