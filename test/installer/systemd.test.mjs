// The installer and unit under a real systemd (Debian 13 in a privileged container):
// install (the encryption key provisioned as /etc/uptime-goblin/secret.key) → upgrade → a key restored
// root-only, and one elsewhere that the uptime-goblin account cannot read → failed verification and automatic rollback → an unexpected exit 0 is
// restarted → a refusal (exit 78) is not → Node moved to a new directory → a pre-1.4.3 unit
// with a vanished Node path is reported and repaired → reboot → the proxy preflight of the
// upgrade to 1.5 with Uptime Goblin stopped. Then, on a second host, the upgrade rehearsal of delivery
// spec §10 item 9: a real 1.4.3 install (tag v1.4.3) upgraded to this tree as the reference deploy
// wrapper runs the installer, which provisions /etc/uptime-goblin/secret.key.
// Needs the image from test/installer/systemd.Dockerfile and network access for npm ci. Skipped
// with a message when the image is missing, unless TEST_REQUIRE includes systemd.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { makeSource, repository, required, temporary } from './helpers.mjs';
import { installTag, skipWithoutTag } from '../upgrade/fixtures.mjs';
import { readManifest } from '../../scripts/check.mjs';
import fs from 'node:fs';
import path from 'node:path';

const image = 'orbit-installer-systemd:debian13';
const docker = (...args) => spawnSync('docker', args, { encoding: 'utf8', timeout: 300000 });
// Every test container is privileged (systemd needs that) and runs an install or a flood of
// processes, so each gets limits of its own, as Codex's maintenance systemd test gives it: 2 GiB
// of memory, 2 CPUs and 512 processes. Checked on the started container (Docker drops a limit
// the kernel cannot apply with only a warning). test/docker-limits.test.mjs checks that every
// container a test starts has them, right after the subcommand.
const limits = ['--memory', '2g', '--cpus', '2', '--pids-limit', '512'];
function assertLimited(name) {
  const host = JSON.parse(docker('inspect', name).stdout)[0].HostConfig;
  assert.deepEqual(
    { Memory: host.Memory, NanoCpus: host.NanoCpus, PidsLimit: host.PidsLimit },
    { Memory: 2 * 2 ** 30, NanoCpus: 2e9, PidsLimit: 512 },
    `${name} runs within its limits`
  );
}
let skip = false;
if (docker('version', '--format', '{{.Server.Version}}').status !== 0)
  skip = 'Docker is not available';
else if (docker('image', 'inspect', image).status !== 0)
  skip = `the ${image} image is not built (docker build --pull -t ${image} -f test/installer/systemd.Dockerfile test/installer; needs network access)`;
if (skip && required('systemd')) {
  const reason = skip;
  test('the real-systemd installer test can run (TEST_REQUIRE=systemd)', () =>
    assert.fail(`TEST_REQUIRE includes systemd, but ${reason}`));
  skip = 'reported as a failure above';
}

test('the installer and unit under real systemd', { skip, timeout: 900000 }, async t => {
  const name = `orbit-systemd-${randomBytes(4).toString('hex')}`;
  const started = docker(
    'run',
    ...limits,
    '--detach',
    '--name',
    name,
    '--privileged',
    '--cgroupns=host',
    '--volume',
    '/sys/fs/cgroup:/sys/fs/cgroup:rw',
    '--tmpfs',
    '/run:size=48m',
    '--tmpfs',
    '/run/lock',
    '--tmpfs',
    '/tmp',
    image
  );
  assert.equal(started.status, 0, started.stderr);
  t.after(() => docker('rm', '--force', '--volumes', name));
  assertLimited(name);
  const sh = script => docker('exec', name, 'bash', '-c', script);
  const out = script => {
    const result = sh(script);
    assert.equal(result.status, 0, `${script}\n${result.stdout}${result.stderr}`);
    return result.stdout.trim();
  };
  const booted = async () => {
    for (let i = 0; i < 120; i++) {
      const state = sh('systemctl is-system-running').stdout.trim();
      if (['running', 'degraded'].includes(state)) return;
      await delay(500);
    }
    assert.fail(`systemd did not finish booting: ${sh('systemctl --failed --no-pager').stdout}`);
  };
  const property = key => out(`systemctl show --property=${key} --value uptime-goblin.service`);
  const status = () => JSON.parse(out('cat /var/lib/uptime-goblin/run/status.json'));
  const verified = (timeout = 60) =>
    sh(
      `node --env-file=/etc/uptime-goblin.env /opt/uptime-goblin/lib/healthcheck.mjs --wait --timeout ${timeout} --data-dir /var/lib/uptime-goblin --unit uptime-goblin.service`
    );
  const version = tree => JSON.parse(out(`cat ${tree}/package.json`)).version;
  const copy = (source, target) => {
    const result = docker('cp', source, `${name}:${target}`);
    assert.equal(result.status, 0, result.stderr);
  };
  await booted();
  copy(makeSource(t, { version: '1.4.3-test.1' }), '/usr/local/src/uptime-goblin-1');
  copy(makeSource(t, { version: '1.4.3-test.2', change: 'two' }), '/usr/local/src/uptime-goblin-2');
  copy(makeSource(t, { version: '1.4.3-test.3', mode: 'crash' }), '/usr/local/src/uptime-goblin-3');

  await t.test('a fresh install is verified against the running process', () => {
    const result = sh('bash /usr/local/src/uptime-goblin-1/deploy/install.sh');
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.match(
      result.stdout,
      /Orbit 1\.4\.3-test\.1 \(build [0-9a-f]{12}\) is serving as process \d+/
    );
    assert.equal(
      out('grep ^ExecStart= /etc/systemd/system/uptime-goblin.service'),
      'ExecStart=/usr/local/bin/node /opt/uptime-goblin/server.mjs --supervised'
    );
    assert.equal(out('systemctl is-enabled uptime-goblin.service'), 'enabled');
    assert.equal(property('ActiveState'), 'active');
    assert.equal(status().pid, Number(property('MainPID')));
    assert.equal(status().version, '1.4.3-test.1');
    const analysis = sh('systemd-analyze verify /etc/systemd/system/uptime-goblin.service');
    assert.equal(analysis.status, 0, analysis.stdout + analysis.stderr);
    assert.equal(property('Type'), 'notify');
    assert.equal(property('NotifyAccess'), 'all');
  });

  await t.test('systemctl restart returns once Uptime Goblin serves (Type=notify)', () => {
    const before = Number(property('MainPID'));
    // In one exec, with no wait between: when restart returns, the unit is active and the new
    // process has written run/status.json.
    const [state, pid, ...status] = out(
      'systemctl restart uptime-goblin.service && systemctl show --property=ActiveState --value uptime-goblin.service && systemctl show --property=MainPID --value uptime-goblin.service && cat /var/lib/uptime-goblin/run/status.json'
    ).split('\n');
    assert.equal(state, 'active');
    assert.notEqual(Number(pid), before);
    assert.equal(JSON.parse(status.join('\n')).pid, Number(pid));
    assert.equal(verified(5).status, 0);
    // One more start than the steps below were written for: clear systemd's start rate limit
    // (5 in 10 s), which their installs and restarts would otherwise reach.
    out('systemctl reset-failed uptime-goblin.service');
  });

  await t.test(
    'the encryption key is /etc/uptime-goblin/secret.key, read through the unit, never in the environment',
    () => {
      // Delivery spec §4.5: root:uptime-goblin 0440 in a root:uptime-goblin 0750 directory, named in
      // /etc/uptime-goblin.env; /etc stays read-only under ProtectSystem=strict and the group reads it.
      assert.equal(out('stat -c "%a %U:%G" /etc/uptime-goblin'), '750 root:uptime-goblin');
      assert.equal(
        out('stat -c "%a %U:%G" /etc/uptime-goblin/secret.key'),
        '440 root:uptime-goblin'
      );
      assert.match(
        out('cat /etc/uptime-goblin.env'),
        /^GOBLIN_SECRET_KEY_FILE=\/etc\/uptime-goblin\/secret\.key$/m
      );
      const key = out('cat /etc/uptime-goblin/secret.key');
      assert.match(key, /^[0-9a-f]{64}$/);
      assert.equal(sh('test -e /var/lib/uptime-goblin/secret.key').status, 1, 'none in the data');
      // The start line names the file; the key's bytes are not in the process environment.
      const journal = out('journalctl --unit=uptime-goblin.service --no-pager --output=cat');
      assert.match(
        journal,
        /^Encryption key: GOBLIN_SECRET_KEY_FILE \(\/etc\/uptime-goblin\/secret\.key\) · fingerprint [0-9a-f]{16}$/m
      );
      const environ = out(`tr '\\0' '\\n' </proc/${property('MainPID')}/environ`);
      assert.match(environ, /^GOBLIN_SECRET_KEY_FILE=\/etc\/uptime-goblin\/secret\.key$/m);
      assert.ok(!environ.includes(key), 'the key is not in /proc/<pid>/environ');
    }
  );

  await t.test('an upgrade keeps the previous code', () => {
    const result = sh('bash /usr/local/src/uptime-goblin-2/deploy/install.sh');
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.equal(version('/opt/uptime-goblin'), '1.4.3-test.2');
    assert.equal(version('/opt/uptime-goblin.previous'), '1.4.3-test.1');
    assert.equal(status().version, '1.4.3-test.2');
  });

  await t.test(
    'a key restored root-only goes back to root:uptime-goblin 0440; another key file the uptime-goblin account cannot read is refused before Uptime Goblin stops',
    () => {
      // docs/installation.md backs the key up with `install -m 600`; restored the same way it is
      // root:root 0600, which Uptime Goblin, as the uptime-goblin account, cannot open: the upgrade used to stop
      // it, fail verification with exit 78 (key_file_unreadable, EACCES) and roll back to code
      // that failed the same way, leaving Uptime Goblin down (review round 2).
      out(
        'install -d -m 700 /secure-keys && install -m 600 /etc/uptime-goblin/secret.key /secure-keys/orbit-secret.key && install -m 600 /secure-keys/orbit-secret.key /etc/uptime-goblin/secret.key'
      );
      assert.equal(out('stat -c "%a %U:%G" /etc/uptime-goblin/secret.key'), '600 root:root');
      const install = 'bash /usr/local/src/uptime-goblin-2/deploy/install.sh';
      const repaired = sh(install);
      assert.equal(repaired.status, 0, repaired.stdout + repaired.stderr);
      assert.match(
        repaired.stdout,
        /^Gave \/etc\/uptime-goblin\/secret\.key to root:uptime-goblin, mode 0440, in \/etc\/uptime-goblin \(root:uptime-goblin, mode 0750\), so that the uptime-goblin account Uptime Goblin runs as can read it\.$/m
      );
      assert.equal(
        out('stat -c "%a %U:%G" /etc/uptime-goblin/secret.key'),
        '440 root:uptime-goblin'
      );
      assert.equal(out('stat -c "%a %U:%G" /etc/uptime-goblin'), '750 root:uptime-goblin');
      assert.equal(property('ActiveState'), 'active');
      assert.equal(status().pid, Number(property('MainPID')));

      // A key file of the admin's own choosing, root's alone: not the installer's to change, so the
      // install is refused before Uptime Goblin stops, and the fix it prints works.
      out(
        'install -d -m 755 /srv/orbit-keys && install -m 600 /etc/uptime-goblin/secret.key /srv/orbit-keys/orbit.key && cp /etc/uptime-goblin.env /root/orbit.env.key && sed -i "s|^GOBLIN_SECRET_KEY_FILE=.*|GOBLIN_SECRET_KEY_FILE=/srv/orbit-keys/orbit.key|" /etc/uptime-goblin.env'
      );
      try {
        const pid = property('MainPID');
        const refused = sh(install);
        assert.equal(refused.status, 1, refused.stdout + refused.stderr);
        assert.match(
          refused.stderr,
          /^GOBLIN_SECRET_KEY_FILE \(\/srv\/orbit-keys\/orbit\.key\) cannot be read by the uptime-goblin account, which Uptime Goblin runs as, so Uptime Goblin would refuse to start \(exit status 78, key_file_unreadable\)\. .* Uptime Goblin was not changed\.$/m
        );
        assert.doesNotMatch(refused.stdout, /Installing Uptime Goblin/);
        assert.equal(property('MainPID'), pid, 'Uptime Goblin was not stopped');
        assert.equal(out('stat -c "%a %U:%G" /srv/orbit-keys/orbit.key'), '600 root:root');
        const fix = /Let the group uptime-goblin read it: (sudo chown [^,]*), in a directory/.exec(
          refused.stderr
        )?.[1];
        assert.ok(fix, refused.stderr);
        out(fix.replaceAll('sudo ', ''));
        const passed = sh(install);
        assert.equal(passed.status, 0, passed.stdout + passed.stderr);
        assert.match(
          out('journalctl --unit=uptime-goblin.service --no-pager --output=cat'),
          /^Encryption key: GOBLIN_SECRET_KEY_FILE \(\/srv\/orbit-keys\/orbit\.key\) · fingerprint [0-9a-f]{16}$/m
        );
      } finally {
        // Later steps expect the installer's key file again. Three starts in a few seconds: reset
        // systemd's start rate limit (5 in 10 s), which the rollback steps below would hit.
        out(
          'cp /root/orbit.env.key /etc/uptime-goblin.env && systemctl restart uptime-goblin.service && systemctl reset-failed uptime-goblin.service'
        );
      }
      assert.equal(verified().status, 0);
    }
  );

  await t.test('rollback restarts the loaded unit when a full /run prevents daemon-reload', () => {
    // systemd refuses daemon-reload with under 16 MiB free, but can restart a loaded unit.
    // Keep this failure inside the container's small /run tmpfs and release it afterward.
    out(
      'available=$(df --output=avail -B1 /run | tail -1); fallocate -l $((available - 2*1024*1024)) /run/orbit-test-filler'
    );
    try {
      const result = sh(
        'bash /usr/local/src/uptime-goblin-3/deploy/install.sh --verify-timeout 10'
      );
      assert.equal(result.status, 1, result.stdout + result.stderr);
      assert.match(
        result.stderr,
        /Refusing to reload, not enough space available on \/run\/systemd/
      );
      assert.match(
        result.stderr,
        /WARNING: systemd could not reload its unit files during rollback/
      );
      assert.match(result.stderr, /The previous version is running again/);
      assert.equal(version('/opt/uptime-goblin'), '1.4.3-test.2');
      assert.equal(property('ActiveState'), 'active');
      assert.equal(verified().status, 0);
      assert.equal(status().version, '1.4.3-test.2');
      assert.equal(status().pid, Number(property('MainPID')));
    } finally {
      out('rm /run/orbit-test-filler');
    }
  });

  await t.test('a failed verification rolls the code back', () => {
    const result = sh('bash /usr/local/src/uptime-goblin-3/deploy/install.sh --verify-timeout 20');
    assert.equal(result.status, 1, result.stdout + result.stderr);
    assert.match(result.stderr, /fake orbit: simulated crash/);
    assert.match(result.stderr, /The previous version is running again/);
    assert.equal(version('/opt/uptime-goblin'), '1.4.3-test.2');
    assert.equal(version('/opt/uptime-goblin.failed'), '1.4.3-test.3');
    // The restored release runs under the new unit made Type=simple.
    assert.equal(property('Type'), 'simple');
    assert.equal(verified().status, 0);
    assert.equal(status().version, '1.4.3-test.2');
  });

  await t.test('an exit 0 that no stop request caused is restarted', async () => {
    const before = Number(property('MainPID'));
    const restarts = Number(property('NRestarts'));
    // SIGTERM straight to the process: Uptime Goblin exits 0, but systemd did not ask it to stop.
    out(`kill -TERM ${before}`);
    for (let i = 0; i < 60 && Number(property('NRestarts')) === restarts; i++) await delay(500);
    assert.equal(Number(property('NRestarts')), restarts + 1);
    assert.equal(verified().status, 0);
    assert.notEqual(Number(property('MainPID')), before);
  });

  await t.test('a refusal (exit 78) is reported, not retried', async () => {
    out(
      "cp /etc/uptime-goblin.env /root/orbit.env.saved && sed -i 's/^GOBLIN_PASSWORD=.*/GOBLIN_PASSWORD=short/' /etc/uptime-goblin.env"
    );
    try {
      // Under Type=notify the start never reports ready, so restart (which waits for that)
      // says it failed; the failed verification above left the unit Type=simple, which does not.
      const restarted = sh('systemctl restart uptime-goblin.service');
      if (property('Type') === 'notify')
        assert.notEqual(restarted.status, 0, restarted.stdout + restarted.stderr);
      for (let i = 0; i < 40 && property('ActiveState') !== 'failed'; i++) await delay(500);
      assert.equal(property('ActiveState'), 'failed');
      assert.equal(property('ExecMainStatus'), '78');
      // A manual restart resets systemd's counter, so count from the failed state.
      const restarts = Number(property('NRestarts'));
      await delay(7000); // longer than RestartSec
      assert.equal(property('ActiveState'), 'failed');
      assert.equal(Number(property('NRestarts')), restarts);
    } finally {
      // Later steps need a startable Uptime Goblin even when an assertion above failed.
      out(
        'cp /root/orbit.env.saved /etc/uptime-goblin.env && systemctl restart uptime-goblin.service'
      );
    }
    assert.equal(verified().status, 0);
  });

  await t.test('the unit keeps working when Node moves to a new directory', () => {
    out(
      'mv /opt/node-24 /opt/node-24.1 && ln -sfn /opt/node-24.1/bin/node /usr/local/bin/node && ln -sfn /opt/node-24.1/bin/npm /usr/local/bin/npm'
    );
    out('systemctl restart uptime-goblin.service');
    assert.equal(verified().status, 0);
  });

  await t.test('a pre-1.4.3 unit whose Node path vanished is reported and repaired', async () => {
    // What 1.4.2's installer wrote: the resolved path, which the move above removed.
    out(
      "sed -i 's|^ExecStart=.*|ExecStart=/opt/node-24/bin/node /opt/uptime-goblin/server.mjs|' /etc/systemd/system/uptime-goblin.service && systemctl daemon-reload"
    );
    sh('systemctl restart uptime-goblin.service');
    await delay(2000);
    assert.notEqual(property('ActiveState'), 'active');
    const result = sh('bash /usr/local/src/uptime-goblin-2/deploy/install.sh');
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.match(
      result.stderr,
      /starts Node from \/opt\/node-24\/bin\/node, which no longer exists/
    );
    assert.equal(
      out('grep ^ExecStart= /etc/systemd/system/uptime-goblin.service'),
      'ExecStart=/usr/local/bin/node /opt/uptime-goblin/server.mjs --supervised'
    );
  });

  await t.test('Uptime Goblin starts again after a reboot', async () => {
    const restarted = docker('restart', name);
    assert.equal(restarted.status, 0, restarted.stderr);
    await booted();
    assert.equal(verified(120).status, 0);
    assert.equal(status().version, '1.4.3-test.2');
    assert.equal(status().pid, Number(property('MainPID')));
  });

  await t.test(
    'the proxy preflight tells a stopped 1.4.3 from one that has not seen nginx',
    async () => {
      // 1.4.3 removes run/status.json when it stops, so the preflight of the upgrade to 1.5
      // must not blame nginx then: opening Uptime Goblin through nginx cannot work while it is stopped.
      const repaired = sh(
        'bash /usr/local/src/uptime-goblin-2/deploy/install.sh --trust-proxy loopback'
      );
      assert.equal(repaired.status, 0, repaired.stdout + repaired.stderr);
      copy(makeSource(t, { version: '1.5.0-test.1' }), '/usr/local/src/uptime-goblin-15');
      const upgrade = 'bash /usr/local/src/uptime-goblin-15/deploy/install.sh';
      const serving = sh(upgrade);
      assert.equal(serving.status, 1, serving.stdout + serving.stderr);
      assert.match(
        serving.stderr,
        /The running Orbit 1\.4\.3-test\.2 has not recorded what your reverse proxy sends \(GOBLIN_TRUST_PROXY=loopback\)\. Before upgrading: add proxy_set_header X-Forwarded-Proto \$scheme;/
      );
      out('systemctl stop uptime-goblin.service');
      assert.equal(
        sh('test -e /var/lib/uptime-goblin/run/status.json').status,
        1,
        'the record is gone'
      );
      const stopped = sh(upgrade);
      assert.equal(stopped.status, 1, stopped.stdout + stopped.stderr);
      assert.match(
        stopped.stderr,
        /Orbit 1\.4\.3-test\.2 is not running, and it clears its record of what your reverse proxy sends when it stops \(GOBLIN_TRUST_PROXY=loopback\)\. Before upgrading: start it \(sudo systemctl start uptime-goblin\), open Orbit through nginx once, then run this installer again without stopping Orbit\./
      );
      assert.doesNotMatch(stopped.stderr, /proxy_set_header/);
      assert.equal(version('/opt/uptime-goblin'), '1.4.3-test.2', 'nothing was changed');
      assert.equal(sh('systemctl is-active uptime-goblin.service').stdout.trim(), 'inactive');
      out('systemctl start uptime-goblin.service');
      assert.equal(verified().status, 0);
    }
  );
});

// Delivery spec §10 item 9: a real-systemd upgrade from 1.4.3 provisions /etc/uptime-goblin/secret.key.
// A host of its own, so nothing of the test above (Node moved, a 1.5 test build) is in the way.
// 1.4.3 is Orbit, installed by its own installer (deploy/install-lxc.sh of the tag) in the Orbit
// layout, which the upgrade moves to the Uptime Goblin one (deploy/install.sh, Renamed from Orbit).
test(
  'a real 1.4.3 install upgraded as the deploy wrapper does moves to the Uptime Goblin layout and gets /etc/uptime-goblin/secret.key, kept out of the environment',
  { skip, timeout: 900000 },
  async t => {
    if (skipWithoutTag(t, 'v1.4.3')) return;
    const name = `orbit-systemd-${randomBytes(4).toString('hex')}`;
    const started = docker(
      'run',
      ...limits,
      '--detach',
      '--name',
      name,
      '--privileged',
      '--cgroupns=host',
      '--volume',
      '/sys/fs/cgroup:/sys/fs/cgroup:rw',
      '--tmpfs',
      '/run:size=48m',
      '--tmpfs',
      '/run/lock',
      '--tmpfs',
      '/tmp',
      image
    );
    assert.equal(started.status, 0, started.stderr);
    t.after(() => docker('rm', '--force', '--volumes', name));
    assertLimited(name);
    const sh = script => docker('exec', name, 'bash', '-c', script);
    const out = script => {
      const result = sh(script);
      assert.equal(result.status, 0, `${script}\n${result.stdout}${result.stderr}`);
      return result.stdout.trim();
    };
    for (let i = 0; i < 120; i++) {
      if (['running', 'degraded'].includes(sh('systemctl is-system-running').stdout.trim())) break;
      await delay(500);
    }
    const property = key => out(`systemctl show --property=${key} --value uptime-goblin.service`);
    const status = () => JSON.parse(out('cat /var/lib/uptime-goblin/run/status.json'));
    const version = tree => JSON.parse(out(`cat ${tree}/package.json`)).version;
    const copy = (source, target) => {
      const result = docker('cp', source, `${name}:${target}`);
      assert.equal(result.status, 0, result.stderr);
    };
    const working = JSON.parse(
      fs.readFileSync(path.join(repository, 'package.json'), 'utf8')
    ).version;
    copy(
      installTag('v1.4.3', path.join(temporary(t, 'orbit-143-'), 'app')),
      '/usr/local/src/orbit-143'
    );
    copy(makeSource(t, { version: working }), '/usr/local/src/uptime-goblin-wt');
    // The wrapper's invocation (orbit-design/deploy/orbit-deploy.sh), for 1.4.3 as for 1.5.
    const wrapper = '--trust-proxy loopback --allow-loopback';

    // 1.4.3 as its own installer leaves it, in the Orbit layout: no key anywhere.
    const old = sh(`bash /usr/local/src/orbit-143/deploy/install-lxc.sh ${wrapper}`);
    assert.equal(old.status, 0, old.stdout + old.stderr);
    assert.equal(JSON.parse(out('cat /var/lib/orbit/run/status.json')).version, '1.4.3');
    assert.equal(sh('test -e /etc/orbit/secret.key').status, 1);
    const settings = out('cat /etc/orbit.env');
    assert.doesNotMatch(settings, /ORBIT_SECRET_KEY/);
    const owner = out('stat -c "%u:%g" /var/lib/orbit');

    // The upgrade, as the wrapper runs it after the admin checked the proxy by hand.
    const upgrade = `bash /usr/local/src/uptime-goblin-wt/deploy/install.sh ${wrapper} --proxy-proto-checked`;
    const result = sh(upgrade);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    // The migration: every part of the Orbit layout renamed, the account too, so the files keep
    // their owner; the old settings and unit files kept; /etc/uptime-goblin.env with the new names.
    assert.match(result.stdout, /^This host has the Orbit layout/m);
    assert.match(
      result.stdout,
      /^  Renamed the account orbit to uptime-goblin\.$[\s\S]*^  Renamed \/opt\/orbit to \/opt\/uptime-goblin\.$/m
    );
    for (const gone of [
      '/opt/orbit',
      '/var/lib/orbit',
      '/etc/orbit.env',
      '/etc/orbit',
      '/etc/systemd/system/orbit.service',
      '/var/lib/uptime-goblin.migrating',
    ])
      assert.equal(sh(`test -e ${gone}`).status, 1, `${gone} was moved`);
    // As the checks left it before the move: 1.4.3's file with the key line they added.
    assert.equal(
      out('cat /etc/orbit.env.migrated'),
      `${settings}\n# Added by the Uptime Goblin 1.5 installer: the encryption key for Uptime Goblin's sealed settings. Back it up separately.\nORBIT_SECRET_KEY_FILE=/etc/orbit/secret.key`
    );
    assert.equal(out('test -f /etc/systemd/system/orbit.service.migrated && echo kept'), 'kept');
    assert.equal(
      out('stat -c "%u:%g %U:%G" /var/lib/uptime-goblin'),
      `${owner} uptime-goblin:uptime-goblin`
    );
    assert.notEqual(sh('getent passwd orbit').status, 0, 'the account was renamed');
    assert.equal(out('getent passwd uptime-goblin').split(':')[5], '/opt/uptime-goblin');
    assert.equal(out('systemctl is-enabled uptime-goblin.service'), 'enabled');
    assert.notEqual(sh('systemctl is-active orbit.service').stdout.trim(), 'active');
    assert.equal(version('/opt/uptime-goblin.previous'), '1.4.3');
    const migrated = out('cat /etc/uptime-goblin.env');
    assert.match(migrated, /^GOBLIN_TRUST_PROXY=loopback$/m);
    assert.match(migrated, /^GOBLIN_ALLOW_LOOPBACK=1$/m);
    assert.match(migrated, /^GOBLIN_PASSWORD=\S+$/m);
    assert.doesNotMatch(migrated, /^ORBIT_/m);
    assert.equal(out('stat -c %a /etc/uptime-goblin.env'), '600');
    assert.doesNotMatch(
      out('journalctl --unit=uptime-goblin.service --no-pager --output=cat'),
      /Deprecated settings/,
      'no ORBIT_ name reaches Uptime Goblin'
    );
    assert.match(
      result.stdout,
      /^Created the encryption key \/etc\/uptime-goblin\/secret\.key\. Back it up separately from \/var\/lib\/uptime-goblin: without it Uptime Goblin cannot open what it has sealed\.$/m
    );
    assert.match(
      result.stdout,
      /^Encryption key: \/etc\/uptime-goblin\/secret\.key\. Back it up separately from \/var\/lib\/uptime-goblin\.$/m
    );
    assert.equal(status().version, working);
    assert.equal(status().pid, Number(property('MainPID')));
    assert.equal(out('stat -c "%a %U:%G" /etc/uptime-goblin'), '750 root:uptime-goblin');
    assert.equal(out('stat -c "%a %U:%G" /etc/uptime-goblin/secret.key'), '440 root:uptime-goblin');
    const key = out('cat /etc/uptime-goblin/secret.key');
    assert.match(key, /^[0-9a-f]{64}$/);
    const lines = () =>
      out('cat /etc/uptime-goblin.env')
        .split('\n')
        .filter(line => line.startsWith('GOBLIN_SECRET_KEY'));
    assert.deepEqual(lines(), ['GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key']);
    assert.equal(sh('test -e /var/lib/uptime-goblin/secret.key').status, 1, 'no key in the data');
    // The keyring Uptime Goblin created at its first 1.5 start opens with that key.
    const journal = out('journalctl --unit=uptime-goblin.service --no-pager --output=cat');
    const line =
      /^Encryption key: GOBLIN_SECRET_KEY_FILE \(\/etc\/uptime-goblin\/secret\.key\) · fingerprint ([0-9a-f]{16})$/m.exec(
        journal
      );
    assert.ok(line, journal);
    const environ = out(`tr '\\0' '\\n' </proc/${property('MainPID')}/environ`);
    assert.match(environ, /^GOBLIN_SECRET_KEY_FILE=\/etc\/uptime-goblin\/secret\.key$/m);
    assert.ok(!environ.includes(key), 'the key is not in /proc/<pid>/environ');

    // Running the installer again keeps the key and adds no line.
    const again = sh(upgrade);
    assert.equal(again.status, 0, again.stdout + again.stderr);
    assert.doesNotMatch(again.stdout, /Created the encryption key/);
    assert.equal(out('cat /etc/uptime-goblin/secret.key'), key);
    assert.deepEqual(lines(), ['GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key']);
    const fingerprints = [
      ...out('journalctl --unit=uptime-goblin.service --no-pager --output=cat').matchAll(
        /^Encryption key: .* · fingerprint ([0-9a-f]{16})$/gm
      ),
    ].map(match => match[1]);
    assert.ok(fingerprints.length >= 2, 'a start before and after the second run');
    assert.deepEqual(new Set(fingerprints), new Set([line[1]]), 'one key throughout');

    // The key commands as documented, with the real permissions: /etc/uptime-goblin.env is root's
    // 0600 and only systemd reads it, the key file is root:uptime-goblin 0440, and `sudo -u uptime-goblin`
    // starts a clean environment (no sudo in the image: env -i and runuser do the same).
    const read = file => fs.readFileSync(path.join(repository, file), 'utf8');
    const asOrbit = command =>
      sh(
        command
          .replace(
            /^sudo -u uptime-goblin /,
            'env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin runuser -u uptime-goblin -- '
          )
          .replace(/^sudo /, '')
      );
    const documented = (file, action) => {
      const found = new RegExp(
        `^sudo -u uptime-goblin .*node /opt/uptime-goblin/lib/cli/goblin-admin\\.mjs key ${action} .*--data-dir /var/lib/uptime-goblin$`,
        'm'
      ).exec(read(file))?.[0];
      assert.ok(found, `${file} documents no native key ${action} command line`);
      return found;
    };
    const bare = action =>
      asOrbit(
        `sudo -u uptime-goblin node /opt/uptime-goblin/lib/cli/goblin-admin.mjs key ${action} --data-dir /var/lib/uptime-goblin`
      );
    const startsWith = async fingerprint => {
      out('systemctl reset-failed uptime-goblin.service; systemctl restart uptime-goblin.service');
      for (let i = 0; i < 60 && property('ActiveState') !== 'active'; i++) await delay(500);
      const result = sh(
        'node --env-file=/etc/uptime-goblin.env /opt/uptime-goblin/lib/healthcheck.mjs --wait --timeout 60 --data-dir /var/lib/uptime-goblin --unit uptime-goblin.service'
      );
      assert.equal(result.status, 0, result.stdout + result.stderr);
      const starts = [
        ...out('journalctl --unit=uptime-goblin.service --no-pager --output=cat').matchAll(
          /^Encryption key: .* · fingerprint ([0-9a-f]{16})$/gm
        ),
      ];
      assert.equal(starts.at(-1)[1], fingerprint, 'the last start used this key');
    };
    assert.notEqual(
      sh('runuser -u uptime-goblin -- cat /etc/uptime-goblin.env').status,
      0,
      'root only'
    );
    const checked = asOrbit(documented('docs/installation.md', 'status'));
    assert.equal(checked.status, 0, checked.stdout + checked.stderr);
    assert.match(checked.stdout, /^The key opens every data key\.$/m);
    // Without the key file (as the docs once printed it): not called lost, nothing changed.
    const unseen = bare('status');
    assert.equal(unseen.status, 1, unseen.stdout + unseen.stderr);
    assert.match(unseen.stdout, /^Master key: not found by this command\./m);
    assert.doesNotMatch(unseen.stdout, /PROBLEM|key reset/);
    out('systemctl stop uptime-goblin.service');
    const refused = bare('reset --confirm-lost-key');
    assert.equal(refused.status, 2, refused.stdout + refused.stderr);
    assert.equal(sh('test -e /var/lib/uptime-goblin/secret.key').status, 1, 'no key generated');
    const rotated = asOrbit(documented('docs/installation.md', 'rotate'));
    assert.equal(rotated.status, 0, rotated.stdout + rotated.stderr);
    await startsWith(line[1]);

    // A lost key: the start refuses with ENOENT; docs/troubleshooting.md 'Lost encryption key'
    // steps 2 and 3, as printed, put a new key in place and reset the keyring under it.
    out('systemctl stop uptime-goblin.service && rm /etc/uptime-goblin/secret.key');
    sh('systemctl restart uptime-goblin.service');
    for (let i = 0; i < 40 && property('ActiveState') !== 'failed'; i++) await delay(500);
    assert.equal(property('ExecMainStatus'), '78');
    assert.match(
      out('journalctl --unit=uptime-goblin.service --no-pager --output=cat'),
      /GOBLIN_SECRET_KEY_FILE \(\/etc\/uptime-goblin\/secret\.key\) cannot be read: ENOENT\./
    );
    const lost = read('docs/troubleshooting.md')
      .split('## Lost encryption key')[1]
      .split('\n## ')[0];
    const step2 = /^2\. .*$/m.exec(lost)?.[0] ?? '';
    // The native commands (the Compose ones make ./orbit_secret_key).
    const commands = [
      ...step2.matchAll(/`((?:sudo install|openssl rand)[^`]*\/etc\/uptime-goblin[^`]*)`/g),
    ].map(match => match[1]);
    assert.equal(commands.length, 2, step2);
    for (const command of commands) out(command.replaceAll('sudo ', ''));
    assert.equal(out('stat -c "%a %U:%G" /etc/uptime-goblin/secret.key'), '440 root:uptime-goblin');
    const step3 = /^3\. .*?`(sudo -u uptime-goblin [^`]*key reset --confirm-lost-key[^`]*)`/m.exec(
      lost
    )?.[1];
    assert.ok(step3, lost);
    const reset = asOrbit(step3);
    assert.equal(reset.status, 0, reset.stdout + reset.stderr);
    assert.match(reset.stdout, /\(\/etc\/uptime-goblin\/secret\.key\)/);
    assert.equal(sh('test -e /var/lib/uptime-goblin/secret.key').status, 1, 'no key in the data');
    const fresh = /fingerprint ([0-9a-f]{16})/.exec(reset.stdout)[1];
    assert.notEqual(fresh, line[1]);
    await startsWith(fresh);
  }
);

// Signs in to the Uptime Goblin on 127.0.0.1:4317 beside it (a loopback peer), adds a Prometheus source
// that reads a fixture this script serves on 127.0.0.1, collects it and prints what each step
// answered as one JSON line. Run with node inside the container; the password comes in
// GOBLIN_TEST_PASSWORD.
const exerciseScript = `
import http from 'node:http';
const fixture = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain; version=0.0.4' });
  res.end('example_temperature_celsius{sensor="cpu"} 42.5\\n');
});
await new Promise(resolve => fixture.listen(9109, '127.0.0.1', resolve));
let cookie = '';
const call = (method, target, body) =>
  new Promise((resolve, reject) => {
    const headers = {
      Host: 'localhost:4317',
      Origin: 'http://localhost:4317',
      'Sec-Fetch-Site': 'same-origin',
      'X-Goblin-Request': '1',
      'X-Goblin-Client': 'web/test',
      ...(cookie ? { Cookie: cookie } : {}),
      ...(body ? { 'Content-Type': 'application/json' } : {}),
    };
    const req = http.request({ host: '127.0.0.1', port: 4317, method, path: target, headers }, res => {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', chunk => (text += chunk));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text }));
    });
    req.on('error', reject);
    req.end(body ? JSON.stringify(body) : undefined);
  });
const out = {};
const login = await call('POST', '/api/auth/login', { login: 'admin', password: process.env.GOBLIN_TEST_PASSWORD });
out.login = login.status;
cookie = (login.headers['set-cookie'] ?? [''])[0].split(';')[0];
const added = await call('POST', '/api/services', {
  type: 'prometheus',
  name: 'Fixture',
  group: 'Test',
  apiUrl: 'http://127.0.0.1:9109/metrics',
  metrics: [{ key: 'temperature', label: 'Temperature', path: 'example_temperature_celsius', labels: { sensor: 'cpu' }, unit: 'C', scale: 1 }],
});
out.added = added.status;
out.refresh = (await call('POST', '/api/refresh', {})).status;
for (let i = 0; i < 60 && !out.reading; i++) {
  if ((await call('GET', '/api/dashboard')).text.includes('42.5')) out.reading = 42.5;
  else await new Promise(resolve => setTimeout(resolve, 500));
}
fixture.close();
console.log(JSON.stringify(out));
`;

// The unit as shipped, with the real Uptime Goblin (the manifest's files and nodemailer, as the installer
// lays them out, without its npm ci, so the container needs no network): the limits reach
// uptime-goblin.service's cgroup and Uptime Goblin's process, the sandbox (system-call filter included) lets
// Uptime Goblin start, sign in, collect and stop, a process flood stops at TasksMax while Uptime Goblin answers,
// and a drop-in that lifts the limits makes the next start refuse (exit status 78, the unit
// left failed, the verifier failing at once), until /etc/uptime-goblin.env names them in
// GOBLIN_ALLOW_UNLIMITED, with which Uptime Goblin starts and says which it runs without
// (lib/resource-limits.mjs; before B48 it only warned and started).
test(
  'the unit as shipped: limits in its cgroup, the sandbox, the real Uptime Goblin serving; a drop-in that lifts them refuses the start unless GOBLIN_ALLOW_UNLIMITED names them',
  { skip, timeout: 600000 },
  async t => {
    const nodemailer = path.join(repository, 'node_modules', 'nodemailer');
    assert.ok(fs.existsSync(nodemailer), 'run npm ci first: the test installs nodemailer from it');
    const tree = path.join(temporary(t, 'orbit-unit-'), 'orbit');
    for (const file of readManifest(repository)) {
      fs.mkdirSync(path.dirname(path.join(tree, file)), { recursive: true });
      fs.copyFileSync(path.join(repository, file), path.join(tree, file));
    }
    fs.cpSync(nodemailer, path.join(tree, 'node_modules', 'nodemailer'), { recursive: true });
    const name = `orbit-unit-${randomBytes(4).toString('hex')}`;
    const started = docker(
      'run',
      ...limits,
      '--detach',
      '--name',
      name,
      '--network',
      'none',
      '--privileged',
      '--cgroupns=host',
      '--volume',
      '/sys/fs/cgroup:/sys/fs/cgroup:rw',
      '--tmpfs',
      '/run:size=48m',
      '--tmpfs',
      '/run/lock',
      '--tmpfs',
      '/tmp',
      image
    );
    assert.equal(started.status, 0, started.stderr);
    t.after(() => docker('rm', '--force', '--volumes', name));
    assertLimited(name);
    const sh = script => docker('exec', name, 'bash', '-c', script);
    const out = script => {
      const result = sh(script);
      assert.equal(result.status, 0, `${script}\n${result.stdout}${result.stderr}`);
      return result.stdout.trim();
    };
    for (let i = 0; i < 120; i++) {
      if (['running', 'degraded'].includes(sh('systemctl is-system-running').stdout.trim())) break;
      await delay(500);
    }
    for (const [source, target] of [
      [tree, '/opt/uptime-goblin'],
      [
        path.join(repository, 'deploy/uptime-goblin.service'),
        '/etc/systemd/system/uptime-goblin.service',
      ],
    ]) {
      const copied = docker('cp', source, `${name}:${target}`);
      assert.equal(copied.status, 0, copied.stderr);
    }
    const password = randomBytes(18).toString('base64url');
    // As install.sh leaves the host: root-owned code, the uptime-goblin account, a key file the
    // group uptime-goblin reads, /etc/uptime-goblin.env, and ExecStart naming this host's node.
    out(
      [
        'useradd --system --home-dir /var/lib/uptime-goblin --shell /usr/sbin/nologin uptime-goblin',
        'chown -R root:root /opt/uptime-goblin && chmod -R u=rwX,go=rX /opt/uptime-goblin',
        'install -d -m 750 -o root -g uptime-goblin /etc/uptime-goblin',
        `(umask 077 && node -e 'process.stdout.write(require("node:crypto").randomBytes(32).toString("hex"))' > /etc/uptime-goblin/secret.key)`,
        'chown root:uptime-goblin /etc/uptime-goblin/secret.key && chmod 440 /etc/uptime-goblin/secret.key',
        `printf 'HOST=127.0.0.1\\nPORT=4317\\nGOBLIN_ALLOWED_HOSTS=localhost:4317\\nGOBLIN_PASSWORD=%s\\nGOBLIN_ALLOW_LOOPBACK=1\\nGOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key\\n' '${password}' > /etc/uptime-goblin.env`,
        'chmod 600 /etc/uptime-goblin.env',
        `sed -i 's|^ExecStart=/usr/bin/node |ExecStart=/usr/local/bin/node |' /etc/systemd/system/uptime-goblin.service`,
        'systemctl daemon-reload',
      ].join(' && ')
    );
    const verify = sh('systemd-analyze verify /etc/systemd/system/uptime-goblin.service');
    assert.equal(verify.status, 0, verify.stdout + verify.stderr);
    const property = key => out(`systemctl show --property=${key} --value uptime-goblin.service`);
    const journal = () => out('journalctl --unit=uptime-goblin.service --no-pager --output=cat');
    const ready = async () => {
      for (let i = 0; i < 60; i++) {
        if (sh('test -e /var/lib/uptime-goblin/run/status.json').status === 0) return;
        await delay(500);
      }
      assert.fail(journal());
    };
    out('systemctl start uptime-goblin.service');
    await ready();
    assert.equal(property('ActiveState'), 'active');

    // What systemd made of the limits and the sandbox, and what reached the cgroup and Uptime Goblin.
    for (const [key, value] of [
      ['MemoryMax', String(2 ** 30)],
      ['MemorySwapMax', '0'],
      ['TasksMax', '256'],
      ['CPUQuotaPerSecUSec', '2s'],
      ['LimitNOFILE', '4096'],
      ['LimitCORE', '0'],
      ['ProtectClock', 'yes'],
      ['ProtectHostname', 'yes'],
      ['ProtectKernelLogs', 'yes'],
      ['RemoveIPC', 'yes'],
      ['NoNewPrivileges', 'yes'],
    ])
      assert.equal(property(key), value, key);
    const pid = property('MainPID');
    const cgroup = `/sys/fs/cgroup${out(`sed -n 's/^0:://p' /proc/${pid}/cgroup`)}`;
    assert.equal(
      out(
        `cat ${cgroup}/memory.max ${cgroup}/memory.swap.max ${cgroup}/pids.max ${cgroup}/cpu.max`
      ),
      `${2 ** 30}\n0\n256\n200000 100000`
    );
    // Started with --supervised, which /etc/uptime-goblin.env cannot take away.
    assert.equal(
      out(`tr '\\0' ' ' < /proc/${pid}/cmdline`),
      '/usr/local/bin/node /opt/uptime-goblin/server.mjs --supervised'
    );
    assert.match(out(`cat /proc/${pid}/limits`), /^Max open files +4096 +4096 +files/m);
    assert.match(out(`cat /proc/${pid}/limits`), /^Max core file size +0 +0 +bytes/m);
    assert.match(out(`grep ^Seccomp: /proc/${pid}/status`), /^Seccomp:\s+2$/, 'filtered');
    // systemd's own rating (the 1.4.2 set scored 3.3 here; these directives bring it to 1.7).
    const exposure = /Overall exposure level for uptime-goblin\.service: (\d+\.\d)/.exec(
      out('systemd-analyze security uptime-goblin.service --no-pager')
    )?.[1];
    assert.ok(Number(exposure) <= 2, `exposure ${exposure}`);

    // Uptime Goblin works under them: sign-in, a source added and collected; no limit is missing.
    const exercised = spawnSync(
      'docker',
      [
        'exec',
        '-i',
        '-e',
        `GOBLIN_TEST_PASSWORD=${password}`,
        name,
        'node',
        '--input-type=module',
        '-',
      ],
      { input: exerciseScript, encoding: 'utf8', timeout: 120000 }
    );
    assert.equal(exercised.status, 0, exercised.stdout + exercised.stderr);
    assert.deepEqual(JSON.parse(exercised.stdout), {
      login: 200,
      added: 201,
      refresh: 202,
      reading: 42.5,
    });
    assert.doesNotMatch(journal(), /resource limits|runs without a|GOBLIN_ALLOW_UNLIMITED/);

    // A flood of processes in uptime-goblin.service stops at TasksMax; Uptime Goblin keeps answering and is not
    // restarted. (dash, not bash, which would retry each failed fork for seconds.)
    const health = () =>
      sh(
        `node -e 'fetch("http://127.0.0.1:4317/health",{headers:{Host:"localhost:4317"}}).then(r=>process.exit(r.status===200?0:1),()=>process.exit(2))'`
      ).status;
    const flood = docker(
      'exec',
      '--detach',
      name,
      'sh',
      '-c',
      `echo $$ > ${cgroup}/cgroup.procs; i=0; while [ $i -lt 400 ]; do sleep 60 & i=$((i+1)); done`
    );
    assert.equal(flood.status, 0, flood.stderr);
    let flooded = false;
    for (let i = 0; i < 40 && !flooded; i++) {
      flooded = /^max [1-9]/m.test(out(`cat ${cgroup}/pids.events`));
      if (!flooded) await delay(250);
    }
    assert.ok(flooded, out(`cat ${cgroup}/pids.current ${cgroup}/pids.events`));
    assert.equal(health(), 0, 'Uptime Goblin answers at its process limit');
    out('pkill -x sleep; true');
    assert.equal(property('MainPID'), pid);
    assert.equal(property('NRestarts'), '0');

    // A drop-in that lifts the memory and task limits: the next start refuses (78), names both,
    // and systemd leaves the unit failed instead of restarting it.
    out('systemctl stop uptime-goblin.service && rm -f /var/lib/uptime-goblin/run/status.json');
    out(
      "mkdir -p /etc/systemd/system/uptime-goblin.service.d && printf '[Service]\\nMemoryMax=infinity\\nTasksMax=infinity\\n' > /etc/systemd/system/uptime-goblin.service.d/lift.conf && systemctl daemon-reload"
    );
    assert.equal(property('MemoryMax'), 'infinity');
    assert.equal(property('TasksMax'), 'infinity');
    sh('systemctl start uptime-goblin.service');
    for (let i = 0; i < 40 && property('ActiveState') !== 'failed'; i++) await delay(500);
    assert.equal(property('ActiveState'), 'failed');
    assert.equal(property('ExecMainStatus'), '78');
    const refusal = journal();
    assert.match(
      refusal,
      /^Uptime Goblin refused to start without its resource limits: under a service manager \(started with --supervised or GOBLIN_SUPERVISED=1\) it starts only where its own cgroup holds its memory, CPU time and processes to a limit, and here its memory and process limits are not in force\.$/m
    );
    assert.match(refusal, /^Memory limit: none \(memory\.max is max\)\. Under Docker, /m);
    assert.match(refusal, /^Process limit: none \(pids\.max is max\)\. Under Docker, /m);
    assert.match(refusal, /set GOBLIN_ALLOW_UNLIMITED=memory,pids in Uptime Goblin's environment/);
    assert.match(refusal, /^Uptime Goblin refused to start \(exit status 78\)\./m);
    assert.equal(sh('test -e /var/lib/uptime-goblin/run/status.json').status, 1, 'it never served');
    const restarts = Number(property('NRestarts'));
    await delay(7000); // longer than RestartSec
    assert.equal(property('ActiveState'), 'failed');
    assert.equal(Number(property('NRestarts')), restarts, 'not restarted');
    // The installer's verifier fails at once, naming the failed unit.
    const verifier = sh(
      'node --env-file=/etc/uptime-goblin.env /opt/uptime-goblin/lib/healthcheck.mjs --wait --timeout 30 --data-dir /var/lib/uptime-goblin --unit uptime-goblin.service'
    );
    assert.equal(verifier.status, 1);
    assert.match(
      verifier.stderr,
      /^Uptime Goblin is not verified: uptime-goblin\.service failed \(exit-code\) and systemd will not restart it\.$/m
    );
    // systemd lets /etc/uptime-goblin.env override the unit's Environment=GOBLIN_SUPERVISED=1. A 0 there
    // would turn the check off, and a typo too (it meant off, with a warning). The unit's
    // --supervised keeps Uptime Goblin supervised: a 0 is ignored, with a line, and still refused here;
    // a typo refuses the start on its own.
    // The journal of one start, as this test reads it (the installer reads no position and draws
    // no conclusion from the journal): the cursor journalctl --show-cursor prints after the newest
    // entry of the whole journal, its last line, taken just before the start, then uptime-goblin.service's
    // entries after it. The cursor is opaque: given back as one argument with no shell between
    // (docker exec), never taken apart. No second has to pass: the previous start has failed
    // before the cursor is taken. That its lines were stored before the cursor is what a run
    // observes on that journal, not something a position proves (Codex review F-02-R2).
    const position = () => {
      const shown = docker(
        'exec',
        name,
        'journalctl',
        '--lines=1',
        '--show-cursor',
        '--no-pager',
        '--output=cat'
      );
      assert.equal(shown.status, 0, shown.stdout + shown.stderr);
      const lines = shown.stdout.replace(/\n$/, '').split('\n');
      const last = lines.pop();
      assert.ok(last.startsWith('-- cursor: ') && last.length > '-- cursor: '.length, shown.stdout);
      assert.ok(!lines.some(text => text.includes('-- cursor: ')), shown.stdout);
      return last.slice('-- cursor: '.length);
    };
    const journalAfter = cursor => {
      const shown = docker(
        'exec',
        name,
        'journalctl',
        '--unit=uptime-goblin.service',
        '--no-pager',
        '--output=cat',
        `--after-cursor=${cursor}`
      );
      assert.equal(shown.status, 0, shown.stdout + shown.stderr);
      return shown.stdout.trim();
    };
    const failedStart = async line => {
      out(
        // reset-failed fails on a unit that is not failed (not loaded after a clean stop).
        `sed -i '/^GOBLIN_SUPERVISED=/d' /etc/uptime-goblin.env && printf '%s\\n' '${line}' >> /etc/uptime-goblin.env && { systemctl reset-failed uptime-goblin.service 2>/dev/null || true; }`
      );
      const cursor = position();
      sh('systemctl start uptime-goblin.service');
      for (let i = 0; i < 40 && property('ActiveState') !== 'failed'; i++) await delay(500);
      assert.equal(property('ActiveState'), 'failed', line);
      assert.equal(property('ExecMainStatus'), '78', line);
      assert.equal(
        sh('test -e /var/lib/uptime-goblin/run/status.json').status,
        1,
        'it never served'
      );
      return journalAfter(cursor);
    };
    const off = await failedStart('GOBLIN_SUPERVISED=0');
    assert.match(
      off,
      /^GOBLIN_SUPERVISED="0" is ignored: Uptime Goblin was started with --supervised, as the systemd unit and the Docker image start it, which this setting cannot turn off\./m
    );
    assert.match(off, /^Uptime Goblin refused to start without its resource limits: /m);
    assert.match(off, /set GOBLIN_ALLOW_UNLIMITED=memory,pids in Uptime Goblin's environment/);
    const typo = await failedStart('GOBLIN_SUPERVISED=bogus');
    assert.match(
      typo,
      /^GOBLIN_SUPERVISED must be 1 or 0 \(true, yes or on; false, no or off\), or empty; it is "bogus"\.$/m
    );
    assert.match(typo, /^Uptime Goblin refused to start \(exit status 78\)\./m);
    assert.doesNotMatch(typo, /resource limits/);
    out("sed -i '/^GOBLIN_SUPERVISED=/d' /etc/uptime-goblin.env");
    // Named in GOBLIN_ALLOW_UNLIMITED: it starts, and says at the start which it runs without.
    out(
      "printf 'GOBLIN_ALLOW_UNLIMITED=memory,pids\\n' >> /etc/uptime-goblin.env && systemctl reset-failed uptime-goblin.service && systemctl start uptime-goblin.service"
    );
    await ready();
    assert.equal(property('ActiveState'), 'active');
    for (let i = 0; i < 20 && !/runs without a process limit/.test(journal()); i++)
      await delay(500);
    assert.match(
      journal(),
      /^Uptime Goblin runs without a memory limit, as GOBLIN_ALLOW_UNLIMITED allows: none \(memory\.max is max\)\./m
    );
    assert.match(
      journal(),
      /^Uptime Goblin runs without a process limit, as GOBLIN_ALLOW_UNLIMITED allows: none \(pids\.max is max\)\./m
    );
    out('systemctl stop uptime-goblin.service');
    assert.equal(property('ExecMainStatus'), '0');
    assert.equal(property('Result'), 'success');
    // A drop-in that empties CPUQuota=: systemd then may give uptime-goblin.service no cpu controller at
    // all where no other unit of system.slice uses it, or else leave cpu.max at max; either is a
    // CPU limit not in force.
    out(
      "printf '[Service]\\nCPUQuota=\\n' > /etc/systemd/system/uptime-goblin.service.d/lift.conf && sed -i '/^GOBLIN_ALLOW_UNLIMITED=/d' /etc/uptime-goblin.env && systemctl daemon-reload"
    );
    assert.equal(property('CPUQuotaPerSecUSec'), 'infinity');
    const cpu = await failedStart('GOBLIN_SUPERVISED=1');
    assert.match(
      cpu,
      /^CPU limit: none \((Uptime Goblin's cgroup has no cpu controller|cpu\.max is max), and no CPU set of Uptime Goblin's own limits it: /m
    );
    assert.match(cpu, /set GOBLIN_ALLOW_UNLIMITED=cpu in Uptime Goblin's environment/);
  }
);
