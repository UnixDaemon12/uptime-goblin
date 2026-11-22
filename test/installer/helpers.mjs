// Shared set-up for the installer tests: a scratch "host" (GOBLIN_INSTALL_ROOT) with fake
// systemctl, journalctl, npm and account tools on PATH, and release source trees built from
// deploy/manifest.txt.
import fs from 'node:fs';
import os from 'node:os';
import net from 'node:net';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { readManifest } from '../../scripts/check.mjs';

export const repository = fileURLToPath(new URL('../../', import.meta.url));
const fakeBin = fileURLToPath(new URL('./fake-bin/', import.meta.url));
const fakeServer = fileURLToPath(new URL('./fake-server.mjs', import.meta.url));

// TEST_REQUIRE lists what must be present; anything else may be skipped (see test/setup.mjs).
export function required(name) {
  return (process.env.TEST_REQUIRE || '')
    .split(',')
    .map(item => item.trim())
    .includes(name);
}

// The admin password in the /etc/uptime-goblin.env that makeHost writes (synthetic, at least 12
// characters, as Uptime Goblin requires).
export const testPassword = 'installer-test-password';

export function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

export function temporary(t, prefix) {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

// A release source tree: every manifest file from this repository plus the installer and unit,
// with the given version. `mode` swaps server.mjs for the contract stand-in (fake-server.mjs).
export function makeSource(t, { version = '1.4.3-test.1', mode, change } = {}) {
  const source = temporary(t, 'orbit-source-');
  const files = [
    ...readManifest(repository),
    'deploy/install.sh',
    'deploy/install-lxc.sh',
    'deploy/uptime-goblin.service',
  ];
  for (const file of files) {
    fs.mkdirSync(path.dirname(path.join(source, file)), { recursive: true });
    fs.copyFileSync(path.join(repository, file), path.join(source, file));
  }
  const pkg = JSON.parse(fs.readFileSync(path.join(source, 'package.json'), 'utf8'));
  fs.writeFileSync(
    path.join(source, 'package.json'),
    JSON.stringify({ ...pkg, version }, null, 2) + '\n'
  );
  if (mode)
    fs.writeFileSync(
      path.join(source, 'server.mjs'),
      fs
        .readFileSync(fakeServer, 'utf8')
        .replace("const mode = '__MODE__';", `const mode = ${JSON.stringify(mode)};`)
    );
  if (change) fs.appendFileSync(path.join(source, 'public', 'style.css'), `\n/* ${change} */\n`);
  return source;
}

// A scratch host. `node` is reached through a symlink, as /usr/bin/node usually is, so the tests
// can tell the unresolved path from the file it points to.
export async function makeHost(t) {
  // Not temporary(): the directory must outlive the service, which is stopped first (below).
  const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-host-')));
  const root = path.join(base, 'root'),
    bin = path.join(base, 'bin'),
    nodeBin = path.join(base, 'node', 'bin'),
    systemd = path.join(base, 'systemd');
  for (const directory of [
    path.join(root, 'run/systemd/system'),
    path.join(root, 'etc'),
    bin,
    nodeBin,
    systemd,
  ])
    fs.mkdirSync(directory, { recursive: true });
  for (const name of fs.readdirSync(fakeBin)) {
    fs.copyFileSync(path.join(fakeBin, name), path.join(bin, name));
    fs.chmodSync(path.join(bin, name), 0o755);
  }
  fs.symlinkSync(process.execPath, path.join(nodeBin, 'node'));
  const port = await freePort();
  // An install as the installer leaves one: Uptime Goblin always requires an admin password, and the
  // installer refuses, changing nothing, an /etc/uptime-goblin.env that gives Uptime Goblin none while the data
  // directory has no auth.json. A synthetic test value, never a real one.
  fs.writeFileSync(
    path.join(root, 'etc/uptime-goblin.env'),
    `HOST=127.0.0.1\nPORT=${port}\nGOBLIN_ALLOWED_HOSTS=localhost:${port}\nGOBLIN_PASSWORD=${testPassword}\n`,
    { mode: 0o600 }
  );
  const host = {
    base,
    root,
    port,
    nodeBin,
    node: path.join(nodeBin, 'node'),
    env: {
      PATH: [bin, nodeBin, '/usr/bin', '/bin', '/usr/sbin', '/sbin'].join(path.delimiter),
      GOBLIN_INSTALL_ROOT: root,
      // The installer takes GOBLIN_INSTALL_ROOT only beside this test guard.
      GOBLIN_INSTALLER_TEST: '1',
      FAKE_SYSTEMD_DIR: systemd,
      FAKE_NPM_MODULES: path.join(repository, 'node_modules'),
      TMPDIR: os.tmpdir(),
      LANG: 'C.UTF-8',
    },
    path: relative => path.join(root, relative),
    state: () => {
      try {
        return JSON.parse(fs.readFileSync(path.join(systemd, 'main.json'), 'utf8'));
      } catch {
        return null;
      }
    },
    calls: () => {
      try {
        return fs.readFileSync(path.join(systemd, 'calls.log'), 'utf8');
      } catch {
        return '';
      }
    },
    // The whole service log the fake systemctl keeps, and the fake journalctl as the installer
    // runs it (its --since=@seconds, FAKE_JOURNALCTL_FAULT and FAKE_JOURNALCTL_LATE model what a
    // journal can return, not journald's behaviour, see fake-bin/journalctl).
    journal: () => {
      try {
        return fs.readFileSync(path.join(systemd, 'journal.log'), 'utf8');
      } catch {
        return '';
      }
    },
    journalctl: (...args) =>
      spawnSync(path.join(bin, 'journalctl'), args, { env: host.env, encoding: 'utf8' }),
    // The arguments of each fake journalctl call so far, the installer's and the test's, one
    // string each (fake-bin/journalctl notes them in journalctl.calls).
    journalctlCalls: () => {
      try {
        return fs
          .readFileSync(path.join(systemd, 'journalctl.calls'), 'utf8')
          .split('\n')
          .filter(Boolean);
      } catch {
        return [];
      }
    },
    status: () => {
      try {
        return JSON.parse(
          fs.readFileSync(path.join(root, 'var/lib/uptime-goblin/run/status.json'), 'utf8')
        );
      } catch {
        return null;
      }
    },
    installedVersion: (tree = 'opt/uptime-goblin') =>
      JSON.parse(fs.readFileSync(path.join(root, tree, 'package.json'), 'utf8')).version,
    systemctl: (...args) =>
      spawnSync(path.join(bin, 'systemctl'), args, { env: host.env, encoding: 'utf8' }),
    install: (source, args = [], env = {}, options = {}) =>
      runInstaller(source, args, { ...host.env, ...env }, options),
  };
  // orbit.service's state, the unit of a host with the Orbit layout (fake-bin/systemctl.cjs).
  host.orbitState = () => {
    try {
      return JSON.parse(fs.readFileSync(path.join(systemd, 'orbit.main.json'), 'utf8'));
    } catch {
      return null;
    }
  };
  // Never leave a service process behind, whatever the test did; then remove the host.
  t.after(() => {
    for (const [unit, state] of [
      ['uptime-goblin.service', host.state],
      ['orbit.service', host.orbitState],
    ]) {
      host.systemctl('stop', unit);
      const now = state();
      for (const pid of [now?.pid, now?.supervisor])
        if (pid)
          try {
            process.kill(pid, 'SIGKILL');
          } catch {}
    }
    fs.rmSync(base, { recursive: true, force: true });
  });
  return host;
}

// A scratch host without /etc/uptime-goblin.env, as on a first install. The installer then writes one
// with PORT=4317, Uptime Goblin's default, which an Uptime Goblin run with its defaults (or another test's) may
// hold on the test machine, so every node the installer starts loads a hook that writes this
// host's free port in its place. `host.wroteDefaultPort()` says whether the installer wrote
// PORT=4317 (the hook saw it).
export async function makeFreshHost(t) {
  const host = await makeHost(t);
  const envFile = host.path('etc/uptime-goblin.env'),
    marker = path.join(host.base, 'wrote-port-4317'),
    hook = path.join(host.base, 'fresh-port-hook.mjs');
  fs.rmSync(envFile);
  fs.writeFileSync(
    hook,
    `import fs from 'node:fs';
     import path from 'node:path';
     import { syncBuiltinESMExports } from 'node:module';
     const write = fs.writeFileSync;
     fs.writeFileSync = function (file, data, ...rest) {
       if (typeof file === 'string' && path.resolve(file) === ${JSON.stringify(envFile)} &&
           typeof data === 'string' && /^PORT=4317$/m.test(data)) {
         write(${JSON.stringify(marker)}, '');
         data = data.replace(/^PORT=4317$/m, 'PORT=${host.port}');
       }
       return write.call(this, file, data, ...rest);
     };
     syncBuiltinESMExports();`
  );
  host.env.NODE_OPTIONS = `--import=${pathToFileURL(hook).href}`;
  host.wroteDefaultPort = () => fs.existsSync(marker);
  return host;
}

// `timeout` (ms) bounds a run that could hang, such as one that would wait on a FIFO without
// the fix under test: the installer and everything it started (its own process group) are
// killed, and the result has status null.
// `script` runs another installer file of the source (deploy/install-lxc.sh, the old name's shim).
export function runInstaller(source, args, env, { timeout, script = 'deploy/install.sh' } = {}) {
  return new Promise(resolve => {
    const started = Date.now();
    const child = spawn('bash', [path.join(source, script), ...args], {
      env,
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: Boolean(timeout),
    });
    let stdout = '',
      stderr = '';
    const timer =
      timeout &&
      setTimeout(() => {
        stderr += `\n[test] the installer was still running after ${timeout} ms and was killed\n`;
        try {
          process.kill(-child.pid, 'SIGKILL');
        } catch {}
      }, timeout);
    child.stdout.on('data', chunk => (stdout += chunk));
    child.stderr.on('data', chunk => (stderr += chunk));
    child.on('close', status => {
      clearTimeout(timer);
      resolve({ status, stdout, stderr, output: stdout + stderr, ms: Date.now() - started });
    });
  });
}
