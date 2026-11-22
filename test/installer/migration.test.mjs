// The installer's migration from the Orbit layout (releases before 1.5, before the rename to
// Uptime Goblin) to the Uptime Goblin one (deploy/install.sh, "Renamed from Orbit"): the move, the
// rollback that restores the Orbit layout exactly, a run again after one cut short at each step,
// the refusal of a move that would cross file systems, and a first install that uses only the new
// names. A scratch host as in installer.test.mjs, with the fake systemd, account tools and
// runuser of fake-bin/; every value is synthetic.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { makeFreshHost, makeHost, makeSource, repository, testPassword } from './helpers.mjs';

const ok = result => `status ${result.status}\n${result.output}`;
// Synthetic keys (64 hex digits, not one byte repeated, which the key reader refuses).
const testKey = label => `${crypto.createHash('sha256').update(label).digest('hex')}\n`;
const keyText = testKey('migration test key');

// The unit an Orbit installer (1.4.x) wrote: this release's unit with the Orbit names.
function orbitUnit(node) {
  return fs
    .readFileSync(path.join(repository, 'deploy/uptime-goblin.service'), 'utf8')
    .replace(/^ExecStart=.*$/m, `ExecStart=${node} /opt/orbit/server.mjs --supervised`)
    .replaceAll('/opt/uptime-goblin', '/opt/orbit')
    .replaceAll('/var/lib/uptime-goblin', '/var/lib/orbit')
    .replaceAll('/etc/uptime-goblin.env', '/etc/orbit.env')
    .replaceAll('GOBLIN_', 'ORBIT_')
    .replace(/^(User|Group|StateDirectory)=uptime-goblin$/gm, '$1=orbit');
}

/**
 * A scratch host with the Orbit layout, as an Orbit installer left it: orbit.service (enabled, and
 * running unless `running` is false) runs `version` from /opt/orbit on /var/lib/orbit, with
 * /etc/orbit.env (ORBIT_ names), the account and group orbit, and, with `key`, the key file
 * /etc/orbit/secret.key that /etc/orbit.env names (as a 1.5 pre-release installer left it);
 * `dropIn`, the text of /etc/systemd/system/orbit.service.d/limits.conf.
 */
async function makeOrbitHost(
  t,
  { version = '1.4.3-test.1', key = true, running = true, dropIn, env = '' } = {}
) {
  const host = await makeHost(t);
  fs.rmSync(host.path('etc/uptime-goblin.env'));
  const old = makeSource(t, { version, mode: 'ok' });
  fs.cpSync(old, host.path('opt/orbit'), { recursive: true });
  fs.mkdirSync(host.path('var/lib/orbit'), { recursive: true, mode: 0o700 });
  fs.writeFileSync(host.path('var/lib/orbit/marker'), 'the data\n', { mode: 0o600 });
  let settings = `HOST=127.0.0.1\nPORT=${host.port}\nORBIT_ALLOWED_HOSTS=localhost:${host.port}\nORBIT_PASSWORD=${testPassword}\n${env}`;
  if (key) {
    fs.mkdirSync(host.path('etc/orbit'), { mode: 0o750 });
    fs.writeFileSync(host.path('etc/orbit/secret.key'), keyText, { mode: 0o440 });
    settings += 'ORBIT_SECRET_KEY_FILE=/etc/orbit/secret.key\n';
  }
  fs.writeFileSync(host.path('etc/orbit.env'), settings, { mode: 0o600 });
  fs.mkdirSync(host.path('etc/systemd/system'), { recursive: true });
  fs.writeFileSync(host.path('etc/systemd/system/orbit.service'), orbitUnit(host.node));
  if (dropIn) {
    fs.mkdirSync(host.path('etc/systemd/system/orbit.service.d'));
    fs.writeFileSync(host.path('etc/systemd/system/orbit.service.d/limits.conf'), dropIn);
  }
  fs.writeFileSync(
    path.join(host.env.FAKE_SYSTEMD_DIR, 'accounts.json'),
    JSON.stringify({
      users: { orbit: { uid: 999, gid: 999, home: '/opt/orbit' } },
      groups: { orbit: 999 },
    })
  );
  host.systemctl('enable', 'orbit.service');
  if (running) {
    host.systemctl('start', 'orbit.service');
    await until(() => fs.existsSync(host.path('var/lib/orbit/run/status.json')));
  }
  return host;
}

async function until(condition, ms = 10000) {
  for (const end = Date.now() + ms; Date.now() < end; ) {
    if (condition()) return;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  assert.fail('timed out');
}

const accounts = host =>
  JSON.parse(fs.readFileSync(path.join(host.env.FAKE_SYSTEMD_DIR, 'accounts.json'), 'utf8'));
const exists = (host, file) => {
  try {
    fs.lstatSync(host.path(file));
    return true;
  } catch {
    return false;
  }
};
const mode = (host, file) => (fs.statSync(host.path(file)).mode & 0o7777).toString(8);
const alive = pid => {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
};

// What the Orbit layout holds, to compare before and after: each file and directory under the
// Orbit paths with its mode and a hash of its bytes (run/, which the running service rewrites at
// every start, left out), the accounts, and which units are enabled.
function layout(host) {
  const out = {};
  const walk = relative => {
    const at = host.path(relative);
    let stat;
    try {
      stat = fs.lstatSync(at);
    } catch {
      return;
    }
    if (/(^|\/)run$/.test(relative) && relative.startsWith('var/lib/')) return;
    const shown = (stat.mode & 0o7777).toString(8);
    if (stat.isSymbolicLink()) out[relative] = `link ${fs.readlinkSync(at)}`;
    else if (stat.isDirectory()) {
      out[relative] = `dir ${shown}`;
      for (const name of fs.readdirSync(at).sort()) walk(path.posix.join(relative, name));
    } else
      out[relative] =
        `${shown} ${crypto.createHash('sha256').update(fs.readFileSync(at)).digest('hex')}`;
  };
  for (const file of [
    'opt/orbit',
    'var/lib/orbit',
    'etc/orbit.env',
    'etc/orbit',
    'etc/systemd/system/orbit.service',
    'etc/systemd/system/orbit.service.d',
  ])
    walk(file);
  out.accounts = JSON.stringify(accounts(host));
  out.enabled = fs
    .readdirSync(host.env.FAKE_SYSTEMD_DIR)
    .filter(name => name.startsWith('enabled-'))
    .sort()
    .join(' ');
  return out;
}

const newPaths = [
  'opt/uptime-goblin',
  'opt/uptime-goblin.previous',
  'var/lib/uptime-goblin',
  'etc/uptime-goblin.env',
  'etc/uptime-goblin',
  'etc/systemd/system/uptime-goblin.service',
  'etc/systemd/system/uptime-goblin.service.d',
  'var/lib/uptime-goblin.migrating',
];

// The Orbit layout is back as it was, with orbit.service running the previous release, and none
// of the Uptime Goblin paths but the new release kept in /opt/uptime-goblin.failed.
function assertRestored(host, before, version = '1.4.3-test.1') {
  assert.deepEqual(layout(host), before, 'the Orbit layout is as it was');
  for (const file of newPaths) assert.equal(exists(host, file), false, `${file} is gone`);
  for (const file of ['etc/orbit.env.migrated', 'etc/systemd/system/orbit.service.migrated'])
    assert.equal(exists(host, file), false, `${file} is gone`);
  const state = host.orbitState();
  assert.ok(state?.pid && alive(state.pid), 'orbit.service runs again');
  const status = JSON.parse(fs.readFileSync(host.path('var/lib/orbit/run/status.json'), 'utf8'));
  assert.equal(status.version, version);
}

// The Uptime Goblin layout after a migration that worked.
function assertMigrated(host, { version = '1.5.0-test.1', key = true } = {}) {
  for (const file of [
    'opt/orbit',
    'var/lib/orbit',
    'etc/orbit.env',
    'etc/orbit',
    'etc/systemd/system/orbit.service',
    'etc/systemd/system/orbit.service.d',
    'var/lib/uptime-goblin.migrating',
  ])
    assert.equal(exists(host, file), false, `${file} was moved`);
  assert.equal(host.installedVersion(), version);
  assert.equal(host.installedVersion('opt/uptime-goblin.previous'), '1.4.3-test.1');
  assert.equal(fs.readFileSync(host.path('var/lib/uptime-goblin/marker'), 'utf8'), 'the data\n');
  assert.equal(mode(host, 'var/lib/uptime-goblin'), '700');
  const env = fs.readFileSync(host.path('etc/uptime-goblin.env'), 'utf8');
  assert.equal(mode(host, 'etc/uptime-goblin.env'), '600');
  assert.match(env, new RegExp(`^GOBLIN_PASSWORD=${testPassword}$`, 'm'));
  assert.match(env, /^GOBLIN_ALLOWED_HOSTS=localhost:\d+$/m);
  assert.doesNotMatch(env, /^ORBIT_/m, 'every ORBIT_ name is written as its GOBLIN_ one');
  assert.match(
    fs.readFileSync(host.path('etc/orbit.env.migrated'), 'utf8'),
    /^ORBIT_PASSWORD=/m,
    'the old settings file is kept'
  );
  assert.ok(exists(host, 'etc/systemd/system/orbit.service.migrated'), 'the old unit is kept');
  if (key) {
    assert.match(env, /^GOBLIN_SECRET_KEY_FILE=\/etc\/uptime-goblin\/secret\.key$/m);
    assert.equal(fs.readFileSync(host.path('etc/uptime-goblin/secret.key'), 'utf8'), keyText);
    assert.equal(mode(host, 'etc/uptime-goblin'), '750');
    assert.equal(mode(host, 'etc/uptime-goblin/secret.key'), '440');
  }
  assert.deepEqual(accounts(host), {
    users: { 'uptime-goblin': { uid: 999, gid: 999, home: '/opt/uptime-goblin' } },
    groups: { 'uptime-goblin': 999 },
  });
  const systemd = host.env.FAKE_SYSTEMD_DIR;
  assert.ok(fs.existsSync(path.join(systemd, 'enabled-uptime-goblin.service')));
  assert.equal(fs.existsSync(path.join(systemd, 'enabled-orbit.service')), false);
  assert.ok(alive(host.state().pid), 'uptime-goblin.service runs');
  assert.equal(host.status().version, version);
  assert.equal(host.orbitState()?.pid || 0, 0, 'orbit.service does not run');
}

/**
 * A node --import hook for every node the installer starts (the installer's own steps and the
 * fake systemctl and account tools), which models what this file tests and a host cannot be
 * made to do here. `crash`: kill the installer's whole process group (the installer runs in its
 * own, `timeout`) right after a rename to that path (`rename:<path>`) or once a fake tool run with
 * those arguments is done (`argv:<arguments>`), as a power cut or kill -9 would. `device`: report
 * another device for that path, as for a mount point. `exdev`: a rename of that path fails with
 * EXDEV, as across file systems.
 */
function hook(host, { crash = '', device = '', exdev = '' }) {
  const file = path.join(host.base, `migration-hook-${crypto.randomUUID()}.mjs`);
  fs.writeFileSync(
    file,
    `import fs from 'node:fs';
     import { syncBuiltinESMExports } from 'node:module';
     const crash = ${JSON.stringify(crash)}, device = ${JSON.stringify(device)}, exdev = ${JSON.stringify(exdev)};
     const die = () => process.kill(0, 'SIGKILL');
     const rename = fs.renameSync;
     fs.renameSync = function (from, to) {
       if (exdev && String(from) === exdev)
         throw Object.assign(new Error('EXDEV: cross-device link not permitted'), { code: 'EXDEV' });
       const result = rename.call(this, from, to);
       if (crash === 'rename:' + String(to)) die();
       return result;
     };
     if (crash.startsWith('argv:') && process.argv.slice(2).join(' ') === crash.slice(5))
       process.on('exit', die);
     for (const name of ['lstatSync', 'statSync']) {
       const real = fs[name];
       fs[name] = function (at, ...rest) {
         const stat = real.call(this, at, ...rest);
         if (device && stat && String(at) === device)
           return Object.assign(Object.create(Object.getPrototypeOf(stat)), stat, { dev: stat.dev + 1 });
         return stat;
       };
     }
     syncBuiltinESMExports();`
  );
  return { NODE_OPTIONS: `--import=${pathToFileURL(file).href}` };
}

test('an upgrade from the Orbit layout moves every part of it, in order, logged, after the checks', async t => {
  const host = await makeOrbitHost(t, { dropIn: '[Service]\nMemoryMax=768M\n' });
  const source = makeSource(t, { version: '1.5.0-test.1', mode: 'ok' });
  const result = await host.install(source);
  assert.equal(result.status, 0, ok(result));
  assertMigrated(host);
  assert.equal(
    fs.readFileSync(host.path('etc/systemd/system/uptime-goblin.service.d/limits.conf'), 'utf8'),
    '[Service]\nMemoryMax=768M\n',
    'the drop-in moved with its directory'
  );
  const steps = [
    'This host has the Orbit layout',
    'Preparing pinned application dependencies',
    'Moving this installation from the Orbit layout to the Uptime Goblin one',
    '  Stopped orbit.service.',
    '  Renamed /var/lib/orbit to /var/lib/uptime-goblin.',
    '  Wrote /etc/uptime-goblin.env from /etc/orbit.env (3 ORBIT_ names written as GOBLIN_), mode 0600.',
    '  Kept /etc/orbit.env as /etc/orbit.env.migrated.',
    '  Renamed /etc/orbit to /etc/uptime-goblin.',
    '  Renamed the account orbit to uptime-goblin.',
    '  Renamed the group orbit to uptime-goblin.',
    '  Renamed /etc/systemd/system/orbit.service.d to /etc/systemd/system/uptime-goblin.service.d.',
    '  Disabled orbit.service and kept its unit file as /etc/systemd/system/orbit.service.migrated.',
    '  Renamed /opt/orbit to /opt/uptime-goblin.',
    'Uptime Goblin 1.5.0-test.1 is running',
    'This installation now has the Uptime Goblin layout.',
  ];
  let at = -1;
  for (const step of steps) {
    const next = result.stdout.indexOf(step, at + 1);
    assert.ok(next > at, `"${step}" follows, in ${result.stdout}`);
    at = next;
  }
  // Each step's own call, in this order: no account was made, the old one renamed.
  assert.deepEqual(
    fs.readFileSync(path.join(host.env.FAKE_SYSTEMD_DIR, 'accounts.log'), 'utf8').split('\n'),
    ['usermod -l uptime-goblin -d /opt/uptime-goblin orbit', 'groupmod -n uptime-goblin orbit', '']
  );
  // The checks read the Orbit files where they were, and named them so.
  assert.match(result.stdout, /Preserving existing \/etc\/orbit\.env/);
  // A second run is an ordinary upgrade of the Uptime Goblin layout.
  const again = await host.install(makeSource(t, { version: '1.5.0-test.2', mode: 'ok' }));
  assert.equal(again.status, 0, ok(again));
  assert.doesNotMatch(again.output, /Orbit layout/);
  assert.equal(host.installedVersion(), '1.5.0-test.2');
});

test('the migration writes /etc/uptime-goblin.env with the GOBLIN_ names and the moved paths, values as they were', async t => {
  const host = await makeOrbitHost(t, {
    env: '# a comment kept as it is\nORBIT_TRUST_PROXY=loopback\nGOBLIN_LEGACY_BASIC=0\nORBIT_LEGACY_BASIC=0\nORBIT_SECRET_KEY_PREVIOUS_FILE=/etc/orbit/old.key\n',
  });
  fs.writeFileSync(host.path('etc/orbit/old.key'), testKey('migration test previous key'), {
    mode: 0o440,
  });
  // (A proxy that 1.4.x did not record: the operator checked it.)
  const result = await host.install(makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }), [
    '--proxy-proto-checked',
  ]);
  assert.equal(result.status, 0, ok(result));
  assert.equal(
    fs.readFileSync(host.path('etc/uptime-goblin.env'), 'utf8'),
    `HOST=127.0.0.1\nPORT=${host.port}\nGOBLIN_ALLOWED_HOSTS=localhost:${host.port}\nGOBLIN_PASSWORD=${testPassword}\n# a comment kept as it is\nGOBLIN_TRUST_PROXY=loopback\nGOBLIN_LEGACY_BASIC=0\nGOBLIN_LEGACY_BASIC=0\nGOBLIN_SECRET_KEY_PREVIOUS_FILE=/etc/uptime-goblin/old.key\nGOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key\n`
  );
});

test('an ORBIT_ name and its GOBLIN_ one with different values are refused before anything changes', async t => {
  const host = await makeOrbitHost(t, { env: 'GOBLIN_LEGACY_BASIC=1\nORBIT_LEGACY_BASIC=0\n' });
  const before = layout(host);
  const result = await host.install(makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }));
  assert.equal(result.status, 1, ok(result));
  assert.match(
    result.stderr,
    /GOBLIN_LEGACY_BASIC and ORBIT_LEGACY_BASIC are both set, to different values[^\n]*\/etc\/orbit\.env[^\n]*Nothing was changed\./
  );
  assert.deepEqual(layout(host), before);
  assert.ok(alive(host.orbitState().pid));
});

test('a failed upgrade restores the Orbit layout exactly, and the previous release serves again', async t => {
  const host = await makeOrbitHost(t, { dropIn: '[Service]\nTasksMax=200\n' });
  const before = layout(host);
  const result = await host.install(makeSource(t, { version: '1.5.0-test.1', mode: 'crash' }), [
    '--verify-timeout',
    '5',
  ]);
  assert.equal(result.status, 1, ok(result));
  assert.match(
    result.stderr,
    /Restoring the previous version from \/opt\/uptime-goblin\.previous and the Orbit layout/
  );
  assert.match(
    result.stdout,
    /Restoring the Orbit layout:[\s\S]*Renamed \/var\/lib\/uptime-goblin back to \/var\/lib\/orbit\.[\s\S]*Started orbit\.service again\./
  );
  assert.match(
    result.stderr,
    /The previous version is running again; the upgrade to 1\.5\.0-test\.1 was rolled back\. The Orbit layout is restored as it was, and orbit\.service runs it\./
  );
  assertRestored(host, before);
  assert.equal(host.installedVersion('opt/uptime-goblin.failed'), '1.5.0-test.1');
  // The next upgrade migrates again.
  const again = await host.install(makeSource(t, { version: '1.5.0-test.2', mode: 'ok' }));
  assert.equal(again.status, 0, ok(again));
  assertMigrated(host, { version: '1.5.0-test.2' });
});

test('a failed upgrade of an Orbit layout without a release restores it as it was too', async t => {
  const host = await makeOrbitHost(t, { running: false });
  fs.rmSync(host.path('opt/orbit'), { recursive: true });
  const before = layout(host);
  const result = await host.install(makeSource(t, { version: '1.5.0-test.1', mode: 'refuse' }), [
    '--verify-timeout',
    '5',
  ]);
  assert.equal(result.status, 1, ok(result));
  assert.match(
    result.stderr,
    /There is no previous version to restore; the Orbit layout is as it was/
  );
  assert.deepEqual(layout(host), before);
  for (const file of newPaths) assert.equal(exists(host, file), false, `${file} is gone`);
  assert.equal(host.orbitState()?.pid || 0, 0, 'orbit.service, which did not run, is not started');
});

// A host without /etc/orbit: the key step makes /etc/orbit/secret.key (and names it in
// /etc/orbit.env) before the migration, which moves it to /etc/uptime-goblin. A failed upgrade
// moves it back, so no Uptime Goblin path is left to make the next run refuse a host with parts of
// both layouts, and keeps it there: what the failed start sealed opens only with it, and the
// next upgrade uses it again.
test('a failed upgrade of an Orbit layout without /etc/orbit leaves no /etc/uptime-goblin, keeps the key it made, and the next run migrates', async t => {
  const host = await makeOrbitHost(t, { key: false });
  const before = layout(host);
  assert.equal(exists(host, 'etc/orbit'), false);
  const result = await host.install(makeSource(t, { version: '1.5.0-test.1', mode: 'crash' }), [
    '--verify-timeout',
    '5',
  ]);
  assert.equal(result.status, 1, ok(result));
  for (const file of newPaths) assert.equal(exists(host, file), false, `${file} is gone`);
  const after = layout(host),
    key = fs.readFileSync(host.path('etc/orbit/secret.key'), 'utf8');
  assert.match(key, /^[0-9a-f]{64}\n$/);
  assert.equal(after['etc/orbit'], 'dir 750');
  assert.match(after['etc/orbit/secret.key'], /^440 /);
  assert.equal(
    fs.readFileSync(host.path('etc/orbit.env'), 'utf8').split('\n').at(-2),
    'ORBIT_SECRET_KEY_FILE=/etc/orbit/secret.key'
  );
  for (const file of ['etc/orbit', 'etc/orbit/secret.key', 'etc/orbit.env']) {
    delete after[file];
    delete before[file];
  }
  assert.deepEqual(after, before, 'the rest of the Orbit layout is as it was');
  assert.ok(alive(host.orbitState().pid), 'orbit.service runs again');
  const again = await host.install(makeSource(t, { version: '1.5.0-test.2', mode: 'ok' }));
  assert.equal(again.status, 0, ok(again));
  assertMigrated(host, { version: '1.5.0-test.2', key: false });
  assert.equal(fs.readFileSync(host.path('etc/uptime-goblin/secret.key'), 'utf8'), key);
});

// Each step of the migration, and of the upgrade after it, cut short as a power cut or kill -9
// would cut it: the next run undoes what was done, then migrates again and installs.
const cuts = root => [
  ['the stop', 'argv:stop orbit.service'],
  ['the data move', `rename:${root}/var/lib/uptime-goblin`],
  ['the new settings file', `rename:${root}/etc/uptime-goblin.env`],
  ['the old settings file kept', `rename:${root}/etc/orbit.env.migrated`],
  ['the key directory move', `rename:${root}/etc/uptime-goblin`],
  ['the account rename', 'argv:usermod -l uptime-goblin -d /opt/uptime-goblin orbit'],
  ['the group rename', 'argv:groupmod -n uptime-goblin orbit'],
  ['the drop-in move', `rename:${root}/etc/systemd/system/uptime-goblin.service.d`],
  ['the old unit disabled', 'argv:disable --quiet orbit.service'],
  ['the old unit kept', `rename:${root}/etc/systemd/system/orbit.service.migrated`],
  ['the code move', `rename:${root}/opt/uptime-goblin`],
  ['the new unit enabled', 'argv:enable --quiet uptime-goblin.service'],
  [
    'the verification',
    'argv:show --property=MainPID --property=ActiveState --property=Result uptime-goblin.service',
  ],
];
for (const index of cuts('').keys()) {
  test(`a run cut short at ${cuts('')[index][0]} is undone by the next run, which migrates again`, async t => {
    const host = await makeOrbitHost(t, { dropIn: '[Service]\nTasksMax=200\n' });
    const before = layout(host);
    const [, crash] = cuts(host.root)[index];
    const cut = await host.install(
      makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }),
      [],
      hook(host, { crash }),
      { timeout: 120000 }
    );
    assert.equal(cut.status, null, `the run was cut short: ${ok(cut)}`);
    assert.ok(exists(host, 'var/lib/uptime-goblin.migrating'), 'the record is there');
    // A usage error stops a run before it reads or undoes anything.
    const undo = await host.install(makeSource(t, { version: '1.5.0-test.2', mode: 'ok' }), [
      '--verify-timeout',
      'nope',
    ]);
    assert.equal(undo.status, 2, ok(undo));
    assert.equal(exists(host, 'var/lib/uptime-goblin.migrating'), true, 'usage errors come first');
    const again = await host.install(makeSource(t, { version: '1.5.0-test.2', mode: 'ok' }));
    assert.equal(again.status, 0, ok(again));
    assert.match(again.stderr, /An earlier run of this installer was cut short/);
    assert.match(again.stdout, /The Orbit layout is restored\./);
    const restored = again.stdout.indexOf('The Orbit layout is restored.');
    assert.ok(restored < again.stdout.indexOf('Preparing pinned application dependencies'));
    assertMigrated(host, { version: '1.5.0-test.2' });
    assert.equal(layout(host).accounts, JSON.stringify(accounts(host)));
    assert.notDeepEqual(layout(host), before);
  });
}

test('a run cut short while it restored the Orbit layout is finished by the next run', async t => {
  const host = await makeOrbitHost(t);
  const before = layout(host);
  const cut = await host.install(
    makeSource(t, { version: '1.5.0-test.1', mode: 'crash' }),
    ['--verify-timeout', '5'],
    hook(host, { crash: `rename:${host.root}/etc/orbit` }),
    { timeout: 120000 }
  );
  assert.equal(cut.status, null, ok(cut));
  assert.match(cut.stdout, /Restoring the Orbit layout:/);
  const again = await host.install(makeSource(t, { version: '1.5.0-test.1', mode: 'crash' }), [
    '--verify-timeout',
    '5',
  ]);
  assert.equal(again.status, 1, ok(again));
  assert.match(again.stderr, /An earlier run of this installer was cut short/);
  assertRestored(host, before);
});

test('a move that would cross file systems is refused before anything changes', async t => {
  for (const [what, options, message] of [
    [
      'a mount point',
      host => ({ device: host.path('var/lib/orbit') }),
      /This installation cannot be moved from the Orbit layout to the Uptime Goblin one: \/var\/lib\/orbit is a mount point \(another file system than \/var\/lib\), which cannot be renamed to \/var\/lib\/uptime-goblin\.[^\n]*Nothing was changed\./,
    ],
    [
      'a symbolic link',
      host => {
        fs.renameSync(host.path('etc/orbit'), host.path('etc/orbit-real'));
        fs.symlinkSync('orbit-real', host.path('etc/orbit'));
        return {};
      },
      /\/etc\/orbit is a symbolic link: the migration renames the files themselves and never follows a link\.[^\n]*Nothing was changed\./,
    ],
  ]) {
    const host = await makeOrbitHost(t);
    const env = hook(host, options(host));
    const before = layout(host);
    const result = await host.install(
      makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }),
      [],
      env
    );
    assert.equal(result.status, 1, `${what}: ${ok(result)}`);
    assert.match(result.stderr, message, what);
    assert.doesNotMatch(result.stdout, /Preparing pinned application dependencies/, what);
    assert.deepEqual(layout(host), before, what);
    for (const file of newPaths) assert.equal(exists(host, file), false, `${what}: ${file}`);
    assert.ok(alive(host.orbitState().pid), `${what}: orbit.service still runs`);
  }
  // A rename that fails anyway (EXDEV): the steps done are undone and orbit.service starts again.
  const host = await makeOrbitHost(t);
  const before = layout(host);
  const result = await host.install(
    makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }),
    [],
    hook(host, { exdev: host.path('etc/orbit') })
  );
  assert.equal(result.status, 1, ok(result));
  assert.match(
    result.stderr,
    /The migration from the Orbit layout stopped: \/etc\/orbit cannot be renamed to \/etc\/uptime-goblin: they are on different file systems\./
  );
  assert.match(
    result.stderr,
    /Uptime Goblin was not installed, and the Orbit layout is as it was\./
  );
  assertRestored(host, before);
  assert.equal(exists(host, 'opt/uptime-goblin.failed'), false);
});

// Going back to Orbit by hand after an upgrade that worked (deploy/install.sh
// --restore-orbit-layout, docs/installation.md, Rolling back 1.5 to 1.4.3): 1.4.x reads only its
// ORBIT_ settings and the Orbit paths, which the migration renamed, so swapping the code alone
// cannot bring it back. The Orbit layout is back as it was before the upgrade, but for the data,
// which 1.5 has run on, and the next upgrade migrates again.
const withoutData = snapshot =>
  Object.fromEntries(
    Object.entries(snapshot).filter(([file]) => !file.startsWith('var/lib/orbit/'))
  );

test('after an upgrade that worked, --restore-orbit-layout puts the Orbit layout back with the kept Orbit release, and the next upgrade migrates again', async t => {
  const host = await makeOrbitHost(t, { dropIn: '[Service]\nTasksMax=200\n' });
  const before = layout(host);
  const source = makeSource(t, { version: '1.5.0-test.1', mode: 'ok' });
  const upgraded = await host.install(source);
  assert.equal(upgraded.status, 0, ok(upgraded));
  assertMigrated(host);
  // Settings changed under Uptime Goblin are kept for the operator, never lost.
  fs.appendFileSync(host.path('etc/uptime-goblin.env'), 'GOBLIN_AUDIT_RETENTION_DAYS=120\n');
  const settings = fs.readFileSync(host.path('etc/uptime-goblin.env'), 'utf8');
  const result = await host.install(source, ['--restore-orbit-layout']);
  assert.equal(result.status, 0, ok(result));
  assert.match(
    result.stdout,
    /^Going back to Orbit 1\.4\.3-test\.1, kept in \/opt\/uptime-goblin\.previous, with the Orbit layout\.$/m
  );
  assert.match(
    result.stdout,
    /Restoring the Orbit layout:[\s\S]*Renamed \/var\/lib\/uptime-goblin back to \/var\/lib\/orbit\.[\s\S]*Started orbit\.service again\./
  );
  assert.match(
    result.stdout,
    /^Orbit 1\.4\.3-test\.1 runs again from \/opt\/orbit as orbit\.service, on \/var\/lib\/orbit with \/etc\/orbit\.env\. The settings Uptime Goblin ran with are kept as \/etc\/uptime-goblin\.env\.kept/m
  );
  assert.doesNotMatch(
    result.output,
    /Preparing pinned application dependencies/,
    'nothing installed'
  );
  assert.deepEqual(withoutData(layout(host)), withoutData(before), 'the Orbit layout as it was');
  assert.equal(fs.readFileSync(host.path('var/lib/orbit/marker'), 'utf8'), 'the data\n');
  assert.equal(mode(host, 'var/lib/orbit'), '700');
  for (const file of newPaths.filter(file => file !== 'opt/uptime-goblin.previous'))
    assert.equal(exists(host, file), false, `${file} is gone`);
  assert.equal(exists(host, 'opt/uptime-goblin.previous'), false);
  for (const file of ['etc/orbit.env.migrated', 'etc/systemd/system/orbit.service.migrated'])
    assert.equal(exists(host, file), false, `${file} is back in place`);
  assert.equal(fs.readFileSync(host.path('etc/uptime-goblin.env.kept'), 'utf8'), settings);
  assert.equal(mode(host, 'etc/uptime-goblin.env.kept'), '600');
  assert.equal(host.installedVersion('opt/uptime-goblin.failed'), '1.5.0-test.1');
  const state = host.orbitState();
  assert.ok(state?.pid && alive(state.pid), 'orbit.service runs');
  assert.equal(
    JSON.parse(fs.readFileSync(host.path('var/lib/orbit/run/status.json'), 'utf8')).version,
    '1.4.3-test.1'
  );
  assert.equal(host.state()?.pid || 0, 0, 'uptime-goblin.service does not run');
  // Run again: the Orbit layout is there already, and nothing changes.
  const twice = await host.install(source, ['--restore-orbit-layout']);
  assert.equal(twice.status, 1, ok(twice));
  assert.match(twice.stderr, /This host has the Orbit layout already/);
  // The next upgrade migrates again (the kept copies are out of its way).
  fs.rmSync(host.path('opt/uptime-goblin.failed'), { recursive: true });
  const again = await host.install(makeSource(t, { version: '1.5.0-test.2', mode: 'ok' }));
  assert.equal(again.status, 0, ok(again));
  assertMigrated(host, { version: '1.5.0-test.2' });
});

test('--restore-orbit-layout refuses, changing nothing, where there is nothing to go back to or something is in the way', async t => {
  // An install made as Uptime Goblin: no kept Orbit release, settings or unit.
  const fresh = await makeFreshHost(t);
  const source = makeSource(t, { version: '1.5.0-test.1', mode: 'ok' });
  assert.equal((await fresh.install(source)).status, 0);
  const second = await fresh.install(makeSource(t, { version: '1.5.0-test.2', mode: 'ok' }));
  assert.equal(second.status, 0, ok(second));
  const refused = await fresh.install(source, ['--restore-orbit-layout']);
  assert.equal(refused.status, 1, ok(refused));
  assert.match(
    refused.stderr,
    /^This installation cannot go back to the Orbit layout: \/opt\/uptime-goblin\.previous holds Uptime Goblin 1\.5\.0-test\.1, not an Orbit release \(before 1\.5\)[^\n]*\/etc\/orbit\.env\.migrated, which the migration from the Orbit layout keeps, is not there[^\n]*Nothing was changed\.$/m
  );
  assert.equal(fresh.installedVersion(), '1.5.0-test.2');
  assert.ok(alive(fresh.state().pid), 'Uptime Goblin still runs');
  // No other option: it installs nothing.
  const usage = await fresh.install(source, ['--restore-orbit-layout', '--listen', '0.0.0.0']);
  assert.equal(usage.status, 2, ok(usage));
  assert.match(usage.stderr, /--restore-orbit-layout takes no other option but --verify-timeout/);
  // A migrated host with something in the way: the kept settings removed, an account orbit.
  const host = await makeOrbitHost(t);
  assert.equal((await host.install(source)).status, 0);
  fs.renameSync(host.path('etc/orbit.env.migrated'), host.path('root-orbit.env'));
  const before = layout(host);
  const missing = await host.install(source, ['--restore-orbit-layout']);
  assert.equal(missing.status, 1, ok(missing));
  assert.match(
    missing.stderr,
    /\/etc\/orbit\.env\.migrated, which the migration from the Orbit layout keeps, is not there/
  );
  assert.deepEqual(layout(host), before);
  assert.equal(host.installedVersion(), '1.5.0-test.1');
  assert.ok(alive(host.state().pid));
  // The Orbit layout itself: nothing to go back from.
  const orbit = await makeOrbitHost(t);
  const already = await orbit.install(source, ['--restore-orbit-layout']);
  assert.equal(already.status, 1, ok(already));
  assert.match(
    already.stderr,
    /This host has the Orbit layout already, so there is nothing to go back from\. Nothing was changed\./
  );
});

test('a --restore-orbit-layout cut short is finished by the next one', async t => {
  const host = await makeOrbitHost(t);
  const before = layout(host);
  const source = makeSource(t, { version: '1.5.0-test.1', mode: 'ok' });
  assert.equal((await host.install(source)).status, 0);
  const cut = await host.install(
    source,
    ['--restore-orbit-layout'],
    hook(host, { crash: `rename:${host.root}/etc/orbit` }),
    { timeout: 120000 }
  );
  assert.equal(cut.status, null, ok(cut));
  assert.ok(exists(host, 'var/lib/uptime-goblin.migrating'), 'the record is there');
  const again = await host.install(source, ['--restore-orbit-layout']);
  assert.equal(again.status, 0, ok(again));
  assert.match(again.stderr, /An earlier run of this installer was cut short/);
  assert.deepEqual(withoutData(layout(host)), withoutData(before));
  assert.ok(alive(host.orbitState().pid), 'orbit.service runs');
  assert.equal(exists(host, 'var/lib/uptime-goblin.migrating'), false);
});

// A run killed between writing the new settings file's temporary copy and renaming it leaves
// /etc/uptime-goblin.env.goblin-tmp (root's, 0600, GOBLIN_PASSWORD in it), and one killed while
// it wrote the record /var/lib/uptime-goblin.migrating.tmp. Restoring the Orbit layout removes both,
// also when no migration follows (here: going back to Orbit after the cut).
test("restoring the Orbit layout removes the migration's temporary files a cut left", async t => {
  const host = await makeOrbitHost(t);
  const before = layout(host);
  const cut = await host.install(
    makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }),
    [],
    hook(host, { crash: `rename:${host.root}/var/lib/uptime-goblin` }),
    { timeout: 120000 }
  );
  assert.equal(cut.status, null, ok(cut));
  fs.writeFileSync(
    host.path('etc/uptime-goblin.env.goblin-tmp'),
    `GOBLIN_PASSWORD=${testPassword}\n`,
    {
      mode: 0o600,
    }
  );
  fs.writeFileSync(host.path('var/lib/uptime-goblin.migrating.tmp'), '{}\n', { mode: 0o600 });
  const result = await host.install(makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }), [
    '--restore-orbit-layout',
  ]);
  assert.equal(result.status, 0, ok(result));
  for (const file of ['etc/uptime-goblin.env.goblin-tmp', 'var/lib/uptime-goblin.migrating.tmp'])
    assert.equal(exists(host, file), false, `${file} is removed`);
  assertRestored(host, before);
});

test('a host with parts of both layouts and no record is refused, changing nothing', async t => {
  const host = await makeOrbitHost(t);
  fs.writeFileSync(host.path('etc/uptime-goblin.env'), 'HOST=127.0.0.1\n', { mode: 0o600 });
  const before = layout(host);
  const result = await host.install(makeSource(t, { version: '1.5.0-test.1', mode: 'ok' }));
  assert.equal(result.status, 1, ok(result));
  assert.match(
    result.stderr,
    /This host has parts of both the Orbit layout \([^)]*\/etc\/orbit\.env[^)]*\) and the Uptime Goblin one \(\/etc\/uptime-goblin\.env\)[^\n]*Nothing was changed\./
  );
  assert.deepEqual(layout(host), before);
});

test('a first install uses only the Uptime Goblin names, and the old installer name runs it', async t => {
  const host = await makeFreshHost(t);
  const source = makeSource(t, { version: '1.5.0-test.1', mode: 'ok' });
  const result = await host.install(source, [], {}, { script: 'deploy/install-lxc.sh' });
  assert.equal(result.status, 0, ok(result));
  assert.match(
    result.stderr,
    /^deploy\/install-lxc\.sh is deprecated and is removed in 1\.7: run deploy\/install\.sh, which this runs now\.$/m
  );
  assert.doesNotMatch(result.output, /Orbit/, 'no message names Orbit');
  const env = fs.readFileSync(host.path('etc/uptime-goblin.env'), 'utf8');
  assert.match(env, /^GOBLIN_ALLOWED_HOSTS=localhost:4317$/m);
  assert.match(env, /^GOBLIN_PASSWORD=\S{32}$/m);
  assert.match(env, /^GOBLIN_SECRET_KEY_FILE=\/etc\/uptime-goblin\/secret\.key$/m);
  assert.doesNotMatch(env, /ORBIT/);
  assert.match(
    fs.readFileSync(host.path('etc/systemd/system/uptime-goblin.service'), 'utf8'),
    /^User=uptime-goblin$[\s\S]*^Environment=GOBLIN_DATA_DIR=\/var\/lib\/uptime-goblin$[\s\S]*^EnvironmentFile=\/etc\/uptime-goblin\.env$/m
  );
  for (const file of [
    'opt/orbit',
    'var/lib/orbit',
    'etc/orbit.env',
    'etc/orbit',
    'etc/systemd/system/orbit.service',
    'var/lib/uptime-goblin.migrating',
  ])
    assert.equal(exists(host, file), false, `${file} is not made`);
  assert.deepEqual(Object.keys(accounts(host).users), ['uptime-goblin']);
  assert.deepEqual(accounts(host).users['uptime-goblin'].home, '/opt/uptime-goblin');
  assert.ok(fs.existsSync(host.path('etc/uptime-goblin/secret.key')));
  assert.ok(alive(host.state().pid));
  assert.equal(host.status().version, '1.5.0-test.1');
  // The shim passes the exit status on.
  const usage = await host.install(source, ['--nope'], {}, { script: 'deploy/install-lxc.sh' });
  assert.equal(usage.status, 2, ok(usage));
});
