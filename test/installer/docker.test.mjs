// The Docker image: it builds (the build itself fails when a manifest file is missing), neither
// its build context nor any image layer carries a file .dockerignore excludes, it starts,
// passes its HEALTHCHECK without signing in, runs supervised, refuses bad settings with exit 78
// and exits 0 when stopped. Building needs network access for npm ci, so this runs only when
// TEST_REQUIRE includes docker (the CI docker job).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { createFeatures } from '../../lib/features.mjs';
import { insecureHttpSessionsSetting } from '../../lib/environment.mjs';
import { readManifest } from '../../scripts/check.mjs';
import { layerContains } from './image-layers.mjs';
import { repository, required, freePort, temporary } from './helpers.mjs';
import { installTag, tagUnavailable } from '../upgrade/fixtures.mjs';

// The default compose.yaml gives a variable (`NAME: ${NAME-${OLD-default}}`, OLD its ORBIT_ name
// from before the rename, or `${NAME:-${OLD:-default}}` where an empty value counts as unset),
// so the test runs the image exactly as a default Compose install does.
function composeDefault(name) {
  const text = fs.readFileSync(path.join(repository, 'compose.yaml'), 'utf8');
  const old = name.replace(/^GOBLIN_/, 'ORBIT_');
  const match = new RegExp(
    `^\\s+${name}: \\$\\{${name}:?-\\$\\{${old}:?-([^}]*)\\}\\}\\s*$`,
    'm'
  ).exec(text);
  assert.ok(match, `compose.yaml sets ${name} with a default`);
  return match[1];
}

// A setting as .env.example names it, as a pattern: its GOBLIN_ name, or its ORBIT_ one from
// before the rename (.env.example still has those; compose.yaml reads both), for a test that
// reads .env.example.
const exampleName = name => `(?:${name}|${name.replace(/^GOBLIN_/, 'ORBIT_')})`;

// One request to 127.0.0.1:<port> with an explicit Host header, as a browser on the Docker host
// sends it to the published port (fetch cannot set Host).
function request(port, { method = 'GET', path: target, headers = {}, body }) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path: target, headers }, res => {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', chunk => (text += chunk));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

const docker = (...args) => spawnSync('docker', args, { encoding: 'utf8', timeout: 900000 });

// Every container these tests run has finite memory, CPU and process limits, the ones the
// maintenance compose.yaml sets; serviceLimits are the same for a Compose service (the
// projects' test.yaml and the services the tests add).
const limits = ['--memory=1g', '--cpus=2', '--pids-limit=256'];
// The Node image the Dockerfile pins, by digest: the tag alone can name another platform's image
// on the host (an amd64 copy on an arm64 Mac), whose platform warning then lands in stderr.
const pinnedNode = /^FROM (node:24-bookworm-slim@sha256:[0-9a-f]{64})$/m.exec(
  fs.readFileSync(path.join(repository, 'Dockerfile'), 'utf8')
)[1];
const serviceLimits = '    mem_limit: 1g\n    cpus: 2\n    pids_limit: 256\n';

// Whether Docker has no `kind` (container, volume or image) by this id or name: inspect says
// "No such …". Any other failure (the daemon unreachable) proves nothing, so it is not absent.
function absent(kind, name) {
  const inspected = docker(kind, 'inspect', name);
  return inspected.status !== 0 && /no such/i.test(inspected.stderr);
}

// What one Compose project holds, found by its project label: the containers (one-off `run`
// ones too), volumes and networks, or a line saying why they could not be listed.
function projectObjects(name) {
  return [
    ['ps', '--all', '--quiet'],
    ['volume', 'ls', '--quiet'],
    ['network', 'ls', '--quiet'],
  ].flatMap(command => {
    const listed = docker(...command, '--filter', `label=com.docker.compose.project=${name}`);
    return listed.status === 0
      ? listed.stdout.split('\n').filter(Boolean)
      : [`docker ${command.join(' ')}: ${listed.stderr.trim() || listed.status}`];
  });
}

// What one test makes in Docker, and its single clean-up, which is checked. Make it before
// anything that clean-up needs (node:test runs a test's after hooks in the order they were
// registered, so a Compose project's directory, made later, is still there). It removes the
// containers by the exact ids their `docker create` returned, each recorded before it starts,
// so one whose start fails goes too; then each Compose project by its own unique name and
// files; then the volumes, then the image tags. Containers go first: removing an image that a
// container still uses only untags it, and the image stays behind once the container goes;
// a volume in use cannot be removed. Nothing is chosen by image (`--filter ancestor=<tag>` also
// finds another test's container whose tag names the same cached image) or from a listing of
// everything the daemon has. Each removal is confirmed, since `docker rm --force` and `docker
// image rm --force` exit 0 for what is not there, and every failure is reported once all of
// them have been tried.
function dockerOwner(t) {
  const containers = [],
    projects = [],
    volumes = [],
    images = [];
  t.after(async () => {
    const failures = [];
    // A container whose --rm removal is under way can take a moment to go.
    const gone = async (kind, name, removal) => {
      for (let i = 0; i < 40; i++) {
        if (absent(kind, name)) return;
        await delay(250);
      }
      failures.push(
        `${kind} ${name} is still there, or Docker cannot tell: ${removal.stderr.trim() || removal.status}`
      );
    };
    for (const id of containers.toReversed())
      await gone('container', id, docker('rm', '--force', '--volumes', id));
    for (const { name, directory } of projects) {
      const down = spawnSync(
        'docker',
        [
          ...['compose', '--project-name', name, '-f', 'compose.yaml', '-f', 'test.yaml'],
          ...['down', '--volumes', '--remove-orphans', '--timeout', '1'],
        ],
        { cwd: directory, encoding: 'utf8', timeout: 300000 }
      );
      const left = projectObjects(name);
      if (down.status !== 0 || left.length)
        failures.push(
          `Compose project ${name}: down exited ${down.status} (${down.stderr.trim()}); left: ${left.join(' ') || 'nothing'}`
        );
    }
    for (const name of volumes) await gone('volume', name, docker('volume', 'rm', '--force', name));
    for (const tag of images) await gone('image', tag, docker('image', 'rm', '--force', tag));
    if (failures.length) assert.fail(`Docker clean-up failed:\n${failures.join('\n')}`);
  });
  return {
    // Builds `tag`, a tag no image has yet, so that removing it takes nothing of anyone else's.
    build(tag, context = repository) {
      assert.ok(absent('image', tag), `the image ${tag} exists already, or Docker cannot tell`);
      images.push(tag);
      const built = docker('build', '--tag', tag, context);
      assert.equal(built.status, 0, built.stdout + built.stderr);
    },
    // A volume no volume has the name of yet (`docker volume create` would take that one).
    volume(name) {
      assert.ok(absent('volume', name), `the volume ${name} exists already, or Docker cannot tell`);
      volumes.push(name);
      const created = docker('volume', 'create', name);
      assert.equal(created.status, 0, created.stderr);
    },
    // As `docker run --detach` with the limits, in two steps: the id `docker create` returns
    // is checked and recorded before the container starts. Returns that id.
    run(...args) {
      const created = docker('create', ...limits, ...args);
      assert.equal(created.status, 0, created.stderr);
      const id = created.stdout.trim();
      assert.match(id, /^[a-f0-9]{64}$/, created.stderr);
      containers.push(id);
      const started = docker('start', id);
      assert.equal(started.status, 0, started.stderr);
      return id;
    },
    // A Compose project in `directory` (with its compose.yaml and test.yaml), by a name no
    // project has yet: Compose labels what it makes with it, and down removes only that.
    project(name, directory) {
      assert.deepEqual(projectObjects(name), [], `the Compose project ${name} exists already`);
      projects.push({ name, directory });
    },
  };
}

// Builds `image` for a test; returns the test's dockerOwner, which removes the image last.
function buildImage(t, image, context = repository) {
  const own = dockerOwner(t);
  own.build(image, context);
  return own;
}

// Every file below `directory`, as sorted paths relative to it with / separators.
function filesIn(directory) {
  return fs
    .readdirSync(directory, { recursive: true, withFileTypes: true })
    .filter(entry => !entry.isDirectory())
    .map(entry => path.relative(directory, path.join(entry.parentPath, entry.name)))
    .map(file => file.split(path.sep).join('/'))
    .sort();
}

// Run inside a running container of the image (node --input-type=module -e): who owns what. The
// code is root's and no group or other user can change it, whatever the container's own
// filesystem allows (read_only in compose.yaml hides that: touch /app/x fails there whoever owns
// /app, but a plain docker run would let the node account rewrite a node-owned file), and a
// write to it is refused; /var/lib/uptime-goblin and run/ are the runtime user's and private, its files 0600,
// and a new file there is the runtime user's and private; no package manager is left in the
// image, and the runtime dependency still loads. As the maintenance image test checks them:
// ownership through a link is that of what it names (stat), and only real directories are
// walked (lstat), so a link under /app is judged by its target, not refused for being one.
const imageOwnershipCheck = `import fs from 'node:fs';
import assert from 'node:assert/strict';
import path from 'node:path';
import nodemailer from 'nodemailer';
assert.equal(typeof nodemailer.createTransport, 'function', 'the runtime dependency must remain usable');
for (const name of ['npm', 'npx', 'corepack', 'yarn', 'yarnpkg', 'pnpm', 'pnpx'])
  assert.equal(fs.lstatSync('/usr/local/bin/' + name, { throwIfNoEntry: false }), undefined, name + ' must not remain as an executable or dangling shim');
for (const name of ['npm', 'corepack'])
  assert.equal(fs.lstatSync('/usr/local/lib/node_modules/' + name, { throwIfNoEntry: false }), undefined, name + ' must not remain in the runtime global modules');
assert.deepEqual(fs.readdirSync('/opt').filter(name => name.startsWith('yarn-')), [], 'the bundled Yarn tree must not remain');
const uid = process.getuid();
assert.notEqual(uid, 0, 'Uptime Goblin must run as a non-root user');
const verifyCode = file => {
  const stat = fs.statSync(file);
  assert.equal(stat.uid, 0, file + ' must remain root-owned');
  assert.equal(stat.mode & 0o022, 0, file + ' must not be group/other writable');
  if (fs.lstatSync(file).isDirectory())
    for (const name of fs.readdirSync(file)) verifyCode(path.join(file, name));
};
const app = fs.statSync('/app');
assert.equal(app.uid, 0, '/app must remain root-owned');
assert.equal(app.mode & 0o022, 0, '/app must not be group/other writable');
for (const name of fs.readdirSync('/app')) if (name !== 'data') verifyCode(path.join('/app', name));
for (const file of ['/app/server.mjs', '/app/node_modules/nodemailer/package.json'])
  assert.throws(() => {
    const fd = fs.openSync(file, 'a');
    fs.closeSync(fd);
  }, error => ['EACCES', 'EROFS'].includes(error.code), file + ' must reject writes');
for (const file of ['/var/lib/uptime-goblin', '/var/lib/uptime-goblin/run']) {
  const stat = fs.statSync(file);
  assert.equal(stat.uid, uid, file + ' must belong to the runtime user');
  assert.equal(stat.mode & 0o777, 0o700, file + ' must be private');
}
for (const file of ['/var/lib/uptime-goblin/config.json', '/var/lib/uptime-goblin/control.sqlite', '/var/lib/uptime-goblin/history.sqlite', '/var/lib/uptime-goblin/run/status.json',
                    ...(fs.existsSync('/var/lib/uptime-goblin/auth.json') ? ['/var/lib/uptime-goblin/auth.json'] : [])]) {
  const stat = fs.statSync(file);
  assert.equal(stat.uid, uid, file + ' must belong to the runtime user');
  assert.equal(stat.mode & 0o777, 0o600, file + ' must be private');
}
const probe = '/var/lib/uptime-goblin/runtime-permission-probe';
try {
  fs.writeFileSync(probe, 'synthetic writable data', { flag: 'wx', mode: 0o600 });
  assert.equal(fs.readFileSync(probe, 'utf8'), 'synthetic writable data');
  assert.equal(fs.statSync(probe).uid, uid);
  assert.equal(fs.statSync(probe).mode & 0o777, 0o600);
} finally {
  fs.rmSync(probe, { force: true });
}`;

// Run by sh inside a container of the image: the pinned base image predates Debian's
// libpcre2-8-0 security update, which the Dockerfile installs on top (test/packaging.test.mjs
// checks the step). It prints the installed version and exits 0 only when that is
// 10.42-1+deb12u2 or later. dpkg-query's format is in single quotes: in double quotes sh expands
// ${Version}, an unset variable, to nothing, and dpkg-query refuses the empty format (exit 1) on
// every image, the updated one included.
const libpcreCheck =
  'v=$(dpkg-query -W -f=\'${Version}\' libpcre2-8-0) && echo "$v" && dpkg --compare-versions "$v" ge 10.42-1+deb12u2';

test('the libpcre2-8-0 check gives dpkg-query its format as written and dpkg the version it printed', t => {
  // Stand-ins that record their arguments: dpkg-query refuses an empty format as Debian's does,
  // and dpkg's comparison answers COMPARE (0: that version or later).
  const bin = temporary(t, 'orbit-dpkg-');
  const calls = path.join(bin, 'calls');
  const record = `printf '%s\\n' "$0 $*" >> '${calls}'\n`;
  fs.writeFileSync(
    path.join(bin, 'dpkg-query'),
    `#!/bin/sh\n${record}[ "$2" = '-f=\${Version}' ] || { echo 'dpkg-query: error in show format: may not be empty string' >&2; exit 1; }\n[ -n "$VERSION" ] || exit 1\nprintf '%s' "$VERSION"\n`,
    { mode: 0o755 }
  );
  fs.writeFileSync(path.join(bin, 'dpkg'), `#!/bin/sh\n${record}exit "$COMPARE"\n`, {
    mode: 0o755,
  });
  const run = env => {
    fs.rmSync(calls, { force: true });
    const result = spawnSync('sh', ['-c', libpcreCheck], {
      encoding: 'utf8',
      env: { PATH: `${bin}:/usr/bin:/bin`, ...env },
    });
    const said = fs.existsSync(calls) ? fs.readFileSync(calls, 'utf8') : '';
    return { status: result.status, stdout: result.stdout, calls: said.replaceAll(`${bin}/`, '') };
  };
  assert.deepEqual(run({ VERSION: '10.42-1+deb12u2', COMPARE: '0' }), {
    status: 0,
    stdout: '10.42-1+deb12u2\n',
    calls:
      'dpkg-query -W -f=${Version} libpcre2-8-0\ndpkg --compare-versions 10.42-1+deb12u2 ge 10.42-1+deb12u2\n',
  });
  // An older version (the pinned base's own): dpkg says so, and the check fails.
  const older = run({ VERSION: '10.42-1+deb12u1', COMPARE: '1' });
  assert.equal(older.status, 1);
  assert.match(older.calls, /^dpkg --compare-versions 10\.42-1\+deb12u1 ge 10\.42-1\+deb12u2$/m);
  // The package missing: dpkg-query fails, and nothing is compared.
  const missing = run({ VERSION: '', COMPARE: '0' });
  assert.notEqual(missing.status, 0);
  assert.doesNotMatch(missing.calls, /^dpkg /m);
});

let skip = required('docker')
  ? false
  : 'set TEST_REQUIRE=docker to build and run the image (needs Docker and network access)';
if (!skip && docker('version', '--format', '{{.Server.Version}}').status !== 0) {
  test('Docker is available (TEST_REQUIRE=docker)', () => assert.fail('Docker is not available'));
  skip = 'reported as a failure above';
}

test(
  'the Docker image builds, becomes healthy, and stops or refuses cleanly',
  { skip, timeout: 900000 },
  async t => {
    const id = randomBytes(4).toString('hex');
    const image = `uptime-goblin:test-${id}`,
      name = `orbit-docker-${id}`;
    // Built from a copy of the shipped files plus synthetic secrets where a local backup or
    // credential file could sit, nested ones in 1.5's module directories included.
    const scratch = temporary(t, 'orbit-docker-'),
      context = path.join(scratch, 'context');
    const files = [...readManifest(repository), 'Dockerfile', '.dockerignore'];
    for (const file of files) {
      const target = path.join(context, file);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.copyFileSync(path.join(repository, file), target);
    }
    const excluded = new Map();
    for (const file of [
      '.env',
      'orbit_secret_key',
      'data/config.json',
      'lib/private.env',
      'lib/audit/private-backup.json',
      'docs/private-backup.json',
      'public/data/auth.json',
      'public/shared/private.env',
      'public/modules/private.env',
      'public/modules/configure/private-backup.json',
      'deploy/orbit.env',
    ]) {
      const target = path.join(context, file);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      const marker = `orbit-excluded-secret-${randomBytes(24).toString('hex')}`;
      excluded.set(file, Buffer.from(marker));
      fs.writeFileSync(target, marker, { mode: 0o600 });
    }
    // A shipped, harmless marker is the positive control for the layer scanner.
    const shippedMarker = `orbit-shipped-control-${randomBytes(24).toString('hex')}`;
    fs.appendFileSync(path.join(context, 'docs/security.md'), `\n<!-- ${shippedMarker} -->\n`);

    // The context as BuildKit sends it, exported by a scratch build (no image, no network):
    // exactly the manifest files and the Dockerfile. This also covers deploy/ and the top
    // level, which the Dockerfile copies only by name.
    const probe = path.join(scratch, 'context.Dockerfile'),
      sent = path.join(scratch, 'sent');
    fs.writeFileSync(probe, 'FROM scratch\nCOPY . /\n');
    const exported = docker(
      'build',
      '--file',
      probe,
      '--output',
      `type=local,dest=${sent}`,
      context
    );
    assert.equal(exported.status, 0, exported.stdout + exported.stderr);
    assert.deepEqual(
      [...excluded.keys()].filter(file => fs.existsSync(path.join(sent, file))),
      [],
      'Excluded files reached the build context'
    );
    assert.deepEqual(filesIn(sent), [...readManifest(repository), 'Dockerfile'].sort());

    const own = buildImage(t, image, context);

    const archive = path.join(scratch, 'image.tar');
    const saved = docker('image', 'save', '--output', archive, image);
    assert.equal(saved.status, 0, saved.stderr);
    const manifest = spawnSync('tar', ['-xOf', archive, 'manifest.json'], {
      encoding: 'utf8',
      timeout: 30000,
      maxBuffer: 1024 * 1024,
    });
    assert.equal(manifest.status, 0, manifest.stderr);
    const images = JSON.parse(manifest.stdout);
    assert.equal(images.length, 1);
    assert.ok(Array.isArray(images[0].Layers) && images[0].Layers.length > 0);
    let shippedFound = false;
    const leaked = new Set();
    for (const layer of images[0].Layers) {
      assert.equal(typeof layer, 'string');
      const found = await layerContains(archive, layer, [
        ...excluded.values(),
        Buffer.from(shippedMarker),
      ]);
      [...excluded.keys()].forEach((file, i) => {
        if (found[i]) leaked.add(file);
      });
      shippedFound ||= found.at(-1);
    }
    assert.deepEqual([...leaked].sort(), [], 'Excluded context files reached image layers');
    assert.ok(shippedFound, 'The image-layer scan must find its shipped positive control');
    fs.rmSync(archive);

    // Without a password Uptime Goblin may not listen on 0.0.0.0: a refusal, reported as exit 78.
    const refused = docker('run', ...limits, '--rm', image);
    assert.equal(refused.status, 78, refused.stdout + refused.stderr);
    assert.match(refused.stderr, /GOBLIN_PASSWORD/);
    // compose.yaml's GOBLIN_INSECURE_HTTP_SESSIONS default on a port published beyond loopback,
    // with no trusted proxy: a refusal too, never plain-HTTP sign-in turned on silently.
    const lan = docker(
      'run',
      ...limits,
      '--rm',
      '--env',
      `GOBLIN_PASSWORD=${randomBytes(18).toString('base64url')}`,
      '--env',
      `GOBLIN_INSECURE_HTTP_SESSIONS=${composeDefault('GOBLIN_INSECURE_HTTP_SESSIONS')}`,
      '--env',
      'GOBLIN_PUBLISHED_ADDRESS=192.0.2.5',
      image
    );
    assert.equal(lan.status, 78, lan.stdout + lan.stderr);
    assert.match(
      lan.stderr,
      /^Docker Compose publishes Uptime Goblin on "192\.0\.2\.5" \(GOBLIN_BIND_ADDRESS\), which is not a loopback address, with no reverse proxy Uptime Goblin trusts \(GOBLIN_TRUST_PROXY\)/m
    );

    own.run(
      '--name',
      name,
      '--env',
      `GOBLIN_PASSWORD=${randomBytes(18).toString('base64url')}`,
      '--read-only',
      '--tmpfs',
      '/tmp:size=16m,mode=1777',
      '--cap-drop',
      'ALL',
      '--security-opt',
      'no-new-privileges:true',
      image
    );
    const exec = (...args) => docker('exec', name, ...args);
    let ready = false;
    for (let i = 0; i < 60 && !ready; i++) {
      ready = exec('node', 'lib/healthcheck.mjs').status === 0;
      if (!ready) await delay(1000);
    }
    assert.ok(ready, docker('logs', name).stdout + docker('logs', name).stderr);
    assert.equal(exec('printenv', 'GOBLIN_SUPERVISED').stdout.trim(), '1');
    // The image has Debian's libpcre2-8-0 security update, or later (libpcreCheck).
    const pcre = exec('sh', '-c', libpcreCheck);
    assert.equal(pcre.status, 0, `libpcre2-8-0 ${pcre.stdout}${pcre.stderr}`);
    assert.match(pcre.stdout, /^\S+\n$/, 'the installed version, printed');
    const status = JSON.parse(exec('cat', '/var/lib/uptime-goblin/run/status.json').stdout);
    const version = JSON.parse(
      fs.readFileSync(path.join(repository, 'package.json'), 'utf8')
    ).version;
    assert.equal(status.version, version);
    assert.match(status.build, /^[0-9a-f]{12}$/);
    const instance = exec('node', 'lib/healthcheck.mjs', '--instance', status.nonce);
    assert.equal(instance.status, 0, instance.stderr);
    // Every manifest file is in the image, at its manifest path.
    const missing = readManifest(repository).filter(
      file => exec('test', '-f', `/app/${file}`).status !== 0
    );
    assert.deepEqual(missing, []);
    // Docker's own HEALTHCHECK agrees.
    let health = '';
    for (let i = 0; i < 90 && health !== 'healthy'; i++) {
      health = docker('inspect', '--format', '{{.State.Health.Status}}', name).stdout.trim();
      if (health !== 'healthy') await delay(1000);
    }
    assert.equal(health, 'healthy');

    const stopped = docker('stop', name);
    assert.equal(stopped.status, 0, stopped.stderr);
    assert.equal(docker('inspect', '--format', '{{.State.ExitCode}}', name).stdout.trim(), '0');

    // As compose.yaml runs it: published on the Docker host's loopback, HOST=0.0.0.0 inside,
    // and plain-HTTP sessions on by default there (D21, OD1: compose-default with a loopback
    // GOBLIN_PUBLISHED_ADDRESS). A browser on the Docker host signs in through the published
    // port; inside the container its peer is the Docker gateway, so the transport is http.
    const port = await freePort(),
      password = randomBytes(18).toString('base64url'),
      composed = `${name}-compose`;
    const insecure = composeDefault('GOBLIN_INSECURE_HTTP_SESSIONS');
    assert.equal(insecure, 'compose-default');
    own.run(
      '--name',
      composed,
      '--publish',
      `127.0.0.1:${port}:4317`,
      '--env',
      'HOST=0.0.0.0',
      '--env',
      `GOBLIN_PASSWORD=${password}`,
      '--env',
      `GOBLIN_ALLOWED_HOSTS=localhost:${port}`,
      '--env',
      `GOBLIN_INSECURE_HTTP_SESSIONS=${insecure}`,
      '--env',
      'GOBLIN_PUBLISHED_ADDRESS=127.0.0.1',
      '--env',
      `GOBLIN_LEGACY_BASIC=${composeDefault('GOBLIN_LEGACY_BASIC')}`,
      '--env',
      `GOBLIN_AUDIT_LOG=${composeDefault('GOBLIN_AUDIT_LOG')}`,
      '--env',
      `GOBLIN_AUDIT_RETENTION_DAYS=${composeDefault('GOBLIN_AUDIT_RETENTION_DAYS')}`,
      '--read-only',
      '--tmpfs',
      '/tmp:size=16m,mode=1777',
      '--cap-drop',
      'ALL',
      '--security-opt',
      'no-new-privileges:true',
      image
    );
    let up = false;
    for (let i = 0; i < 60 && !up; i++) {
      up = docker('exec', composed, 'node', 'lib/healthcheck.mjs').status === 0;
      if (!up) await delay(1000);
    }
    assert.ok(up, docker('logs', composed).stdout + docker('logs', composed).stderr);
    const logs = docker('logs', composed);
    assert.match(logs.stdout, /plain-HTTP sessions: allowed/);
    const browser = {
      Host: `localhost:${port}`,
      Origin: `http://localhost:${port}`,
      'Sec-Fetch-Site': 'same-origin',
      'X-Goblin-Request': '1',
      'X-Goblin-Client': 'web/test',
    };
    const login = await request(port, {
      method: 'POST',
      path: '/api/auth/login',
      headers: { ...browser, 'Content-Type': 'application/json' },
      body: JSON.stringify({ login: 'admin', password }),
    });
    assert.equal(login.status, 200, login.text);
    const [cookie] = login.headers['set-cookie'] ?? [];
    assert.match(
      cookie,
      /^goblin_session=v1\.[A-Za-z0-9_-]{43}; Path=\/; HttpOnly; SameSite=Strict$/
    );
    const session = await request(port, {
      path: '/api/session',
      headers: { ...browser, Cookie: cookie.split(';')[0] },
    });
    assert.equal(session.status, 200, session.text);
    const body = JSON.parse(session.text);
    assert.equal(body.via, 'session');
    assert.equal(body.transport.kind, 'http');
    assert.equal(body.transport.insecure, true);
    // The audit's checkpoints reach the container's log by default (audit spec D12, OD5): the
    // start and the sign-in each printed one; the entries themselves are not copied (off).
    const audited = docker('logs', composed).stdout;
    assert.ok(
      audited.split('\n').filter(line => line.startsWith('{"orbit":"audit.checkpoint"')).length >=
        2,
      audited
    );
    assert.doesNotMatch(audited, /^\{"orbit":"audit",/m);
    const composedStop = docker('stop', composed);
    assert.equal(composedStop.status, 0, composedStop.stderr);
  }
);

// Under Docker Compose, goblin-admin runs in a container of its own (`docker compose run --rm
// --no-deps uptime-goblin …`), beside an Uptime Goblin container on the same data volume. 1.4.x takes no
// orbit.lock and its run/status.json names a process id of its own container, which goblin-admin
// cannot see: after a code rollback to 1.4.3, an offline command must still refuse while 1.4.3
// runs, and run once it is stopped (§16 C4).
test(
  'goblin-admin in its own container refuses while 1.4.3 runs in another on the same volume',
  { skip, timeout: 300000 },
  async t => {
    const unavailable = tagUnavailable('v1.4.3');
    if (unavailable) {
      if (required('history')) assert.fail(`${unavailable} (TEST_REQUIRE=history)`);
      t.skip(unavailable);
      return;
    }
    const id = randomBytes(4).toString('hex'),
      volume = `goblin-admin-${id}`,
      name = `orbit-143-${id}`;
    const v143 = installTag('v1.4.3', path.join(temporary(t, 'orbit-docker-143-'), 'app'));
    // The mount point of the data volume inside the read-only tree.
    fs.mkdirSync(path.join(v143, 'data'));
    const node = pinnedNode;
    const own = dockerOwner(t);
    own.volume(volume);
    const owned = docker(
      'run',
      ...limits,
      '--rm',
      '--network',
      'none',
      '--volume',
      `${volume}:/data`,
      node,
      'sh',
      '-c',
      'chown 1000:1000 /data && chmod 700 /data'
    );
    assert.equal(owned.status, 0, owned.stderr);
    own.run(
      '--name',
      name,
      '--init',
      '--user',
      'node',
      '--network',
      'none',
      '--read-only',
      '--tmpfs',
      '/tmp:size=16m,mode=1777',
      '--volume',
      `${v143}:/app:ro`,
      '--volume',
      `${volume}:/app/data`,
      '--workdir',
      '/app',
      '--env',
      'HOST=127.0.0.1',
      '--env',
      'PORT=4317',
      '--env',
      'ORBIT_DATA_DIR=/app/data',
      '--env',
      `ORBIT_PASSWORD=${randomBytes(18).toString('base64url')}`,
      node,
      'node',
      'server.mjs'
    );
    let serving = false;
    for (let i = 0; i < 60 && !serving; i++) {
      serving =
        docker('exec', name, 'test', '-f', '/app/data/run/status.json').status === 0 &&
        docker(
          'exec',
          name,
          'node',
          '-e',
          'fetch("http://127.0.0.1:4317/health").then(r => process.exit(r.status === 200 ? 0 : 1), () => process.exit(1))'
        ).status === 0;
      if (!serving) await delay(500);
    }
    assert.ok(serving, docker('logs', name).stdout + docker('logs', name).stderr);
    assert.equal(
      JSON.parse(docker('exec', name, 'cat', '/app/data/run/status.json').stdout).version,
      '1.4.3'
    );
    // As `docker compose run --rm --no-deps uptime-goblin node lib/cli/goblin-admin.mjs snapshot` runs it.
    const admin = (command = 'snapshot') =>
      docker(
        'run',
        ...limits,
        '--rm',
        '--init',
        '--user',
        'node',
        '--network',
        'none',
        '--read-only',
        '--volume',
        `${repository}:/app:ro`,
        // Beside the working tree, not in it (the tree has no data directory to mount on).
        '--volume',
        `${volume}:/data`,
        '--workdir',
        '/app',
        '--env',
        'GOBLIN_DATA_DIR=/data',
        node,
        'node',
        'lib/cli/goblin-admin.mjs',
        command
      );
    const refused = admin();
    assert.equal(refused.status, 75, refused.stdout + refused.stderr);
    assert.match(
      refused.stderr,
      /Orbit 1\.4\.3 may be running on \/data: run\/status\.json names it, and from inside a container goblin-admin cannot see another container's processes\. Stop it first \(docker compose stop uptime-goblin\)\./
    );
    assert.notEqual(
      docker('exec', name, 'test', '-e', '/app/data/snapshots').status,
      0,
      'nothing written beside the running 1.4.3'
    );
    // status cannot see 1.4.3's process either (its process id is one of the other container's,
    // missing here or any process of this one): it says so, rather than "not running".
    const watching = admin('status');
    assert.equal(watching.status, 0, watching.stdout + watching.stderr);
    assert.match(
      watching.stdout,
      /^Orbit: may be running \(another container's processes cannot be seen from here\), version 1\.4\.3 build [0-9a-f]+, pid \d+, phase unknown, /m
    );
    // Stopped, 1.4.3 removes its record, and the command runs. status does not say "not
    // running" all the same: with no record and the lock free, a 1.4.2 container (which records
    // nothing; the kept 1.5 image after a rollback to it) may serve the volume unseen.
    assert.equal(docker('stop', name).status, 0);
    assert.match(
      admin('status').stdout,
      /^Uptime Goblin: may be running \(Orbit 1\.4\.2 and earlier keep no run\/status\.json and take no orbit\.lock, and another container's processes cannot be seen from here\)$/m
    );
    const ran = admin();
    assert.equal(ran.status, 0, ran.stdout + ran.stderr);
    assert.match(ran.stdout, /^Snapshot manual-/);
  }
);

// The same with 1.5 in the Uptime Goblin container: orbit.lock, which every 1.5 holds while it runs, is
// seen from the goblin-admin container, while run/status.json names a process of the other one
// (missing here without --init, and often goblin-admin itself under --init, as Compose runs it).
// status answers from the lock, and an offline command's refusal names Compose's stop.
test(
  'goblin-admin in its own container sees a 1.5 Uptime Goblin in another through orbit.lock',
  { skip, timeout: 300000 },
  async t => {
    const id = randomBytes(4).toString('hex'),
      volume = `goblin-admin15-${id}`,
      name = `orbit-15-${id}`;
    const release = JSON.parse(
      fs.readFileSync(path.join(repository, 'package.json'), 'utf8')
    ).version;
    // The manifest files and the dependencies (node_modules may be a link out of the tree).
    const tree = path.join(temporary(t, 'orbit-docker-15-'), 'app');
    for (const file of readManifest(repository)) {
      fs.mkdirSync(path.dirname(path.join(tree, file)), { recursive: true });
      fs.copyFileSync(path.join(repository, file), path.join(tree, file));
    }
    fs.cpSync(path.join(repository, 'node_modules'), path.join(tree, 'node_modules'), {
      recursive: true,
      dereference: true,
    });
    fs.mkdirSync(path.join(tree, 'data'));
    const node = pinnedNode;
    const own = dockerOwner(t);
    own.volume(volume);
    const owned = docker(
      'run',
      ...limits,
      '--rm',
      '--network',
      'none',
      '--volume',
      `${volume}:/data`,
      node,
      'sh',
      '-c',
      'chown 1000:1000 /data && chmod 700 /data'
    );
    assert.equal(owned.status, 0, owned.stderr);
    own.run(
      '--rm',
      '--name',
      name,
      '--init',
      '--user',
      'node',
      '--network',
      'none',
      '--read-only',
      '--tmpfs',
      '/tmp:size=16m,mode=1777',
      '--volume',
      `${tree}:/app:ro`,
      '--volume',
      `${volume}:/var/lib/uptime-goblin`,
      '--workdir',
      '/app',
      '--env',
      'HOST=127.0.0.1',
      '--env',
      'PORT=4317',
      '--env',
      'GOBLIN_DATA_DIR=/var/lib/uptime-goblin',
      '--env',
      `GOBLIN_PASSWORD=${randomBytes(18).toString('base64url')}`,
      node,
      'node',
      'server.mjs'
    );
    let serving = false;
    for (let i = 0; i < 60 && !serving; i++) {
      serving =
        docker('exec', name, 'test', '-f', '/var/lib/uptime-goblin/run/status.json').status === 0 &&
        docker(
          'exec',
          name,
          'node',
          '-e',
          'fetch("http://127.0.0.1:4317/health").then(r => process.exit(r.status === 200 ? 0 : 1), () => process.exit(1))'
        ).status === 0;
      if (!serving) await delay(500);
    }
    assert.ok(serving, docker('logs', name).stdout + docker('logs', name).stderr);
    // As `docker compose run --rm --no-deps uptime-goblin node lib/cli/goblin-admin.mjs <command>` runs it
    // (init: true), and as `docker run` without --init runs the kept image after a rollback.
    const admin = (command, init = true) =>
      docker(
        'run',
        ...limits,
        '--rm',
        ...(init ? ['--init'] : []),
        '--user',
        'node',
        '--network',
        'none',
        '--read-only',
        '--volume',
        `${tree}:/app:ro`,
        '--volume',
        `${volume}:/data`,
        '--workdir',
        '/app',
        '--env',
        'GOBLIN_DATA_DIR=/data',
        node,
        'node',
        'lib/cli/goblin-admin.mjs',
        command
      );
    const escaped = release.replaceAll('.', '\\.');
    for (const init of [true, false]) {
      const running = admin('status', init);
      assert.equal(running.status, 0, running.stdout + running.stderr);
      assert.match(
        running.stdout,
        new RegExp(
          `^Uptime Goblin: running, version ${escaped} build [0-9a-f]+, pid \\d+, phase ready, `,
          'm'
        ),
        `init ${init}`
      );
    }
    const refused = admin('snapshot');
    assert.equal(refused.status, 75, refused.stdout + refused.stderr);
    // (Docker's own warning, on a host whose cached node image is for another platform, is not
    // goblin-admin's.)
    assert.equal(
      refused.stderr.replace(/^WARNING: The requested image's platform .*\n/m, ''),
      'goblin-admin snapshot: Uptime Goblin (or another goblin-admin command) is using /data. Stop it first (docker compose stop uptime-goblin)\n'
    );
    // Killed (a crash: the record stays, the lock goes with the process): the recorded Uptime Goblin is
    // not running, whatever process here has the id the record names, and the command runs. A
    // 1.4.2 container, which records nothing, cannot be ruled out from here (as when stopped).
    assert.equal(docker('kill', name).status, 0);
    for (let i = 0; i < 40 && docker('container', 'inspect', name).status === 0; i++)
      await delay(250);
    for (const init of [true, false])
      assert.match(
        admin('status', init).stdout,
        new RegExp(
          `^Uptime Goblin: may be running \\(Orbit 1\\.4\\.2 and earlier keep no run/status\\.json and take no orbit\\.lock, and another container's processes cannot be seen from here\\); run/status\\.json is left by Uptime Goblin ${escaped} build [0-9a-f]+, pid \\d+, started .+, which is not running$`,
          'm'
        ),
        `init ${init}`
      );
    const ran = admin('snapshot');
    assert.equal(ran.status, 0, ran.stdout + ran.stderr);
    assert.match(ran.stdout, /^Snapshot manual-/);
  }
);

// ---------------------------------------------------------------------------------------------
// Docker Compose and the encryption key (delivery spec §4.6): compose.secret.yaml's key, the
// generated /var/lib/uptime-goblin/secret.key without it, the documented switch from one to the other, and
// the 40 s stop grace period. Compose runs the image built here under a project of its own; the
// test's override only names that image, drops the published port and the restart policy (a
// refusal must stay visible) and sets the test containers' limits, so what runs is compose.yaml
// (and compose.secret.yaml) as shipped. With `shippedRestart` it keeps compose.yaml's
// `restart: unless-stopped`, so that a refusal repeats as it does for a user (A65: with restart
// 'no' the Docker MOVE test hid that the recipe's docker compose cp fails once the refused
// container's key file is set aside). With `shippedLimits` the override sets no limit, so the
// container runs with compose.yaml's own (1 GiB, 1 CPU, 256 processes), which are finite as every
// test container's must be (test/helpers/docker-guard.mjs refuses a project without them).

/**
 * A Compose project in a temporary directory with compose.yaml, compose.secret.yaml and `extra`,
 * under a project name of its own, which `own` (the test's dockerOwner) takes down at the end.
 */
function composeProject(
  t,
  own,
  image,
  extra = '',
  { shippedRestart = false, shippedLimits = false } = {}
) {
  const directory = temporary(t, 'orbit-compose-');
  for (const file of ['compose.yaml', 'compose.secret.yaml'])
    fs.copyFileSync(path.join(repository, file), path.join(directory, file));
  fs.writeFileSync(
    path.join(directory, 'test.yaml'),
    `services:\n  uptime-goblin:\n    image: ${image}\n    ports: !reset []\n${shippedLimits ? '' : serviceLimits}${shippedRestart ? '' : "    restart: 'no'\n"}${extra}`
  );
  fs.writeFileSync(
    path.join(directory, '.env'),
    `GOBLIN_PASSWORD=${randomBytes(18).toString('base64url')}\n`,
    { mode: 0o600 }
  );
  const name = `orbitkeys${randomBytes(4).toString('hex')}`;
  own.project(name, directory);
  // With no files, Compose takes them from COMPOSE_FILE in .env, as the docs set it up.
  const compose = (files, ...args) =>
    spawnSync(
      'docker',
      ['compose', '--project-name', name, ...files.flatMap(file => ['-f', file]), ...args],
      { cwd: directory, encoding: 'utf8', timeout: 300000 }
    );
  return { directory, name, compose };
}

// Orbit 1.4.3's own image, built from the release tag with that release's Dockerfile (the image
// a 1.4.3 install built as orbit-homelab:local), under a tag of this test's (`own` removes it).
function buildOrbit143(t, own) {
  const tree = installTag('v1.4.3', path.join(temporary(t, 'orbit-image-143-'), 'context'));
  const tag = `orbit-homelab:test-143-${randomBytes(4).toString('hex')}`;
  own.build(tag, tree);
  return tag;
}

// The compose.override.yaml that docs/installation.md gives for the rollback from 1.5 to 1.4.3
// under Docker Compose, as printed, with `image` (buildOrbit143) in place of the
// orbit-homelab:1.4.3 a user kept.
function rollbackOverride(image) {
  const installation = fs.readFileSync(path.join(repository, 'docs/installation.md'), 'utf8');
  const from = installation.indexOf('**Under Docker Compose**, the 1.4.3 image reads only');
  assert.ok(from > 0, 'docs/installation.md gives the Compose rollback to 1.4.3');
  const block = /```yaml\n([\s\S]*?)```/.exec(installation.slice(from))?.[1];
  assert.ok(block?.includes('    image: orbit-homelab:1.4.3\n'), block);
  return block.replace('    image: orbit-homelab:1.4.3\n', `    image: ${image}\n`);
}

// When the start of `service` that is running now began, as Docker records it (State.StartedAt),
// for `logs --since`: that start's output and none of an earlier one's. The daemon's clock, which
// also stamps the log lines, gives it, not the host's. `docker compose restart` keeps the
// container and the output of its earlier start, and a host time taken a second before the
// restart (`now()` in the tests) also took in that start's last lines whenever the restart came
// within that second of them (round 4 of checkpoint 2c: the key test read the earlier start's
// same-key warning as the new start's, 1 run in 10). `compose` and `files` as composeProject's.
function startedAt(compose, files, service = 'uptime-goblin') {
  const id = compose(files, 'ps', '--quiet', service).stdout.trim();
  assert.match(id, /^[a-f0-9]{64}$/, `one running ${service} container`);
  const inspected = docker('inspect', '--format', '{{.State.Running}} {{.State.StartedAt}}', id);
  assert.equal(inspected.status, 0, inspected.stderr);
  const [running, started] = inspected.stdout.trim().split(' ');
  assert.equal(running, 'true', inspected.stdout);
  assert.ok(Date.parse(started) > 0, inspected.stdout);
  return started;
}

// A key file's text, as the person who made it reads it back. The recipe gives the file to uid
// 1000 with mode 0400, so on a Linux host whose user is not uid 1000 (a GitHub runner is uid
// 1001) only root can read it: there it is read as root in a helper container, as `sudo cat`
// would. A Mac, or a Linux host whose user is uid 1000, reads it directly. Any other error, or a
// failed read, still fails the test.
function readKeyFile(file) {
  try {
    return fs.readFileSync(file, 'utf8');
  } catch (error) {
    if (error.code !== 'EACCES') throw error;
    const read = docker(
      'run',
      ...limits,
      '--rm',
      '--network',
      'none',
      '--volume',
      `${path.dirname(file)}:/d:ro`,
      'node:24-bookworm-slim',
      'cat',
      `/d/${path.basename(file)}`
    );
    assert.equal(read.status, 0, read.stderr);
    return read.stdout;
  }
}

// A key file as the recipe makes it (0400), owned by uid 1000 as the image's user needs on a
// Linux host (a root helper container chowns it; OrbStack lets the container's user read it as it
// is, measured; Docker Desktop was not tested).
function writeKeyFile(directory, hex) {
  const file = path.join(directory, 'orbit_secret_key');
  fs.rmSync(file, { force: true });
  fs.writeFileSync(file, `${hex}\n`, { mode: 0o400 });
  docker(
    'run',
    ...limits,
    '--rm',
    '--network',
    'none',
    '--volume',
    `${directory}:/d`,
    'node:24-bookworm-slim',
    'chown',
    '1000:1000',
    '/d/orbit_secret_key'
  );
  return file;
}

// The check of compose.secret.yaml (docs/installation.md gives the same), run on the test's
// project: its files in place of -f compose.yaml, whose image (`build: .`) the test does not
// build; the rest of the line runs as printed (it adds compose.secret.yaml when orbit_secret_key
// exists). `files` must name the 1.5 image, which the check runs in. Its first line, `verdict`,
// is NEW, KEEP, COPY, MOVE or RESTORE.
function volumeCheck({ directory, name }, files) {
  const override = fs.readFileSync(path.join(repository, 'compose.secret.yaml'), 'utf8');
  const checkLine = /^# {3}(docker compose -f compose\.yaml .*)$/m.exec(override)?.[1];
  assert.ok(checkLine, override);
  const result = spawnSync(
    'sh',
    [
      '-c',
      checkLine.replace(
        'docker compose -f compose.yaml',
        `docker compose --project-name ${name} ${files.map(file => `-f ${file}`).join(' ')}`
      ),
    ],
    { cwd: directory, encoding: 'utf8', timeout: 300000 }
  );
  return { ...result, verdict: result.stdout.split('\n')[0] };
}

// Once a refused start repeats under compose.yaml's restart policy (a project made with
// shippedRestart): the container's last exit status and restart count ("78 3"), once it has
// been started again at least twice, as a user finds it.
async function refusing(compose, files = []) {
  let state = '';
  for (let i = 0; i < 60; i++) {
    const id = compose(files, 'ps', '--all', '--quiet', 'uptime-goblin').stdout.trim();
    state = docker(
      'inspect',
      '--format',
      '{{.State.ExitCode}} {{.RestartCount}}',
      id
    ).stdout.trim();
    if (/^78 ([2-9]|[1-9]\d+)$/.test(state)) break;
    await delay(1000);
  }
  return state;
}

// The shell commands of a recipe block of docs/installation.md: a line that starts with a space
// or `}` continues the command above it (the commands that read the volume's key span lines).
function recipeCommands(block) {
  const commands = [];
  for (const line of block.split('\n').filter(Boolean))
    if (/^[\s}]/.test(line) && commands.length) commands[commands.length - 1] += `\n${line}`;
    else commands.push(line);
  return commands;
}

// The recipe blocks of docs/installation.md's Docker Compose key section: the check, then the
// new-key, copy and move recipes. A66: each recipe is three blocks (its first command, the chown
// a Linux host needs, its start), told apart by the paragraphs that open the copy and MOVE
// recipes; `fresh`, `copy` and `move` are each recipe's blocks joined, as a person pasting the
// whole recipe at once has them, and `recipes` keeps the blocks. A67: `older` is the block after
// the verdicts, for KEEP beside an older /var/lib/uptime-goblin/secret.key (the line that deletes it).
function keyRecipes(
  installation = fs.readFileSync(path.join(repository, 'docs/installation.md'), 'utf8')
) {
  const section = installation.slice(
    installation.indexOf('**Docker Compose.** Use the override'),
    installation.indexOf('**`npm start`.**')
  );
  const blocksIn = text => [...text.matchAll(/```sh\n([\s\S]*?)```/g)].map(match => match[1]);
  const blocks = blocksIn(section);
  const at = text => {
    const index = section.indexOf(text);
    assert.ok(index > 0, `docs/installation.md: ${text}`);
    return index;
  };
  const keepAt = at('With `KEEP`, a `/var/lib/uptime-goblin/secret.key` still in the volume'),
    freshAt = at('The first recipe is for a new install'),
    copyAt = at('Data that only 1.4.x has run on has no key'),
    moveAt = at('The third recipe is for `MOVE`.'),
    endAt = at('Instead of `COMPOSE_FILE`');
  const keepText = section.slice(keepAt, at('Each recipe is three blocks'));
  const [older] = blocksIn(keepText);
  const texts = {
    fresh: section.slice(freshAt, copyAt),
    copy: section.slice(copyAt, moveAt),
    move: section.slice(moveAt, endAt),
  };
  const [check] = blocks;
  const recipes = Object.fromEntries(
    Object.entries(texts).map(([name, text]) => [name, blocksIn(text)])
  );
  return {
    section,
    blocks,
    check,
    older,
    keepText,
    recipes,
    texts,
    fresh: recipes.fresh.join(''),
    copy: recipes.copy.join(''),
    move: recipes.move.join(''),
  };
}

// A key recipe of docs/installation.md, its commands run as printed in the project directory, so
// a step the recipe lacks is missing here too (review round 4: the test added the chown a Linux
// host needs itself, and the recipe as printed exited 78 EACCES there). Only what a test cannot
// run as printed is adapted: a `docker compose` command names the test's project, one with
// `-f compose.yaml` also the test's override (it names the image built here: compose.yaml's
// `build: .` has no Dockerfile in the project), `up -d` neither builds nor pulls, the
// COMPOSE_FILE line also names the test's override, and `sudo chown 1000 orbit_secret_key` runs
// as root in a helper container instead of through sudo. Returns each command's result.
function runRecipe(lines, { directory, name }) {
  return lines.map(line => {
    if (/^sudo chown 1000 orbit_secret_key(\s+#.*)?$/.test(line))
      return docker(
        'run',
        ...limits,
        '--rm',
        '--network',
        'none',
        '--volume',
        `${directory}:/d`,
        'node:24-bookworm-slim',
        'chown',
        '1000',
        '/d/orbit_secret_key'
      );
    return spawnSync('sh', ['-c', adaptCommand(line, name)], {
      cwd: directory,
      encoding: 'utf8',
      timeout: 300000,
    });
  });
}

// One command of a recipe as the test runs it (runRecipe): the test's project, its override,
// no build or pull, and the test's override in the COMPOSE_FILE line.
function adaptCommand(line, name) {
  const files = 'COMPOSE_FILE=compose.yaml:compose.secret.yaml';
  return line.includes(`echo '${files}' >> .env`)
    ? line.replace(files, `${files}:test.yaml`)
    : line
        .replaceAll(
          'docker compose -f compose.yaml ',
          `docker compose --project-name ${name} -f compose.yaml -f test.yaml `
        )
        .replace(/docker compose (?!--project-name)/g, `docker compose --project-name ${name} `)
        .replace(/ up -d( --force-recreate)?$/, ' up -d$1 --no-build --pull never');
}

// A whole recipe pasted at once (A66): its commands, adapted as runRecipe adapts them, in one
// shell, each running whatever the one before it did, as in a terminal. `sudo` is a stand-in
// that declines (a Mac skips the chown; no real sudo runs).
function pasteRecipe(t, text, { directory, name }) {
  const bin = temporary(t, 'orbit-paste-bin-');
  fs.writeFileSync(
    path.join(bin, 'sudo'),
    "#!/bin/sh\necho 'sudo (stand-in): declined' >&2\nexit 1\n",
    { mode: 0o755 }
  );
  const script = recipeCommands(text)
    .map(command => adaptCommand(command, name))
    .join('\n');
  return spawnSync('sh', ['-c', script], {
    cwd: directory,
    encoding: 'utf8',
    timeout: 600000,
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, PATH: `${bin}${path.delimiter}${process.env.PATH}` },
  });
}

test(
  'Compose: the key from compose.secret.yaml, a generated secret.key without it, and the documented switch',
  { skip, timeout: 900000 },
  async t => {
    const { keyFingerprint } = await import('../../lib/keyring.mjs');
    const image = `uptime-goblin:test-keys-${randomBytes(4).toString('hex')}`;
    const own = buildImage(t, image);
    // What the start that began at `since` logged once Uptime Goblin is healthy. Docker keeps stdout and
    // stderr apart, so the warnings (stderr) need not follow the start line (stdout) in order.
    const healthy = async (compose, files, since) => {
      for (let i = 0; i < 90; i++) {
        if (
          compose(files, 'exec', '-T', 'uptime-goblin', 'node', 'lib/healthcheck.mjs').status === 0
        )
          return compose(files, 'logs', '--no-log-prefix', '--since', since, 'uptime-goblin')
            .stdout;
        await delay(1000);
      }
      assert.fail(compose(files, 'logs', 'uptime-goblin').stdout);
    };
    const now = () => new Date(Date.now() - 1000).toISOString();
    const withSecret = ['compose.yaml', 'compose.secret.yaml', 'test.yaml'],
      plain = ['compose.yaml', 'test.yaml'];
    const up = (compose, files) => {
      const result = compose(files, 'up', '--detach', '--no-build', '--pull', 'never');
      assert.equal(result.status, 0, result.stdout + result.stderr);
    };

    // A new install with the Compose secret: the start names it, and no key enters the volume.
    {
      const { directory, name, compose } = composeProject(t, own, image);
      const key = randomBytes(32).toString('hex');
      writeKeyFile(directory, key);
      const since = now();
      up(compose, withSecret);
      const logs = await healthy(compose, withSecret, since);
      assert.match(
        logs,
        new RegExp(
          `^Encryption key: the Compose secret \\(/run/secrets/orbit_secret_key\\) · fingerprint ${keyFingerprint(Buffer.from(key, 'hex'))}$`,
          'm'
        )
      );
      assert.doesNotMatch(logs, /inside the data directory/);
      assert.notEqual(
        compose(
          withSecret,
          'exec',
          '-T',
          'uptime-goblin',
          'test',
          '-e',
          '/var/lib/uptime-goblin/secret.key'
        ).status,
        0,
        'no secret.key in the volume'
      );
      // The key is not in the container's environment either.
      const environment = compose(withSecret, 'exec', '-T', 'uptime-goblin', 'env').stdout;
      assert.ok(!environment.includes(key));
      // The documented check on this volume says KEEP: sealed with the orbit_secret_key in use
      // (review round 4: it said NEW, and the new-key line then replaced that key as root, so
      // every start exited 78 key_mismatch with the sealing key gone). The new-key line of the
      // recipe leaves an existing file alone.
      const check = volumeCheck({ directory, name }, plain);
      assert.equal(check.verdict, 'KEEP', check.stdout + check.stderr);
      const installation = fs.readFileSync(path.join(repository, 'docs/installation.md'), 'utf8');
      const newKey = /^test -e orbit_secret_key && .*openssl rand.*$/m.exec(installation)?.[0];
      assert.ok(newKey, 'docs/installation.md has the new-key line');
      const kept = spawnSync('sh', ['-c', newKey], { cwd: directory, encoding: 'utf8' });
      assert.equal(kept.status, 0, kept.stderr);
      assert.equal(kept.stdout.trim(), 'orbit_secret_key exists: keep it');
      assert.equal(readKeyFile(path.join(directory, 'orbit_secret_key')), `${key}\n`);
    }

    // Without the override: a generated secret.key in the volume, with the warning. Then the
    // existing-install switch: copy it out (here from the running container; the copy recipe as
    // printed runs in the COPY test below), start with the override (same fingerprint, and the
    // unused-key warning while the volume still has its copy), delete the copy (no warning).
    const { directory, compose } = composeProject(t, own, image);
    let since = now();
    up(compose, plain);
    let logs = await healthy(compose, plain, since);
    const generated =
      /^Encryption key: a new \/var\/lib\/uptime-goblin\/secret\.key \(generated now\) · fingerprint ([0-9a-f]{16})$/m.exec(
        logs
      );
    assert.ok(generated, logs);
    assert.match(
      logs,
      /\/var\/lib\/uptime-goblin\/secret\.key is inside the data directory, so every copy of the data directory carries the key/
    );
    const copied = compose(
      plain,
      'cp',
      'uptime-goblin:/var/lib/uptime-goblin/secret.key',
      './orbit_secret_key'
    );
    assert.equal(copied.status, 0, copied.stderr);
    writeKeyFile(directory, readKeyFile(path.join(directory, 'orbit_secret_key')).trim());
    since = now();
    up(compose, withSecret);
    logs = await healthy(compose, withSecret, since);
    assert.match(
      logs,
      new RegExp(
        `^Encryption key: the Compose secret \\(/run/secrets/orbit_secret_key\\) · fingerprint ${generated[1]}$`,
        'm'
      ),
      'the same key'
    );
    // The same key, copied out of the volume: delete the volume's copy once the secret no longer
    // comes from it (Uptime Goblin cannot see where a secret is mounted from).
    assert.ok(
      logs
        .split('\n')
        .includes(
          "/var/lib/uptime-goblin/secret.key holds the same key as the Compose secret (/run/secrets/orbit_secret_key), which Uptime Goblin uses. If the Compose secret's file is this secret.key (a data directory mounted from the host), deleting it would stop Uptime Goblin from starting: first copy the key to a file outside the data directory and make that the secret's file. Once the secret no longer comes from /var/lib/uptime-goblin/secret.key and Uptime Goblin has started with it, delete /var/lib/uptime-goblin/secret.key; every copy of the data directory carries it. This line deletes it only while the key it is given is another file that holds the same key and opens the data, and otherwise says why and deletes nothing: docker compose exec uptime-goblin node lib/cli/goblin-admin.mjs key remove-data-copy"
        ),
      logs
    );
    assert.doesNotMatch(logs, /inside the data directory/, 'the secret is a copy, not that file');
    // A66: the copy goes with goblin-admin key remove-data-copy, in Uptime Goblin's container beside the
    // running Uptime Goblin (uid 1000, read-only root file system, orbit.lock held).
    const removed = compose(
      withSecret,
      'exec',
      '-T',
      'uptime-goblin',
      'node',
      'lib/cli/goblin-admin.mjs',
      'key',
      'remove-data-copy'
    );
    assert.equal(removed.status, 0, removed.stdout + removed.stderr);
    assert.equal(
      removed.stdout,
      `Deleted /var/lib/uptime-goblin/secret.key: the Compose secret (/run/secrets/orbit_secret_key) holds the same key (fingerprint ${generated[1]}) and opens this data. Keep a backup of that key apart from the data.\n`
    );
    // The restart keeps the container and the warning its earlier start logged: this start's
    // logs are read from when it began (startedAt), and hold one start.
    const earlier = startedAt(compose, withSecret);
    assert.equal(compose(withSecret, 'restart', 'uptime-goblin').status, 0);
    since = startedAt(compose, withSecret);
    assert.ok(Date.parse(since) > Date.parse(earlier), `started at ${earlier}, then ${since}`);
    logs = await healthy(compose, withSecret, since);
    assert.match(logs, new RegExp(`fingerprint ${generated[1]}$`, 'm'));
    assert.equal(logs.match(/^Encryption key: /gm)?.length, 1, logs);
    assert.doesNotMatch(logs, /is not used|holds the same key/);

    // How the container ended, once it has (a refusal exits; restart is off in test.yaml).
    const exited = async files => {
      let exit = '';
      for (let i = 0; i < 60; i++) {
        const id = compose(files, 'ps', '--all', '--quiet', 'uptime-goblin').stdout.trim();
        const state = docker('inspect', '--format', '{{.State.Status}} {{.State.ExitCode}}', id);
        exit = state.stdout.trim();
        if (exit.startsWith('exited')) break;
        await delay(1000);
      }
      return exit;
    };
    const recreate = files =>
      compose(files, 'up', '--detach', '--no-build', '--pull', 'never', '--force-recreate');
    // An update as docs/installation.md once gave it, with compose.yaml alone: the recreated
    // container has no key, and with the volume's copy gone every start refuses (key_missing).
    recreate(plain);
    assert.equal(await exited(plain), 'exited 78');
    assert.match(
      compose(plain, 'logs', '--no-log-prefix', 'uptime-goblin').stdout,
      /The encryption key is missing: this data has a keyring, but no key was found/
    );
    // As the docs set it up now: COMPOSE_FILE in .env names the override, so the same command
    // without -f keeps the key (the test's own override appended: it names the image).
    fs.appendFileSync(
      path.join(directory, '.env'),
      'COMPOSE_FILE=compose.yaml:compose.secret.yaml:test.yaml\n'
    );
    since = now();
    assert.equal(recreate([]).status, 0);
    logs = await healthy(compose, [], since);
    assert.match(
      logs,
      new RegExp(
        `^Encryption key: the Compose secret \\(/run/secrets/orbit_secret_key\\) · fingerprint ${generated[1]}$`,
        'm'
      )
    );

    // A new key (`openssl rand -hex 32`) on that data: exit 78, key_mismatch, nothing changed.
    const other = randomBytes(32).toString('hex');
    writeKeyFile(directory, other);
    // A new container (the old one keeps the file it mounted).
    recreate(withSecret);
    assert.equal(await exited(withSecret), 'exited 78');
    assert.match(
      compose(withSecret, 'logs', '--no-log-prefix', 'uptime-goblin').stdout,
      new RegExp(
        `The encryption key \\(fingerprint ${keyFingerprint(Buffer.from(other, 'hex'))}\\) does not match this data\\.`
      )
    );
  }
);

// startedAt across `docker compose restart`, which keeps the container and its earlier start's
// output: the logs since it are the new start's alone. Each start of this service prints its own
// id at once (and a warning on stderr), then every 100 ms until it is stopped, as an earlier
// start may still be logging when the restart comes. A host time taken a second before the
// restart, the window the key test used, also holds the earlier start's lines here, every time.
test(
  "Compose: a restarted container's logs since startedAt are the new start's alone, though restart keeps the earlier start's",
  { skip, timeout: 300000 },
  async t => {
    const own = dockerOwner(t);
    const directory = temporary(t, 'orbit-restart-');
    fs.writeFileSync(
      path.join(directory, 'compose.yaml'),
      `services:\n  ticker:\n    image: node:24-bookworm-slim\n    network_mode: none\n    command: ['node', '-e', "const id = crypto.randomUUID(); console.log('start', id); console.error('warning', id); setInterval(() => console.log('still', id), 100); process.on('SIGTERM', () => process.exit(0))"]\n`
    );
    fs.writeFileSync(
      path.join(directory, 'test.yaml'),
      `services:\n  ticker:\n${serviceLimits}    restart: 'no'\n`
    );
    const name = `orbitrestart${randomBytes(4).toString('hex')}`;
    own.project(name, directory);
    const files = ['compose.yaml', 'test.yaml'];
    const compose = (files, ...args) =>
      spawnSync(
        'docker',
        ['compose', '--project-name', name, ...files.flatMap(file => ['-f', file]), ...args],
        { cwd: directory, encoding: 'utf8', timeout: 300000 }
      );
    const starts = text => [...text.matchAll(/^start (\S+)$/gm)].map(match => match[1]);
    // The service's logs (`since`: from then on), once they hold `count` starts and a later line
    // of the last one.
    const logs = async (count, since = []) => {
      let text = '';
      for (let i = 0; i < 120; i++) {
        text = compose(files, 'logs', '--no-log-prefix', ...since, 'ticker').stdout;
        const ids = starts(text);
        if (ids.length >= count && text.includes(`still ${ids.at(-1)}`)) break;
        await delay(250);
      }
      return text;
    };
    const up = compose(files, 'up', '--detach', '--pull', 'never');
    assert.equal(up.status, 0, up.stdout + up.stderr);
    const [first] = starts(await logs(1));
    assert.ok(first, 'the first start printed its id');
    const earlier = startedAt(compose, files, 'ticker');
    const restarted = compose(files, 'restart', 'ticker');
    assert.equal(restarted.status, 0, restarted.stdout + restarted.stderr);
    const since = startedAt(compose, files, 'ticker');
    assert.ok(Date.parse(since) > Date.parse(earlier), `started at ${earlier}, then ${since}`);
    // The container kept the first start's output: the case startedAt is for.
    const all = await logs(2);
    const [, second] = starts(all);
    assert.deepEqual(starts(all), [first, second], all);
    assert.notEqual(second, first);
    // Since startedAt: the second start's line, its warning and its ticks, none of the first's.
    const text = await logs(1, ['--since', since]),
      lines = text.split('\n').filter(Boolean);
    assert.deepEqual([...new Set(lines.map(line => line.split(' ')[1]))], [second], text);
    assert.deepEqual(starts(text), [second]);
    assert.ok(lines.includes(`warning ${second}`), text);
  }
);

// The upgrade from 1.4.x under Compose: 1.4.3 never writes secret.key, and 1.5 makes its keyring
// at its first start, so the documented new-key recipe is the one for that data; the copy
// recipe's first command finds nothing there (review round 2: the upgrade notes sent 1.4.x
// installs to the copy). 1.4.3 runs from its tag on the project's own volume, as uid 1000.
test(
  'Compose: a volume only 1.4.3 has run on has no secret.key, and the documented new-key recipe upgrades it',
  { skip, timeout: 900000 },
  async t => {
    const unavailable = tagUnavailable('v1.4.3');
    if (unavailable) {
      if (required('history')) assert.fail(`${unavailable} (TEST_REQUIRE=history)`);
      t.skip(unavailable);
      return;
    }
    const { keyFingerprint } = await import('../../lib/keyring.mjs');
    const id = randomBytes(4).toString('hex');
    const image = `uptime-goblin:test-keys143-${id}`,
      old = `orbit-compose-143-${id}`,
      node = 'node:24-bookworm-slim';
    const own = buildImage(t, image);
    const { directory, name, compose } = composeProject(t, own, image);
    const plain = ['compose.yaml', 'test.yaml'];
    // The project's volume as Compose makes it, given to the image's user (uid 1000).
    const created = compose(plain, 'create', '--no-build', '--pull', 'never');
    assert.equal(created.status, 0, created.stdout + created.stderr);
    const volume = `${name}_orbit-data`;
    const owned = docker(
      'run',
      ...limits,
      '--rm',
      '--network',
      'none',
      '--volume',
      `${volume}:/data`,
      node,
      'sh',
      '-c',
      'chown 1000:1000 /data && chmod 700 /data'
    );
    assert.equal(owned.status, 0, owned.stderr);
    const v143 = installTag('v1.4.3', path.join(temporary(t, 'orbit-compose-143-'), 'app'));
    fs.mkdirSync(path.join(v143, 'data'));
    own.run(
      '--name',
      old,
      '--init',
      '--user',
      'node',
      '--network',
      'none',
      '--read-only',
      '--tmpfs',
      '/tmp:size=16m,mode=1777',
      '--volume',
      `${v143}:/app:ro`,
      '--volume',
      `${volume}:/app/data`,
      '--workdir',
      '/app',
      '--env',
      'HOST=127.0.0.1',
      '--env',
      'PORT=4317',
      '--env',
      'ORBIT_DATA_DIR=/app/data',
      '--env',
      `ORBIT_PASSWORD=${randomBytes(18).toString('base64url')}`,
      node,
      'node',
      'server.mjs'
    );
    let version = null;
    for (let i = 0; i < 60 && version !== '1.4.3'; i++) {
      const status = docker('exec', old, 'cat', '/app/data/run/status.json');
      if (status.status === 0) version = JSON.parse(status.stdout).version;
      else await delay(500);
    }
    assert.equal(version, '1.4.3', docker('logs', old).stdout + docker('logs', old).stderr);
    assert.equal(docker('stop', old).status, 0);
    assert.equal(docker('rm', old).status, 0);
    // What 1.4.3 left in the volume: its data, and no key.
    const listed = docker(
      'run',
      ...limits,
      '--rm',
      '--network',
      'none',
      '-v',
      `${volume}:/data`,
      node,
      'ls',
      '-A',
      '/data'
    );
    assert.equal(listed.status, 0, listed.stderr);
    assert.match(listed.stdout, /^config\.json$/m);
    assert.doesNotMatch(listed.stdout, /secret\.key|control\.sqlite/);
    // The copy recipe's first command has nothing to copy on this data, and the check says NEW.
    const copied = compose(
      plain,
      'cp',
      'uptime-goblin:/var/lib/uptime-goblin/secret.key',
      './orbit_secret_key'
    );
    assert.notEqual(copied.status, 0, copied.stdout + copied.stderr);
    assert.ok(!fs.existsSync(path.join(directory, 'orbit_secret_key')));
    const check = volumeCheck({ directory, name }, plain);
    assert.equal(check.verdict, 'NEW', check.stdout + check.stderr);
    // The check only reads: it left no key and no control database in the volume.
    assert.doesNotMatch(
      docker(
        'run',
        ...limits,
        '--rm',
        '--network',
        'none',
        '-v',
        `${volume}:/data`,
        node,
        'ls',
        '-A',
        '/data'
      ).stdout,
      /secret\.key|control\.sqlite/
    );

    // The documented recipe for it, run as docs/installation.md prints it (runRecipe): the
    // chown a Linux host needs is the recipe's own block, before the start.
    const lines = recipeCommands(keyRecipes().fresh);
    assert.deepEqual(lines, [
      "test -e orbit_secret_key && echo 'orbit_secret_key exists: keep it' || { (umask 077 && openssl rand -hex 32 > orbit_secret_key) && chmod 0400 orbit_secret_key; }",
      'sudo chown 1000 orbit_secret_key',
      "echo 'COMPOSE_FILE=compose.yaml:compose.secret.yaml' >> .env",
      'docker compose up -d',
    ]);
    const since = new Date(Date.now() - 1000).toISOString();
    for (const [i, result] of runRecipe(lines, { directory, name }).entries())
      assert.equal(result.status, 0, `${lines[i]}\n${result.stdout}${result.stderr}`);
    const key = readKeyFile(path.join(directory, 'orbit_secret_key')).trim();
    assert.match(key, /^[0-9a-f]{64}$/);
    let healthy = false;
    for (let i = 0; i < 90 && !healthy; i++) {
      healthy =
        compose([], 'exec', '-T', 'uptime-goblin', 'node', 'lib/healthcheck.mjs').status === 0;
      if (!healthy) await delay(1000);
    }
    const logs = compose([], 'logs', '--no-log-prefix', '--since', since, 'uptime-goblin').stdout;
    assert.ok(healthy, logs);
    assert.match(
      logs,
      new RegExp(
        `^Encryption key: the Compose secret \\(/run/secrets/orbit_secret_key\\) · fingerprint ${keyFingerprint(Buffer.from(key, 'hex'))}$`,
        'm'
      )
    );
    assert.doesNotMatch(logs, /secret\.key is inside the data directory|does not match this data/);
    const after = compose(
      [],
      'exec',
      '-T',
      'uptime-goblin',
      'ls',
      '-A',
      '/var/lib/uptime-goblin',
      '/var/lib/uptime-goblin/snapshots'
    );
    assert.equal(after.status, 0, after.stderr);
    assert.doesNotMatch(after.stdout, /^secret\.key$/m, 'no key in the volume');
    assert.match(after.stdout, /^control\.sqlite$/m, 'the keyring, sealed with that key');
    assert.match(after.stdout, /^pre-upgrade-/m, "the pinned snapshot of 1.4.3's data");
  }
);

// Review round 3: a volume 1.5 ran on without compose.secret.yaml, then rolled back to 1.4.3,
// which leaves /var/lib/uptime-goblin/secret.key alone. The release running is 1.4.x, but the volume holds
// the key its data is sealed with: the recipe for "the upgrade from 1.4.x" (a new key) refused,
// exit 78 key_mismatch for good (restart: unless-stopped), and the refusal never named that
// file. Now the check that compose.secret.yaml and the docs give says COPY on that volume, the
// new key's refusal names /var/lib/uptime-goblin/secret.key with its fingerprint, and the copy recipe works.
// Review of 9a7d6e5: the copy recipe no longer copies over an orbit_secret_key; after that new
// key the check says MOVE (a copy, then the file removed, sets the key aside: after a rename,
// OrbStack could still mount the renamed file, and the start refused with the key set aside;
// Docker Desktop was not tested). A65: with compose.yaml's restart policy, as shipped, the move
// recipe reads the volume's key with a container of its own before it sets anything aside.
// A66: its last line deletes the volume's copy with goblin-admin key remove-data-copy.
test(
  'Compose: a volume 1.5 ran on without the override, then 1.4.3: the documented check says COPY, a new key refuses naming /var/lib/uptime-goblin/secret.key and restarts, the check then says MOVE, and the move recipe, run as printed while the refused container restarts, upgrades it',
  { skip, timeout: 900000 },
  async t => {
    const unavailable = tagUnavailable('v1.4.3');
    if (unavailable) {
      if (required('history')) assert.fail(`${unavailable} (TEST_REQUIRE=history)`);
      t.skip(unavailable);
      return;
    }
    const { keyFingerprint } = await import('../../lib/keyring.mjs');
    const image = `uptime-goblin:test-keysback-${randomBytes(4).toString('hex')}`;
    const own = buildImage(t, image);
    const old = buildOrbit143(t, own);
    const { directory, name, compose } = composeProject(t, own, image, '', {
      shippedRestart: true,
    });
    // 1.4.3 as docs/installation.md rolls back to it: its own image, under the 1.5 compose.yaml,
    // with the documented compose.override.yaml (rollbackOverride), on the same volume.
    fs.writeFileSync(path.join(directory, 'compose.override.yaml'), rollbackOverride(old));
    const plain = ['compose.yaml', 'test.yaml'],
      back = ['compose.yaml', 'test.yaml', 'compose.override.yaml'];
    const up = files =>
      compose(files, 'up', '--detach', '--no-build', '--pull', 'never', '--force-recreate');
    const healthy = async (files, since) => {
      for (let i = 0; i < 90; i++) {
        if (
          compose(files, 'exec', '-T', 'uptime-goblin', 'node', 'lib/healthcheck.mjs').status === 0
        )
          return compose(files, 'logs', '--no-log-prefix', '--since', since, 'uptime-goblin')
            .stdout;
        await delay(1000);
      }
      assert.fail(compose(files, 'logs', 'uptime-goblin').stdout);
    };
    const now = () => new Date(Date.now() - 1000).toISOString();

    // 1.5 without the override generates /var/lib/uptime-goblin/secret.key and seals the data with it.
    let since = now();
    let result = up(plain);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    let logs = await healthy(plain, since);
    const generated =
      /^Encryption key: a new \/var\/lib\/uptime-goblin\/secret\.key \(generated now\) · fingerprint ([0-9a-f]{16})$/m.exec(
        logs
      )?.[1];
    assert.ok(generated, logs);
    assert.equal(compose(plain, 'stop').status, 0);
    // The rollback: 1.4.3 runs on that volume, and leaves secret.key there.
    result = up(back);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    let version = null;
    for (let i = 0; i < 60 && version !== '1.4.3'; i++) {
      const status = compose(
        back,
        'exec',
        '-T',
        'uptime-goblin',
        'cat',
        '/app/data/run/status.json'
      );
      if (status.status === 0) version = JSON.parse(status.stdout).version;
      else await delay(500);
    }
    assert.equal(version, '1.4.3', compose(back, 'logs', 'uptime-goblin').stdout);
    // The check of compose.secret.yaml (and docs/installation.md): COPY, while 1.4.3 runs. The
    // check runs goblin-admin, so in the 1.5 image (`plain` names it).
    const check = volumeCheck({ directory, name }, plain);
    assert.equal(check.verdict, 'COPY', check.stdout + check.stderr);
    assert.equal(compose(back, 'stop').status, 0);
    // Forward again, as the docs say: the override goes.
    fs.rmSync(path.join(directory, 'compose.override.yaml'));

    // The recipe for data only 1.4.x has run on, which this volume is not: a new key, named in
    // .env as that recipe does, refuses (exit 78) and names the key that opens the data, with
    // MOVE. compose.yaml's restart policy is kept (shippedRestart), so the refusal repeats, in a
    // container that mounts orbit_secret_key, as it does for a user.
    const wrongKey = randomBytes(32).toString('hex');
    writeKeyFile(directory, wrongKey);
    fs.appendFileSync(
      path.join(directory, '.env'),
      'COMPOSE_FILE=compose.yaml:compose.secret.yaml:test.yaml\n'
    );
    result = up([]);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    const refused = await refusing(compose);
    assert.match(
      refused,
      /^78 ([2-9]|[1-9]\d+)$/,
      'Uptime Goblin refuses, and compose.yaml starts it again'
    );
    logs = compose([], 'logs', '--no-log-prefix', 'uptime-goblin').stdout;
    assert.match(logs, /does not match this data\./);
    assert.ok(
      logs.includes(
        `/var/lib/uptime-goblin/secret.key (fingerprint ${generated}) opens this data: Uptime Goblin generated it there when it ran without the Compose secret (/run/secrets/orbit_secret_key), and a rollback to 1.4.x leaves it in place. Use that key: make the Compose secret (/run/secrets/orbit_secret_key) hold it (Docker Compose: the check in compose.secret.yaml prints MOVE: take that file's MOVE recipe, which puts this key in a new orbit_secret_key and keeps the current one as orbit_secret_key.unused)`
      ),
      logs
    );
    // The check says so too.
    const moveCheck = volumeCheck({ directory, name }, plain);
    assert.equal(moveCheck.verdict, 'MOVE', moveCheck.stdout + moveCheck.stderr);

    // The move recipe, run as docs/installation.md prints it (runRecipe), with its own chown and
    // start, one command at a time as a person runs them (2 s apart) while the restart policy
    // keeps starting the refused container. A65: A60's MOVE set the key aside, then took the copy
    // recipe, whose docker compose cp read /var/lib/uptime-goblin/secret.key through that container; once its
    // orbit_secret_key was gone the cp failed ("Could not find the file /var/lib/uptime-goblin/secret.key in
    // container"), 5 of 5 runs of this test with A60's lines, and no orbit_secret_key was made.
    // The recipe reads the key with a container of its own, and goblin-admin checks it, before
    // it changes any file; Uptime Goblin then starts in a new container.
    const commands = recipeCommands(keyRecipes().move);
    const start = commands.indexOf('docker compose up -d --force-recreate');
    assert.ok(start > 0, commands.join('\n'));
    assert.ok(
      commands.slice(0, start).some(line => line.startsWith('sudo chown 1000 orbit_secret_key')),
      'the move recipe gives the key file to uid 1000 before it starts Uptime Goblin'
    );
    for (const [i, command] of commands.slice(0, start).entries()) {
      if (i) await delay(2000);
      const [done] = runRecipe([command], { directory, name });
      assert.equal(done.status, 0, `${command}\n${done.stdout}${done.stderr}`);
    }
    assert.equal(
      readKeyFile(path.join(directory, 'orbit_secret_key.unused')),
      `${wrongKey}\n`,
      'the new key, kept aside'
    );
    const movedKey = readKeyFile(path.join(directory, 'orbit_secret_key')).trim();
    assert.equal(keyFingerprint(Buffer.from(movedKey, 'hex')), generated);
    assert.deepEqual(
      fs
        .readdirSync(directory)
        .filter(file => file.startsWith('orbit_secret_key'))
        .sort(),
      ['orbit_secret_key', 'orbit_secret_key.unused'],
      'the file the volume key was read into is gone'
    );
    await delay(2000);
    since = now();
    const [started] = runRecipe([commands[start]], { directory, name });
    assert.equal(started.status, 0, started.stdout + started.stderr);
    logs = await healthy([], since);
    const secretLine = `Encryption key: the Compose secret (/run/secrets/orbit_secret_key) · fingerprint ${generated}`;
    assert.ok(logs.split('\n').includes(secretLine), logs);
    // The recipe's checks, then the deletion of the volume's copy, as printed.
    const [shown, configured, removed] = runRecipe(commands.slice(start + 1), {
      directory,
      name,
    });
    assert.ok(shown.stdout.includes(secretLine), shown.stdout + shown.stderr);
    assert.match(configured.stdout, /orbit_secret_key/);
    assert.equal(removed.status, 0, removed.stderr);
    assert.notEqual(
      compose([], 'exec', '-T', 'uptime-goblin', 'test', '-e', '/var/lib/uptime-goblin/secret.key')
        .status,
      0,
      'the volume no longer carries the key'
    );
    assert.equal(volumeCheck({ directory, name }, plain).verdict, 'KEEP');
  }
);

// The upgrade from Orbit 1.4.3 under Docker Compose, end to end on one project and its volume
// (docs/installation.md, Renamed from Orbit and Rolling back 1.5 to 1.4.3). (1) 1.4.3 runs from
// its own image under the 1.4.3 release's compose.yaml (service orbit, the volume at /app/data,
// .env with the ORBIT_ names). (2) The 1.5 image under that old compose.yaml: the volume, mounted
// at /app/data alone, is used there, with a notice, and the ORBIT_ settings with theirs. (3) The
// 1.5 compose.yaml with the volume at both paths: up -d --remove-orphans removes the old orbit
// container, and the start refuses (exit 78). (4) As documented: both names in .env with
// different values (an empty GOBLIN_WEBHOOK_URL beside an old ORBIT_WEBHOOK_URL) refuse; .env with
// only the ORBIT_ names reaches the container as the GOBLIN_ ones (compose.yaml's nested
// fallback), with a notice, on the data at /var/lib/uptime-goblin. (5) The documented rollback
// override starts 1.4.3 again on that volume with those settings. (6) Without it, 1.5 again.
test(
  'Compose from Orbit 1.4.3: its own compose.yaml, the 1.5 image on /app/data, both paths refused, --remove-orphans, ORBIT_ settings through compose.yaml, the documented rollback to 1.4.3 and forward again',
  { skip, timeout: 900000 },
  async t => {
    const unavailable = tagUnavailable('v1.4.3');
    if (unavailable) {
      if (required('history')) assert.fail(`${unavailable} (TEST_REQUIRE=history)`);
      t.skip(unavailable);
      return;
    }
    const id = randomBytes(4).toString('hex');
    const image = `uptime-goblin:test-from143-${id}`;
    const own = buildImage(t, image);
    const old = buildOrbit143(t, own);
    const release = JSON.parse(
      fs.readFileSync(path.join(repository, 'package.json'), 'utf8')
    ).version;
    const directory = temporary(t, 'orbit-compose-from143-');
    const name = `orbitfrom143${id}`;
    own.project(name, directory);
    const compose = (files, ...args) =>
      spawnSync(
        'docker',
        ['compose', '--project-name', name, ...files.flatMap(file => ['-f', file]), ...args],
        { cwd: directory, encoding: 'utf8', timeout: 300000 }
      );
    const files = ['compose.yaml', 'test.yaml'];
    // The test's override: the image, no published port, no restart (a refusal stays visible)
    // and the test containers' limits, for `service`, plus `extra` lines.
    const override = (service, tag, extra = '') =>
      fs.writeFileSync(
        path.join(directory, 'test.yaml'),
        `services:\n  ${service}:\n    image: ${tag}\n    ports: !reset []\n${serviceLimits}    restart: 'no'\n${extra}`
      );
    const password = randomBytes(18).toString('base64url');
    const env = `ORBIT_PASSWORD=${password}\nORBIT_ALLOWED_HOSTS=goblin.example.com:4317\n`;
    fs.writeFileSync(path.join(directory, '.env'), env, { mode: 0o600 });
    const up = (list = files, ...more) => {
      const result = compose(list, 'up', '--detach', '--no-build', '--pull', 'never', ...more);
      assert.equal(result.status, 0, result.stdout + result.stderr);
    };
    const logs = (service, list = files) => {
      const result = compose(list, 'logs', '--no-log-prefix', service);
      return result.stdout + result.stderr;
    };
    const healthy = async (service, list = files) => {
      for (let i = 0; i < 90; i++) {
        if (compose(list, 'exec', '-T', service, 'node', 'lib/healthcheck.mjs').status === 0)
          return;
        await delay(1000);
      }
      assert.fail(logs(service, list));
    };
    const statusVersion = async (service, file, expected, list = files) => {
      let version = null;
      for (let i = 0; i < 90 && version !== expected; i++) {
        const read = compose(list, 'exec', '-T', service, 'cat', file);
        if (read.status === 0) version = JSON.parse(read.stdout).version;
        if (version !== expected) await delay(1000);
      }
      assert.equal(version, expected, logs(service, list));
    };
    const exitedWith = async service => {
      let state = '';
      for (let i = 0; i < 60; i++) {
        const container = compose(files, 'ps', '--all', '--quiet', service).stdout.trim();
        state = docker(
          'inspect',
          '--format',
          '{{.State.Status}} {{.State.ExitCode}}',
          container
        ).stdout.trim();
        if (state.startsWith('exited')) break;
        await delay(1000);
      }
      return state;
    };
    const containersOf = service =>
      docker(
        'ps',
        '--all',
        '--quiet',
        '--filter',
        `label=com.docker.compose.project=${name}`,
        '--filter',
        `label=com.docker.compose.service=${service}`
      ).stdout.trim();

    // (1) Orbit 1.4.3 as its release ran it: its compose.yaml, service orbit, /app/data.
    const tree = installTag('v1.4.3', path.join(temporary(t, 'orbit-compose-143-tree-'), 'app'));
    fs.copyFileSync(path.join(tree, 'compose.yaml'), path.join(directory, 'compose.yaml'));
    assert.match(
      fs.readFileSync(path.join(directory, 'compose.yaml'), 'utf8'),
      /^ {2}orbit:\n[\s\S]*^ {6}- orbit-data:\/app\/data$/m
    );
    override('orbit', old);
    up();
    await statusVersion('orbit', '/app/data/run/status.json', '1.4.3');

    // (2) The 1.5 image under the old compose.yaml: only /app/data holds data, so it is used.
    override('orbit', image);
    up();
    await healthy('orbit');
    await statusVersion('orbit', '/app/data/run/status.json', release);
    const fallback = logs('orbit');
    assert.ok(
      fallback.includes(
        'The data volume is mounted at /app/data, where the image kept its data before the rename to Uptime Goblin, and is used there. Mount it at /var/lib/uptime-goblin instead (compose.yaml: - orbit-data:/var/lib/uptime-goblin); /app/data is no longer read from 1.7.'
      ),
      fallback
    );
    assert.match(fallback, /^Deprecated settings: .*ORBIT_PASSWORD → GOBLIN_PASSWORD/m);
    const kept = compose(
      files,
      'exec',
      '-T',
      'orbit',
      'ls',
      '-A',
      '/app/data',
      '/app/data/snapshots'
    );
    assert.equal(kept.status, 0, kept.stderr);
    assert.match(kept.stdout, /^config\.json$/m, "1.4.3's data");
    assert.match(kept.stdout, /^pre-upgrade-/m, "the pinned snapshot of 1.4.3's data");

    // (3) The 1.5 project files, with the volume at both paths: --remove-orphans takes the old
    // orbit container, and the start refuses, naming both.
    for (const file of ['compose.yaml', 'compose.secret.yaml'])
      fs.copyFileSync(path.join(repository, file), path.join(directory, file));
    override('uptime-goblin', image, '    volumes:\n      - orbit-data:/app/data\n');
    assert.notEqual(containersOf('orbit'), '', 'the old orbit container is there');
    up(files, '--remove-orphans');
    assert.equal(containersOf('orbit'), '', '--remove-orphans removed the orbit container');
    assert.equal(await exitedWith('uptime-goblin'), 'exited 78');
    assert.match(
      logs('uptime-goblin'),
      /^Both \/var\/lib\/uptime-goblin and \/app\/data hold data, so which one is meant cannot be told\./m
    );

    // (4) The volume at /var/lib/uptime-goblin alone. Both names of a setting in .env with
    // different values refuse, an empty GOBLIN_ value included (it never falls back).
    override('uptime-goblin', image);
    fs.appendFileSync(
      path.join(directory, '.env'),
      'ORBIT_WEBHOOK_URL=https://hooks.example.com/old\nGOBLIN_WEBHOOK_URL=\n'
    );
    up();
    assert.equal(await exitedWith('uptime-goblin'), 'exited 78');
    const conflict = logs('uptime-goblin');
    assert.match(
      conflict,
      /GOBLIN_WEBHOOK_URL and ORBIT_WEBHOOK_URL are both set, to different values, so which was meant cannot be told\./
    );
    assert.doesNotMatch(conflict, /hooks\.example\.com/);
    // .env with the ORBIT_ names only, as 1.4.3 left it: compose.yaml passes them as GOBLIN_.
    fs.writeFileSync(path.join(directory, '.env'), env, { mode: 0o600 });
    up();
    await healthy('uptime-goblin');
    await statusVersion('uptime-goblin', '/var/lib/uptime-goblin/run/status.json', release);
    const upgraded = logs('uptime-goblin');
    assert.match(
      upgraded,
      /^Deprecated settings: (?=.*ORBIT_ALLOWED_HOSTS → GOBLIN_ALLOWED_HOSTS)(?=.*ORBIT_PASSWORD → GOBLIN_PASSWORD).*$/m
    );
    assert.doesNotMatch(upgraded, /mounted at \/app\/data/);
    assert.equal(
      compose(files, 'exec', '-T', 'uptime-goblin', 'printenv', 'GOBLIN_ALLOWED_HOSTS').stdout,
      'goblin.example.com:4317\n'
    );
    const moved = compose(
      files,
      'exec',
      '-T',
      'uptime-goblin',
      'ls',
      '-A',
      '/var/lib/uptime-goblin'
    );
    assert.match(moved.stdout, /^config\.json$/m, moved.stderr);

    // (5) The documented rollback: 1.4.3's image with the override, on the same volume.
    fs.writeFileSync(path.join(directory, 'compose.override.yaml'), rollbackOverride(old));
    const back = ['compose.yaml', 'test.yaml', 'compose.override.yaml'];
    assert.equal(compose(back, 'stop', 'uptime-goblin').status, 0);
    up(back);
    await statusVersion('uptime-goblin', '/app/data/run/status.json', '1.4.3', back);
    assert.equal(
      compose(back, 'exec', '-T', 'uptime-goblin', 'printenv', 'ORBIT_ALLOWED_HOSTS').stdout,
      'goblin.example.com:4317\n'
    );
    const signedIn = compose(
      back,
      'exec',
      '-T',
      'uptime-goblin',
      'node',
      '-e',
      `fetch('http://127.0.0.1:4317/api/dashboard', { headers: { Host: 'goblin.example.com:4317', Authorization: 'Basic ' + btoa('admin:' + ${JSON.stringify(password)}) } }).then(r => process.exit(r.status === 200 ? 0 : r.status % 256), () => process.exit(1))`
    );
    assert.equal(signedIn.status, 0, `1.4.3 signs in with the password: ${signedIn.stderr}`);

    // (6) Forward again: without the override, 1.5 on /var/lib/uptime-goblin.
    fs.rmSync(path.join(directory, 'compose.override.yaml'));
    up();
    await healthy('uptime-goblin');
    await statusVersion('uptime-goblin', '/var/lib/uptime-goblin/run/status.json', release);
  }
);

// A65: the copy recipe read /var/lib/uptime-goblin/secret.key with docker compose cp, through Uptime Goblin's own
// container. That works while Uptime Goblin runs without the override, but not once that container is
// one that refused with an orbit_secret_key that is gone (a wrong key removed by hand, or set
// aside as A60's MOVE did): the cp failed, 3 of 3 runs, and no orbit_secret_key was made. The
// recipe now reads the key with a container of its own and has goblin-admin check it. Both
// states run here, with compose.yaml's restart policy and a person's pace (2 s between commands).
test(
  "Compose: the copy recipe reads the volume's key with a container of its own, while Uptime Goblin runs without the override and after a refused key file was removed by hand",
  { skip, timeout: 900000 },
  async t => {
    const { keyFingerprint } = await import('../../lib/keyring.mjs');
    const image = `uptime-goblin:test-keyscopy-${randomBytes(4).toString('hex')}`;
    const own = buildImage(t, image);
    const plain = ['compose.yaml', 'test.yaml'];
    const now = () => new Date(Date.now() - 1000).toISOString();
    const commands = recipeCommands(keyRecipes().copy);
    const start = commands.indexOf('docker compose up -d');
    assert.ok(start > 0, commands.join('\n'));
    for (const removedByHand of [false, true]) {
      const project = composeProject(t, own, image, '', { shippedRestart: true });
      const { directory, compose } = project;
      const healthy = async (files, since) => {
        for (let i = 0; i < 90; i++) {
          if (
            compose(files, 'exec', '-T', 'uptime-goblin', 'node', 'lib/healthcheck.mjs').status ===
            0
          )
            return compose(files, 'logs', '--no-log-prefix', '--since', since, 'uptime-goblin')
              .stdout;
          await delay(1000);
        }
        assert.fail(compose(files, 'logs', 'uptime-goblin').stdout);
      };
      // 1.5 without the override generates /var/lib/uptime-goblin/secret.key and seals the data with it.
      let since = now();
      let result = compose(plain, 'up', '--detach', '--no-build', '--pull', 'never');
      assert.equal(result.status, 0, result.stdout + result.stderr);
      let logs = await healthy(plain, since);
      const generated =
        /^Encryption key: a new \/var\/lib\/uptime-goblin\/secret\.key \(generated now\) · fingerprint ([0-9a-f]{16})$/m.exec(
          logs
        )?.[1];
      assert.ok(generated, logs);
      if (removedByHand) {
        // A new key by mistake, named in .env as the new-key recipe does: Uptime Goblin refuses, again
        // and again, in a container that mounts it; then that key file is removed by hand.
        writeKeyFile(directory, randomBytes(32).toString('hex'));
        fs.appendFileSync(
          path.join(directory, '.env'),
          'COMPOSE_FILE=compose.yaml:compose.secret.yaml:test.yaml\n'
        );
        result = compose([], 'up', '--detach', '--no-build', '--pull', 'never');
        assert.equal(result.status, 0, result.stdout + result.stderr);
        assert.match(await refusing(compose), /^78 ([2-9]|[1-9]\d+)$/);
        fs.rmSync(path.join(directory, 'orbit_secret_key'));
        await delay(2000);
      }
      const check = volumeCheck(project, plain);
      assert.equal(check.verdict, 'COPY', check.stdout + check.stderr);
      // The copy recipe, as docs/installation.md prints it, up to its start.
      for (const [i, command] of commands.slice(0, start).entries()) {
        if (i) await delay(2000);
        const [done] = runRecipe([command], project);
        assert.equal(done.status, 0, `${command}\n${done.stdout}${done.stderr}`);
      }
      const keyFile = path.join(directory, 'orbit_secret_key');
      const copied = readKeyFile(keyFile).trim();
      assert.equal(keyFingerprint(Buffer.from(copied, 'hex')), generated, `${removedByHand}`);
      assert.equal(fs.statSync(keyFile).mode & 0o777, 0o400);
      assert.deepEqual(
        fs.readdirSync(directory).filter(file => file.startsWith('orbit_secret_key')),
        ['orbit_secret_key'],
        'the file the volume key was read into is gone'
      );
      // Its start (`up -d`, as printed), its checks, and the deletion of the volume's copy.
      await delay(2000);
      since = now();
      const [started] = runRecipe([commands[start]], project);
      assert.equal(started.status, 0, started.stdout + started.stderr);
      logs = await healthy([], since);
      const secretLine = `Encryption key: the Compose secret (/run/secrets/orbit_secret_key) · fingerprint ${generated}`;
      assert.ok(logs.split('\n').includes(secretLine), logs);
      const [shown, configured, removed] = runRecipe(commands.slice(start + 1), project);
      assert.ok(shown.stdout.includes(secretLine), shown.stdout + shown.stderr);
      assert.match(configured.stdout, /orbit_secret_key/);
      assert.equal(removed.status, 0, removed.stderr);
      assert.notEqual(
        compose(
          [],
          'exec',
          '-T',
          'uptime-goblin',
          'test',
          '-e',
          '/var/lib/uptime-goblin/secret.key'
        ).status,
        0,
        'the volume no longer carries the key'
      );
    }
  }
);

// How one run of the MOVE recipe's last line went, in the A66 tests below (their knock).
// 'reached': it ran in Uptime Goblin's container and ended there, so its exit status is the line's own:
// goblin-admin answered (it says why it kept the file; A65's rm exited 0 once it had deleted it,
// or said rm: …), rather than finding no container running. 'killed': it ended 137 (SIGKILL)
// because the refusing container it ran in stopped under it. Docker kills whatever still runs in
// a container that stops, even an goblin-admin that has already printed its answer, so the line's
// own exit status is lost; such a run is not counted, but the volume's key is checked after it
// too. Round 3 of checkpoint 2c saw one counted ("137 goblin-admin key: … Nothing was deleted."),
// and the test failed.
function lastLineRun({ status, stdout, stderr }) {
  if (status === 137) return 'killed';
  return status === 0 || /Nothing was deleted|rm: /.test(stdout + stderr) ? 'reached' : 'missed';
}

test('a run of the recipe line that Docker killed with its stopping container is not counted', () => {
  const answer =
    'goblin-admin key: The Compose secret (/run/secrets/orbit_secret_key) (fingerprint 0123456789abcdef) does not open this data, so /var/lib/uptime-goblin/secret.key may be the only key that does. Nothing was deleted.\n';
  assert.equal(lastLineRun({ status: 137, stdout: answer, stderr: '' }), 'killed');
  assert.equal(lastLineRun({ status: 137, stdout: '', stderr: '' }), 'killed');
  assert.equal(lastLineRun({ status: 1, stdout: answer, stderr: '' }), 'reached');
  assert.equal(lastLineRun({ status: 0, stdout: '', stderr: '' }), 'reached');
  assert.equal(lastLineRun({ status: 1, stdout: '', stderr: 'rm: cannot remove …\n' }), 'reached');
  assert.equal(
    lastLineRun({ status: 1, stdout: '', stderr: 'service "uptime-goblin" is not running\n' }),
    'missed'
  );
});

// A 'killed' run is excused only when its container did stop under it: between a look before the
// run and a look after, the project's Uptime Goblin container is gone, no longer running, another one, or
// started again (a new StartedAt or RestartCount, Docker's restart policy). A 137 from a
// container that ran throughout is no such stop, and fails the test (stoppedWithRun).
function orbitContainer(project) {
  const listed = docker(
    'ps',
    '--all',
    '--quiet',
    '--filter',
    `label=com.docker.compose.project=${project}`,
    '--filter',
    'label=com.docker.compose.service=orbit'
  ).stdout.trim();
  if (!listed || listed.includes('\n')) return null;
  const [inspected] = JSON.parse(docker('inspect', listed).stdout || '[]');
  if (!inspected) return null;
  return {
    id: inspected.Id,
    startedAt: inspected.State.StartedAt,
    restarts: inspected.RestartCount,
    running: inspected.State.Running,
  };
}
function stoppedUnder(before, after) {
  return (
    !before ||
    !after ||
    !after.running ||
    after.id !== before.id ||
    after.startedAt !== before.startedAt ||
    after.restarts !== before.restarts
  );
}

test('a 137 counts as killed with its container only when that container stopped or restarted under the run', () => {
  const up = { id: 'c1', startedAt: '2026-10-04T10:00:00Z', restarts: 2, running: true };
  assert.equal(stoppedUnder(up, { ...up }), false, 'the same container ran throughout');
  assert.equal(stoppedUnder(up, { ...up, running: false }), true);
  assert.equal(stoppedUnder(up, { ...up, startedAt: '2026-10-04T10:00:03Z', restarts: 3 }), true);
  assert.equal(stoppedUnder(up, { ...up, restarts: 3 }), true);
  assert.equal(stoppedUnder(up, { ...up, id: 'c2' }), true);
  assert.equal(stoppedUnder(up, null), true);
  assert.equal(stoppedUnder(null, up), true);
});

// Whether a run that ended 137 did so because the container it ran in (`before`, as orbitContainer
// saw it just before the run) stopped under it. Docker answers the exec's 137 before it has
// handled the container's own exit: for a while after it, an inspect still shows that container
// running, with the same StartedAt and RestartCount (and State.Running stays true while it
// restarts). So, right after the 137, an exec into the container (`startsIn`, docker exec <id>
// true) tells whether its first process still runs, since a container whose first process has
// exited takes no other; then `look` (orbitContainer) is repeated, every `every` ms for up to
// `within` ms, until Docker shows that stop. A container that still takes a process and is still
// that same start of it ran throughout: false, without waiting for a stop of its own (a refusing
// container stops about a second after it starts, and would excuse any 137). One that takes it in
// a later start did stop after the look before the run, and is excused, though the look cannot
// tell whether the run began before that stop or after it. A stop Docker never shows: false.
async function stoppedWithRun(before, { startsIn, look, every = 100, within = 10000 }) {
  if (!before) return true;
  if (startsIn(before.id)) return stoppedUnder(before, look());
  for (const until = Date.now() + within; ; await delay(every)) {
    if (stoppedUnder(before, look())) return true;
    if (Date.now() >= until) return false;
  }
}

test('a 137 is excused only when its container no longer takes a process and Docker then shows it stopped or started again', async () => {
  const up = { id: 'c1', startedAt: '2026-10-04T10:00:00Z', restarts: 2, running: true };
  const again = { ...up, startedAt: '2026-10-04T10:00:03Z', restarts: 3 };
  // `look` answers each of `seen` in turn, then the last one for good; `startsIn` records its id.
  const excused = (startsIn, ...seen) => {
    const asked = [];
    return stoppedWithRun(up, {
      startsIn: id => (asked.push(id), startsIn),
      look: () => (seen.length > 1 ? seen.shift() : seen[0]),
      every: 1,
      within: 300,
    }).then(answer => {
      assert.deepEqual(asked, ['c1'], 'the exec went to the container the run began in');
      return answer;
    });
  };
  // Docker shows the stop only after the 137: the same start, running, for three looks.
  assert.equal(await excused(false, up, up, up, again), true);
  assert.equal(await excused(false, up, { ...up, running: false }), true);
  assert.equal(await excused(false, up, null), true, 'removed');
  assert.equal(await excused(false, up), false, 'Docker never shows the stop');
  // It still takes a process, and is the start the run began in: it ran throughout, though it
  // stops later on its own.
  assert.equal(await excused(true, up, up, again), false);
  // It takes a process in a later start of it: it stopped since the look before the run.
  assert.equal(await excused(true, again), true);
  // No one container before the run (it was being made again): nothing to hold it to.
  assert.equal(
    await stoppedWithRun(null, { startsIn: () => true, look: () => up, every: 1, within: 300 }),
    true
  );
});

// A66: the MOVE recipe pasted whole in two states it is not for, as the real-Docker check of A65
// did: its lines are independent once pasted, and its last line, then docker compose exec orbit
// rm /var/lib/uptime-goblin/secret.key, deleted the only key that opens the data. (1) The COPY state, Uptime Goblin
// running without the override: the first command stops (there is no orbit_secret_key to set
// aside), the start fails (its bind source does not exist) and leaves Uptime Goblin's container running,
// and the rm deleted the key in it, 3 of 3 runs. (2) The MOVE state with an
// orbit_secret_key.unused left by an earlier attempt: the first command stops, the start makes a
// container that mounts the wrong key C and refuses, and the rm reached it within its second of
// life (1 of 1, and 2 of 15 in a probe). The last line is now goblin-admin key remove-data-copy;
// after the paste it is run again and again while that container restarts, until it has reached
// the container 3 times, so that a line that deletes would be caught. The volume's key stays,
// byte for byte, and the check says what it said before. One test per state.
for (const [state, title] of [
  ['COPY', 'on a COPY volume while Uptime Goblin runs without the override'],
  [
    'MOVE with .unused',
    'beside an earlier orbit_secret_key.unused while the container that mounts the new key refuses',
  ],
])
  test(
    `Compose: a recipe pasted whole in the wrong state keeps the only key: the MOVE recipe ${title}`,
    { skip, timeout: 900000 },
    async t => {
      const image = `uptime-goblin:test-keyspaste-${randomBytes(4).toString('hex')}`;
      const own = buildImage(t, image);
      const plain = ['compose.yaml', 'test.yaml'];
      const { move } = keyRecipes();
      const lastLine = recipeCommands(move).at(-1);
      const healthy = async compose => {
        for (let i = 0; i < 90; i++) {
          if (
            compose(plain, 'exec', '-T', 'uptime-goblin', 'node', 'lib/healthcheck.mjs').status ===
            0
          )
            return;
          await delay(1000);
        }
        assert.fail(compose(plain, 'logs', 'uptime-goblin').stdout);
      };
      // The key in the volume, read by a container of the test's own (never through Uptime Goblin's).
      const volumeKey = name => {
        const read = docker(
          'run',
          ...limits,
          '--rm',
          '--network',
          'none',
          '--volume',
          `${name}_orbit-data:/d:ro`,
          'node:24-bookworm-slim',
          'sh',
          '-c',
          'cat /d/secret.key 2>/dev/null || echo absent'
        );
        assert.equal(read.status, 0, read.stderr);
        return read.stdout;
      };
      const keyFiles = directory =>
        Object.fromEntries(
          fs
            .readdirSync(directory)
            .filter(file => file.startsWith('orbit_secret_key'))
            .sort()
            .map(file => [file, readKeyFile(path.join(directory, file))])
        );
      // The last line again and again until it has run in Uptime Goblin's container `times` times, the
      // volume's key checked each time. A container that refuses lives about a second and is
      // started again after a delay that doubles, so with `again` each round of 8 s begins with the
      // recipe's start once more (as a second paste would): a new container, the shortest delay.
      // Returns the counted runs' exit statuses and output (lastLineRun says which count). A run
      // killed with its container counts only as that, and only when the container did stop or
      // restart under it (stoppedWithRun); where Uptime Goblin stays up (`killable` false, the COPY state)
      // any 137 fails.
      const startLine = recipeCommands(move).find(line => /^docker compose up -d/.test(line));
      const knock = async (project, a, times, { again = false, killable = true } = {}) => {
        let reached = 0;
        const seen = [],
          killed = [];
        const after = () => `the volume key, after:\n${[...seen, ...killed].join('\n')}`;
        for (let round = 0; round < 20 && reached < times; round++) {
          if (again && round) runRecipe([startLine], project);
          const until = Date.now() + 8000;
          while (Date.now() < until && reached < times) {
            const before = orbitContainer(project.name);
            const [result] = runRecipe([lastLine], project);
            const run = lastLineRun(result),
              said = `${result.status} ${(result.stdout + result.stderr).trim()}`;
            if (run === 'missed') continue;
            if (run === 'reached') {
              reached++;
              seen.push(said);
            } else {
              assert.ok(
                killable,
                `killed (137) although Uptime Goblin's container stays up: ${said}`
              );
              const stopped = await stoppedWithRun(before, {
                startsIn: id => docker('exec', id, 'true').status === 0,
                look: () => orbitContainer(project.name),
              });
              assert.ok(
                stopped,
                `killed (137) while its container ran throughout: ${said}\n${JSON.stringify({ before, now: orbitContainer(project.name) })}`
              );
              killed.push(said);
              t.diagnostic(`killed with its container, so not counted: ${said}`);
            }
            assert.equal(volumeKey(project.name), a, after());
          }
          assert.equal(volumeKey(project.name), a, after());
        }
        assert.equal(reached, times, 'the last line ran in the container');
        return seen;
      };

      // (1) The COPY state: Uptime Goblin runs with the key it generated, without the override.
      if (state === 'COPY') {
        const project = composeProject(t, own, image, '', { shippedRestart: true });
        const { directory, name, compose } = project;
        let result = compose(plain, 'up', '--detach', '--no-build', '--pull', 'never');
        assert.equal(result.status, 0, result.stdout + result.stderr);
        await healthy(compose);
        const a = volumeKey(name);
        assert.match(a, /^[0-9a-f]{64}\n$/);
        assert.equal(volumeCheck(project, plain).verdict, 'COPY');
        const pasted = pasteRecipe(t, move, project);
        const said = pasted.stdout + pasted.stderr;
        assert.match(said, /Stopped before the end: run the check/);
        assert.equal(volumeKey(name), a, said);
        assert.deepEqual(keyFiles(directory), {}, 'no key file was made or set aside');
        const seen = await knock(project, a, 3, { killable: false });
        for (const line of seen)
          assert.match(
            line,
            /^1 (.*\n)?goblin-admin key: The key this command is given is \/var\/lib\/uptime-goblin\/secret\.key itself: .* this command must run in its container: the line below\. Nothing was deleted\.\ndocker compose exec uptime-goblin node lib\/cli\/goblin-admin\.mjs key remove-data-copy$/s,
            line
          );
        // Uptime Goblin still runs with that key, and the check says COPY, as before.
        assert.equal(
          compose(plain, 'exec', '-T', 'uptime-goblin', 'node', 'lib/healthcheck.mjs').status,
          0,
          'Uptime Goblin still runs'
        );
        assert.equal(volumeCheck(project, plain).verdict, 'COPY');
      }

      // (2) The MOVE state, beside an orbit_secret_key.unused from an earlier attempt.
      else {
        const project = composeProject(t, own, image, '', { shippedRestart: true });
        const { directory, name, compose } = project;
        let result = compose(plain, 'up', '--detach', '--no-build', '--pull', 'never');
        assert.equal(result.status, 0, result.stdout + result.stderr);
        await healthy(compose);
        const a = volumeKey(name);
        assert.match(a, /^[0-9a-f]{64}\n$/);
        const c = randomBytes(32).toString('hex'),
          d = randomBytes(32).toString('hex');
        writeKeyFile(directory, c);
        fs.appendFileSync(
          path.join(directory, '.env'),
          'COMPOSE_FILE=compose.yaml:compose.secret.yaml:test.yaml\n'
        );
        result = compose([], 'up', '--detach', '--no-build', '--pull', 'never');
        assert.equal(result.status, 0, result.stdout + result.stderr);
        assert.match(await refusing(compose), /^78 ([2-9]|[1-9]\d+)$/);
        fs.writeFileSync(path.join(directory, 'orbit_secret_key.unused'), `${d}\n`, {
          mode: 0o400,
        });
        assert.equal(volumeCheck(project, plain).verdict, 'MOVE');
        const before = keyFiles(directory);
        const pasted = pasteRecipe(t, move, project);
        const said = pasted.stdout + pasted.stderr;
        assert.match(said, /orbit_secret_key\.unused exists: not replaced; choose another name/);
        assert.equal(volumeKey(name), a, said);
        const seen = await knock(project, a, 3, { again: true });
        for (const line of seen)
          assert.match(
            line,
            /^1 (.*\n)?goblin-admin key: The Compose secret \(\/run\/secrets\/orbit_secret_key\) \(fingerprint [0-9a-f]{16}\) does not open this data, so \/var\/lib\/uptime-goblin\/secret\.key may be the only key that does\. .* Nothing was deleted\.$/s,
            line
          );
        assert.deepEqual(keyFiles(directory), before, 'C and the earlier key, byte for byte');
        assert.equal(volumeCheck(project, plain).verdict, 'MOVE');
      }
    }
  );

// Review of 9a7d6e5: data moved from the generated /var/lib/uptime-goblin/secret.key (A) to the Compose
// secret (B) with `key rewrap`, a supported state in which Uptime Goblin warns that the volume's A is not
// used. The check saw only that file and said COPY, and the copy recipe put A over B, after which
// every start refused, key_mismatch. Now the check tries each key on the data and says KEEP, and
// the copy recipe's first command leaves orbit_secret_key as it is; the move recipe's, run there
// by mistake, finds that A does not open the data before it changes anything (A65).
test(
  'Compose: data moved to the Compose secret with key rewrap keeps that secret: the check says KEEP beside the older secret.key, and neither the copy nor the move command replaces orbit_secret_key',
  { skip, timeout: 900000 },
  async t => {
    const { keyFingerprint } = await import('../../lib/keyring.mjs');
    const image = `uptime-goblin:test-keysmoved-${randomBytes(4).toString('hex')}`;
    const own = buildImage(t, image);
    const { directory, name, compose } = composeProject(t, own, image);
    const plain = ['compose.yaml', 'test.yaml'],
      withSecret = ['compose.yaml', 'compose.secret.yaml', 'test.yaml'];
    const healthy = async (files, since) => {
      for (let i = 0; i < 90; i++) {
        if (
          compose(files, 'exec', '-T', 'uptime-goblin', 'node', 'lib/healthcheck.mjs').status === 0
        )
          return compose(files, 'logs', '--no-log-prefix', '--since', since, 'uptime-goblin')
            .stdout;
        await delay(1000);
      }
      assert.fail(compose(files, 'logs', 'uptime-goblin').stdout);
    };
    const now = () => new Date(Date.now() - 1000).toISOString();
    const up = files =>
      compose(files, 'up', '--detach', '--no-build', '--pull', 'never', '--force-recreate');

    // 1.5 without the override: it generates A in the volume and seals the data with it.
    let since = now();
    let result = up(plain);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    let logs = await healthy(plain, since);
    const a =
      /^Encryption key: a new \/var\/lib\/uptime-goblin\/secret\.key \(generated now\) · fingerprint ([0-9a-f]{16})$/m.exec(
        logs
      )?.[1];
    assert.ok(a, logs);
    assert.equal(compose(plain, 'stop').status, 0);
    // The move to B, as docs/installation.md#goblin-admin gives a key change: B is the Compose
    // secret, the old key the previous one, and goblin-admin rewraps with Uptime Goblin stopped.
    const b = randomBytes(32).toString('hex');
    const keyFile = writeKeyFile(directory, b);
    const rewrap = compose(
      withSecret,
      'run',
      '--rm',
      '--no-deps',
      '--env',
      'GOBLIN_SECRET_KEY_PREVIOUS_FILE=/var/lib/uptime-goblin/secret.key',
      'uptime-goblin',
      'node',
      'lib/cli/goblin-admin.mjs',
      'key',
      'rewrap'
    );
    assert.equal(rewrap.status, 0, rewrap.stdout + rewrap.stderr);
    const bPrint = keyFingerprint(Buffer.from(b, 'hex'));
    assert.match(
      rewrap.stdout,
      new RegExp(`^Rewrapped \\d+ data key\\(s\\) with the key ${bPrint};`)
    );
    // The documented check: KEEP, though /var/lib/uptime-goblin/secret.key (A) is still in the volume, which
    // it names as an older key, with the line that deletes it as its third line (A67).
    const olderLine =
      'docker compose exec uptime-goblin node lib/cli/goblin-admin.mjs key remove-data-copy --unused';
    const check = volumeCheck({ directory, name }, plain);
    assert.equal(check.verdict, 'KEEP', check.stdout + check.stderr);
    assert.ok(
      check.stdout.includes(
        `/var/lib/uptime-goblin/secret.key (fingerprint ${a}) is there too: an older key, which Uptime Goblin does not use and which opens none of this data's keys (as after key rewrap).`
      ),
      check.stdout
    );
    assert.equal(check.stdout.split('\n')[2], olderLine, check.stdout);
    // The copy recipe's first command, as docs/installation.md prints it: it keeps B.
    const recipes = keyRecipes();
    const [copyCommand] = recipeCommands(recipes.copy);
    assert.match(copyCommand, /^test -e orbit_secret_key && /);
    const [copied] = runRecipe([copyCommand], { directory, name });
    assert.equal(copied.status, 0, copied.stderr);
    assert.equal(copied.stdout, 'orbit_secret_key exists: not replaced; run the check\n');
    assert.equal(readKeyFile(keyFile), `${b}\n`, 'orbit_secret_key, byte for byte');
    // The move recipe's first command, run here by mistake (A65): it reads A with a container of
    // its own, goblin-admin finds that A does not open the data, and it stops before it sets B
    // aside or changes any file.
    const [moveCommand] = recipeCommands(recipes.move);
    const [notMoved] = runRecipe([moveCommand], { directory, name });
    assert.notEqual(notMoved.status, 0, notMoved.stdout + notMoved.stderr);
    assert.match(notMoved.stdout, /^Stopped before the end: run the check$/m);
    assert.equal(readKeyFile(keyFile), `${b}\n`, 'orbit_secret_key, byte for byte');
    assert.deepEqual(
      fs.readdirSync(directory).filter(file => file.startsWith('orbit_secret_key')),
      ['orbit_secret_key'],
      'nothing set aside, and the file the volume key was read into is gone'
    );
    // Uptime Goblin starts with B and names A as a key it does not use.
    since = now();
    result = up(withSecret);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    logs = await healthy(withSecret, since);
    assert.match(
      logs,
      new RegExp(
        `^Encryption key: the Compose secret \\(/run/secrets/orbit_secret_key\\) · fingerprint ${bPrint}$`,
        'm'
      )
    );
    const warning = `/var/lib/uptime-goblin/secret.key (fingerprint ${a}) is an older key, which Uptime Goblin does not use: the key comes from the Compose secret (/run/secrets/orbit_secret_key) (fingerprint ${bPrint}), as after goblin-admin key rewrap, and every copy of the data directory carries it. This line deletes it only while the key it is given opens every data key and /var/lib/uptime-goblin/secret.key opens none, and otherwise says why and deletes nothing: ${olderLine}`;
    assert.ok(logs.split('\n').includes(warning), logs);
    assert.doesNotMatch(logs, /does not match this data/);
    // A67: the copy recipe's last line keeps A (no copy) and gives the --unused line; the line
    // the warning and the check give, run as printed in Uptime Goblin's container while Uptime Goblin runs,
    // deletes A, and B stays. The next start says nothing about the volume's key.
    const inVolume = () =>
      compose(
        withSecret,
        'exec',
        '-T',
        'uptime-goblin',
        'test',
        '-e',
        '/var/lib/uptime-goblin/secret.key'
      ).status;
    // KEEP runs with COMPOSE_FILE in .env, as the docs set it up (with the test's override).
    fs.appendFileSync(
      path.join(directory, '.env'),
      'COMPOSE_FILE=compose.yaml:compose.secret.yaml:test.yaml\n'
    );
    const [copyLast] = runRecipe([recipeCommands(recipes.copy).at(-1)], { directory, name });
    assert.equal(copyLast.status, 1, copyLast.stdout + copyLast.stderr);
    assert.match(
      copyLast.stderr,
      /it is an older key, which Uptime Goblin does not use\. Delete it with the line below\. Nothing was deleted\.\ndocker compose exec uptime-goblin node lib\/cli\/goblin-admin\.mjs key remove-data-copy --unused$/m
    );
    assert.equal(inVolume(), 0, 'A is still in the volume');
    const [removed] = runRecipe([olderLine], { directory, name });
    assert.equal(removed.status, 0, removed.stdout + removed.stderr);
    assert.equal(
      removed.stdout.trim(),
      `Deleted /var/lib/uptime-goblin/secret.key, an older key (fingerprint ${a}) that opens none of this data's keys: the Compose secret (/run/secrets/orbit_secret_key) (fingerprint ${bPrint}) opens them all. A backup or a snapshot (goblin-admin snapshots) of the data from before the key changed still needs that older key. Keep a backup of the key Uptime Goblin uses apart from the data.`
    );
    assert.equal(inVolume(), 1, 'A is gone from the volume');
    assert.equal(readKeyFile(keyFile), `${b}\n`, 'orbit_secret_key, byte for byte');
    const [again] = runRecipe([olderLine], { directory, name });
    assert.equal(again.status, 1, again.stdout + again.stderr);
    assert.match(
      again.stderr,
      /There is no \/var\/lib\/uptime-goblin\/secret\.key\. Nothing was deleted\.$/m
    );
    since = now();
    result = up(withSecret);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    logs = await healthy(withSecret, since);
    assert.match(
      logs,
      new RegExp(
        `^Encryption key: the Compose secret \\(/run/secrets/orbit_secret_key\\) · fingerprint ${bPrint}$`,
        'm'
      )
    );
    assert.doesNotMatch(logs, /\/var\/lib\/uptime-goblin\/secret\.key/);
    assert.equal(
      volumeCheck({ directory, name }, plain).stdout.split('\n').length,
      3,
      'KEEP and why, no line'
    );
  }
);

test(
  'Compose gives Uptime Goblin 40 s to stop: a stop with a webhook request held ends with exit 0',
  { skip, timeout: 900000 },
  async t => {
    const text = fs.readFileSync(path.join(repository, 'compose.yaml'), 'utf8');
    assert.match(text, /^ {4}stop_grace_period: 40s$/m);
    const image = `uptime-goblin:test-stop-${randomBytes(4).toString('hex')}`;
    const own = buildImage(t, image);
    // A receiver on the project's network that takes the request and never answers.
    const receiver = [
      '  receiver:',
      '    image: node:24-bookworm-slim',
      serviceLimits.trimEnd(),
      '    command:',
      '      - node',
      '      - -e',
      `      - "require('node:http').createServer(req => { console.log('held', req.method, req.headers['x-goblin-delivery']); }).listen(8080)"`,
      '',
    ].join('\n');
    const { compose } = composeProject(
      t,
      own,
      image,
      '    environment:\n      GOBLIN_WEBHOOK_URL: http://receiver:8080/hook\n' + receiver
    );
    const files = ['compose.yaml', 'test.yaml'];
    const up = compose(files, 'up', '--detach', '--no-build', '--pull', 'never');
    assert.equal(up.status, 0, up.stdout + up.stderr);
    let ready = false;
    for (let i = 0; i < 90 && !ready; i++) {
      ready =
        compose(files, 'exec', '-T', 'uptime-goblin', 'node', 'lib/healthcheck.mjs').status === 0;
      if (!ready) await delay(1000);
    }
    assert.ok(ready, compose(files, 'logs').stdout);
    // Inside the container, as a browser on loopback: sign in, alert at the first failure, and
    // add a source that cannot be reached, so an availability alert fires.
    const script = `
      const password = process.env.GOBLIN_PASSWORD, base = 'http://localhost:4317';
      const headers = { Origin: base, 'Sec-Fetch-Site': 'same-origin', 'X-Goblin-Request': '1', 'X-Goblin-Client': 'web/test', 'Content-Type': 'application/json' };
      const login = await fetch(base + '/api/auth/login', { method: 'POST', headers, body: JSON.stringify({ login: 'admin', password }) });
      if (login.status !== 200) throw new Error('sign-in ' + login.status);
      headers.Cookie = login.headers.get('set-cookie').split(';')[0];
      const settings = await fetch(base + '/api/settings', { method: 'PATCH', headers, body: JSON.stringify({ monitoring: { availabilityFailures: 1, availabilitySeconds: 0, timeoutSeconds: 5, retryCount: 0 } }) });
      if (settings.status !== 200) throw new Error('settings ' + settings.status + ' ' + await settings.text());
      const source = await fetch(base + '/api/services', { method: 'POST', headers, body: JSON.stringify({ type: 'http', name: 'Down', apiUrl: 'http://receiver:9/' }) });
      if (source.status !== 201) throw new Error('source ' + source.status + ' ' + await source.text());
    `;
    const setup = compose(
      files,
      'exec',
      '-T',
      'uptime-goblin',
      'node',
      '--input-type=module',
      '-e',
      script
    );
    assert.equal(setup.status, 0, setup.stdout + setup.stderr);
    let held = false;
    for (let i = 0; i < 180 && !held; i++) {
      held = /^held POST d_[a-z2-7]{26}$/m.test(
        compose(files, 'logs', '--no-log-prefix', 'receiver').stdout
      );
      if (!held) await delay(1000);
    }
    assert.ok(held, compose(files, 'logs').stdout);
    const started = Date.now();
    const stopped = compose(files, 'stop', 'uptime-goblin');
    const took = Date.now() - started;
    assert.equal(stopped.status, 0, stopped.stderr);
    const id = compose(files, 'ps', '--all', '--quiet', 'uptime-goblin').stdout.trim();
    assert.equal(docker('inspect', '--format', '{{.State.ExitCode}}', id).stdout.trim(), '0');
    assert.ok(took < 40000, `stopped in ${took} ms`);
  }
);

// What compose.yaml gives the running container (test/packaging.test.mjs checks the file and
// what Compose renders of it): uid 1000 whatever the image says, the limits, open-file and
// core-dump limits and hardening as Docker applied them, no write outside /var/lib/uptime-goblin, a flood of
// processes that stops at pids_limit while Uptime Goblin answers, and limits that what .env holds does
// not lift. The helper containers get limits of their own. The test's own override (test.yaml)
// must set no limit, or this would test that file instead. The override docs/troubleshooting.md
// gives for a host without CPU bandwidth control (cpus: 0, which lifts the CPU time limit, with
// cpuset: '0', which holds Uptime Goblin to CPU 0 and counts as its CPU limit only where Uptime Goblin verifies
// that set at its start) is not started here: no test container may run without a CPU time
// limit, and test/helpers/docker-guard.mjs, which requires a positive cpus and counts no cpuset
// in its place, refuses such a project before Docker sees it. What Compose renders of that
// override is checked in test/packaging.test.mjs ("compose.override.yaml reaches the documented
// -f commands …"); which CPU sets count as Uptime Goblin's CPU limit in test/resource-limits.test.mjs
// ("decision table, CPU: a quota, or a CPU set of its own that applies, is enforced" and "…
// every CPU it names is online …"), with the refusal for want of one there too ("each missing
// limit is named once …"); and the installer's paragraph after such a refusal in
// test/installer/installer.test.mjs ("a start refused for want of a resource limit …").
test(
  'Compose as shipped: uid 1000 within its limits and hardening, writes only to /var/lib/uptime-goblin, serves at its process limit; .env lifts no limit',
  { skip, timeout: 900000 },
  async t => {
    const image = `uptime-goblin:test-limits-${randomBytes(4).toString('hex')}`;
    const own = buildImage(t, image);
    const { directory, compose } = composeProject(t, own, image, '', { shippedLimits: true });
    assert.doesNotMatch(
      fs.readFileSync(path.join(directory, 'test.yaml'), 'utf8'),
      /^\s+(mem_limit|memswap_limit|cpus|pids_limit|mem_reservation|ulimits|deploy):/m,
      "test.yaml sets a limit, so the container would not run with compose.yaml's own"
    );
    const files = ['compose.yaml', 'test.yaml'];
    const start = async () => {
      const up = compose(files, 'up', '--detach', '--no-build', '--pull', 'never');
      assert.equal(up.status, 0, up.stdout + up.stderr);
      let ready = false;
      for (let i = 0; i < 90 && !ready; i++) {
        ready =
          compose(files, 'exec', '-T', 'uptime-goblin', 'node', 'lib/healthcheck.mjs').status === 0;
        if (!ready) await delay(1000);
      }
      assert.ok(ready, compose(files, 'logs').stdout);
      return compose(files, 'ps', '--quiet', 'uptime-goblin').stdout.trim();
    };
    const logs = () => {
      const result = compose(files, 'logs', '--no-log-prefix', 'uptime-goblin');
      return result.stdout + result.stderr;
    };
    const helper = (...args) =>
      docker('run', '--memory', '128m', '--cpus', '1', '--pids-limit', '32', '--rm', ...args);
    const id = await start();
    const inspected = JSON.parse(docker('inspect', id).stdout)[0];
    assert.equal(inspected.Config.User, '1000:1000');
    const host = inspected.HostConfig;
    assert.deepEqual(
      {
        Memory: host.Memory,
        MemorySwap: host.MemorySwap,
        NanoCpus: host.NanoCpus,
        PidsLimit: host.PidsLimit,
        ReadonlyRootfs: host.ReadonlyRootfs,
        CapDrop: host.CapDrop,
        SecurityOpt: host.SecurityOpt,
        Tmpfs: host.Tmpfs,
        LogConfig: host.LogConfig,
      },
      {
        Memory: 2 ** 30,
        MemorySwap: 2 ** 30,
        NanoCpus: 1e9,
        PidsLimit: 256,
        ReadonlyRootfs: true,
        CapDrop: ['ALL'],
        SecurityOpt: ['no-new-privileges:true'],
        Tmpfs: { '/tmp': 'size=16m,mode=1777' },
        LogConfig: { Type: 'json-file', Config: { 'max-file': '2', 'max-size': '5m' } },
      }
    );
    assert.deepEqual(
      (host.Ulimits ?? []).map(({ Name, Soft, Hard }) => `${Name} ${Soft} ${Hard}`).sort(),
      ['core 0 0', 'nofile 4096 4096']
    );
    const inside = compose(
      files,
      'exec',
      '-T',
      'uptime-goblin',
      'sh',
      '-c',
      'id -u; id -g; ulimit -Hn; ulimit -Hc; touch /app/x 2>/dev/null && echo app-writable; touch /var/lib/uptime-goblin/x && rm /var/lib/uptime-goblin/x && echo data-writable'
    );
    assert.equal(inside.stdout, '1000\n1000\n4096\n0\ndata-writable\n', inside.stderr);
    assert.doesNotMatch(logs(), /no limit/);
    // Who owns the code and the data, whatever read_only hides (imageOwnershipCheck).
    const owners = compose(
      files,
      'exec',
      '-T',
      'uptime-goblin',
      'node',
      '--input-type=module',
      '-e',
      imageOwnershipCheck
    );
    assert.equal(owners.status, 0, owners.stderr);

    // A flood of processes stops at pids_limit (no docker exec can start then either); Uptime Goblin
    // keeps answering, from a container on its network, and is not restarted.
    const pid = inspected.State.Pid;
    const flood = docker(
      'exec',
      '--detach',
      id,
      'sh',
      '-c',
      'i=0; while [ $i -lt 400 ]; do sleep 60 & i=$((i+1)); done; wait'
    );
    assert.equal(flood.status, 0, flood.stderr);
    let refused = '',
      last = '';
    for (let i = 0; i < 40 && !refused; i++) {
      const tried = docker('exec', id, 'true');
      const said = tried.stdout + tried.stderr;
      last = `exit ${tried.status}: ${said}`;
      if (tried.status !== 0 && /Resource temporarily unavailable/.test(said)) refused = said;
      else await delay(250);
    }
    assert.ok(
      refused,
      `the flood reached pids_limit: docker exec cannot start a process (last try: ${last}; ${docker('stats', '--no-stream', '--format', '{{.PIDs}}', id).stdout.trim()} processes)`
    );
    const pids = Number(docker('stats', '--no-stream', '--format', '{{.PIDs}}', id).stdout);
    assert.ok(pids > 200 && pids <= 256, `${pids} processes`);
    const answered = helper(
      '--network',
      `container:${id}`,
      'node:24-bookworm-slim',
      'node',
      '-e',
      `fetch('http://127.0.0.1:4317/health',{headers:{Host:'localhost:4317'}}).then(r=>process.exit(r.status===200?0:1),()=>process.exit(2))`
    );
    assert.equal(answered.status, 0, answered.stdout + answered.stderr);
    const released = helper(
      '--network',
      'none',
      '--pid',
      `container:${id}`,
      '--user',
      '1000:1000',
      'node:24-bookworm-slim',
      'sh',
      '-c',
      'for d in /proc/[0-9]*; do [ "$(cat $d/comm 2>/dev/null)" = sleep ] && kill ${d#/proc/}; done; true'
    );
    assert.equal(released.status, 0, released.stderr);
    const after = JSON.parse(docker('inspect', id).stdout)[0];
    assert.deepEqual([after.State.Pid, after.RestartCount], [pid, 0]);

    // What .env holds lifts no limit: compose.yaml reads none from it (this branch once read
    // GOBLIN_PIDS_LIMIT, and Docker took 0 for no limit). Started again with it, Uptime Goblin runs within
    // the same limits and names none as missing.
    fs.appendFileSync(path.join(directory, '.env'), 'GOBLIN_PIDS_LIMIT=0\nGOBLIN_CPUS=0\n');
    const again = await start();
    const againHost = JSON.parse(docker('inspect', again).stdout)[0].HostConfig;
    assert.deepEqual(
      [againHost.NanoCpus, againHost.Memory, againHost.PidsLimit],
      [1e9, 2 ** 30, 256]
    );
    assert.doesNotMatch(logs(), /no limit/);
  }
);

// .env is only interpolation for compose.yaml, which lists the container's environment item by
// item: GOBLIN_SECRET_KEY and GOBLIN_SECRET_KEY_FILE in .env never reach Uptime Goblin under Compose, which
// then generates /var/lib/uptime-goblin/secret.key (review round 3: .env.example offered both lines and said
// GOBLIN_SECRET_KEY "stays visible … in docker inspect", as if it applied there, so a Compose user
// believed the key was outside the volume, and adopting compose.secret.yaml later with that key
// refused, key_mismatch).
// Where a shell starts a comment in `text`: the index of a '#' that begins a word outside
// quotes, or -1. A '#' inside a word (${#x}, $#, a#b) or in quotes is no comment.
function shellCommentAt(text) {
  let quote = null;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quote === "'") {
      if (c === "'") quote = null;
    } else if (c === '\\') i++;
    else if (quote === '"') {
      if (c === '"') quote = null;
    } else if (c === "'" || c === '"') quote = c;
    else if (c === '#' && (i === 0 || /[\s;&|()<>]/.test(text[i - 1]))) return i;
  }
  return -1;
}

// A66: the admin's zsh has interactivecomments off, zsh's default, so a pasted '# …' is no comment:
// "grep 'Encryption key'   # the Compose secret, …" grepped files named '#', 'the', …; the
// chown's "# on a Linux host; skip it …" became more words for sudo; the COMPOSE_FILE line wrote
// its comment into .env and ran the words after ';' as a command; and the last line's "# only
// then" became more words for rm. No shell block in the docs, nor any command line of
// compose.secret.yaml, holds a comment: the explanations are prose, and a line only for some
// hosts (the chown on Linux) is a block of its own.
test('no shell block a person would paste holds a comment, whole-line or trailing: a zsh without interactivecomments runs it as words', () => {
  for (const [text, found] of [
    ['echo a # b', 7],
    ['# a note\necho a', 0],
    ["grep 'Encryption key'   # the secret", 24],
    ['echo a;# b', 7],
    ["echo '#' \"a # b\" ${#x} $# a#b \\# 'it''s'", -1],
    ["test -e f && echo 'f exists: keep it' || { echo; }", -1],
  ])
    assert.equal(shellCommentAt(text), found, text);
  const read = name => fs.readFileSync(path.join(repository, name), 'utf8');
  const documents = [
    ...fs.readdirSync(repository).filter(name => name.endsWith('.md')),
    ...fs
      .readdirSync(path.join(repository, 'docs'))
      .filter(name => name.endsWith('.md'))
      .map(name => `docs/${name}`),
  ];
  let blocks = 0;
  for (const name of documents) {
    const text = read(name);
    for (const match of text.matchAll(
      /^( *)```(?:sh|bash|shell|zsh|console)\n([\s\S]*?)^\1```/gm
    )) {
      blocks++;
      const block = match[2];
      const at = shellCommentAt(block);
      const line =
        text.slice(0, match.index).split('\n').length + block.slice(0, at).split('\n').length;
      assert.equal(
        at,
        -1,
        `${name}:${line}: ${block.split('\n')[block.slice(0, at).split('\n').length - 1]}`
      );
    }
  }
  assert.ok(blocks >= 20, `${blocks} shell blocks`);
  // compose.secret.yaml: each line that starts with '#' and three spaces is a command.
  const commands = read('compose.secret.yaml')
    .split('\n')
    .filter(line => /^# {3}/.test(line))
    .map(line => line.slice(4));
  assert.ok(commands.length >= 20, commands.join('\n'));
  for (const command of commands) assert.equal(shellCommentAt(command), -1, command);
});

// Audit spec D13, D14, PRO-7: Compose passes both audit settings from .env, empty by default
// (Uptime Goblin's own defaults: off and 90 days), and .env.example names them.
test('compose.yaml passes GOBLIN_AUDIT_LOG and GOBLIN_AUDIT_RETENTION_DAYS with empty defaults, and .env.example names both', () => {
  for (const name of ['GOBLIN_AUDIT_LOG', 'GOBLIN_AUDIT_RETENTION_DAYS'])
    assert.equal(composeDefault(name), '', name);
  const example = fs.readFileSync(path.join(repository, '.env.example'), 'utf8');
  for (const name of ['GOBLIN_AUDIT_LOG', 'GOBLIN_AUDIT_RETENTION_DAYS'])
    assert.match(example, new RegExp(`^${exampleName(name)}=$`, 'm'), name);
  assert.match(example, /off \(the default\), stdout, or stdout-full/);
  assert.match(example, /30 to 3650 \(90 when empty\)/);
});

// B12 (1.5 release blockers), with OD1 kept: under Compose plain-HTTP sign-in is on while
// GOBLIN_INSECURE_HTTP_SESSIONS is unset (.env.example ships the line commented out) and the port
// is published on the Docker host's loopback, and a value .env gives counts as it does for npm
// start, so an empty one is off. `${…:-1}` made an empty value 1 as well: blanking the line, as
// the other lines of .env.example teach for "off", kept plain-HTTP sign-in, and the password
// crossing the network with it, on a LAN address. And the banners' way back must work under
// Compose too: "remove GOBLIN_INSECURE_HTTP_SESSIONS" changed nothing there. The maintainer's decision of
// 2026-11-12: an upgrade never turns plain-HTTP sign-in on silently, so the unset default is
// compose-default, which is on only for a loopback GOBLIN_BIND_ADDRESS, off on another address
// behind a proxy GOBLIN_TRUST_PROXY names, and otherwise a refusal to start.
test('GOBLIN_INSECURE_HTTP_SESSIONS under Compose: compose-default only while unset (on for a loopback publish, off behind a trusted proxy, otherwise a refusal); empty or 0 is off, and the banners’ way back turns it off', async t => {
  const read = name => fs.readFileSync(path.join(repository, name), 'utf8');
  assert.equal(composeDefault('GOBLIN_INSECURE_HTTP_SESSIONS'), 'compose-default');
  assert.match(
    read('compose.yaml'),
    /^ {6}GOBLIN_INSECURE_HTTP_SESSIONS: \$\{GOBLIN_INSECURE_HTTP_SESSIONS-\$\{ORBIT_INSECURE_HTTP_SESSIONS-compose-default\}\}$/m,
    'an empty value stays empty (no colon)'
  );
  assert.match(
    read('compose.yaml'),
    /^ {6}GOBLIN_PUBLISHED_ADDRESS: \$\{GOBLIN_BIND_ADDRESS:-\$\{ORBIT_BIND_ADDRESS:-127\.0\.0\.1\}\}$/m,
    'Uptime Goblin learns where the port is published'
  );
  // public/modules/identity/session.js: the plain-HTTP banners (bannerTexts).
  const banners = [
    ...read('public/modules/identity/session.js').matchAll(
      /^ {2}(insecure|insecureBehindProxy):\s*'([^']*)',$/gm
    ),
  ].map(match => match[2]);
  assert.equal(banners.length, 2, 'both plain-HTTP banners found');
  const ways = banners.map(text => {
    assert.doesNotMatch(text, /remove GOBLIN_INSECURE_HTTP_SESSIONS/i, text);
    assert.match(text, /\(Docker: in \.env, then docker compose up -d\)/, text);
    const way = /\bset (GOBLIN_INSECURE_HTTP_SESSIONS=[^\s,]+)/.exec(text);
    assert.ok(way, text);
    return way[1];
  });
  // What Uptime Goblin makes of the container's environment: true, false or 'refused' (exit 78).
  const plainHttp = async env => {
    if (insecureHttpSessionsSetting(env).refusal) return 'refused';
    return createFeatures({ env, release: '1.5.0' }).enabled('insecureHttpSessions');
  };

  // What Compose passes for each .env, where the Compose CLI is present (no daemon needed), and
  // what Uptime Goblin makes of it.
  if (spawnSync('docker', ['compose', 'version'], { encoding: 'utf8' }).status !== 0) {
    if (required('docker')) assert.fail('docker compose is not available');
    return t.skip('docker compose is not installed');
  }
  const directory = temporary(t, 'orbit-compose-insecure-');
  fs.copyFileSync(path.join(repository, 'compose.yaml'), path.join(directory, 'compose.yaml'));
  const shipped = read('.env.example').replace(
    /^(?:GOBLIN|ORBIT)_PASSWORD=(?:'')?$/m,
    "GOBLIN_PASSWORD='compose-insecure-test-1'"
  );
  const commented = /^# (?:GOBLIN|ORBIT)_INSECURE_HTTP_SESSIONS=1$/m;
  const bind = /^(?:GOBLIN|ORBIT)_BIND_ADDRESS=127\.0\.0\.1$/m;
  const trust = /^(?:GOBLIN|ORBIT)_TRUST_PROXY=$/m;
  for (const line of [commented, bind, trust]) assert.match(shipped, line);
  const lan = shipped.replace(bind, 'GOBLIN_BIND_ADDRESS=192.0.2.5');
  // Compose reads the shell's environment before .env: this one sets none of them.
  const environment = { ...process.env };
  for (const name of ['INSECURE_HTTP_SESSIONS', 'BIND_ADDRESS', 'TRUST_PROXY'])
    for (const prefix of ['GOBLIN_', 'ORBIT_']) delete environment[prefix + name];
  const passed = text => {
    fs.writeFileSync(path.join(directory, '.env'), text, { mode: 0o600 });
    const result = spawnSync('docker', ['compose', 'config', '--format', 'json'], {
      cwd: directory,
      encoding: 'utf8',
      env: environment,
    });
    assert.equal(result.status, 0, result.stderr);
    const service = JSON.parse(result.stdout).services['uptime-goblin'].environment;
    assert.equal(service.GOBLIN_PASSWORD, 'compose-insecure-test-1', 'the .env file was read');
    return service;
  };
  for (const [what, text, value, on] of [
    ['.env.example as shipped (commented out)', shipped, 'compose-default', true],
    ['no line', shipped.replace(commented, ''), 'compose-default', true],
    ['set to 1', shipped.replace(commented, 'GOBLIN_INSECURE_HTTP_SESSIONS=1'), '1', true],
    ['empty', shipped.replace(commented, 'GOBLIN_INSECURE_HTTP_SESSIONS='), '', false],
    ['set to 0', shipped.replace(commented, 'GOBLIN_INSECURE_HTTP_SESSIONS=0'), '0', false],
    ...ways.map(way => [`the banner’s ${way}`, shipped.replace(commented, way), '0', false]),
    // Published on a LAN address: never on by itself.
    ['a LAN address, no line', lan, 'compose-default', 'refused'],
    [
      'a LAN address behind a trusted proxy',
      lan.replace(trust, 'GOBLIN_TRUST_PROXY=192.0.2.1'),
      'compose-default',
      false,
    ],
    [
      'a LAN address, set to 1',
      lan.replace(commented, 'GOBLIN_INSECURE_HTTP_SESSIONS=1'),
      '1',
      true,
    ],
    [
      'a LAN address, set to 0',
      lan.replace(commented, 'GOBLIN_INSECURE_HTTP_SESSIONS=0'),
      '0',
      false,
    ],
  ]) {
    const service = passed(text);
    assert.equal(service.GOBLIN_INSECURE_HTTP_SESSIONS, value, what);
    assert.equal(await plainHttp(service), on, what);
  }
  // npm start reads an empty value the same way, an unset one as off, and compose-default
  // without GOBLIN_PUBLISHED_ADDRESS as a value that is neither yes nor no (off).
  assert.equal(await plainHttp({ GOBLIN_INSECURE_HTTP_SESSIONS: '' }), false);
  assert.equal(await plainHttp({}), false);
  assert.equal(await plainHttp({ GOBLIN_INSECURE_HTTP_SESSIONS: 'compose-default' }), false);
});

test('the key lines of .env.example are for npm start: compose.yaml passes neither into the container, and the docs say so', t => {
  const read = name => fs.readFileSync(path.join(repository, name), 'utf8');
  const example = read('.env.example');
  const lines = example.split('\n');
  const keyLine = lines.findIndex(line =>
    new RegExp(`^# ${exampleName('GOBLIN_SECRET_KEY_FILE')}=`).test(line)
  );
  assert.ok(keyLine > 0, example);
  const before = lines.slice(Math.max(0, keyLine - 4), keyLine).join('\n');
  assert.match(before, /for npm start only: Docker Compose ignores them/);
  assert.match(before, /use compose\.secret\.yaml there/);
  assert.doesNotMatch(example, /docker inspect/);
  const configuration = read('docs/configuration.md');
  for (const name of ['GOBLIN_SECRET_KEY_FILE', 'GOBLIN_SECRET_KEY']) {
    const row = configuration.split('\n').find(line => line.startsWith(`| \`${name}\` |`));
    assert.ok(row, name);
    assert.match(
      row,
      /Docker Compose (ignores both variables|does not pass it into the container)/
    );
    assert.match(row, /compose\.secret\.yaml/);
  }
  assert.match(
    configuration.split('\n').find(line => line.startsWith('| `GOBLIN_SECRET_KEY` |')),
    /`docker run --env`/
  );

  // What Compose does with them, where the Compose CLI is present (no daemon needed).
  if (spawnSync('docker', ['compose', 'version'], { encoding: 'utf8' }).status !== 0) {
    if (required('docker')) assert.fail('docker compose is not available');
    return t.skip('docker compose is not installed');
  }
  const directory = temporary(t, 'orbit-compose-env-');
  fs.copyFileSync(path.join(repository, 'compose.yaml'), path.join(directory, 'compose.yaml'));
  fs.writeFileSync(
    path.join(directory, '.env'),
    `GOBLIN_PASSWORD='compose-env-test-1'\nGOBLIN_SECRET_KEY=${randomBytes(32).toString('hex')}\nGOBLIN_SECRET_KEY_FILE=/home/you/.orbit-secret.key\n`,
    { mode: 0o600 }
  );
  const result = spawnSync('docker', ['compose', 'config', '--format', 'json'], {
    cwd: directory,
    encoding: 'utf8',
  });
  assert.equal(result.status, 0, result.stderr);
  const environment = JSON.parse(result.stdout).services['uptime-goblin'].environment;
  assert.equal(environment.GOBLIN_PASSWORD, 'compose-env-test-1', 'the .env file was read');
  assert.ok(!Object.hasOwn(environment, 'GOBLIN_SECRET_KEY'), JSON.stringify(environment));
  assert.ok(!Object.hasOwn(environment, 'GOBLIN_SECRET_KEY_FILE'), JSON.stringify(environment));
});

// The first commands of the copy and move recipes, as docs/installation.md and compose.secret.yaml
// print them (A65). Both read /var/lib/uptime-goblin/secret.key with a container of their own into a new
// file (mktemp: 0600, never an existing file; >| also under noclobber), not with docker compose
// cp, which reads through Uptime Goblin's container and failed once a refused container's
// orbit_secret_key was gone; goblin-admin key status, given that file's bytes, checks that they
// are a key that opens the data; only then does a file change. The move command sets the key
// that does not open the data aside (a copy, then the file removed, as A60 found on OrbStack)
// and puts the volume's key in a new orbit_secret_key, never a renamed one.
const readVolumeKey = [
  '  volume_key=$(mktemp orbit_secret_key.XXXXXX) &&',
  '  docker compose -f compose.yaml run --rm --no-deps -T uptime-goblin cat /var/lib/uptime-goblin/secret.key >| "$volume_key" &&',
  '  test -s "$volume_key" &&',
  `  docker compose -f compose.yaml run --rm --no-deps -T uptime-goblin sh -c 'umask 077 && cat > /tmp/key && GOBLIN_SECRET_KEY_FILE=/tmp/key node lib/cli/goblin-admin.mjs key status > /dev/null' < "$volume_key" &&`,
];
const placeVolumeKey = [
  '  cp "$volume_key" orbit_secret_key && chmod 0400 orbit_secret_key && rm -f "$volume_key" ||',
  `  { rm -f "$volume_key"; echo 'Stopped before the end: run the check'; false; }`,
  '}',
];
const documentedCopy = [
  "test -e orbit_secret_key && echo 'orbit_secret_key exists: not replaced; run the check' || {",
  ...readVolumeKey,
  ...placeVolumeKey,
].join('\n');
const documentedMove = [
  "test -e orbit_secret_key.unused && echo 'orbit_secret_key.unused exists: not replaced; choose another name' || {",
  ...readVolumeKey,
  '  cp -p orbit_secret_key orbit_secret_key.unused && rm -f orbit_secret_key &&',
  ...placeVolumeKey,
].join('\n');
// A command as compose.secret.yaml prints it: each line as a comment.
const asComment = command =>
  command
    .split('\n')
    .map(line => `#   ${line}\n`)
    .join('');

// Once compose.secret.yaml holds the key and the volume's copy is deleted, every docker compose
// command must include the override: one with compose.yaml alone (an update, a rollback, a
// settings change) recreates the container without the key, and every start refuses. The docs
// therefore name it once in .env (COMPOSE_FILE), before the step that deletes the copy, and the
// lost-key reset under Compose passes it. `docker compose config` (no daemon needed) shows what
// the documented .env line does.
test('the docs name compose.secret.yaml in .env (COMPOSE_FILE) before the volume copy goes, so later docker compose commands keep the key', async t => {
  const read = name => fs.readFileSync(path.join(repository, name), 'utf8');
  const line = "echo 'COMPOSE_FILE=compose.yaml:compose.secret.yaml' >> .env";
  const installation = read('docs/installation.md');
  const { section, check, older, keepText, fresh, copy, move, recipes, texts } = keyRecipes();
  const blocks = [fresh, copy, move];
  // A66: the last line of the copy and MOVE recipes deletes the volume's copy with goblin-admin
  // key remove-data-copy, never with rm: pasted whole, a recipe runs every line, and an rm after
  // a step that had stopped deleted the only key that opened the data.
  const removeCopy =
    'docker compose exec uptime-goblin node lib/cli/goblin-admin.mjs key remove-data-copy';
  for (const block of blocks) {
    const named = block.indexOf(line);
    assert.ok(named >= 0, block);
    for (const later of ['docker compose up -d', removeCopy])
      if (block.includes(later)) assert.ok(named < block.indexOf(later), `${later} after ${line}`);
  }
  assert.equal(recipeCommands(copy).at(-1), removeCopy, copy);
  assert.equal(recipeCommands(move).at(-1), removeCopy, move);
  assert.doesNotMatch(fresh, /secret\.key/, 'the new-key recipe deletes nothing');
  for (const name of ['docs/installation.md', 'compose.secret.yaml', 'docs/troubleshooting.md'])
    assert.doesNotMatch(read(name), /rm \/var\/lib\/uptime-goblin\/secret\.key/, name);
  assert.match(section, /every later `docker compose` command includes it/);
  // Data from 1.4.x has no key (1.4.x never writes secret.key): its upgrade takes the new-key
  // recipe, and the copy recipe, whose first command fails on such data, is for data 1.5 has
  // already run on (review round 2: the upgrade notes sent 1.4.x installs to the copy). What the
  // volume holds decides, not the release running (review round 3: a volume 1.5 ran on without
  // the override runs 1.4.3 again after a rollback, and keeps its secret.key; the "upgrade from
  // 1.4.x" recipe then refused, key_mismatch, for good), so a check that prints COPY or NEW
  // comes first, the same in the docs and in compose.secret.yaml.
  // Review round 4: a volume sealed with compose.secret.yaml's key has no secret.key either, so
  // the check said NEW there, and the new-key line replaced that key (as root): every start then
  // exited 78 key_mismatch, the sealing key gone. Now such a volume (control.sqlite and no
  // secret.key) says KEEP, and the new-key line never replaces an existing file.
  // Review of 9a7d6e5: which files exist says nothing about the data (after a move to the secret
  // with key rewrap, /var/lib/uptime-goblin/secret.key is the old key), so the check said COPY there and the
  // copy recipe replaced the working orbit_secret_key. The check is now goblin-admin key
  // compose-check, which tries each key on the data (with compose.secret.yaml, to mount it, when
  // orbit_secret_key exists), and the copy line never replaces an existing file.
  const checkLine =
    "docker compose -f compose.yaml $(test -e orbit_secret_key && echo '-f compose.secret.yaml') run --rm --no-deps uptime-goblin node lib/cli/goblin-admin.mjs key compose-check";
  assert.equal(check.trim(), checkLine);
  assert.match(
    section,
    /The first recipe is for a new install, or a volume only 1\.4\.x has run on \(`NEW`: its data has no key yet\)/
  );
  const newKey =
    "test -e orbit_secret_key && echo 'orbit_secret_key exists: keep it' || { (umask 077 && openssl rand -hex 32 > orbit_secret_key) && chmod 0400 orbit_secret_key; }";
  assert.equal(recipeCommands(fresh)[0], newKey, fresh);
  // A65: the copy and move recipes read the volume's key with a container of their own, check
  // it, and only then change a file; MOVE is a recipe of its own, which starts Uptime Goblin with
  // --force-recreate as its own line (A60 said "in place of its docker compose up -d", and
  // compose.secret.yaml "starting with docker compose up -d --force-recreate").
  assert.equal(recipeCommands(copy)[0], documentedCopy, copy);
  assert.equal(recipeCommands(move)[0], documentedMove, move);
  assert.ok(recipeCommands(copy).includes('docker compose up -d'), copy);
  assert.ok(recipeCommands(move).includes('docker compose up -d --force-recreate'), move);
  for (const block of blocks) assert.doesNotMatch(block, /docker compose cp /, block);
  // Review round 4: both recipes started Uptime Goblin before the chown a Linux host needs (it came in
  // the paragraph after them), so as printed every start exited 78 key_file_unreadable (EACCES).
  // Each recipe now gives the file to uid 1000 itself, before it starts Uptime Goblin. A66: in a block of
  // its own, introduced by "On a Linux host:", with no trailing comment (a zsh without
  // interactivecomments ran "# on a Linux host; skip it …" as more words of sudo).
  const chown = 'sudo chown 1000 orbit_secret_key';
  for (const [name, three] of Object.entries(recipes)) {
    assert.equal(three.length, 3, `${name}: its command, the chown, its start`);
    assert.equal(three[1], `${chown}\n`, name);
    assert.match(
      three[2],
      /^echo 'COMPOSE_FILE=compose\.yaml:compose\.secret\.yaml' >> \.env\ndocker compose up -d/,
      name
    );
    const commands = recipeCommands(three.join(''));
    const start = commands.findIndex(command => /^docker compose up -d( |$)/.test(command));
    assert.ok(
      commands.indexOf(chown) > 0 && commands.indexOf(chown) < start,
      `${name}: chown first`
    );
  }
  for (const text of Object.values(texts))
    assert.ok(
      text.includes('On a Linux host:\n\n```sh\nsudo chown 1000 orbit_secret_key\n```'),
      text
    );
  assert.match(
    section,
    /On a Mac, skip the `chown` block: OrbStack, where these recipes were measured, lets the container's user read the file as it is \(Docker Desktop was not tested\)\./
  );
  assert.match(section, /Paste them one at a time and read what each prints before the next\./);
  assert.match(
    section,
    /The check runs `goblin-admin key compose-check` in the 1\.5 image \(build it first, with `docker compose build --pull`\), with `compose\.secret\.yaml` when `orbit_secret_key` exists/
  );
  const choice = section.slice(
    section.indexOf(check) + check.length,
    section.indexOf(recipes.fresh[0])
  );
  assert.match(
    choice,
    /`COPY` means there is no `orbit_secret_key` and the volume's `\/var\/lib\/uptime-goblin\/secret\.key` opens the data: 1\.5 has run on this volume without the override, also when 1\.4\.x runs on it again after a \[rollback\]/
  );
  // A67: "keep that file" (orbit_secret_key, or the older /var/lib/uptime-goblin/secret.key?) is gone: KEEP
  // keeps orbit_secret_key, and an older key in the volume goes with the line that checks it is
  // one, which the check prints as its third line and the start warning gives too.
  assert.match(
    choice,
    /`KEEP` means your `orbit_secret_key` opens the data: 1\.5 has run on it with `compose\.secret\.yaml` .* take none of the recipes: keep `orbit_secret_key` and `COMPOSE_FILE` \(a new key cannot open that data: exit status 78\), also when the volume still holds a `secret\.key` \(below\)\./
  );
  const { removeDataKeyLine } = await import('../../lib/keyring.mjs');
  const olderLine = removeDataKeyLine({ compose: true, unused: true });
  assert.equal(
    olderLine,
    'docker compose exec uptime-goblin node lib/cli/goblin-admin.mjs key remove-data-copy --unused'
  );
  assert.equal(older, `${olderLine}\n`, 'the KEEP block is that line alone');
  assert.match(
    keepText,
    /^With `KEEP`, a `\/var\/lib\/uptime-goblin\/secret\.key` still in the volume is not the key Uptime Goblin uses, and every copy of the volume carries it\. The check's second line says what it is, and its third line is the command that deletes it, in Uptime Goblin's container, once Uptime Goblin runs with `orbit_secret_key`/
  );
  assert.match(
    keepText,
    /A copy of your key, left by a copy recipe that stopped before its last line, goes with that last line, `key remove-data-copy`\. An older key, one that opens none of the data's keys, as after `key rewrap` .* goes with this line, which deletes it only while Uptime Goblin's key opens every data key and that file opens none, and otherwise says why, deletes nothing and exits with status 1/
  );
  assert.match(
    section,
    /after `KEEP` beside a `\/var\/lib\/uptime-goblin\/secret\.key` that Uptime Goblin does not use, a third line is the command that deletes it/
  );
  for (const name of [
    'docs/installation.md',
    'compose.secret.yaml',
    'docs/troubleshooting.md',
    'CHANGELOG.md',
  ])
    assert.doesNotMatch(read(name), /keep that file/, name);
  // The goblin-admin section has both lines, natively and under Compose, as goblin-admin builds them.
  const adminSection = installation.slice(installation.indexOf('### goblin-admin'));
  for (const unused of [false, true]) {
    for (const lineText of [
      removeDataKeyLine({ compose: true, unused }),
      removeDataKeyLine({ unused }),
    ])
      assert.ok(adminSection.includes(`\n\`\`\`sh\n${lineText}\n\`\`\`\n`), lineText);
  }
  assert.match(
    installation,
    /A `secret\.key` left in the data directory beside another source is reported at every start, with the line that deletes it, which runs beside the running Uptime Goblin: `goblin-admin key remove-data-copy` for a copy of the key Uptime Goblin uses, and `goblin-admin key remove-data-copy --unused` for an older key/
  );
  assert.doesNotMatch(
    installation,
    /then delete the one in `\/var\/lib\/uptime-goblin`, as it says/
  );
  // The native installer's message gives the native line too (installer.test.mjs runs it).
  const installer = read('deploy/install.sh');
  assert.ok(
    installer.includes(
      `with this line, which deletes it only while /etc/uptime-goblin/secret.key holds the same key and opens the data: ${removeDataKeyLine({})}');`
    ),
    'install.sh'
  );
  assert.doesNotMatch(installer, /then delete \/var\/lib\/uptime-goblin\/secret\.key/);
  assert.match(
    read('CHANGELOG.md'),
    /`goblin-admin key remove-data-copy --unused` for an older key, which Uptime Goblin does not use, as after `key rewrap`: it deletes the file only while the key Uptime Goblin is given opens every data key and that file opens none/
  );
  assert.match(
    choice,
    /`MOVE` means your `orbit_secret_key` does not open the data and `\/var\/lib\/uptime-goblin\/secret\.key` does, .* take the third recipe, which puts the volume's key in a new `orbit_secret_key` and keeps yours as `orbit_secret_key\.unused`, then starts Uptime Goblin in a new container\./
  );
  assert.doesNotMatch(section, /in place of its `docker compose up -d`/);
  assert.match(choice, /`RESTORE` means no key there opens the data: make no key and copy none;/);
  assert.doesNotMatch(choice, /needs neither: keep its `orbit_secret_key`/);
  const intro = texts.copy.slice(0, texts.copy.indexOf('```sh'));
  assert.match(intro, /1\.4\.x never writes `secret\.key`/);
  assert.match(
    intro,
    /A volume that 1\.5 has already run on without the override \(`COPY`\) .* \(a new key cannot open that data/
  );
  assert.match(
    intro,
    /It reads the volume's key with a container of its own \(`docker compose run`, in the 1\.5 image like the check\) into a new file, not with `docker compose cp`, which reads through Uptime Goblin's container and fails .* `goblin-admin key status` then checks that the file holds a key that opens the data, and only then is it copied to `orbit_secret_key`\./
  );
  const moveIntro = texts.move;
  assert.match(
    moveIntro,
    /The third recipe is for `MOVE`\. Uptime Goblin refuses in a container that mounts your `orbit_secret_key`, so its first command reads the volume's key and checks it as the second recipe does, before it changes any file\. Only then does it set your file aside, kept as `orbit_secret_key\.unused` .* and copy the volume's key to a new `orbit_secret_key`\.\n[\s\S]*\nUptime Goblin then starts in a new container, with `docker compose up -d --force-recreate` after those lines/
  );
  assert.doesNotMatch(installation, /An existing install keeps the key it already has/);
  assert.doesNotMatch(
    installation,
    /use `compose\.secret\.yaml` with a new key \(1\.4\.x data has none yet\)/
  );
  assert.match(
    installation,
    /Its key comes from what the volume holds, not from the release running/
  );
  assert.match(
    installation,
    /also when going forward again after a rollback \(`KEEP`: make no new key\)/
  );
  assert.match(
    installation,
    /\[the check\]\(#encryption-key\) then prints `KEEP`, and no new key is needed/
  );
  assert.match(
    installation,
    /A volume that 1\.5 ran on without `compose\.secret\.yaml` keeps its `\/var\/lib\/uptime-goblin\/secret\.key` under 1\.4\.3: to adopt the override later/
  );
  const changelog = read('CHANGELOG.md');
  assert.doesNotMatch(
    changelog,
    /an existing install copies its `\/var\/lib\/uptime-goblin\/secret\.key`/
  );
  assert.match(
    changelog,
    /data from 1\.4\.x has no key yet, so the upgrade from 1\.4\.x makes a new one/
  );
  assert.match(changelog, /what the volume holds decides its key, not the release running/);
  assert.match(changelog, /`goblin-admin key compose-check` in the 1\.5 image and tries each key/);
  assert.match(
    changelog,
    /the copy recipe's first line never replaces an existing `orbit_secret_key` either/
  );
  assert.match(
    changelog,
    /the copy and `MOVE` recipes read `\/var\/lib\/uptime-goblin\/secret\.key` with a container of their own and have `goblin-admin` check that it opens the data before they change a file/
  );
  const troubleshooting = read('docs/troubleshooting.md');
  assert.match(
    troubleshooting,
    /under Compose the check then prints `MOVE`, so take \[the `MOVE` recipe\]\(installation\.md#encryption-key\), which reads that key with a container of its own \(not `docker compose cp`, .*\) and checks that it opens the data before it changes any file, then sets the `orbit_secret_key` that does not open it aside, as `orbit_secret_key\.unused`, puts that key in a new `orbit_secret_key` and starts Uptime Goblin in a new container/
  );
  assert.doesNotMatch(troubleshooting, /take \[the copy recipe\]/);
  const override = read('compose.secret.yaml');
  assert.ok(override.includes(`#   ${checkLine}\n`), override);
  assert.match(
    override,
    /^# KEEP: orbit_secret_key opens the data: 1\.5 has run on this volume WITH this override/m
  );
  // A67: KEEP keeps orbit_secret_key, and gives the line for an older key in the volume.
  assert.match(override, /^# Make no key and copy none: keep orbit_secret_key and COMPOSE_FILE /m);
  const keepNote = override.slice(override.indexOf('# KEEP:'), override.indexOf('# COPY:'));
  assert.ok(keepNote.endsWith(asComment(olderLine)), keepNote);
  assert.match(keepNote, /the check's third line is the command that deletes it/);
  assert.match(
    override,
    /^# COPY: no orbit_secret_key, and \/var\/lib\/uptime-goblin\/secret\.key opens the data/m
  );
  assert.match(
    override,
    /^# MOVE: orbit_secret_key does not open the data, and \/var\/lib\/uptime-goblin\/secret\.key does/m
  );
  assert.match(
    override,
    /^# MOVE: .*\n# for a volume that needed COPY\)\. Take the last recipe below\.$/m
  );
  // The same commands as the docs (the stand-in test below runs them); MOVE sets the key aside
  // without replacing anything, and not by a rename (measured on OrbStack). Its start is its own
  // step after the key is in place, never something to run first (A60: "starting with docker
  // compose up -d --force-recreate").
  assert.doesNotMatch(override, /starting with docker compose up -d --force-recreate/);
  assert.match(
    override,
    /^# Then, with COMPOSE_FILE set as above .*\n# a new container, after those lines: up -d --force-recreate, /m
  );
  // A66: every recipe's commands as compose.secret.yaml prints them, in the docs' order, each
  // line a command of its own ('#' and three spaces), the Linux-only chown after "# On a Linux
  // host only:", and no line of notes indented like a command.
  let from = 0;
  for (const [name, three] of Object.entries(recipes))
    for (const [i, block] of three.entries()) {
      const at = override.indexOf(
        (i === 1 ? '# On a Linux host only:\n' : '') + asComment(block.replace(/\n$/, '')),
        from
      );
      assert.ok(at >= from, `compose.secret.yaml: the ${name} recipe's block ${i + 1}\n${block}`);
      from = at + 1;
    }
  for (const note of override.split('\n').filter(line => /^# {3}/.test(line)))
    assert.match(
      note,
      /^# {3}(test -e |docker compose |sudo chown 1000 orbit_secret_key$|echo 'COMPOSE_FILE=|\(umask 077 && f=~\/uptime-goblin-journal\.txt |\s{2}|\}$)/,
      'a command, not a note'
    );
  assert.match(
    override,
    /On a Mac,\n# OrbStack \(where these recipes were measured\) lets the container's user read the file as it\n# is, so skip the chown there; Docker Desktop was not tested\./
  );
  for (const line of override.split('\n').filter(line => line.startsWith('#   ')))
    assert.doesNotMatch(line, /docker compose cp /, line);
  assert.match(override, /^# RESTORE: no key here opens the data\. Make no key and copy none/m);
  assert.ok(override.includes(`#   ${newKey}\n`), override);
  assert.ok(override.includes(asComment(documentedCopy)), override);
  assert.ok(override.includes(asComment(documentedMove)), override);
  // Each recipe there gives the file to uid 1000 before its start.
  const overrideChown = `# On a Linux host only:\n#   ${chown}\n`;
  const firstChown = override.indexOf(overrideChown),
    copyLine = override.indexOf(asComment(documentedCopy)),
    moveLine = override.indexOf(asComment(documentedMove));
  assert.ok(override.indexOf(newKey) < firstChown && firstChown < copyLine, override);
  assert.ok(override.indexOf(overrideChown, copyLine) > copyLine, override);
  assert.ok(override.indexOf(overrideChown, moveLine) > moveLine, override);
  assert.ok(
    override.indexOf(overrideChown, moveLine) <
      override.indexOf('docker compose up -d --force-recreate', moveLine),
    override
  );
  assert.match(
    override,
    /^# A NEW install, or a volume ONLY 1\.4\.x HAS RUN ON \(NEW: 1\.4\.x data has no key/m
  );
  assert.match(override, /^# A volume 1\.5 HAS RUN ON without this override \(COPY\)/m);
  assert.match(override, /^# A volume that needed COPY and was GIVEN A NEW KEY \(MOVE\)/m);
  // The files the recipes make beside orbit_secret_key hold keys too: git ignores them.
  assert.match(read('.gitignore'), /^orbit_secret_key\.\*$/m);
  assert.ok(override.indexOf(checkLine) < override.indexOf('openssl rand'), override);
  assert.doesNotMatch(override, /An EXISTING install keeps the key it already has/);
  assert.doesNotMatch(override, /or the UPGRADE FROM 1\.4\.x/);
  assert.ok(
    override.indexOf("echo 'COMPOSE_FILE=compose.yaml:compose.secret.yaml' >> .env") >= 0 &&
      override.indexOf('COMPOSE_FILE') < override.indexOf('key remove-data-copy'),
    override
  );
  assert.match(read('.env.example'), /^# COMPOSE_FILE=compose\.yaml:compose\.secret\.yaml$/m);
  // The new-key line as printed: an existing file is kept, byte for byte; none, a new key.
  {
    const keys = temporary(t, 'orbit-new-key-');
    fs.writeFileSync(path.join(keys, 'orbit_secret_key'), 'the key that sealed the data\n', {
      mode: 0o400,
    });
    const kept = spawnSync('sh', ['-c', newKey], { cwd: keys, encoding: 'utf8' });
    assert.equal(kept.status, 0, kept.stderr);
    assert.equal(kept.stdout, 'orbit_secret_key exists: keep it\n');
    assert.equal(
      fs.readFileSync(path.join(keys, 'orbit_secret_key'), 'utf8'),
      'the key that sealed the data\n'
    );
    if (spawnSync('openssl', ['version'], { encoding: 'utf8' }).status === 0) {
      fs.rmSync(path.join(keys, 'orbit_secret_key'));
      const made = spawnSync('sh', ['-c', newKey], { cwd: keys, encoding: 'utf8' });
      assert.equal(made.status, 0, made.stderr);
      assert.match(
        fs.readFileSync(path.join(keys, 'orbit_secret_key'), 'utf8'),
        /^[0-9a-f]{64}\n$/
      );
      assert.equal(fs.statSync(path.join(keys, 'orbit_secret_key')).mode & 0o777, 0o400);
    }
  }
  // The Compose reset of a lost key passes the override (or, without one, --use-data-dir-key).
  const resets = [
    ...read('docs/troubleshooting.md').matchAll(/`(docker compose [^`]*key reset[^`]*)`/g),
  ].map(match => match[1]);
  assert.ok(resets.length >= 2, resets.join('\n'));
  for (const reset of resets)
    assert.match(reset, /-f compose\.yaml -f compose\.secret\.yaml run|--use-data-dir-key$/);

  // What the documented .env line does, where the Compose CLI is present.
  if (spawnSync('docker', ['compose', 'version'], { encoding: 'utf8' }).status !== 0) {
    if (required('docker')) assert.fail('docker compose is not available');
    return t.skip('docker compose is not installed');
  }
  const directory = temporary(t, 'orbit-compose-files-');
  for (const file of ['compose.yaml', 'compose.secret.yaml'])
    fs.copyFileSync(path.join(repository, file), path.join(directory, file));
  fs.writeFileSync(path.join(directory, 'orbit_secret_key'), '', { mode: 0o400 });
  fs.writeFileSync(path.join(directory, '.env'), 'GOBLIN_PASSWORD=compose-files-test\n');
  const secrets = () => {
    const result = spawnSync('docker', ['compose', 'config', '--format', 'json'], {
      cwd: directory,
      encoding: 'utf8',
    });
    assert.equal(result.status, 0, result.stderr);
    return JSON.parse(result.stdout).services['uptime-goblin'].secrets ?? null;
  };
  assert.equal(secrets(), null, 'compose.yaml alone mounts no key');
  const shell = spawnSync('sh', ['-c', line], { cwd: directory, encoding: 'utf8' });
  assert.equal(shell.status, 0, shell.stderr);
  assert.deepEqual(
    secrets()?.map(secret => [secret.source, secret.target]),
    [['orbit_secret_key', '/run/secrets/orbit_secret_key']]
  );
});

// Review of 9a7d6e5, without Docker: the documented check and the first commands of the copy
// and move recipes, run as printed in a project directory, with a stand-in `docker` first on
// PATH that does what Compose does with them. /var/lib/uptime-goblin is the volume (a data directory here);
// compose.secret.yaml mounts ./orbit_secret_key at /run/secrets/orbit_secret_key (Compose refuses
// a missing file); `run` runs the command in the image: this tree's goblin-admin, `cat` of a file
// in the volume, or `sh -c` with /var/lib/uptime-goblin the volume, /tmp a directory of that container and
// `node lib/cli/goblin-admin.mjs` this tree's goblin-admin, on the command's stdin. `cp` replaces
// its destination, as docker cp does whatever the destination's mode; with FAKE_MOUNTED (the
// service's container is one that refused with ./orbit_secret_key mounted) it fails once that
// file is gone, as on OrbStack with Docker Engine 29.4 (A65: 3 of 3, and 5 of 5 runs of the
// Docker MOVE test with A60's lines). FAKE_CAT replaces what `cat` prints (a read that went wrong
// on the way).
// A66, for the rest of a recipe: the service's container is FAKE_ROOT/container.json, {files,
// secrets} (the Compose files it was made with, and the directory its
// /run/secrets/orbit_secret_key comes from, a copy of ./orbit_secret_key as it was at its start,
// or null). Compose takes its files from -f, else from COMPOSE_FILE in .env. `up -d` with
// compose.secret.yaml and no ./orbit_secret_key fails (bind source path does not exist) and
// leaves the container as it was, as OrbStack did; otherwise it starts a container that mounts
// the file as it is now. `exec` runs in that container, always reaching it: a container that
// refuses lives about a second, and the real exec reached one 2 of 15 times in a probe. `rm`
// deletes in the volume; `node lib/cli/goblin-admin.mjs` runs this tree's goblin-admin with that
// container's secret. `logs` prints nothing and `config` the secret the files mount.
// The volumes hold real control databases: a keyring Uptime Goblin made under the key it generated, and
// one that `goblin-admin key rewrap` then moved to the Compose secret, beside the older secret.key.
const standInDocker = `import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
const { FAKE_VOLUME: volume, FAKE_ROOT: root, FAKE_REPOSITORY: repository } = process.env;
const args = process.argv.slice(2);
const fail = message => {
  process.stderr.write('stand-in docker: ' + message + '\\n');
  process.exit(1);
};
const orbitAdmin = async (argv, env, secretsDirectory) => {
  const { main } = await import(pathToFileURL(path.join(repository, 'lib/cli/goblin-admin.mjs')));
  return main([...argv, '--data-dir', volume], {
    env,
    uid: 1000,
    container: true,
    keySources: { credentialsDirectory: path.join(root, 'no-credentials'), secretsDirectory },
  });
};
const containerFile = path.join(root, 'container.json');
const container = () =>
  fs.existsSync(containerFile) ? JSON.parse(fs.readFileSync(containerFile, 'utf8')) : null;
// What the container's /run/secrets holds: the key file as it is now.
const mount = () => {
  const secrets = fs.mkdtempSync(path.join(root, 'mounted-'));
  fs.copyFileSync('orbit_secret_key', path.join(secrets, 'orbit_secret_key'));
  return secrets;
};
// COMPOSE_FILE from the environment, else the last such line of .env, else compose.yaml.
const composeFiles = () => {
  let value = process.env.COMPOSE_FILE;
  if (!value && fs.existsSync('.env'))
    for (const line of fs.readFileSync('.env', 'utf8').split('\\n'))
      if (line.startsWith('COMPOSE_FILE=')) value = line.slice('COMPOSE_FILE='.length);
  return value ? value.split(':') : ['compose.yaml'];
};
async function compose() {
  fs.appendFileSync(path.join(root, 'calls'), JSON.stringify(args) + '\\n');
  if (args[0] !== 'compose') fail('unexpected: ' + args.join(' '));
  let at = 1;
  const files = [];
  while (args[at] === '-f' || args[at] === '--project-name') {
    if (args[at] === '-f') files.push(args[at + 1]);
    at += 2;
  }
  if (!files.length) files.push(...composeFiles());
  const [command, ...rest] = args.slice(at);
  const withSecret = files.includes('compose.secret.yaml');
  if (command === 'up') {
    if (!rest.includes('-d')) fail('unexpected: ' + args.join(' '));
    if (withSecret && !fs.existsSync('orbit_secret_key'))
      fail('Error response from daemon: invalid mount config for type "bind": bind source path does not exist: ' + path.resolve('orbit_secret_key'));
    fs.writeFileSync(containerFile, JSON.stringify({ files, secrets: withSecret ? mount() : null }));
    return 0;
  }
  if (command === 'logs') return 0;
  if (command === 'config') {
    process.stdout.write('services:\\n  orbit:\\n' + (withSecret ? '    secrets:\\n      - source: orbit_secret_key\\n        target: /run/secrets/orbit_secret_key\\n' : ''));
    return 0;
  }
  if (command === 'exec') {
    let next = 0;
    while (rest[next]?.startsWith('-')) next++;
    if (rest[next] !== 'uptime-goblin') fail('unexpected: ' + args.join(' '));
    const running = container();
    if (!running) fail('service "uptime-goblin" is not running');
    const inside = rest.slice(next + 1);
    if (inside[0] === 'rm') {
      let status = 0;
      for (const target of inside.slice(1)) {
        const file = target.startsWith('/var/lib/uptime-goblin/') ? path.join(volume, target.slice('/var/lib/uptime-goblin/'.length)) : null;
        if (file && fs.existsSync(file)) fs.rmSync(file);
        else {
          process.stderr.write("rm: cannot remove '" + target + "': No such file or directory\\n");
          status = 1;
        }
      }
      return status;
    }
    if (inside[0] !== 'node' || inside[1] !== 'lib/cli/goblin-admin.mjs')
      fail('unexpected exec ' + inside.join(' '));
    return orbitAdmin(inside.slice(2), {}, running.secrets ?? path.join(root, 'no-secrets'));
  }
  if (command === 'cp') {
    const [from, to] = rest;
    if (!from.startsWith('uptime-goblin:/var/lib/uptime-goblin/')) fail('unexpected cp ' + from);
    const source = path.join(volume, from.slice('uptime-goblin:/var/lib/uptime-goblin/'.length));
    if (!fs.existsSync(source) || (process.env.FAKE_MOUNTED && !fs.existsSync('orbit_secret_key')))
      fail('Could not find the file ' + from.slice('orbit:'.length) + ' in container');
    fs.rmSync(to, { force: true });
    fs.copyFileSync(source, to);
    return 0;
  }
  let next = 0;
  const options = [];
  while (rest[next]?.startsWith('-')) options.push(rest[next++]);
  if (
    command !== 'run' ||
    options.filter(option => option !== '-T').join(' ') !== '--rm --no-deps' ||
    rest[next] !== 'uptime-goblin'
  )
    fail('unexpected: ' + args.join(' '));
  const inImage = rest.slice(next + 1);
  let secrets = path.join(root, 'no-secrets');
  if (files.includes('compose.secret.yaml')) {
    if (!fs.existsSync('orbit_secret_key')) fail('secret file ./orbit_secret_key not found');
    secrets = fs.mkdtempSync(path.join(root, 'secrets-'));
    fs.copyFileSync('orbit_secret_key', path.join(secrets, 'orbit_secret_key'));
  }
  if (inImage[0] === 'cat' && inImage.length === 2 && inImage[1].startsWith('/var/lib/uptime-goblin/')) {
    const file = path.join(volume, inImage[1].slice('/var/lib/uptime-goblin/'.length));
    if (!fs.existsSync(file)) {
      process.stderr.write('cat: ' + inImage[1] + ': No such file or directory\\n');
      return 1;
    }
    process.stdout.write(process.env.FAKE_CAT ?? fs.readFileSync(file));
    return 0;
  }
  if (inImage[0] === 'sh' && inImage[1] === '-c' && inImage.length === 3) {
    const tmp = fs.mkdtempSync(path.join(root, 'tmp-'));
    const script = inImage[2]
      .replaceAll('/var/lib/uptime-goblin/', '"$FAKE_VOLUME"/')
      .replaceAll('/tmp/', '"$FAKE_TMP"/')
      .replaceAll('node lib/cli/goblin-admin.mjs', '"$FAKE_NODE" "$FAKE_SELF" --goblin-admin');
    const result = spawnSync('sh', ['-c', script], {
      stdio: 'inherit',
      env: {
        ...process.env,
        FAKE_TMP: tmp,
        FAKE_NODE: process.execPath,
        FAKE_SELF: process.argv[1],
        FAKE_SECRETS: secrets,
      },
    });
    fs.rmSync(tmp, { recursive: true, force: true });
    return result.status ?? 1;
  }
  if (inImage[0] !== 'node' || inImage[1] !== 'lib/cli/goblin-admin.mjs')
    fail('unexpected command ' + inImage.join(' '));
  return orbitAdmin(inImage.slice(2), {}, secrets);
}
// goblin-admin as sh -c runs it in the image: with its environment's GOBLIN_ variables.
process.exitCode =
  args[0] === '--goblin-admin'
    ? await orbitAdmin(
        args.slice(1),
        Object.fromEntries(Object.entries(process.env).filter(([name]) => name.startsWith('GOBLIN_'))),
        process.env.FAKE_SECRETS
      )
    : await compose();
`;

test('the documented check, copy and move commands never replace an orbit_secret_key that opens the data, and read the volume key with a container of their own, checked before any file changes', async t => {
  const { startControl } = await import('../../lib/db/control.mjs');
  const { acquireLock } = await import('../../lib/db/lock.mjs');
  const { main } = await import('../../lib/cli/goblin-admin.mjs');
  const { keyFingerprint } = await import('../../lib/keyring.mjs');
  const release = JSON.parse(
    fs.readFileSync(path.join(repository, 'package.json'), 'utf8')
  ).version;
  const base = temporary(t, 'orbit-compose-lines-');
  const bin = path.join(base, 'bin');
  fs.mkdirSync(bin);
  fs.mkdirSync(path.join(base, 'no-secrets'));
  fs.writeFileSync(path.join(bin, 'docker.mjs'), standInDocker);
  const quote = word => `'${word.replaceAll("'", `'\\''`)}'`;
  fs.writeFileSync(
    path.join(bin, 'docker'),
    `#!/bin/sh\nexec ${quote(process.execPath)} ${quote(path.join(bin, 'docker.mjs'))} "$@"\n`,
    { mode: 0o755 }
  );
  const none = {
    credentialsDirectory: path.join(base, 'no-credentials'),
    secretsDirectory: path.join(base, 'no-secrets'),
  };
  // A volume 1.5 has run on without compose.secret.yaml: it generated secret.key, sealed with it.
  const volume = async label => {
    const directory = path.join(base, label);
    fs.mkdirSync(directory);
    fs.writeFileSync(path.join(directory, 'config.json'), '{"services":[]}\n');
    const lock = acquireLock(directory);
    try {
      const started = await startControl(directory, {
        lock,
        credentialConfigured: true,
        release,
        env: {},
        keySources: none,
      });
      started.control.close();
      assert.equal(started.key.source, 'generated');
      return { directory, generated: started.key.fingerprint };
    } finally {
      lock.release();
    }
  };
  const admin = async (directory, args, env = {}) => {
    let out = '',
      err = '';
    const code = await main([...args, '--data-dir', directory], {
      env,
      uid: 1000,
      container: true,
      keySources: none,
      stdout: text => (out += text),
      stderr: text => (err += text),
    });
    return { code, out, err };
  };

  // The commands as docs/installation.md prints them (the docs test holds compose.secret.yaml to
  // the same).
  const { check, copy, move } = keyRecipes();
  const checkLine = check.trim();
  const [copyCommand] = recipeCommands(copy);
  const [moveCommand] = recipeCommands(move);
  assert.equal(copyCommand, documentedCopy);
  assert.equal(moveCommand, documentedMove);
  const project = path.join(base, 'project');
  fs.mkdirSync(project);
  const keyFile = path.join(project, 'orbit_secret_key'),
    unused = `${keyFile}.unused`;
  const putKey = hex => {
    fs.rmSync(keyFile, { force: true });
    if (hex) fs.writeFileSync(keyFile, `${hex}\n`, { mode: 0o400 });
  };
  const read = file => (fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : null);
  // Every orbit_secret_key file in the project: a command leaves no file it read the key into.
  const keyFiles = () =>
    fs
      .readdirSync(project)
      .filter(file => file.startsWith('orbit_secret_key'))
      .sort();
  const calls = () =>
    fs
      .readFileSync(path.join(base, 'calls'), 'utf8')
      .split('\n')
      .filter(Boolean)
      .map(line => JSON.parse(line));
  const run = (line, directory, { env = {}, noclobber = false } = {}) => {
    fs.writeFileSync(path.join(base, 'calls'), '');
    return spawnSync('sh', [...(noclobber ? ['-C'] : []), '-c', line], {
      cwd: project,
      encoding: 'utf8',
      env: {
        ...process.env,
        PATH: `${bin}${path.delimiter}${process.env.PATH}`,
        FAKE_VOLUME: directory,
        FAKE_ROOT: base,
        FAKE_REPOSITORY: repository,
        ...env,
      },
    });
  };
  const verdict = directory => {
    const result = run(checkLine, directory);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    return result.stdout.split('\n')[0];
  };
  // The read: two containers of their own, with compose.yaml alone (no key mounted), the first
  // printing the volume's key, the second running goblin-admin key status on what the host got.
  const readTheVolumeKey = [
    [
      'compose',
      '-f',
      'compose.yaml',
      'run',
      '--rm',
      '--no-deps',
      '-T',
      'uptime-goblin',
      'cat',
      '/var/lib/uptime-goblin/secret.key',
    ],
    [
      'compose',
      '-f',
      'compose.yaml',
      'run',
      '--rm',
      '--no-deps',
      '-T',
      'uptime-goblin',
      'sh',
      '-c',
      'umask 077 && cat > /tmp/key && GOBLIN_SECRET_KEY_FILE=/tmp/key node lib/cli/goblin-admin.mjs key status > /dev/null',
    ],
  ];
  const stopped = 'Stopped before the end: run the check\n';

  // The reviewer's state: the data moved from the generated key A to the Compose secret B with
  // key rewrap, as docs/installation.md#goblin-admin gives a key change; A stays in the volume.
  const moved = await volume('moved');
  const b = 'c3'.repeat(16) + 'd4'.repeat(16);
  putKey(b);
  const rewrap = await admin(moved.directory, ['key', 'rewrap'], {
    GOBLIN_SECRET_KEY_FILE: keyFile,
    GOBLIN_SECRET_KEY_PREVIOUS_FILE: path.join(moved.directory, 'secret.key'),
  });
  assert.equal(rewrap.code, 0, rewrap.err);
  const opens = async () =>
    JSON.parse(
      (
        await admin(moved.directory, ['key', 'status', '--json'], {
          GOBLIN_SECRET_KEY_FILE: keyFile,
        })
      ).out
    ).matches;
  assert.equal(await opens(), true, 'orbit_secret_key opens the data');
  assert.equal(verdict(moved.directory), 'KEEP', 'not COPY: secret.key is the old key');
  assert.match(
    fs.readFileSync(path.join(base, 'calls'), 'utf8'),
    /"-f","compose\.yaml","-f","compose\.secret\.yaml","run"/,
    'the check mounted orbit_secret_key'
  );
  const copied = run(copyCommand, moved.directory);
  assert.equal(copied.status, 0, copied.stderr);
  assert.equal(copied.stdout, 'orbit_secret_key exists: not replaced; run the check\n');
  assert.deepEqual(calls(), [], 'it reads nothing');
  assert.equal(read(keyFile), `${b}\n`, 'orbit_secret_key, byte for byte');
  // The move command, there by mistake: A is read, and goblin-admin finds it does not open the
  // data, before anything is set aside.
  const notMoved = run(moveCommand, moved.directory);
  assert.notEqual(notMoved.status, 0);
  assert.equal(notMoved.stdout, stopped);
  assert.deepEqual(calls(), readTheVolumeKey);
  assert.equal(read(keyFile), `${b}\n`, 'orbit_secret_key, byte for byte');
  assert.deepEqual(keyFiles(), ['orbit_secret_key'], 'nothing set aside, nothing left');
  assert.equal(await opens(), true, 'and it still opens the data');
  // Without orbit_secret_key, the old key in the volume is no answer either: RESTORE, and the
  // copy command finds that A does not open the data, and makes no orbit_secret_key.
  putKey(null);
  assert.equal(verdict(moved.directory), 'RESTORE');
  const notCopied = run(copyCommand, moved.directory);
  assert.notEqual(notCopied.status, 0);
  assert.equal(notCopied.stdout, stopped);
  assert.deepEqual(keyFiles(), []);
  putKey(b);

  // A volume that needs the copy, given a new key by mistake: MOVE. Uptime Goblin refuses in a container
  // that mounts orbit_secret_key (FAKE_MOUNTED: docker compose cp fails once it is gone).
  const generated = await volume('generated');
  const wrong = 'e5'.repeat(16) + 'f6'.repeat(16);
  const refused = { env: { FAKE_MOUNTED: '1' } };
  putKey(wrong);
  assert.equal(verdict(generated.directory), 'MOVE');
  // An orbit_secret_key.unused there already is never replaced: nothing is read or changed.
  fs.writeFileSync(unused, 'an earlier key\n', { mode: 0o400 });
  const taken = run(moveCommand, generated.directory, refused);
  assert.equal(taken.status, 0, taken.stderr);
  assert.equal(taken.stdout, 'orbit_secret_key.unused exists: not replaced; choose another name\n');
  assert.deepEqual(calls(), []);
  assert.equal(read(unused), 'an earlier key\n');
  assert.equal(read(keyFile), `${wrong}\n`);
  fs.rmSync(unused, { force: true });
  // A read that went wrong on the way (not a key): goblin-admin refuses those bytes, and the key
  // file stays where it is.
  const garbled = run(moveCommand, generated.directory, {
    env: { ...refused.env, FAKE_CAT: 'Container orbit-run Creating\n' },
  });
  assert.notEqual(garbled.status, 0);
  assert.equal(garbled.stdout, stopped);
  assert.deepEqual(calls(), readTheVolumeKey);
  assert.equal(read(keyFile), `${wrong}\n`);
  assert.deepEqual(keyFiles(), ['orbit_secret_key']);
  // As printed (in a shell with noclobber too): the volume's key read and checked, then the new
  // key set aside, kept byte for byte, and the volume's key in a new orbit_secret_key, 0400.
  const movedAside = run(moveCommand, generated.directory, { ...refused, noclobber: true });
  assert.equal(movedAside.status, 0, movedAside.stdout + movedAside.stderr);
  assert.equal(movedAside.stdout, '');
  assert.deepEqual(calls(), readTheVolumeKey, 'no docker compose cp');
  assert.equal(read(unused), `${wrong}\n`);
  assert.equal(fs.statSync(unused).mode & 0o777, 0o400);
  assert.equal(keyFingerprint(Buffer.from(read(keyFile).trim(), 'hex')), generated.generated);
  assert.equal(fs.statSync(keyFile).mode & 0o777, 0o400);
  assert.deepEqual(keyFiles(), ['orbit_secret_key', 'orbit_secret_key.unused']);
  assert.equal(verdict(generated.directory), 'KEEP');
  fs.rmSync(unused);

  // COPY after the key that refused was removed by hand (the container still mounts it): the
  // copy command reads the volume's key the same way, never through that container.
  const removed = await volume('removed');
  putKey(wrong);
  assert.equal(verdict(removed.directory), 'MOVE');
  putKey(null);
  assert.equal(verdict(removed.directory), 'COPY');
  const copy2 = run(copyCommand, removed.directory, refused);
  assert.equal(copy2.status, 0, copy2.stdout + copy2.stderr);
  assert.equal(copy2.stdout, '');
  assert.deepEqual(calls(), readTheVolumeKey, 'no docker compose cp');
  assert.equal(keyFingerprint(Buffer.from(read(keyFile).trim(), 'hex')), removed.generated);
  assert.equal(fs.statSync(keyFile).mode & 0o777, 0o400);
  assert.deepEqual(keyFiles(), ['orbit_secret_key']);
  assert.equal(verdict(removed.directory), 'KEEP');

  // Nothing sealed yet: NEW, with or without an orbit_secret_key (the new-key line keeps it).
  // The copy command finds no key in such a volume, and makes no file.
  const empty = path.join(base, 'empty');
  fs.mkdirSync(empty);
  assert.equal(verdict(empty), 'NEW');
  putKey(null);
  assert.equal(verdict(empty), 'NEW');
  const nothing = run(copyCommand, empty);
  assert.notEqual(nothing.status, 0);
  assert.equal(nothing.stdout, stopped);
  assert.match(
    nothing.stderr,
    /cat: \/var\/lib\/uptime-goblin\/secret\.key: No such file or directory/
  );
  assert.deepEqual(keyFiles(), []);
  assert.deepEqual(fs.readdirSync(empty), [], 'the check and the read only read');
});

// A66: a recipe block's lines are independent once pasted, so after a first command that
// stopped, the rest ran anyway, and the copy and MOVE recipes ended with docker compose exec
// orbit rm /var/lib/uptime-goblin/secret.key. With the MOVE recipe pasted whole in the COPY state (Uptime Goblin
// running without the override), its start failed for want of ./orbit_secret_key, and the rm ran
// in the running container: 3 of 3 real runs deleted the only key that opens the data. In the MOVE
// state with an orbit_secret_key.unused from an earlier attempt, the start made a container that
// mounts the wrong key and refuses, and the rm reached it within its second of life (2 of 15 in a
// probe, 1 of 1 for real). The last line is now goblin-admin key remove-data-copy, which deletes
// the volume's copy only while the key that container is given is another file holding the same
// key that opens the data. Every recipe is pasted whole here (its three blocks at once, as a
// person who pastes everything does) in every state, with the stand-in `docker` (whose exec always
// reaches the container) and a `sudo` that declines: through sh, and, where zsh is installed,
// through an interactive zsh reading the paste, which, as the admin's does, takes no '#' for a comment.
// The key that seals the data must stay where it was, or be moved only to ./orbit_secret_key with
// the volume's copy deleted after it. A67: the KEEP block (key remove-data-copy --unused) is pasted
// in every state too: it deletes the volume's key only in the KEEP state, where that is the older
// key A and the data moved to B, and keeps it, saying why, wherever A is the key that opens it.
test('a recipe pasted whole in the wrong state never deletes the only key that opens the data: the MOVE recipe on a COPY volume, or beside an earlier orbit_secret_key.unused, keeps the volume key', async t => {
  const { startControl } = await import('../../lib/db/control.mjs');
  const { acquireLock } = await import('../../lib/db/lock.mjs');
  const { main } = await import('../../lib/cli/goblin-admin.mjs');
  const release = JSON.parse(
    fs.readFileSync(path.join(repository, 'package.json'), 'utf8')
  ).version;
  const base = temporary(t, 'orbit-compose-paste-');
  const bin = path.join(base, 'bin');
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'docker.mjs'), standInDocker);
  const quote = word => `'${word.replaceAll("'", `'\\''`)}'`;
  fs.writeFileSync(
    path.join(bin, 'docker'),
    `#!/bin/sh\nexec ${quote(process.execPath)} ${quote(path.join(bin, 'docker.mjs'))} "$@"\n`,
    { mode: 0o755 }
  );
  // A sudo that declines, as a person on a Mac does (and no real sudo is ever run).
  fs.writeFileSync(
    path.join(bin, 'sudo'),
    "#!/bin/sh\necho 'sudo (stand-in): declined' >&2\nexit 1\n",
    { mode: 0o755 }
  );
  const zsh = spawnSync('zsh', ['-f', '-c', 'true']).status === 0;
  const shells = zsh ? ['sh', 'zsh'] : ['sh'];
  const { fresh, copy, move, older } = keyRecipes();
  const recipes = { fresh, copy, move, older };
  const C = 'c7'.repeat(16) + 'e1'.repeat(16),
    D = 'd8'.repeat(16) + 'f2'.repeat(16),
    B = 'b9'.repeat(16) + 'a3'.repeat(16);
  const read = file => (fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : null);
  let count = 0;

  // A volume 1.5 ran on without compose.secret.yaml (A, generated, seals it), its project
  // directory and the service's container, in one of the states the check names.
  const prepare = async state => {
    const root = path.join(base, `case-${++count}`);
    const directory = path.join(root, 'volume'),
      project = path.join(root, 'project');
    for (const made of [root, directory, project, path.join(root, 'no-secrets')])
      fs.mkdirSync(made, { recursive: true });
    const none = {
      credentialsDirectory: path.join(root, 'no-credentials'),
      secretsDirectory: path.join(root, 'no-secrets'),
    };
    fs.writeFileSync(path.join(directory, 'config.json'), '{"services":[]}\n');
    const lock = acquireLock(directory);
    try {
      const started = await startControl(directory, {
        lock,
        credentialConfigured: true,
        release,
        env: {},
        keySources: none,
      });
      started.control.close();
      assert.equal(started.key.source, 'generated');
    } finally {
      lock.release();
    }
    const A = read(path.join(directory, 'secret.key'));
    const keyFile = path.join(project, 'orbit_secret_key');
    const put = (file, hex) => fs.writeFileSync(file, `${hex}\n`, { mode: 0o400 });
    // The service's container: Uptime Goblin as it runs (COPY: without the override), or one that
    // mounts orbit_secret_key and refuses (MOVE), or runs with it (KEEP).
    const run = secret => {
      let secrets = null;
      if (secret) {
        secrets = fs.mkdtempSync(path.join(root, 'mounted-'));
        put(path.join(secrets, 'orbit_secret_key'), secret);
        fs.writeFileSync(
          path.join(project, '.env'),
          'COMPOSE_FILE=compose.yaml:compose.secret.yaml\n'
        );
      }
      fs.writeFileSync(
        path.join(root, 'container.json'),
        JSON.stringify({
          files: secret ? ['compose.yaml', 'compose.secret.yaml'] : ['compose.yaml'],
          secrets,
        })
      );
    };
    const keys = { A };
    if (state === 'COPY') run(null);
    if (state.startsWith('MOVE')) {
      put(keyFile, C);
      run(C);
      keys.C = `${C}\n`;
    }
    if (state === 'MOVE with .unused') {
      put(`${keyFile}.unused`, D);
      keys.D = `${D}\n`;
    }
    if (state === 'KEEP') {
      // The data moved to B with key rewrap; A stays in the volume as an older key.
      put(keyFile, B);
      let err = '';
      const code = await main(['key', 'rewrap', '--data-dir', directory], {
        env: {
          GOBLIN_SECRET_KEY_FILE: keyFile,
          GOBLIN_SECRET_KEY_PREVIOUS_FILE: path.join(directory, 'secret.key'),
        },
        uid: 1000,
        container: true,
        keySources: none,
        stdout: () => {},
        stderr: text => (err += text),
      });
      assert.equal(code, 0, err);
      run(B);
      keys.B = `${B}\n`;
    }
    return { root, directory, project, keyFile, keys };
  };
  const environment = ({ root, directory }) => ({
    ...process.env,
    PATH: `${bin}${path.delimiter}${process.env.PATH}`,
    HOME: root,
    ZDOTDIR: root,
    FAKE_VOLUME: directory,
    FAKE_ROOT: root,
    FAKE_REPOSITORY: repository,
  });
  // The whole recipe as pasted: through sh, or an interactive zsh reading it (-i -s: no rc
  // files, and '#' is no comment, as with interactivecomments off).
  const paste = (text, scenario, shell) =>
    shell === 'zsh'
      ? spawnSync('zsh', ['-f', '-i', '-s'], {
          cwd: scenario.project,
          input: text,
          encoding: 'utf8',
          env: environment(scenario),
        })
      : spawnSync('sh', ['-c', text], {
          cwd: scenario.project,
          encoding: 'utf8',
          stdio: ['ignore', 'pipe', 'pipe'],
          env: environment(scenario),
        });
  const checkLine = keyRecipes().check.trim();
  const verdict = scenario => {
    const result = spawnSync('sh', ['-c', checkLine], {
      cwd: scenario.project,
      encoding: 'utf8',
      env: environment(scenario),
    });
    assert.equal(result.status, 0, result.stdout + result.stderr);
    return result.stdout.split('\n')[0];
  };
  // Where each key is now: the volume, orbit_secret_key, orbit_secret_key.unused.
  const where = ({ directory, keyFile }) => ({
    volume: read(path.join(directory, 'secret.key')),
    key: read(keyFile),
    unused: read(`${keyFile}.unused`),
  });

  // Every case runs; the failures are listed together at the end.
  const failures = [];
  for (const shell of shells)
    for (const state of ['COPY', 'MOVE', 'MOVE with .unused', 'KEEP'])
      for (const [name, text] of Object.entries(recipes)) {
        const label = `${state} state, the ${name} recipe pasted whole into ${shell}`;
        try {
          await pasteCase(shell, state, name, text, label);
        } catch (error) {
          failures.push(`${label}: ${error.message.split('\n')[0]}`);
        }
      }
  assert.deepEqual(failures, []);

  async function pasteCase(shell, state, name, text, label) {
    const scenario = await prepare(state);
    const { keys } = scenario;
    assert.equal(
      verdict(scenario),
      { COPY: 'COPY', MOVE: 'MOVE', 'MOVE with .unused': 'MOVE', KEEP: 'KEEP' }[state],
      label
    );
    const pasted = paste(text, scenario, shell);
    const output = `${label}\n${pasted.stdout}${pasted.stderr}`;
    const after = where(scenario);
    const sealing = state === 'KEEP' ? keys.B : keys.A;
    assert.ok(
      after.volume === sealing || after.key === sealing,
      `the key that opens the data is still there: ${output}`
    );
    if (state === 'COPY' && name === 'copy') {
      // The copy recipe in its own state: the key copied, then the volume's copy deleted.
      assert.deepEqual(after, { volume: null, key: keys.A, unused: null }, output);
      assert.equal(verdict(scenario), 'KEEP', output);
    } else if (state === 'MOVE' && name === 'move') {
      assert.deepEqual(after, { volume: null, key: keys.A, unused: keys.C }, output);
      assert.equal(verdict(scenario), 'KEEP', output);
    } else if (state === 'KEEP' && name === 'older') {
      // The older key A goes; B, which opens every data key, stays.
      assert.deepEqual(after, { volume: null, key: keys.B, unused: null }, output);
      assert.match(
        pasted.stdout,
        /^Deleted \S+, an older key \(fingerprint [0-9a-f]{16}\) that opens none of this data's keys/,
        output
      );
      assert.equal(verdict(scenario), 'KEEP', output);
    } else {
      // Anything else keeps the volume's key byte for byte, and no key file you had.
      assert.equal(after.volume, keys.A, output);
      if (keys.B) assert.equal(after.key, keys.B, output);
      if (keys.D) assert.equal(after.unused, keys.D, output);
      if (state.startsWith('MOVE') && name !== 'move') assert.equal(after.key, keys.C, output);
    }
    if (
      name !== 'fresh' &&
      !(state === 'COPY' && name === 'copy') &&
      !(state === 'MOVE' && name === 'move') &&
      !(state === 'KEEP' && name === 'older')
    )
      assert.match(
        pasted.stderr,
        /Nothing was deleted\./,
        `the last line ran and refused: ${output}`
      );
    // The two states the review found the key deleted in, A65's lines pasted whole.
    if (name === 'move' && state === 'COPY') {
      assert.equal(after.key, null, output);
      assert.equal(after.unused, null, output);
      assert.equal(verdict(scenario), 'COPY', output);
    }
    if (name === 'move' && state === 'MOVE with .unused')
      assert.equal(verdict(scenario), 'MOVE', output);
  }
});
