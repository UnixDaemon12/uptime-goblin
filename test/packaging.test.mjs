import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import {
  parseManifest,
  readManifest,
  checkClosure,
  moduleSpecifiers,
  htmlReferences,
} from '../scripts/check.mjs';
import {
  declareGit,
  expectNested,
  gitCheckout,
  gitMissing,
  gitProbe,
  gitStubs,
  runNested,
} from './helpers/git.mjs';
import { required } from './installer/helpers.mjs';

const repository = fileURLToPath(new URL('..', import.meta.url));
const read = file => fs.readFileSync(path.join(repository, file), 'utf8');
const manifest = readManifest(repository);

function temporary(t, prefix) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function walk(directory, relative = '') {
  const files = [];
  for (const entry of fs.readdirSync(path.join(directory, relative), { withFileTypes: true })) {
    if (entry.name.startsWith('.')) continue;
    const item = relative ? `${relative}/${entry.name}` : entry.name;
    if (entry.isDirectory()) files.push(...walk(directory, item));
    else files.push(item);
  }
  return files;
}

test('deploy/manifest.txt is sorted, unique, safe and lists only existing files', () => {
  assert.deepEqual(parseManifest(read('deploy/manifest.txt')).problems, []);
  for (const file of manifest)
    assert.ok(fs.lstatSync(path.join(repository, file)).isFile(), `${file} is a regular file`);
  for (const required of [
    'server.mjs',
    'package.json',
    'package-lock.json',
    'lib/healthcheck.mjs',
    'deploy/manifest.txt',
    'public/index.html',
  ])
    assert.ok(manifest.includes(required), required);
  assert.deepEqual(parseManifest('b\na\n').problems, ['line 2: a must sort before b']);
  assert.deepEqual(parseManifest('a\na\n').problems, ['line 2: duplicate a']);
  for (const bad of ['../etc/passwd', '/etc/passwd', 'lib/./a.mjs', 'a b', 'lib//a.mjs', 'a\r'])
    assert.equal(parseManifest(`LICENSE\n${bad}\n`).problems.length, 1, JSON.stringify(bad));
  assert.deepEqual(parseManifest('# only a comment\n\n').problems, ['the manifest lists no files']);
});

// A new module or page asset must be added to the manifest, or no install would contain it.
test('every server module and web asset on disk is in the manifest', () => {
  for (const file of walk(path.join(repository, 'lib')))
    if (file.endsWith('.mjs'))
      assert.ok(manifest.includes(`lib/${file}`), `deploy/manifest.txt must list lib/${file}`);
  for (const file of walk(path.join(repository, 'public')))
    assert.ok(manifest.includes(`public/${file}`), `deploy/manifest.txt must list public/${file}`);
});

test('every import of a shipped file is shipped too (module-graph closure)', () => {
  const { problems, modules } = checkClosure(repository);
  assert.deepEqual(problems, []);
  for (const entry of ['server.mjs', 'lib/healthcheck.mjs', 'public/app.js'])
    assert.ok(modules.includes(entry), entry);
  assert.deepEqual(
    moduleSpecifiers(
      [
        "import fs from 'node:fs';",
        'import {',
        '  a,',
        "} from './a.mjs';",
        "export * from '../public/shared/x.js';",
        "import './side-effect.js';",
        "const lazy = await import('./lazy.mjs');",
        "// import nope from './comment.mjs' is only prose here",
        'const text = \'import b from "./string.mjs"\';',
      ].join('\n')
    ),
    ['node:fs', './a.mjs', '../public/shared/x.js', './side-effect.js', './lazy.mjs']
  );
  assert.deepEqual(
    htmlReferences('<link href="/style.css?v=1" /><script src="/app.js"></script><a href="#x">'),
    ['/style.css', '/app.js']
  );
});

test('npm run check follows imports and fails on unlisted, missing or broken modules', t => {
  const root = temporary(t, 'orbit-check-');
  const write = (file, text) => {
    fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    fs.writeFileSync(path.join(root, file), text);
  };
  const run = () =>
    spawnSync(process.execPath, [path.join(repository, 'scripts/check.mjs'), '--root', root], {
      encoding: 'utf8',
    });
  write('package.json', JSON.stringify({ type: 'module', dependencies: { nodemailer: '1' } }));
  write('server.mjs', "import './lib/a.mjs';\nimport nodemailer from 'nodemailer';\n");
  write('lib/a.mjs', "export * from '../public/shared/b.js';\nimport 'node:fs';\n");
  write('public/shared/b.js', 'export const b = 1;\n');
  write('public/index.html', '<script type="module" src="/app.js"></script>');
  write('public/app.js', "import { b } from '/shared/b.js';\n");
  const listed = files => write('deploy/manifest.txt', files.sort().join('\n') + '\n');
  const all = [
    'deploy/manifest.txt',
    'lib/a.mjs',
    'package.json',
    'public/app.js',
    'public/index.html',
    'public/shared/b.js',
    'server.mjs',
  ];
  listed(all);
  let result = run();
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /4 shipped modules pass node --check/);

  listed(all.filter(file => file !== 'public/shared/b.js'));
  result = run();
  assert.equal(result.status, 1);
  assert.match(
    result.stderr,
    /lib\/a\.mjs imports public\/shared\/b\.js, which deploy\/manifest\.txt does not list/
  );
  assert.match(result.stderr, /public\/app\.js imports public\/shared\/b\.js, which/);

  listed(all);
  write('lib/a.mjs', "import './gone.mjs';\nimport left from 'left-pad';\n");
  result = run();
  assert.equal(result.status, 1);
  assert.match(result.stderr, /lib\/a\.mjs imports lib\/gone\.mjs, which does not exist/);
  assert.match(result.stderr, /lib\/a\.mjs imports left-pad, which is not a runtime dependency/);

  write('lib/a.mjs', 'export const broken = ;\n');
  result = run();
  assert.equal(result.status, 1);
  assert.match(result.stderr, /lib\/a\.mjs failed node --check/);

  write('lib/a.mjs', 'export {};\n');
  write('deploy/manifest.txt', 'server.mjs\nlib/a.mjs\n');
  result = run();
  assert.equal(result.status, 1);
  assert.match(result.stderr, /lib\/a\.mjs must sort before server\.mjs/);

  const npm = JSON.parse(read('package.json'));
  assert.equal(npm.scripts.check, 'node scripts/check.mjs');
});

test('the installer reads the manifest instead of keeping its own file lists', () => {
  const installer = read('deploy/install.sh');
  assert.match(installer, /deploy\/manifest\.txt/);
  // It runs these itself (verification, the --trust-proxy parser, the --listen and
  // --allowed-hosts rules, and the encryption-key check against existing data: parseKey and
  // inspectKeyring); it copies none by name.
  const used = new Set([
    'lib/healthcheck.mjs',
    'lib/throttle.mjs',
    'lib/environment.mjs',
    'lib/keyring.mjs',
    'lib/db/control.mjs',
    // GOBLIN_ALLOW_UNLIMITED and GOBLIN_SUPERVISED in /etc/uptime-goblin.env, read by this release's own
    // parsers before an upgrade changes anything.
    'lib/resource-limits.mjs',
    // The password preflight: GOBLIN_PASSWORD as systemd would give it, judged by this release's
    // own check before an upgrade changes anything.
    'lib/identity/password.mjs',
    // The downgrade check: the installed and the new version in Uptime Goblin's own release order
    // (compareReleases), before anything changes.
    'lib/db/migrate.mjs',
  ]);
  // A67: the message after it copies the key out of /var/lib/uptime-goblin gives the goblin-admin line
  // that deletes the data directory's copy (/opt/uptime-goblin/lib/cli/goblin-admin.mjs): named for the operator
  // to run, neither copied nor run by the installer.
  const named = new Set(['lib/cli/goblin-admin.mjs']);
  for (const file of named)
    assert.equal(
      installer.split(file).length - 1,
      installer.split(
        `node /opt/uptime-goblin/${file} key remove-data-copy --data-dir /var/lib/uptime-goblin');`
      ).length - 1,
      `install.sh names ${file} only in the remove-data-copy line of its message`
    );
  for (const file of manifest.filter(
    file => /^(lib|public)\//.test(file) && !used.has(file) && !named.has(file)
  ))
    assert.ok(!installer.includes(file), `install.sh must not name ${file}`);
});

// Docker's .dockerignore semantics: the last matching pattern wins, a pattern also matches every
// path below a matching directory, * stays within one path segment, ** crosses segments and **/
// also matches no directory at all (lib/**/*.mjs matches lib/x.mjs).
function dockerIgnored(patterns, file) {
  let ignored = false;
  for (const raw of patterns) {
    const negated = raw.startsWith('!');
    const pattern = path.posix.normalize(negated ? raw.slice(1) : raw).replace(/\/$/, '');
    const expression = new RegExp(
      '^' +
        pattern
          .split(/(\*\*\/|\*\*|\*|\?)/)
          .map(part =>
            part === '**/'
              ? '(.*/)?'
              : part === '**'
                ? '.*'
                : part === '*'
                  ? '[^/]*'
                  : part === '?'
                    ? '[^/]'
                    : part.replace(/[.+^${}()|[\]\\]/g, '\\$&')
          )
          .join('') +
        '$'
    );
    const parts = file.split('/');
    const candidates = parts.map((_, i) => parts.slice(0, i + 1).join('/'));
    if (candidates.some(candidate => expression.test(candidate))) ignored = !negated;
  }
  return ignored;
}

test('the Docker image contains every manifest file at its manifest path', () => {
  const patterns = read('.dockerignore')
    .split('\n')
    .map(line => line.trim())
    .filter(line => line && !line.startsWith('#'));
  assert.equal(dockerIgnored(['**', '!lib/', '!lib/*.mjs'], 'lib/x.mjs'), false);
  assert.equal(dockerIgnored(['**', '!lib/*.mjs'], 'lib/sub/x.mjs'), true);
  assert.equal(dockerIgnored(['**', '!lib/'], 'lib/sub/x.mjs'), false);
  assert.equal(dockerIgnored(['**', '!lib/'], 'data/config.json'), true);
  // A reopened directory's descendants excluded again, then the source files allowed.
  const reopened = ['**', '!lib/', 'lib/**', '!lib/**/*.mjs'];
  assert.equal(dockerIgnored(reopened, 'lib/x.mjs'), false);
  assert.equal(dockerIgnored(reopened, 'lib/sub/x.mjs'), false);
  assert.equal(dockerIgnored(reopened, 'lib/sub/private.env'), true);
  for (const file of manifest)
    assert.equal(dockerIgnored(patterns, file), false, `.dockerignore must allow ${file}`);
  for (const file of [
    'data/config.json',
    '.env',
    'node_modules/x/index.js',
    'test/api.test.mjs',
    // The encryption key: compose.secret.yaml's file and one Uptime Goblin generated under npm start.
    'orbit_secret_key',
    'data/secret.key',
    // A local backup or credential file inside a directory the image takes: re-opening the
    // directory (!lib/) let each of these into the build context, and COPY into the image
    // (test/installer/docker.test.mjs builds with these and scans the context and every image
    // layer).
    'lib/private.env',
    'lib/audit/private-backup.json',
    'docs/private-backup.json',
    'public/data/auth.json',
    'public/shared/private.env',
    'public/modules/private.env',
    'public/modules/configure/private-backup.json',
    'deploy/orbit.env',
  ])
    assert.equal(dockerIgnored(patterns, file), true, `.dockerignore must exclude ${file}`);

  const dockerfile = read('Dockerfile');
  assert.match(dockerfile, /^WORKDIR \/app$/m);
  // Supply chain: the base is pinned by digest (a tag can be moved), and no package manager is
  // left in the runtime image (test/installer/docker.test.mjs checks the built image too).
  const from = dockerfile.match(/^FROM\s+(\S+)/gm) ?? [];
  assert.ok(from.length > 0);
  for (const line of from) assert.match(line, /^FROM\s+[^\s@]+@sha256:[0-9a-f]{64}$/, line);
  // The pinned base predates Debian's libpcre2-8-0 10.42-1+deb12u2 security update, so the image
  // installs exactly that version on top (the step of Codex's maintenance Dockerfile): a version
  // Debian no longer offers fails the build instead of leaving the older one, and no package
  // lists stay in the image. Drop the step, and this check, only with a base that carries it.
  const apt = dockerfile.match(/^RUN apt-get update [\s\S]*?(?=\n[A-Z]+\s)/m)?.[0] ?? '';
  const aptWords = apt.split(/\s+/).filter(word => word !== '\\');
  assert.ok(aptWords.includes('libpcre2-8-0=10.42-1+deb12u2'), 'the libpcre2-8-0 security update');
  assert.ok(aptWords.includes('--no-install-recommends'), apt);
  assert.ok(aptWords.includes('/var/lib/apt/lists/*'), 'the package lists are removed');
  const packages = aptWords.slice(aptWords.indexOf('--no-install-recommends') + 1);
  for (const name of packages.slice(0, packages.indexOf('&&')))
    assert.match(
      name,
      /^[a-z0-9][a-z0-9.+-]*=[0-9][A-Za-z0-9.+~:-]*$/,
      `${name}: an exact version`
    );
  // The npm ci instruction: up to the next instruction (its comment lines included).
  const install = dockerfile.match(/^RUN npm ci [\s\S]*?(?=\n[A-Z]+\s)/m)?.[0] ?? '';
  for (const removed of [
    '/usr/local/lib/node_modules/npm',
    '/usr/local/lib/node_modules/corepack',
    '/opt/yarn-*',
    '/usr/local/bin/npm',
    '/usr/local/bin/npx',
    '/usr/local/bin/corepack',
    '/usr/local/bin/yarn',
    '/usr/local/bin/yarnpkg',
  ])
    assert.ok(install.split(/\s+/).includes(removed), `the npm ci step removes ${removed}`);
  const copies = [...dockerfile.matchAll(/^COPY\s+(?!--from)(.+)$/gm)].map(match =>
    match[1].split(/\s+/).filter(word => !word.startsWith('--'))
  );
  const inImage = file => {
    for (const words of copies) {
      const destination = words.at(-1).replace(/^\.\/?/, '');
      for (const source of words.slice(0, -1)) {
        if (source === file) {
          const folder = destination.endsWith('/') || words.length > 2 || destination === '';
          return folder ? path.posix.join(destination, path.posix.basename(file)) : destination;
        }
        if (file.startsWith(source + '/'))
          return path.posix.join(destination, file.slice(source.length + 1));
      }
    }
    return null;
  };
  for (const file of manifest) assert.equal(inImage(file), file, `Dockerfile must COPY ${file}`);
  // The build itself fails when a manifest file is missing from the image.
  assert.match(dockerfile, /^RUN node -e ".*deploy\/manifest\.txt.*Missing from the image/m);
  assert.match(dockerfile, /GOBLIN_SUPERVISED=1/);
  // Supervised from the command line too, which docker run -e and a Compose override's
  // environment cannot change (GOBLIN_SUPERVISED=0 there would turn the limits check off).
  assert.match(dockerfile, /^CMD \["node", "server\.mjs", "--supervised"\]$/m);
  assert.equal(dockerfile.match(/^CMD /gm).length, 1);
  assert.match(
    dockerfile,
    /^HEALTHCHECK .*--start-period=60s .*CMD \["node", "lib\/healthcheck\.mjs"\]$/m
  );
});

test('the systemd unit restarts every unexpected exit but not a refusal (C4)', () => {
  const unit = read('deploy/uptime-goblin.service');
  const directives = unit
    .split('\n')
    .filter(line => /^[A-Za-z]+=/.test(line))
    .map(line => line.split('=')[0]);
  assert.equal(directives.filter(name => name === 'ExecStart').length, 1);
  for (const line of [
    'Restart=always',
    'RestartSec=5',
    'RestartPreventExitStatus=78',
    'Environment=GOBLIN_SUPERVISED=1',
    'EnvironmentFile=/etc/uptime-goblin.env',
    // /etc/uptime-goblin.env overrides Environment=, not this command line.
    'ExecStart=/usr/bin/node /opt/uptime-goblin/server.mjs --supervised',
  ])
    assert.match(unit, new RegExp(`^${line}$`, 'm'), line);
  assert.doesNotMatch(unit, /^Restart=on-failure$/m);
  // Every 1.4.2 hardening directive is kept.
  for (const directive of [
    'NoNewPrivileges=yes',
    'PrivateTmp=yes',
    'ProtectSystem=strict',
    'ProtectHome=yes',
    'ReadWritePaths=/var/lib/uptime-goblin',
    'CapabilityBoundingSet=',
    'PrivateDevices=yes',
    'ProtectKernelTunables=yes',
    'ProtectKernelModules=yes',
    'ProtectControlGroups=yes',
    'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX',
    'RestrictNamespaces=yes',
    'RestrictRealtime=yes',
    'RestrictSUIDSGID=yes',
    'LockPersonality=yes',
    'SystemCallArchitectures=native',
    'UMask=0077',
  ])
    assert.match(unit, new RegExp(`^${directive}$`, 'm'), directive);
});

// Whether the Compose CLI is here (no daemon needed). Without it a test skips, unless
// TEST_REQUIRE names docker: then it fails, as test/installer/docker.test.mjs does.
function composeInstalled(t) {
  const version = spawnSync('docker', ['compose', 'version'], {
    encoding: 'utf8',
    timeout: 30000,
    killSignal: 'SIGKILL',
  });
  if (version.status === 0) return true;
  if (required('docker'))
    assert.fail('docker compose is not installed (TEST_REQUIRE=docker needs it)');
  t.skip('docker compose is not installed');
  return false;
}

// The limits are written in compose.yaml itself, as in Codex's maintenance compose.yaml: Docker
// reads 0 (and a negative pids_limit) as no limit, and Compose cannot check what .env gives, so
// an .env value (GOBLIN_PIDS_LIMIT=0, as this branch had) lifted a limit with no check at all.
// They change only through an override file, which is what docs/installation.md describes.
test('compose.yaml and uptime-goblin.service set memory, CPU and process limits, each bounded, none from .env', t => {
  const compose = read('compose.yaml');
  const service = compose.slice(
    compose.indexOf('  uptime-goblin:\n'),
    compose.indexOf('\nvolumes:')
  );
  for (const line of ['mem_limit: 1g', 'memswap_limit: 1g', 'cpus: 1', 'pids_limit: 256'])
    assert.match(service, new RegExp(`^    ${line}$`, 'm'), line);
  assert.doesNotMatch(
    service,
    /^\s+(mem_limit|memswap_limit|cpus|pids_limit|mem_reservation):.*\$/m
  );
  // Plain-HTTP sign-in's start warning needs to know where Compose publishes the port.
  assert.match(
    service,
    /^      GOBLIN_PUBLISHED_ADDRESS: \$\{GOBLIN_BIND_ADDRESS:-\$\{ORBIT_BIND_ADDRESS:-127\.0\.0\.1\}\}$/m
  );
  const unit = read('deploy/uptime-goblin.service');
  for (const line of ['MemoryMax=1G', 'MemorySwapMax=0', 'CPUQuota=200%', 'TasksMax=256'])
    assert.match(unit, new RegExp(`^${line}$`, 'm'), line);
  assert.doesNotMatch(unit, /^(MemoryMax|TasksMax|CPUQuota)=(infinity)?$/m);
  // What Compose makes of them, where its CLI is present (no daemon needed); with
  // TEST_REQUIRE=docker its absence fails, as a skip is never a pass.
  if (!composeInstalled(t)) return;
  const directory = temporary(t, 'orbit-compose-limits-');
  fs.copyFileSync(path.join(repository, 'compose.yaml'), path.join(directory, 'compose.yaml'));
  const config = env =>
    spawnSync('docker', ['compose', 'config', '--format', 'json'], {
      cwd: directory,
      encoding: 'utf8',
      env: {
        PATH: process.env.PATH,
        HOME: process.env.HOME,
        GOBLIN_PASSWORD: 'compose-limits-test-1',
        ...env,
      },
    });
  const limits = env => {
    const result = config(env);
    assert.equal(result.status, 0, result.stderr);
    const { mem_limit, memswap_limit, cpus, pids_limit, environment } = JSON.parse(result.stdout)
      .services['uptime-goblin'];
    return {
      memory: Number(mem_limit),
      swap: Number(memswap_limit),
      cpus: Number(cpus),
      pids: Number(pids_limit),
      published: environment.GOBLIN_PUBLISHED_ADDRESS,
    };
  };
  // One CPU: Docker refuses to create a container allowed more CPUs than its host has, so a
  // higher default stopped every one-CPU host (a small VPS, an LXC, a NAS).
  const shipped = { memory: 2 ** 30, swap: 2 ** 30, cpus: 1, pids: 256, published: '127.0.0.1' };
  assert.deepEqual(limits({}), shipped);
  // What .env (or the shell) holds lifts nothing: the names this branch read, set to what
  // Docker takes for no limit.
  assert.deepEqual(
    limits({ GOBLIN_MEM_LIMIT: '0', GOBLIN_CPUS: '0', GOBLIN_PIDS_LIMIT: '-1' }),
    shipped
  );
  assert.deepEqual(limits({ GOBLIN_BIND_ADDRESS: '0.0.0.0' }), {
    ...shipped,
    published: '0.0.0.0',
  });
  // compose.override.yaml, which Compose reads beside compose.yaml, changes them.
  fs.writeFileSync(
    path.join(directory, 'compose.override.yaml'),
    'services:\n  uptime-goblin:\n    mem_limit: 512m\n    memswap_limit: 512m\n    cpus: 0.5\n    pids_limit: 128\n'
  );
  assert.deepEqual(limits({}), {
    memory: 512 * 2 ** 20,
    swap: 512 * 2 ** 20,
    cpus: 0.5,
    pids: 128,
    published: '127.0.0.1',
  });
});

// A host where Docker refuses any limit on CPU time ("NanoCPUs can not be set …") needs cpus: 0
// with cpuset: '0' in compose.override.yaml (B48: cpus: 0 alone leaves no CPU limit, and a
// supervised Uptime Goblin refuses to start without one), and Compose reads that file by itself only for
// a command given no -f while .env sets no COMPOSE_FILE. Review round 3: the key check, the copy
// and MOVE recipes and the key reset pass -f compose.yaml, and each recipe appends a COMPOSE_FILE line without the
// override, so on such a host they still gave Docker cpus: 1. What the docs say about it
// (test/docs-install-changelog.test.mjs pins the wording), against what Compose renders (no
// daemon needed): every documented `docker compose -f compose.yaml …` command as written, then
// with -f compose.override.yaml after -f compose.yaml, and the COMPOSE_FILE lines in .env.
test('compose.override.yaml reaches the documented -f commands and COMPOSE_FILE lines only as the docs say', t => {
  const commands = [
    ...[...read('docs/installation.md').matchAll(/```sh\n([\s\S]*?)```/g)].flatMap(block =>
      block[1].split('\n')
    ),
    ...read('compose.secret.yaml')
      .split('\n')
      .filter(line => /^# {3}/.test(line))
      .map(line => line.slice(4)),
    ...[...read('docs/troubleshooting.md').matchAll(/`(docker compose -f [^`]*)`/g)].map(
      match => match[1]
    ),
  ]
    .map(line => line.trim())
    .filter(line => /\bdocker compose -f /.test(line));
  // The check and the recipes' two reads, in installation.md and compose.secret.yaml, and the
  // key reset in troubleshooting.md.
  assert.equal(commands.length, 11, commands.join('\n'));
  const prefixes = [...new Set(commands.map(line => line.slice(0, line.indexOf(' run '))))];
  for (const prefix of prefixes) assert.match(prefix, /^docker compose -f compose\.yaml\b/);
  assert.equal(prefixes.length, 3, prefixes.join('\n'));
  // The override the documents give such a host, in their words: one CPU set in place of the CPU
  // time limit Docker refuses there (given in prose, as before, not as a block of its own).
  const override = "services:\n  uptime-goblin:\n    cpus: 0\n    cpuset: '0'\n";
  const given =
    "put `cpus: 0` and `cpuset: '0'` under `services:` → `uptime-goblin:` in `compose.override.yaml`";
  for (const file of ['docs/installation.md', 'docs/troubleshooting.md'])
    assert.ok(read(file).replace(/\s+/g, ' ').includes(given), file);
  if (!composeInstalled(t)) return;
  const directory = temporary(t, 'orbit-compose-override-');
  for (const file of ['compose.yaml', 'compose.secret.yaml'])
    fs.copyFileSync(path.join(repository, file), path.join(directory, file));
  fs.writeFileSync(path.join(directory, 'compose.override.yaml'), override);
  const key = path.join(directory, 'orbit_secret_key');
  const environment = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    GOBLIN_PASSWORD: 'compose-override-test-1',
  };
  // The CPU limits and the secrets Compose gives the uptime-goblin service for a shell command line.
  const rendered = (line, env = environment) => {
    const result = spawnSync('sh', ['-c', `${line} config --format json`], {
      cwd: directory,
      encoding: 'utf8',
      env,
      timeout: 30000,
      killSignal: 'SIGKILL',
    });
    assert.equal(result.status, 0, `${line}: ${result.stderr}`);
    const service = JSON.parse(result.stdout).services['uptime-goblin'];
    return {
      cpus: service.cpus ?? 'none',
      cpuset: service.cpuset ?? 'none',
      secrets: (service.secrets ?? []).map(item => item.source),
    };
  };
  const amend = prefix =>
    prefix.replace(
      'docker compose -f compose.yaml',
      'docker compose -f compose.yaml -f compose.override.yaml'
    );
  for (const withKey of [true, false]) {
    if (withKey) fs.writeFileSync(key, '', { mode: 0o600 });
    else fs.rmSync(key, { force: true });
    for (const prefix of prefixes) {
      // As written: compose.yaml's CPU limit, whatever COMPOSE_FILE says, as -f outranks it.
      const written = rendered(prefix, {
        ...environment,
        COMPOSE_FILE: 'compose.yaml:compose.secret.yaml:compose.override.yaml',
      });
      assert.equal(String(written.cpus), '1', prefix);
      assert.equal(written.cpuset, 'none', prefix);
      // With -f compose.override.yaml after -f compose.yaml: no CPU time limit (Compose leaves
      // cpus: 0 out), CPU 0 alone, the same secrets.
      const amended = rendered(amend(prefix));
      assert.deepEqual(
        amended,
        { cpus: 'none', cpuset: '0', secrets: written.secrets },
        amend(prefix)
      );
    }
  }
  // .env: the line each recipe appends leaves the override out, the last COMPOSE_FILE line
  // counts, and with no COMPOSE_FILE and no -f Compose reads the override by itself.
  const recipeLine = 'COMPOSE_FILE=compose.yaml:compose.secret.yaml';
  const docsLine = 'COMPOSE_FILE=compose.yaml:compose.secret.yaml:compose.override.yaml';
  for (const [lines, cpus] of [
    [[], 'none 0'],
    [[recipeLine], '1 none'],
    [[recipeLine, docsLine], 'none 0'],
    [[docsLine, recipeLine], '1 none'],
  ]) {
    fs.writeFileSync(path.join(directory, '.env'), lines.map(line => `${line}\n`).join(''));
    const { cpus: time, cpuset } = rendered('docker compose');
    assert.equal(`${time} ${cpuset}`, cpus, lines.join(' then ') || 'no .env');
  }
});

// What compose.yaml gives the container besides the limits, as text and as Compose renders it,
// alone and with compose.secret.yaml (which must not drop any of it). The user is named in
// compose.yaml itself, not left to the USER line of whatever image carries uptime-goblin:local.
// test/installer/docker.test.mjs checks the same on a running container.
test('compose.yaml keeps its hardening: uid 1000, read-only root, no capabilities, file and core limits, loopback port, bounded log', t => {
  const compose = read('compose.yaml');
  const service = compose.slice(
    compose.indexOf('  uptime-goblin:\n'),
    compose.indexOf('\nvolumes:')
  );
  const lines = service.split('\n');
  for (const line of [
    "    user: '1000:1000'",
    '    read_only: true',
    '      - /tmp:size=16m,mode=1777',
    '      - no-new-privileges:true',
    "      - '${GOBLIN_BIND_ADDRESS:-${ORBIT_BIND_ADDRESS:-127.0.0.1}}:4317:4317'",
  ])
    assert.ok(lines.includes(line), line);
  assert.match(service, /^ {4}cap_drop:\n {6}- ALL$/m);
  assert.match(
    service,
    /^ {4}ulimits:\n {6}nofile:\n {8}soft: 4096\n {8}hard: 4096\n {6}core: 0$/m
  );
  assert.match(
    service,
    /^ {4}logging:\n {6}driver: json-file\n {6}options:\n {8}max-size: '5m'\n {8}max-file: '2'$/m
  );
  // Nothing that gives back what the lines above take away (security_opt is checked as Compose
  // renders it, below).
  assert.doesNotMatch(
    service,
    /^ {4}(privileged|cap_add|network_mode|pid|ipc|userns_mode|devices|cgroup_parent):/m
  );
  if (!composeInstalled(t)) return;
  const directory = temporary(t, 'orbit-compose-hardening-');
  for (const file of ['compose.yaml', 'compose.secret.yaml'])
    fs.copyFileSync(path.join(repository, file), path.join(directory, file));
  for (const files of [['compose.yaml'], ['compose.yaml', 'compose.secret.yaml']]) {
    const result = spawnSync(
      'docker',
      ['compose', ...files.flatMap(file => ['-f', file]), 'config', '--format', 'json'],
      {
        cwd: directory,
        encoding: 'utf8',
        env: {
          PATH: process.env.PATH,
          HOME: process.env.HOME,
          GOBLIN_PASSWORD: 'compose-hardening-test-1',
        },
      }
    );
    assert.equal(result.status, 0, result.stderr);
    const orbit = JSON.parse(result.stdout).services['uptime-goblin'];
    const what = files.join(' + ');
    assert.equal(orbit.user, '1000:1000', what);
    assert.equal(orbit.read_only, true, what);
    assert.deepEqual(orbit.cap_drop, ['ALL'], what);
    assert.deepEqual(orbit.security_opt, ['no-new-privileges:true'], what);
    assert.deepEqual(orbit.tmpfs, ['/tmp:size=16m,mode=1777'], what);
    // core: 0 (Compose's JSON leaves zero values out, so a set limit of 0 shows as {}).
    assert.deepEqual(orbit.ulimits, { core: {}, nofile: { soft: 4096, hard: 4096 } }, what);
    assert.deepEqual(
      orbit.ports.map(port => [port.host_ip, port.published, port.target]),
      [['127.0.0.1', '4317', 4317]],
      what
    );
    assert.deepEqual(
      orbit.logging,
      { driver: 'json-file', options: { 'max-size': '5m', 'max-file': '2' } },
      what
    );
    assert.deepEqual(
      [orbit.mem_limit, orbit.memswap_limit, orbit.cpus, orbit.pids_limit].map(Number),
      [2 ** 30, 2 ** 30, 1, 256],
      what
    );
  }
});

// The sandbox the unit adds to the 1.4.2 set (C4 above), measured under real systemd with the
// real Uptime Goblin: started, signed in, collected, and the test suites run under it with a filter that
// kills on any call outside the list (test/installer/systemd.test.mjs runs the unit itself).
// Directives that mount a new /proc or message-queue file system, deny calls Uptime Goblin's file copies
// make, or forbid V8's compiler stay out until they are measured where Uptime Goblin is deployed.
test('the systemd unit limits open files and core dumps and keeps Uptime Goblin to the kernel it needs', () => {
  const unit = read('deploy/uptime-goblin.service');
  for (const directive of [
    'LimitNOFILE=4096',
    'LimitCORE=0',
    'ProtectClock=yes',
    'ProtectHostname=yes',
    'ProtectKernelLogs=yes',
    'RemoveIPC=yes',
    'SystemCallFilter=@system-service @pkey',
    'SystemCallErrorNumber=EPERM',
  ])
    assert.match(unit, new RegExp(`^${directive}$`, 'm'), directive);
  assert.equal(unit.match(/^SystemCallFilter=/gm).length, 1, 'one system-call list');
  for (const directive of [
    'MemoryDenyWriteExecute',
    'PrivateUsers',
    'ProtectProc',
    'ProcSubset',
    'PrivateIPC',
    'RestrictFileSystems',
  ])
    assert.doesNotMatch(unit, new RegExp(`^${directive}=`, 'm'), directive);
});

function releaseTree(t) {
  const root = temporary(t, 'orbit-package-');
  const copy = relative => {
    const from = path.join(repository, relative);
    if (!fs.existsSync(from)) return;
    fs.cpSync(from, path.join(root, relative), {
      recursive: true,
      filter: source => {
        const name = path.relative(repository, source).split(path.sep).join('/');
        return (
          path.basename(source) !== '.DS_Store' &&
          !name.startsWith('test/fixtures/releases') &&
          !name.startsWith('test/fixtures/npm')
        );
      },
    });
  };
  for (const item of [
    'README.md',
    'LICENSE',
    '.prettierrc.json',
    '.prettierignore',
    'CONTRIBUTING.md',
    'SECURITY.md',
    'CHANGELOG.md',
    '.gitignore',
    '.dockerignore',
    '.env.example',
    'package.json',
    'package-lock.json',
    'server.mjs',
    'Dockerfile',
    'compose.yaml',
    'compose.secret.yaml',
    'sonar-project.properties',
    'lib',
    'public',
    'deploy',
    'docs',
    'examples',
    'test',
    'scripts',
    '.github',
  ])
    copy(item);
  // Fixtures of old releases must never be packed (each release would nest its predecessors).
  for (const fixture of [
    'test/fixtures/releases/orbit-homelab-1.4.2.tar.gz',
    'test/fixtures/npm/x.tgz',
  ]) {
    fs.mkdirSync(path.dirname(path.join(root, fixture)), { recursive: true });
    fs.writeFileSync(path.join(root, fixture), 'fixture');
  }
  const version = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')).version;
  return { root, name: `uptime-goblin-${version}` };
}

const noAgent = () => {
  const env = { ...process.env };
  delete env.SSH_AUTH_SOCK;
  delete env.ORBIT_SIGNING_KEY;
  return env;
};
const packageRelease = (root, env = {}) =>
  spawnSync(process.execPath, [path.join(root, 'scripts/package-release.mjs')], {
    cwd: root,
    encoding: 'utf8',
    env: { ...noAgent(), ...env },
  });

test('a release archive holds every manifest file and no release fixtures', t => {
  const { root, name } = releaseTree(t);
  const result = packageRelease(root);
  assert.equal(result.status, 0, result.stderr);
  const listing = spawnSync('tar', ['-tzf', path.join(root, 'release', `${name}.tar.gz`)], {
    encoding: 'utf8',
  }).stdout.split('\n');
  for (const file of manifest) assert.ok(listing.includes(`${name}/${file}`), file);
  assert.ok(listing.includes(`${name}/deploy/install.sh`));
  // docs/installation.md and compose.yaml point Docker users at the encryption-key override.
  assert.ok(listing.includes(`${name}/compose.secret.yaml`));
  // The tracked SonarQube scope travels with the source it describes.
  assert.ok(listing.includes(`${name}/sonar-project.properties`));
  assert.ok(listing.includes(`${name}/SHA256SUMS`));
  assert.ok(!listing.includes(`${name}/SHA256SUMS.sig`), 'unsigned without ORBIT_SIGNING_KEY');
  assert.ok(!listing.some(entry => entry.includes('test/fixtures/releases')));
  assert.ok(!listing.some(entry => entry.includes('test/fixtures/npm')));
  const directory = path.join(root, 'release', name);
  for (const line of fs
    .readFileSync(path.join(directory, 'SHA256SUMS'), 'utf8')
    .trim()
    .split('\n')) {
    const [sum, file] = line.split('  ');
    const actual = createHash('sha256')
      .update(fs.readFileSync(path.join(directory, file)))
      .digest('hex');
    assert.equal(actual, sum, file);
  }

  // Packaging refuses a manifest that names a file it would not pack.
  const again = releaseTree(t);
  fs.appendFileSync(path.join(again.root, 'deploy/manifest.txt'), 'test/api.test.mjs\n');
  fs.rmSync(path.join(again.root, 'test/api.test.mjs'));
  const refused = packageRelease(again.root);
  assert.notEqual(refused.status, 0);
  assert.match(refused.stderr, /deploy\/manifest\.txt/);
});

const hasSshKeygen = spawnSync('ssh-keygen', ['-?'], { encoding: 'utf8' }).error?.code !== 'ENOENT';

test('a release refuses a symlink at the root of an allowed source directory', t => {
  const { root, name } = releaseTree(t);
  const outside = temporary(t, 'orbit-outside-release-');
  fs.writeFileSync(path.join(outside, 'internal-note.txt'), 'Fixture: not release material.');
  fs.rmSync(path.join(root, 'examples'), { recursive: true });
  fs.symlinkSync(outside, path.join(root, 'examples'), 'dir');
  const result = packageRelease(root);
  assert.notEqual(
    result.status,
    0,
    'a top-level symlink must not pull outside files into a release'
  );
  assert.match(result.stderr, /Symlinks are not allowed in release inputs: examples/);
  assert.ok(!fs.existsSync(path.join(root, 'release', name)));
  assert.ok(!fs.existsSync(path.join(root, 'release', `${name}.tar.gz`)));
});

test('release directories stay traversable after packaging with a private umask', t => {
  const { root, name } = releaseTree(t);
  const result = spawnSync(
    process.execPath,
    [
      '--input-type=module',
      '-e',
      'process.umask(0o077); await import(process.argv[1]);',
      pathToFileURL(path.join(root, 'scripts/package-release.mjs')).href,
    ],
    { cwd: root, encoding: 'utf8', env: noAgent() }
  );
  assert.equal(result.status, 0, result.stderr);
  const extracted = temporary(t, 'orbit-private-umask-');
  const unpacked = spawnSync(
    'tar',
    // Inspect the archived permissions, without applying the test process's own umask.
    ['-xzpf', path.join(root, 'release', `${name}.tar.gz`), '-C', extracted],
    { encoding: 'utf8' }
  );
  assert.equal(unpacked.status, 0, unpacked.stderr);
  const check = directory => {
    assert.equal(fs.statSync(directory).mode & 0o777, 0o755, directory);
    for (const entry of fs.readdirSync(directory, { withFileTypes: true }))
      if (entry.isDirectory()) check(path.join(directory, entry.name));
  };
  check(path.join(extracted, name));
});

test(
  'ORBIT_SIGNING_KEY signs SHA256SUMS so ssh-keygen -Y verify accepts only the pinned key',
  { skip: hasSshKeygen ? false : 'ssh-keygen is not installed' },
  t => {
    // Throwaway keys in a temporary directory: never a real release key, never ~/.ssh.
    const keys = temporary(t, 'orbit-signing-');
    const keygen = (...args) => {
      const result = spawnSync('ssh-keygen', args, { encoding: 'utf8', env: noAgent() });
      assert.equal(result.status, 0, result.stderr);
      return result;
    };
    keygen(
      '-q',
      '-t',
      'ed25519',
      '-N',
      '',
      '-C',
      'orbit test release',
      '-f',
      path.join(keys, 'release')
    );
    keygen('-q', '-t', 'ed25519', '-N', '', '-C', 'someone else', '-f', path.join(keys, 'other'));
    const signer = file =>
      `release@orbit-homelab namespaces="orbit-release" ${fs.readFileSync(path.join(keys, `${file}.pub`), 'utf8').trim()}\n`;
    fs.writeFileSync(path.join(keys, 'allowed_signers'), signer('release'));
    fs.writeFileSync(path.join(keys, 'other_signers'), signer('other'));

    const { root, name } = releaseTree(t);
    // A tree whose allowed_signers holds no key yet: signing works but cannot be checked.
    const unpinned = path.join(root, 'deploy/allowed_signers');
    fs.writeFileSync(
      unpinned,
      fs
        .readFileSync(unpinned, 'utf8')
        .split('\n')
        .filter(line => !line || line.startsWith('#'))
        .join('\n')
    );
    const result = packageRelease(root, { ORBIT_SIGNING_KEY: path.join(keys, 'release') });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /Signed SHA256SUMS\. deploy\/allowed_signers has no key yet/);
    const directory = path.join(root, 'release', name);
    const listing = spawnSync('tar', ['-tzf', path.join(root, 'release', `${name}.tar.gz`)], {
      encoding: 'utf8',
    }).stdout;
    assert.match(listing, new RegExp(`^${name}/SHA256SUMS\\.sig$`, 'm'));
    // SHA256SUMS does not list the signature (it is made afterwards).
    assert.doesNotMatch(
      fs.readFileSync(path.join(directory, 'SHA256SUMS'), 'utf8'),
      /^[0-9a-f]{64} {2}SHA256SUMS(\.sig)?$/m
    );
    const verify = (signers, input, namespace = 'orbit-release') =>
      spawnSync(
        'ssh-keygen',
        [
          '-Y',
          'verify',
          '-f',
          signers,
          '-I',
          'release@orbit-homelab',
          '-n',
          namespace,
          '-s',
          path.join(directory, 'SHA256SUMS.sig'),
        ],
        { input, encoding: 'utf8', env: noAgent() }
      ).status;
    const sums = fs.readFileSync(path.join(directory, 'SHA256SUMS'));
    assert.equal(verify(path.join(keys, 'allowed_signers'), sums), 0);
    assert.notEqual(verify(path.join(keys, 'other_signers'), sums), 0, 'another key');
    assert.notEqual(
      verify(path.join(keys, 'allowed_signers'), Buffer.concat([sums, Buffer.from('x')])),
      0,
      'tampered'
    );
    assert.notEqual(verify(path.join(keys, 'allowed_signers'), sums, 'file'), 0, 'namespace');
    // The key pinned in the repository accepts no signature made with another key.
    assert.notEqual(verify(path.join(repository, 'deploy/allowed_signers'), sums), 0);

    // Once a key is pinned, packaging refuses to sign with any other key.
    const pinned = releaseTree(t);
    fs.appendFileSync(path.join(pinned.root, 'deploy/allowed_signers'), signer('other'));
    const refused = packageRelease(pinned.root, { ORBIT_SIGNING_KEY: path.join(keys, 'release') });
    assert.notEqual(refused.status, 0);
    assert.match(
      refused.stderr,
      /Signing SHA256SUMS failed; release\/uptime-goblin-[^ ]+ was removed/
    );
    assert.ok(
      !fs.existsSync(path.join(pinned.root, 'release', pinned.name)),
      'nothing half-signed'
    );
    const accepted = releaseTree(t);
    fs.appendFileSync(path.join(accepted.root, 'deploy/allowed_signers'), signer('release'));
    const signed = packageRelease(accepted.root, { ORBIT_SIGNING_KEY: path.join(keys, 'release') });
    assert.equal(signed.status, 0, signed.stderr);
    assert.match(signed.stdout, /the signature verifies against deploy\/allowed_signers/);

    const missing = packageRelease(releaseTree(t).root, {
      ORBIT_SIGNING_KEY: path.join(keys, 'nope'),
    });
    assert.notEqual(missing.status, 0);
    assert.match(missing.stderr, /ORBIT_SIGNING_KEY must name a readable ssh signing key file/);
  }
);

test('deploy/allowed_signers holds only comments or release keys for the orbit-release namespace', () => {
  for (const line of read('deploy/allowed_signers').split('\n')) {
    if (!line.trim() || line.startsWith('#')) continue;
    assert.match(
      line,
      /^release@orbit-homelab namespaces="orbit-release" (ssh-ed25519|sk-ssh-ed25519@openssh\.com|ecdsa-sha2-nistp(256|384|521)|sk-ecdsa-sha2-nistp256@openssh\.com|ssh-rsa) AAAA[0-9A-Za-z+/]+=*( .*)?$/
    );
  }
});

test('an unknown TEST_REQUIRE entry fails the run instead of disabling a check', t => {
  const directory = temporary(t, 'orbit-require-');
  fs.writeFileSync(
    path.join(directory, 'a.test.mjs'),
    "import test from 'node:test';\ntest('a', () => {});\n"
  );
  // A nested runner must not believe it reports to this one.
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const run = value =>
    spawnSync(
      process.execPath,
      [
        '--test',
        '--import',
        path.join(repository, 'test/setup.mjs'),
        path.join(directory, 'a.test.mjs'),
      ],
      { encoding: 'utf8', env: { ...env, TEST_REQUIRE: value } }
    );
  assert.equal(run('browser, fixtures').status, 0);
  const typo = run('browsers');
  assert.notEqual(typo.status, 0);
  assert.match(typo.stdout + typo.stderr, /Unknown TEST_REQUIRE entries: browsers/);
});

// The two Compose checks above, run where no docker command is on PATH: they skip, but with
// TEST_REQUIRE=docker (the full release run) they fail. They skipped, and so passed, either way.
test('without docker compose the Compose checks skip, and fail when TEST_REQUIRE names docker', t => {
  const empty = temporary(t, 'orbit-no-docker-');
  const env = { ...process.env, PATH: empty };
  delete env.NODE_TEST_CONTEXT;
  delete env.TEST_REQUIRE;
  const run = extra =>
    spawnSync(
      process.execPath,
      [
        '--test',
        '--test-reporter=tap',
        '--import',
        path.join(repository, 'test/setup.mjs'),
        '--test-name-pattern',
        '^compose\\.yaml (and uptime-goblin\\.service set|keeps its hardening)',
        path.join(repository, 'test/packaging.test.mjs'),
      ],
      {
        cwd: empty,
        encoding: 'utf8',
        env: { ...env, ...extra },
        timeout: 60000,
        killSignal: 'SIGKILL',
      }
    );
  const count = (output, name) => Number(new RegExp(`^# ${name} (\\d+)$`, 'm').exec(output)?.[1]);
  const totals = output => ['tests', 'fail', 'skipped'].map(name => count(output, name));
  const skipped = run({});
  assert.equal(skipped.status, 0, skipped.stdout + skipped.stderr);
  assert.deepEqual(totals(skipped.stdout), [2, 0, 2], skipped.stdout);
  assert.equal(
    (skipped.stdout.match(/ # SKIP docker compose is not installed$/gm) ?? []).length,
    2,
    skipped.stdout
  );
  const failed = run({ TEST_REQUIRE: 'docker' });
  assert.equal(failed.status, 1, failed.stdout + failed.stderr);
  assert.deepEqual(totals(failed.stdout), [2, 2, 0], failed.stdout);
  assert.equal(
    (
      failed.stdout.match(
        /^ {2}error: 'docker compose is not installed \(TEST_REQUIRE=docker needs it\)'$/gm
      ) ?? []
    ).length,
    2,
    failed.stdout
  );
});

// These two ask Git what .gitignore ignores, so they need Git and a checkout. Without Git they
// skip as test/helpers/git.mjs says (and fail with TEST_REQUIRE=git); a source tree that a
// working Git says is in no repository, such as an unpacked source archive, skips them for that
// reason instead. A Git that cannot answer (it cannot be run, or exits with another status), or
// a repository it cannot read, is broken: they run and fail with what it did, with or without
// TEST_REQUIRE.
const gitSkip = declareGit();
const checkout = gitCheckout(repository);
const checkoutSkip = gitMissing ? gitSkip : checkout.outside ? 'not a git checkout' : false;
// git check-ignore exits 0 for an ignored file and 1 for one that is not; any other result fails
// the test rather than reading as "not ignored".
function ignored(file) {
  const answer = gitProbe(['check-ignore', '--quiet', '--no-index', file], {
    cwd: repository,
    statuses: [0, 1],
  });
  if (answer.broken) assert.fail(answer.broken);
  return answer.status === 0;
}
test(
  'release and npm fixtures can be committed although archives are otherwise ignored',
  { skip: checkoutSkip },
  () => {
    if (checkout.broken) assert.fail(checkout.broken);
    assert.equal(ignored('test/fixtures/releases/orbit-homelab-1.4.2-runtime.tar.gz'), false);
    assert.equal(ignored('test/fixtures/npm/nodemailer-10.0.10.tgz'), false);
    assert.equal(ignored('release/orbit-homelab-1.4.3.tar.gz'), true);
    assert.equal(ignored('orbit-homelab-1.4.3.tar.gz'), true);
  }
);
test(
  "the encryption key files are never committed: compose.secret.yaml's orbit_secret_key and secret.key",
  { skip: checkoutSkip },
  () => {
    if (checkout.broken) assert.fail(checkout.broken);
    // The Compose recipe writes the key beside compose.yaml, with no extension.
    assert.equal(ignored('orbit_secret_key'), true);
    assert.equal(ignored('secret.key'), true);
    assert.equal(ignored('data/secret.key'), true);
    assert.equal(ignored('compose.secret.yaml'), false);
  }
);

// The two tests above as their own runner reports them (Codex's TOOLING-GIT-REQUIRED-P3): a
// copy of the files they load runs in a nested runner, without and with TEST_REQUIRE=git, with
// no git, a git that exits 23, one that answers --version but exits 23 to the probe, one that
// exits 1 silently to everything or to everything but --version (exit 1 is no answer to the
// probe), one that cannot be executed (EACCES), and the real Git: in no repository (a source
// archive), beside a `.git` file naming a directory that is gone (a removed worktree's), in a new
// checkout (also with a `git --version` that fails), and in that checkout with its `.git`
// unreadable. Only a missing optional Git and a source archive may skip; a broken Git, or a
// repository Git cannot read, fails, and never reads as "not a git checkout".
test(
  'the .gitignore tests skip only for a missing optional Git or a source archive, never for a broken Git or an unreadable repository',
  { timeout: 120000 },
  t => {
    if (gitSkip) return t.skip(gitSkip);
    const base = fs.realpathSync(temporary(t, 'orbit-git-probe-'));
    const source = path.join(base, 'source');
    for (const file of [
      '.gitignore',
      'deploy/manifest.txt',
      'lib/store-connections.mjs',
      'scripts/check.mjs',
      'test/helpers/docker-guard.mjs',
      'test/helpers/docker-limits.mjs',
      'test/helpers/git.mjs',
      'test/installer/helpers.mjs',
      'test/packaging.test.mjs',
      'test/setup.mjs',
    ]) {
      fs.mkdirSync(path.dirname(path.join(source, file)), { recursive: true });
      fs.copyFileSync(path.join(repository, file), path.join(source, file));
    }
    const stubs = gitStubs(base);
    const run = (PATH, required) =>
      runNested({
        cwd: source,
        file: 'test/packaging.test.mjs',
        pattern:
          'git is installed|release and npm fixtures|encryption key files are never committed',
        PATH,
        required: required ? 'git' : '',
        ceiling: base,
      });
    const probe = 'git rev-parse --is-inside-work-tree';
    for (const required of [false, true]) {
      const name = what => `${what}, TEST_REQUIRE ${required ? '=git' : 'unset'}`;
      expectNested(
        name('no git'),
        run(stubs.missing, required),
        required
          ? {
              status: 1,
              tests: 3,
              fail: 3,
              says: /TEST_REQUIRE lists git, but git is not installed/,
            }
          : {
              status: 0,
              tests: 2,
              skipped: 2,
              says: /# SKIP git is not installed \(TEST_REQUIRE=git makes this fail\)/,
            }
      );
      // Both tests and the file's `git is installed and runs` fail, whatever TEST_REQUIRE says.
      expectNested(name('a git that exits 23'), run(stubs.exits23, required), {
        status: 1,
        tests: 3,
        fail: 3,
        says: [
          new RegExp(`${probe} exited with status 23`),
          /git is broken: git --version exited with status 23/,
        ],
      });
      expectNested(name('a git that cannot be executed'), run(stubs.unrunnable, required), {
        status: 1,
        tests: 3,
        fail: 3,
        says: [
          new RegExp(`${probe} could not run: spawnSync git EACCES`),
          /git is broken: git --version could not run: spawnSync git EACCES/,
        ],
      });
      // `git --version` works, so only the probe's own status can tell it from an archive.
      expectNested(name('a git whose probe exits 23'), run(stubs.probeExits23, required), {
        status: 1,
        tests: 2,
        fail: 2,
        says: new RegExp(`${probe} exited with status 23`),
      });
      // A silent exit 1, to everything: the file's `git is installed and runs` fails too.
      expectNested(name('a git that exits 1'), run(stubs.exits1, required), {
        status: 1,
        tests: 3,
        fail: 3,
        says: [
          new RegExp(`${probe} exited with status 1\\b`),
          /git is broken: git --version exited with status 1\b/,
        ],
      });
      // `git --version` works, and the probe's silent exit 1 is still no answer: only 0 (and
      // Git's own "not a git repository" with no `.git` where it looked) is.
      expectNested(name('a git whose probe exits 1'), run(stubs.probeExits1, required), {
        status: 1,
        tests: 2,
        fail: 2,
        says: new RegExp(`${probe} exited with status 1\\b`),
      });
      expectNested(name('a source archive'), run(process.env.PATH, required), {
        status: 0,
        tests: 2,
        skipped: 2,
        says: /# SKIP not a git checkout/,
      });
      // Git says `not a git repository: …` and exits 128, as it does outside any repository.
      const gitFile = path.join(source, '.git');
      fs.writeFileSync(gitFile, `gitdir: ${path.join(base, 'gone', '.git', 'worktrees', 'x')}\n`);
      try {
        expectNested(
          name('a .git file naming a missing directory'),
          run(process.env.PATH, required),
          {
            status: 1,
            tests: 2,
            fail: 2,
            says: [
              new RegExp(`${probe} exited with status 128: fatal: not a git repository`),
              /\.git exists: a repository Git cannot read, not a source archive/,
            ],
          }
        );
      } finally {
        fs.rmSync(gitFile);
      }
    }
    // A GIT_DIR of this run's own (a hook's, say) must not be the repository it initialises.
    const init = spawnSync('git', ['init', '--quiet'], {
      cwd: source,
      encoding: 'utf8',
      env: Object.fromEntries(Object.entries(process.env).filter(([n]) => !n.startsWith('GIT_'))),
    });
    assert.equal(init.status, 0, init.error?.message ?? init.stderr);
    for (const required of [false, true]) {
      const name = what => `${what}, TEST_REQUIRE ${required ? '=git' : 'unset'}`;
      expectNested(name('a checkout'), run(process.env.PATH, required), {
        status: 0,
        tests: 2,
        pass: 2,
        says: /^ok \d+ - release and npm fixtures/m,
      });
      // Git's answers in a checkout, from a Git whose `git --version` fails: none counts.
      expectNested(
        name('a checkout and a git whose --version fails'),
        run(stubs.versionFails, required),
        {
          status: 1,
          tests: 3,
          fail: 3,
          says: [
            new RegExp(
              `${probe} exited with status 0, but git is broken: git --version exited with status 1`
            ),
            /git is broken: git --version exited with status 1/,
          ],
        }
      );
    }
    // Git passes over a `.git` it cannot read and says there is no repository at all. (A user
    // who can read it anyway, such as root, has a working checkout: that case does not arise.)
    const gitDirectory = path.join(source, '.git');
    fs.chmodSync(gitDirectory, 0);
    try {
      let readable = true;
      try {
        fs.readdirSync(gitDirectory);
      } catch {
        readable = false;
      }
      if (readable) t.diagnostic('this user can read a mode 000 .git: the unreadable case is moot');
      else
        for (const required of [false, true])
          expectNested(
            `a checkout with an unreadable .git, TEST_REQUIRE ${required ? '=git' : 'unset'}`,
            run(process.env.PATH, required),
            {
              status: 1,
              tests: 2,
              fail: 2,
              says: [
                new RegExp(`${probe} exited with status 128: fatal: not a git repository`),
                /\.git exists: a repository Git cannot read, not a source archive/,
              ],
            }
          );
    } finally {
      fs.chmodSync(gitDirectory, 0o755);
    }
  }
);

// The upgrade suite reads release tags with code of its own (gitTag() in test/upgrade/fixtures.mjs,
// which tests copy without test/helpers/), and its tests as their own runner reports them: a read
// as the file loads (export-tag.test.mjs), skipWithoutTag() and installTag() (build.test.mjs) and
// a direct read (the 1.4.2 fixture test), without and with TEST_REQUIRE=git, under the kinds of
// Git above and a git that exits 1 silently, as Git does for a missing tag (to everything, or to
// everything but --version). The copy is the repository of a synthetic private history input
// (TEST_HISTORY, test/upgrade/history.mjs). No git, a source archive or a checkout without the tag
// leave the tag unavailable, and they skip (TEST_REQUIRE=history, not git, makes the export, build
// and 1.4.2 tests fail then); a broken Git or a repository it cannot read fails them, whatever
// TEST_REQUIRE says. This lives here because a new file in test/upgrade/ would join the git-less
// Node 24 run.
test(
  "the upgrade suite's tag reads skip only for no git, a source archive or a missing tag, never for a broken Git or an unreadable repository",
  { timeout: 180000 },
  t => {
    if (gitSkip) return t.skip(gitSkip);
    const base = fs.realpathSync(temporary(t, 'orbit-git-tags-'));
    const source = path.join(base, 'source');
    for (const item of [
      'lib/admin-command.mjs',
      'lib/container.mjs',
      'lib/environment.mjs',
      'lib/healthcheck.mjs',
      'lib/http/static.mjs',
      'lib/legacy-names.mjs',
      'lib/saved-data.mjs',
      'lib/store-connections.mjs',
      'test/fixtures',
      'test/helpers/build-reference.mjs',
      'test/helpers/docker-guard.mjs',
      'test/helpers/docker-limits.mjs',
      'test/setup.mjs',
      'test/upgrade',
    ])
      fs.cpSync(path.join(repository, item), path.join(source, item), { recursive: true });
    const historyInput = path.join(base, 'history.json');
    fs.writeFileSync(
      historyInput,
      JSON.stringify({
        schema: 'uptime-goblin.private-history.v1',
        repository: 'source',
        milestones: { '1.5.0-dev.0': '0'.repeat(40), '1.5.0-dev.1': '1'.repeat(40) },
        fixtures: {},
        rewrites: [],
      })
    );
    const stubs = gitStubs(base);
    const run = (PATH, required) =>
      runNested({
        cwd: source,
        history: historyInput,
        file: [
          'test/upgrade/export-tag.test.mjs',
          'test/upgrade/build.test.mjs',
          'test/upgrade/fixtures.test.mjs',
        ],
        pattern: '^(export-tag|1\\.4\\.3 keeps the build|the 1\\.4\\.2 fixture matches)',
        PATH,
        required: required ? 'git' : '',
        ceiling: base,
      });
    const probe = tag =>
      `git rev-parse --verify --quiet ${tag.replaceAll('.', '\\.')}\\^\\{commit\\}`;
    // The first export-tag test, the build test and the 1.4.2 test skip, saying why; the
    // export-tag usage test passes.
    const unavailable = (v143, v142) => ({
      status: 0,
      tests: 4,
      pass: 1,
      skipped: 3,
      says: [
        /# SKIP git cannot read v1\.4\.3 here/,
        new RegExp(`# SKIP git cannot read the tag v1\\.4\\.3 \\(${v143}\\)`),
        new RegExp(`# SKIP no git checkout with the v1\\.4\\.2 tag: ${v142}`),
      ],
    });
    // export-tag.test.mjs fails as it loads; the build and 1.4.2 tests fail.
    const broken = what => ({
      status: 1,
      tests: 3,
      fail: 3,
      says: ['v1.4.3', 'v1.4.2'].map(tag => new RegExp(`${probe(tag)} ${what}`)),
    });
    const unreadable = broken('exited with status 128: fatal: not a git repository');
    unreadable.says.push(/\.git exists: a repository Git cannot read, not a source archive/);
    for (const required of [false, true]) {
      const name = what => `${what}, TEST_REQUIRE ${required ? '=git' : 'unset'}`;
      const missing = 'git is not installed';
      expectNested(name('no git'), run(stubs.missing, required), unavailable(missing, missing));
      expectNested(
        name('a git that exits 23'),
        run(stubs.exits23, required),
        broken('exited with status 23')
      );
      expectNested(
        name('a git that cannot be executed'),
        run(stubs.unrunnable, required),
        broken('could not run: spawnSync git EACCES')
      );
      // Its silent exit 1 is what Git says of a missing tag, but its `git --version` fails.
      expectNested(
        name('a git that exits 1'),
        run(stubs.exits1, required),
        broken('exited with status 1, but git is broken: git --version exited with status 1')
      );
      // `git --version` works, so only Git failing to find the repository tells it from a clone
      // without the tag.
      expectNested(
        name('a git whose other commands exit 1'),
        run(stubs.probeExits1, required),
        broken(
          'exited with status 1, which says the repository has no v1\\.4\\.[23], but git rev-parse --git-dir exited with status 1'
        )
      );
      const archive = 'a working Git says this source is in no repository';
      expectNested(
        name('a source archive'),
        run(process.env.PATH, required),
        unavailable(archive, archive)
      );
      // Git's own answer for an archive, from a Git whose `git --version` fails.
      expectNested(
        name('a source archive with a git whose --version fails'),
        run(stubs.versionFails, required),
        broken(
          'exited with status 128: fatal: not a git repository [^\\n]*, but git is broken: git --version exited with status 1'
        )
      );
      const gitFile = path.join(source, '.git');
      fs.writeFileSync(gitFile, `gitdir: ${path.join(base, 'gone', '.git', 'worktrees', 'x')}\n`);
      try {
        expectNested(
          name('a .git file naming a missing directory'),
          run(process.env.PATH, required),
          unreadable
        );
      } finally {
        fs.rmSync(gitFile);
      }
    }
    const init = spawnSync('git', ['init', '--quiet'], {
      cwd: source,
      encoding: 'utf8',
      env: Object.fromEntries(Object.entries(process.env).filter(([n]) => !n.startsWith('GIT_'))),
    });
    assert.equal(init.status, 0, init.error?.message ?? init.stderr);
    for (const required of [false, true]) {
      expectNested(
        `a checkout without the tags, TEST_REQUIRE ${required ? '=git' : 'unset'}`,
        run(process.env.PATH, required),
        unavailable('the repository has no v1\\.4\\.3', 'the repository has no v1\\.4\\.2')
      );
      expectNested(
        `a checkout without the tags and a git whose --version fails, TEST_REQUIRE ${required ? '=git' : 'unset'}`,
        run(stubs.versionFails, required),
        broken('exited with status 1, but git is broken: git --version exited with status 1')
      );
    }
    const gitDirectory = path.join(source, '.git');
    fs.chmodSync(gitDirectory, 0);
    try {
      let readable = true;
      try {
        fs.readdirSync(gitDirectory);
      } catch {
        readable = false;
      }
      if (readable) t.diagnostic('this user can read a mode 000 .git: the unreadable case is moot');
      else
        for (const required of [false, true])
          expectNested(
            `a checkout with an unreadable .git, TEST_REQUIRE ${required ? '=git' : 'unset'}`,
            run(process.env.PATH, required),
            unreadable
          );
    } finally {
      fs.chmodSync(gitDirectory, 0o755);
    }
  }
);

// test:fast, test:browser, test:upgrade, test:installer and test:docker are the CI jobs' suites:
// together they must run every test file exactly once, and npm test must run all of them.
test('the CI suites cover every test file exactly once', () => {
  const scripts = JSON.parse(read('package.json')).scripts;
  const patterns = script =>
    scripts[script]
      .split(' ')
      .filter(word => word.startsWith('"test/') || word.startsWith('test/'))
      .map(word => word.replace(/^"|"$/g, ''));
  const glob = patterns =>
    new Set(patterns.flatMap(pattern => fs.globSync(pattern, { cwd: repository })));
  const all = glob(patterns('test'));
  assert.ok(all.size >= 20);
  assert.deepEqual([...glob(['test/**/*.test.mjs'])].sort(), [...all].sort());
  const suites = ['test:fast', 'test:browser', 'test:upgrade', 'test:installer', 'test:docker'];
  for (const file of all) {
    const owners = suites.filter(suite => glob(patterns(suite)).has(file));
    assert.equal(owners.length, 1, `${file} is run by ${owners.join(', ') || 'no CI suite'}`);
  }
  assert.ok(glob(patterns('test:browser')).has('test/ui.test.mjs'));
  assert.ok(glob(patterns('test:installer')).has('test/installer/installer.test.mjs'));

  const ci = read('.github/workflows/ci.yml');
  for (const [script, requirement] of [
    ['test:fast', 'git'],
    ['test:browser', 'browser'],
    ['test:upgrade', 'fixtures'],
    ['test:installer', 'systemd'],
    ['test:docker', 'docker'],
  ]) {
    const job = ci.split(/\n  (?=[a-z]+:\n)/).find(block => block.includes(`npm run ${script}\n`));
    assert.ok(job, `a CI job runs npm run ${script}`);
    assert.match(job, /timeout-minutes: \d+/);
    if (requirement) assert.match(job, new RegExp(`TEST_REQUIRE: ${requirement}\\n`));
    // Public CI has no private history (TEST_HISTORY): no job requires it or fetches history.
    assert.doesNotMatch(job, /TEST_REQUIRE: [^\n]*history|TEST_HISTORY|fetch-depth/);
  }
  for (const step of [
    'npm run format:check',
    'npm run check',
    'npm audit --omit=dev',
    'npm audit signatures',
  ])
    assert.ok(ci.includes(`run: ${step}\n`), step);
  assert.match(
    ci,
    /docker build --pull -t orbit-installer-systemd:debian13 -f test\/installer\/systemd\.Dockerfile/
  );
});

test('the SonarQube scope names every packed source input outside the documentation and tests', () => {
  const settings = Object.fromEntries(
    read('sonar-project.properties')
      .split('\n')
      .filter(line => /^sonar\./.test(line))
      .map(line => line.split(/=(.*)/s).slice(0, 2))
  );
  const sources = settings['sonar.sources'].split(',');
  assert.deepEqual(settings['sonar.tests'].split(','), ['test']);
  // The packager's own top-level lists: a new source input there must also be analyzed.
  const packager = read('scripts/package-release.mjs');
  const list = name =>
    [...new RegExp(`const ${name} = \\[([^\\]]*)\\]`).exec(packager)[1].matchAll(/'([^']+)'/g)].map(
      match => match[1]
    );
  const packed = [...list('files'), ...list('directories')];
  assert.ok(packed.includes('compose.secret.yaml') && packed.includes('lib'));
  // Prose, licence text, examples, tests and tool settings are reviewed by other means.
  const notSource = new Set([
    'README.md',
    'LICENSE',
    'CONTRIBUTING.md',
    'SECURITY.md',
    'CHANGELOG.md',
    '.prettierrc.json',
    '.prettierignore',
    '.gitignore',
    '.dockerignore',
    'sonar-project.properties',
    'docs',
    'examples',
    'test',
  ]);
  for (const input of packed)
    if (!notSource.has(input)) assert.ok(sources.includes(input), `${input} is in sonar.sources`);
  for (const input of sources) assert.ok(packed.includes(input), `${input} is a packed input`);
});
