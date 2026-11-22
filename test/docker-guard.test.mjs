// The run-time half of the Docker limits rule (test/helpers/docker-guard.mjs, installed by
// test/setup.mjs): what the stand-in docker refuses before Docker sees it, against a stand-in of
// the real docker that answers Compose's `config` and records what reaches it. No Docker needed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  composeProblems,
  dockerProblems,
  installDockerGuard,
  serviceProblems,
} from './helpers/docker-guard.mjs';

const limits = ['--memory=1g', '--cpus=2', '--pids-limit=256'];
const limited = { mem_limit: '1073741824', cpus: 2, pids_limit: 256 };

// A stand-in for the real docker (and docker-compose) in a directory of its own: it records each
// call (its arguments, one JSON line each) and answers `config --profiles` and `config --format
// json` from model.json in its directory, or fails `config` when fail.txt is there, with its text;
// any other call with the word cat copies its stdin to its stdout, and one with fail exits 3.
function fakeDocker(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-docker-guard-test-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const bin = path.join(root, 'bin');
  fs.mkdirSync(bin);
  const script = path.join(root, 'fake.cjs');
  fs.writeFileSync(
    script,
    `const fs = require('node:fs'), path = require('node:path');
const root = ${JSON.stringify(root)};
const args = process.argv.slice(3);
fs.appendFileSync(path.join(root, 'calls'), JSON.stringify(args) + '\\n');
const at = args.indexOf('config');
if (at >= 0) {
  if (fs.existsSync(path.join(root, 'fail.txt'))) {
    process.stderr.write(fs.readFileSync(path.join(root, 'fail.txt'), 'utf8'));
    process.exit(15);
  }
  const model = JSON.parse(fs.readFileSync(path.join(root, 'model.json'), 'utf8'));
  if (args[at + 1] === '--profiles') process.stdout.write((model.profiles ?? []).map(p => p + '\\n').join(''));
  else process.stdout.write(JSON.stringify({ services: model.services }));
} else {
  if (args.includes('cat')) process.stdout.write(fs.readFileSync(0));
  if (args.includes('fail')) process.exit(3);
}
`
  );
  for (const name of ['docker', 'docker-compose'])
    fs.writeFileSync(
      path.join(bin, name),
      `#!/bin/sh\nexec '${process.execPath}' '${script}' -- "$@"\n`,
      { mode: 0o755 }
    );
  return {
    root,
    bin,
    real: path.join(bin, 'docker'),
    model: model => fs.writeFileSync(path.join(root, 'model.json'), JSON.stringify(model)),
    fail: text => fs.writeFileSync(path.join(root, 'fail.txt'), text),
    calls: () =>
      fs.existsSync(path.join(root, 'calls'))
        ? fs
            .readFileSync(path.join(root, 'calls'), 'utf8')
            .split('\n')
            .filter(Boolean)
            .map(line => JSON.parse(line))
        : [],
  };
}

test('the Docker guard refuses docker run and create without limits, and what it cannot follow', () => {
  const refused = (args, why) => {
    const problems = dockerProblems(args);
    assert.equal(problems.length, 1, `${args.join(' ')}: ${problems.join('; ')}`);
    assert.match(problems[0], why, args.join(' '));
  };
  for (const args of [
    ['ps'],
    ['version', '--format', '{{.Server.Version}}'],
    ['--version'],
    ['exec', 'orbit', 'sh'],
    ['image', 'rm', '--force', 'x'],
    ['build', '--tag', 'x', '.'],
    ['buildx', 'build', '.'],
    ['builder', 'prune', '--force'],
    ['run', ...limits, '--rm', 'img'],
    ['container', 'create', '-m', '512m', '--cpus', '0.5', '--pids-limit', '64', 'img'],
    ['run', ...limits, '--rm', 'img', 'sh', '-c', 'free -m', '--memory=0'],
    ['compose', 'version'],
    ['compose', '-p', 'x', 'logs', 'orbit'],
  ])
    assert.deepEqual(dockerProblems(args), [], args.join(' '));
  refused(['run', '--rm', 'img'], /^docker run without finite --memory, --cpus, --pids-limit/);
  refused(['create', '--memory=1g', '--cpus=2', 'img'], /without finite --pids-limit/);
  refused(['container', 'run', '--memory=0.5', '--cpus=2', '--pids-limit=9', 'i'], /--memory/);
  refused(['run', ...limits, '--rm', '--memory=0', 'img'], /gives --memory=0 again/);
  refused(['run', ...limits, '--rm', '-m', '0', 'img'], /gives -m again/);
  refused(['update', '--memory=0', 'x'], /docker update can change or remove/);
  refused(['container', 'update', '--pids-limit=-1', 'x'], /docker update/);
  refused(['service', 'create', 'img'], /swarm services/);
  refused(['stack', 'deploy', '-c', 'x.yaml', 's'], /swarm services/);
  refused(['buildx', 'create', '--driver', 'docker-container'], /builder container/);
  // builder is buildx's alias: `docker builder create` is `docker buildx create`.
  refused(['builder', 'create', '--driver', 'docker-container'], /^docker builder create can/);
  refused(['--context', 'other', 'run', '--rm', 'img'], /an option \(--context\) before/);
  refused(['-H', 'unix:///run/docker.sock', 'ps'], /an option \(-H\) before/);
});

test('the Docker guard checks every service of a Compose project, as Compose reads it, before it can make a container', t => {
  const fake = fakeDocker(t);
  const context = { real: fake.real, cwd: fake.root, env: process.env };
  const check = (args, extra = {}) => composeProblems(args, { ...context, ...extra });
  // Limited services: accepted, read with every profile the project has, with the command's own
  // options; mem_limit, cpus and pids_limit or deploy.resources.limits.
  fake.model({
    profiles: ['extra'],
    services: {
      orbit: limited,
      receiver: { deploy: { resources: { limits: { memory: '536870912', cpus: 0.5, pids: 10 } } } },
    },
  });
  assert.deepEqual(check(['--project-name', 'p', '-f', 'a.yaml', '--env-file=e', 'up', '-d']), []);
  assert.deepEqual(fake.calls(), [
    ['compose', '--project-name', 'p', '-f', 'a.yaml', '--env-file=e', 'config', '--profiles'],
    [
      'compose',
      '--project-name',
      'p',
      '-f',
      'a.yaml',
      '--env-file=e',
      '--profile',
      'extra',
      'config',
      '--format',
      'json',
    ],
  ]);
  assert.deepEqual(check(['run', '--rm', 'orbit', 'true']), []);
  assert.deepEqual(check(['up', '-d'], { prefix: [] }), []);
  assert.deepEqual(fake.calls().at(-1).slice(0, 3), ['--profile', 'extra', 'config']);
  // Commands that make no container are not read.
  const before = fake.calls().length;
  for (const args of [['ps', '--all'], ['logs', 'orbit'], ['exec', '-T', 'orbit', 'sh'], ['down']])
    assert.deepEqual(check(args), [], args.join(' '));
  assert.equal(fake.calls().length, before);
  // A service without a limit, or with one that is no limit, is refused by name.
  for (const [service, missing] of [
    [{ mem_limit: '1073741824', cpus: 2 }, 'pids_limit'],
    [{ ...limited, mem_limit: '1' }, 'mem_limit'],
    [{ ...limited, cpus: 0.001 }, 'cpus'],
    [{ ...limited, pids_limit: -1 }, 'pids_limit'],
    [{ cpus: 2 }, 'mem_limit, pids_limit'],
    [{ ...limited, deploy: { resources: { limits: { memory: '0' } } } }, 'mem_limit'],
  ]) {
    fake.model({ services: { orbit: limited, ticker: service } });
    assert.deepEqual(check(['up', '-d']), [
      `docker compose up: the Compose service ticker has no finite ${missing} (at least 6 MiB of memory, 0.01 CPUs and 1 process)`,
    ]);
  }
  assert.deepEqual(serviceProblems({ services: {} }), ['the Compose project has no services']);
  // What cannot be read is refused: Compose failing to read the project, a file from stdin, an
  // option this guard does not know.
  fake.model({ services: { orbit: limited } });
  fake.fail(
    'required variable ORBIT_PASSWORD is missing a value: Set ORBIT_PASSWORD in .env first\n'
  );
  assert.match(
    check(['up', '-d']).join(),
    /^docker compose config --profiles failed \(15\), so the project's limits cannot be checked: required variable ORBIT_PASSWORD/
  );
  fs.rmSync(path.join(fake.root, 'fail.txt'));
  const calls = fake.calls().length;
  for (const args of [
    ['-f', '-', 'up'],
    ['--file=-', 'up'],
    ['-f-', 'up'],
  ])
    assert.match(check(args).join(), /a Compose file read from stdin/, args.join(' '));
  assert.match(check(['--wat', 'up']).join(), /the Compose option --wat is not known/);
  assert.match(check(['-f']).join(), /has no value/);
  assert.equal(fake.calls().length, calls);
});

test('the Docker guard stands first on PATH, and refuses before the real docker sees anything', t => {
  const fake = fakeDocker(t);
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-docker-guard-path-'));
  t.after(() => fs.rmSync(scratch, { recursive: true, force: true }));
  const env = { PATH: [fake.bin, '/usr/bin', '/bin'].join(path.delimiter) };
  const bin = installDockerGuard({ env, directory: scratch });
  assert.ok(bin && env.PATH.startsWith(`${bin}${path.delimiter}${fake.bin}`), env.PATH);
  for (const name of ['docker', 'docker-compose']) assert.ok(fs.existsSync(path.join(bin, name)));
  // A process it starts with that PATH does not stand another guard in front.
  assert.equal(installDockerGuard({ env: { ...env }, directory: scratch }), null);
  // No docker and no docker-compose on PATH: nothing to guard. A directory of the test's own, since
  // a Linux host with Docker has /usr/bin/docker.
  const empty = path.join(scratch, 'empty');
  fs.mkdirSync(empty);
  assert.equal(installDockerGuard({ env: { PATH: empty }, directory: scratch }), null);
  const run = (program, args, options = {}) =>
    spawnSync(program, args, { env, cwd: fake.root, encoding: 'utf8', ...options });
  const refusal = /\(refused by the tests' Docker limits guard, test\/helpers\/docker-guard\.mjs\)/;
  // Refused: by name from a module, from a shell line, a Compose project without limits.
  fake.model({ services: { orbit: { mem_limit: '1073741824', cpus: 2 } } });
  for (const [program, args] of [
    ['docker', ['run', '--rm', 'img']],
    ['sh', ['-c', 'x=docker; "$x" create img']],
    ['docker', ['compose', 'up', '-d']],
    ['sh', ['-c', 'docker compose -p p run --rm orbit true']],
    ['docker-compose', ['up', '-d']],
    ['docker', ['--context', 'other', 'run', ...limits, 'img']],
    ['docker', ['builder', 'create', '--name', 'b', '--driver', 'docker-container', '--bootstrap']],
  ]) {
    const result = run(program, args);
    assert.equal(result.status, 125, `${program} ${args.join(' ')}: ${result.stderr}`);
    assert.match(result.stderr, refusal);
  }
  assert.deepEqual(
    fake.calls().filter(args => !args.includes('config')),
    [],
    'nothing but config reached the real docker'
  );
  // Passed on, with the same arguments, stdin and exit status.
  fake.model({ services: { orbit: limited } });
  assert.equal(run('docker', ['run', ...limits, '--rm', 'img']).status, 0);
  assert.equal(run('sh', ['-c', 'docker compose up -d && docker ps -a']).status, 0);
  assert.equal(run('docker-compose', ['-p', 'p', 'up', '-d']).status, 0);
  assert.equal(run('docker', ['version']).status, 0);
  // node, which runs the guard, reads --env-file wherever it is given, unless after --.
  assert.equal(run('docker', ['compose', '--env-file', 'missing.env', 'up', '-d']).status, 0);
  const piped = run('docker', ['compose', 'run', '-T', 'orbit', 'cat'], { input: 'piped' });
  assert.deepEqual([piped.status, piped.stdout], [0, 'piped']);
  assert.equal(run('docker', ['compose', 'up', 'fail']).status, 3);
  assert.deepEqual(
    fake.calls().filter(args => !args.includes('config')),
    [
      ['run', ...limits, '--rm', 'img'],
      ['compose', 'up', '-d'],
      ['ps', '-a'],
      ['-p', 'p', 'up', '-d'],
      ['version'],
      ['compose', '--env-file', 'missing.env', 'up', '-d'],
      ['compose', 'run', '-T', 'orbit', 'cat'],
      ['compose', 'up', 'fail'],
    ]
  );
});

// A search of PATH passes over, without an error, a stand-in it cannot run (a temporary directory
// mounted noexec, as hardened Linux hosts mount /tmp, and Docker mounts /dev/shm in a container)
// and a directory whose path holds the PATH separator, and docker then runs unguarded. So the
// guard runs each stand-in by name first, and fails, and with it every test file, unless the
// stand-in answers.
test('the Docker guard fails when its stand-ins are not what a search of PATH runs', t => {
  const fake = fakeDocker(t);
  const env = () => ({ PATH: [fake.bin, '/usr/bin', '/bin'].join(path.delimiter) });
  const unguarded =
    /did not run it .*so docker would run unguarded\. The temporary directory .* may be mounted noexec, or its path may hold/;
  // A directory whose path holds the separator: the search splits it, and finds the real docker,
  // which takes the probe word for an unknown command and starts nothing.
  const split = fs.mkdtempSync(path.join(os.tmpdir(), `orbit-docker-guard-${path.delimiter}`));
  t.after(() => fs.rmSync(split, { recursive: true, force: true }));
  assert.throws(() => installDockerGuard({ env: env(), directory: split }), unguarded);
  assert.deepEqual(fake.calls(), [['orbit-guard-probe']], 'the probe word reached the real docker');
  // Where it can run, it answers and stands first.
  const fine = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-docker-guard-fine-'));
  t.after(() => fs.rmSync(fine, { recursive: true, force: true }));
  const ok = env();
  const bin = installDockerGuard({ env: ok, directory: fine });
  assert.ok(bin && ok.PATH.startsWith(bin), ok.PATH);
  assert.equal(fake.calls().length, 1, 'the stand-ins answered the probe themselves');
  // A filesystem mounted noexec (in a Docker container, /dev/shm): only where there is one.
  let noexec = null;
  if (fs.existsSync('/dev/shm')) {
    const shm = fs.mkdtempSync(path.join('/dev/shm', 'orbit-docker-guard-exec-'));
    t.after(() => fs.rmSync(shm, { recursive: true, force: true }));
    fs.writeFileSync(path.join(shm, 'exec-check'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
    noexec = spawnSync(path.join(shm, 'exec-check')).error?.code === 'EACCES';
  }
  if (noexec)
    assert.throws(() => installDockerGuard({ env: env(), directory: '/dev/shm' }), unguarded);
  else t.diagnostic(`no noexec /dev/shm here (${noexec === null ? 'none' : 'it can run files'})`);
});
