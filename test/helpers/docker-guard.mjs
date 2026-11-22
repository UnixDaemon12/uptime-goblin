// The run-time half of the rule that every container a test starts has finite memory, CPU and
// process limits; docker-limits.mjs is the static half, which reads the test files. test/setup.mjs,
// which every test process loads, calls installDockerGuard(): while a real `docker` (or
// `docker-compose`) is on PATH, it puts a stand-in of that name first on PATH, a /bin/sh script in
// a directory of its own. So whatever runs docker by name on that PATH goes through it: a test
// module, a program named in a variable, a shell line, a Compose recipe the docs give.
// installDockerGuard runs each stand-in once by name, as a test would, and throws, failing every
// test file, unless it answers: a search of PATH passes over in silence a stand-in it cannot run (a
// temporary directory mounted noexec, as hardened Linux hosts mount /tmp) or a directory whose path
// holds the PATH separator, and docker would then run unguarded. For the commands that can make or
// change a container, the stand-in runs this module (node docker-guard.mjs -- <real> <name>
// <arguments…>; node reads --env-file even after a script name, but not after --), and only once it
// exits 0 does it exec the real docker with the same arguments; every other command goes straight
// on. Refused, with exit status 125 and a line that names this guard, before Docker sees them
// (dockerProblems):
// - `docker run` and `docker create` (also `container run|create`) without finite --memory,
//   --cpus and --pids-limit right after the subcommand, or with a limit given again before the
//   image: the static rule (runLimitProblems), on the words Docker is given;
// - a Compose command (`docker compose`, `docker-compose`) that can make a container, which is any
//   but those known to make none (ps, logs, exec, stop, down…), unless every service of the
//   project, as Compose itself reads it from the same options, files, environment and .env, with
//   every profile it has (`config --profiles`, then `config --format json`), has a memory limit
//   of at least 6 MiB, at least 0.01 CPUs and a process limit above 0 (mem_limit, cpus and
//   pids_limit, or the same under deploy.resources.limits) (composeProblems). Also refused: a
//   Compose file read from stdin (`-f -`), which that reading would use up, and an option this
//   guard does not know, after which it cannot tell the subcommand;
// - `docker update`, which can change or remove a running container's limits, swarm services
//   (`service`, `stack`), which run containers of their own, a builder that `buildx create` or
//   `builder create` (builder is buildx's alias) can start, and an option before the subcommand
//   (--context, -H), after which the subcommand cannot be told.
// It does not see docker run by a path (/usr/local/bin/docker), which the static check refuses
// where a literal of a test module gives it (its rule 5) and in other files (rule 4), nor a docker
// found ahead of it on PATH (the stand-ins some tests put there, which reach no daemon) or on a
// PATH a test sets without its directory (the static check refuses docker in a literal a module
// hands to another program, rule 5), nor a container made through Docker's API.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { runLimitProblems } from './docker-limits.mjs';

const marker = '.orbit-docker-guard';
const self = fileURLToPath(import.meta.url);
// The docker subcommands the stand-in hands to this module; any other goes straight on.
const guarded = [
  'run',
  'create',
  'container',
  'compose',
  'update',
  'service',
  'stack',
  'buildx',
  'builder',
];
// The word installDockerGuard runs each stand-in with, by name on the PATH it gives, to see that
// the stand-in is what that search finds: it answers with its directory. No docker subcommand.
const probe = 'orbit-guard-probe';
// The Compose subcommands that make no container (they act on those there are, or on images).
// The check of the documented commands reads Compose's options and subcommands with these too.
export const noContainer = new Set([
  'attach',
  'build',
  'config',
  'cp',
  'down',
  'events',
  'exec',
  'images',
  'kill',
  'logs',
  'ls',
  'pause',
  'port',
  'ps',
  'pull',
  'push',
  'restart',
  'rm',
  'start',
  'stats',
  'stop',
  'top',
  'unpause',
  'version',
  'volumes',
  'wait',
]);
// Compose's own options (before its subcommand): those that take a value, and those that do not.
export const composeValues = new Set([
  '-f',
  '--file',
  '-p',
  '--project-name',
  '--project-directory',
  '--env-file',
  '--profile',
  '--ansi',
  '--progress',
  '--parallel',
]);
export const composeFlags = new Set([
  '--all-resources',
  '--compatibility',
  '--dry-run',
  '--verbose',
  '-h',
  '--help',
  '-v',
  '--version',
]);

const memoryMinimum = 6 * 1024 ** 2;
const limitChecks = {
  memory: value =>
    /^\d+$/.test(String(value)) && Number(value) >= memoryMinimum && Number(value) < 2 ** 63,
  cpus: value => Number.isFinite(Number(value)) && Number(value) >= 0.01,
  pids: value => Number.isInteger(Number(value)) && Number(value) > 0,
};

/**
 * What is wrong with the limits of each service of `model`, a Compose project as `docker compose
 * config --format json` gives it: reasons, empty when every service has finite limits.
 */
export function serviceProblems(model) {
  const problems = [];
  for (const [name, service] of Object.entries(model?.services ?? {})) {
    const limits = service?.deploy?.resources?.limits ?? {};
    const given = {
      memory: [service?.mem_limit, limits.memory],
      cpus: [service?.cpus, limits.cpus],
      pids: [service?.pids_limit, limits.pids],
    };
    const wrong = Object.entries(given)
      .filter(([kind, values]) => {
        const set = values.filter(value => value !== undefined && value !== null);
        return !set.length || !set.every(limitChecks[kind]);
      })
      .map(([kind]) => ({ memory: 'mem_limit', cpus: 'cpus', pids: 'pids_limit' })[kind]);
    if (wrong.length)
      problems.push(
        `the Compose service ${name} has no finite ${wrong.join(', ')} (at least 6 MiB of memory, 0.01 CPUs and 1 process)`
      );
  }
  if (!Object.keys(model?.services ?? {}).length)
    problems.push('the Compose project has no services');
  return problems;
}

/**
 * What is wrong with Compose command `args` (its words after `docker compose`, or after
 * `docker-compose`, with `prefix` ['compose'] or []), run by `real` in `cwd` with `env`: reasons,
 * empty when it may run (see the header). Reads the project with `real` when the command can make
 * a container.
 */
export function composeProblems(args, { real, prefix = ['compose'], cwd, env } = {}) {
  const options = [];
  let k = 0;
  for (; k < args.length && args[k].startsWith('-'); k++) {
    const word = args[k];
    const equals = word.startsWith('--') ? word.indexOf('=') : -1;
    const name = equals > 0 ? word.slice(0, equals) : word;
    const attached = /^-[fp]./.test(word);
    if (composeFlags.has(name) && equals < 0) options.push(word);
    else if (attached || (composeValues.has(name) && equals > 0)) {
      const value = attached ? word.slice(2).replace(/^=/, '') : word.slice(equals + 1);
      if (['-f', '--file'].includes(name.slice(0, attached ? 2 : name.length)) && value === '-')
        return ['a Compose file read from stdin (-f -) cannot be checked; write it to a file'];
      options.push(word);
    } else if (composeValues.has(name)) {
      if (k + 1 >= args.length) return [`the Compose option ${word} has no value`];
      if (['-f', '--file'].includes(name) && args[k + 1] === '-')
        return ['a Compose file read from stdin (-f -) cannot be checked; write it to a file'];
      options.push(word, args[++k]);
    } else
      return [
        `the Compose option ${word} is not known to this guard, so it cannot tell which subcommand runs`,
      ];
  }
  const subcommand = args[k];
  if (subcommand === undefined || noContainer.has(subcommand)) return [];
  const read = extra => {
    const result = spawnSync(real, [...prefix, ...options, ...extra], {
      cwd,
      env,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 64 * 1024 * 1024,
      timeout: 120000,
    });
    if (result.status !== 0)
      throw new Error(
        `docker compose ${extra.join(' ')} failed (${result.error?.code ?? result.status}), so the project's limits cannot be checked: ${result.stderr.trim()}`
      );
    return result.stdout;
  };
  try {
    const profiles = read(['config', '--profiles']).split('\n').filter(Boolean);
    const model = JSON.parse(
      read([...profiles.flatMap(profile => ['--profile', profile]), 'config', '--format', 'json'])
    );
    return serviceProblems(model).map(problem => `docker compose ${subcommand}: ${problem}`);
  } catch (error) {
    return [error.message];
  }
}

/**
 * What is wrong with docker command `args` (its words after `docker`): reasons, empty when it may
 * run (see the header). `real`, `cwd` and `env` as composeProblems takes them.
 */
export function dockerProblems(args, context = {}) {
  const [first] = args;
  if (first === undefined) return [];
  if (first.startsWith('-'))
    return args.length === 1 && ['-h', '--help', '-v', '--version'].includes(first)
      ? []
      : [
          `docker is given an option (${first}) before the subcommand, so this guard cannot tell which subcommand runs; choose the daemon with DOCKER_CONTEXT or DOCKER_HOST instead`,
        ];
  const at = first === 'container' ? 1 : 0;
  const subcommand = args[at];
  if (subcommand === 'run' || subcommand === 'create')
    return runLimitProblems(args.slice(at + 1)).map(problem => `docker ${subcommand} ${problem}`);
  if (subcommand === 'update')
    return ["docker update can change or remove a running container's limits"];
  if (at === 0 && (subcommand === 'service' || subcommand === 'stack'))
    return [`docker ${subcommand}: swarm services run containers this guard does not check`];
  // builder is buildx's alias (docker builder create is docker buildx create).
  if (at === 0 && (subcommand === 'buildx' || subcommand === 'builder') && args.includes('create'))
    return [`docker ${subcommand} create can start a builder container this guard does not check`];
  if (at === 0 && subcommand === 'compose') return composeProblems(args.slice(1), context);
  return [];
}

// A word for sh, in single quotes.
const quoted = word => `'${String(word).replaceAll("'", "'\\''")}'`;

/**
 * Puts the stand-in docker (and docker-compose) first on `env.PATH` while a real one is on it,
 * unless the first one there is already a stand-in (a test process started by another). Returns
 * the stand-ins' directory, or null. The directory goes when the process that made it exits.
 */
export function installDockerGuard({ env = process.env, directory = os.tmpdir() } = {}) {
  if (process.platform === 'win32') return null;
  const entries = (env.PATH ?? '').split(path.delimiter).filter(Boolean);
  const find = name => {
    for (const entry of entries) {
      const file = path.resolve(entry, name);
      try {
        fs.accessSync(file, fs.constants.X_OK);
        if (!fs.statSync(file).isFile()) continue;
      } catch {
        continue;
      }
      return { file, guard: fs.existsSync(path.join(entry, marker)) };
    }
    return null;
  };
  const docker = find('docker'),
    compose = find('docker-compose');
  if (docker?.guard || (!docker && compose?.guard)) return null;
  if (!docker && !compose) return null;
  const bin = fs.mkdtempSync(path.join(directory, 'orbit-docker-guard-'));
  process.on('exit', () => fs.rmSync(bin, { recursive: true, force: true }));
  fs.writeFileSync(path.join(bin, marker), '');
  const node = quoted(process.execPath),
    module = quoted(self);
  // Each stand-in answers the probe word with its directory (see below).
  const header = `#!/bin/sh\n# The tests' Docker limits guard: test/helpers/docker-guard.mjs says what it refuses.\nif [ "$1" = ${probe} ]; then printf '%s\\n' ${quoted(bin)}; exit 0; fi\n`;
  if (docker)
    fs.writeFileSync(
      path.join(bin, 'docker'),
      `${header}case "$1" in\n  ${guarded.join('|')}|-*) ${node} ${module} -- ${quoted(docker.file)} docker "$@" || exit $? ;;\nesac\nexec ${quoted(docker.file)} "$@"\n`,
      { mode: 0o755 }
    );
  if (compose)
    fs.writeFileSync(
      path.join(bin, 'docker-compose'),
      `${header}${node} ${module} -- ${quoted(compose.file)} docker-compose "$@" || exit $?\nexec ${quoted(compose.file)} "$@"\n`,
      { mode: 0o755 }
    );
  env.PATH = [bin, ...entries].join(path.delimiter);
  // Each stand-in must be what a search of that PATH runs, or docker would run past it unseen: a
  // search passes over, without an error, a stand-in it cannot run (a temporary directory mounted
  // noexec, as hardened Linux hosts mount /tmp) and a directory whose path holds the PATH
  // separator. So each is run by name, as a test runs docker, with the probe word (spawned by
  // the real docker instead, that word is an unknown command, which starts nothing): the guard
  // fails, and with it every test file, unless each stand-in answers with its directory.
  const options = { env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 120000 };
  for (const [name, run] of [
    ['docker', docker && (() => spawnSync('docker', ['orbit-guard-probe'], options))],
    [
      'docker-compose',
      compose && (() => spawnSync('docker-compose', ['orbit-guard-probe'], options)),
    ],
  ]) {
    const result = run ? run() : null;
    if (result && (result.status !== 0 || result.stdout !== `${bin}\n`))
      throw new Error(
        `The tests' Docker limits guard (test/helpers/docker-guard.mjs) wrote its ${name} to ${bin}, first on PATH, but ${name} run by name did not run it (${result.error?.code ?? `exit status ${result.status}`}, ${JSON.stringify(`${result.stdout ?? ''}${result.stderr ?? ''}`.trim().slice(0, 200))}), so ${name} would run unguarded. The temporary directory ${directory} may be mounted noexec, or its path may hold "${path.delimiter}": set TMPDIR to a directory where files can run.`
      );
  }
  return bin;
}

// Run by the stand-in: node docker-guard.mjs -- <real> <docker|docker-compose> <arguments…>.
if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  const [real, name, ...args] = process.argv.slice(process.argv[2] === '--' ? 3 : 2);
  const context = { real, cwd: process.cwd(), env: process.env };
  const problems =
    name === 'docker-compose'
      ? composeProblems(args, { ...context, prefix: [] })
      : dockerProblems(args, context);
  for (const problem of problems)
    process.stderr.write(
      `${name} (refused by the tests' Docker limits guard, test/helpers/docker-guard.mjs): ${problem}\n`
    );
  process.exitCode = problems.length ? 125 : 0;
}
