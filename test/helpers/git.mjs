// Git, for the tests that run it. Git is a development tool: the shipped image has none, and
// neither has the node:24-bookworm-slim container of the git-less Node 24 test run. A test that
// runs Git says so with the value declareGit() returns, as its `skip` option or as the first
// statement of its body (`if (gitSkip) return t.skip(gitSkip);`, which keeps the test's own
// layout). Without Git such a test is skipped with a reason that names TEST_REQUIRE=git, unless
// TEST_REQUIRE lists `git` (see test/setup.mjs), as the security gate's full test runs do: then
// it runs, and fails, and its file reports one more failing test that says why. Only a missing
// executable can skip: any other result of `git --version` (no permission to run it, an exit
// status, a crash) means a broken Git, and the tests run and fail, with or without TEST_REQUIRE,
// and their file reports a failing `git is installed and runs` test that says why.
//
// A test that asks Git about the source itself (is it a checkout, has it a tag) uses gitProbe():
// the only answers that may skip are a working Git saying so (`outside`: not in a repository, as
// in an unpacked source archive, where Git's search met no `.git`; or the status the caller
// names, such as a missing tag, which the caller confirms by asking Git for the repository it
// found). Every other result is `broken`, which the test must fail on rather than read as such an
// answer: that includes any answer of a git whose `git --version` fails, and a repository Git
// cannot read (an unreadable `.git`, or a worktree's `.git` file naming a directory that is
// gone), which Git reports as no repository at all. test/upgrade/fixtures.mjs reads tags the
// same way, with code of its own.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';

/** Whether TEST_REQUIRE (comma-separated) lists `git`. */
export const gitRequired = (process.env.TEST_REQUIRE || '')
  .split(',')
  .map(name => name.trim())
  .includes('git');

// Git's own messages, untranslated: gitProbe() recognises "not a git repository" by its text.
function environment() {
  const env = { ...process.env, LC_ALL: 'C' };
  delete env.LANGUAGE;
  return env;
}

/** Why `command`'s spawnSync `result` is not a run that exited with one of `statuses`, or false. */
function failure(command, result, statuses) {
  if (result.error) return `${command} could not run: ${result.error.message}`;
  if (result.signal) return `${command} was ended by ${result.signal}`;
  if (statuses.includes(result.status)) return false;
  const stderr = String(result.stderr ?? '').trim();
  return `${command} exited with status ${result.status}${stderr ? `: ${stderr.slice(0, 500)}` : ''}`;
}

const version = spawnSync('git', ['--version'], { encoding: 'utf8', env: environment() });

/** Whether there is no `git` executable on PATH (spawning it fails with ENOENT). */
export const gitMissing = version.error?.code === 'ENOENT';

/** Why the `git` on PATH is broken (it exists but `git --version` does not work), or false. */
export const gitBroken = gitMissing
  ? false
  : failure('git --version', version, [0]) ||
    (/^git version \S/.test(version.stdout)
      ? false
      : `git --version printed ${JSON.stringify(version.stdout.slice(0, 200))}`);

/** Why a test that runs Git is skipped here, or false when it runs. */
export const gitSkip =
  gitMissing && !gitRequired ? 'git is not installed (TEST_REQUIRE=git makes this fail)' : false;

/**
 * Call once, at the top level of a test file whose tests run Git: returns why those tests skip
 * (false when they run), and registers a failing test when TEST_REQUIRE lists git and there is
 * none, or when the git there is broken.
 */
export function declareGit() {
  if (gitMissing && gitRequired)
    test('git is installed (TEST_REQUIRE=git)', () =>
      assert.fail('TEST_REQUIRE lists git, but git is not installed'));
  if (gitBroken)
    test('git is installed and runs', () => assert.fail(`git is broken: ${gitBroken}`));
  return gitSkip;
}

/**
 * The `.git` that Git's search for a repository from `directory` meets: in the directory, then in
 * each parent below the nearest GIT_CEILING_DIRECTORIES entry and, unless
 * GIT_DISCOVERY_ACROSS_FILESYSTEM is set, on the same filesystem. Returns its path, or false when
 * there is none. Git passes over a `.git` it cannot read and says there is no repository; an
 * entry that is there, or that cannot be looked for, means the source is not an archive.
 * (test/upgrade/fixtures.mjs has a copy: tests copy test/upgrade/ without test/helpers/.)
 */
function gitEntry(directory) {
  const real = name => {
    try {
      return fs.realpathSync(name);
    } catch {
      return path.resolve(name);
    }
  };
  const ceilings = new Set(
    (process.env.GIT_CEILING_DIRECTORIES ?? '')
      .split(path.delimiter)
      .filter(entry => path.isAbsolute(entry))
      .map(real)
  );
  const across = /^(1|true|yes|on)$/i.test(process.env.GIT_DISCOVERY_ACROSS_FILESYSTEM ?? '');
  let current = real(directory);
  for (;;) {
    const entry = path.join(current, '.git');
    try {
      fs.lstatSync(entry);
      return entry;
    } catch (error) {
      if (error.code !== 'ENOENT' && error.code !== 'ENOTDIR') return entry;
    }
    const parent = path.dirname(current);
    if (parent === current || ceilings.has(parent)) return false;
    try {
      if (!across && fs.statSync(parent).dev !== fs.statSync(current).dev) return false;
    } catch {
      return false; // Git cannot go up into a directory it cannot examine either.
    }
    current = parent;
  }
}

// What Git says when its search for a repository met no `.git`.
const searchFoundNothing =
  /^fatal: not a git repository \(or any (of the parent directories|parent up to mount point)\b/m;

/**
 * Runs `git <args>` in `cwd` to ask about the source. Returns spawnSync's result (`encoding`
 * 'buffer' keeps stdout as bytes) with `outside`, true when a working Git said the directory it
 * searched from (`cwd`, moved by leading `-C` options) is in no repository and gitEntry() finds
 * no `.git` there, and `broken`, false when a working Git ran and exited with one of `statuses`
 * (or `outside`) and otherwise why not: a missing or unrunnable git, a signal, any other exit
 * status, a git whose `git --version` fails (whatever it answered here), or no repository where
 * a `.git` is (one Git cannot read).
 */
export function gitProbe(args, { cwd, statuses = [0], encoding = 'utf8' } = {}) {
  const result = spawnSync('git', args, {
    cwd,
    encoding,
    env: environment(),
    maxBuffer: 64 * 2 ** 20,
  });
  const stderr = String(result.stderr ?? '');
  const noRepository =
    !gitMissing &&
    !gitBroken &&
    !result.error &&
    result.status === 128 &&
    /^fatal: not a git repository\b/m.test(stderr);
  let directory = path.resolve(cwd ?? '.');
  for (let at = 0; args[at] === '-C' && at + 1 < args.length; at += 2)
    directory = path.resolve(directory, args[at + 1]);
  const entry = noRepository && gitEntry(directory);
  // Not `not a git repository: <path>`: a `.git` file or GIT_DIR naming a non-repository.
  const outside = noRepository && !entry && searchFoundNothing.test(stderr);
  const command = `git ${args.join(' ')}`;
  const broken = outside
    ? false
    : failure(command, result, statuses) ||
      (gitBroken &&
        `${command} exited with status ${result.status}, but git is broken: ${gitBroken}`);
  return {
    ...result,
    outside,
    broken:
      broken && entry
        ? `${broken} (but ${entry} exists: a repository Git cannot read, not a source archive)`
        : broken,
  };
}

/**
 * What Git says of `directory`: `checkout` true in a work tree; `outside` true when a working
 * Git says it is in no repository (an unpacked source archive, which may skip); otherwise
 * `broken` says why Git could not tell, and a test that needs a checkout must fail.
 */
export function gitCheckout(directory) {
  const probe = gitProbe(['rev-parse', '--is-inside-work-tree'], { cwd: directory });
  if (probe.outside || probe.broken)
    return { checkout: false, outside: probe.outside, broken: probe.broken };
  const answer = probe.stdout.trim();
  return answer === 'true'
    ? { checkout: true, outside: false, broken: false }
    : {
        checkout: false,
        outside: false,
        broken: `git rev-parse --is-inside-work-tree printed ${JSON.stringify(answer)}, not true`,
      };
}

// The regressions of these decisions (the maintainer's TOOLING-GIT-REQUIRED-P3) run a test file as its own
// runner reports it, under each kind of Git, with the helpers below.

/**
 * PATH directories under `base` (which must exist): `missing` holds no git; `exits23` a git that
 * exits 23; `probeExits23` one that answers `git --version` but exits 23 to anything else;
 * `exits1` one that exits 1 and says nothing, as Git does for a missing tag; `probeExits1` one
 * that answers `git --version` but does that to anything else; `unrunnable` one that cannot be
 * executed (EACCES); and `versionFails` this PATH's Git with a `git --version` that exits 1.
 * `commands` links every other command on this PATH, for a run that needs them (Chrome's
 * launcher script) but must not find Git.
 */
export function gitStubs(base) {
  const bin = (name, script, mode) => {
    const directory = path.join(base, name);
    fs.mkdirSync(directory);
    if (script) fs.writeFileSync(path.join(directory, 'git'), script, { mode });
    return directory;
  };
  const commands = bin('commands'),
    linked = new Set(['git']);
  let git; // The Git this PATH runs.
  for (const directory of (process.env.PATH ?? '').split(path.delimiter)) {
    if (!path.isAbsolute(directory)) continue;
    let names;
    try {
      names = fs.readdirSync(directory);
    } catch {
      continue; // A PATH entry that does not exist or cannot be listed provides nothing.
    }
    for (const name of names)
      if (!linked.has(name)) {
        linked.add(name);
        fs.symlinkSync(path.join(directory, name), path.join(commands, name));
      }
    if (!git && names.includes('git'))
      try {
        fs.accessSync(path.join(directory, 'git'), fs.constants.X_OK);
        git = path.join(directory, 'git');
      } catch {
        // Not one the shell would run either.
      }
  }
  if (git?.includes("'")) throw new Error(`gitStubs cannot quote ${git}`);
  return {
    missing: bin('missing'),
    exits23: bin('exits-23', '#!/bin/sh\nexit 23\n', 0o755),
    probeExits23: bin(
      'probe-exits-23',
      '#!/bin/sh\n[ "$1" = --version ] && echo "git version 2.99.0" && exit 0\nexit 23\n',
      0o755
    ),
    exits1: bin('exits-1', '#!/bin/sh\nexit 1\n', 0o755),
    probeExits1: bin(
      'probe-exits-1',
      '#!/bin/sh\n[ "$1" = --version ] && echo "git version 2.99.0" && exit 0\nexit 1\n',
      0o755
    ),
    unrunnable: bin('unrunnable', '#!/bin/sh\nexit 0\n', 0o600),
    // PATH's Git, but `git --version` exits 1 (null when PATH has no git).
    versionFails: git
      ? bin(
          'version-fails',
          `#!/bin/sh\n[ "$1" = --version ] && exit 1\nexec '${git}' "$@"\n`,
          0o755
        )
      : null,
    commands,
  };
}

/**
 * Runs the tests of `file` (relative to `cwd`; or an array of files) whose names match `pattern`
 * in a nested runner, with `PATH`, TEST_REQUIRE set to `required` (unset when empty),
 * TEST_HISTORY set to `history` (unset when empty), no GIT_ variable, TEST_TAG_TREES or
 * TEST_HISTORY of this run's own and Git looking for a repository no higher than `ceiling`. Returns the exit status, the TAP totals and the output.
 */
export function runNested({ cwd, file, pattern, PATH, required, ceiling, history }) {
  const env = {};
  for (const [name, value] of Object.entries(process.env))
    if (
      !name.startsWith('GIT_') &&
      !['NODE_TEST_CONTEXT', 'TEST_REQUIRE', 'TEST_TAG_TREES', 'TEST_HISTORY'].includes(name)
    )
      env[name] = value;
  Object.assign(env, { PATH, GIT_CEILING_DIRECTORIES: ceiling });
  if (required) env.TEST_REQUIRE = required;
  if (history) env.TEST_HISTORY = history;
  const result = spawnSync(
    process.execPath,
    [
      '--test',
      '--test-reporter=tap',
      '--import',
      './test/setup.mjs',
      `--test-name-pattern=${pattern}`,
      ...[file].flat(),
    ],
    { cwd, env, encoding: 'utf8', timeout: 60000 }
  );
  const count = name => Number(new RegExp(`^# ${name} (\\d+)$`, 'm').exec(result.stdout)?.[1]);
  return {
    status: result.status,
    counts: Object.fromEntries(['tests', 'pass', 'fail', 'skipped'].map(n => [n, count(n)])),
    output: `${result.error?.message ?? ''}${result.stdout}${result.stderr}`,
  };
}

/** Asserts a runNested() outcome: its exit status, TAP totals and what its output `says`. */
export function expectNested(
  what,
  outcome,
  { status, tests, pass = 0, fail = 0, skipped = 0, says }
) {
  const context = `${what}:\n${outcome.output}`;
  assert.equal(outcome.status, status, context);
  assert.deepEqual(outcome.counts, { tests, pass, fail, skipped }, context);
  for (const pattern of [says].flat()) assert.match(outcome.output, pattern, context);
}
