// Release fixtures for the upgrade and rollback simulation: the runtime files of every
// published release (1.1.0-1.4.2), taken from the verified release tarballs, plus the one
// npm package they all need (nodemailer 10.0.10), so the simulation runs offline.
// test/upgrade/build-fixtures.mjs creates them; test/fixtures/SHA256SUMS pins them.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { readTar, safePath } from './tar.mjs';
import { history, historyRequired, historyRevision, isCommitId } from './history.mjs';

export {
  history,
  historyRequired,
  historyRevision,
  milestoneNames,
  parseRewrites,
  readHistory,
} from './history.mjs';

export const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
export const fixtures = path.join(root, 'test', 'fixtures');
export const versions = Object.freeze([
  '1.1.0',
  '1.2.0',
  '1.3.0',
  '1.3.1',
  '1.4.0',
  '1.4.1',
  '1.4.2',
]);
export const releaseFixture = version => `releases/orbit-homelab-${version}-runtime.tar.gz`;
export const nodemailer = Object.freeze({
  version: '10.0.10',
  file: 'npm/nodemailer-10.0.10.tgz',
  // package-lock.json of every release since 1.1.0 names this tarball.
  integrity:
    'sha512-He9XskOFms62SyAKkLu8CcGcYHAo+BSHSsORI8s4PJH8qZgZY4L4lDfvyN0twvmbpyG+eGrxpyBlskj9d9rJ8A==',
});
// What a release needs at run time. Documentation, tests and deployment files are left out:
// /api/docs answers "not installed" without docs/, as it does in a minimal install.
export const runtimeFile = file =>
  ['package.json', 'package-lock.json', 'server.mjs'].includes(file) ||
  /^lib\/[^/]+\.mjs$/.test(file) ||
  /^public\/[^/]+$/.test(file);
// Provenance, stored inside each fixture next to the release's own SHA256SUMS.
export const provenanceFile = '.orbit-fixture.json';

export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export const sri = bytes => 'sha512-' + createHash('sha512').update(bytes).digest('base64');
export function parseSums(text) {
  const sums = new Map();
  for (const line of text.split('\n')) {
    if (!line) continue;
    const match = /^([a-f0-9]{64}) {2}(.+)$/.exec(line);
    if (!match) throw new Error(`Invalid SHA256SUMS line: ${line}`);
    sums.set(safePath(match[2]), match[1]);
  }
  return sums;
}
export const formatSums = sums =>
  [...sums]
    .sort(([a], [b]) => (a < b ? -1 : 1))
    .map(([file, hash]) => `${hash}  ${file}\n`)
    .join('');

// The pinned hashes of the committed fixture files. `directory` defaults to test/fixtures.
export function pins(directory = fixtures) {
  return parseSums(fs.readFileSync(path.join(directory, 'SHA256SUMS'), 'utf8'));
}
// Missing fixtures skip the simulation, unless TEST_REQUIRE lists `fixtures`, which the
// upgrade CI job sets, so a checkout without them fails there instead of passing silently.
export function missingFixtures() {
  const files = ['SHA256SUMS', nodemailer.file, ...versions.map(releaseFixture)];
  return files.filter(file => !fs.existsSync(path.join(fixtures, file)));
}
export function fixturesRequired() {
  return (process.env.TEST_REQUIRE ?? '')
    .split(',')
    .map(s => s.trim())
    .includes('fixtures');
}
export function skipWithoutFixtures(t) {
  const missing = missingFixtures();
  if (!missing.length) return false;
  const message = `upgrade fixtures are missing: ${missing.join(', ')}`;
  if (fixturesRequired()) throw new Error(message + ' (TEST_REQUIRE=fixtures)');
  t.skip(message);
  return true;
}
// Reads a fixture only if its bytes match the pin.
export function pinned(file, directory = fixtures) {
  const bytes = fs.readFileSync(path.join(directory, file)),
    expected = pins(directory).get(file);
  if (!expected) throw new Error(`${file} is not pinned in test/fixtures/SHA256SUMS`);
  if (sha256(bytes) !== expected) throw new Error(`${file} does not match its pinned SHA-256`);
  return bytes;
}
/**
 * The verified runtime files of a release: the fixture must match its pin, and every file must
 * match the release's own SHA256SUMS (carried in the fixture). Returns {files, sums, provenance}.
 */
export function releaseFiles(version, directory = fixtures) {
  const entries = readTar(pinned(releaseFixture(version), directory)),
    byPath = new Map(entries.map(e => [e.path, e.data])),
    sums = parseSums(byPath.get('SHA256SUMS')?.toString('utf8') ?? ''),
    provenance = JSON.parse(byPath.get(provenanceFile)?.toString('utf8') ?? 'null'),
    files = new Map();
  if (provenance?.version !== version) throw new Error(`${version}: fixture provenance mismatch`);
  for (const [file, data] of byPath) {
    if (file === 'SHA256SUMS' || file === provenanceFile) continue;
    if (!runtimeFile(file)) throw new Error(`${version}: unexpected fixture file ${file}`);
    if (sums.get(file) !== sha256(data))
      throw new Error(`${version}: ${file} does not match the release SHA256SUMS`);
    files.set(file, data);
  }
  for (const file of sums.keys())
    if (runtimeFile(file) && !files.has(file))
      throw new Error(`${version}: fixture is missing ${file}`);
  if (JSON.parse(files.get('package.json')).version !== version)
    throw new Error(`${version}: package.json names another version`);
  return { files, sums, provenance };
}

// The 1.4.2 fixture was built from the commit its tag named then, and the tag must still hold
// exactly its runtime files. Which commit that was, and the reviewed rewrite of it after a history
// rewrite that changed commit ids but no tree, are part of the private history input
// (history.mjs), not of this tree.

/**
 * Checks that `commit`, which `tag` names now and whose source tree is `tree`, is the commit
 * `recorded` that the private history says a fixture was built from, or the rewrite of it that
 * `rewrites` (a Map from parseRewrites()) lists, with the listed tree. Anything else throws.
 * Returns 'recorded' or 'rewritten'.
 */
export function checkRecordedCommit({ tag, recorded, commit, tree }, rewrites) {
  if (!isCommitId(recorded)) throw new Error(`${tag}: the recorded commit is not a full id`);
  if (commit === recorded) return 'recorded';
  if (!(rewrites instanceof Map)) throw new Error(`${tag}: no list of reviewed rewrites`);
  const rewrite = rewrites.get(recorded);
  const names = `${tag} names ${commit}, not the recorded commit ${recorded}`;
  if (!rewrite) throw new Error(`${names}, and the private history lists no rewrite of it`);
  if (commit !== rewrite.commit)
    throw new Error(`${names} or its reviewed rewrite ${rewrite.commit}`);
  if (tree !== rewrite.tree)
    throw new Error(
      `${tag} names ${commit}, the reviewed rewrite of the recorded commit ${recorded}, but its tree ${tree} is not the reviewed tree ${rewrite.tree}`
    );
  return 'rewritten';
}

// The vendored npm tarball, checked against the integrity that package-lock.json records.
export function nodemailerTarball() {
  const bytes = pinned(nodemailer.file);
  if (sri(bytes) !== nodemailer.integrity)
    throw new Error('The vendored nodemailer tarball does not match its npm integrity hash');
  return bytes;
}
function writeTree(directory, files) {
  for (const [file, data] of files) {
    const target = path.join(directory, file);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, data, { mode: 0o644 });
  }
}
// The vendored nodemailer, as npm would unpack it, into <directory>/node_modules/nodemailer.
function installNodemailer(directory) {
  const packageFiles = new Map();
  for (const entry of readTar(nodemailerTarball())) {
    if (!entry.path.startsWith('package/')) throw new Error('Unexpected npm tarball layout');
    packageFiles.set(entry.path.slice('package/'.length), entry.data);
  }
  if (JSON.parse(packageFiles.get('package.json')).version !== nodemailer.version)
    throw new Error('The vendored nodemailer tarball has another version');
  writeTree(path.join(directory, 'node_modules', 'nodemailer'), packageFiles);
}

/**
 * Installs a release into `directory` (created, must not exist) as the native installer lays
 * it out, with nodemailer in node_modules. Returns the directory's real path: releases before
 * 1.4.2 exit silently when started through a symlinked path (such as macOS's /var).
 */
export function installRelease(version, directory) {
  fs.mkdirSync(directory, { recursive: true });
  const real = fs.realpathSync(directory);
  writeTree(real, releaseFiles(version).files);
  installNodemailer(real);
  return real;
}

// ---------------------------------------------------------------------------------------------
// Releases and milestones from this project's history (the tags v1.4.2 and v1.4.3, the
// milestones 1.5.0-dev.0 and 1.5.0-dev.1) run from their git tree in the private history
// repository (history.mjs), never from this checkout. Where the tests run without git (the Node 24
// container), the host exports each tree first with test/upgrade/export-tag.mjs and points
// TEST_TAG_TREES at the export (not an ORBIT_ name, which test/setup.mjs would scrub); every file
// is checked against the export's hashes.

/** The provenance file export-tag.mjs writes beside each exported tree. */
export const tagProvenanceFile = '.orbit-tag.json';

// Reading a tag through Git. Three answers make it unavailable: there is no `git` executable, a
// working Git says the source is in no repository (an unpacked source archive, with no `.git`
// where Git looked), or a working Git says the repository it found has no such tag (a shallow
// clone). Git works only if `git --version` does (checked once, as test/helpers/git.mjs checks
// it), so a git that exits 1 to everything is not a clone without the tag. What an unavailable
// tag does is the caller's: skipWithoutTag() skips, or fails under TEST_REQUIRE=history, and so
// do the export tests (export-tag.test.mjs) and the 1.4.2 fixture tests; the notification policy
// test leaves its 1.4.3 check out. Anything else is a broken Git or a repository Git cannot read, and throws with what
// Git did, so every caller fails whatever TEST_REQUIRE says (the maintainer's TOOLING-GIT-REQUIRED-P3).
// test/helpers/git.mjs decides the same way for the tests that declare Git; this module keeps its
// own code because tests copy test/upgrade/ without test/helpers/.

// Git's messages, untranslated: gitTag() recognises "not a git repository" by its text.
function gitEnvironment() {
  const env = { ...process.env, LC_ALL: 'C' };
  delete env.LANGUAGE;
  return env;
}

// Why the spawnSync `result` of `command` is not a run that exited 0, or false.
function gitFailure(command, result) {
  if (result.error) return `${command} could not run: ${result.error.message}`;
  if (result.signal) return `${command} was ended by ${result.signal}`;
  if (result.status === 0) return false;
  const stderr = String(result.stderr ?? '').trim();
  return `${command} exited with status ${result.status}${stderr ? `: ${stderr.slice(0, 500)}` : ''}`;
}

// Why `git --version` does not work, or false; run once, when a tag is first read.
let versionBroken;
function gitVersionBroken() {
  if (versionBroken === undefined) {
    const result = spawnSync('git', ['--version'], { encoding: 'utf8', env: gitEnvironment() });
    versionBroken =
      gitFailure('git --version', result) ||
      (/^git version \S/.test(result.stdout)
        ? false
        : `git --version printed ${JSON.stringify(result.stdout.slice(0, 200))}`);
  }
  return versionBroken;
}

// The `.git` that Git's search from `directory` meets (itself, then each parent below
// GIT_CEILING_DIRECTORIES, on its filesystem unless GIT_DISCOVERY_ACROSS_FILESYSTEM is set), or
// false: as gitEntry() in test/helpers/git.mjs. Git passes over a `.git` it cannot read.
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
      return false;
    }
    current = parent;
  }
}

// What Git says when its search for a repository met no `.git`.
const searchFoundNothing =
  /^fatal: not a git repository \(or any (of the parent directories|parent up to mount point)\b/m;

/**
 * The commit `tag` names in the repository at `cwd`: `{commit}`, or `{unavailable}` saying why
 * Git cannot read it here (see above). Throws for a broken Git or an unreadable repository.
 */
export function gitTag(tag, cwd) {
  const command = `git rev-parse --verify --quiet ${tag}^{commit}`;
  const result = spawnSync('git', ['rev-parse', '--verify', '--quiet', `${tag}^{commit}`], {
    cwd,
    encoding: 'utf8',
    env: gitEnvironment(),
  });
  // spawnSync reports a missing cwd as ENOENT too; only a missing git makes the tag unavailable.
  if (result.error?.code === 'ENOENT' && fs.statSync(cwd, { throwIfNoEntry: false })?.isDirectory())
    return { unavailable: 'git is not installed' };
  if (result.error) throw new Error(`${command} could not run: ${result.error.message}`);
  if (result.signal) throw new Error(`${command} was ended by ${result.signal}`);
  const stdout = result.stdout.trim(),
    stderr = result.stderr.trim();
  const said = `${stdout}\n${stderr}`.trim().slice(0, 500);
  const outcome = `${command} exited with status ${result.status}${said ? `: ${said}` : ''}`;
  let answer;
  if (result.status === 0 && /^[0-9a-f]{40}([0-9a-f]{24})?$/.test(stdout))
    answer = { commit: stdout };
  // --quiet: a missing tag exits 1 and says nothing.
  else if (result.status === 1 && !stdout && !stderr)
    answer = { unavailable: `the repository has no ${tag}` };
  else if (result.status === 128 && /^fatal: not a git repository\b/m.test(stderr)) {
    const entry = gitEntry(cwd);
    if (entry)
      throw new Error(
        `${outcome} (but ${entry} exists: a repository Git cannot read, not a source archive)`
      );
    // Not `not a git repository: <path>`, a GIT_DIR naming a directory that is not one.
    if (searchFoundNothing.test(stderr))
      answer = { unavailable: 'a working Git says this source is in no repository' };
  }
  if (!answer) throw new Error(outcome);
  // Only a working Git answers: one whose `git --version` fails is broken, whatever it said.
  const broken = gitVersionBroken();
  if (broken) throw new Error(`${outcome}, but git is broken: ${broken}`);
  // A missing tag is an answer about a repository, so Git must find one: a git that exits 1 to
  // everything but --version must not read as a clone without the tag.
  if (result.status === 1) {
    const repository = spawnSync('git', ['rev-parse', '--git-dir'], {
      cwd,
      encoding: 'utf8',
      env: gitEnvironment(),
    });
    const lost =
      gitFailure('git rev-parse --git-dir', repository) ||
      (repository.stdout.trim() ? false : 'git rev-parse --git-dir printed nothing');
    if (lost) throw new Error(`${outcome}, which says the repository has no ${tag}, but ${lost}`);
  }
  return answer;
}

// The tag's commit and files from git in `cwd` (null when gitTag() says the tag is unavailable).
export function gitTagFiles(tag, cwd) {
  const commit = gitTag(tag, cwd);
  if (!commit.commit) return null;
  const archive = spawnSync('git', ['archive', '--format=tar', tag], {
    cwd,
    maxBuffer: 512 * 2 ** 20,
  });
  if (archive.error || archive.status !== 0)
    throw new Error(`git archive ${tag} failed: ${archive.stderr?.toString() || archive.error}`);
  const files = new Map();
  for (const entry of readTar(archive.stdout)) files.set(entry.path, entry.data);
  return { commit: commit.commit, files };
}

// The files of an exported tree after checking each against its provenance file; an extra,
// missing or changed file refuses the tree.
function exportedTagFiles(tag, trees) {
  const base = path.join(trees, tag);
  const provenance = JSON.parse(fs.readFileSync(path.join(base, tagProvenanceFile), 'utf8'));
  if (provenance?.tag !== tag || !provenance.files || typeof provenance.files !== 'object')
    throw new Error(`${base}: ${tagProvenanceFile} does not describe ${tag}`);
  const files = new Map();
  for (const [file, hash] of Object.entries(provenance.files)) {
    const bytes = fs.readFileSync(path.join(base, safePath(file)));
    if (sha256(bytes) !== hash) throw new Error(`${tag}: ${file} does not match its export hash`);
    files.set(file, bytes);
  }
  const walk = relative => {
    for (const entry of fs.readdirSync(path.join(base, relative), { withFileTypes: true })) {
      const item = relative ? `${relative}/${entry.name}` : entry.name;
      if (item === tagProvenanceFile) continue;
      if (entry.isDirectory()) walk(item);
      else if (!files.has(item)) throw new Error(`${tag}: ${item} is not in the export's hashes`);
    }
  };
  walk('');
  return files;
}

/**
 * The commit and files of `name` (a tag, or a milestone's version) in the private history, or
 * null when there is no history input or Git says it is unavailable there. Throws for a wrong
 * history input or a broken Git.
 */
export function historyFiles(name) {
  const input = history();
  if (input.unavailable) return null;
  return gitTagFiles(historyRevision(name, input), input.repository);
}

/**
 * Why `name` (a tag, or a milestone's version) cannot be installed here, or false when it can:
 * from TEST_TAG_TREES when that is set, else from the private history. Throws when Git is broken
 * or the history input is wrong.
 */
export function tagUnavailable(name) {
  const trees = process.env.TEST_TAG_TREES;
  if (trees)
    return fs.existsSync(path.join(trees, name, tagProvenanceFile))
      ? false
      : `TEST_TAG_TREES has no export of ${name} (run node test/upgrade/export-tag.mjs ${name} <dir>)`;
  const input = history();
  if (input.unavailable)
    return `${name} comes from the private history, and ${input.unavailable}; TEST_TAG_TREES is not set either`;
  const { unavailable } = gitTag(historyRevision(name, input), input.repository);
  return unavailable
    ? `git cannot read the tag ${name} (${unavailable}) in the private history repository, and TEST_TAG_TREES is not set`
    : false;
}

/**
 * Skips `t` when `name` or the fixtures are unavailable, unless TEST_REQUIRE lists `history`
 * (or `fixtures`, for the fixtures); a broken Git or a wrong history input fails it.
 */
export function skipWithoutTag(t, name) {
  if (skipWithoutFixtures(t)) return true;
  const reason = tagUnavailable(name);
  if (!reason) return false;
  if (historyRequired()) throw new Error(reason + ' (TEST_REQUIRE=history)');
  t.skip(reason);
  return true;
}

/**
 * Installs `name` (a tag, or a milestone's version) into `directory` with the vendored
 * nodemailer: from $TEST_TAG_TREES/<name>/ (checked against .orbit-tag.json) when TEST_TAG_TREES
 * is set, else from `git archive` in the private history repository. Returns the directory's real
 * path.
 */
export function installTag(name, directory) {
  const trees = process.env.TEST_TAG_TREES;
  const files = trees ? exportedTagFiles(name, trees) : historyFiles(name)?.files;
  if (!files)
    throw new Error(
      `git cannot read ${name} in the private history (TEST_HISTORY) and TEST_TAG_TREES is not set`
    );
  fs.mkdirSync(directory, { recursive: true });
  const real = fs.realpathSync(directory);
  writeTree(real, files);
  installNodemailer(real);
  return real;
}
