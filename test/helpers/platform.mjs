// Tests that can run on one platform only: Linux, macOS (darwin) or the T8 driver's container.
// Each is listed in test/platform-manifest.json and registered through platformTest() or
// platformSubtest(), never with a platform check of its own. Such a test exists only on its
// platform: elsewhere nothing is registered (it is absent, never a skip), and the coverage check
// (scripts/check-platform-coverage.mjs) requires a passing run of it where the manifest says.
//
// On its platform a test is registered under the manifest's exact name. A missing prerequisite
// fails it, naming what is missing (non-root, setfacl), except `docker`, which follows
// TEST_REQUIRE as the suite's other Docker tests do: without `docker` in TEST_REQUIRE the test is
// skipped with that reason, and the coverage check refuses the skip.
//
// With TEST_PLATFORM_RECORDS (an absolute path to a directory) and TEST_PLATFORM_RUN (64
// lowercase hex digits, the run's own code) set, as the gate sets them per stage, each test
// process writes one `<pid>-<uuid>.jsonl` file there: one line per bound test it ran, with its
// id, file, name, platform, Node version, result and the manifest's sha256. Neither set (a
// developer's run): nothing is written. Anything else throws, failing the test file.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { parseManifest } from '../../scripts/check-platform-coverage.mjs';

const repository = fileURLToPath(new URL('../../', import.meta.url));
const manifestFile = path.join(repository, 'test', 'platform-manifest.json');

let loaded = null;
/** The validated manifest, its sha256 and its entries by id; read once per process. */
export function platformManifest() {
  if (loaded) return loaded;
  const { manifest, sha256, problems } = parseManifest(fs.readFileSync(manifestFile));
  if (problems.length)
    throw new Error(`test/platform-manifest.json is not valid: ${problems.join('; ')}`);
  loaded = {
    manifest,
    sha256,
    byId: new Map(manifest.entries.map(entry => [entry.id, entry])),
  };
  return loaded;
}

/**
 * The platform this run is on: `container` when TEST_T8_DIR is set, the variable only the T8
 * driver's container run sets (test/helpers/t8.mjs checks it against the real file system), and
 * otherwise Node's own process.platform.
 */
export function runPlatform(env = process.env, platform = process.platform) {
  return env.TEST_T8_DIR ? 'container' : platform;
}

/**
 * Where this process writes its records: null for a developer's run, else { directory, run }.
 * Throws on a partial or malformed setting.
 */
export function recordSettings(env = process.env, lstat = fs.lstatSync) {
  const directory = env.TEST_PLATFORM_RECORDS,
    run = env.TEST_PLATFORM_RUN;
  if (directory === undefined && run === undefined) return null;
  if (
    typeof directory !== 'string' ||
    !path.isAbsolute(directory) ||
    Buffer.byteLength(directory) > 1024 ||
    /[\u0000-\u001f\u007f]/.test(directory)
  )
    throw new Error(
      'TEST_PLATFORM_RECORDS must be an absolute path (at most 1024 bytes, no control character) when TEST_PLATFORM_RUN is set'
    );
  if (typeof run !== 'string' || !/^[0-9a-f]{64}$/.test(run))
    throw new Error(
      'TEST_PLATFORM_RUN must be 64 lowercase hex digits when TEST_PLATFORM_RECORDS is set'
    );
  let stat;
  try {
    stat = lstat(directory);
  } catch (error) {
    throw new Error(`TEST_PLATFORM_RECORDS cannot be read: ${error.code || error.message}`);
  }
  if (!stat.isDirectory())
    throw new Error('TEST_PLATFORM_RECORDS is not a directory (a link to one is refused)');
  return { directory, run };
}

let sink;
let recordFile = null;
/**
 * Appends one record (an object of the kinds scripts/check-platform-coverage.mjs reads) to this
 * process's record file, adding the run's code and the manifest's sha256. Does nothing in a
 * developer's run. Returns whether it wrote.
 */
function appendRecord(record) {
  sink ??= recordSettings();
  if (!sink) return false;
  if (recordFile === null) {
    const file = path.join(sink.directory, `${process.pid}-${randomUUID()}.jsonl`);
    const { O_WRONLY, O_CREAT, O_EXCL, O_APPEND, O_NOFOLLOW } = fs.constants;
    recordFile = fs.openSync(file, O_WRONLY | O_CREAT | O_EXCL | O_APPEND | O_NOFOLLOW, 0o644);
    // Readable by the host when written inside the T8 container; a record holds no secret.
    fs.fchmodSync(recordFile, 0o644);
  }
  fs.writeSync(
    recordFile,
    `${JSON.stringify({ ...record, run: sink.run, manifest: platformManifest().sha256 })}\n`
  );
  return true;
}

/**
 * Writes the T8 driver's `container` record (test/disk-full.test.mjs) as appendRecord does. A
 * test's `result` record is written only by the wrapper platformTest() gives a bound test, so a
 * test file cannot record a result for a test platformTest did not register.
 */
export function writePlatformRecord(record) {
  if (record?.kind !== 'container')
    throw new Error(
      'writePlatformRecord writes container records only: a platform test records its own result'
    );
  return appendRecord(record);
}

const required = name =>
  (process.env.TEST_REQUIRE || '')
    .split(',')
    .map(item => item.trim())
    .includes(name);

/** Why a static prerequisite is missing here, or null. acl-tmpdir is the test's own check. */
export function missingPrerequisite(name, probe = {}) {
  const uid = probe.uid ?? (() => process.getuid?.());
  const setfacl = probe.setfacl ?? (() => !spawnSync('setfacl', ['--version']).error);
  const docker =
    probe.docker ??
    (() =>
      spawnSync('docker', ['version', '--format', '{{.Server.Version}}'], {
        encoding: 'utf8',
        timeout: 60000,
      }).status === 0);
  if (name === 'non-root') return uid() === 0 ? 'it runs as root' : null;
  if (name === 'setfacl') return setfacl() ? null : 'setfacl is not installed (the acl package)';
  if (name === 'docker') return docker() ? null : 'Docker is not available (TEST_REQUIRE=docker)';
  return null;
}

/**
 * The entry `id` of `manifest` for a call from `file` (relative to the repository) naming the test
 * `name` under the parent tests `parentPath`; throws unless all are the manifest's.
 */
export function bindEntry(manifest, file, id, name, parentPath) {
  const entry = manifest.entries.find(item => item.id === id);
  if (!entry)
    throw new Error(`platform test ${JSON.stringify(id)} is not in test/platform-manifest.json`);
  if (file !== entry.file)
    throw new Error(`platform test ${id} is registered from ${file}, not ${entry.file}`);
  if (entry.name.at(-1) !== name)
    throw new Error(
      `platform test ${id} is named ${JSON.stringify(name)}, not ${JSON.stringify(entry.name.at(-1))}`
    );
  if (parentPath.join(' > ') !== entry.name.slice(0, -1).join(' > '))
    throw new Error(
      `platform test ${id} is registered under ${JSON.stringify(parentPath.join(' > '))}, not ${JSON.stringify(entry.name.slice(0, -1).join(' > '))}`
    );
  return entry;
}

function bound(fileUrl, id, name, parentPath) {
  const { manifest } = platformManifest();
  // The file is the one `fileUrl` names, which the caller gives: every call in the test files
  // passes its own import.meta.url (test/platform-manifest.test.mjs checks that statically).
  const file = path.relative(repository, fileURLToPath(fileUrl)).split(path.sep).join('/');
  // A partial or malformed record setting fails the file now, not after its first test.
  sink ??= recordSettings();
  return { entry: bindEntry(manifest, file, id, name, parentPath), manifest };
}

/**
 * What to register for `entry` on `platform`: { action: 'absent' } (another platform's test),
 * { action: 'skip', reason } (docker without TEST_REQUIRE=docker), { action: 'fail', reason } (a
 * prerequisite missing) or { action: 'run' }. `requires` lists TEST_REQUIRE's names; `probe`
 * stands in for missingPrerequisite's system calls in tests.
 */
export function platformDecision(entry, { platform = runPlatform(), requires, probe } = {}) {
  if (!entry.platforms.includes(platform)) return { action: 'absent' };
  const listed = requires ?? (name => required(name));
  for (const prerequisite of entry.prerequisites) {
    if (prerequisite === 'acl-tmpdir') continue;
    if (prerequisite === 'docker' && !listed('docker'))
      return {
        action: 'skip',
        reason: 'set TEST_REQUIRE=docker to run it (needs Docker and the pinned image)',
      };
    const missing = missingPrerequisite(prerequisite, probe);
    if (missing)
      return {
        action: 'fail',
        reason: `${entry.id} needs ${prerequisite} on ${platform}, and ${missing}`,
      };
  }
  return { action: 'run' };
}

function checkOptions(id, options) {
  for (const key of ['skip', 'todo', 'only'])
    if (options && Object.hasOwn(options, key))
      throw new Error(
        `platform test ${id} takes no ${key} option: it is registered only on its platform, never skipped`
      );
}

/** The test function, recording its result for the coverage check. */
function recorded(entry, fn) {
  return async t => {
    let result = 'completed';
    for (const kind of ['skip', 'todo']) {
      const original = t[kind].bind(t);
      t[kind] = (...args) => {
        result = kind === 'skip' ? 'skipped' : 'todo';
        return original(...args);
      };
    }
    try {
      await fn(t);
    } catch (error) {
      result = 'failed';
      throw error;
    } finally {
      appendRecord({
        kind: 'result',
        id: entry.id,
        file: entry.file,
        name: entry.name,
        platform: runPlatform(),
        node: process.version,
        result,
      });
    }
  };
}

// Files that, run with TEST_T8_DIR set, were given a failing test for it (once per file).
const strayContainer = new Set();

/**
 * Registers `fn` as the test `name` where the manifest entry `id` says, and nowhere else.
 * `fileUrl` is the caller's import.meta.url; `options` are node:test options without skip, todo
 * or only.
 */
export function platformTest(fileUrl, id, name, options, fn) {
  const { entry, manifest } = bound(fileUrl, id, name, []);
  checkOptions(id, options);
  return register(
    entry,
    manifest,
    (testName, testOptions, body) => test(testName, testOptions, body),
    name,
    options,
    fn
  );
}

/**
 * The same for a subtest of the running test `t`, whose full name must be the entry's parent
 * path. Resolves when the subtest ends (at once where it is absent).
 */
export async function platformSubtest(t, fileUrl, id, name, options, fn) {
  const { entry, manifest } = bound(fileUrl, id, name, t.fullName.split(' > '));
  checkOptions(id, options);
  return register(
    entry,
    manifest,
    (testName, testOptions, body) => t.test(testName, testOptions, body),
    name,
    options,
    fn
  );
}

function register(entry, manifest, add, name, options = {}, fn) {
  const here = runPlatform();
  if (
    here === 'container' &&
    !manifest.entries.some(
      other => other.file === entry.file && other.platforms.includes('container')
    ) &&
    !strayContainer.has(entry.file)
  ) {
    strayContainer.add(entry.file);
    // A TEST_T8_DIR exported on a host must not quietly remove this file's platform tests.
    add(`platform: ${entry.file} has no test for the T8 driver's container`, {}, () =>
      assert.fail(
        'TEST_T8_DIR is set, which only the T8 driver sets inside its container, so the platform tests of this file are not registered: unset TEST_T8_DIR'
      )
    );
  }
  const decision = platformDecision(entry, { platform: here });
  if (decision.action === 'absent') return undefined;
  if (decision.action === 'skip')
    return add(
      name,
      { ...options, skip: decision.reason },
      recorded(entry, () => {})
    );
  if (decision.action === 'fail')
    return add(
      name,
      options,
      recorded(entry, () => assert.fail(decision.reason))
    );
  return add(name, options, recorded(entry, fn));
}
