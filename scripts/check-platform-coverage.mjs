// The platform coverage contract of the test suite (test/platform-manifest.json) and its checker.
//
// Some tests can only run on one platform: Linux (/proc, setfacl), macOS (chmod +a, no /proc) or
// the T8 driver's container (a 96 MiB tmpfs). Each is bound to its platform through
// test/helpers/platform.mjs and listed in the manifest: it is registered only there and is
// absent everywhere else, never a skip. The manifest also names the runs that must execute each
// entry. A run with TEST_PLATFORM_RECORDS set writes a record of every bound test it ran.
//
// This module validates the manifest, reads a run's TAP and records, and checks one run against
// the contract: every entry required of the run executed and passed exactly once, every entry of
// another platform is absent, no test skipped or is todo, and nothing else claims to be an entry.
// It also judges a candidate's manifest against the manifests in its history
// (judgeCandidateManifest, built on coverageLoss): a removed or narrowed entry or run is a loss
// unless an exact, reviewed disposition names it, and a commit made without the guard cannot
// delete or weaken the manifest unnoticed. It imports only Node's own modules, so a guard can
// carry it beside scripts/security-evidence.mjs.
//
// Usage: node scripts/check-platform-coverage.mjs --run <id> --runtime <24|26> --tap <file>
//   --records <dir> --nonce <64 hex> [--root <dir>] [--manifest <file>] [--files-from <file>]
//   [--json]
// Exit 0 when the run covers the contract, 1 when it does not, 2 for a usage error.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

export const repositoryRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
export const manifestPath = 'test/platform-manifest.json';

export const PLATFORMS = Object.freeze(['container', 'darwin', 'linux']);
export const RUNTIMES = Object.freeze(['24', '26']);
// non-root and setfacl are checked before the test is registered; acl-tmpdir by the test
// itself; docker follows TEST_REQUIRE (test/helpers/platform.mjs).
export const PREREQUISITES = Object.freeze(['acl-tmpdir', 'docker', 'non-root', 'setfacl']);
export const REQUIRED_FOR = Object.freeze(['commit', 'release']);
export const RESULTS = Object.freeze(['completed', 'failed', 'skipped', 'todo']);

export const limits = Object.freeze({
  manifestBytes: 256 * 1024,
  entries: 500,
  runs: 16,
  idLength: 80,
  fileLength: 200,
  nameLength: 300,
  nameDepth: 3,
  tapBytes: 256 * 1024 * 1024,
  recordFiles: 4096,
  recordFileBytes: 1024 * 1024,
  recordLineBytes: 64 * 1024,
  dispositions: 500,
  textLength: 2000,
  historyCommits: 100000,
  parents: 16,
});

const ID = /^[a-z0-9]+(?:[.-][a-z0-9]+)*$/;
const RUN_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const FILE = /^test\/(?:[a-z0-9][a-z0-9-]*\/){0,3}[a-z0-9][a-z0-9-]*\.test\.mjs$/;
const HEX64 = /^[0-9a-f]{64}$/;
const NODE_VERSION = /^v(\d{1,3})\.\d{1,4}\.\d{1,4}$/;
const RECORD_FILE =
  /^\d{1,10}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.jsonl$/;
const CONTAINER_DIR = /^t8-container-(24|26)-[A-Za-z0-9]{6}$/;
/** The names a records directory may hold: record files, and the T8 driver's evidence folders. */
export const recordNames = Object.freeze({ file: RECORD_FILE, container: CONTAINER_DIR });
const COMMIT = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;

export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const own = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const show = value => JSON.stringify(value)?.slice(0, 200);

/** The image a container run may use for `runtime`: node:<runtime>…, pinned by digest. */
export const imagePattern = runtime =>
  new RegExp(`^node:${runtime}(?:[.-][A-Za-z0-9_.-]{0,100})?@sha256:[0-9a-f]{64}$`);

/**
 * Why `name` (one name of a test name path) cannot be matched exactly in TAP, or cannot be read
 * exactly by a reviewer, or null.
 */
export function nameProblem(name) {
  if (typeof name !== 'string' || !name.length) return 'is not a non-empty string';
  if (name.length > limits.nameLength) return `is longer than ${limits.nameLength} characters`;
  // TAP prints a lone surrogate as U+FFFD, so such a name could never match its result line.
  if (!name.isWellFormed()) return 'holds a lone UTF-16 surrogate';
  if (name !== name.trim()) return 'starts or ends with white space';
  if (name.normalize('NFC') !== name) return 'is not in NFC form';
  // TAP escapes # and \, a line break ends the line, and ` > ` joins a subtest's full name.
  if (/[\u0000-\u001f\u007f-\u009f\u2028\u2029#\\]/.test(name))
    return 'holds #, \\ or a control character';
  // What a reviewer cannot see or tell from a space: format characters (zero-width space and
  // joiners, bidi controls, a byte order mark), private-use characters and spaces but U+0020.
  if (/[\p{Cf}\p{Co}]|(?! )\p{Zs}/u.test(name))
    return 'holds an invisible character or a space other than U+0020';
  if (name.includes(' > ')) return 'holds " > "';
  return null;
}

// A run id is a member name of `runs`; one that Object.prototype also has (constructor,
// toString, __proto__) would reach the prototype wherever a missing run is looked up.
const prototypeName = key => Object.prototype.hasOwnProperty.call(Object.prototype, key);
/** The run `id` of `manifest`, or undefined: never a member of Object.prototype. */
const runOf = (manifest, id) =>
  typeof id === 'string' && own(manifest.runs, id) ? manifest.runs[id] : undefined;

/** Problems with a list that must be a sorted, unique, non-empty subset of `allowed`. */
function subsetProblems(where, value, allowed, { empty = false } = {}) {
  if (!Array.isArray(value)) return [`${where} is not a list`];
  if (!empty && !value.length) return [`${where} is empty`];
  const problems = [];
  for (const item of value)
    if (!allowed.includes(item))
      problems.push(`${where} holds ${show(item)}, not one of ${allowed.join(', ')}`);
  if (new Set(value).size !== value.length) problems.push(`${where} holds a value twice`);
  else if (value.join('\n') !== [...value].sort().join('\n'))
    problems.push(`${where} is not sorted`);
  return problems;
}

function keysProblems(where, value, required, optional = []) {
  if (!isObject(value)) return [`${where} is not an object`];
  const problems = [];
  for (const key of Object.keys(value))
    if (!required.includes(key) && !optional.includes(key))
      problems.push(`${where} has the unknown field ${show(key)}`);
  for (const key of required) if (!own(value, key)) problems.push(`${where} lacks ${key}`);
  return problems;
}

/**
 * Members that appear twice in one object of `text`, which must already parse as JSON: JSON.parse
 * keeps the last of two, so a reviewer could read one value and the checker use another.
 */
export function duplicateMembers(text) {
  const found = [];
  const stack = [];
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      const top = stack.at(-1);
      if (top?.keys && top.expectKey) {
        const key = JSON.parse(text.slice(i, j + 1));
        if (top.keys.has(key)) found.push(key);
        top.keys.add(key);
        top.expectKey = false;
      }
      i = j;
    } else if (c === '{') stack.push({ keys: new Set(), expectKey: true });
    else if (c === '[') stack.push({ keys: null });
    else if (c === '}' || c === ']') stack.pop();
    else if (c === ',' && stack.at(-1)?.keys) stack.at(-1).expectKey = true;
  }
  return found;
}

/**
 * Validates a parsed manifest. Returns its problems ([] for none). See test/platform-manifest.json
 * and docs/engineering-quality.md for the contract.
 */
export function manifestProblems(manifest) {
  const problems = keysProblems('the manifest', manifest, ['schemaVersion', 'runs', 'entries']);
  if (problems.length) return problems;
  if (manifest.schemaVersion !== 1)
    problems.push(`schemaVersion is ${show(manifest.schemaVersion)}, not 1`);
  const runs = manifest.runs;
  if (!isObject(runs)) return [...problems, 'runs is not an object'];
  const runIds = Object.keys(runs);
  if (!runIds.length) problems.push('runs is empty');
  if (runIds.length > limits.runs) problems.push(`runs holds more than ${limits.runs} runs`);
  for (const id of runIds) {
    const where = `run ${show(id)}`;
    if (!RUN_ID.test(id) || id.length > limits.idLength || prototypeName(id))
      problems.push(`${where}: not a valid run id`);
    const run = runs[id];
    const runProblems = keysProblems(
      where,
      run,
      ['platform', 'runtimes', 'files', 'requiredFor'],
      ['images', 'hostRuns']
    );
    problems.push(...runProblems);
    if (runProblems.length) continue;
    if (!PLATFORMS.includes(run.platform))
      problems.push(
        `${where}: platform ${show(run.platform)} is not one of ${PLATFORMS.join(', ')}`
      );
    problems.push(...subsetProblems(`${where}: runtimes`, run.runtimes, RUNTIMES));
    problems.push(...subsetProblems(`${where}: requiredFor`, run.requiredFor, REQUIRED_FOR));
    if (run.files !== 'all') {
      if (!Array.isArray(run.files) || !run.files.length)
        problems.push(`${where}: files is neither "all" nor a non-empty list`);
      else {
        for (const file of run.files)
          if (!validFile(file))
            problems.push(`${where}: files holds ${show(file)}, not a bounded test file path`);
        if (new Set(run.files).size !== run.files.length)
          problems.push(`${where}: files holds a file twice`);
        else if (run.files.join('\n') !== [...run.files].sort().join('\n'))
          problems.push(`${where}: files is not sorted`);
      }
    }
    if (run.platform === 'container') {
      if (!isObject(run.images))
        problems.push(`${where}: a container run needs images, one per runtime`);
      else {
        const keys = Object.keys(run.images).sort();
        if (Array.isArray(run.runtimes) && keys.join() !== [...run.runtimes].sort().join())
          problems.push(
            `${where}: images names runtimes ${keys.join(', ') || 'none'}, not its runtimes ${run.runtimes.join(', ')}`
          );
        for (const runtime of keys) {
          const image = run.images[runtime];
          if (image === null) continue;
          const imageProblems = keysProblems(`${where}: images.${runtime}`, image, [
            'image',
            'driver',
          ]);
          problems.push(...imageProblems);
          if (imageProblems.length) continue;
          if (typeof image.image !== 'string' || !imagePattern(runtime).test(image.image))
            problems.push(
              `${where}: images.${runtime}.image is not node:${runtime}… pinned by its sha256 digest`
            );
          if (typeof image.driver !== 'string' || !ID.test(image.driver))
            problems.push(`${where}: images.${runtime}.driver is not an entry id`);
        }
        // Each runtime's evidence comes from a driver test of its own.
        const drivers = Object.values(run.images)
          .filter(isObject)
          .map(image => image.driver);
        if (new Set(drivers).size !== drivers.length)
          problems.push(`${where}: two runtimes name one driver; each needs a driver of its own`);
      }
      if (!Array.isArray(run.hostRuns) || !run.hostRuns.length)
        problems.push(`${where}: a container run needs hostRuns, the runs whose driver runs it`);
      else
        problems.push(
          ...subsetProblems(
            `${where}: hostRuns`,
            run.hostRuns,
            runIds.filter(other => runs[other]?.platform !== 'container')
          )
        );
    } else if (own(run, 'images') || own(run, 'hostRuns'))
      problems.push(`${where}: only a container run has images and hostRuns`);
  }
  const entries = manifest.entries;
  if (!Array.isArray(entries)) return [...problems, 'entries is not a list'];
  if (!entries.length) problems.push('entries is empty');
  if (entries.length > limits.entries)
    problems.push(`entries holds more than ${limits.entries} entries`);
  const ids = new Set(),
    paths = new Set();
  for (const [index, entry] of entries.entries()) {
    const where = `entry ${index} (${show(entry?.id)})`;
    const entryProblems = keysProblems(where, entry, [
      'id',
      'file',
      'name',
      'platforms',
      'runtimes',
      'prerequisites',
      'evidence',
    ]);
    problems.push(...entryProblems);
    if (entryProblems.length) continue;
    if (typeof entry.id !== 'string' || !ID.test(entry.id) || entry.id.length > limits.idLength)
      problems.push(`${where}: not a valid id`);
    else if (ids.has(entry.id)) problems.push(`${where}: the id is used twice`);
    ids.add(entry.id);
    if (!validFile(entry.file)) problems.push(`${where}: file is not a bounded test file path`);
    if (!Array.isArray(entry.name) || !entry.name.length || entry.name.length > limits.nameDepth)
      problems.push(`${where}: name is not a path of 1 to ${limits.nameDepth} test names`);
    else
      for (const name of entry.name) {
        const problem = nameProblem(name);
        if (problem) problems.push(`${where}: the name ${show(name)} ${problem}`);
      }
    const key = JSON.stringify([entry.file, entry.name]);
    if (paths.has(key)) problems.push(`${where}: another entry has the same file and name`);
    paths.add(key);
    problems.push(...subsetProblems(`${where}: platforms`, entry.platforms, PLATFORMS));
    problems.push(...subsetProblems(`${where}: runtimes`, entry.runtimes, RUNTIMES));
    problems.push(
      ...subsetProblems(`${where}: prerequisites`, entry.prerequisites, PREREQUISITES, {
        empty: true,
      })
    );
    problems.push(...subsetProblems(`${where}: evidence`, entry.evidence, runIds));
    if (
      !Array.isArray(entry.evidence) ||
      !Array.isArray(entry.platforms) ||
      !Array.isArray(entry.runtimes)
    )
      continue;
    for (const runId of entry.evidence) {
      const run = own(runs, runId) ? runs[runId] : undefined;
      if (!isObject(run)) continue;
      if (!entry.platforms.includes(run.platform))
        problems.push(
          `${where}: its evidence run ${runId} is on ${run.platform}, where it is not registered`
        );
      if (Array.isArray(run.files) && !run.files.includes(entry.file))
        problems.push(`${where}: its evidence run ${runId} does not run ${entry.file}`);
      if (Array.isArray(run.runtimes))
        for (const runtime of entry.runtimes)
          if (!run.runtimes.includes(runtime))
            problems.push(`${where}: its evidence run ${runId} is not run on Node ${runtime}`);
    }
  }
  // A container run's driver: a test of the file the container runs, registered and required in
  // every host run that runs the container.
  for (const [runId, run] of Object.entries(runs)) {
    if (!isObject(run?.images) || !Array.isArray(run.hostRuns) || !Array.isArray(run.files))
      continue;
    for (const [runtime, image] of Object.entries(run.images)) {
      if (!isObject(image) || typeof image.driver !== 'string') continue;
      const driver = entries.find(entry => entry?.id === image.driver);
      if (!driver) {
        problems.push(
          `run ${runId}: images.${runtime}.driver ${show(image.driver)} is not an entry`
        );
        continue;
      }
      if (
        !run.files.includes(driver.file) ||
        !Array.isArray(driver.platforms) ||
        driver.platforms.includes('container')
      )
        problems.push(
          `run ${runId}: images.${runtime}.driver ${image.driver} is not a host test of the file the container runs`
        );
      // The driver runs Docker: without docker in TEST_REQUIRE it skips (refused), never passes.
      if (!Array.isArray(driver.prerequisites) || !driver.prerequisites.includes('docker'))
        problems.push(
          `run ${runId}: images.${runtime}.driver ${image.driver} does not list the docker prerequisite`
        );
      for (const host of run.hostRuns)
        if (!Array.isArray(driver.evidence) || !driver.evidence.includes(host))
          problems.push(
            `run ${runId}: its driver ${image.driver} is not required of its host run ${host}`
          );
    }
  }
  return problems;
}

function validFile(file) {
  return (
    typeof file === 'string' &&
    file.length <= limits.fileLength &&
    FILE.test(file) &&
    !file.split('/').some(part => part === '.' || part === '..')
  );
}

/** Parses manifest bytes: { manifest, sha256, problems }. The manifest is null when unusable. */
export function parseManifest(bytes) {
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(String(bytes));
  const digest = sha256(buffer);
  if (buffer.length > limits.manifestBytes)
    return {
      manifest: null,
      sha256: digest,
      problems: [`the manifest is larger than ${limits.manifestBytes} bytes`],
    };
  const text = buffer.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(buffer))
    return { manifest: null, sha256: digest, problems: ['the manifest is not valid UTF-8'] };
  let manifest;
  try {
    manifest = JSON.parse(text);
  } catch (error) {
    return {
      manifest: null,
      sha256: digest,
      problems: [`the manifest is not JSON: ${error.message}`],
    };
  }
  const duplicates = duplicateMembers(text);
  const problems = duplicates.map(
    key => `the manifest names the member ${show(key)} twice in one object`
  );
  problems.push(...manifestProblems(manifest));
  return { manifest: problems.length ? null : manifest, sha256: digest, problems };
}

/** Reads and validates `<root>/test/platform-manifest.json`; throws on any problem. */
export function readManifest(root = repositoryRoot, file = path.join(root, manifestPath)) {
  const {
    manifest,
    sha256: digest,
    problems,
  } = parseManifest(readBounded(file, limits.manifestBytes));
  if (problems.length) throw new Error(`${file}: ${problems.join('; ')}`);
  return { manifest, sha256: digest };
}

/** A regular file of at most `max` bytes, opened without following a link. */
function readBounded(file, max) {
  const fd = fs.openSync(
    file,
    fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK
  );
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) throw new Error(`${file} is not a regular file`);
    if (stat.size > max) throw new Error(`${file} is larger than ${max} bytes`);
    return fs.readFileSync(fd);
  } finally {
    fs.closeSync(fd);
  }
}

/** Every test file the test glob `test/**\/*.test.mjs` names under `root`, sorted. */
export function allTestFiles(root = repositoryRoot) {
  const found = [];
  const walk = relative => {
    for (const entry of fs.readdirSync(path.join(root, relative), { withFileTypes: true })) {
      const file = `${relative}/${entry.name}`;
      if (entry.isDirectory()) walk(file);
      else if (entry.isFile() && entry.name.endsWith('.test.mjs')) found.push(file);
    }
  };
  walk('test');
  return found.sort();
}

/**
 * The test files run `runId` must run: its list, or for "all" every test file of the candidate:
 * `allFiles` when given (the gate and the finalizer pass the candidate's tracked test files, so
 * nothing outside the candidate counts), else every test file under `root`.
 */
export function runFiles(manifest, runId, root = repositoryRoot, allFiles) {
  const run = runOf(manifest, runId);
  if (!run) throw new Error(`the manifest has no run ${show(runId)}`);
  if (run.files !== 'all') return [...run.files];
  return allFiles ? [...allFiles].sort() : allTestFiles(root);
}

// ---------------------------------------------------------------------------------------------
// TAP

function unescapeTap(text) {
  const map = { b: '\b', f: '\f', t: '\t', n: '\n', r: '\r', v: '\v', '\\': '\\', '#': '#' };
  return text.replace(/\\(.)/g, (whole, c) => map[c] ?? whole);
}

/**
 * The result lines of a TAP log of node's TAP reporter, as { path, ok, directive, reason, line,
 * number }: `path` is the test's name path (its parents first), built from the nesting. Only result
 * lines count: comments (the tests' own output, which the reporter prints as `# …`, and the T8
 * driver's escaped diagnostics) never do, and neither does a line inside a YAML block (a failing
 * test's error text). A YAML block ends where the reporter's `...` line says: node's TAP reporter
 * does not escape the keys of a failing assertion's expected and actual values, so a failing test
 * can end its own block early and print a line that reads as a result. Such a run still has that
 * failure in its totals, which checkCoverage refuses, so it cannot pass. Returns
 * { results, problems }.
 */
export function tapResults(tap) {
  const text = String(tap);
  const problems = [];
  if (Buffer.byteLength(text) > limits.tapBytes)
    return { results: [], problems: [`the TAP log is larger than ${limits.tapBytes} bytes`] };
  const lines = text.split('\n');
  const pending = new Map();
  let yamlEnd = null;
  let previousResult = null;
  for (let index = 0; index < lines.length; index++) {
    const line = lines[index].replace(/\r$/, '');
    if (yamlEnd !== null) {
      if (line === yamlEnd) yamlEnd = null;
      continue;
    }
    if (previousResult !== null && line === `${' '.repeat(previousResult)}  ---`) {
      yamlEnd = `${' '.repeat(previousResult)}  ...`;
      previousResult = null;
      continue;
    }
    previousResult = null;
    const match = /^( *)(not ok|ok) (\d+) - (.*)$/.exec(line);
    if (!match) continue;
    const indent = match[1].length;
    if (indent % 4) {
      problems.push(`line ${index + 1}: a result line indented by ${indent} spaces`);
      continue;
    }
    const depth = indent / 4;
    // The name ends at the first ` # ` whose # is not escaped.
    let raw = match[4],
      directive = null,
      reason = '';
    for (let i = 0; i < raw.length; i++) {
      if (raw[i] === '\\') {
        i++;
        continue;
      }
      if (raw[i] === '#' && raw[i - 1] === ' ') {
        const rest = raw.slice(i + 1).trim();
        raw = raw.slice(0, i - 1);
        const parsed = /^(SKIP|TODO)\b\s*(.*)$/i.exec(rest);
        directive = parsed ? parsed[1].toUpperCase() : `OTHER ${rest}`;
        reason = parsed ? parsed[2] : '';
        break;
      }
    }
    const node = {
      name: unescapeTap(raw),
      ok: match[2] === 'ok',
      directive,
      reason,
      line: index + 1,
      number: Number(match[3]),
      children: pending.get(depth + 1) ?? [],
    };
    pending.delete(depth + 1);
    if (!pending.has(depth)) pending.set(depth, []);
    pending.get(depth).push(node);
    previousResult = indent;
  }
  if (yamlEnd !== null) problems.push('the TAP log ends inside a YAML block');
  for (const [depth, nodes] of pending)
    if (depth > 0 && nodes.length)
      problems.push(`${nodes.length} result lines at depth ${depth} have no parent result line`);
  const results = [];
  const flatten = (nodes, parents) => {
    for (const node of nodes) {
      const namePath = [...parents, node.name];
      flatten(node.children, namePath);
      results.push({
        path: namePath,
        ok: node.ok,
        directive: node.directive,
        reason: node.reason,
        line: node.line,
        number: node.number,
      });
    }
  };
  flatten(pending.get(0) ?? [], []);
  return { results, problems };
}

/** The six totals of a TAP log, each exactly once, and what is wrong with them. */
export function tapTotals(tap) {
  const totals = {};
  const problems = [];
  for (const name of ['tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo']) {
    const found = [...String(tap).matchAll(new RegExp(`^# ${name} (\\d+)\\s*$`, 'gm'))];
    if (found.length !== 1)
      problems.push(`the TAP log has ${found.length} "# ${name}" totals, not one`);
    else totals[name] = Number(found[0][1]);
  }
  if (!problems.length) {
    if (!totals.tests || totals.pass !== totals.tests)
      problems.push(`the run passed ${totals.pass} of ${totals.tests} tests`);
    for (const name of ['fail', 'cancelled', 'skipped', 'todo'])
      if (totals[name]) problems.push(`the run has ${totals[name]} ${name}`);
  }
  return { totals, problems };
}

// ---------------------------------------------------------------------------------------------
// Records

const RESULT_FIELDS = [
  'kind',
  'run',
  'manifest',
  'id',
  'file',
  'name',
  'platform',
  'node',
  'result',
];
const CONTAINER_FIELDS = [
  'kind',
  'run',
  'manifest',
  'id',
  'runtime',
  'image',
  'imageId',
  'code',
  'node',
  'evidence',
  'tapSha256',
  'recordsSha256',
];

/** What is wrong with one parsed record line, or null. */
export function recordProblem(record) {
  if (!isObject(record)) return 'is not an object';
  const fields =
    record.kind === 'result'
      ? RESULT_FIELDS
      : record.kind === 'container'
        ? CONTAINER_FIELDS
        : null;
  if (!fields) return `has the kind ${show(record.kind)}`;
  const problems = keysProblems('it', record, fields);
  if (problems.length) return problems.join('; ');
  if (!HEX64.test(record.run)) return 'has a run that is not 64 lowercase hex digits';
  if (!HEX64.test(record.manifest)) return 'has a manifest hash that is not a sha256';
  if (typeof record.id !== 'string' || !ID.test(record.id)) return 'has an invalid id';
  if (typeof record.node !== 'string' || !NODE_VERSION.test(record.node))
    return 'has an invalid node version';
  if (record.kind === 'result') {
    if (!validFile(record.file)) return 'has an invalid file';
    if (
      !Array.isArray(record.name) ||
      !record.name.length ||
      record.name.length > limits.nameDepth ||
      record.name.some(name => nameProblem(name))
    )
      return 'has an invalid name path';
    if (!PLATFORMS.includes(record.platform)) return 'has an unknown platform';
    if (!RESULTS.includes(record.result)) return 'has an unknown result';
    return null;
  }
  if (!RUNTIMES.includes(record.runtime)) return 'has an unknown runtime';
  if (typeof record.image !== 'string' || !imagePattern(record.runtime).test(record.image))
    return 'has an image that is not pinned';
  if (!/^sha256:[0-9a-f]{64}$/.test(record.imageId)) return 'has an invalid image id';
  if (!HEX64.test(record.code)) return 'has a code that is not 64 lowercase hex digits';
  if (typeof record.evidence !== 'string' || !CONTAINER_DIR.test(record.evidence))
    return 'names an invalid evidence folder';
  if (!HEX64.test(record.tapSha256) || !HEX64.test(record.recordsSha256))
    return 'has an invalid sha256';
  return null;
}

/**
 * Reads a records directory: { records, problems, digest }. Only `<pid>-<uuid>.jsonl` regular
 * files (and, with `containers`, the T8 driver's `t8-container-<runtime>-*` folders) may be in it.
 * `digest` hashes every record file's name and bytes, for a container record to bind.
 */
export function readRecords(directory, { containers = true } = {}) {
  const problems = [];
  const records = [];
  let stat;
  try {
    stat = fs.lstatSync(directory);
  } catch (error) {
    return {
      records,
      problems: [`the records directory cannot be read: ${error.code || error.message}`],
      digest: null,
    };
  }
  if (!stat.isDirectory())
    return {
      records,
      problems: ['the records directory is not a directory (or is a link)'],
      digest: null,
    };
  const entries = fs
    .readdirSync(directory, { withFileTypes: true })
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  if (entries.length > limits.recordFiles)
    return {
      records,
      problems: [`the records directory holds more than ${limits.recordFiles} entries`],
      digest: null,
    };
  const hash = createHash('sha256');
  for (const entry of entries) {
    const file = path.join(directory, entry.name);
    if (containers && entry.isDirectory() && CONTAINER_DIR.test(entry.name)) continue;
    if (!entry.isFile() || !RECORD_FILE.test(entry.name)) {
      problems.push(`the records directory holds ${show(entry.name)}, which is not a record file`);
      continue;
    }
    let bytes;
    try {
      bytes = readBounded(file, limits.recordFileBytes);
    } catch (error) {
      problems.push(`${entry.name}: ${error.code || error.message}`);
      continue;
    }
    hash.update(`${entry.name}\0${sha256(bytes)}\n`);
    const text = bytes.toString('utf8');
    if (text.length && !text.endsWith('\n'))
      problems.push(`${entry.name}: its last line is incomplete`);
    for (const [index, line] of text.split('\n').entries()) {
      if (!line) continue;
      if (Buffer.byteLength(line) > limits.recordLineBytes) {
        problems.push(
          `${entry.name}:${index + 1}: the line is longer than ${limits.recordLineBytes} bytes`
        );
        continue;
      }
      let record;
      try {
        record = JSON.parse(line);
      } catch {
        problems.push(`${entry.name}:${index + 1}: not JSON`);
        continue;
      }
      const duplicates = duplicateMembers(line);
      const problem = duplicates.length
        ? `names ${show(duplicates[0])} twice`
        : recordProblem(record);
      if (problem) problems.push(`${entry.name}:${index + 1}: the record ${problem}`);
      else records.push({ ...record, source: `${entry.name}:${index + 1}` });
    }
  }
  return { records, problems, digest: hash.digest('hex') };
}

// ---------------------------------------------------------------------------------------------
// The check of one run

const samePath = (a, b) => a.length === b.length && a.every((name, i) => name === b[i]);
/** Whether the name path `path` ends with `name`: the test `name` at any depth, under any parent. */
const endsWith = (path, name) =>
  path.length >= name.length && samePath(path.slice(path.length - name.length), name);
const major = version => NODE_VERSION.exec(version)?.[1];

/**
 * Checks one run against the contract. `tap` is the run's TAP log; `records` its records (from
 * readRecords); `nonce` its TEST_PLATFORM_RUN; `files` the test files it ran (default: what the
 * manifest says the run runs); `allFiles` the candidate's test files, for a run of every file.
 * Returns { problems, coverage, totals }: `coverage` lists each entry as required, present,
 * absent or not run, with its TAP line. An absence is never counted as a pass, and nothing is
 * added up across runs.
 */
export function checkCoverage({
  manifest,
  manifestSha256,
  runId,
  runtime,
  tap,
  records,
  nonce,
  files,
  root = repositoryRoot,
  allFiles,
}) {
  const problems = [];
  const run = runOf(manifest, runId);
  if (!run)
    return { problems: [`the manifest has no run ${show(runId)}`], coverage: [], totals: {} };
  if (!run.runtimes.includes(runtime)) problems.push(`run ${runId} is not run on Node ${runtime}`);
  // A string only: RegExp.test would read a one-item list holding the nonce as the nonce itself.
  if (typeof nonce !== 'string' || !HEX64.test(nonce))
    problems.push('the run nonce is not 64 lowercase hex digits');
  const declared = runFiles(manifest, runId, root, allFiles);
  const ran = files ? [...files].sort() : declared;
  if (ran.join('\n') !== declared.join('\n')) {
    const missing = declared.filter(file => !ran.includes(file));
    const extra = ran.filter(file => !declared.includes(file));
    problems.push(
      `the run's files are not run ${runId}'s: ${[...missing.map(file => `missing ${file}`), ...extra.map(file => `extra ${file}`)].join(', ')}`
    );
  }
  const { totals, problems: totalProblems } = tapTotals(tap);
  problems.push(...totalProblems);
  const { results, problems: parseProblems } = tapResults(tap);
  problems.push(...parseProblems);
  for (const result of results)
    if (result.directive)
      problems.push(
        `TAP line ${result.line}: "${result.path.join(' > ')}" has the directive ${result.directive}`
      );
  const platform = run.platform;
  const coverage = [];
  const resultRecords = records.filter(record => record.kind === 'result');
  const used = new Set();
  for (const entry of manifest.entries) {
    const lines = results.filter(result => samePath(result.path, entry.name));
    // An entry that must be absent is absent at any depth: no result line ends with its name path,
    // whatever parents it was put under.
    const anywhere = results.filter(result => endsWith(result.path, entry.name));
    const under = line =>
      line.path.length > entry.name.length
        ? ` (under "${line.path.slice(0, line.path.length - entry.name.length).join(' > ')}")`
        : '';
    const mine = resultRecords.filter(record => record.id === entry.id);
    for (const record of mine) used.add(record);
    const registered = entry.platforms.includes(platform);
    const required =
      registered && entry.evidence.includes(runId) && entry.runtimes.includes(runtime);
    const expected = registered && ran.includes(entry.file);
    const label = `${entry.id} ("${entry.name.join(' > ')}")`;
    if (!registered) {
      for (const line of anywhere)
        problems.push(
          `${label} belongs to ${entry.platforms.join(', ')}, not ${platform}, but TAP line ${line.line} names it${under(line)}`
        );
      for (const record of mine)
        problems.push(
          `${label} belongs to ${entry.platforms.join(', ')}, not ${platform}, but ${record.source} records it`
        );
      coverage.push({ id: entry.id, status: 'absent', lines: anywhere.map(line => line.line) });
      continue;
    }
    if (!expected) {
      for (const line of anywhere)
        problems.push(
          `${label}: TAP line ${line.line} names it${under(line)}, but this run does not run ${entry.file}`
        );
      for (const record of mine)
        problems.push(
          `${label}: ${record.source} records it, but this run does not run ${entry.file}`
        );
      coverage.push({ id: entry.id, status: 'not run', lines: [] });
      continue;
    }
    const status = required ? 'required' : 'present';
    if (lines.length !== 1)
      problems.push(
        `${label} has ${lines.length} result lines in this run, not one${lines.length ? ` (TAP lines ${lines.map(line => line.line).join(', ')})` : ': absence is not a pass'}`
      );
    else if (!lines[0].ok || lines[0].directive)
      problems.push(`${label} did not pass: TAP line ${lines[0].line}`);
    if (mine.length !== 1)
      problems.push(`${label} has ${mine.length} records in this run, not one`);
    for (const record of mine) {
      const at = record.source;
      if (record.run !== nonce)
        problems.push(`${label}: ${at} is from another run (${record.run.slice(0, 12)}…)`);
      if (record.manifest !== manifestSha256)
        problems.push(`${label}: ${at} was written with another manifest`);
      if (record.file !== entry.file)
        problems.push(`${label}: ${at} names the file ${record.file}`);
      if (!samePath(record.name, entry.name)) problems.push(`${label}: ${at} names another test`);
      if (record.platform !== platform)
        problems.push(`${label}: ${at} ran on ${record.platform}, not ${platform}`);
      if (major(record.node) !== runtime)
        problems.push(`${label}: ${at} ran on Node ${record.node}, not Node ${runtime}`);
      if (record.result !== 'completed') problems.push(`${label}: ${at} says ${record.result}`);
    }
    coverage.push({ id: entry.id, status, lines: lines.map(line => line.line) });
  }
  for (const record of resultRecords)
    if (!used.has(record))
      problems.push(
        `${record.source} records ${show(record.id)}, which the manifest does not list`
      );
  return { problems, coverage, totals };
}

/**
 * The T8 container evidence a host run must carry: when the run requires a T8 driver, one
 * `container` record per runtime of each container run, whose saved inner TAP and records pass
 * checkCoverage for that container run and runtime, with the driver's code as the nonce.
 */
export function checkContainerEvidence({
  manifest,
  manifestSha256,
  runId,
  runtime,
  records,
  nonce,
  directory,
  root = repositoryRoot,
}) {
  const problems = [];
  const evidence = [];
  const containerRecords = records.filter(record => record.kind === 'container');
  const used = new Set();
  for (const [containerId, run] of Object.entries(manifest.runs)) {
    if (run.platform !== 'container' || !run.hostRuns.includes(runId)) continue;
    for (const inner of run.runtimes) {
      const image = run.images[inner];
      const found = containerRecords.filter(record => record.runtime === inner);
      for (const record of found) used.add(record);
      if (image === null) {
        problems.push(
          `no T8 container evidence for Node ${inner}: ${containerId}.images.${inner} is null (no approved pinned image)`
        );
        continue;
      }
      if (found.length !== 1) {
        problems.push(`${found.length} T8 container records for Node ${inner}, not one`);
        continue;
      }
      const record = found[0];
      const label = `the T8 container run on Node ${inner} (${record.source})`;
      if (record.run !== nonce) problems.push(`${label} is from another run`);
      if (record.manifest !== manifestSha256)
        problems.push(`${label} was written with another manifest`);
      if (record.id !== image.driver)
        problems.push(`${label} names the driver ${record.id}, not ${image.driver}`);
      if (record.image !== image.image)
        problems.push(`${label} ran ${record.image}, not ${image.image}`);
      if (major(record.node) !== inner)
        problems.push(`${label}: the run inside was Node ${record.node}, not Node ${inner}`);
      const folder = path.join(directory, record.evidence);
      let tapBytes, inside;
      try {
        if (!fs.lstatSync(folder).isDirectory()) throw new Error('not a directory');
        tapBytes = readBounded(path.join(folder, 'inner.tap'), limits.tapBytes);
        inside = readRecords(path.join(folder, 'records'), { containers: false });
      } catch (error) {
        problems.push(`${label}: its evidence cannot be read (${error.code || error.message})`);
        continue;
      }
      if (sha256(tapBytes) !== record.tapSha256)
        problems.push(`${label}: inner.tap changed after the driver recorded it`);
      if (inside.digest !== record.recordsSha256)
        problems.push(`${label}: its records changed after the driver recorded them`);
      problems.push(...inside.problems.map(problem => `${label}: ${problem}`));
      const result = checkCoverage({
        manifest,
        manifestSha256,
        runId: containerId,
        runtime: inner,
        tap: tapBytes.toString('utf8'),
        records: inside.records,
        nonce: record.code,
        root,
      });
      problems.push(...result.problems.map(problem => `${label}: ${problem}`));
      evidence.push({
        runtime: inner,
        image: record.image,
        imageId: record.imageId,
        node: record.node,
        code: record.code,
        totals: result.totals,
        coverage: result.coverage,
      });
    }
  }
  for (const record of containerRecords)
    if (!used.has(record))
      problems.push(`${record.source}: a T8 container record this run does not require`);
  return { problems, evidence };
}

// ---------------------------------------------------------------------------------------------
// Removal and weakening

/**
 * The losses of `candidate` (a validated manifest, or null for none) against `baseline` (a
 * validated manifest): every entry or run removed, and every narrowing of one, each as { key,
 * old, what }: `old` is the entry or run as the baseline had it. Adding never loses anything.
 */
function lossesAgainst(baseline, candidate) {
  const losses = [];
  const now = candidate ?? { runs: {}, entries: [] };
  const lose = (key, old, what) => losses.push({ key, old, what });
  for (const [id, run] of Object.entries(baseline.runs)) {
    const next = runOf(now, id);
    if (!next) {
      lose(`run:${id}`, run, `run ${id} was removed`);
      continue;
    }
    if (next.platform !== run.platform)
      lose(`run:${id}:platform`, run, `run ${id} moved from ${run.platform} to ${next.platform}`);
    for (const runtime of run.runtimes)
      if (!next.runtimes.includes(runtime))
        lose(`run:${id}:runtime:${runtime}`, run, `run ${id} no longer runs on Node ${runtime}`);
    for (const gate of run.requiredFor)
      if (!next.requiredFor.includes(gate))
        lose(`run:${id}:requiredFor:${gate}`, run, `run ${id} is no longer required for ${gate}`);
    if (run.files === 'all') {
      if (next.files !== 'all')
        lose(`run:${id}:files`, run, `run ${id} no longer runs every test file`);
    } else if (next.files !== 'all')
      for (const file of run.files)
        if (!next.files.includes(file))
          lose(`run:${id}:file:${file}`, run, `run ${id} no longer runs ${file}`);
    for (const host of run.hostRuns ?? [])
      if (!next.hostRuns?.includes(host))
        lose(
          `run:${id}:hostRun:${host}`,
          run,
          `run ${id} is no longer run by the driver in ${host}`
        );
    // A pinned image is the reviewed one: another digest or driver is not the same evidence.
    for (const [runtime, image] of Object.entries(run.images ?? {})) {
      if (image === null) continue;
      const after =
        isObject(next.images) && own(next.images, runtime) ? next.images[runtime] : null;
      if (!isObject(after))
        lose(
          `run:${id}:image:${runtime}`,
          run,
          `run ${id} has no image for Node ${runtime} any more`
        );
      else if (after.image !== image.image || after.driver !== image.driver)
        lose(
          `run:${id}:image:${runtime}`,
          run,
          `run ${id} runs another image or driver for Node ${runtime}`
        );
    }
  }
  for (const entry of baseline.entries) {
    const next = now.entries.find(item => item.id === entry.id);
    if (!next) {
      lose(`entry:${entry.id}`, entry, `entry ${entry.id} was removed`);
      continue;
    }
    if (next.file !== entry.file)
      lose(
        `entry:${entry.id}:file`,
        entry,
        `entry ${entry.id} moved from ${entry.file} to ${next.file}`
      );
    if (!samePath(next.name, entry.name))
      lose(`entry:${entry.id}:name`, entry, `entry ${entry.id} names another test`);
    for (const platform of entry.platforms)
      if (!next.platforms.includes(platform))
        lose(
          `entry:${entry.id}:platform:${platform}`,
          entry,
          `entry ${entry.id} is no longer registered on ${platform}`
        );
    for (const runtime of entry.runtimes)
      if (!next.runtimes.includes(runtime))
        lose(
          `entry:${entry.id}:runtime:${runtime}`,
          entry,
          `entry ${entry.id} is no longer required on Node ${runtime}`
        );
    for (const runId of entry.evidence)
      if (!next.evidence.includes(runId))
        lose(
          `entry:${entry.id}:evidence:${runId}`,
          entry,
          `entry ${entry.id} is no longer required of run ${runId}`
        );
    // A prerequisite only adds a condition (an unmet one fails the test, or skips the driver
    // without TEST_REQUIRE=docker, which the check refuses); removing one changes what runs.
    for (const prerequisite of entry.prerequisites)
      if (!next.prerequisites.includes(prerequisite))
        lose(
          `entry:${entry.id}:prerequisite:${prerequisite}`,
          entry,
          `entry ${entry.id} no longer needs ${prerequisite}`
        );
  }
  return losses;
}

const reviewText = value =>
  typeof value === 'string' &&
  value.trim().length > 0 &&
  value.length <= limits.textLength &&
  !/[\u0000-\u001f\u007f]/.test(value);

/**
 * Why a disposition is not bound to the candidate or lacks its review fields, or null. The binding
 * is the candidate's tree with its complete ordered parent vector (GATE-CONTRACT v3 C18): a
 * disposition names the same tree and the same parents in the same order, never a single parent.
 */
function bindingProblem(where, disposition, binding) {
  const parents = binding?.parents;
  if (
    typeof binding?.tree !== 'string' ||
    !Array.isArray(parents) ||
    !parents.length ||
    typeof disposition.tree !== 'string' ||
    !COMMIT.test(disposition.tree) ||
    disposition.tree !== binding.tree ||
    !Array.isArray(disposition.parents) ||
    disposition.parents.length !== parents.length ||
    !disposition.parents.every(
      (item, index) => typeof item === 'string' && COMMIT.test(item) && item === parents[index]
    )
  )
    return `${where} is not bound to this candidate's tree and complete ordered parent vector`;
  if (
    !reviewText(disposition.reason) ||
    !reviewText(disposition.reviewer) ||
    !reviewText(disposition.reference)
  )
    return `${where} needs a reason, a reviewer and an evidence reference`;
  return null;
}

const LOSS_DISPOSITION = [
  'loss',
  'old',
  'replacement',
  'reason',
  'reviewer',
  'reference',
  'tree',
  'parents',
];
const lossKey = (key, old) => `${key}\0${JSON.stringify(old)}`;

/**
 * Applies loss dispositions, given as [index, disposition] pairs, to `losses` of the candidate
 * manifest `candidate`: a disposition excuses the loss whose key and old value it names exactly
 * (the same loss against several baselines is one loss), once. Returns { excused(loss), problems }.
 */
function applyDispositions(losses, pairs, binding, candidate) {
  const problems = [];
  const excused = new Set();
  for (const [index, disposition] of pairs) {
    const where = `disposition ${index}`;
    const fields = keysProblems(where, disposition, LOSS_DISPOSITION);
    if (fields.length) {
      problems.push(...fields);
      continue;
    }
    const bound = bindingProblem(where, disposition, binding);
    if (bound) {
      problems.push(bound);
      continue;
    }
    const named = losses.filter(loss => loss.key === disposition.loss);
    if (!named.length) {
      problems.push(`${where} names ${show(disposition.loss)}, which this candidate does not lose`);
      continue;
    }
    const key = lossKey(disposition.loss, disposition.old);
    if (!named.some(loss => lossKey(loss.key, loss.old) === key)) {
      problems.push(`${where}: its old ${named[0].key.split(':')[0]} is not the baseline's`);
      continue;
    }
    if (
      disposition.replacement !== null &&
      !candidate.entries.some(entry => entry.id === disposition.replacement)
    ) {
      problems.push(
        `${where}: its replacement ${show(disposition.replacement)} is not an entry of the candidate`
      );
      continue;
    }
    if (excused.has(key)) {
      problems.push(`${where}: ${disposition.loss} already has a disposition`);
      continue;
    }
    excused.add(key);
  }
  return { excused: loss => excused.has(lossKey(loss.key, loss.old)), problems };
}

const NO_BASELINE =
  'there is no baseline manifest to judge the candidate against: a parent without one is not a maintenance branch (judgeCandidateManifest decides that from the history)';
const NO_CANDIDATE =
  'the candidate has no usable manifest: it loses every entry and run, and no disposition excuses that';

/**
 * The coverage `candidate` loses against one `baseline` manifest: { losses, problems }. Both are
 * validated manifests, except that `candidate` may be null (none, or unusable), which loses
 * everything and is a problem no disposition excuses. A loss is excused only by one disposition
 * naming it exactly (its key, and the old entry or run as the baseline had it), bound to the
 * candidate's tree and complete ordered parent vector, with a reason, a reviewer and an evidence
 * reference. A disposition that excuses nothing, or a second one for a loss, is a problem. A
 * missing baseline is a problem too, never "nothing to lose": a commit made without the guard can
 * delete the manifest, so judgeCandidateManifest finds the baselines in the candidate's history.
 */
export function coverageLoss(baseline, candidate, dispositions = [], binding = {}) {
  if (!isObject(baseline) || !isObject(baseline.runs) || !Array.isArray(baseline.entries))
    return { losses: [], problems: [NO_BASELINE] };
  const losses = lossesAgainst(baseline, candidate);
  const problems = candidate ? [] : [NO_CANDIDATE];
  if (!Array.isArray(dispositions) || dispositions.length > limits.dispositions)
    return {
      losses: losses.map(loss => ({ ...loss, excused: false })),
      problems: [...problems, `dispositions is not a list of at most ${limits.dispositions}`],
    };
  const applied = candidate
    ? applyDispositions(losses, [...dispositions.entries()], binding, candidate)
    : { excused: () => false, problems: [] };
  return {
    losses: losses.map(loss => ({ ...loss, excused: applied.excused(loss) })),
    problems: [...problems, ...applied.problems],
  };
}

const isBytes = value => typeof value === 'string' || value instanceof Uint8Array;
const asBuffer = bytes =>
  typeof bytes === 'string' || Buffer.isBuffer(bytes)
    ? bytes
    : Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
const HISTORY_NODE = ['commit', 'parents', 'manifest', 'reviewed'];
const BASELINE_DISPOSITION = [
  'baseline',
  'manifestSha256',
  'reason',
  'reviewer',
  'reference',
  'tree',
  'parents',
];
const commitList = (value, max) =>
  Array.isArray(value) &&
  value.length <= max &&
  value.every(item => typeof item === 'string' && COMMIT.test(item)) &&
  new Set(value).size === value.length;

/**
 * Judges a candidate's test/platform-manifest.json against the manifests in its history, so that
 * a commit made without the guard (with --no-verify, or by git revert, cherry-pick or rebase, which
 * run no pre-commit hook) can neither delete nor weaken the coverage that history established.
 *
 * - `candidate`: the candidate's manifest bytes, or null when it has none.
 * - `heads`: the candidate's parents (HEAD and each MERGE_HEAD; none for a root commit).
 * - `history`: every commit those parents reach, each { commit, parents, manifest, reviewed }:
 *   `manifest` is the bytes at test/platform-manifest.json in that commit, or null for nothing
 *   there (something there that is not a regular file is given as bytes that do not validate, such
 *   as an empty buffer); `reviewed` is null, or { manifestSha256 } when a verified finalization of
 *   the gate approved that commit, with the sha256 of the manifest its coverage check judged (null
 *   when the commit had none). A commit the parents reach but `history` lacks is a problem.
 * - `dispositions`: loss dispositions (as for coverageLoss) and baseline dispositions,
 *   { baseline, manifestSha256, reason, reviewer, reference, tree, parents }, each making the valid
 *   manifest of one commit behind the candidate a reviewed baseline.
 * - `binding`: the candidate's { tree, parents } (its complete ordered parent vector).
 *
 * A branch whose history never held the manifest (maintenance, B35) loses nothing and needs no
 * platform run (kind 'maintenance'), and a candidate that adds the first one loses nothing (kind
 * 'introduction'). Once any commit behind the candidate held it (kind 'manifest'), the candidate
 * must hold a valid manifest, and no disposition excuses its removal; it is judged against every
 * valid manifest from its parents back to the last reviewed commit on each path, that commit
 * included, and at least one of those baselines must be established by review (a reviewed commit
 * or a baseline disposition), or the candidate is refused. A baseline disposition adds a baseline;
 * it never removes one. Returns { kind, manifest, sha256, baselines, losses, problems }: the
 * candidate passes only with no problem and every loss excused.
 */
export function judgeCandidateManifest({
  candidate = null,
  heads,
  history,
  dispositions = [],
  binding = {},
} = {}) {
  const problems = [];
  const result = (kind, extra = {}) => ({
    kind,
    manifest: null,
    sha256: null,
    baselines: [],
    losses: [],
    problems,
    ...extra,
  });
  if (!commitList(heads, limits.parents))
    problems.push(`heads is not a list of at most ${limits.parents} distinct commit ids`);
  if (!Array.isArray(history) || history.length > limits.historyCommits)
    problems.push(`history is not a list of at most ${limits.historyCommits} commits`);
  if (!Array.isArray(dispositions) || dispositions.length > limits.dispositions)
    problems.push(`dispositions is not a list of at most ${limits.dispositions}`);
  if (candidate !== null && !isBytes(candidate))
    problems.push('the candidate manifest is neither bytes nor null');
  if (problems.length) return result(null);
  const nodes = new Map();
  for (const [index, node] of history.entries()) {
    const where = `history ${index}`;
    const fields = keysProblems(where, node, HISTORY_NODE);
    if (fields.length) {
      problems.push(...fields);
      continue;
    }
    if (typeof node.commit !== 'string' || !COMMIT.test(node.commit)) {
      problems.push(`${where}: commit is not a commit id`);
      continue;
    }
    if (nodes.has(node.commit)) {
      problems.push(`${where}: commit ${node.commit} is given twice`);
      continue;
    }
    if (!commitList(node.parents, limits.parents))
      problems.push(
        `${where}: parents is not a list of at most ${limits.parents} distinct commit ids`
      );
    if (node.manifest !== null && !isBytes(node.manifest))
      problems.push(`${where}: manifest is neither bytes nor null`);
    if (
      node.reviewed !== null &&
      (keysProblems(where, node.reviewed, ['manifestSha256']).length ||
        (node.reviewed.manifestSha256 !== null && !HEX64.test(`${node.reviewed.manifestSha256}`)))
    )
      problems.push(`${where}: reviewed is neither null nor { manifestSha256 }`);
    nodes.set(node.commit, node);
  }
  if (problems.length) return result(null);
  // Each distinct manifest is parsed once, however many commits hold it.
  const parsed = new Map();
  const parse = bytes => {
    const buffer = asBuffer(bytes);
    const digest = sha256(buffer);
    if (!parsed.has(digest)) parsed.set(digest, parseManifest(buffer));
    return parsed.get(digest);
  };
  const mine = candidate === null ? null : parse(candidate);
  const candidateManifest = mine?.manifest ?? null;
  // Every commit the parents reach (B35: the history behind the parents counts).
  const reachable = new Set();
  const stack = [...heads];
  while (stack.length) {
    const id = stack.pop();
    if (reachable.has(id)) continue;
    reachable.add(id);
    const node = nodes.get(id);
    if (node) stack.push(...node.parents);
    else problems.push(`the history lacks commit ${id}, which the candidate's parents reach`);
  }
  const held = [...reachable].some(id => (nodes.get(id)?.manifest ?? null) !== null);
  if (!held) {
    if (dispositions.length)
      problems.push(
        'dispositions were given, but no commit behind the candidate holds a manifest: nothing can be lost'
      );
    if (candidate === null) return result('maintenance');
    problems.push(...mine.problems);
    return result('introduction', { manifest: candidateManifest, sha256: mine.sha256 });
  }
  if (candidate === null)
    problems.push(
      'the candidate has no test/platform-manifest.json, which a commit behind it holds: that removes every platform run, and no disposition excuses it'
    );
  else if (mine.problems.length)
    problems.push(
      `the candidate's test/platform-manifest.json is not usable, and a commit behind it holds one: ${mine.problems.join('; ')}`
    );
  // The baselines: every valid manifest from the parents back to the last reviewed commit on each
  // path, that commit included. A reviewed commit ends its path: what lies behind it was judged
  // when it was approved.
  const baselines = new Map();
  const addBaseline = (commit, manifest, reviewed, source) => {
    const known = baselines.get(manifest.sha256);
    if (known) {
      known.reviewed ||= reviewed;
      known.sources.add(source);
      known.commits.add(commit);
    } else
      baselines.set(manifest.sha256, {
        sha256: manifest.sha256,
        manifest: manifest.manifest,
        commits: new Set([commit]),
        reviewed,
        sources: new Set([source]),
      });
  };
  const visited = new Set();
  const work = [...heads];
  while (work.length) {
    const id = work.pop();
    if (visited.has(id)) continue;
    visited.add(id);
    const node = nodes.get(id);
    if (!node) continue;
    const manifest = node.manifest === null ? null : parse(node.manifest);
    let reviewed = false;
    if (node.reviewed) {
      const holds = manifest ? manifest.sha256 : null;
      if (node.reviewed.manifestSha256 === holds) reviewed = true;
      else
        problems.push(
          `commit ${id}: its approval judged ${node.reviewed.manifestSha256 === null ? 'no manifest' : `the manifest ${node.reviewed.manifestSha256}`}, not ${holds === null ? 'the commit, which has none' : `the one it holds (${holds})`}`
        );
    }
    if (manifest?.manifest) addBaseline(id, manifest, reviewed, reviewed ? 'reviewed' : 'history');
    if (!reviewed) work.push(...node.parents);
  }
  const named = new Set();
  const lossPairs = [];
  for (const [index, disposition] of dispositions.entries()) {
    if (!isObject(disposition) || !own(disposition, 'baseline')) {
      lossPairs.push([index, disposition]);
      continue;
    }
    const where = `disposition ${index}`;
    const fields = keysProblems(where, disposition, BASELINE_DISPOSITION);
    if (fields.length) {
      problems.push(...fields);
      continue;
    }
    const bound = bindingProblem(where, disposition, binding);
    if (bound) {
      problems.push(bound);
      continue;
    }
    const node =
      typeof disposition.baseline === 'string' && reachable.has(disposition.baseline)
        ? nodes.get(disposition.baseline)
        : undefined;
    if (!node) {
      problems.push(
        `${where} names ${show(disposition.baseline)}, which is not a commit behind the candidate`
      );
      continue;
    }
    const manifest = node.manifest === null ? null : parse(node.manifest);
    if (!manifest?.manifest || manifest.sha256 !== disposition.manifestSha256) {
      problems.push(
        `${where}: commit ${node.commit} holds no valid manifest with the sha256 it names`
      );
      continue;
    }
    if (named.has(node.commit)) {
      problems.push(`${where}: commit ${node.commit} already has a baseline disposition`);
      continue;
    }
    named.add(node.commit);
    addBaseline(node.commit, manifest, true, 'disposition');
  }
  const list = [...baselines.values()];
  if (!list.some(baseline => baseline.reviewed))
    problems.push(
      'no reviewed manifest can be established for this candidate: no commit behind it that the gate approved holds a valid manifest on the way back from its parents, and no baseline disposition names one'
    );
  const losses = new Map();
  for (const baseline of list)
    for (const loss of lossesAgainst(baseline.manifest, candidateManifest)) {
      const key = lossKey(loss.key, loss.old);
      if (losses.has(key)) losses.get(key).baselines.push(baseline.sha256);
      else losses.set(key, { ...loss, baselines: [baseline.sha256] });
    }
  const applied = candidateManifest
    ? applyDispositions([...losses.values()], lossPairs, binding, candidateManifest)
    : { excused: () => false, problems: [] };
  return result('manifest', {
    manifest: candidateManifest,
    sha256: mine?.sha256 ?? null,
    baselines: list.map(({ sha256: digest, commits, reviewed, sources }) => ({
      sha256: digest,
      commits: [...commits],
      reviewed,
      sources: [...sources],
    })),
    losses: [...losses.values()].map(loss => ({ ...loss, excused: applied.excused(loss) })),
    problems: [...problems, ...applied.problems],
  });
}

// ---------------------------------------------------------------------------------------------
// Command line

const isMain = () => {
  try {
    return (
      Boolean(process.argv[1]) &&
      fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url))
    );
  } catch {
    return false;
  }
};

const usage =
  'Usage: node scripts/check-platform-coverage.mjs --run <id> --runtime <24|26> --tap <file> --records <dir> --nonce <64 hex> [--root <dir>] [--manifest <file>] [--files-from <file>] [--json]';

export function parseArguments(argv) {
  const options = { json: false };
  const names = {
    '--run': 'run',
    '--runtime': 'runtime',
    '--tap': 'tap',
    '--records': 'records',
    '--nonce': 'nonce',
    '--root': 'root',
    '--manifest': 'manifest',
    '--files-from': 'filesFrom',
  };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--json' && !options.json) options.json = true;
    else if (own(names, argv[i]) && i + 1 < argv.length && !own(options, names[argv[i]]))
      options[names[argv[i]]] = argv[++i];
    else throw new Error(`unexpected argument ${show(argv[i])}`);
  }
  for (const name of ['run', 'runtime', 'tap', 'records', 'nonce'])
    if (!options[name]) throw new Error(`--${name} is required`);
  return options;
}

if (isMain()) {
  let options;
  try {
    options = parseArguments(process.argv.slice(2));
  } catch (error) {
    console.error(`${error.message}\n${usage}`);
    process.exit(2);
  }
  const root = path.resolve(options.root ?? repositoryRoot);
  let report;
  try {
    const { manifest, sha256: manifestSha256 } = readManifest(
      root,
      options.manifest ? path.resolve(options.manifest) : undefined
    );
    const tap = readBounded(path.resolve(options.tap), limits.tapBytes).toString('utf8');
    const read = readRecords(path.resolve(options.records));
    const files = options.filesFrom
      ? readBounded(path.resolve(options.filesFrom), 1024 * 1024)
          .toString('utf8')
          .split('\n')
          .filter(Boolean)
      : undefined;
    const common = {
      manifest,
      manifestSha256,
      runId: options.run,
      runtime: options.runtime,
      records: read.records,
      nonce: options.nonce,
      root,
    };
    const run = checkCoverage({ ...common, tap, files });
    const container = checkContainerEvidence({
      ...common,
      directory: path.resolve(options.records),
    });
    report = {
      run: options.run,
      runtime: options.runtime,
      manifestSha256,
      totals: run.totals,
      coverage: run.coverage,
      container: container.evidence,
      problems: [...read.problems, ...run.problems, ...container.problems],
    };
  } catch (error) {
    report = { run: options.run, runtime: options.runtime, problems: [error.message] };
  }
  if (options.json) console.log(JSON.stringify(report, null, 2));
  else if (report.problems.length)
    for (const problem of report.problems) console.error(`✖ ${problem}`);
  else
    console.log(
      `✔ run ${report.run} on Node ${report.runtime} covers the platform contract (${report.coverage.filter(item => item.status === 'required').length} required entries)`
    );
  process.exitCode = report.problems.length ? 1 : 0;
}
