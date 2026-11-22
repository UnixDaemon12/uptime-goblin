// The gate's side of the platform coverage contract (test/platform-manifest.json, which
// scripts/check-platform-coverage.mjs validates and checks runs against).
//
// - The environment of a test stage: no inherited TEST_*, UPDATE_GOLDEN or NODE_TEST_CONTEXT, and
//   the gate's own TEST_REQUIRE, records folder and run code.
// - The sealed form of a test stage's platform records (one flat file, as sealRun() needs).
// - The history the candidate's manifest is judged against (judgeCandidateManifest), and the file
//   of reviewed coverage dispositions.
// - The candidate identity of GATE-CONTRACT v3 C18: the tree with its complete ordered parent
//   vector, and after a commit exists the same vector recomputed from the commit's own object.
// - The checks of a run's platform evidence that the gate makes during the run and the finalizer
//   and the commit guard make again from the sealed evidence: the run's own test stages, its
//   companion runs on the other platforms, each Node runtime's identity, the authenticity of the
//   T8 images and, on Linux, the network record.
//
// It reads no run directory: scripts/security-finalization.mjs reads sealed runs and gives them
// here. Like the modules it imports, it uses only Node's own modules, so the commit guard carries
// it beside them (scripts/install-security-hooks.mjs). These are local consistency checks, not
// signatures: code a stage runs can still forge what it writes, as the gate's own logs.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { sha256, testTotals } from './security-evidence.mjs';
import {
  PROFILE_PLATFORMS,
  canonicalJson,
  installedCatalog,
  judgeStages,
  profileStages,
} from './security-catalog.mjs';
import {
  checkEntryData,
  entryCountProblems,
  entryProfile,
  impliedDirectories,
  pathProblem,
  profileIdentity,
  validateEntries,
} from './security-entries.mjs';
import { gateIdentityStage } from './security-gate-identity.mjs';
import {
  checkContainerEvidence,
  checkCoverage,
  duplicateMembers,
  judgeCandidateManifest,
  readRecords,
  recordNames,
} from './check-platform-coverage.mjs';

export const manifestFile = 'test/platform-manifest.json';
/**
 * The record family of this draft's local run record (result.json) and its version within that
 * family (security review GDR4-02; maintainer note 014104 item 6c): a local diagnostic record, not a C12 phase
 * record. scripts/security-finalization.mjs reads it (recordFamily, parseRunRecord).
 */
export const LOCAL_RUN_KIND = 'orbit-gate-local-diagnostic-run';
export const LOCAL_RUN_KIND_VERSION = 1;
const HEX64 = /^[0-9a-f]{64}$/;
const OBJECT_ID = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const NODE_VERSION = /^v(\d{1,3})\.\d{1,4}\.\d{1,4}$/;
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const own = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
const show = value => JSON.stringify(value)?.slice(0, 200);
// A pattern applies only to a string: RegExp.test turns a list into text, so ['<64 hex>'] would
// otherwise pass as '<64 hex>'.
export const matches = (pattern, value) => typeof value === 'string' && pattern.test(value);
const major = version =>
  typeof version === 'string' ? NODE_VERSION.exec(version)?.[1] : undefined;
const text = value =>
  typeof value === 'string' &&
  value.trim().length > 0 &&
  value.length <= 2000 &&
  !/[\u0000-\u001f\u007f]/.test(value);
// A UTC time as the gate writes it (toISOString, or without milliseconds or with fewer digits), and
// a real calendar time: it must read back as the same date and time. Date.parse alone rolls a day
// or hour that does not exist over (2026-09-31 as 2026-10-01, T24:00:00 as the next day), so such a
// time would count as well formed for one reader and malformed for a stricter one (verify-1 of
// gate-draft-r4; v5 C3, C14, C23 change 18: a malformed start or end breaks the order rules).
const UTC_TIME = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,3}))?Z$/;
export const isTime = value => {
  const parts = typeof value === 'string' ? UTC_TIME.exec(value) : null;
  if (!parts) return false;
  const at = Date.parse(value);
  return (
    Number.isFinite(at) &&
    new Date(at).toISOString() === `${parts[1]}.${(parts[2] ?? '').padEnd(3, '0')}Z`
  );
};

/** Problems with the fields of `value`: exactly `required`, plus any of `optional`. */
function fields(where, value, required, optional = []) {
  if (!isObject(value)) return [`${where} is not an object`];
  const problems = [];
  for (const key of Object.keys(value))
    if (!required.includes(key) && !optional.includes(key))
      problems.push(`${where} has the unknown field ${show(key)}`);
  for (const key of required) if (!own(value, key)) problems.push(`${where} lacks ${key}`);
  return problems;
}

/** Parses bytes as one strict JSON document: UTF-8, no member named twice in one object. */
export function strictJson(bytes, what, max = 1024 * 1024) {
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (buffer.length > max) throw new Error(`${what} is larger than ${max} bytes`);
  const source = buffer.toString('utf8');
  if (!Buffer.from(source, 'utf8').equals(buffer)) throw new Error(`${what} is not UTF-8`);
  let value;
  try {
    value = JSON.parse(source);
  } catch {
    throw new Error(`${what} is not JSON`);
  }
  const twice = duplicateMembers(source);
  if (twice.length) throw new Error(`${what} names the member ${show(twice[0])} twice`);
  return value;
}

/**
 * A regular file of at most `max` bytes, opened without following a link. With `privateOnly`,
 * a file that its group or others may read or write is refused, as the gate's evidence is.
 */
export function readRegularFile(file, { max = 1024 * 1024, privateOnly = true } = {}) {
  const fd = fs.openSync(
    file,
    fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK
  );
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile()) throw new Error(`${file} is not a regular file`);
    if (privateOnly && stat.mode & 0o077) throw new Error(`${file} is not private`);
    if (stat.size > max) throw new Error(`${file} is larger than ${max} bytes`);
    const bytes = fs.readFileSync(fd);
    if (bytes.length !== stat.size) throw new Error(`${file} changed size while being read`);
    return bytes;
  } finally {
    fs.closeSync(fd);
  }
}

// ---------------------------------------------------------------------------------------------
// The environment of a test stage

/**
 * The TEST_REQUIRE of every test stage: every name that makes a 1.5 suite fail instead of skipping
 * when what it needs is missing (test/setup.mjs), including the 250,000-row audit capacity
 * measurement and Git. `postgres` is known to test/setup.mjs but has no consumer before 1.7; add it
 * here when a suite starts to need a PostgreSQL server.
 */
export const testRequire = 'browser,fixtures,systemd,docker,capacity,git';

/**
 * Whether the gate never inherits the variable `name`, in any letter case: every TEST_* (the
 * suite's switches, TEST_REQUIRE, TEST_T8_DIR, TEST_T8_RUN, TEST_TAG_TREES, TEST_PLATFORM_RECORDS
 * and TEST_PLATFORM_RUN today, and any added later), UPDATE_GOLDEN (the golden test rewrites the
 * tracked files instead of comparing them) and NODE_TEST_CONTEXT (it changes what node --test
 * prints).
 */
export const isTestInput = name => /^(?:TEST_|UPDATE_GOLDEN$|NODE_TEST_CONTEXT$)/i.test(name);

/**
 * Removes every test input from `env` (the gate passes process.env, before any stage runs).
 * Returns what to record: the count and the names, never the values (at most 100 names of at most
 * 200 characters each).
 */
export function removeTestInputs(env) {
  const names = Object.keys(env).filter(isTestInput).sort();
  for (const name of names) delete env[name];
  return { count: names.length, names: names.slice(0, 100).map(name => name.slice(0, 200)) };
}

/**
 * Inherited variables that choose a tool the test stages use: which git, docker, setfacl, python3
 * and curl (PATH), which browser (CHROME_PATH, test/helpers/cdp.mjs), which Docker daemon the T8
 * driver and the image check talk to (DOCKER_HOST, DOCKER_CONTEXT, DOCKER_CONFIG), and the home
 * and temporary folders.
 */
export const steeringInputs = Object.freeze([
  'PATH',
  'CHROME_PATH',
  'DOCKER_HOST',
  'DOCKER_CONTEXT',
  'DOCKER_CONFIG',
  'HOME',
  'TMPDIR',
]);

/**
 * What the gate inherits from the caller's environment `env` (after the gate's own removals of
 * test inputs, npm settings and NODE_OPTIONS, and before it sets any Git variable of its own): the
 * count and names of all variables (at most 500 names of at most 200 characters), and the values
 * of steeringInputs (null when unset; at most 4096 characters each). Other values are never
 * recorded. Every stage gets these variables with their Git variables as stageGitEnvironment sets
 * them (since gate-draft-r11: a Git variable named here that STAGE_GIT_VARIABLES does not admit
 * reaches no stage, and the gate's own Git settings are not named here), and the test stages also
 * the gate's three controls.
 */
export function inheritedEnvironment(env) {
  const names = Object.keys(env).sort();
  return {
    count: names.length,
    names: names.slice(0, 500).map(name => name.slice(0, 200)),
    values: Object.fromEntries(
      steeringInputs.map(name => [
        name,
        typeof env[name] === 'string' ? env[name].slice(0, 4096) : null,
      ])
    ),
  };
}

/**
 * A new private folder for one test stage's records, and a new run code. The folder is the real
 * path, so a link in the scratch area's path cannot lead the records elsewhere.
 */
export function testControls(parent, label) {
  const records = fs.realpathSync(fs.mkdtempSync(path.join(parent, `records-${label}-`)));
  fs.chmodSync(records, 0o700);
  return { records, run: randomBytes(32).toString('hex') };
}

/**
 * The environment of a test stage: `env` without any test input, then the gate's TEST_REQUIRE,
 * TEST_PLATFORM_RECORDS (`records`: an absolute, empty folder of this user that nobody else may
 * read, not a link) and TEST_PLATFORM_RUN (`run`: 64 lowercase hex digits). Throws when a control
 * is malformed.
 */
export function testEnvironment(env, { records, run }, uid = process.getuid?.()) {
  if (
    typeof records !== 'string' ||
    !path.isAbsolute(records) ||
    Buffer.byteLength(records) > 1024 ||
    /[\u0000-\u001f\u007f]/.test(records)
  )
    throw new Error(
      "a test stage's records folder must be an absolute path of at most 1024 bytes without control characters"
    );
  const stat = fs.lstatSync(records);
  if (
    !stat.isDirectory() ||
    stat.mode & 0o077 ||
    (uid !== undefined && stat.uid !== uid) ||
    fs.readdirSync(records).length
  )
    throw new Error(
      "a test stage's records folder must be a new, empty folder of the gate's user that nobody else may read (not a link)"
    );
  if (!matches(HEX64, run))
    throw new Error("a test stage's run code must be 64 lowercase hex digits");
  const kept = Object.fromEntries(Object.entries(env).filter(([name]) => !isTestInput(name)));
  return {
    ...kept,
    TEST_REQUIRE: testRequire,
    TEST_PLATFORM_RECORDS: records,
    TEST_PLATFORM_RUN: run,
  };
}

// ---------------------------------------------------------------------------------------------
// The sealed form of a records folder

// The profile of a sealed records pack in the shared entry validator (scripts/security-entries.mjs;
// maintainer decision 3): packRecords, which writes a pack, and validatePack, which every reader of one
// goes through (unpackRecords, so the finalizer and the commit guard too), name this one constant
// and nothing a pack says. GATE-CONTRACT v4 C21 (a draft); security review GD-02.
const RECORD_PACK = entryProfile('record-pack', 1);
/** The limits of a sealed records pack: the record-pack profile's (security-entries.mjs). */
export const packLimits = RECORD_PACK.limits;
/** What this reader names of the record-pack profile: { name, sha256, version }. */
export const recordPackIdentity = () => profileIdentity(RECORD_PACK);
/**
 * Problems with a catalog's binding of the record-pack profile (its `recordPack`): it must name
 * exactly this validator's profile, its name, version and sha256 (v5 C21, C24 change 11; maintainer
 * decision 3). The sha256 covers the validator module's own bytes, so a catalog bound to another
 * validator, or a validator changed under an unchanged catalog, is refused by every producer and
 * reader of a pack.
 */
export function recordPackBindingProblems(catalog) {
  const bound = catalog?.recordPack ?? null;
  return canonicalJson(bound) === canonicalJson(recordPackIdentity())
    ? []
    : [
        `the catalog binds the record-pack profile ${show(bound)}, not this validator's ${show(recordPackIdentity())} (v5 C21, C24; maintainer decision 3)`,
      ];
}
/** Throws unless the installed catalog binds this validator's record-pack profile. */
function assertRecordPackBound() {
  const problems = recordPackBindingProblems(installedCatalog().catalog);
  if (problems.length) throw new Error(problems[0]);
}
/**
 * The pack schema: 2 names its entry profile. A schema 1 pack names none and is refused. This is
 * the record pack's own series: it is not the run record's schema (security-finalization.mjs), and
 * no reader takes one number for the other (v5 C12, C21).
 */
export const PACK_SCHEMA = 2;
const { file: RECORD_FILE, container: CONTAINER_DIR } = recordNames;

/** 'file', 'directory' or null: whether `relative` is a path the harness writes in a records folder. */
function packedKind(relative) {
  if (typeof relative !== 'string') return null;
  const parts = relative.split('/');
  if (parts.length === 1)
    return RECORD_FILE.test(parts[0]) ? 'file' : CONTAINER_DIR.test(parts[0]) ? 'directory' : null;
  if (!CONTAINER_DIR.test(parts[0])) return null;
  if (parts.length === 2)
    return parts[1] === 'inner.tap' ? 'file' : parts[1] === 'records' ? 'directory' : null;
  if (parts.length === 3 && parts[1] === 'records' && RECORD_FILE.test(parts[2])) return 'file';
  return null;
}

/**
 * Problems with the counts of a pack against `limits` (the record-pack profile's; a test may pass
 * other values to show that each check works on its own): entryCountProblems of the shared
 * validator.
 */
export const packCountProblems = (counts, limits = packLimits) =>
  entryCountProblems(counts, limits);

/** The bytes a canonical base64 text decodes to, from its length and padding alone. */
const decodedLength = text =>
  text.length % 4
    ? Math.floor((text.length * 3) / 4)
    : (text.length / 4) * 3 - (text.endsWith('==') ? 2 : text.endsWith('=') ? 1 : 0);

/**
 * The bounded decoder of a pack's envelope, exactly as packRecords writes it:
 * {"schemaVersion":2,"profile":{"name":…,"sha256":…,"version":…},"directories":[…],
 * "files":[{"path":…,"sha256":…,"base64":…},…]} and a newline. It reads the bytes once, from the
 * start, holding no more than the profile allows: it stops at the first byte that does not fit,
 * at the first directory or file over its count, at a string longer than a path may be, and at a
 * base64 text longer than the remaining byte limit, so a huge pack is refused without being
 * parsed whole (maintainer decision 3: bounded decoder memory). Strings are printable ASCII with no
 * escape, which every name the harness writes is. Returns { profile, directories, files: [{ path,
 * sha256, base64 }] }; throws on anything else, an unknown member or version included.
 */
function decodePackEnvelope(buffer) {
  const { limits } = RECORD_PACK;
  if (buffer.length > limits.envelopeBytes)
    throw new Error(
      `the sealed records are larger than the record-pack profile allows (${buffer.length} bytes, more than ${limits.envelopeBytes})`
    );
  let at = 0;
  const fail = message => {
    throw new Error(`the sealed records ${message} (at byte ${at} of ${buffer.length})`);
  };
  const literal = text => {
    const bytes = Buffer.from(text, 'latin1');
    if (at + bytes.length > buffer.length || !buffer.subarray(at, at + bytes.length).equals(bytes))
      fail(`are not in the canonical form the gate writes (expected ${show(text)})`);
    at += bytes.length;
  };
  const string = (max, what) => {
    if (buffer[at] !== 0x22) fail(`hold ${what} that is not text (a JSON string)`);
    const start = (at += 1);
    for (; at < buffer.length && buffer[at] !== 0x22; at += 1) {
      const byte = buffer[at];
      if (byte < 0x20 || byte > 0x7e || byte === 0x5c)
        fail(`hold ${what} with a byte the format does not allow`);
      if (at - start >= max) fail(`hold ${what} longer than ${max} bytes`);
    }
    if (at >= buffer.length) fail('end inside a string');
    const value = buffer.toString('latin1', start, at);
    at += 1;
    return value;
  };
  const number = what => {
    const start = at;
    while (at < buffer.length && buffer[at] >= 0x30 && buffer[at] <= 0x39 && at - start < 6)
      at += 1;
    const text = buffer.toString('latin1', start, at);
    // Canonical digits only: no leading zero, as JSON.stringify writes a number.
    if (at === start || text !== String(Number(text))) fail(`hold ${what} that is not a number`);
    return text;
  };
  literal('{"schemaVersion":');
  const schema = number('a schema version');
  if (schema !== String(PACK_SCHEMA))
    fail(
      schema === '1'
        ? 'are schema 1, which names no entry profile: no reader falls back to it'
        : `have the unknown schema version ${schema}`
    );
  literal(',"profile":{"name":');
  const name = string(64, 'a profile name');
  literal(',"sha256":');
  const profileSha256 = string(64, 'a profile digest');
  literal(',"version":');
  const version = Number(number('a profile version'));
  literal('},"directories":[');
  // The profile the pack names must be exactly the one this reader expects: an unknown or pending
  // profile, another version or another definition fails, and a pack cannot name a looser one.
  let named;
  try {
    named = entryProfile(name, version);
  } catch (error) {
    fail(`name an entry profile this reader does not accept: ${error.message}`);
  }
  if (named !== RECORD_PACK || profileSha256 !== RECORD_PACK.sha256)
    fail(`name the entry profile ${name} ${version} ${profileSha256}, not the record-pack profile`);
  const directories = [];
  if (buffer[at] !== 0x5d)
    for (;;) {
      if (directories.length >= limits.directories)
        fail(`hold more than ${limits.directories} directories (${directories.length + 1})`);
      directories.push(string(limits.pathBytes, 'a directory path'));
      if (buffer[at] === 0x2c) at += 1;
      else break;
    }
  literal('],"files":[');
  const files = [];
  let bytes = 0;
  if (buffer[at] !== 0x5d)
    for (;;) {
      if (files.length >= limits.files)
        fail(`hold more than ${limits.files} files (${files.length + 1})`);
      literal('{"path":');
      const item = { path: string(limits.pathBytes, 'a file path') };
      literal(',"sha256":');
      item.sha256 = string(64, 'a sha256');
      literal(',"base64":');
      // No longer than the base64 of the bytes still allowed.
      item.base64 = string(Math.ceil((limits.bytes - bytes) / 3) * 4, 'a file over the byte limit');
      literal('}');
      bytes += decodedLength(item.base64);
      if (bytes > limits.bytes) fail(`hold more than ${limits.bytes} bytes`);
      files.push(item);
      if (buffer[at] === 0x2c) at += 1;
      else break;
    }
  literal(']}\n');
  if (at !== buffer.length) fail('continue after their end');
  return { directories, files };
}

/**
 * Validates a sealed records pack completely, writing nothing: the bounded decoder above, then the
 * shared entry validator with the record-pack profile (counts first, directories once each,
 * listed or implied; every path, extension and type; duplicates and case collisions; a file where
 * a folder is), then the harness's own grammar (only its paths, sorted, every implied folder
 * listed), then each file's canonical base64, declared size and sha256. Returns { directories,
 * files: [{ path, data }] } for unpackRecords; throws on any problem.
 */
export function validatePack(bytes) {
  assertRecordPackBound();
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  const pack = decodePackEnvelope(buffer);
  const entries = [
    ...pack.directories.map(item => ({ path: item, type: 'directory' })),
    ...pack.files.map(item => ({
      path: item.path,
      type: 'file',
      size: decodedLength(item.base64),
      sha256: item.sha256,
    })),
  ];
  validateEntries(RECORD_PACK, entries, { where: 'the sealed records' });
  const listed = pack.directories;
  const paths = pack.files.map(item => item.path);
  const sorted = list => list.join('\n') === [...list].sort().join('\n');
  if (!listed.every(item => packedKind(item) === 'directory') || !sorted(listed))
    throw new Error('the sealed records list a directory the harness does not write');
  if (!sorted(paths)) throw new Error('the sealed records list a file twice or out of order');
  const directories = new Set(listed);
  for (const item of [...listed, ...paths])
    for (const folder of impliedDirectories(item))
      if (!directories.has(folder))
        throw new Error(
          `the sealed records list a path inside ${show(folder)} without that folder`
        );
  const files = [];
  for (const [index, item] of pack.files.entries()) {
    if (packedKind(item.path) !== 'file')
      throw new Error(
        `the sealed records hold ${show(item.path)}, which the harness does not write`
      );
    const data = Buffer.from(item.base64, 'base64');
    if (data.toString('base64') !== item.base64)
      throw new Error(`the sealed record file ${show(item.path)} does not match its sha256`);
    checkEntryData(entries[listed.length + index], data, { where: 'the sealed record file' });
    files.push({ path: item.path, data });
  }
  return { directories: listed, files };
}

/**
 * The records folder of a test stage as one pack (bytes): every directory and every file with its
 * sha256 and base64 bytes, naming the record-pack profile. Only what the harness writes is
 * accepted: record files, and the T8 driver's evidence folders with their inner.tap and records
 * folder. Anything else (another name, a link, a FIFO or other type), or a folder that would go
 * over a limit of the profile, throws, which blocks the coverage stage: nothing unexpected is
 * sealed or silently left out. A folder is counted, and the limits checked, before anything
 * inside it is read, and each folder is listed one entry at a time, so a huge folder is refused
 * without being read whole. The result passes validatePack, the check every reader applies, with
 * the same profile.
 */
export function packRecords(directory) {
  assertRecordPackBound();
  const top = fs.lstatSync(directory);
  if (!top.isDirectory()) throw new Error('the records folder is not a directory (or is a link)');
  const directories = [];
  const files = [];
  let total = 0;
  const over = extra => {
    const problems = packCountProblems({
      files: files.length + (extra.files ?? 0),
      directories: directories.length + (extra.directories ?? 0),
      bytes: total + (extra.bytes ?? 0),
      depth: extra.depth ?? 0,
    });
    if (problems.length) throw new Error(`the records folder holds ${problems.join(', ')}`);
  };
  const walk = relative => {
    const absolute = relative ? path.join(directory, relative) : directory;
    const entries = [];
    const handle = fs.opendirSync(absolute);
    try {
      for (let entry; (entry = handle.readSync()); ) {
        entries.push(entry);
        // No folder may hold more entries than the whole pack may.
        if (entries.length > packLimits.entries)
          throw new Error(`the records folder holds more than ${packLimits.entries} entries`);
      }
    } finally {
      handle.closeSync();
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const entry of entries) {
      const name = relative ? `${relative}/${entry.name}` : entry.name;
      over({ depth: name.split('/').length });
      const problem = pathProblem(RECORD_PACK, name);
      if (problem) throw new Error(`the records folder holds ${problem}`);
      const kind = packedKind(name);
      if (kind === 'directory' && entry.isDirectory()) {
        over({ directories: 1 });
        directories.push(name);
        walk(name);
      } else if (kind === 'file' && entry.isFile()) {
        over({ files: 1 });
        const bytes = readRegularFile(path.join(directory, name), {
          max: packLimits.bytes,
          privateOnly: false,
        });
        over({ bytes: bytes.length });
        total += bytes.length;
        files.push({ path: name, sha256: sha256(bytes), base64: bytes.toString('base64') });
      } else
        throw new Error(
          `the records folder holds ${show(name)}, which is not a file or folder the harness writes there`
        );
    }
  };
  walk('');
  directories.sort();
  files.sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0));
  const bytes = Buffer.from(
    `${JSON.stringify({ schemaVersion: PACK_SCHEMA, profile: profileIdentity(RECORD_PACK), directories, files })}\n`
  );
  validatePack(bytes);
  return bytes;
}

/**
 * Writes a packed records folder into `into`, an empty private directory, only after validatePack
 * has accepted the whole pack: nothing is written for a pack it refuses.
 */
export function unpackRecords(bytes, into) {
  const pack = validatePack(bytes);
  if (fs.readdirSync(into).length) throw new Error('the folder to unpack into is not empty');
  for (const item of pack.directories) fs.mkdirSync(path.join(into, item), { mode: 0o700 });
  for (const item of pack.files)
    fs.writeFileSync(path.join(into, item.path), item.data, { flag: 'wx', mode: 0o600 });
}

/** Runs `use(folder)` on the sealed records unpacked into a new private temporary folder. */
export function withUnpackedRecords(bytes, use) {
  validatePack(bytes);
  const folder = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-platform-records-')));
  try {
    fs.chmodSync(folder, 0o700);
    unpackRecords(bytes, folder);
    return use(folder);
  } finally {
    fs.rmSync(folder, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------------------------
// Reading each commit as it is

// Git can be made to show a history other than the commits' own: grafts (GIT_GRAFT_FILE, or
// info/grafts in the common Git directory), replace refs (refs/replace/*, or the base
// GIT_REPLACE_REF_BASE names), a shallow boundary (GIT_SHALLOW_FILE, or the shallow file) and the
// commit-graph cache (objects/info/commit-graph), whose parents and trees Git uses without
// checking them against the commits. Each could hide a commit that deleted or weakened the
// manifest, or a lint script, from the gate, the finalizer and the commit guard.
const historyVariables = ['GIT_GRAFT_FILE', 'GIT_REPLACE_REF_BASE', 'GIT_SHALLOW_FILE'];
// A path that cannot exist (/dev/null is not a folder), so Git reads no grafts at all.
const noGrafts = '/dev/null/orbit-no-grafts';
// Read by Git after every configuration file and after GIT_CONFIG_COUNT, so these values win.
const historySettings = "'core.commitgraph=false' 'core.usereplacerefs=false'";

/**
 * Sets `env` (process.env, or a child's environment) so that Git reads each commit as it is: no
 * grafts (GIT_GRAFT_FILE names a path that cannot exist, so neither an inherited GIT_GRAFT_FILE nor
 * info/grafts is read), no replace refs (GIT_NO_REPLACE_OBJECTS=1 and core.useReplaceRefs=false),
 * no commit-graph (core.commitGraph=false), and no inherited GIT_REPLACE_REF_BASE or
 * GIT_SHALLOW_FILE. A shallow repository or an info/grafts file is refused separately
 * (historyRewriteProblems). Returns the names of the inherited variables it replaced, never their
 * values.
 */
export function hardenGitHistory(env) {
  const replaced = Object.keys(env)
    .filter(
      name =>
        (historyVariables.includes(name) &&
          !(name === 'GIT_GRAFT_FILE' && env[name] === noGrafts)) ||
        (name === 'GIT_NO_REPLACE_OBJECTS' && env[name] !== '1')
    )
    .sort();
  for (const name of historyVariables) delete env[name];
  env.GIT_GRAFT_FILE = noGrafts;
  env.GIT_NO_REPLACE_OBJECTS = '1';
  const settings = env.GIT_CONFIG_PARAMETERS;
  if (typeof settings !== 'string' || !settings.endsWith(historySettings))
    env.GIT_CONFIG_PARAMETERS = settings ? `${settings} ${historySettings}` : historySettings;
  return replaced;
}

/** A copy of `env` with hardenGitHistory applied. */
export function gitHistoryEnvironment(env = process.env) {
  const copy = { ...env };
  hardenGitHistory(copy);
  return copy;
}

/**
 * What makes the history of the repository whose common Git directory is `common` differ from its
 * commits' own even with hardenGitHistory, or shows that something tried: a shallow boundary (the
 * commits behind it are missing, so nothing can judge them) and an info/grafts file. `git(args)`
 * runs Git (with the hardened environment) and returns its output. An empty list means neither.
 */
export function historyRewriteProblems(git, common) {
  const problems = [];
  if (git(['rev-parse', '--is-shallow-repository'], '').toString().trim() !== 'false')
    problems.push('the repository is shallow: fetch its full history first');
  const grafts = path.join(common, 'info', 'grafts');
  if (fs.lstatSync(grafts, { throwIfNoEntry: false }))
    problems.push(
      `${grafts} exists: Git grafts change the history the platform contract and the lint stages are judged by; remove it`
    );
  return problems;
}

// ---------------------------------------------------------------------------------------------
// The repository binding of every authority and gate verification read (GDR9-AUTH-ROOT-01)

/** The Git environment variables that change what a pathspec means (removed by the binding). */
export const PATHSPEC_VARIABLES = Object.freeze(
  ['LITERAL', 'GLOB', 'NOGLOB', 'ICASE'].map(name => `GIT_${name}_PATHSPECS`)
);
const QUARANTINE_VARIABLES = Object.freeze([
  'GIT_OBJECT_DIRECTORY',
  'GIT_ALTERNATE_OBJECT_DIRECTORIES',
  'GIT_QUARANTINE_PATH',
]);
// Git names a quarantine (receive-pack's `incoming`, bulk-checkin's `bulk-fsync`) tmp_objdir-<name>
// inside the object directory it belongs to.
const QUARANTINE_NAME = /^tmp_objdir-[A-Za-z0-9][A-Za-z0-9_-]*$/;
// The index of the candidate a commit hook judges: `git commit` names the git directory's index,
// its lock (commit -a) or a next-index-<pid>.lock (commit <paths>).
const INDEX_NAME = /^(?:index|index\.lock|next-index-\d+\.lock)$/;
// The first Git that honours GIT_NO_LAZY_FETCH (2.44).
const LAZY_FETCH_GIT = [2, 44];

/**
 * The active records of the bytes of an objects/info/alternates file, by Git's own grammar
 * (gate-draft-r11, GDR10-ALT-PARSE-01; Git's read_info_alternates, link_alt_odb_entries and
 * parse_alt_odb_entry): the bytes are split at each newline byte and nothing else, and nothing is
 * trimmed. Only a truly empty record and a record whose first byte is `#` name no store. Every
 * other record is active and is returned exactly as it is: a path with leading or trailing blanks
 * (` #foreign` is the relative path ` #foreign`, not a comment: gate-draft-r10 trimmed it first and
 * so missed the store Git reads), a path of blanks only, a C-quoted path (Git unquotes it), and a
 * record ending in a carriage return (the return is part of the path Git resolves). A NUL byte
 * refuses the whole file: Git stops reading there, so its records cannot be shown as Git reads them.
 */
export function activeAlternateRecords(bytes) {
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (buffer.includes(0))
    throw new Error('it holds a NUL byte, where Git stops reading it, so what it names is unknown');
  const records = [];
  for (let start = 0; start <= buffer.length; ) {
    const end = buffer.indexOf(0x0a, start);
    const record = buffer.subarray(start, end === -1 ? buffer.length : end);
    if (record.length && record[0] !== 0x23) records.push(record.toString('utf8'));
    if (end === -1) break;
    start = end + 1;
  }
  return records;
}

/**
 * The active records of the alternates file of the object directory `objects`
 * (activeAlternateRecords; gate-draft-r10 round 2, check-1 of GDR9-AUTH-ROOT-01: Git follows that
 * file to another object store, and the binding admits none). An empty list when there is no such
 * file. Throws when the file exists but is not a regular file (a link included), is over 1 MiB or
 * holds a NUL byte.
 */
function alternateStores(objects) {
  const file = path.join(objects, 'info', 'alternates');
  let bytes;
  try {
    bytes = readRegularFile(file, { max: 1024 * 1024, privateOnly: false });
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw new Error(
      error.code === 'ELOOP' ? `${file} is a symbolic link, not a regular file` : error.message
    );
  }
  try {
    return activeAlternateRecords(bytes);
  } catch (error) {
    throw new Error(`${file}: ${error.message}`);
  }
}

/**
 * What the bound runner does with each environment variable that can choose another repository,
 * work tree, common directory, ref namespace, index, object source or configuration
 * (GDR9-AUTH-ROOT-01; GDR9-AUTH-OBJECT-01 for GIT_NO_LAZY_FETCH). `bound`: admitted only when it
 * names the bound repository's own value, and then replaced by it (GIT_COMMON_DIR is then removed,
 * since the git directory names it); `refused`: any value refuses the binding (GIT_NAMESPACE, when
 * not empty); `quarantine`: admitted only together, as the bound repository's own quarantine with
 * its object directory as the one alternate, refused otherwise; `index`: removed, except for a
 * reader of the candidate's index, which admits only the bound git directory's index, index.lock
 * or next-index-<pid>.lock; `overridden`: set to the binding's value whatever is inherited;
 * `removed`: never passed on; `admitted`: passed on as inherited. Since gate-draft-r12
 * (GDR11-AUTH-CONFIG-01) every other variable follows the one authority configuration policy that
 * the stage environment follows too (STAGE_GIT_VARIABLES, stageGitEnvironment): no global or system
 * configuration file (GIT_CONFIG_GLOBAL and GIT_CONFIG_SYSTEM are /dev/null, GIT_CONFIG_NOSYSTEM=1,
 * so neither HOME/.gitconfig nor XDG_CONFIG_HOME/git/config is read), no system attributes file
 * (GIT_ATTR_NOSYSTEM=1), the gate's settings (STAGE_GIT_SETTINGS, then the history settings) as
 * the only configuration given in the environment, only the few variables STAGE_GIT_VARIABLES
 * admits, and every other Git variable removed, whatever its name. The binding's own settings come
 * between the two (round 2: BOUND_GIT_SETTINGS, then the switch-off of each filter driver and hook
 * the repository's configuration defines), and its HOME is NO_HOME. Through gate-draft-r11 the
 * binding admitted the caller's configuration files, so a setting there changed what the gate's
 * own reads and the authority reads emitted (i18n.logOutputEncoding turned the commit-message scan
 * input into UTF-16) and started a configured helper (core.fsmonitor ran on every read of the
 * index).
 */
export const BOUND_GIT_VARIABLES = Object.freeze({
  GIT_DIR: 'bound',
  GIT_WORK_TREE: 'bound',
  GIT_COMMON_DIR: 'bound',
  GIT_NAMESPACE: 'refused',
  GIT_OBJECT_DIRECTORY: 'quarantine',
  GIT_ALTERNATE_OBJECT_DIRECTORIES: 'quarantine',
  GIT_QUARANTINE_PATH: 'quarantine',
  GIT_INDEX_FILE: 'index',
  GIT_CONFIG_PARAMETERS: 'overridden',
  GIT_NO_LAZY_FETCH: 'overridden',
  GIT_GRAFT_FILE: 'overridden',
  GIT_NO_REPLACE_OBJECTS: 'overridden',
  GIT_CONFIG_GLOBAL: 'overridden',
  GIT_CONFIG_SYSTEM: 'overridden',
  GIT_CONFIG_NOSYSTEM: 'overridden',
  GIT_ATTR_NOSYSTEM: 'overridden',
  GIT_REPLACE_REF_BASE: 'removed',
  GIT_SHALLOW_FILE: 'removed',
  GIT_CONFIG: 'removed',
  GIT_CONFIG_COUNT: 'removed',
  'GIT_CONFIG_KEY_<n>': 'removed',
  'GIT_CONFIG_VALUE_<n>': 'removed',
  GIT_CEILING_DIRECTORIES: 'removed',
  GIT_DISCOVERY_ACROSS_FILESYSTEM: 'removed',
  ...Object.fromEntries(PATHSPEC_VARIABLES.map(name => [name, 'removed'])),
  GIT_EXEC_PATH: 'admitted',
  GIT_AUTHOR_NAME: 'admitted',
  GIT_AUTHOR_EMAIL: 'admitted',
  GIT_AUTHOR_DATE: 'admitted',
  GIT_COMMITTER_NAME: 'admitted',
  GIT_COMMITTER_EMAIL: 'admitted',
  GIT_COMMITTER_DATE: 'admitted',
  'GIT_<any other name>': 'removed',
});

/**
 * The repository an authority or gate verification read may read (GDR9-AUTH-ROOT-01): the one Git
 * finds from the canonical `root` (a folder of its working tree, the main one or a linked one)
 * with every inherited selector, ceiling, object source, index and injected configuration removed,
 * and `run(args, input, { maxBuffer, config })`, the one runner bound to it: every read it makes
 * names that repository's git directory and top level explicitly, with the history hardened
 * (hardenGitHistory, its settings the only configuration given on the command line, `config`
 * appended), no lazy fetch from a promisor remote (GIT_NO_LAZY_FETCH=1; GDR9-AUTH-OBJECT-01) and
 * no pathspec variable. An inherited GIT_DIR, GIT_WORK_TREE or GIT_COMMON_DIR that names another
 * repository, work tree or common directory, a nonempty GIT_NAMESPACE, an object source other than
 * the repository's own quarantine (QUARANTINE_NAME, inside its object directory, with that
 * directory as its one alternate, as Git's receive-pack sets it) and, for a reader of the
 * candidate's index (`index`), a GIT_INDEX_FILE other than its git directory's index refuse: none
 * is silently ignored, so a hook whose Git chose another repository is refused rather than checked
 * against this one. A relative inherited value is read from process.cwd(), the folder Git gave it
 * for. A Git older than 2.44 ignores GIT_NO_LAZY_FETCH, so with one a repository that has a
 * promisor remote is refused. BOUND_GIT_VARIABLES lists each variable's treatment. Round 2 of
 * gate-draft-r10 (check-1): an object store is also chosen by a file, not only by a variable: an
 * info/alternates file that names a store, in the bound object directory or in its quarantine
 * (where Git's receive-pack writes none), refuses too, so every object the authority reads is the
 * repository's own; an alternates file with no active record (empty, or only empty records and
 * records whose first byte is `#`) names none and is admitted. Its records are read byte for byte
 * as Git reads them (activeAlternateRecords; gate-draft-r11, GDR10-ALT-PARSE-01): nothing is
 * trimmed, so a record that only looks like a comment or a blank line after trimming (` #foreign`,
 * a tab, blanks, a carriage return) is active and refuses, before any read of the binding can
 * resolve an object through it. Every path is canonicalized with the operating system's realpath
 * (fs.realpathSync.native), which gives a case-insensitive file system's own letter case, so a
 * root spelled in another case binds the repository it names at every entry point alike. Since
 * gate-draft-r12 (GDR11-AUTH-CONFIG-01) the binding's environment, discovery included, is the one
 * authority configuration policy (stageGitEnvironment, BOUND_GIT_VARIABLES): Git reads no
 * configuration, attributes or ignore file that the caller's environment chooses, and its
 * command-line settings (STAGE_GIT_SETTINGS) switch off the user's attributes and ignore files,
 * every fsmonitor, another output encoding and signature checks, which win over the repository's
 * own configuration too, as do the settings that switch off each filter driver that configuration
 * defines (a clean filter ran in write-tree). Round 2 of gate-draft-r12 (check-1): those
 * switch-off settings are given in Git's `'key'='value'` form, so a driver named with `=` (which
 * the `'key=value'` form split at its first `=`, R12C1-FILTER-EQ-01) or with an empty name is
 * switched off too; no hook runs for a bound read either (BOUND_GIT_SETTINGS: no hooks folder, the
 * repository's .git/hooks or its core.hooksPath, for every read but `git rev-parse`, which runs
 * none and is asked where they are, and each hook its configuration defines,
 * `hook.<name>.enabled=false`; a post-index-change hook started in write-tree, R12C1-HOOK-01); and
 * HOME names no folder (NO_HOME), so a `~/` path in the repository's own configuration (an
 * include.path, an includeIf) names no file the caller's environment chooses
 * (R12C1-HOME-INCLUDE-01). That configuration (.git/config and what it includes) is still read,
 * as Git always reads it: what the authority reads from Git is chosen so
 * that it cannot change it (raw objects, typed plumbing, explicit options; metadataScanInput,
 * HISTORY_LOG_OPTIONS). No safe.directory is honoured from any file,
 * so a repository that another user owns is refused, by Git's own ownership check, at every entry
 * point (cross-owner use is not supported, and is unmeasured). Throws, naming why, when the
 * repository cannot be bound; a bare repository has no working tree and is refused.
 */
export function bindRepository(root, { env = process.env, index = false } = {}) {
  const refuse = why => {
    throw new Error(`the repository at ${show(root)} cannot be bound: ${why} (GDR9-AUTH-ROOT-01)`);
  };
  if (typeof root !== 'string' || !root) refuse('no root folder is given');
  let canonical;
  try {
    canonical = fs.realpathSync.native(path.resolve(root));
  } catch {
    refuse('the root folder does not exist');
  }
  if (!fs.statSync(canonical).isDirectory()) refuse('the root is not a folder');
  const given = name =>
    Object.hasOwn(env, name) && env[name] !== undefined ? String(env[name]) : undefined;
  const at = value => {
    try {
      return fs.realpathSync.native(path.resolve(process.cwd(), value));
    } catch {
      return undefined;
    }
  };
  // The stores an alternates file in `objects` names; refuses when it names one, or cannot be read.
  const ownStoresOnly = (objects, what) => {
    let stores;
    try {
      stores = alternateStores(objects);
    } catch (error) {
      refuse(`the alternates file of ${what} cannot be read (${error.message})`);
    }
    if (stores.length)
      refuse(
        `the info/alternates file of ${what} ${path.join(objects, 'info', 'alternates')} names another object store (${stores
          .slice(0, 3)
          .map(store => show(store))
          .join(
            ', '
          )}; Git reads every record but an empty one and one whose first byte is #, GDR10-ALT-PARSE-01): the authority reads only the repository's own objects`
      );
  };
  if (given('GIT_NAMESPACE'))
    refuse(
      `the inherited GIT_NAMESPACE ${show(given('GIT_NAMESPACE'))} selects another ref namespace, and the authority reads only the repository's own refs`
    );
  // Discovery from the root alone, in the one authority environment (gate-draft-r12,
  // GDR11-AUTH-CONFIG-01): no inherited Git variable but the few it admits, so no selector, object
  // source, index, ceiling, pathspec variable or injected configuration, no configuration file the
  // caller's environment chooses, the history hardened and no lazy fetch; since round 2 also no
  // hook and no home folder (BOUND_GIT_SETTINGS, NO_HOME).
  const clean = { ...stageGitEnvironment(env), HOME: NO_HOME };
  clean.GIT_CONFIG_PARAMETERS = `${STAGE_GIT_SETTINGS} ${BOUND_GIT_SETTINGS} ${historySettings}`;
  let found;
  try {
    found = execFileSync(
      'git',
      [
        'rev-parse',
        '--path-format=absolute',
        '--git-dir',
        '--git-common-dir',
        '--show-toplevel',
        '--git-path',
        'objects',
      ],
      { cwd: canonical, env: clean, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }
    ).split('\n');
  } catch (error) {
    refuse(
      `Git finds no working tree of a repository there (${String(error.stderr || error.message)
        .trim()
        .split('\n')[0]
        .slice(0, 200)})`
    );
  }
  if (
    found.length !== 5 ||
    found[4] !== '' ||
    !found.slice(0, 4).every(item => path.isAbsolute(item))
  )
    refuse('unexpected git rev-parse output');
  const [gitDir, commonDir, top, objects] = found.slice(0, 4).map(item => at(item));
  if (!gitDir || !commonDir || !top || !objects) refuse('a folder Git names does not exist');
  if (canonical !== top && !canonical.startsWith(`${top}${path.sep}`))
    refuse(`the root is not inside the working tree ${top} that Git finds there`);
  // An inherited selector may only name what the root names.
  for (const [name, own, what] of [
    ['GIT_DIR', gitDir, 'git directory'],
    ['GIT_WORK_TREE', top, 'working tree'],
    ['GIT_COMMON_DIR', commonDir, 'common directory'],
  ]) {
    const value = given(name);
    if (value !== undefined && at(value) !== own)
      refuse(
        `the inherited ${name} names ${show(value)}, not the ${what} ${own} of the repository at the root: an inherited selector cannot choose another repository, working tree or common directory for the authority`
      );
  }
  // The object source: the repository's own object directory, or its own quarantine, neither
  // naming another store in an alternates file (round 2).
  ownStoresOnly(objects, "the repository's object directory");
  let quarantine = {};
  const sources = QUARANTINE_VARIABLES.filter(name => given(name) !== undefined);
  if (sources.length) {
    const named = given('GIT_QUARANTINE_PATH');
    const store = given('GIT_OBJECT_DIRECTORY');
    const alternates = given('GIT_ALTERNATE_OBJECT_DIRECTORIES');
    const stat =
      named !== undefined && path.isAbsolute(named)
        ? fs.lstatSync(named, { throwIfNoEntry: false })
        : undefined;
    const folder = named === undefined ? undefined : at(named);
    if (
      store === undefined ||
      alternates === undefined ||
      !stat?.isDirectory() ||
      !folder ||
      path.dirname(folder) !== objects ||
      !QUARANTINE_NAME.test(path.basename(folder)) ||
      at(store) !== folder ||
      alternates.includes('"') ||
      alternates.split(path.delimiter).length !== 1 ||
      at(alternates) !== objects
    )
      refuse(
        `the inherited ${sources.join(', ')} ${sources.length === 1 ? 'names' : 'name'} an object source other than the repository's own object directory ${objects} or its own quarantine (GIT_QUARANTINE_PATH and GIT_OBJECT_DIRECTORY naming one tmp_objdir-<name> folder of that directory, and GIT_ALTERNATE_OBJECT_DIRECTORIES exactly that directory)`
      );
    ownStoresOnly(folder, 'its quarantine');
    quarantine = {
      GIT_QUARANTINE_PATH: folder,
      GIT_OBJECT_DIRECTORY: folder,
      GIT_ALTERNATE_OBJECT_DIRECTORIES: objects,
    };
  }
  // The candidate's index, for a reader of it only.
  let indexFile = {};
  const indexNamed = given('GIT_INDEX_FILE');
  if (index && indexNamed !== undefined) {
    const file = path.resolve(process.cwd(), indexNamed);
    const stat = fs.lstatSync(file, { throwIfNoEntry: false });
    if (
      !stat?.isFile() ||
      at(path.dirname(file)) !== gitDir ||
      !INDEX_NAME.test(path.basename(file))
    )
      refuse(
        `the inherited GIT_INDEX_FILE names ${show(indexNamed)}, not the index, index.lock or next-index-<pid>.lock of the git directory ${gitDir}`
      );
    indexFile = { GIT_INDEX_FILE: path.join(gitDir, path.basename(file)) };
  }
  const bound = { ...clean, GIT_DIR: gitDir, GIT_WORK_TREE: top, ...quarantine, ...indexFile };
  const spawnOptions = {
    cwd: top,
    env: bound,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  };
  // A Git that ignores GIT_NO_LAZY_FETCH may fetch from a promisor remote.
  const version = /^git version (\d+)\.(\d+)/.exec(execFileSync('git', ['version'], spawnOptions));
  if (
    !version ||
    Number(version[1]) < LAZY_FETCH_GIT[0] ||
    (Number(version[1]) === LAZY_FETCH_GIT[0] && Number(version[2]) < LAZY_FETCH_GIT[1])
  ) {
    let promisor;
    try {
      promisor = execFileSync(
        'git',
        ['config', '--get-regexp', '^(extensions\\.partialclone|remote\\..*\\.promisor)$'],
        spawnOptions
      );
    } catch (error) {
      if (error.status !== 1) refuse('its configuration cannot be read');
      promisor = '';
    }
    if (promisor.trim())
      refuse(
        `this Git (${version ? `${version[1]}.${version[2]}` : 'of an unknown version'}) predates GIT_NO_LAZY_FETCH (2.44) and the repository has a promisor remote, so a missing object could be fetched during the check`
      );
  }
  // The filter drivers the repository's own configuration defines (gate-draft-r12,
  // GDR11-AUTH-CONFIG-01): Git runs a clean or process filter for a path its attributes assign one
  // to whenever it checks a file's content against the index, which `git write-tree` does for an
  // entry whose recorded state is not clearly current (and `git status` for every changed one), so
  // a filter program ran in the gate's, the finalizer's and the commit guard's own reads. Each is
  // switched off for every bound read, on Git's command line, where that wins over the repository's
  // configuration: an empty clean, smudge and process command, and not required. No bound read
  // writes a file from the index, and the tree Git writes is the index's own, so no authority fact
  // depends on a filter. (The caller's files can define none: the binding reads none of them.)
  // Round 2 of gate-draft-r12 (check-1): each setting is given as `'key'='value'`, which Git
  // reads as that key and that value whatever the key holds; the `'key=value'` form that round 1
  // used is split at its first `=`, so for a driver named `a=b` it set `filter.a` and left the
  // driver on (R12C1-FILTER-EQ-01), and a driver with an empty name (`[filter ""]`, which a
  // `filter=` attribute selects) was not listed at all. Every name is taken here, the empty one
  // included. The same is done for each hook the repository's configuration defines
  // (`hook.<name>.command` and `.event`, run since Git 2.54 like a hook in the hooks folder, which
  // core.hooksPath=/dev/null does not stop): `hook.<name>.enabled=false` (R12C1-HOOK-01).
  const drivers = new Set();
  const hooks = new Set();
  const off = [];
  try {
    for (const key of execFileSync(
      'git',
      ['config', '--name-only', '--get-regexp', '^(filter|hook)\\.'],
      spawnOptions
    ).split('\n')) {
      const named = /^(filter|hook)\.(.*)\.[^.]+$/s.exec(key);
      if (named) (named[1] === 'filter' ? drivers : hooks).add(named[2]);
    }
  } catch (error) {
    if (error.status !== 1) refuse('its configuration cannot be read');
  }
  if (drivers.size || hooks.size) {
    // The `'key'='value'` form is Git 2.31's; an older Git refuses it, and every read with it.
    if (!version || Number(version[1]) < 2 || (Number(version[1]) === 2 && Number(version[2]) < 31))
      refuse(
        `this Git (${version ? `${version[1]}.${version[2]}` : 'of an unknown version'}) predates the 'key'='value' settings (2.31) that switch off the filter drivers and hooks the repository's configuration defines`
      );
    const quoted = value => `'${value.replaceAll("'", "'\\''")}'`;
    off.push(
      ...[...drivers].sort().flatMap(name =>
        [
          ['clean', ''],
          ['smudge', ''],
          ['process', ''],
          ['required', 'false'],
        ].map(([item, value]) => `${quoted(`filter.${name}.${item}`)}=${quoted(value)}`)
      ),
      ...[...hooks].sort().map(name => `${quoted(`hook.${name}.enabled`)}=${quoted('false')}`)
    );
  }
  const parameters = (...settings) =>
    [STAGE_GIT_SETTINGS, ...settings, ...off, historySettings].join(' ');
  bound.GIT_CONFIG_PARAMETERS = parameters(BOUND_GIT_SETTINGS);
  // `git rev-parse` starts no hook and writes no index, and the commit guard asks it where the
  // repository's own hooks are (`--git-path hooks/reference-transaction`, the hook Git itself runs
  // from the repository's core.hooksPath or .git/hooks), which a hooks folder of /dev/null would
  // not answer (round 2): it alone runs without BOUND_GIT_SETTINGS. Every other bound read, and the
  // gate's own Git with the binding's environment, has no hooks folder.
  const revParse = parameters();
  const run = (args, input, { maxBuffer = 64 * 1024 ** 2, config } = {}) => {
    const settings = args[0] === 'rev-parse' ? revParse : bound.GIT_CONFIG_PARAMETERS;
    return execFileSync('git', args, {
      cwd: top,
      env: { ...bound, GIT_CONFIG_PARAMETERS: config ? `${settings} ${config}` : settings },
      input,
      maxBuffer,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  };
  return Object.freeze({
    root: canonical,
    top,
    gitDir,
    commonDir,
    objects,
    env: Object.freeze({ ...bound }),
    run,
  });
}

// ---------------------------------------------------------------------------------------------
// The one authority configuration policy: the environment of every authority read and of every
// process the gate starts (gate-draft-r11, GDR10-AUTH-STAGE-01; gate-draft-r12, GDR11-AUTH-CONFIG-01)

/**
 * What the gate's stage environment (stageGitEnvironment) does with each Git environment variable
 * (gate-draft-r11, GDR10-AUTH-STAGE-01; maintainer note 20261019T073253967039Z item 1). Since gate-draft-r12
 * (GDR11-AUTH-CONFIG-01) this is the one authority configuration policy: the repository binding
 * (bindRepository, so the gate's own reads, the finalizer, the commit guard, --verify-commit and the
 * reference-transaction hook) follows it too, with only its validated selectors added
 * (BOUND_GIT_VARIABLES), and GIT_ATTR_NOSYSTEM=1 is set too, so no system attributes file is read
 * either. `overridden`: set to
 * the gate's value whatever is inherited (GIT_NO_LAZY_FETCH=1; the history settings as
 * hardenGitHistory sets them, after the stage settings STAGE_GIT_SETTINGS, which are then the only
 * configuration given in the environment; and, since round 2 of gate-draft-r11 (check-1
 * R11C1-STAGE-CONF-CLONE and -HISTORY), no global or system configuration file:
 * GIT_CONFIG_GLOBAL=/dev/null, so neither HOME/.gitconfig nor XDG_CONFIG_HOME/git/config either,
 * GIT_CONFIG_SYSTEM=/dev/null and GIT_CONFIG_NOSYSTEM=1, because such a file, named by the caller's
 * environment, rewrote the URL the snapshot is cloned from to another repository or a remote
 * helper, put its settings in front of every stage and, with an attributes file, hid history content
 * from the secret scan); `admitted`: passed on as inherited (the folder of Git's own programs, which
 * stays the carried runtime-substitution item with PATH, and the identity a commit made by a test
 * is written with). Every other GIT_* variable is `removed`, whatever its name: every one that selects
 * a repository, working tree, common directory, index, ref namespace, object directory, alternate
 * store or quarantine, that injects configuration (GIT_CONFIG_PARAMETERS, GIT_CONFIG_COUNT with its
 * KEY and VALUE entries, GIT_CONFIG, and GIT_TEMPLATE_DIR, whose config file a new repository
 * copies), that changes discovery, pathspecs or attributes, or that chooses an external diff, a
 * protocol, a transport, an editor or a trace file, and any variable Git adds later. A stage never
 * inherits a repository selector: one that reads a repository is given it (boundStageEnvironment).
 */
export const STAGE_GIT_VARIABLES = Object.freeze({
  GIT_NO_LAZY_FETCH: 'overridden',
  GIT_CONFIG_PARAMETERS: 'overridden',
  GIT_GRAFT_FILE: 'overridden',
  GIT_NO_REPLACE_OBJECTS: 'overridden',
  GIT_CONFIG_GLOBAL: 'overridden',
  GIT_CONFIG_SYSTEM: 'overridden',
  GIT_CONFIG_NOSYSTEM: 'overridden',
  GIT_ATTR_NOSYSTEM: 'overridden',
  GIT_EXEC_PATH: 'admitted',
  GIT_AUTHOR_NAME: 'admitted',
  GIT_AUTHOR_EMAIL: 'admitted',
  GIT_AUTHOR_DATE: 'admitted',
  GIT_COMMITTER_NAME: 'admitted',
  GIT_COMMITTER_EMAIL: 'admitted',
  GIT_COMMITTER_DATE: 'admitted',
  'GIT_<any other name>': 'removed',
});

/**
 * The settings every stage's Git, and every read of the repository binding, is given before the
 * history settings (round 2 of gate-draft-r11, check-1 R11C1-STAGE-CONF-HISTORY): no attributes
 * file and no ignore file of the user's, so that the default ones Git reads under
 * XDG_CONFIG_HOME/git/ or HOME/.config/git/ when no configuration names one (a `* -diff` there hid
 * history content from the secret scan's Git command, and an `eol` or encoding rule there changed
 * the snapshot's files) are not read either; and, since gate-draft-r12 (GDR11-AUTH-CONFIG-01), no
 * fsmonitor (`core.fsmonitor=false`): a core.fsmonitor in the repository's own configuration, or in
 * a configuration file the caller's environment named, started its program on every Git read of the
 * index (write-tree, ls-files, diff --cached, status), the gate's, the finalizer's and the commit
 * guard's own among them; Git's own output encoding for formatted output
 * (`i18n.logOutputEncoding=UTF-8`): another one there re-encoded the authority's formatted reads
 * (`rev-list --format=%H %T %P`, the history walk of the finalizer and the commit guard, and
 * `log --format=%T %P`, the commit-graph comparison of verifyCommit and the hook), which then
 * refused an approved commit as unreadable; and no signature check in `git log`
 * (`log.showSignature=false`): with it, that comparison started gpg.program for a signed commit.
 * Settings given this way win over every configuration file, the repository's own included; they
 * are the settings the authority's reads depend on, measured with Git 2.54, not every setting Git
 * has. The repository's own attributes (its .gitattributes files and info/attributes) still apply
 * to what reads them; the history secret scan's Git command is made independent of them by its
 * options (HISTORY_LOG_OPTIONS), and the metadata scan reads raw objects (metadataScanInput).
 */
export const STAGE_GIT_SETTINGS =
  "'core.attributesfile=/dev/null' 'core.excludesfile=/dev/null' 'core.fsmonitor=false' 'i18n.logoutputencoding=UTF-8' 'log.showsignature=false'";

/**
 * The settings every read of the repository binding (bindRepository) is given after
 * STAGE_GIT_SETTINGS (round 2 of gate-draft-r12, check-1 R12C1-HOOK-01): no hooks folder
 * (`core.hooksPath=/dev/null`, which wins over the repository's .git/hooks and its own
 * core.hooksPath), so no hook there starts for a bound read: a post-index-change hook started when
 * `git write-tree` wrote the index (the gate's first read, and the finalizer's and the commit
 * guard's). Each hook the repository's configuration defines by name (`hook.<name>.command`) is
 * switched off by the binding too (`hook.<name>.enabled=false`). The binding's `git rev-parse`
 * alone runs without them: it starts no hook and writes no index, and the commit guard asks it
 * where the hooks Git runs are (bindRepository). A stage is not given these: the gate's test stage
 * runs tests whose own fixtures depend on hooks.
 */
export const BOUND_GIT_SETTINGS = "'core.hookspath=/dev/null'";

/**
 * The HOME of every Git process of the repository binding (round 2 of gate-draft-r12, check-1
 * R12C1-HOME-INCLUDE-01): a path that cannot exist (/dev/null is not a folder). Git resolves a `~/`
 * path in the repository's own configuration (an include.path, an includeIf gitdir:~/) against
 * HOME, so the caller's HOME chose a file whose settings every bound read then saw; with this one
 * such a path names no file, and Git leaves a missing include out. No bound read needs a home
 * folder: the binding reads no global configuration, attributes or ignore file.
 */
export const NO_HOME = '/dev/null/orbit-no-home';

/**
 * The environment every process the gate starts is given (GDR10-AUTH-STAGE-01): `env` (the gate's
 * process.env after its own removals) with each Git variable treated as STAGE_GIT_VARIABLES says.
 * It names no repository, so Git in a stage finds the repository of the folder it runs in (the
 * snapshot, for every stage that runs there) unless the stage is given one explicitly
 * (boundStageEnvironment). It names no configuration file either (round 2): Git in a stage reads
 * the configuration of the repository it works in and the gate's settings (STAGE_GIT_SETTINGS, then
 * the history settings), and nothing that HOME, XDG_CONFIG_HOME or an inherited Git variable
 * chooses (since gate-draft-r12 no system attributes file either), but for a file that a `~/`
 * include in that repository's own configuration names, which Git resolves against HOME (round 2
 * of gate-draft-r12, check-1 R12C1-HOME-INCLUDE-01: the history secret scan's Git reads the
 * validated repository's configuration, and its log options win over the settings measured; a
 * stage keeps the caller's HOME). The repository binding starts from this environment as well
 * (bindRepository), with a HOME of its own (NO_HOME). A new object: `env` is not changed.
 */
export function stageGitEnvironment(env) {
  const stage = {};
  for (const [name, value] of Object.entries(env))
    if (!/^GIT_/i.test(name) || STAGE_GIT_VARIABLES[name] === 'admitted') stage[name] = value;
  stage.GIT_CONFIG_GLOBAL = '/dev/null';
  stage.GIT_CONFIG_SYSTEM = '/dev/null';
  stage.GIT_CONFIG_NOSYSTEM = '1';
  stage.GIT_ATTR_NOSYSTEM = '1';
  stage.GIT_CONFIG_PARAMETERS = STAGE_GIT_SETTINGS;
  hardenGitHistory(stage);
  stage.GIT_NO_LAZY_FETCH = '1';
  return stage;
}

/**
 * `stage` (stageGitEnvironment) with the repository of `binding` (bindRepository) named
 * explicitly (GDR10-AUTH-STAGE-01): its git directory and top level and, only when the binding
 * admitted the repository's own quarantine, that quarantine's three variables as the binding set
 * them; never an index. The gate's history secret scan reads the validated root this way, and the
 * snapshot's own steps the snapshot, through a binding of their own.
 */
export function boundStageEnvironment(binding, stage) {
  const named = { GIT_DIR: binding.gitDir, GIT_WORK_TREE: binding.top };
  for (const name of QUARANTINE_VARIABLES)
    if (binding.env[name] !== undefined) named[name] = binding.env[name];
  return { ...stage, ...named };
}

// ---------------------------------------------------------------------------------------------
// The secret scans' history and metadata inputs (gate-draft-r12, GDR11-HISTORY-ATTRS-01 and
// GDR11-AUTH-CONFIG-01)

/**
 * The Git log options of the gate's history secret scan, given to Gitleaks as its `--log-opts`
 * (Gitleaks runs `git -C <root> log -p -U0` with them). gate-draft-r12 (GDR11-HISTORY-ATTRS-01):
 * with `--all` alone, a `* -diff` in a committed or untracked .gitattributes or in info/attributes,
 * a diff driver with `binary=true` and a textconv driver each left the history's added lines out
 * of what Git showed while it exited 0, and the textconv program ran. `--text`, `--no-textconv` and
 * `--no-ext-diff` make each patch Git shows show its changes as their own text, whatever
 * attributes, drivers or configuration say, and run no converter or external diff. (A merge commit
 * shows no patch without -m or --diff-merges, so content that only a merge introduces is in no
 * patch, as through gate-draft-r11.) The repository's own configuration,
 * which Git always reads, changed that output too (GDR11-AUTH-CONFIG-01): `color.diff=always` or
 * `color.ui=always` coloured every added line, so none began with `+`, and `log.showRoot=false` left
 * out the root commit's patch, while a pretty format, a date format, decorations, abbreviated
 * commit ids, signatures, notes, an output encoding and diff prefixes changed the commit and file
 * headers. Each of those has an option that wins over every configuration file, and the options
 * below set each to Git's own default form: with them, under each of those settings, Git's output
 * is byte for byte what plain `git log -p -U0 --all` shows in the same repository with no
 * configuration and no attributes. Other settings still change header bytes, though no content
 * (round 2 of gate-draft-r12, check-1 R12C1-HISTORY-CLAIM-01): mailmap.file the author line,
 * core.quotePath=false the quoting of path headers and diff.renames=false a rename's headers (shown
 * as a deletion and an addition), so the output is the clean oracle's for the settings measured,
 * not for every setting Git has. This is the Git command's input, measured with Git 2.54 and a
 * stand-in that runs the command Gitleaks runs; the pinned Gitleaks 8.30.1 has not been run with
 * these options, so what it reports with them is still to be qualified.
 */
export const HISTORY_LOG_OPTIONS = Object.freeze([
  '--all',
  '--root',
  '--text',
  '--no-textconv',
  '--no-ext-diff',
  '--no-color',
  '--encoding=UTF-8',
  '--pretty=medium',
  '--date=default',
  '--no-decorate',
  '--no-abbrev-commit',
  '--no-show-signature',
  '--no-notes',
  '--src-prefix=a/',
  '--dst-prefix=b/',
]);

// The object id of Git's own hash for a raw object of `type` with `content`.
const objectId = (type, content, length) =>
  createHash(length === 40 ? 'sha1' : 'sha256')
    .update(`${type} ${content.length}\0`)
    .update(content)
    .digest('hex');

/**
 * The raw objects `ids` as `git cat-file --batch` gives them, each checked (gate-draft-r12,
 * GDR11-AUTH-CONFIG-01): every answer is `<id> <type> <size>` for the id asked, in order, of one of
 * `types`, with exactly `size` bytes and the newline after them, and those bytes are the object
 * whose id is their hash; nothing follows the last. A missing object (no lazy fetch: the binding
 * sets GIT_NO_LAZY_FETCH=1), another type, a short or long answer and content that is not the
 * object refuse. Returns the answers, each with its exact bytes (`frame`).
 */
function batchObjects(run, ids, types) {
  if (!ids.length) return [];
  const output = run(['cat-file', '--batch'], ids.map(id => `${id}\n`).join(''));
  if (!Buffer.isBuffer(output)) throw new Error('Git did not return the objects as bytes');
  const objects = [];
  let at = 0;
  for (const id of ids) {
    const end = output.indexOf(0x0a, at);
    if (end === -1) throw new Error(`Git's answer ends before the object ${id}: it is incomplete`);
    const header = output.subarray(at, end).toString('latin1');
    const match = /^([0-9a-f]{40}|[0-9a-f]{64}) ([a-z]+) (\d{1,12})$/.exec(header);
    if (!match || match[1] !== id)
      throw new Error(
        `the object ${id} cannot be read (Git answers ${show(header.slice(0, 120))})`
      );
    if (!types.includes(match[2]))
      throw new Error(`the object ${id} is a ${match[2]}, not a ${types.join(' or ')}`);
    const size = Number(match[3]);
    const start = end + 1;
    if (start + size >= output.length || output[start + size] !== 0x0a)
      throw new Error(`Git's answer for the object ${id} is shorter than its ${size} bytes`);
    const content = output.subarray(start, start + size);
    if (objectId(match[2], content, id.length) !== id)
      throw new Error(`the bytes Git gives for the object ${id} are not that object`);
    objects.push({ id, type: match[2], content, frame: output.subarray(at, start + size + 1) });
    at = start + size + 1;
  }
  if (at !== output.length) throw new Error("Git's answer holds more than the objects asked for");
  return objects;
}

// The object ids of `text` (one per line, each line ended), none twice.
function idLines(text, what) {
  if (text && !text.endsWith('\n')) throw new Error(`the list of ${what} is not complete`);
  const ids = text ? text.slice(0, -1).split('\n') : [];
  for (const id of ids)
    if (!OBJECT_ID.test(id)) throw new Error(`the list of ${what} holds ${show(id.slice(0, 80))}`);
  if (new Set(ids).size !== ids.length)
    throw new Error(`the list of ${what} names an object twice`);
  return ids;
}

// The header lines of a raw commit or tag (before its first empty line).
const headerLines = content => {
  const end = content.indexOf('\n\n');
  return (end === -1 ? content : content.slice(0, end)).split('\n');
};

/**
 * The names a commit's `encoding` header may give for the metadata scan to read the commit raw
 * (round 2 of gate-draft-r12, check-1 R12C1-META-ENC-01): UTF-8, US-ASCII, ISO-8859-1 to -16 and
 * Windows-1250 to -1258 (CP1250 to CP1258), in the spellings Git and iconv take. In each, every
 * ASCII character of the text is its own byte and no other byte or sequence stands for one, so
 * ASCII text that Git shows (Git re-encodes a commit's text from that encoding to UTF-8 to show it)
 * is in the raw object as the same bytes, where the scan's patterns find it. In another encoding it
 * need not be: in UTF-7 (`+AFIAMQAy...-`), ISO-2022-JP (an escape sequence between two letters) or
 * HZ (`~` and a newline), Git shows ASCII text that the raw object does not hold, with no NUL byte
 * for the scan to refuse. A commit naming any other encoding, or another spelling, is refused, not
 * left out. A tag has no such header: Git shows its text as stored.
 */
const RAW_TEXT_ENCODING =
  /^(?:utf-?8|us-ascii|ascii|iso[-_]?8859[-_]?(?:[1-9]|1[0-6])|latin-?[1-9]|(?:cp|windows-)125[0-8])$/i;

/**
 * The input of the gate's metadata secret scan (gate-draft-r12, GDR11-AUTH-CONFIG-01): every commit
 * reachable from a ref or HEAD and every tag object reachable from a ref, as Git stores it, read
 * with `run` (the repository binding's runner: (args, input) => bytes). Through gate-draft-r11 the
 * gate wrote `git log --all --format=%H%n%B` and `for-each-ref --format=%(contents)` for the
 * scanner, which a configuration file of the caller's or the repository's own changed while Git
 * exited 0 (`i18n.logOutputEncoding=UTF-16` gave UTF-16 text, NUL bytes and no ASCII marker), and
 * which left out every header (author, committer, merged tags, extra headers). Now nothing formats
 * it: the commits are enumerated with `rev-list --all` and the refs with `for-each-ref` (object id
 * and type only), and each object is read raw with `cat-file --batch`, whose output no setting
 * changes, and checked (batchObjects): its type, its size and its bytes, which must hash to its id.
 * The enumeration is checked too: every commit's parents (read from its own object, with grafts,
 * replace refs and the commit-graph off) are in it, and so is every commit a ref, HEAD (`head`) or a
 * tag names; tags are followed through tags of tags. A missing or unreadable object, an answer that
 * is not complete, an object holding a NUL byte (text such as UTF-16 whose ASCII would not match a
 * pattern, which the scan cannot read as text), since round 2 a commit whose `encoding` header
 * names an encoding in which ASCII text need not be its own bytes (RAW_TEXT_ENCODING; UTF-7 held
 * text Git shows in other bytes, with no NUL byte, check-1 R12C1-META-ENC-01) and an enumeration
 * that is not closed refuse: the
 * scan is given nothing rather than part of the metadata. Returns `commits` and `tags`, the exact
 * `cat-file --batch` bytes of each (`<id> <type> <size>`, a newline, the object, a newline), with
 * their counts. What a ref names that is not a commit or tag (a tree or a blob) is counted as
 * `otherTargets`: it is not metadata, and no scan here reads it. Commits that only MERGE_HEAD or
 * FETCH_HEAD name, and not a ref, are not in it, as they are not in the history scan's either.
 */
export function metadataScanInput(run, { head } = {}) {
  const text = args => {
    const output = run(args, '');
    return Buffer.isBuffer(output) ? output.toString('latin1') : String(output);
  };
  const commitIds = idLines(text(['rev-list', '--all']), 'commits');
  const commitSet = new Set(commitIds);
  const refs = text(['for-each-ref', '--format=%(objectname) %(objecttype) %(refname)']);
  if (refs && !refs.endsWith('\n')) throw new Error('the list of refs is not complete');
  const tagQueue = [];
  let otherTargets = 0;
  const target = (id, type, where) => {
    if (!OBJECT_ID.test(id)) throw new Error(`${where} names ${show(id)}, not an object id`);
    if (type === 'commit') {
      if (!commitSet.has(id))
        throw new Error(`${where} names the commit ${id}, which the list of commits leaves out`);
    } else if (type === 'tag') tagQueue.push(id);
    else if (type === 'tree' || type === 'blob') otherTargets += 1;
    else throw new Error(`${where} names ${id} of the type ${show(type)}`);
  };
  for (const line of refs ? refs.slice(0, -1).split('\n') : []) {
    const match = /^(\S+) (\S+) (\S+)$/.exec(line);
    if (!match) throw new Error(`the ref line ${show(line.slice(0, 120))} is not one`);
    target(match[1], match[2], `the ref ${match[3]}`);
  }
  if (head !== undefined) target(head, 'commit', 'HEAD');
  // The commits, each its own object; its parents are in the list.
  const commits = batchObjects(run, commitIds, ['commit']);
  for (const object of commits) {
    if (object.content.includes(0))
      throw new Error(
        `the commit ${object.id} holds a NUL byte, so the scan cannot read it as text (an encoding such as UTF-16): it is refused, not left out`
      );
    const lines = headerLines(object.content.toString('latin1'));
    if (!/^tree [0-9a-f]+$/.test(lines[0] ?? ''))
      throw new Error(`the commit ${object.id} does not begin with its tree`);
    // Round 2 (R12C1-META-ENC-01): every `encoding` header (Git reads the first) names an encoding
    // whose ASCII text is its own bytes.
    for (const line of lines)
      if (line.startsWith('encoding ') && !RAW_TEXT_ENCODING.test(line.slice(9)))
        throw new Error(
          `the commit ${object.id} names the encoding ${show(line.slice(9, 80))}, in which the text Git shows need not be the ASCII bytes the scan's patterns match (UTF-7, for one, holds ASCII text in other bytes): it is refused, not left out`
        );
    for (const line of lines.slice(1)) {
      if (!line.startsWith('parent ')) break;
      const parent = line.slice(7);
      if (!commitSet.has(parent))
        throw new Error(
          `the parent ${show(parent)} of the commit ${object.id} is not in the list of commits, so the list is not the whole history`
        );
    }
  }
  // The tag objects, through tags of tags, each once.
  const tagsById = new Map();
  for (let depth = 0; tagQueue.length; depth += 1) {
    if (depth > 64) throw new Error('the tags name tags more than 64 deep');
    const next = [...new Set(tagQueue.splice(0))].filter(id => !tagsById.has(id));
    for (const object of batchObjects(run, next, ['tag'])) {
      if (object.content.includes(0))
        throw new Error(
          `the tag ${object.id} holds a NUL byte, so the scan cannot read it as text (an encoding such as UTF-16): it is refused, not left out`
        );
      const lines = headerLines(object.content.toString('latin1'));
      const named = /^object (\S+)$/.exec(lines[0] ?? '');
      const typed = /^type (\S+)$/.exec(lines[1] ?? '');
      if (!named || !typed)
        throw new Error(`the tag ${object.id} does not begin with the object and type it names`);
      tagsById.set(object.id, object);
      target(named[1], typed[1], `the tag ${object.id}`);
    }
  }
  const tags = [...tagsById.values()].sort((a, b) => (a.id < b.id ? -1 : 1));
  return {
    commits: Buffer.concat(commits.map(object => object.frame)),
    tags: Buffer.concat(tags.map(object => object.frame)),
    counts: { commits: commits.length, tags: tags.length, otherTargets },
  };
}

// ---------------------------------------------------------------------------------------------
// The candidate identity: the tree with its complete ordered parent vector (GATE-CONTRACT v3 C18)

export const CANDIDATE_IDENTITY_VERSION = 1;
// As many parents as the platform judgment takes (scripts/check-platform-coverage.mjs limits).
const PARENT_LIMIT = 16;

/** Problems with a parent vector: a nonempty list of at most 16 distinct full commit ids. */
export function parentVectorProblems(parents) {
  if (!Array.isArray(parents) || !parents.length)
    return ['the parent vector is not a nonempty list'];
  if (parents.length > PARENT_LIMIT)
    return [`the parent vector has more than ${PARENT_LIMIT} parents`];
  if (!parents.every(item => matches(OBJECT_ID, item)))
    return ['the parent vector holds something that is not a full commit id'];
  if (new Set(parents).size !== parents.length) return ['the parent vector names a commit twice'];
  return [];
}

/** Whether two parent vectors are the same commits in the same order. */
export const sameParents = (a, b) =>
  Array.isArray(a) &&
  Array.isArray(b) &&
  a.length === b.length &&
  a.every((item, index) => item === b[index]);

/** The key of a tree with its complete ordered parent vector: never a shorter key. */
export const identityKey = (tree, parents) => `${tree} ${parents.join(' ')}`;

/**
 * The state of the reserved manifest path that the candidate identity records (v3 C19), from the
 * judgment (judgePlatformManifest): never-held when no commit behind the candidate, and not the
 * candidate, ever held it (maintenance), or valid with the sha256 of the manifest the judgment
 * accepted. Null for anything else (a judgment with problems, or none), which gives no pass.
 */
export function platformManifestState(judged) {
  if (!isObject(judged) || !Array.isArray(judged.problems) || judged.problems.length) return null;
  if (judged.kind === 'maintenance') return { state: 'never-held' };
  if (['manifest', 'introduction'].includes(judged.kind) && matches(HEX64, judged.manifestSha256))
    return { sha256: judged.manifestSha256, state: 'valid' };
  return null;
}

/**
 * The candidate identity record and its sha256 (v3 C18; the record's form is v3's proposal, and
 * the maintainer's decisions accept candidate identity version 1 as the starting vocabulary): the
 * tree, the complete ordered parent vector, the sha256 of the canonical JSON of the candidate's
 * file manifest and the manifest path's state, as canonical JSON. Throws when a part is missing.
 */
export function candidateIdentity({ tree, parents, files, platformManifest }) {
  if (!matches(OBJECT_ID, tree)) throw new Error('the candidate identity has no tree');
  const problems = parentVectorProblems(parents);
  if (problems.length) throw new Error(`the candidate identity: ${problems.join('; ')}`);
  if (!Array.isArray(files)) throw new Error('the candidate identity has no file manifest');
  if (!isObject(platformManifest))
    throw new Error(
      'the candidate identity has no state of the reserved manifest path (C19): the manifest must be judged first'
    );
  const record = {
    filesSha256: sha256(canonicalJson(files)),
    parents: [...parents],
    platformManifest,
    tree,
    version: CANDIDATE_IDENTITY_VERSION,
  };
  return { record, sha256: sha256(canonicalJson(record)) };
}

/**
 * The tree and complete ordered parent vector of `commit` as its own object records them, read
 * with `git cat-file commit` (`git` runs with hardenGitHistory's environment, so no replace ref or
 * graft stands in for it) and parsed strictly: the first header is the tree, every parent header
 * follows it directly, and none comes later.
 */
export function readCommitObject(git, commit) {
  if (!matches(OBJECT_ID, commit)) throw new Error(`${show(commit)} is not a full commit id`);
  const raw = git(['cat-file', 'commit', commit], '');
  const text = Buffer.isBuffer(raw) ? raw.toString('utf8') : String(raw);
  const end = text.indexOf('\n\n');
  const lines = (end < 0 ? text : text.slice(0, end)).split('\n');
  const tree = /^tree ([0-9a-f]{40}|[0-9a-f]{64})$/.exec(lines[0] ?? '')?.[1];
  if (!tree) throw new Error(`commit ${commit} does not begin with its tree`);
  const parents = [];
  let index = 1;
  for (; index < lines.length; index += 1) {
    const parent = /^parent ([0-9a-f]{40}|[0-9a-f]{64})$/.exec(lines[index])?.[1];
    if (!parent) break;
    parents.push(parent);
  }
  if (lines.slice(index).some(line => line.startsWith('parent ')))
    throw new Error(`commit ${commit} names a parent after its other headers`);
  return { tree, parents };
}

/**
 * Why the tree or parents Git could show for `commits` might differ from their own objects': a ref
 * named after one of them, its tree or a parent (a replace ref, in refs/replace/ or under another
 * base), or a commit-graph that gives one another tree or other parents than its object
 * (`graphGit` runs Git with the commit-graph on, replace refs and grafts still off). Grafts and a
 * shallow boundary are refused for the whole repository (historyRewriteProblems). This refuses
 * rather than choosing one view (v3 C18).
 */
export function parentAmbiguityProblems({ git, graphGit, commits }) {
  const problems = [];
  const named = new Set(
    git(['for-each-ref', '--format=%(refname)'], '')
      .toString('utf8')
      .split('\n')
      .filter(Boolean)
      .map(name => name.slice(name.lastIndexOf('/') + 1))
  );
  for (const commit of commits) {
    const object = readCommitObject(git, commit);
    for (const id of [commit, object.tree, ...object.parents])
      if (named.has(id))
        problems.push(
          `a ref is named after ${id} (${id === commit ? 'the commit' : id === object.tree ? 'its tree' : 'a parent'} of ${commit}), as a replace ref is: remove it`
        );
    if (graphGit) {
      const seen = graphGit(['log', '-1', '--no-walk', '--format=%T %P', commit, '--'], '')
        .toString('utf8')
        .trim()
        .split(' ')
        .filter(Boolean);
      if (seen[0] !== object.tree || !sameParents(seen.slice(1), object.parents))
        problems.push(
          `the commit-graph gives commit ${commit} another tree or other parents than its object: rewrite it (git commit-graph write)`
        );
    }
  }
  return problems;
}

/**
 * After a commit exists (v3 C18, and the maintainer's C18 clarification): recomputes its
 * tree and complete ordered parent vector from its own object and compares them with the
 * `intended` { tree, parents } that were approved before it was made, exactly and in order, and
 * refuses any replace or commit-graph ambiguity. Returns the problems (none when it matches).
 */
export function committedIdentityProblems({ git, graphGit, commit, intended }) {
  let object;
  try {
    object = readCommitObject(git, commit);
  } catch (error) {
    return [error.message];
  }
  const problems = [];
  if (object.tree !== intended?.tree)
    problems.push(
      `commit ${commit} has the tree ${object.tree}, not the intended ${intended?.tree}`
    );
  if (!sameParents(object.parents, intended?.parents))
    problems.push(
      `commit ${commit} has the parents [${object.parents.join(', ')}], not the intended complete ordered vector [${Array.isArray(intended?.parents) ? intended.parents.join(', ') : ''}]`
    );
  try {
    problems.push(...parentAmbiguityProblems({ git, graphGit, commits: [commit] }));
  } catch (error) {
    problems.push(error.message);
  }
  return problems;
}

// ---------------------------------------------------------------------------------------------
// The history the candidate's manifest is judged against

const historyLimit = 100000;
const manifestBlobLimit = 1024 * 1024;

/**
 * The bytes at test/platform-manifest.json in each tree-ish of `names` (commits or trees, as full
 * object ids), from Git (`git(args, input)` runs Git and returns its output as a Buffer, throwing
 * when Git fails): a Map name -> Buffer, or null where nothing is there. Something there that is
 * not a regular file (a folder, a link, a submodule) or a file over 1 MiB is given as bytes that
 * cannot validate, as judgeCandidateManifest() asks. Git prints "<id> submodule" for a submodule
 * whose commit this repository lacks, whatever the format asks; one whose commit it has is a
 * commit with mode 160000. A commit whose history holds either is then a commit behind the
 * candidate that held a manifest: the branch has a platform contract from then on (see
 * docs/engineering-quality.md).
 */
export function manifestsAt(git, names) {
  const result = new Map();
  if (!names.length) return result;
  const check = git(
    ['cat-file', '--batch-check=%(objectname) %(objecttype) %(objectmode) %(objectsize)'],
    names.map(name => `${name}:${manifestFile}\n`).join('')
  )
    .toString('utf8')
    .split('\n');
  if (check.pop() !== '' || check.length !== names.length)
    throw new Error('unexpected git cat-file output');
  const wanted = new Map();
  for (const [index, line] of check.entries()) {
    const name = names[index];
    if (line === `${name}:${manifestFile} missing`) {
      result.set(name, null);
      continue;
    }
    if (/^(?:[0-9a-f]{40}|[0-9a-f]{64}) submodule$/.test(line)) {
      result.set(name, Buffer.alloc(0));
      continue;
    }
    const match = /^([0-9a-f]{40}|[0-9a-f]{64}) (blob|tree|commit|tag) ([0-7]*) (\d+)$/.exec(line);
    if (!match) throw new Error('unexpected git cat-file output');
    const [, id, type, mode, size] = match;
    if (type === 'blob' && ['100644', '100755'].includes(mode) && Number(size) <= manifestBlobLimit)
      wanted.set(name, id);
    else result.set(name, Buffer.alloc(0));
  }
  const ids = [...new Set(wanted.values())];
  const blobs = new Map();
  if (ids.length) {
    const output = git(['cat-file', '--batch'], ids.map(id => `${id}\n`).join(''));
    let offset = 0;
    for (const id of ids) {
      const end = output.indexOf(10, offset);
      const header = end < 0 ? '' : output.toString('utf8', offset, end);
      const match = /^([0-9a-f]{40}|[0-9a-f]{64}) blob (\d+)$/.exec(header);
      if (!match || match[1] !== id) throw new Error('unexpected git cat-file output');
      const size = Number(match[2]);
      const start = end + 1;
      if (output[start + size] !== 10) throw new Error('unexpected git cat-file output');
      blobs.set(id, Buffer.from(output.subarray(start, start + size)));
      offset = start + size + 1;
    }
    if (offset !== output.length) throw new Error('unexpected git cat-file output');
  }
  for (const [name, id] of wanted) result.set(name, blobs.get(id));
  return result;
}

/**
 * Every commit `heads` reach, as judgeCandidateManifest() takes them: { commit, parents, manifest,
 * reviewed }, with `tree` too. Each commit's tree and parents are its object's own (Git runs with
 * hardenGitHistory's environment). `approvals` maps identityKey(tree, complete ordered parents) to
 * the manifest sha256 a verified finalization of that candidate judged (security-finalization.mjs
 * finds them, and checks each commit it marks again from its object): only a commit with exactly
 * that tree and that whole parent vector, in order, is reviewed, never one that shares only the
 * tree and the first parent (security review GD-01). A root commit is walked but never reviewed. More
 * than 100,000 commits throws.
 */
export function readHistory(git, heads, approvals = new Map()) {
  if (!Array.isArray(heads) || !heads.every(head => matches(OBJECT_ID, head)))
    throw new Error('the parents are not commit ids');
  if (!heads.length) return [];
  const lines = git(
    [
      'rev-list',
      '--no-commit-header',
      '--format=%H %T %P',
      `--max-count=${historyLimit + 1}`,
      ...heads,
      '--',
    ],
    ''
  )
    .toString('utf8')
    .split('\n');
  if (lines.pop() !== '') throw new Error('unexpected git rev-list output');
  if (lines.length > historyLimit)
    throw new Error(`the history behind the candidate has more than ${historyLimit} commits`);
  const nodes = lines.map(line => {
    // "<commit> <tree> <parents…>"; a root commit has no parents (the line ends with a space).
    const ids = line.split(' ').filter(Boolean);
    if (ids.length < 2 || !ids.every(id => OBJECT_ID.test(id)))
      throw new Error('unexpected git rev-list output');
    const [commit, tree, ...parents] = ids;
    return { commit, tree, parents };
  });
  const manifests = manifestsAt(
    git,
    nodes.map(node => node.commit)
  );
  return nodes.map(({ commit, tree, parents }) => {
    const approved = parents.length ? approvals.get(identityKey(tree, parents)) : undefined;
    return {
      commit,
      parents,
      manifest: manifests.get(commit),
      reviewed: approved === undefined ? null : { manifestSha256: approved },
      tree,
    };
  });
}

/**
 * The reviewed coverage dispositions file (`<git common dir>/orbit-security/coverage/<tree>.json`,
 * read by the caller as a private regular file): { schemaVersion: 2, tree, parents, dispositions },
 * bound to the candidate's tree and its complete ordered parent vector (v3 C18). Version 1, which
 * named a single parent, gives no authority (maintainer decision "C18 legacy approvals").
 * Returns the dispositions; throws on anything else.
 */
export function parseCoverageDispositions(bytes, binding) {
  const value = strictJson(bytes, 'the coverage dispositions file');
  if (isObject(value) && value.schemaVersion === 1)
    throw new Error(
      'the coverage dispositions file is version 1, bound to a single parent, which gives no authority: write version 2 with the complete ordered parent vector'
    );
  const problems = fields('the coverage dispositions file', value, [
    'schemaVersion',
    'tree',
    'parents',
    'dispositions',
  ]);
  if (problems.length) throw new Error(problems.join('; '));
  if (value.schemaVersion !== 2)
    throw new Error('the coverage dispositions file has another schema version');
  if (value.tree !== binding.tree || !sameParents(value.parents, binding.parents))
    throw new Error(
      "the coverage dispositions file is not bound to this candidate's tree and complete ordered parent vector"
    );
  if (!Array.isArray(value.dispositions) || value.dispositions.length > 500)
    throw new Error('the coverage dispositions file holds no list of at most 500 dispositions');
  return value.dispositions;
}

/**
 * Judges the candidate's manifest (judgeCandidateManifest) and turns every problem and every loss
 * no disposition excuses into problems. `complete` is false while Git runs the guard for an
 * automatic merge (its other parent is not known yet) or MERGE_HEAD cannot be read; `reason` says
 * which. Then the candidate is refused, whatever its kind: its complete parent vector is not
 * known, so nothing can be approved for it (v3 C18; security review GD-R1 found that the earlier
 * maintenance exception let a two-parent commit through before its unseen parent was judged).
 * Merge with --no-commit, then run git commit. `refused` lists what makes the parents Git shows
 * ambiguous (parentAmbiguityProblems), each a problem too. `binding` is the candidate's
 * { tree, parents }.
 */
export function judgePlatformManifest({
  candidate,
  heads,
  complete = true,
  reason = '',
  history,
  refused = [],
  dispositions = [],
  binding,
}) {
  const judged = judgeCandidateManifest({
    candidate,
    heads,
    history: history.map(({ commit, parents, manifest, reviewed }) => ({
      commit,
      parents,
      manifest,
      reviewed,
    })),
    dispositions,
    binding,
  });
  const problems = [];
  if (!complete)
    problems.push(
      `the parents of this commit are not all known (${reason}): merge with --no-commit, then run git commit`
    );
  problems.push(...refused);
  problems.push(...judged.problems);
  for (const loss of judged.losses)
    if (!loss.excused)
      problems.push(`a loss no reviewed disposition excuses: ${loss.what} (${loss.key})`);
  return {
    kind: judged.kind,
    manifestSha256: judged.sha256,
    manifest: judged.manifest,
    heads: [...heads],
    baselines: judged.baselines,
    losses: judged.losses,
    problems,
  };
}

/** What the run records of its judgment, and what every other run of the candidate must equal. */
export const judgmentSummary = judged => ({
  kind: judged.kind,
  manifestSha256: judged.manifestSha256 ?? null,
});

// ---------------------------------------------------------------------------------------------
// Which runs a candidate needs

/** The one non-container run of `manifest` on `platform` that runs every file, or null. */
export function fullRunOf(manifest, platform) {
  const found = Object.entries(manifest.runs).filter(
    ([, run]) => run.platform === platform && run.files === 'all'
  );
  return found.length === 1 ? found[0][0] : null;
}

/** The non-container runs `gate` (commit or release) requires. */
export const requiredRuns = (manifest, gate) =>
  Object.entries(manifest.runs)
    .filter(([, run]) => run.platform !== 'container' && run.requiredFor.includes(gate))
    .map(([id]) => id)
    .sort();

/**
 * Whether a passing run `a` also covers run `b`: the same run, or one on the same platform that
 * runs every file of `b` on every runtime of `b`, and that every entry requiring `b` requires too
 * (so a macOS full run covers the macOS platform run).
 */
export function satisfies(manifest, a, b) {
  if (a === b) return true;
  const runA = manifest.runs[a],
    runB = manifest.runs[b];
  if (!runA || !runB || runA.platform !== runB.platform || runA.platform === 'container')
    return false;
  if (
    runA.files !== 'all' &&
    (runB.files === 'all' || !runB.files.every(file => runA.files.includes(file)))
  )
    return false;
  if (!runB.runtimes.every(runtime => runA.runtimes.includes(runtime))) return false;
  return manifest.entries.every(entry => !entry.evidence.includes(b) || entry.evidence.includes(a));
}

/** Whether run `runId` hosts a container run with at least one pinned image (the T8 driver). */
export const hostsImages = (manifest, runId) =>
  Object.values(manifest.runs).some(
    run =>
      run.platform === 'container' &&
      run.hostRuns.includes(runId) &&
      Object.values(run.images).some(image => image !== null)
  );

// ---------------------------------------------------------------------------------------------
// Runtime identity

const RUNTIME_FIELDS = [
  'schemaVersion',
  'binarySha256',
  'version',
  'platform',
  'arch',
  'distribution',
  'recordedAt',
  'reference',
];
const OUTCOMES = ['verified', 'absent', 'invalid', 'unavailable'];

/** Problems with an exception: { reason, reviewer, reference, reviewedAt }, plus `extra` fields. */
function exceptionProblems(where, value, extra = []) {
  const problems = fields(where, value, [
    'reason',
    'reviewer',
    'reference',
    'reviewedAt',
    ...extra,
  ]);
  if (problems.length) return problems;
  for (const key of ['reason', 'reviewer', 'reference'])
    if (!text(value[key])) problems.push(`${where}: ${key} is not a non-empty line of text`);
  if (!isTime(value.reviewedAt)) problems.push(`${where}: reviewedAt is not a UTC time`);
  return problems;
}

// The name Node's release archives give each platform and architecture (process.platform and
// process.arch): node-<version>-<platform>-<architecture>.tar.gz or .tar.xz.
const releaseArchitectures = Object.freeze({
  darwin: { arm64: 'arm64', x64: 'x64' },
  linux: { arm64: 'arm64', x64: 'x64', arm: 'armv7l', ppc64: 'ppc64le', s390x: 's390x' },
});

/**
 * The reviewed list of Node release signing keys (`<git common dir>/orbit-security/
 * runtime-identity/release-keys.json`): { schemaVersion: 1, keyringSha256, fingerprints, source,
 * sourceSha256, reviewer, reference, reviewedAt }. `fingerprints` are the keys (40 upper-case hex
 * digits each, at most 64, none twice) that may sign a release's SHASUMS256.txt, `keyringSha256`
 * the sha256 of the isolated keyring made from exactly them, and `source` and `sourceSha256` where
 * the list came from. Throws when it is anything else.
 */
export function parseReleaseKeys(bytes) {
  const where = 'the reviewed Node release keys';
  const value = strictJson(bytes, where, 64 * 1024);
  const problems = fields(where, value, [
    'schemaVersion',
    'keyringSha256',
    'fingerprints',
    'source',
    'sourceSha256',
    'reviewer',
    'reference',
    'reviewedAt',
  ]);
  if (problems.length) throw new Error(problems.join('; '));
  if (
    value.schemaVersion !== 1 ||
    !matches(HEX64, value.keyringSha256) ||
    !matches(HEX64, value.sourceSha256) ||
    !Array.isArray(value.fingerprints) ||
    !value.fingerprints.length ||
    value.fingerprints.length > 64 ||
    !value.fingerprints.every(item => typeof item === 'string' && /^[0-9A-F]{40}$/.test(item)) ||
    new Set(value.fingerprints).size !== value.fingerprints.length ||
    !['source', 'reviewer', 'reference'].every(key => text(value[key])) ||
    !isTime(value.reviewedAt)
  )
    throw new Error(
      `${where} are not { schemaVersion 1, keyring and source sha256, 1 to 64 distinct fingerprints of 40 upper-case hex digits, source, reviewer, reference, reviewedAt }`
    );
  return value;
}

/**
 * Problems with a runtime identity record (`<git common dir>/orbit-security/runtime-identity/
 * <binary sha256>.json`) for the Node executable observed as { sha256, version, platform, arch }.
 * An upstream binary needs distribution "nodejs-release", the release archive of exactly that
 * version, platform and architecture, and a verified check of the release's signed SHASUMS256.txt
 * by a key of `releaseKeys` (parseReleaseKeys) with that list's keyring; a Homebrew build is a
 * different identity, never described as signed by the Node release keys: its formula and version
 * must be that Node's, and it counts only through a reviewed exception.
 */
export function runtimeIdentityProblems(record, observed, releaseKeys = null) {
  const where = 'the runtime identity record';
  const problems = fields(where, record, RUNTIME_FIELDS, ['release', 'homebrew', 'exception']);
  if (problems.length) return problems;
  if (record.schemaVersion !== 1) problems.push(`${where} has another schema version`);
  if (record.binarySha256 !== observed.sha256)
    problems.push(
      `${where} is for the binary ${show(record.binarySha256)}, not ${observed.sha256}`
    );
  if (record.version !== observed.version)
    problems.push(`${where} is for Node ${show(record.version)}, not ${observed.version}`);
  if (record.platform !== observed.platform || record.arch !== observed.arch)
    problems.push(
      `${where} is for ${show(record.platform)}/${show(record.arch)}, not ${observed.platform}/${observed.arch}`
    );
  if (!isTime(record.recordedAt)) problems.push(`${where}: recordedAt is not a UTC time`);
  if (!text(record.reference)) problems.push(`${where} has no evidence reference`);
  if (record.distribution === 'nodejs-release') {
    if (own(record, 'homebrew') || own(record, 'exception'))
      problems.push(`${where}: a Node release binary has no Homebrew build or exception`);
    const release = record.release;
    const releaseProblems = fields(`${where}: release`, release, [
      'archive',
      'archiveSha256',
      'shasumsSha256',
      'signatureSha256',
      'signer',
      'keyringSha256',
      'outcome',
    ]);
    problems.push(...releaseProblems);
    if (!releaseProblems.length) {
      const architecture = own(releaseArchitectures, observed.platform)
        ? releaseArchitectures[observed.platform][observed.arch]
        : undefined;
      const archive = `node-${observed.version}-${observed.platform}-${architecture}.tar.`;
      if (
        typeof architecture !== 'string' ||
        typeof release.archive !== 'string' ||
        ![`${archive}gz`, `${archive}xz`].includes(release.archive)
      )
        problems.push(
          `${where}: release.archive ${show(release.archive)} is not the Node ${observed.version} release archive for ${observed.platform}/${observed.arch}`
        );
      for (const key of ['archiveSha256', 'shasumsSha256', 'signatureSha256', 'keyringSha256'])
        if (!matches(HEX64, release[key]))
          problems.push(`${where}: release.${key} is not a sha256`);
      if (!matches(/^[0-9A-F]{40}$/, release.signer))
        problems.push(
          `${where}: release.signer is not a key fingerprint (40 upper-case hex digits)`
        );
      else if (!releaseKeys)
        problems.push(
          `${where}: there is no reviewed list of Node release keys to check its signer`
        );
      else {
        if (!releaseKeys.fingerprints.includes(release.signer))
          problems.push(
            `${where}: release.signer ${release.signer} is not one of the reviewed Node release keys`
          );
        if (release.keyringSha256 !== releaseKeys.keyringSha256)
          problems.push(
            `${where}: release.keyringSha256 is not the keyring of the reviewed Node release keys`
          );
      }
      if (!OUTCOMES.includes(release.outcome))
        problems.push(`${where}: release.outcome ${show(release.outcome)} is unknown`);
      else if (release.outcome !== 'verified')
        problems.push(`${where}: the signed SHASUMS check is ${release.outcome}, not verified`);
    }
  } else if (record.distribution === 'homebrew') {
    if (own(record, 'release'))
      problems.push(
        `${where}: a Homebrew build is not a Node release binary and has no release signature check`
      );
    const brew = record.homebrew;
    const brewProblems = fields(`${where}: homebrew`, brew, ['formula', 'version', 'bottleSha256']);
    problems.push(...brewProblems);
    if (!brewProblems.length) {
      if (brew.formula !== 'node' && brew.formula !== `node@${major(observed.version)}`)
        problems.push(
          `${where}: homebrew.formula ${show(brew.formula)} is not node or node@${major(observed.version)}`
        );
      if (
        typeof brew.version !== 'string' ||
        !/^\d{1,3}\.\d{1,4}\.\d{1,4}(?:_\d{1,3})?$/.test(brew.version) ||
        `v${brew.version.replace(/_\d+$/, '')}` !== observed.version
      )
        problems.push(
          `${where}: homebrew.version ${show(brew.version)} is not the formula version of Node ${observed.version}`
        );
      if (brew.bottleSha256 !== null && !matches(HEX64, brew.bottleSha256))
        problems.push(`${where}: homebrew.bottleSha256 is neither null nor a sha256`);
    }
    if (!own(record, 'exception'))
      problems.push(
        `${where}: a Homebrew build counts only through a reviewed exception, and has none`
      );
    else problems.push(...exceptionProblems(`${where}: exception`, record.exception));
  } else problems.push(`${where}: distribution ${show(record.distribution)} is unknown`);
  return problems;
}

// ---------------------------------------------------------------------------------------------
// Golden tools: Actionlint (GATE-CONTRACT v4 C4 and C7, drafts; security review GD-R2; maintainer decision 8)

// The gate-owned Actionlint configuration, written into the evidence and named with -config-file:
// empty, as the security review's control (`-config-file /dev/null`), so no candidate file can ignore a
// finding. The candidate's own .github/actionlint.yaml and .yml are refused before anything is
// installed as well (candidate-policy).
export const actionlintConfig = '';
export const actionlintConfigFile = 'actionlint-config.yaml';
/**
 * The arguments the workflow-analysis stage gives the pinned Actionlint binary: the gate-owned
 * configuration, and no shellcheck or pyflakes integration, since Actionlint would otherwise start
 * whatever shellcheck or pyflakes it finds on PATH, tools the golden-tool manifest does not pin.
 */
export const actionlintArguments = configPath => [
  '-config-file',
  configPath,
  '-shellcheck=',
  '-pyflakes=',
  '-no-color',
];
/** Whether a candidate file would configure Actionlint (any letter case, as a macOS volume reads it). */
export const actionlintCandidateConfig = file => /^\.github\/actionlint\.ya?ml$/i.test(file);
/** The file name of a golden-tool record for `tool` on `platform` and `arch` (a proposed path). */
export const goldenToolName = (tool, platform, arch) => `${tool}-${platform}-${arch}.json`;

// The golden-tool record's version: 2 binds the dependency closure the tool needs to run (maintainer
// decision 8). A version 1 record binds none, and no reader falls back to it.
export const GOLDEN_TOOL_SCHEMA = 2;
const GOLDEN_FIELDS = [
  'schemaVersion',
  'tool',
  'platform',
  'arch',
  'path',
  'version',
  'sha256',
  'provenance',
  'dependencyClosure',
  'reviewer',
  'reference',
  'reviewedAt',
];
const CLOSURE_LIMIT = 64;
const absoluteToolPath = value =>
  typeof value === 'string' &&
  path.isAbsolute(value) &&
  path.normalize(value) === value &&
  text(value);

/** The digest of a dependency closure: the sha256 of its canonical JSON ([{ path, sha256 }…]). */
export const closureSha256 = closure => sha256(canonicalJson(closure));

/**
 * What a gate run must name while no qualified pin exists for `tool` (maintainer decision 8; v4 C4):
 * the tool, its reviewed version, the platform, the proposed name of the pin's golden-tool record,
 * and the evidence the pin needs before the tool can run, ending with its binding in the qualified
 * golden-tool manifest of the trusted gate export, which this draft does not have. The missing
 * pin is pending AND blocking: the run exits nonzero, nothing falls back to PATH, a download, an
 * observed hash, a local golden-tool record, a skip or continue-on-error, and no finalization can
 * pass.
 */
export function missingToolPin({ tool, version, platform, arch }) {
  return {
    tool,
    version,
    platform,
    arch,
    record: goldenToolName(tool, platform, arch),
    evidence: [
      'path: the exact absolute path the gate runs',
      `version: ${version}`,
      'sha256: the binary digest',
      `platform: ${platform}/${arch}`,
      'provenance: source, archive, archive sha256 and verification',
      'dependencyClosure: every file the binary needs to run, with its sha256',
      'review: reviewer, reference and time',
      "binding: the qualified golden-tool manifest of the trusted gate export, which must bind all of the above (the gate identity's toolPinsSha256 and toolPaths; v4 C1, C4, C7); a local golden-tool record gives no authority",
    ],
  };
}

/**
 * The form of a golden-tool record, as a run seals the record of the binary it ran: { schemaVersion
 * 2, tool, platform, arch, path, version, sha256, provenance: { source, archive, archiveSha256,
 * verification }, dependencyClosure: [{ path, sha256 }…], reviewer, reference, reviewedAt }. v4 C7
 * names what the golden-tool manifest holds (exact absolute path, version, digest, package or
 * source provenance, platform), and maintainer decision 8 adds the dependency closure needed to run it:
 * every file besides the binary, sorted by path, each once (an empty list states that the binary
 * needs none, which the review has to establish). The form is proposed. A record of this form is
 * only a claim: nothing here authenticates it, so it gives no authority on its own. Only the
 * qualified golden-tool manifest of the trusted gate export can bind a pin (maintainer decision 8;
 * v4 C4, C7), and this draft has none: the gate reads no such record and runs no Actionlint, and
 * the finalizer leaves the binding to F. Throws unless the bytes are that, for `tool` on
 * `platform`/`arch` at the reviewed `version`; a version 1 record is refused.
 */
export function parseGoldenTool(bytes, { tool, platform, arch, version }) {
  const where = `the golden-tool record of ${tool}`;
  const value = strictJson(bytes, where, 64 * 1024);
  if (isObject(value) && value.schemaVersion === 1)
    throw new Error(
      `${where} is version 1, which binds no dependency closure: no reader falls back to it (maintainer decision 8)`
    );
  const problems = fields(where, value, GOLDEN_FIELDS);
  if (problems.length) throw new Error(problems.join('; '));
  const provenance = fields(`${where}: provenance`, value.provenance, [
    'source',
    'archive',
    'archiveSha256',
    'verification',
  ]);
  if (provenance.length) throw new Error(provenance.join('; '));
  if (
    value.schemaVersion !== GOLDEN_TOOL_SCHEMA ||
    value.tool !== tool ||
    value.platform !== platform ||
    value.arch !== arch ||
    value.version !== version ||
    !absoluteToolPath(value.path) ||
    !matches(HEX64, value.sha256) ||
    !matches(HEX64, value.provenance.archiveSha256) ||
    !['source', 'archive', 'verification'].every(key => text(value.provenance[key])) ||
    !['reviewer', 'reference'].every(key => text(value[key])) ||
    !isTime(value.reviewedAt)
  )
    throw new Error(
      `${where} is not a version 2 record of ${tool} ${version} on ${platform}/${arch} with an absolute path, its sha256, provenance, a dependency closure and a review`
    );
  const closure = value.dependencyClosure;
  if (!Array.isArray(closure) || closure.length > CLOSURE_LIMIT)
    throw new Error(`${where}: dependencyClosure is not a list of at most ${CLOSURE_LIMIT} files`);
  for (const [index, item] of closure.entries()) {
    const itemProblems = fields(`${where}: dependencyClosure item`, item, ['path', 'sha256']);
    if (itemProblems.length) throw new Error(itemProblems.join('; '));
    if (
      !absoluteToolPath(item.path) ||
      item.path === value.path ||
      !matches(HEX64, item.sha256) ||
      (index > 0 && !(closure[index - 1].path < item.path))
    )
      throw new Error(
        `${where}: dependencyClosure must name absolute files other than the binary, each once, sorted, with their sha256`
      );
  }
  return value;
}

/** The sha256 of the regular file at `file`, opened without following a link. */
export function fileSha256(file, max = 512 * 1024 * 1024) {
  return sha256(readRegularFile(file, { max, privateOnly: false }));
}

// ---------------------------------------------------------------------------------------------
// Image authenticity

const IMAGE_FIELDS = [
  'schemaVersion',
  'image',
  'indexDigest',
  'platform',
  'platformManifestDigest',
  'configDigest',
  'indexBase64',
  'platformManifestBase64',
  'outcome',
  'recordedAt',
];
const IMAGE_OUTCOMES = ['verified', 'exception', 'absent', 'invalid', 'unavailable'];
const PLATFORM_PART = /^[a-z0-9]{1,20}$/;
const INDEX_TYPES = [
  'application/vnd.oci.image.index.v1+json',
  'application/vnd.docker.distribution.manifest.list.v2+json',
];
const MANIFEST_TYPES = [
  'application/vnd.oci.image.manifest.v1+json',
  'application/vnd.docker.distribution.manifest.v2+json',
];
const CONFIG_TYPES = [
  'application/vnd.oci.image.config.v1+json',
  'application/vnd.docker.container.image.v1+json',
];
const DESCRIPTOR_LIMIT = 256 * 1024;

/** The bytes of `value`: canonical base64 of at most `max` bytes, or null. */
function base64Bytes(value, max) {
  if (typeof value !== 'string' || !value.length || value.length > Math.ceil(max / 3) * 4)
    return null;
  const bytes = Buffer.from(value, 'base64');
  return bytes.toString('base64') === value && bytes.length <= max ? bytes : null;
}

/**
 * Problems with the digests an image authenticity record binds, worked out from the exact bytes it
 * carries rather than taken on trust: the image index (`indexBase64`, whose sha256 must be the
 * index digest), its one entry for the record's platform (whose digest must be
 * `platformManifestDigest`), and that platform manifest (`platformManifestBase64`, whose sha256
 * must be that digest and whose config must be `configDigest`). So the platform manifest is the
 * one the pinned index gives the platform Docker ran, and the config the one it names.
 */
function imageDigestProblems(where, record) {
  const problems = [];
  const parse = (bytes, what, check) => {
    let value;
    try {
      value = strictJson(bytes, `the ${what} it carries`, DESCRIPTOR_LIMIT);
    } catch (error) {
      problems.push(`${where}: ${error.message}`);
      return null;
    }
    if (!isObject(value) || value.schemaVersion !== 2 || !check(value)) {
      problems.push(`${where}: the ${what} it carries is not an OCI or Docker image ${what}`);
      return null;
    }
    return value;
  };
  const indexBytes = base64Bytes(record.indexBase64, DESCRIPTOR_LIMIT);
  if (!indexBytes)
    problems.push(
      `${where}: indexBase64 is not the base64 bytes of an image index of 256 KiB or less`
    );
  else if (`sha256:${sha256(indexBytes)}` !== record.indexDigest)
    problems.push(`${where}: the index it carries does not hash to its index digest`);
  const index =
    indexBytes &&
    parse(
      indexBytes,
      'index',
      value =>
        (!own(value, 'mediaType') || INDEX_TYPES.includes(value.mediaType)) &&
        Array.isArray(value.manifests) &&
        value.manifests.length <= 1024 &&
        !own(value, 'config') &&
        !own(value, 'layers')
    );
  if (index && isObject(record.platform)) {
    const { os: system, architecture, variant } = record.platform;
    const entries = index.manifests.filter(
      item =>
        isObject(item?.platform) &&
        item.platform.os === system &&
        item.platform.architecture === architecture &&
        (item.platform.variant ?? null) === variant
    );
    if (entries.length !== 1)
      problems.push(
        `${where}: its index has ${entries.length} entries for ${show(record.platform)}, not one`
      );
    else if (
      !MANIFEST_TYPES.includes(entries[0].mediaType) ||
      entries[0].digest !== record.platformManifestDigest
    )
      problems.push(
        `${where}: platformManifestDigest is not the image manifest its index gives that platform (${show(entries[0].digest)})`
      );
  }
  const manifestBytes = base64Bytes(record.platformManifestBase64, DESCRIPTOR_LIMIT);
  if (!manifestBytes)
    problems.push(
      `${where}: platformManifestBase64 is not the base64 bytes of an image manifest of 256 KiB or less`
    );
  else if (`sha256:${sha256(manifestBytes)}` !== record.platformManifestDigest)
    problems.push(
      `${where}: the platform manifest it carries does not hash to platformManifestDigest`
    );
  const manifest =
    manifestBytes &&
    parse(
      manifestBytes,
      'manifest',
      value =>
        (!own(value, 'mediaType') || MANIFEST_TYPES.includes(value.mediaType)) &&
        isObject(value.config) &&
        CONFIG_TYPES.includes(value.config.mediaType) &&
        !own(value, 'manifests')
    );
  if (manifest && manifest.config.digest !== record.configDigest)
    problems.push(
      `${where}: configDigest is not the config its platform manifest names (${show(manifest.config.digest)})`
    );
  return problems;
}

/** The file name of an image's authenticity record for one platform. */
export function imageRecordName(image, platform) {
  const digest = /@sha256:([0-9a-f]{64})$/.exec(image ?? '')?.[1];
  if (
    !digest ||
    !matches(PLATFORM_PART, platform?.os) ||
    !matches(PLATFORM_PART, platform?.architecture) ||
    (platform.variant !== null && !matches(PLATFORM_PART, platform.variant))
  )
    return null;
  return `${digest}-${platform.os}-${platform.architecture}${platform.variant ? `-${platform.variant}` : ''}.json`;
}

/**
 * What Docker reports of each image (`docker image inspect --format '{{json .}}' <image>…`, one
 * line per image, in order): [{ id, repoDigests, platform: { os, architecture, variant } }].
 */
export function parseImageInspection(log, images) {
  const lines = String(log)
    .split('\n')
    .filter(line => line.trim());
  if (lines.length !== images.length)
    throw new Error(`docker image inspect described ${lines.length} images, not ${images.length}`);
  return lines.map((line, index) => {
    let value;
    try {
      value = JSON.parse(line);
    } catch {
      throw new Error(`docker image inspect line ${index + 1} is not JSON`);
    }
    if (
      !isObject(value) ||
      !matches(DIGEST, value.Id) ||
      !Array.isArray(value.RepoDigests) ||
      !value.RepoDigests.every(item => typeof item === 'string') ||
      !matches(PLATFORM_PART, value.Os) ||
      !matches(PLATFORM_PART, value.Architecture) ||
      (value.Variant !== undefined &&
        value.Variant !== '' &&
        !matches(PLATFORM_PART, value.Variant))
    )
      throw new Error(
        `docker image inspect line ${index + 1} lacks an image id, digests or platform`
      );
    return {
      image: images[index],
      id: value.Id,
      repoDigests: value.RepoDigests,
      platform: { os: value.Os, architecture: value.Architecture, variant: value.Variant || null },
    };
  });
}

/**
 * Problems with the authenticity record of the image a T8 container run used. `used`: { image,
 * imageId } from the driver's container record, and `observed` from parseImageInspection. T8
 * evidence counts only for an image whose record names this exact pinned image and index digest,
 * the platform Docker ran, the platform manifest the index gives that platform and its config
 * (imageDigestProblems, from the index and manifest bytes the record carries), and the image ID
 * Docker reports (the index digest with the containerd image store, else the config digest), with
 * a verified publisher signature or a reviewed exception. Absent, invalid and unavailable are
 * recorded outcomes that block use.
 */
export function imageAuthenticityProblems(record, used, observed) {
  const where = `the authenticity record of ${used.image}`;
  const problems = fields(where, record, IMAGE_FIELDS, ['verification', 'exception']);
  if (problems.length) return problems;
  const indexDigest = /@(sha256:[0-9a-f]{64})$/.exec(used.image)?.[1];
  if (record.schemaVersion !== 1) problems.push(`${where} has another schema version`);
  if (record.image !== used.image)
    problems.push(`${where} is for another image: ${show(record.image)}`);
  if (record.indexDigest !== indexDigest)
    problems.push(`${where} binds the digest ${show(record.indexDigest)}, not ${indexDigest}`);
  for (const key of ['platformManifestDigest', 'configDigest'])
    if (!matches(DIGEST, record[key])) problems.push(`${where}: ${key} is not a sha256 digest`);
  problems.push(...imageDigestProblems(where, record));
  const platformProblems = fields(`${where}: platform`, record.platform, [
    'os',
    'architecture',
    'variant',
  ]);
  problems.push(...platformProblems);
  if (
    !platformProblems.length &&
    (record.platform.os !== observed.platform.os ||
      record.platform.architecture !== observed.platform.architecture ||
      record.platform.variant !== observed.platform.variant)
  )
    problems.push(
      `${where} is for ${show(record.platform)}, not the platform Docker ran: ${show(observed.platform)}`
    );
  if (observed.image !== used.image) problems.push(`${where}: Docker described another image`);
  if (observed.id !== used.imageId)
    problems.push(
      `${where}: Docker reports the image ID ${observed.id}, not the driver's ${used.imageId}`
    );
  const repository = used.image.split('@')[0].split(':')[0];
  const names = [repository, `docker.io/library/${repository}`, `docker.io/${repository}`];
  if (!observed.repoDigests.some(item => names.some(name => item === `${name}@${indexDigest}`)))
    problems.push(`${where}: Docker does not list the pinned digest ${indexDigest} for it`);
  if (used.imageId !== record.indexDigest && used.imageId !== record.configDigest)
    problems.push(
      `${where}: the image ID ${used.imageId} is neither its index digest nor its config digest`
    );
  if (!isTime(record.recordedAt)) problems.push(`${where}: recordedAt is not a UTC time`);
  if (!IMAGE_OUTCOMES.includes(record.outcome))
    problems.push(`${where}: the outcome ${show(record.outcome)} is unknown`);
  else if (record.outcome === 'verified') {
    if (own(record, 'exception')) problems.push(`${where}: a verified image has no exception`);
    const verification = fields(`${where}: verification`, record.verification, [
      'mechanism',
      'identity',
      'trustRoot',
      'evidenceSha256',
    ]);
    problems.push(...verification);
    if (!verification.length) {
      for (const key of ['mechanism', 'identity', 'trustRoot'])
        if (!text(record.verification[key]))
          problems.push(`${where}: verification.${key} is not a non-empty line of text`);
      if (!matches(HEX64, record.verification.evidenceSha256))
        problems.push(`${where}: verification.evidenceSha256 is not a sha256`);
    }
  } else if (record.outcome === 'exception') {
    if (own(record, 'verification'))
      problems.push(`${where}: an exception is not a verified publisher signature`);
    const exception = exceptionProblems(`${where}: exception`, record.exception, [
      'disposition',
      'evidenceSha256',
    ]);
    problems.push(...exception);
    if (!exception.length) {
      if (!text(record.exception.disposition))
        problems.push(`${where}: exception.disposition is not a non-empty line of text`);
      if (!matches(HEX64, record.exception.evidenceSha256))
        problems.push(`${where}: exception.evidenceSha256 is not a sha256`);
    }
  } else
    problems.push(
      `${where}: its publisher signature is ${record.outcome}, which blocks use (only verified, or a reviewed exception, counts)`
    );
  return problems;
}

/**
 * Why the T8 image check stays pending even when its authenticity record is consistent
 * (imageAuthenticityProblems finds nothing): an authenticity record is identity and evidence, not
 * authority to run the image (security review IP-01; v3 C5). Use needs a reviewed activation record
 * bound to the exact image, platform, purpose, consumer, scan disposition and runner, and none is
 * defined or reviewed yet (v3 C17 item 12). And an image ID that equals the index digest (Docker's
 * containerd image store) is not the same thing as a manifest digest: what that store reports is
 * unverified (v3 C5, C17 item 4), so no pass rests on it.
 */
export function imageAuthorityPending(record, used) {
  const reasons = [
    `${used.image}: no reviewed activation record (v3 C5): an authenticity record is evidence, not authority to run the image (IP-01)`,
  ];
  if (used.imageId === record?.indexDigest)
    reasons.push(
      `${used.image}: Docker reports its index digest as the image ID, and what the containerd image store reports is unverified (v3 C5, C17 item 4)`
    );
  return reasons;
}

// ---------------------------------------------------------------------------------------------
// The network record (Linux)

const COUNTER = /^[A-Za-z0-9._:-]{1,64}$/;

/** Parses a network state snapshot (the file named by ORBIT_SECURITY_NETWORK_STATE). */
export function parseNetworkState(bytes) {
  const state = strictJson(bytes, 'the network state', 64 * 1024);
  const problems = fields('the network state', state, [
    'schemaVersion',
    'phase',
    'policySha256',
    'enforcement',
    'epoch',
    'counters',
    'observedAt',
  ]);
  if (problems.length) throw new Error(problems.join('; '));
  if (state.schemaVersion !== 1) throw new Error('the network state has another schema version');
  if (!['prepare', 'test', 'scanner-update', 'snyk'].includes(state.phase))
    throw new Error(`the network state's phase ${show(state.phase)} is unknown`);
  if (!matches(HEX64, state.policySha256))
    throw new Error("the network state's policy is not a sha256");
  if (typeof state.enforcement !== 'string' || !COUNTER.test(state.enforcement))
    throw new Error("the network state's enforcement is not a name");
  if (typeof state.epoch !== 'string' || !COUNTER.test(state.epoch))
    throw new Error("the network state's epoch is not a name");
  if (
    !isObject(state.counters) ||
    !Object.keys(state.counters).length ||
    Object.keys(state.counters).length > 256
  )
    throw new Error('the network state has no counters (or more than 256)');
  for (const [name, counter] of Object.entries(state.counters))
    if (
      !COUNTER.test(name) ||
      fields('a counter', counter, ['packets', 'bytes']).length ||
      !Number.isSafeInteger(counter.packets) ||
      !Number.isSafeInteger(counter.bytes) ||
      counter.packets < 0 ||
      counter.bytes < 0
    )
      throw new Error(`the network state's counter ${show(name)} is malformed`);
  if (!isTime(state.observedAt))
    throw new Error("the network state's observedAt is not a UTC time");
  return state;
}

/**
 * Problems with the network record of one test stage: the snapshots read right before and after
 * it ({ bytes, readAt }) and the reviewed policy record (`<git common dir>/orbit-security/
 * network-policy/<policy sha256>.json`: { schemaVersion, sha256, reviewer, reference, reviewedAt }).
 * The policy in force was the reviewed one, enforced outside the guest, in the test phase, with the
 * same counters (none lower) from before the stage started to after it finished.
 */
export function networkProblems({ stage, before, after, policy }) {
  const where = `the network record of ${stage.name}`;
  const problems = [];
  let start, end;
  try {
    start = parseNetworkState(before.bytes);
    end = parseNetworkState(after.bytes);
  } catch (error) {
    return [`${where}: ${error.message}`];
  }
  for (const [label, state] of [
    ['before', start],
    ['after', end],
  ]) {
    if (state.phase !== 'test')
      problems.push(`${where}: the ${label} phase is ${state.phase}, not test`);
    if (state.enforcement !== 'outside-guest')
      problems.push(
        `${where}: the ${label} enforcement is ${state.enforcement}, not outside-guest`
      );
  }
  if (start.policySha256 !== end.policySha256)
    problems.push(`${where}: the policy changed during it`);
  if (start.epoch !== end.epoch) problems.push(`${where}: the counters were reset during it`);
  const names = Object.keys(start.counters).sort();
  if (names.join('\n') !== Object.keys(end.counters).sort().join('\n'))
    problems.push(`${where}: the counters before and after differ`);
  else
    for (const name of names)
      if (
        end.counters[name].packets < start.counters[name].packets ||
        end.counters[name].bytes < start.counters[name].bytes
      )
        problems.push(`${where}: the counter ${name} went down`);
  const at = value => Date.parse(value);
  if (!isTime(before.readAt) || !isTime(after.readAt))
    problems.push(`${where}: a snapshot has no time it was read`);
  else {
    if (!(at(start.observedAt) <= at(before.readAt) && at(before.readAt) <= at(stage.started)))
      problems.push(`${where}: the before snapshot was not observed before the stage started`);
    if (!(at(stage.finished) <= at(end.observedAt) && at(end.observedAt) <= at(after.readAt)))
      problems.push(`${where}: the after snapshot was not observed after the stage finished`);
  }
  let reviewed;
  try {
    reviewed = strictJson(policy, 'the network policy record', 64 * 1024);
  } catch (error) {
    return [...problems, `${where}: ${error.message}`];
  }
  const policyProblems = fields('the network policy record', reviewed, [
    'schemaVersion',
    'sha256',
    'reviewer',
    'reference',
    'reviewedAt',
  ]);
  if (policyProblems.length)
    return [...problems, ...policyProblems.map(item => `${where}: ${item}`)];
  if (
    reviewed.schemaVersion !== 1 ||
    reviewed.sha256 !== start.policySha256 ||
    !text(reviewed.reviewer) ||
    !text(reviewed.reference) ||
    !isTime(reviewed.reviewedAt)
  )
    problems.push(`${where}: the policy in force has no reviewed policy record`);
  return problems;
}

// ---------------------------------------------------------------------------------------------
// The checks of a run's platform evidence

/** The candidate's test files: every tracked file the gate's test glob names. */
export const candidateTestFiles = files =>
  files
    .map(({ file }) => file)
    .filter(file => file.startsWith('test/') && file.endsWith('.test.mjs'))
    .sort();

/**
 * The coverage of one test stage, over its TAP log and its sealed records: checkCoverage of the
 * stage's run on its runtime, with its run code, and checkContainerEvidence of the container runs
 * it hosts. Returns { problems, coverage, container, records }: `records` are the records the
 * stage wrote (the container records among them, for the image check).
 */
export function stageCoverage({
  manifest,
  manifestSha256,
  runId,
  runtime,
  tap,
  pack,
  nonce,
  allFiles,
}) {
  return withUnpackedRecords(pack, folder => {
    const read = readRecords(folder);
    const common = { manifest, manifestSha256, runId, runtime, records: read.records, nonce };
    const run = checkCoverage({
      ...common,
      tap,
      files: manifest.runs[runId]?.files === 'all' ? allFiles : undefined,
      allFiles,
    });
    const container = checkContainerEvidence({ ...common, directory: folder });
    return {
      problems: [...read.problems, ...run.problems, ...container.problems],
      coverage: run.coverage,
      container: container.evidence,
      totals: run.totals,
      records: read.records,
    };
  });
}

/**
 * The runtimes (majors) run `runId` of `manifest` needs that none of `versions` (the Node
 * versions its test stages ran) is: a gate run started on Node 24 runs one test stage, and a run
 * that needs Node 26 too is then incomplete.
 */
export function runtimeGaps(manifest, runId, versions) {
  const tested = new Set(versions.map(major).filter(Boolean));
  return (manifest.runs[runId]?.runtimes ?? []).filter(runtime => !tested.has(runtime));
}

/**
 * The reviewed Node release keys a run sealed with its runtime-identity stage (`releaseKeys`
 * names the file), or null when it sealed none. Throws when the sealed copy is malformed.
 */
function sealedReleaseKeys(identity, get, has) {
  if (identity?.releaseKeys === undefined) return null;
  if (typeof identity.releaseKeys !== 'string' || !has(identity.releaseKeys))
    throw new Error('runtime-identity names reviewed release keys it did not seal');
  return parseReleaseKeys(get(identity.releaseKeys));
}

// ---------------------------------------------------------------------------------------------
// The order of a run's stages (GATE-CONTRACT v5 C23 order rules; v5 change 19 as the maintainer
// confirmed it in GATE-CONTRACT-v5-change19-decision.txt, sha256 aa2d5863…)
//
// This draft runs phases N and O as one local run, so one record holds the stages of both. Each
// rule below is v5's, for the phase its catalog array places the stages in, and each is judged on
// the stages' recorded intervals: a start and an end, present and well formed, inside the record's
// own window, the end not before the start. A stage a rule names that has no such interval breaks
// the rule. "A before B" means A ends no later than B starts (an inclusive handoff, as v5 change 18
// says for the T8 stages) and A is recorded before B. A stage's place in a catalog array orders
// nothing: only these rules order stages (v5 C23). A rule whose stages a run does not record has
// nothing to order; their absence is the catalog's to judge.
//
// In v5 the end of phase N orders every N stage before every O stage. This record has no such
// boundary, so the rules that v5 gets from it are stated here as order rules: platform-manifest and
// candidate-policy, N's trusted static checks, end before every stage that executes candidate code
// or builds an image (the lints, the npm script stages, both builds and the test stages, whose
// tests build images with TEST_REQUIRE including docker). Not judged here, because this draft
// makes no record of them (pending): each build's pre-build authority before its RUN steps, its
// result record sealed and verified before any use, systemd-test-image verifying its own result
// (v5 C5, C17 item 12), and the trusted bootstrap's check before any stage (v5 C1, C23).

/**
 * The candidate-controlled build stages of the catalog: the two image builds (v5 C3, C5). The test
 * stages also run candidate-controlled builds in this draft (testStageBuilds), and are ordered as
 * stages that execute candidate code.
 */
export const candidateBuildStages = Object.freeze(['container-build', 'systemd-test-image']);

/**
 * The stages of phase O, besides the test stages (by their prefix), that execute candidate code:
 * the two lints, which must be the first, and the npm stages that run the candidate's scripts
 * (v5 C3). `dependencies-install` (`npm ci --ignore-scripts`) runs no candidate script.
 */
export const candidateCodeStages = Object.freeze([
  'sql-lint',
  'import-lint',
  'format',
  'syntax-manifest',
  'documentation',
]);

/**
 * The stages that build, run or scan an image, besides the test stages (the T8 driver runs the T8
 * image in them): `image-approval` comes before each (v5 C3, C23 N).
 */
export const imageUseStages = Object.freeze([
  'container-build',
  'systemd-test-image',
  'source-analysis',
  'container-vulnerabilities',
  'container-sbom',
]);

const T8_N_STAGES = ['t8-image-identity', 't8-image-authenticity'];
const CHANGE19 =
  'platform-manifest ends before every candidate-controlled build starts, so that F takes the companion profiles from a judgment made before any candidate code ran on the VM (v5 C17 item 12, C23 N, change 19: a stricter changed requirement, confirmed by the maintainer decision GATE-CONTRACT-v5-change19-decision.txt)';
const BEFORE_CANDIDATE_CODE =
  'platform-manifest ends before any stage that executes candidate code starts (sql-lint, import-lint, the npm script stages and the test stages, whose tests also build images), so that F takes the companion profiles from a judgment made before any candidate code ran on the VM (v5 C23 Rules and change 19; in v5 the end of phase N orders it, and this one-record draft has no phase boundary)';
const POLICY_FIRST =
  'candidate-policy, a trusted static check of phase N, ends before every candidate-controlled build and every stage that executes candidate code starts (v5 C3, C4, C5; in v5 the end of phase N orders it, and this one-record draft has no phase boundary)';
/**
 * Why each test stage of a run stays pending although nothing in it is wrong: every test stage runs
 * with the gate's TEST_REQUIRE (testRequire above), and while that includes docker the candidate's
 * tests may build images, as test/installer/docker.test.mjs does (the candidate's image, and a
 * FROM scratch context), with no pre-build authority record for any of those builds. v5 C5 (changes
 * 3 and 15) makes every stage that builds an image pending and blocking until that record exists,
 * and the maintainer's answer 014104 item 1 settles that such builds must not start at all: the gate
 * withholds every test stage before dispatch while that authority is missing
 * (scripts/security-dispatch.mjs, `test-image-builds`), and a withheld stage is pending
 * (withheldStage). This reason is for a test stage that did run, which is possible only with an
 * authority given, and it still stays pending: no producer of that authority is qualified.
 */
export const testStageBuilds = testRequire.split(',').includes('docker')
  ? "its tests ran with TEST_REQUIRE including docker, so the candidate's tests may build images (test/installer/docker.test.mjs builds the candidate's own image and a FROM scratch context), and no such build has a pre-build authority record (v5 C5 changes 3 and 15; C17 item 12): the stage stays pending, never a pass"
  : null;
const GDR3_01 =
  't8-image-identity ends before t8-image-authenticity starts, judged on both valid recorded intervals; the handoff is inclusive, and any earlier start is an overlap, however short (v5 C23 N, change 18; GDR3-01)';

/** The window of a record: { start, end } from its own valid times, or null. */
function recordWindow(record) {
  if (!isTime(record?.started) || !isTime(record?.finished)) return null;
  const start = Date.parse(record.started),
    end = Date.parse(record.finished);
  return end < start ? null : { start, end };
}

/** The recorded interval of a stage inside `window`: { start, end }, or { problem }. */
function stageInterval(stage, window) {
  if (!isTime(stage?.started) || !isTime(stage?.finished))
    return { problem: 'no recorded start and end, present and well formed' };
  const start = Date.parse(stage.started),
    end = Date.parse(stage.finished);
  if (end < start) return { problem: 'an end before its start' };
  if (!window)
    return { problem: "no record window to lie in (the record's own times are not valid)" };
  if (start < window.start || end > window.end)
    return { problem: "an interval outside its record's window" };
  return { start, end };
}

/**
 * A checker of order rules over one record's stages. `before(a, b, why)`: a ends no later than b
 * starts, and a is recorded before b. `follows(a, b, why)`: b is recorded right after a, starts no
 * earlier than a ends, and no other stage starts between them. `last(a, why)`: a is recorded last
 * and starts no earlier than every other stage ends. Each problem names the rule it breaks.
 */
function orderChecker(record) {
  const stages = Array.isArray(record?.stages) ? record.stages : [];
  const window = recordWindow(record);
  const index = new Map();
  stages.forEach((stage, position) => {
    if (typeof stage?.name === 'string' && !index.has(stage.name)) index.set(stage.name, position);
  });
  const intervals = new Map();
  const interval = name => {
    if (!intervals.has(name)) intervals.set(name, stageInterval(stages[index.get(name)], window));
    return intervals.get(name);
  };
  const problems = [];
  const invalid = new Set();
  // Both stages need a valid interval; each one without is reported once, as breaking the rule.
  const valid = (names, why) => {
    let ok = true;
    for (const name of names) {
      const found = interval(name);
      if (!found.problem) continue;
      ok = false;
      if (!invalid.has(name)) {
        invalid.add(name);
        problems.push(
          `${name} has ${found.problem}, so it breaks the order rule that ${why} (v5 C12, C23)`
        );
      }
    }
    return ok;
  };
  const has = name => index.has(name);
  return {
    stages,
    problems,
    has,
    before(a, b, why) {
      if (!has(a) || !has(b) || !valid([a, b], why)) return;
      if (index.get(a) > index.get(b) || interval(a).end > interval(b).start)
        problems.push(`${a} must end before ${b} starts: ${why}`);
    },
    follows(a, b, why) {
      if (!has(a) || !has(b) || !valid([a, b], why)) return;
      const end = interval(a).end,
        start = interval(b).start;
      const between = stages.some((stage, position) => {
        if (position === index.get(a) || position === index.get(b)) return false;
        if (typeof stage?.name !== 'string' || index.get(stage.name) !== position) return false;
        const other = interval(stage.name);
        return !other.problem && other.start > end && other.start < start;
      });
      if (index.get(b) !== index.get(a) + 1 || start < end || between)
        problems.push(`${b} must directly follow ${a}: ${why}`);
    },
    last(a, why) {
      if (!has(a) || !valid([a], why)) return;
      const start = interval(a).start;
      const later = stages.some((stage, position) => {
        if (position === index.get(a) || typeof stage?.name !== 'string') return false;
        const other = stageInterval(stage, window);
        return !other.problem && other.end > start;
      });
      if (index.get(a) !== stages.length - 1 || later)
        problems.push(`${a} must be the last stage: ${why}`);
    },
  };
}

/**
 * Problems with the order of the T8 image stages in a run (v5 C3, C5, C23; GDR3-01): in N,
 * t8-image-identity ends before t8-image-authenticity starts (an inclusive handoff, judged on both
 * stages' valid recorded intervals, whatever order the record lists them in), and both end before
 * container-build, systemd-test-image or any other candidate-controlled build instruction starts,
 * and so before any candidate code runs on the VM (the lints, the npm script stages and the test
 * stages, which also run builds); across N and O, both end before t8-image-activation starts,
 * which binds them; in O, t8-image-activation ends before sql-lint, import-lint, every other stage
 * that executes candidate code and the first use of the T8 image (the first test stage, `prefix`)
 * starts. A companion run that hosts T8 records the T8 stages before its own test stages. These
 * hold whether or not the record has a t8-image-activation stage (whose absence the catalog
 * refuses).
 */
export function t8OrderProblems(record, prefix) {
  const check = orderChecker(record);
  const tests = check.stages
    .map(stage => stage?.name)
    .filter(name => typeof name === 'string' && name.startsWith(prefix));
  check.before('t8-image-identity', 't8-image-authenticity', GDR3_01);
  for (const t8 of T8_N_STAGES) {
    for (const build of candidateBuildStages)
      check.before(
        t8,
        build,
        'the T8 image identity and authenticity end before every candidate-controlled build instruction starts (v5 C3, C5, C23 N, change 2; GCV4-01)'
      );
    for (const later of [...candidateCodeStages, ...tests])
      check.before(
        t8,
        later,
        'the T8 image identity and authenticity end before any candidate code runs on the VM and before the first use of the T8 image (v5 C3, C5, C23, change 2)'
      );
    check.before(
      t8,
      't8-image-activation',
      "N's T8 identity and authenticity records exist before O's t8-image-activation, which binds them (v5 C23 across N and O)"
    );
  }
  for (const later of [...candidateCodeStages, ...tests])
    check.before(
      't8-image-activation',
      later,
      't8-image-activation ends before sql-lint, import-lint, every other stage that executes candidate code and the first use of the T8 image start (v5 C3, C5, C23 O, changes 4 and 20)'
    );
  return check.problems;
}

/**
 * Problems with the order of every stage v5's C23 order rules name, in a gate run (`prefix`
 * full-tests-: the linux-full profile's N and O stages, held in one local record) or a companion
 * run (`prefix` platform-tests-: the darwin-platform rules, which v5 proposes by analogy), each on
 * the stages' valid recorded intervals. The T8 rules are t8OrderProblems'. In a gate run,
 * platform-manifest (change 19) and candidate-policy also end before every stage that executes
 * candidate code or builds an image, which v5's phase boundary would order (above). Not judged
 * here, because this draft makes no record of them (pending, v5 C1, C5, C17 item 12): each build's
 * pre-build authority before its RUN steps, its result record sealed and verified before use,
 * systemd-test-image verifying its own result, and the trusted bootstrap's check before any stage.
 * Neither catalog build starts in this draft (scripts/security-gate.mjs); the test stages' own
 * image builds stay pending (testStageBuilds).
 */
export function orderProblems(record, { prefix }) {
  const check = orderChecker(record);
  const tests = check.stages
    .map(stage => stage?.name)
    .filter(name => typeof name === 'string' && name.startsWith(prefix));
  const coverage = tests.map(test => [test, `platform-coverage-${test.slice(prefix.length)}`]);
  const lastly =
    'candidate-unchanged is the last stage (v5 C23 N and O; darwin-platform by analogy)';
  if (prefix === 'full-tests-') {
    // N
    for (const first of ['candidate-policy', 'platform-manifest', 'pristine-copy'])
      check.before(
        first,
        'dependencies-install',
        'candidate-policy, platform-manifest and pristine-copy come before dependencies-install (v5 C3, C23 N)'
      );
    for (const use of [...imageUseStages, ...tests])
      check.before(
        'image-approval',
        use,
        'image-approval comes before container-build, systemd-test-image and any other build, run or scan of an image (v5 C3, C23 N)'
      );
    // Change 19, against both catalog builds and against every stage that executes candidate code
    // (the test stages run image builds too); candidate-policy likewise (v5 C3, C4).
    for (const build of candidateBuildStages) check.before('platform-manifest', build, CHANGE19);
    for (const later of [...candidateCodeStages, ...tests])
      check.before('platform-manifest', later, BEFORE_CANDIDATE_CODE);
    for (const later of [...candidateBuildStages, ...candidateCodeStages, ...tests])
      check.before('candidate-policy', later, POLICY_FIRST);
    check.follows(
      'container-build',
      'container-identity',
      'container-identity directly follows container-build (v5 C3, C23 N)'
    );
    // O
    for (const lint of ['sql-lint', 'import-lint'])
      for (const later of [...candidateCodeStages.slice(2), ...tests])
        check.before(
          lint,
          later,
          'sql-lint and import-lint are the first stages that execute candidate code (v5 C3, C23 O)'
        );
    for (const first of ['test-host', 'runtime-identity'])
      for (const test of tests)
        check.before(
          first,
          test,
          'test-host and runtime-identity come before the full-test stages (v5 C23 O)'
        );
  } else
    for (const first of ['candidate-policy', 'platform-manifest'])
      for (const test of tests)
        check.before(
          first,
          test,
          'candidate-policy and platform-manifest come before any test stage (v5 C23 darwin-platform, proposed by analogy)'
        );
  for (const [test, stage] of coverage)
    check.follows(
      test,
      stage,
      "each coverage stage directly follows its runtime's test stage (v5 C23 O; darwin-platform by analogy)"
    );
  check.last('candidate-unchanged', lastly);
  return [...t8OrderProblems(record, prefix), ...check.problems];
}

// ---------------------------------------------------------------------------------------------
// The T8 image's activation binding (v5 C5, C14, C23)
//
// t8-image-activation binds the image O selects for T8 to N's sealed t8-image-identity and
// t8-image-authenticity records (and, for a locally produced T8-related image, its sealed result
// record) under the same run, candidate, gate identity, catalog, platform, consumer and purpose.
// It is a binding check, not a second authenticity claim. The exact form of its record is pending
// (v5 C17 item 12) and no producer is qualified, so the stage is always pending and F never passes
// on it. The form below is gate-draft-r4's proposal, for the maintainer: the gate writes it and F rebuilds
// it from the sealed run and requires the two to be equal.

/** The sealed file of the activation's binding, and the proposal's fixed values. */
export const activationBindingFile = 't8-image-activation.json';
export const ACTIVATION_PROPOSAL = Object.freeze({
  version: 1,
  consumer: 't8-driver',
  purpose: 't8-container-tests',
  form: 'gate-draft-r4 proposal: the binding record of t8-image-activation (v5 C5, C14, C17 item 12); not reviewed, and no producer is qualified',
});
/** What a t8-image-activation stage record may hold: a binding, never authenticity evidence. */
const ACTIVATION_FIELDS = ['name', 'started', 'finished', 'status', 'reason', 'error', 'binding'];

/**
 * The binding t8-image-activation records for a run (`name`: the run folder's name; `record`: the
 * run record; `get`/`has`: its sealed files), as the gate writes it and F rebuilds it. Throws when
 * N's T8 records are missing or unreadable. `result` is null: this draft builds no image for T8
 * to use (its two catalog builds are pending and never start, and the T8 driver uses the pinned
 * images), so no result record exists to bind; the
 * run nonce of v5 C14 is the controller's, which this local run does not have (pending).
 */
export function activationBinding({ name, record, get, has, catalogSha256 }) {
  const stages = new Map(
    (Array.isArray(record?.stages) ? record.stages : []).map(stage => [stage?.name, stage])
  );
  const identity = stages.get('t8-image-identity');
  const authenticity = stages.get('t8-image-authenticity');
  if (!identity || typeof identity.log !== 'string' || !has(identity.log))
    throw new Error('t8-image-identity sealed no observation of the T8 images');
  if (!Array.isArray(identity.images) || !identity.images.length)
    throw new Error('t8-image-identity names no T8 image');
  if (!authenticity || !Array.isArray(authenticity.records))
    throw new Error('t8-image-authenticity sealed no records');
  const evidence = files =>
    files.map(file => {
      if (typeof file !== 'string' || !has(file))
        throw new Error(`a bound T8 record ${show(file)} is not sealed with the run`);
      return { path: file, sha256: sha256(get(file)) };
    });
  const observed = parseImageInspection(get(identity.log).toString('utf8'), identity.images);
  const gate = gateIdentityStage(stages.get('gate-identity'), { catalogSha256 });
  return {
    candidateIdentitySha256: record.candidateIdentitySha256 ?? null,
    catalogSha256,
    consumer: ACTIVATION_PROPOSAL.consumer,
    form: ACTIVATION_PROPOSAL.form,
    gateIdentity: gate.binding,
    images: observed.map(item => ({
      image: item.image,
      imageId: item.id,
      platform: item.platform,
    })),
    platform: { architecture: record.host?.arch ?? null, os: record.host?.platform ?? null },
    purpose: ACTIVATION_PROPOSAL.purpose,
    records: {
      authenticity: {
        evidence: evidence(authenticity.records.map(item => item?.file)),
        finished: authenticity.finished ?? null,
        stage: 't8-image-authenticity',
        started: authenticity.started ?? null,
      },
      identity: {
        evidence: evidence([identity.log]),
        finished: identity.finished ?? null,
        stage: 't8-image-identity',
        started: identity.started ?? null,
      },
    },
    result: null,
    run: name,
    version: ACTIVATION_PROPOSAL.version,
  };
}

/**
 * F's reconciliation of the T8 image's records within `image-approvals` (v5 C14 change 5): O's
 * t8-image-activation must bind exactly N's sealed t8-image-identity and t8-image-authenticity
 * records of this run, with the same run, candidate identity, gate identity (version 3), catalog,
 * platform, consumer, purpose and image identity (activationBinding, rebuilt here from the sealed
 * run), records that themselves show identity ending before authenticity starts on valid
 * intervals (v5 change 18), and no result record. A run that hosts no T8 image binds nothing.
 * Returns the problems; none still leaves the stage pending (the record form is a proposal).
 */
export function t8ActivationProblems(run, { manifest, runId, catalogSha256 }) {
  const { record, get, has } = run;
  const activation = (Array.isArray(record?.stages) ? record.stages : []).find(
    stage => stage?.name === 't8-image-activation'
  );
  if (!activation) return [];
  const problems = [];
  for (const key of Object.keys(activation))
    if (!ACTIVATION_FIELDS.includes(key))
      problems.push(
        `t8-image-activation records ${show(key)}: it is a binding check, not a second authenticity claim or a stage that runs anything (v5 C5)`
      );
  if (!hostsImages(manifest, runId)) {
    if (own(activation, 'binding'))
      problems.push('t8-image-activation binds T8 records, but the run hosts no pinned T8 image');
    return problems;
  }
  if (typeof activation.binding !== 'string' || !has(activation.binding)) {
    // When t8-image-identity was withheld before dispatch (no docker image inspect while its stage
    // policy, endpoint or operational hold is unmet; maintainer note 014104), there is no observation to
    // bind: a pending activation that binds nothing is then all there can be, and it stays pending.
    const identity = (Array.isArray(record?.stages) ? record.stages : []).find(
      stage => stage?.name === 't8-image-identity'
    );
    if (withheldStage(identity) && activation.status === 'pending' && !own(activation, 'binding'))
      return problems;
    return [...problems, "t8-image-activation sealed no binding of N's T8 records (v5 C5, C14)"];
  }
  let sealed, expected;
  try {
    sealed = strictJson(get(activation.binding), 'the t8-image-activation binding');
    expected = activationBinding({ name: run.name, record, get, has, catalogSha256 });
  } catch (error) {
    return [...problems, `t8-image-activation: ${error.message}`];
  }
  if (!isObject(sealed)) return [...problems, 't8-image-activation: its binding is not an object'];
  // Exactly the members of the binding, each equal: a member it lacks is not taken as null, and a
  // member it has no place for is refused even when its value is null.
  for (const key of new Set([...Object.keys(sealed), ...Object.keys(expected)]))
    if (!own(expected, key))
      problems.push(
        `t8-image-activation's binding holds ${show(key)}, which the binding has no place for`
      );
    else if (!own(sealed, key))
      problems.push(
        `t8-image-activation's binding lacks ${key}: an absent member is not taken as null (v5 C14)`
      );
    else if (canonicalJson(sealed[key]) !== canonicalJson(expected[key]))
      problems.push(
        `t8-image-activation binds another ${key} than this run's: ${show(sealed[key])}, not ${show(expected[key])} (v5 C14: the same run, candidate, gate identity, catalog, platform, consumer, purpose and image identity, and exactly N's sealed records)`
      );
  // The records it binds must show the succession of v5 change 18 on valid intervals.
  const window = recordWindow(record);
  const bound = sealed.records ?? {};
  const identity = stageInterval(bound.identity, window);
  const authenticity = stageInterval(bound.authenticity, window);
  if (identity.problem || authenticity.problem || identity.end > authenticity.start)
    problems.push(
      `t8-image-activation binds N records that do not show ${GDR3_01}: F refuses the activation (v5 C23 across N and O)`
    );
  return problems;
}

/** The test stages of a run: `prefix` is full-tests- (a gate run) or platform-tests- (companion). */
const testStages = (record, prefix) =>
  record.stages.filter(stage => typeof stage.name === 'string' && stage.name.startsWith(prefix));

/** The slot of a test stage (current-runtime or minimum-runtime). */
const slotOf = (name, prefix) => name.slice(prefix.length);

/** What a dispatched command leaves on its stage record, and a withheld stage never has. */
const DISPATCH_TRACES = [
  'command',
  'log',
  'exit',
  'signal',
  'error',
  'tests',
  'records',
  'runtime',
  'platformRun',
  'images',
  'snapshots',
  'binding',
];
/**
 * Whether a stage record is that of a stage the gate withheld before dispatch
 * (scripts/security-dispatch.mjs: the pre-dispatch barrier was closed, an authority it needs is
 * missing, or, for a test stage, test-host or runtime-identity had not passed or did not apply to
 * it): pending, with a reason, and with nothing a dispatched command leaves. Such a stage ran
 * nothing, so it is pending, never a pass, and there is nothing of it to check.
 */
export const withheldStage = stage =>
  isObject(stage) &&
  stage.status === 'pending' &&
  text(stage.reason) &&
  DISPATCH_TRACES.every(key => !own(stage, key));

/**
 * Checks the platform evidence of one sealed run (`run`: { name, record, files, get, has,
 * runSha256 } from security-finalization.mjs) against the candidate's judged manifest: its test
 * stages (`prefix`), their coverage of run `runId`, each runtime's identity, the T8 images and, on
 * Linux, the network record (diagnostic: it can refuse, never authorise isolation; v3 C13).
 * Returns { stages, pending }: the run's summary, and why its evidence stays pending although
 * nothing in it is wrong (each test stage while its tests may build images with no pre-build
 * authority record, testStageBuilds; each test stage the gate withheld before dispatch, with what
 * depends on it; the T8 images' missing activation records). Throws with the first problems.
 */
export function checkRunPlatform(run, { manifest, manifestSha256, runId, prefix, allFiles }) {
  const { record, get, has } = run;
  const problems = [];
  const stages = new Map(record.stages.map(stage => [stage.name, stage]));
  // Why this run's evidence stays pending although nothing in it is wrong, by stage.
  const pending = [];
  // A test stage withheld before dispatch ran nothing: it is pending (its reason says why), and its
  // coverage, runtime and network evidence do not exist to be checked (GDR4-01; maintainer note 014104 item 1).
  const withheld = testStages(record, prefix).filter(withheldStage);
  for (const stage of withheld) {
    pending.push({ stage: stage.name, reason: `${run.name}: ${stage.name}: ${stage.reason}` });
    // Nothing ran, so nothing of it can have been covered.
    const coverage = stages.get(`platform-coverage-${slotOf(stage.name, prefix)}`);
    if (coverage && coverage.status !== 'pending')
      problems.push(
        `${run.name}: platform-coverage-${slotOf(stage.name, prefix)} is ${coverage.status}, but ${stage.name} was withheld before dispatch, so there is no run to cover`
      );
  }
  const tested = testStages(record, prefix).filter(stage => !withheld.includes(stage));
  const runtimes = new Map();
  const versions = [];
  const summary = [];
  const containerRecords = [];
  const identity = stages.get('runtime-identity');
  const identities = Array.isArray(identity?.runtimes) ? identity.runtimes : [];
  let releaseKeys = null;
  try {
    releaseKeys = sealedReleaseKeys(identity, get, has);
  } catch (error) {
    problems.push(`${run.name}: ${error.message}`);
  }
  for (const stage of tested) {
    const slot = slotOf(stage.name, prefix);
    const where = `${run.name}: ${stage.name}`;
    const version = stage.runtime?.version;
    const runtime = major(version);
    if (!runtime || !matches(HEX64, stage.runtime?.sha256)) {
      problems.push(`${where} records no Node version and binary sha256`);
      continue;
    }
    if (runtimes.has(runtime)) problems.push(`${where}: Node ${runtime} is tested twice`);
    runtimes.set(runtime, stage.name);
    versions.push(version);
    const known = identities.find(item => item?.sha256 === stage.runtime.sha256);
    if (!known || known.version !== version)
      problems.push(`${where}: runtime-identity does not cover its Node binary`);
    else {
      try {
        const recordBytes = get(known.record);
        problems.push(
          ...runtimeIdentityProblems(
            strictJson(recordBytes, 'the runtime identity record'),
            {
              sha256: stage.runtime.sha256,
              version,
              platform: record.host?.platform,
              arch: record.host?.arch,
            },
            releaseKeys
          ).map(item => `${where}: ${item}`)
        );
      } catch (error) {
        problems.push(`${where}: ${error.message}`);
      }
    }
    if (
      !matches(HEX64, stage.platformRun) ||
      typeof stage.records !== 'string' ||
      !has(stage.records)
    ) {
      problems.push(`${where} has no sealed records and run code`);
      continue;
    }
    const coverageStage = stages.get(`platform-coverage-${slot}`);
    if (!coverageStage || coverageStage.status !== 'pass' || coverageStage.of !== stage.name)
      problems.push(`${where}: platform-coverage-${slot} did not pass for it`);
    let checked;
    try {
      checked = stageCoverage({
        manifest,
        manifestSha256,
        runId,
        runtime,
        tap: get(stage.log).toString('utf8'),
        pack: get(stage.records),
        nonce: stage.platformRun,
        allFiles,
      });
    } catch (error) {
      problems.push(`${where}: ${error.message}`);
      continue;
    }
    problems.push(...checked.problems.map(item => `${where}: ${item}`));
    containerRecords.push(...checked.records.filter(item => item.kind === 'container'));
    let tests;
    try {
      tests = testTotals(get(stage.log).toString('utf8'));
    } catch (error) {
      problems.push(`${where}: ${error.message}`);
    }
    if (tests && JSON.stringify(tests) !== JSON.stringify(stage.tests))
      problems.push(`${where}: its test totals disagree with its log`);
    // What the approval binds of the stage: its runtime, its own totals, its coverage map (each
    // entry required, present, absent or not run, with its TAP lines) and which runtime produced
    // each T8 container evidence it carries.
    summary.push({
      name: stage.name,
      runtime: version,
      sha256: stage.runtime.sha256,
      tests: stage.tests,
      coverage: checked.coverage,
      containers: checked.container.map(item => ({
        runtime: item.runtime,
        image: item.image,
        imageId: item.imageId,
        node: item.node,
      })),
    });
  }
  // A runtime the run needs and no test stage ran: pending when a test stage was withheld (it would
  // have run it), a problem otherwise.
  for (const runtime of runtimeGaps(manifest, runId, versions))
    if (withheld.length)
      pending.push({
        stage: withheld[0].name,
        reason: `${run.name}: run ${runId} is not tested on Node ${runtime}: its test stage was withheld before dispatch`,
      });
    else problems.push(`${run.name}: run ${runId} is not tested on Node ${runtime}`);
  // Each test stage, while its tests may build images with no pre-build authority record (v5 C5).
  if (testStageBuilds)
    for (const stage of tested)
      pending.push({ stage: stage.name, reason: `${run.name}: ${stage.name}: ${testStageBuilds}` });
  const inspection = stages.get('t8-image-identity');
  if (hostsImages(manifest, runId) && withheldStage(inspection)) {
    // The T8 image inspect was withheld before dispatch (maintainer note 014104: no real docker image
    // inspect while its stage policy, endpoint or operational hold is unmet): no identity of any T8
    // image was observed, so a T8 container record of this run names an image nobody checked.
    for (const container of containerRecords)
      problems.push(
        `${run.name}: a T8 container record names ${container.image}, but t8-image-identity was withheld before dispatch, so no identity of it was observed before candidate code ran`
      );
  } else if (hostsImages(manifest, runId)) {
    const authenticity = stages.get('t8-image-authenticity');
    try {
      if (
        !inspection?.log ||
        !Array.isArray(inspection.images) ||
        !Array.isArray(authenticity?.records)
      )
        throw new Error('the T8 image identity and authenticity stages are missing');
      const observed = parseImageInspection(
        get(inspection.log).toString('utf8'),
        inspection.images
      );
      for (const container of containerRecords) {
        const seen = observed.find(item => item.image === container.image);
        const name = seen && imageRecordName(container.image, seen.platform);
        const sealed = authenticity.records.find(
          item => item?.file === `image-authenticity-${name}`
        )?.file;
        if (!seen || !name || !sealed || !has(sealed)) {
          problems.push(`${run.name}: no sealed authenticity record of ${container.image}`);
          continue;
        }
        const imageRecord = strictJson(get(sealed), 'the image authenticity record');
        const used = { image: container.image, imageId: container.imageId };
        const found = imageAuthenticityProblems(imageRecord, used, seen);
        problems.push(...found.map(item => `${run.name}: ${item}`));
        if (!found.length)
          for (const reason of imageAuthorityPending(imageRecord, used))
            pending.push({ stage: 't8-image-authenticity', reason: `${run.name}: ${reason}` });
      }
    } catch (error) {
      problems.push(`${run.name}: ${error.message}`);
    }
  }
  const network = stages.get('network-policy');
  if (
    record.host?.platform === 'linux' &&
    !tested.length &&
    withheld.length &&
    withheldStage(network)
  )
    // No test stage ran, so no network record was taken: pending with its test stages.
    pending.push({
      stage: 'network-policy',
      reason: `${run.name}: network-policy: ${network.reason}`,
    });
  else if (record.host?.platform === 'linux') {
    try {
      if (!network || !Array.isArray(network.snapshots) || typeof network.policy !== 'string')
        throw new Error('the network-policy stage is missing');
      for (const stage of tested) {
        const snapshot = network.snapshots.find(item => item?.stage === stage.name);
        if (!snapshot) {
          problems.push(`${run.name}: ${stage.name} has no network record`);
          continue;
        }
        problems.push(
          ...networkProblems({
            stage,
            before: { bytes: get(snapshot.before.file), readAt: snapshot.before.readAt },
            after: { bytes: get(snapshot.after.file), readAt: snapshot.after.readAt },
            policy: get(network.policy),
          }).map(item => `${run.name}: ${item}`)
        );
      }
    } catch (error) {
      problems.push(`${run.name}: ${error.message}`);
    }
  }
  if (problems.length) throw new Error(problems.slice(0, 20).join('; '));
  return { stages: summary, pending };
}

/**
 * What a maintenance (B35) run must record before its test stages (GDR6-REQ-01, the security review
 * of gate-draft-r6, under the maintainer's B35 decision of 20261017T140102522864Z): test-host and
 * runtime-identity, as every other run must. B35 decides that a candidate whose history never held
 * the manifest is judged as maintenance, by the earlier gate's stage list and its own approved
 * runtimes; it gives no permission to run a runtime nobody identified.
 */
export const MAINTENANCE_TEST_PREREQUISITES = Object.freeze(['test-host', 'runtime-identity']);

/**
 * The approved B35 maintenance execution plan (GDR7-FIN-01, the security review of gate-draft-r7,
 * under the maintainer's decision 1 of 20261018T051017695655Z): every stage a maintenance run may record,
 * each bound to its execution class and to when the run must record it. It is one schema for the
 * finalizer (checkRun), the commit guard (validateFinalization) and the recorded-approval reader
 * behind --verify-commit and the reference-transaction hook (recordedApproval): the earlier gate's
 * list (requiredStages in security-finalization.mjs is its `always` part, in this order), the
 * configured Node 24 slot, 1.5's two lint stages and the two record-only stages the current gate
 * writes for a candidate with no manifest. A stage it does not name, or a record of a stage that
 * its class does not allow, is refused (maintenancePlanProblems).
 *
 * `execution` is the class:
 * - `record`: recorded without a command, a requirement the gate checks itself (the host, the
 *   runtimes, a tool version, the review) or an informational record. Nothing runs in it, so a
 *   record of it that carries a command, a log, an exit or signal, test totals, records, run code
 *   or a runtime is refused.
 * - `execute`: a gate-owned command (the snapshot, a tool query, an npm stage, a scanner, a build).
 *   Once passed it carries its command and sealed log (checkRun). It runs no test suite on a Node
 *   binary, so it carries no test totals, records, run code or runtime.
 * - `lint`: one of 1.5's lint stages, a gate-owned command over the candidate's lint sources, under
 *   the same rule as `execute`.
 * - `test`: a test execution, the candidate's tests on the Node binary of an approved `slot`. The
 *   host and runtime binding applies to every one that ran (maintenanceRuntimeProblems).
 *
 * `required` says when a run must record it: `always`; `named`, when the caller names it as a lint
 * stage the candidate needs (current.lintStages: the maintenance gate records none); `newer-node`,
 * the configured Node 24 slot, when the run's own Node (its host Node) is not Node 24 (a Node 24
 * gate runs it too, without being required to, when its configured Node 24 executable is a
 * different file: two distinct Node 24 executables); `optional`, never required.
 */
export const MAINTENANCE_PLAN = Object.freeze(
  [
    ['snapshot-clone', 'execute', 'always'],
    ['snapshot-index', 'execute', 'always'],
    ['snapshot-files', 'execute', 'always'],
    ['gitleaks-version', 'record', 'always'],
    ['trivy-version', 'record', 'always'],
    ['actionlint-version', 'record', 'always'],
    ['docker-version', 'execute', 'always'],
    ['npm-version', 'execute', 'always'],
    ['sast-rules-download', 'execute', 'always'],
    ['sast-rules-checksum', 'record', 'always'],
    ['sast-rules-extract', 'execute', 'always'],
    ['sast-image-pull', 'execute', 'always'],
    ['candidate-policy', 'record', 'always'],
    ['dependencies-install', 'execute', 'always'],
    ['format', 'execute', 'always'],
    ['syntax-manifest', 'execute', 'always'],
    ['documentation', 'execute', 'always'],
    ['dependencies-all', 'execute', 'always'],
    ['dependencies-production', 'execute', 'always'],
    ['registry-signatures', 'execute', 'always'],
    ['workflow-analysis', 'execute', 'always'],
    ['secrets-source', 'execute', 'always'],
    ['secrets-history', 'execute', 'always'],
    ['secrets-metadata', 'execute', 'always'],
    ['source-analysis', 'execute', 'always'],
    ['container-configuration', 'execute', 'always'],
    ['container-build', 'execute', 'always'],
    ['container-identity', 'execute', 'always'],
    ['container-vulnerabilities', 'execute', 'always'],
    ['container-sbom', 'execute', 'always'],
    ['scanner-database', 'execute', 'always'],
    ['systemd-test-image', 'execute', 'always'],
    ['test-host', 'record', 'always'],
    ['runtime-identity', 'record', 'always'],
    ['full-tests-current-runtime', 'test', 'always', 'current-runtime'],
    ['full-tests-minimum-runtime', 'test', 'newer-node', 'minimum-runtime'],
    ['minimum-runtime-available', 'record', 'always'],
    ['independent-review', 'record', 'always'],
    ['candidate-unchanged', 'record', 'always'],
    ['sql-lint', 'lint', 'named'],
    ['import-lint', 'lint', 'named'],
    ['gate-implementation', 'record', 'optional'],
    ['platform-manifest', 'record', 'optional'],
  ].map(([name, execution, required, slot]) =>
    Object.freeze({ name, execution, required, ...(slot ? { slot } : {}) })
  )
);
const MAINTENANCE_PLAN_STAGES = new Map(MAINTENANCE_PLAN.map(entry => [entry.name, entry]));
/** What only a stage that ran a command leaves on its record (a withheld one has none of it). */
const EXECUTION_TRACES = Object.freeze(DISPATCH_TRACES.filter(key => key !== 'error'));
/** What only a test execution leaves on its record: its totals, records, run code and runtime. */
const TEST_EXECUTION_TRACES = Object.freeze(['tests', 'records', 'platformRun', 'runtime']);
/** A name of a test stage, of a gate run (full-tests-) or of a companion run (platform-tests-). */
const TEST_STAGE_NAME = /^(?:full|platform)-tests-/;

/**
 * The record form of each execution class of the approved B35 plan (GDR7-FIN-01; the internal
 * check of gate-draft-r8 found that a step record nested in a stage's `steps` escaped the plan and
 * runtime checks, which read only a stage record's own members): the members a maintenance run's
 * stage record of that class may hold, and nothing else. Every record may hold its name, its
 * status, its recorded interval and why it is pending or blocked (`reason`, `error`). A gate-owned
 * command (`execute`) and a lint stage (`lint`) also hold their command and sealed log, their exit
 * and signal and the dispatch authority they ran under. A test slot (`test`) holds those too, and
 * what only a test execution leaves: its totals, records, run code and runtime, and the tests that
 * did not run (`unexecuted`). A stage also holds the data its own check records
 * (MAINTENANCE_STAGE_DATA). Any other member is refused (maintenancePlanProblems): `steps` above
 * all, the 1.5 gate's composite form, whose step records hold commands of their own
 * (prepared-inputs and sast-rules in scripts/security-gate.mjs), since a maintenance run records
 * each execution as its own stage of the plan, and members no producer writes, such as `argv` or
 * `exitCode`. What each member holds is closed too (MAINTENANCE_MEMBER_SCHEMAS and
 * MAINTENANCE_STAGE_DATA_SCHEMAS below; GDR8-SCHEMA-01).
 */
const RECORD_MEMBERS = ['name', 'status', 'started', 'finished', 'reason', 'error'];
const COMMAND_MEMBERS = [...RECORD_MEMBERS, 'command', 'log', 'exit', 'signal', 'authority'];
export const MAINTENANCE_RECORD_FORMS = Object.freeze({
  record: Object.freeze(RECORD_MEMBERS),
  execute: Object.freeze(COMMAND_MEMBERS),
  lint: Object.freeze(COMMAND_MEMBERS),
  test: Object.freeze([...COMMAND_MEMBERS, ...TEST_EXECUTION_TRACES, 'unexecuted']),
});
/**
 * The data a stage of the approved B35 plan records besides its class's form, by stage: the pinned
 * Actionlint (actionlint-version's `tool`, workflow-analysis's hashes before and after it ran, or
 * the pin a pending one names as missing), the host (test-host), the runtimes and the release keys
 * (runtime-identity), the gate files (gate-implementation) and the platform judgment
 * (platform-manifest), as scripts/security-gate.mjs and the synthetic fixtures record them.
 */
export const MAINTENANCE_STAGE_DATA = Object.freeze({
  'actionlint-version': Object.freeze(['tool', 'missingPin']),
  'workflow-analysis': Object.freeze(['binarySha256', 'dependencyClosureSha256', 'missingPin']),
  'test-host': Object.freeze(['host']),
  'runtime-identity': Object.freeze(['runtimes', 'releaseKeys']),
  'gate-implementation': Object.freeze(['files']),
  'platform-manifest': Object.freeze(['judgment', 'dispositions']),
});

// The closed schema of every member a maintenance (B35) stage record may hold (GDR8-SCHEMA-01,
// the security review of gate-draft-r8; the maintainer's decision 3: unknown fields fail
// closed, a field a producer needs takes an explicit schema change with positive and negative
// evidence, and no open-ended extension object is allowed). The record forms above close each
// stage record's own members; these close what those members hold, at every depth: an object is
// exactly its listed members, each present and of its schema (no extension bag), a list holds
// only items of its item schema, and a scalar is of its type. So an unknown member nested
// anywhere is refused whatever its spelling, and so is a structured value where a scalar belongs.
// This is a PROPOSED shared producer/consumer interface (the maintainer's decision 3), not an accepted one:
// the maintenance branch's own gate must still be shown to write exactly these forms before it is
// integrated. The forms are those scripts/security-gate.mjs writes (startStage, requirement,
// withhold, testHost, runtimeOf, runtimeIdentity, unexecutedTests, testTotals, missingToolPin,
// decideAuthorities in scripts/security-dispatch.mjs) and the synthetic fixtures
// (test/helpers/security-run.mjs) record.
const schemaOf = Object.freeze;
const STRING = schemaOf({ type: 'string' });
const COUNT = schemaOf({ type: 'count' });
const INTEGER = schemaOf({ type: 'integer' });
const INTEGER_OR_NULL = schemaOf({ type: 'integer', nullable: true });
const STRING_OR_NULL = schemaOf({ type: 'string', nullable: true });
const BOOLEAN_OR_NULL = schemaOf({ type: 'boolean', nullable: true });
const oneOf = (...values) => schemaOf({ oneOf: Object.freeze(values) });
const listOf = item => schemaOf({ list: item });
const exactly = members => schemaOf({ object: Object.freeze(members) });
const BEFORE_AFTER = exactly({ before: STRING, after: STRING });
const MISSING_PIN = exactly({
  tool: STRING,
  version: STRING,
  platform: STRING,
  arch: STRING,
  record: STRING,
  evidence: listOf(STRING),
});
/** The schema of each member of the record forms (MAINTENANCE_RECORD_FORMS), by member. */
export const MAINTENANCE_MEMBER_SCHEMAS = Object.freeze({
  name: STRING,
  status: oneOf('pass', 'blocked', 'pending'),
  started: STRING,
  finished: STRING,
  reason: STRING,
  error: STRING,
  command: listOf(STRING),
  log: STRING,
  exit: INTEGER_OR_NULL,
  signal: STRING_OR_NULL,
  authority: listOf(exactly({ purpose: STRING, reference: STRING, source: STRING })),
  tests: exactly({
    tests: COUNT,
    pass: COUNT,
    fail: COUNT,
    cancelled: COUNT,
    skipped: COUNT,
    todo: COUNT,
  }),
  records: STRING,
  platformRun: STRING,
  runtime: exactly({ path: STRING, version: STRING, sha256: STRING }),
  unexecuted: exactly({
    count: COUNT,
    tests: listOf(exactly({ test: STRING, directive: oneOf('SKIP', 'TODO'), reason: STRING })),
  }),
});
/** The schema of each stage's own data (MAINTENANCE_STAGE_DATA), by stage and member. */
export const MAINTENANCE_STAGE_DATA_SCHEMAS = Object.freeze({
  'actionlint-version': Object.freeze({
    tool: exactly({
      path: STRING,
      sha256: STRING,
      version: STRING,
      record: STRING,
      dependencyClosureSha256: STRING,
    }),
    missingPin: MISSING_PIN,
  }),
  'workflow-analysis': Object.freeze({
    binarySha256: BEFORE_AFTER,
    dependencyClosureSha256: BEFORE_AFTER,
    missingPin: MISSING_PIN,
  }),
  'test-host': Object.freeze({
    host: exactly({ platform: STRING, uid: INTEGER, setfacl: BOOLEAN_OR_NULL }),
  }),
  'runtime-identity': Object.freeze({
    runtimes: listOf(exactly({ path: STRING, version: STRING, sha256: STRING, record: STRING })),
    releaseKeys: STRING,
  }),
  'gate-implementation': Object.freeze({ files: listOf(STRING) }),
  'platform-manifest': Object.freeze({ judgment: STRING, dispositions: STRING }),
});
/** How many schema problems one stage record reports before it stops (it is refused anyway). */
const SCHEMA_PROBLEM_LIMIT = 20;
const SCALAR_TYPES = Object.freeze({
  string: value => typeof value === 'string',
  count: value => Number.isSafeInteger(value) && value >= 0,
  integer: value => Number.isSafeInteger(value),
  boolean: value => typeof value === 'boolean',
});
const SCALAR_NAMES = Object.freeze({
  string: 'a string',
  count: 'a nonnegative integer',
  integer: 'an integer',
  boolean: 'true or false',
});
const describeValue = value =>
  Array.isArray(value) ? 'a list' : isObject(value) ? 'an object' : show(value);

/**
 * Adds to `problems` why `value` (at `where`) is not of `schema`, without recursion beyond the
 * schema's own depth: the members of an unknown object are never read, so a deep or large
 * unknown value costs one problem. Stops at SCHEMA_PROBLEM_LIMIT.
 */
function schemaProblems(value, schema, where, problems) {
  if (problems.length >= SCHEMA_PROBLEM_LIMIT) return;
  if (schema.object) {
    if (!isObject(value)) {
      problems.push(
        `${where} is ${describeValue(value)}, not an object of exactly ${Object.keys(schema.object).join(', ')}`
      );
      return;
    }
    for (const key of Object.keys(value)) {
      if (problems.length >= SCHEMA_PROBLEM_LIMIT) return;
      if (!own(schema.object, key))
        problems.push(`${where} holds ${show(key)}, which its closed schema does not have`);
    }
    for (const [key, item] of Object.entries(schema.object)) {
      if (problems.length >= SCHEMA_PROBLEM_LIMIT) return;
      if (!own(value, key))
        problems.push(`${where} lacks ${key}, which its closed schema requires`);
      else schemaProblems(value[key], item, `${where}.${key}`, problems);
    }
    return;
  }
  if (schema.list) {
    if (!Array.isArray(value)) {
      problems.push(`${where} is ${describeValue(value)}, not a list`);
      return;
    }
    for (let index = 0; index < value.length && problems.length < SCHEMA_PROBLEM_LIMIT; index++)
      schemaProblems(value[index], schema.list, `${where}[${index}]`, problems);
    return;
  }
  if (schema.oneOf) {
    if (!schema.oneOf.includes(value))
      problems.push(
        `${where} is ${describeValue(value)}, not one of ${schema.oneOf.map(show).join(', ')}`
      );
    return;
  }
  if (!SCALAR_TYPES[schema.type](value) && !(schema.nullable && value === null))
    problems.push(
      `${where} is ${describeValue(value)}, not ${SCALAR_NAMES[schema.type]}${schema.nullable ? ' or null' : ''}`
    );
}

/**
 * The closed-schema problems of one maintenance (B35) stage record `stage` (GDR8-SCHEMA-01): each
 * member its class's record form and its own data permit, judged against its schema at every depth
 * (MAINTENANCE_MEMBER_SCHEMAS, MAINTENANCE_STAGE_DATA_SCHEMAS). A member outside the form, a stage
 * outside the plan and a nameless record are maintenancePlanProblems' to name, not this function's.
 * Each problem names where it is (`test-host.host`, `runtime-identity.runtimes[0]`).
 */
export function maintenanceStageSchemaProblems(stage) {
  if (!isObject(stage) || typeof stage.name !== 'string') return [];
  const entry = MAINTENANCE_PLAN_STAGES.get(stage.name);
  if (!entry) return [];
  const data = MAINTENANCE_STAGE_DATA_SCHEMAS[stage.name] ?? {};
  const problems = [];
  for (const key of Object.keys(stage)) {
    const schema = MAINTENANCE_RECORD_FORMS[entry.execution].includes(key)
      ? MAINTENANCE_MEMBER_SCHEMAS[key]
      : own(data, key)
        ? data[key]
        : null;
    if (schema) schemaProblems(stage[key], schema, `${stage.name}.${key}`, problems);
  }
  return problems.map(item => `${item} (GDR8-SCHEMA-01)`);
}
/** What makes an object a stage record, or a list of them, wherever it is nested. */
const STAGE_RECORD_MEMBERS = Object.freeze([
  'command',
  'log',
  'exit',
  'signal',
  'steps',
  'stages',
  'records',
  'platformRun',
  'runtime',
]);
/** How many nested values a stage record may hold before it is refused as too deep to judge. */
const NESTED_LIMIT = 10000;

/**
 * The records nested anywhere inside the stage record `stage` (below its own members) that are
 * shaped as stage records: an object with a command, log, exit, signal, steps, stages, records, run
 * code or runtime of its own, or with both a name and a status. Each is returned with where it is
 * (`steps[0]`, `host.probe`). A test stage's own runtime, totals and authority, test-host's host,
 * runtime-identity's runtimes and every other datum the plan's record forms hold are none of these.
 * Breadth first and without recursion, so a deep record cannot exhaust the stack; past NESTED_LIMIT
 * nested values it stops, and an entry with no record says so.
 */
function nestedStageRecords(stage) {
  const found = [];
  const queue = Object.entries(stage);
  for (let index = 0; index < queue.length; index++) {
    if (index >= NESTED_LIMIT) {
      found.push({ where: queue[index][0], record: null });
      break;
    }
    const [where, value] = queue[index];
    if (value === null || typeof value !== 'object') continue;
    const list = Array.isArray(value);
    if (
      !list &&
      (STAGE_RECORD_MEMBERS.some(key => own(value, key)) ||
        (own(value, 'name') && own(value, 'status')))
    )
      found.push({ where, record: value });
    for (const [key, item] of Object.entries(value))
      queue.push([list ? `${where}[${key}]` : `${where}.${key}`, item]);
  }
  return found;
}

/**
 * The stages of the approved B35 plan (MAINTENANCE_PLAN) that the maintenance run `record` must
 * record: those always required, the configured Node 24 slot when the run's own Node is not Node
 * 24, and the lint stages the caller names (`lintStages`).
 */
export function maintenanceRequiredStages(record, lintStages = []) {
  const newer = !/^v24\./.test(typeof record?.host?.node === 'string' ? record.host.node : '');
  return MAINTENANCE_PLAN.filter(
    entry =>
      entry.required === 'always' ||
      (entry.required === 'newer-node' && newer) ||
      (entry.required === 'named' && lintStages.includes(entry.name))
  ).map(entry => entry.name);
}

/**
 * Problems with the stages of the maintenance (B35) run `record` against the approved B35 plan
 * (MAINTENANCE_PLAN; GDR7-FIN-01): each stage must have a name the plan has, be recorded once and
 * be of its class. A stage the plan does not name is refused whatever it carries: one that ran a
 * command is a candidate-code or tool execution outside the approved plan, and one that did not is
 * a record no approved maintenance gate writes. A record-only stage that carries any trace of a
 * command or of a test execution is refused, as is test-execution evidence on a stage the plan does
 * not class as a test slot. A stage record may hold only the members of its class's record form
 * and its own data (MAINTENANCE_RECORD_FORMS, MAINTENANCE_STAGE_DATA), so `steps`, the composite
 * form, and an unknown member are refused; each member it holds must be of its closed schema at
 * every depth (maintenanceStageSchemaProblems; GDR8-SCHEMA-01), so an unknown nested member, such
 * as `host.probe` carrying an `argv` and an `exitCode`, is refused whatever its spelling; and no
 * record shaped as a stage record may be nested
 * anywhere inside it (nestedStageRecords): an execution recorded inside another stage's record is
 * as much outside the plan as one recorded beside it. Which stages must be present is
 * maintenanceRequiredStages'; whether each passed is the finalizer's (checkRun). Withheld records
 * (pending, with a reason, carrying nothing a command leaves) and informational records of the
 * plan are of their class. Returns the problems.
 */
export function maintenancePlanProblems(record) {
  const problems = [];
  const stages = Array.isArray(record?.stages) ? record.stages : [];
  const counts = new Map();
  for (const stage of stages) {
    if (!isObject(stage) || typeof stage.name !== 'string') {
      problems.push(`a stage record has no name: ${show(stage)}`);
      continue;
    }
    counts.set(stage.name, (counts.get(stage.name) ?? 0) + 1);
    const entry = MAINTENANCE_PLAN_STAGES.get(stage.name);
    const traces = EXECUTION_TRACES.filter(key => own(stage, key));
    if (!entry) {
      problems.push(
        traces.length
          ? `${stage.name} is an executed stage outside the approved B35 plan (it carries ${traces.join(', ')}): no maintenance run may execute it (GDR7-FIN-01)`
          : `${stage.name} is not a stage of the approved B35 plan (GDR7-FIN-01)`
      );
      continue;
    }
    if (entry.execution === 'record' && traces.length)
      problems.push(
        `${stage.name} is a record-only stage of the approved B35 plan, but it carries ${traces.join(', ')}: nothing may execute under its name (GDR7-FIN-01)`
      );
    const tested = TEST_EXECUTION_TRACES.filter(key => own(stage, key));
    const untested = entry.execution !== 'record' && entry.execution !== 'test';
    if (untested && tested.length)
      problems.push(
        `${stage.name} is of the execution class ${entry.execution} in the approved B35 plan, not a test slot, but it carries ${tested.join(', ')}: no test execution may run under its name (GDR7-FIN-01)`
      );
    // Every other member its class's record form and its own data do not have (the traces named
    // above are named once).
    const allowed = new Set([
      ...MAINTENANCE_RECORD_FORMS[entry.execution],
      ...(MAINTENANCE_STAGE_DATA[stage.name] ?? []),
      ...(entry.execution === 'record' ? traces : []),
      ...(untested ? tested : []),
    ]);
    const unknown = Object.keys(stage).filter(key => !allowed.has(key));
    if (unknown.length)
      problems.push(
        `${stage.name} carries ${unknown.map(show).join(', ')}, which the record form of its class (${entry.execution}) in the approved B35 plan does not have${unknown.includes('steps') ? ': steps is the composite record form, and a maintenance run records each execution as its own stage of the plan' : ''} (GDR7-FIN-01)`
      );
    for (const nested of nestedStageRecords(stage))
      problems.push(
        nested.record
          ? `${stage.name} holds a stage record at ${nested.where}${typeof nested.record.name === 'string' ? ` (${show(nested.record.name)})` : ''}: an execution recorded inside another stage's record is outside the approved B35 plan, which records each execution as its own stage (GDR7-FIN-01)`
          : `${stage.name} nests more than ${NESTED_LIMIT} values, too many to judge (GDR7-FIN-01)`
      );
    // What each permitted member holds, at every depth, against its closed schema
    // (GDR8-SCHEMA-01): an unknown nested member or a value of another shape is refused whatever
    // its spelling, so an execution-like description hidden under another name is refused too.
    problems.push(...maintenanceStageSchemaProblems(stage));
  }
  for (const [name, count] of counts)
    if (count > 1 && MAINTENANCE_PLAN_STAGES.has(name))
      problems.push(
        `${name} is recorded ${count} times: the approved B35 plan has it once (GDR7-FIN-01)`
      );
  return problems;
}

/**
 * Problems with the host and runtime evidence of a sealed maintenance (B35) run (`run`: { name,
 * record, get, has } from security-finalization.mjs), which the finalizer and the commit guard
 * consume (checkPlatformEvidence): a maintenance run has no platform manifest, catalog or coverage
 * to check, but its test stages ran candidate code on Node binaries, and those must have been
 * identified first (GDR6-REQ-01). test-host and runtime-identity must each be recorded exactly
 * once, passed, on a valid recorded interval inside the run; test-host must name the run's
 * platform and a user other than root; runtime-identity must list each runtime as { version,
 * sha256, record }, no binary twice, each with its sealed identity record valid for that binary,
 * version and the run's platform and architecture (runtimeIdentityProblems, with the reviewed
 * release keys the stage sealed). Each test execution that ran (one withheld before dispatch ran
 * nothing) must be one of the approved test slots of MAINTENANCE_PLAN, current-runtime on the
 * gate's own Node (the run's host Node) and minimum-runtime on Node 24 (the configured Node 24
 * executable, which may be a second Node 24 binary), record its Node version and binary sha256,
 * be identified by runtime-identity with that version, and start no earlier than both
 * prerequisites end, recorded after them. A test execution is found by the plan's class and by
 * what the record carries (test totals, records, run code, a runtime) or a test-stage name, not by
 * one name prefix (GDR7-FIN-01): one that is no approved slot is refused, and so is one recorded
 * inside another stage's record (in its `steps`, say), whatever that stage is. Legacy evidence
 * without either prerequisite is refused on that basis. The checks read only the sealed run, never the
 * time now, so the recorded-approval reader applies them too (maintenanceEvidenceProblems).
 * Returns the problems: none when the evidence holds.
 */
export function maintenanceRuntimeProblems(run) {
  const { record, get, has } = run;
  const problems = [];
  const stages = Array.isArray(record?.stages) ? record.stages : [];
  const window = recordWindow(record);
  const found = new Map();
  for (const name of MAINTENANCE_TEST_PREREQUISITES) {
    const named = stages.filter(stage => isObject(stage) && stage.name === name);
    if (!named.length) {
      problems.push(
        `${name} is absent: a maintenance (B35) run must record test-host and runtime-identity, each passed, before its test stages (GDR6-REQ-01), so evidence without it is refused`
      );
      continue;
    }
    if (named.length > 1) {
      problems.push(`${name} is recorded ${named.length} times, so it has no one result`);
      continue;
    }
    const [stage] = named;
    if (stage.status !== 'pass') {
      problems.push(`${name} is ${show(stage.status)}, not pass`);
      continue;
    }
    const interval = stageInterval(stage, window);
    if (interval.problem) {
      problems.push(`${name} has ${interval.problem}`);
      continue;
    }
    found.set(name, { stage, ...interval });
  }
  const host = found.get('test-host')?.stage;
  if (host) {
    if (!isObject(host.host) || host.host.platform !== record.host?.platform)
      problems.push(
        `test-host does not apply to this run: it names the platform ${show(isObject(host.host) ? host.host.platform : undefined)}, not ${show(record.host?.platform)}`
      );
    if (!isObject(host.host) || !Number.isSafeInteger(host.host.uid) || host.host.uid <= 0)
      problems.push('test-host records root, or no user');
  }
  const identity = found.get('runtime-identity')?.stage;
  const identified = new Map();
  if (identity) {
    let releaseKeys = null;
    try {
      releaseKeys = sealedReleaseKeys(identity, get, has);
    } catch (error) {
      problems.push(`runtime-identity: ${error.message}`);
    }
    if (!Array.isArray(identity.runtimes) || !identity.runtimes.length)
      problems.push('runtime-identity identifies no runtime');
    for (const entry of Array.isArray(identity.runtimes) ? identity.runtimes : []) {
      if (
        !isObject(entry) ||
        !matches(HEX64, entry.sha256) ||
        !matches(NODE_VERSION, entry.version) ||
        typeof entry.record !== 'string'
      ) {
        problems.push(
          `runtime-identity lists a runtime that is not { version, sha256, record }: ${show(entry)}`
        );
        continue;
      }
      if (identified.has(entry.sha256)) {
        problems.push(`runtime-identity lists the binary ${entry.sha256} twice`);
        continue;
      }
      identified.set(entry.sha256, entry);
      const where = `runtime-identity, Node ${entry.version} (${entry.sha256})`;
      if (!has(entry.record)) {
        problems.push(
          `${where}: its identity record ${show(entry.record)} is not sealed with the run`
        );
        continue;
      }
      try {
        problems.push(
          ...runtimeIdentityProblems(
            strictJson(get(entry.record), 'the runtime identity record'),
            {
              sha256: entry.sha256,
              version: entry.version,
              platform: record.host?.platform,
              arch: record.host?.arch,
            },
            releaseKeys
          ).map(item => `${where}: ${item}`)
        );
      } catch (error) {
        problems.push(`${where}: ${error.message}`);
      }
    }
  }
  // Every test execution of the run, by the approved plan's classes and the record's own evidence
  // rather than a name prefix (GDR7-FIN-01): each stage the plan classes as a test slot, each stage
  // that carries what only a test execution leaves (its totals, records, run code or runtime), and
  // each stage named as a test stage of any kind. One withheld before dispatch ran nothing. A stage
  // that is not a test slot of the plan has no approved runtime to be bound to, and is refused.
  const tests = stages.filter(
    stage =>
      isObject(stage) &&
      typeof stage.name === 'string' &&
      !withheldStage(stage) &&
      (MAINTENANCE_PLAN_STAGES.get(stage.name)?.execution === 'test' ||
        TEST_EXECUTION_TRACES.some(key => own(stage, key)) ||
        TEST_STAGE_NAME.test(stage.name))
  );
  for (const stage of tests) {
    const where = stage.name;
    const planned = MAINTENANCE_PLAN_STAGES.get(stage.name);
    const slot = planned?.execution === 'test' ? planned.slot : undefined;
    if (!slot) {
      problems.push(
        `${where} is not a test stage of a maintenance run: the approved B35 plan has no such test slot, so no runtime it ran is bound to an approved one (GDR7-FIN-01)`
      );
      continue;
    }
    const runtime = stage.runtime;
    if (
      !isObject(runtime) ||
      !matches(HEX64, runtime.sha256) ||
      !matches(NODE_VERSION, runtime.version)
    ) {
      problems.push(`${where} records no Node version and binary sha256`);
      continue;
    }
    if (slot === 'current-runtime' && runtime.version !== record.host?.node)
      problems.push(
        `${where} ran Node ${runtime.version}, not the gate's own Node ${show(record.host?.node)}, its approved slot`
      );
    if (slot === 'minimum-runtime' && major(runtime.version) !== '24')
      problems.push(`${where} ran Node ${runtime.version}, not Node 24, its approved slot`);
    const entry = identified.get(runtime.sha256);
    if (identity && (!entry || entry.version !== runtime.version))
      problems.push(
        `${where}: runtime-identity does not identify its Node binary (Node ${runtime.version}, sha256 ${runtime.sha256})`
      );
    const interval = stageInterval(stage, window);
    if (interval.problem) {
      problems.push(`${where} has ${interval.problem}`);
      continue;
    }
    for (const [name, before] of found)
      if (before.end > interval.start || stages.indexOf(before.stage) > stages.indexOf(stage))
        problems.push(
          `${name} must end before ${where} starts, and be recorded before it (v5 C23 O; GDR6-REQ-01)`
        );
  }
  // A test execution recorded inside another stage's record (in `steps`, the 1.5 gate's composite
  // form, or anywhere else in it), under any stage, withheld or not: no approved slot is nested in
  // a stage, so no runtime it ran is bound to an approved one (GDR7-FIN-01).
  for (const stage of stages)
    if (isObject(stage) && typeof stage.name === 'string')
      for (const { where, record: nested } of nestedStageRecords(stage))
        if (
          nested &&
          (TEST_EXECUTION_TRACES.some(key => own(nested, key)) ||
            (typeof nested.name === 'string' &&
              (TEST_STAGE_NAME.test(nested.name) ||
                MAINTENANCE_PLAN_STAGES.get(nested.name)?.execution === 'test')))
        )
          problems.push(
            `${stage.name} holds a test execution at ${where}${typeof nested.name === 'string' ? ` (${show(nested.name)})` : ''}: no approved test slot of the B35 plan is nested in another stage's record, so no runtime it ran is bound to an approved one (GDR7-FIN-01)`
          );
  return problems;
}

/**
 * The shared, moment-independent B35 checks of a sealed maintenance run (`run`: { name, record,
 * get, has } from security-finalization.mjs): the approved plan (maintenancePlanProblems), the
 * stages it requires of this run (maintenanceRequiredStages, with the lint stages a caller names
 * as `lintStages`) and the host and runtime evidence (maintenanceRuntimeProblems). Each reads only
 * the sealed run, never the time now. The finalizer and the commit guard apply them before a
 * finalization is written or accepted (checkPlatformEvidence, checkRun), and the recorded-approval
 * reader (recordedApproval, behind --verify-commit and the reference-transaction hook) applies them
 * again whenever a recorded maintenance approval would give authority, so an approval of a run
 * that the current rules refuse gives none (GDR7-AUTH-01). `lintStages` has no default
 * (GDR8-AUTH-LINT-01): the caller passes the lint stages its candidate or commit requires, the
 * commit guard and verifyCommit each deriving them from the candidate or the exact commit and its
 * parents' history, so no reader can fall back to requiring none. Returns the problems, each
 * labelled.
 */
export function maintenanceEvidenceProblems(run, { lintStages } = {}) {
  if (
    !Array.isArray(lintStages) ||
    !lintStages.every(name => MAINTENANCE_PLAN_STAGES.get(name)?.required === 'named') ||
    new Set(lintStages).size !== lintStages.length
  )
    throw new Error(
      'maintenanceEvidenceProblems needs the lint stages the candidate requires, as a list of the plan stages a caller names (GDR8-AUTH-LINT-01): none is assumed'
    );
  const stages = Array.isArray(run?.record?.stages) ? run.record.stages : [];
  const names = new Set(stages.map(stage => (isObject(stage) ? stage.name : undefined)));
  return [
    ...maintenanceRuntimeProblems(run).map(item => `host and runtime evidence: ${item}`),
    ...maintenancePlanProblems(run?.record).map(item => `execution plan: ${item}`),
    ...maintenanceRequiredStages(run?.record, lintStages)
      .filter(name => !names.has(name))
      .map(
        name =>
          `execution plan: ${name} is required of this run by the approved B35 plan and is missing`
      ),
  ];
}

// Stages a gate run records without a command. A stage the draft does not implement is recorded
// as pending, also without a command (pendingStage in scripts/security-gate.mjs).
export const platformRequirementStages = Object.freeze([
  'platform-manifest',
  'test-host',
  'runtime-identity',
  'platform-coverage-current-runtime',
  'platform-coverage-minimum-runtime',
  't8-image-authenticity',
  't8-image-activation',
  'network-policy',
]);

/**
 * The stages whose record forms are pending (v5 C5, C17 item 12), so that no producer is qualified
 * and none of them is ever a pass: the three T8 stages, the two candidate-controlled image builds
 * and container-identity, which verifies a build's same-run result record. The gate records each
 * as pending; F refuses any of them recorded as passed, and refuses a run in which either build,
 * container-identity or a scan of the built image ran (a build whose pre-build authority is
 * pending does not start, v5 C5 change 3). t8-image-identity alone may have run something while
 * pending: exactly its local read-only `docker image inspect` (t8InspectCommand), whose output
 * the image and coverage checks read.
 */
export const pendingRecordStages = Object.freeze({
  't8-image-identity':
    'its record form, the reviewed stage policy for docker image inspect (decision 7) and T8 qualification are pending (v5 C5, C17 item 12): the local observation is evidence, not authority',
  't8-image-authenticity':
    'its record form and T8 qualification are pending, and no reviewed activation record exists (v5 C5, C17 item 12; IP-01)',
  't8-image-activation':
    "its binding record form is pending (gate-draft-r4 proposes one), and N's T8 records it binds are pending too (v5 C5, C14, C17 item 12)",
  'container-build':
    'its pre-build authority record form is pending (bases, context, Dockerfile, arguments, platform, builder and endpoint, stage policy and boundaries), so the build does not start (v5 C5 change 3, C17 item 12); FROM scratch is no exception (v5 change 15)',
  'container-identity':
    'the same-run result record it verifies has a pending form and no producer, and container-build did not start (v5 C5 change 3, C17 item 12)',
  'systemd-test-image':
    'pending under the isolation hold (081147), and its pre-build authority record form is pending, so the build does not start (v5 C3, C5 change 3, C17 item 12)',
});
/** The stages that need an image the run built, and so cannot run while the builds are pending. */
export const builtImageStages = Object.freeze(['container-vulnerabilities', 'container-sbom']);
/** The exact command of t8-image-identity's local read-only observation of `images`. */
export const t8InspectCommand = images => [
  'docker',
  'image',
  'inspect',
  '--format',
  '{{json .}}',
  ...images,
];

const DAY = 24 * 60 * 60 * 1000;

/**
 * Whether the times of a run hold: `started` and `finished` UTC times, finished not before
 * started nor after `now`, and started at most 24 hours before `now` (the ceiling is inclusive,
 * as v3 C14 proposes: a run of exactly 24 hours is inside it). Then every stage's own times lie
 * inside the run's, in a main run as in a companion run (v3 C12; security review GD-R3). Returns the
 * problems.
 */
export function runTimeProblems(record, now) {
  const problems = [];
  const started = Date.parse(record?.started),
    finished = Date.parse(record?.finished);
  if (!isTime(record?.started) || !isTime(record?.finished) || finished < started)
    return ['the run has invalid or inverted times'];
  if (finished > now) problems.push('the run finishes later than now');
  if (now - started > DAY) problems.push('the run is stale: it started more than 24 hours ago');
  for (const stage of Array.isArray(record.stages) ? record.stages : []) {
    const name = typeof stage?.name === 'string' ? stage.name : 'a stage';
    if (!isTime(stage?.started) || !isTime(stage?.finished))
      problems.push(`${name} records no start and finish time`);
    else if (Date.parse(stage.finished) < Date.parse(stage.started))
      problems.push(`${name} finishes before it starts`);
    else if (Date.parse(stage.started) < started || Date.parse(stage.finished) > finished)
      problems.push(`${name} is outside the run's times`);
  }
  return problems;
}

/**
 * The main profile F selects itself for a candidate (v4 C2, C14; the security review of v3: F
 * chooses the mode, the profile and the catalog and compares each with what a record names): the
 * one profile of the installed catalog with reviewed N and O arrays that the candidate's judged
 * manifest declares as a full run of every test file. Its platform is F's own
 * (PROFILE_PLATFORMS, security-catalog.mjs), never the one the manifest declares: verify-1 of
 * gate-draft-r3 found that an introduction manifest declaring `linux-full` on darwin made a darwin
 * gate run the selected one. Neither the run record (its host, its catalog binding), the
 * candidate's manifest nor a caller decides it. Returns { profile, platform, declared } (declared:
 * the platform the manifest names for that run, which the caller must find equal), or null when
 * there is no such single profile, or F binds no platform to it (then nothing is a pass).
 */
export function selectMainProfile(catalog, manifest) {
  const chosen = Object.entries(catalog?.profiles ?? {})
    .filter(([, phases]) => own(phases, 'N') && own(phases, 'O'))
    .map(([name]) => name)
    .filter(
      name =>
        isObject(manifest?.runs) &&
        own(manifest.runs, name) &&
        manifest.runs[name].files === 'all' &&
        typeof manifest.runs[name].platform === 'string' &&
        manifest.runs[name].platform !== 'container'
    );
  if (chosen.length !== 1 || !own(PROFILE_PLATFORMS, chosen[0])) return null;
  return {
    profile: chosen[0],
    platform: PROFILE_PLATFORMS[chosen[0]],
    declared: manifest.runs[chosen[0]].platform,
  };
}

/**
 * The catalog judgment of one run (security-catalog.mjs judgeStages) for the profile the
 * finalizer selected itself, never one a run or a caller names: { profile, verdict, passed,
 * pending, failed }. A run must record the same catalog sha256, mode and profile. A profile with
 * no reviewed array gives pending (v3 C23: such a run cannot be satisfied, so never pass).
 * `pendingStages` moves stages the finalizer judged pending itself (the T8 image authority) out of
 * `passed`.
 */
export function catalogJudgment(
  record,
  { catalog, catalogSha256, mode, profile, pendingStages = [] }
) {
  const failed = [];
  if (
    !isObject(record.catalog) ||
    record.catalog.sha256 !== catalogSha256 ||
    record.catalog.mode !== mode ||
    record.catalog.profile !== profile
  )
    failed.push(
      `the run records the catalog ${show(record.catalog)}, not ${show({ mode, profile, sha256: catalogSha256 })}`
    );
  let required;
  try {
    required = profileStages(catalog, profile, mode).all;
  } catch (error) {
    return {
      profile,
      verdict: failed.length ? 'fail' : 'pending',
      passed: [],
      pending: [error.message],
      failed,
    };
  }
  const judged = judgeStages(record.stages, required);
  const moved = judged.passed.filter(id => pendingStages.includes(id));
  const passed = judged.passed.filter(id => !moved.includes(id));
  const pending = [...judged.pending, ...moved];
  const allFailed = [...failed, ...judged.failed];
  return {
    profile,
    verdict: allFailed.length ? 'fail' : pending.length ? 'pending' : 'pass',
    passed,
    pending,
    failed: allFailed,
  };
}

/**
 * Checks one sealed companion run (platform mode) for the candidate `current` at `now`: sealed and
 * unchanged with nothing added (the reader checks that), a record of the local run family
 * (LOCAL_RUN_KIND version 1, a diagnostic record, not a C12 phase record), the same tree, complete ordered
 * parent vector and candidate identity (`identitySha256`) and canonical file manifest, the
 * platform of its run, not root, the candidate's tool configuration, the run's times and every
 * stage's inside them (runTimeProblems), every stage passed or pending, exactly the catalog's
 * array for its profile (the companion's run, which the finalizer selected from the judged
 * manifest), the same manifest judgment as the gate run, and its platform evidence
 * (checkRunPlatform). Returns its summary, or throws.
 */
export function checkCompanion(
  run,
  {
    current,
    identitySha256,
    manifest,
    manifestSha256,
    judged,
    now,
    toolsSha256,
    tools,
    catalog,
    profiles,
  }
) {
  const { record } = run;
  const fail = message => {
    throw new Error(`${run.name}: ${message}`);
  };
  if (
    record.kind !== LOCAL_RUN_KIND ||
    record.kindVersion !== LOCAL_RUN_KIND_VERSION ||
    record.mode !== 'platform' ||
    !['pass', 'pending'].includes(record.status)
  )
    fail(
      `it is not a companion run (an ${LOCAL_RUN_KIND} record, version ${LOCAL_RUN_KIND_VERSION}, of platform mode) that passed or is pending`
    );
  const runId = record.platformRun;
  const declared =
    typeof runId === 'string' && own(manifest.runs, runId) ? manifest.runs[runId] : null;
  if (!declared || declared.platform === 'container')
    fail(`it ran ${show(runId)}, not a run of the manifest`);
  // A catalog profile's platform is F's own, not the manifest's (PROFILE_PLATFORMS).
  if (own(PROFILE_PLATFORMS, runId) && declared.platform !== PROFILE_PLATFORMS[runId])
    fail(
      `the candidate's manifest declares ${runId} on ${show(declared.platform)}, but F binds the profile ${runId} to ${PROFILE_PLATFORMS[runId]} itself (v4 C14)`
    );
  // F chooses the companion profiles itself: the runs of the manifest that cover a run the
  // candidate still needs (`profiles`). A companion whose run is not one of them is not judged
  // against any array (v4 C2, C14, C22; the security review of v3).
  if (!Array.isArray(profiles) || !profiles.includes(runId))
    fail(
      `its run ${show(runId)} covers no run this candidate still needs: F selected no such companion profile (it selected ${show(profiles)})`
    );
  if (record.tree !== current.tree || !sameParents(record.parents, current.parents))
    fail('it is of another tree or complete ordered parent vector');
  if (record.candidateIdentitySha256 !== identitySha256)
    fail('it names another candidate identity');
  if (JSON.stringify(run.files) !== JSON.stringify(current.files))
    fail("its file manifest is not the candidate's");
  const times = runTimeProblems(record, now);
  if (times.length) fail(times.slice(0, 5).join('; '));
  if (record.host?.platform !== declared.platform)
    fail(`it ran on ${show(record.host?.platform)}, not ${declared.platform}`);
  if (!Number.isSafeInteger(record.host?.uid) || record.host.uid < 0 || record.host.uid === 0)
    fail('it ran as root, or records no user');
  if (typeof record.host?.arch !== 'string' || !matches(NODE_VERSION, record.host?.node))
    fail('it records no architecture or Node version');
  if (
    sha256(run.get('tool-config.json')) !== toolsSha256 ||
    JSON.stringify(record.tools) !== JSON.stringify(tools)
  )
    fail("its tool configuration is not the candidate's");
  if (JSON.stringify(record.platform) !== JSON.stringify(judgmentSummary(judged)))
    fail('it judged another manifest');
  const names = new Set();
  for (const stage of record.stages ?? []) {
    if (typeof stage?.name !== 'string' || names.has(stage.name))
      fail('a stage is duplicated or unnamed');
    names.add(stage.name);
    if (stage.error || stage.signal || !['pass', 'pending'].includes(stage.status))
      fail(`${stage.name} did not pass`);
    if (stage.status === 'pending') {
      // Only t8-image-identity may have run something while pending: its exact local query.
      const observation =
        stage.name === 't8-image-identity' &&
        Array.isArray(stage.images) &&
        JSON.stringify(stage.command) === JSON.stringify(t8InspectCommand(stage.images)) &&
        stage.exit === 0 &&
        typeof stage.log === 'string' &&
        run.has(stage.log);
      if ((stage.command && !observation) || !text(stage.reason))
        fail(`${stage.name} is pending without a reason`);
      continue;
    }
    if (stage.command && stage.exit !== 0) fail(`${stage.name} did not exit 0`);
    if (stage.command && (typeof stage.log !== 'string' || !run.has(stage.log)))
      fail(`${stage.name} has no sealed log`);
  }
  // Exactly the catalog's stages first, so a missing or extra stage is named as such.
  const membership = catalogJudgment(record, { ...catalog, mode: 'commit', profile: runId });
  if (membership.verdict === 'fail') fail(membership.failed.slice(0, 10).join('; '));
  // Then the order of its stages, on their recorded intervals (v5 C23; darwin-platform's rules
  // are proposed by analogy).
  const order = orderProblems(record, { prefix: 'platform-tests-' });
  if (order.length) fail(order.slice(0, 10).join('; '));
  // Its gate identity, when its gate-identity stage carries one: version 3 only (v4 C1; GCV3-03),
  // binding the installed catalog. Even then it stays pending: F compares it (v4 C14).
  const gate = gateIdentityStage(
    record.stages.find(stage => stage?.name === 'gate-identity'),
    { catalogSha256: catalog.catalogSha256 }
  );
  if (gate.problems.length) fail(gate.problems.join('; '));
  const checked = checkRunPlatform(run, {
    manifest,
    manifestSha256,
    runId,
    prefix: 'platform-tests-',
    allFiles: candidateTestFiles(current.files),
  });
  const judgedCatalog = catalogJudgment(record, {
    ...catalog,
    mode: 'commit',
    profile: runId,
    pendingStages: [
      ...checked.pending.map(item => item.stage),
      ...(gate.identity ? ['gate-identity'] : []),
    ],
  });
  if (judgedCatalog.verdict === 'fail') fail(judgedCatalog.failed.slice(0, 10).join('; '));
  return {
    directory: run.name,
    run: runId,
    runSha256: run.runSha256,
    started: record.started,
    finished: record.finished,
    host: {
      platform: record.host.platform,
      arch: record.host.arch,
      node: record.host.node,
      uid: record.host.uid,
    },
    stages: checked.stages,
    catalog: judgedCatalog,
    // The companion's own gate identity binding ({ sha256, version: 3 }), or null when its
    // gate-identity stage carries no record: the approval binds it with the platform evidence
    // (verify-1 of gate-draft-r3 found it checked but not carried).
    gateIdentity: gate.binding,
    pending: checked.pending,
  };
}

/**
 * The platform evidence of a gate run and its companions for the candidate `current` (with
 * `current.platform`, the inputs of the judgment, and `current.parents`, its complete ordered
 * parent vector) at `now`. `main` and each of `companions` is a sealed run; `catalog` is
 * { catalog, catalogSha256 } from the installed catalog. Returns { judged, state, identity,
 * summary, pending }: the judgment, the manifest path's state and the candidate identity it gives,
 * then for a candidate with a platform contract the summary the approval binds (null for one
 * without: maintenance, B35) and why its evidence is still pending. Throws on a problem. A
 * maintenance run returns early, with no platform evidence to bind, but only once its host and
 * runtime evidence holds (maintenanceRuntimeProblems; GDR6-REQ-01) and its stages keep to the
 * approved B35 plan (maintenancePlanProblems; GDR7-FIN-01): the early return passes no run that
 * lacks test-host or runtime-identity, whose test executions ran a runtime they do not identify or
 * that is no approved slot, or that executed a stage outside the plan or under a record-only name,
 * or holds a member its class's record form does not have or an execution nested in another
 * stage's record.
 */
export function checkPlatformEvidence({ main, companions, current, now, catalog }) {
  const binding = { tree: current.tree, parents: current.parents };
  const dispositions = main.has('coverage-dispositions.json')
    ? parseCoverageDispositions(main.get('coverage-dispositions.json'), binding)
    : [];
  const judged = judgePlatformManifest({ ...current.platform, dispositions, binding });
  if (judged.problems.length)
    throw new Error(`Platform coverage contract: ${judged.problems.slice(0, 10).join('; ')}`);
  const state = platformManifestState(judged);
  const identity = candidateIdentity({ ...binding, files: current.files, platformManifest: state });
  if (judged.kind === 'maintenance') {
    if (companions.length)
      throw new Error('Companion runs were given, but the candidate has no platform contract');
    const runtime = maintenanceRuntimeProblems(main);
    if (runtime.length)
      throw new Error(
        `Maintenance (B35) host and runtime evidence: ${runtime.slice(0, 10).join('; ')}`
      );
    // The approved B35 plan (GDR7-FIN-01): no stage outside it, none against its class or its
    // class's record form, and none nested in another stage's record.
    const plan = maintenancePlanProblems(main.record);
    if (plan.length)
      throw new Error(`Maintenance (B35) execution plan: ${plan.slice(0, 10).join('; ')}`);
    return { judged, state, identity, profile: null, summary: null, pending: [] };
  }
  const { manifest, manifestSha256 } = judged;
  if (JSON.stringify(main.record.platform) !== JSON.stringify(judgmentSummary(judged)))
    throw new Error('The run judged another platform manifest than the candidate holds');
  if (
    current.files.find(item => item.file === manifestFile)?.sha256 !== manifestSha256 ||
    !main.has('platform-manifest.json') ||
    sha256(main.get('platform-manifest.json')) !== manifestSha256
  )
    throw new Error("The run's sealed platform manifest is not the candidate's");
  // F selects the main profile itself, from the installed catalog and the judged manifest, then
  // compares the run with it: a run on another platform is not the run F selected.
  const selected = selectMainProfile(catalog.catalog, manifest);
  if (!selected)
    throw new Error(
      'F selects no main profile: the catalog has no reviewed N and O arrays for exactly one full run of this manifest (v4 C14, C23)'
    );
  if (selected.declared !== selected.platform)
    throw new Error(
      `The candidate's manifest declares ${selected.profile} on ${show(selected.declared)}, but F binds the profile ${selected.profile} to ${selected.platform} itself (v4 C14; the security review of v3)`
    );
  const platform = main.record.host?.platform;
  if (platform !== selected.platform)
    throw new Error(
      `F selected the profile ${selected.profile}, a run on ${selected.platform}; this gate run ran on ${show(platform)} (v4 C14)`
    );
  const mainRun = selected.profile;
  const allFiles = candidateTestFiles(current.files);
  const checkedMain = checkRunPlatform(main, {
    manifest,
    manifestSha256,
    runId: mainRun,
    prefix: 'full-tests-',
    allFiles,
  });
  const toolsBytes = main.get('tool-config.json');
  const outstanding = requiredRuns(manifest, 'commit').filter(
    id => !satisfies(manifest, mainRun, id)
  );
  // The companion profiles F selects itself: each run of the manifest, other than a container
  // run, that covers a run the candidate still needs.
  const companionProfiles = Object.keys(manifest.runs)
    .filter(id => manifest.runs[id].platform !== 'container')
    .filter(id => outstanding.some(need => satisfies(manifest, id, need)))
    .sort();
  const checked = [];
  const seen = new Set();
  for (const run of companions) {
    if (seen.has(run.name)) throw new Error(`${run.name} is given twice`);
    seen.add(run.name);
    const summary = checkCompanion(run, {
      current,
      identitySha256: identity.sha256,
      manifest,
      manifestSha256,
      judged,
      now,
      toolsSha256: sha256(toolsBytes),
      tools: main.record.tools,
      catalog,
      profiles: companionProfiles,
    });
    const covers = outstanding.filter(id => satisfies(manifest, summary.run, id));
    if (
      !covers.length ||
      covers.some(id => checked.some(other => satisfies(manifest, other.run, id)))
    )
      throw new Error(`${run.name} covers no run this candidate still needs`);
    checked.push(summary);
  }
  const missing = outstanding.filter(
    id => !checked.some(other => satisfies(manifest, other.run, id))
  );
  if (missing.length)
    throw new Error(
      `No companion run covers ${missing.join(', ')} for this candidate (absence is never a pass)`
    );
  const pending = [...checkedMain.pending];
  for (const companion of checked) {
    pending.push(...companion.pending);
    for (const id of companion.catalog.pending)
      pending.push({ stage: id, reason: `${companion.directory}: ${id} is pending` });
    // A companion's own clock is a claim: its dispatch, start, end and receipt need intervals a
    // qualified controller observed (v3 C22), which this draft has no source for.
    pending.push({
      stage: 'companion-evidence',
      reason: `${companion.directory}: no trusted dispatch, start, end and receipt intervals (v3 C22)`,
    });
  }
  return {
    judged,
    state,
    identity,
    profile: mainRun,
    summary: {
      kind: judged.kind,
      manifestSha256,
      excused: judged.losses.map(loss => loss.key).sort(),
      // The entry profile every records pack of these runs was read with (maintainer decision 3: bind
      // the profile to the evidence): the reader's own, so an approval binds the validator that
      // judged its packs, and the commit guard, whose installed validator must name the same.
      recordPack: recordPackIdentity(),
      run: mainRun,
      stages: checkedMain.stages,
      companions: checked.sort((a, b) => (a.directory < b.directory ? -1 : 1)),
    },
    pending,
  };
}
