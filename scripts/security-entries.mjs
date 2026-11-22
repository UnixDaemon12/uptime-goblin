// The one shared entry validator of the gate (Codex decision 3 of 2026-10-14, message
// 20261014T154123422844Z; GATE-CONTRACT v4 C21 and C24, a draft that has not been reviewed).
//
// Every producer and consumer of one artifact validates its entries here, with the same fixed
// trusted profile: the canonical path, type, collision, count, depth and byte rules, and their
// boundary cases, are written once. The artifact cannot choose its profile or change a limit: a
// caller names the profile it expects from a constant in its own code, never from the artifact,
// and an unknown profile, version or field fails closed. Format decoders stay separate and
// bounded (the record pack's is in security-platform.mjs); they hand their entries here before
// anything is written to disk. The Git-export provenance-comment header of v4 C24 is a narrow rule
// of the gate-export parser, which is not in this tree: no profile here admits a header, a link
// target or any other metadata.
//
// Like the modules beside it, this one uses only Node's own modules, so the commit guard carries
// it (scripts/install-security-hooks.mjs). These are local consistency checks, not signatures.
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { canonicalJson } from './security-catalog.mjs';

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const HEX64 = /^[0-9a-f]{64}$/;
const own = (object, key) => Object.prototype.hasOwnProperty.call(object, key);
const show = value => JSON.stringify(value)?.slice(0, 200);

/**
 * The validator's identity, part of every profile's: its name, its version and the sha256 of this
 * module's own bytes, so a producer and a consumer with different validator code name different
 * profiles and a pack from the one is refused by the other.
 */
export const ENTRY_VALIDATOR = Object.freeze({
  name: 'orbit-entry-validator',
  version: 1,
  sha256: sha256(fs.readFileSync(new URL(import.meta.url))),
});

const MiB = 1024 * 1024;
const packBytes = 40 * MiB;

// The fixed trusted profiles. Each names what one artifact format may hold.
//
// record-pack, version 1: the sealed records of a test stage (security-platform.mjs). Files,
// directories and total entries are decided (COORDINATOR-DECISIONS "C21 pack bounds", and again in
// Codex decision 3: 8,192 files, 8,192 directories, 16,384 total entries, implied parent
// directories counted once each like explicit ones). The byte limit is the existing 40 MiB. The
// depth of three path segments is the named starting bound Daybreak's review of v3 accepted,
// because the harness's path grammar admits nothing deeper; it is not frozen yet. pathBytes, 84,
// is the longest path that grammar admits (a T8 container folder, records/ and a record file with
// a ten-digit pid), so it adds no new policy: it lets the decoder refuse a longer string before
// it holds it. envelopeBytes is the existing ceiling of the whole serialized pack (the base64 of
// the byte limit, plus 4 MiB for names and hashes). Only regular files and directories, and files
// only with the extensions the harness writes.
const PROFILES = {
  'record-pack': {
    version: 1,
    types: ['directory', 'file'],
    extensions: ['.jsonl', '.tap'],
    limits: {
      files: 8192,
      directories: 8192,
      entries: 16384,
      bytes: packBytes,
      depth: 3,
      pathBytes: 84,
      envelopeBytes: Math.ceil((packBytes * 4) / 3) + 4 * MiB,
    },
  },
};

// Profiles that are named but have no reviewed limits: asking for one fails closed. The captured
// evidence archive may get a stricter profile of its own, but the proposed 4,096 entries, 1,024
// directories, 4,608 total and its byte and depth values stay pending until they are frozen and
// reviewed against what the archive must hold and the controller's memory (Codex decision 3).
// "Smaller" does not make a profile reviewed. Its parser is not in this tree either.
export const pendingProfiles = Object.freeze({
  'captured-archive':
    'its entry, directory, total, byte and depth limits are proposals, pending until frozen and reviewed (Codex decision 3); its parser is not in this tree',
});

const deepFreeze = value => {
  if (value && typeof value === 'object') {
    for (const item of Object.values(value)) deepFreeze(item);
    Object.freeze(value);
  }
  return value;
};

// Each profile's identity: the sha256 of the canonical JSON of its definition and the validator
// it is enforced by. A pack names this identity; its consumer requires its own.
const built = new Map();
for (const [name, definition] of Object.entries(PROFILES)) {
  const body = { name, ...definition, validator: ENTRY_VALIDATOR };
  built.set(name, deepFreeze({ ...body, sha256: sha256(canonicalJson(body)) }));
}

/**
 * The fixed profile `name` at `version`: { name, version, types, extensions, limits, validator,
 * sha256 }. Throws for an unknown name, a pending profile or another version: nothing falls back
 * to a looser or default profile.
 */
export function entryProfile(name, version) {
  if (typeof name === 'string' && own(pendingProfiles, name))
    throw new Error(`the entry profile ${show(name)} is pending: ${pendingProfiles[name]}`);
  const profile = typeof name === 'string' && built.has(name) ? built.get(name) : null;
  if (!profile) throw new Error(`the entry profile ${show(name)} is unknown`);
  if (version !== profile.version)
    throw new Error(`the entry profile ${name} has no version ${show(version)}`);
  return profile;
}

/** What an artifact names of its profile: { name, sha256, version }. */
export const profileIdentity = profile => ({
  name: profile.name,
  sha256: profile.sha256,
  version: profile.version,
});

/**
 * Problems with the counts of a set of entries against `limits`: { files, directories, bytes,
 * depth }, directories counted once each, explicit and implied alike, and entries being files and
 * directories together. The decoders call it with their profile's limits; a test may pass smaller
 * limits to show that each check works on its own (with the record-pack values, 16,384 entries is
 * exactly 8,192 files plus 8,192 directories, so one more entry is always over another limit too).
 */
export function entryCountProblems({ files, directories, bytes, depth }, limits) {
  const problems = [];
  if (files > limits.files) problems.push(`more than ${limits.files} files (${files})`);
  if (directories > limits.directories)
    problems.push(`more than ${limits.directories} directories (${directories})`);
  if (files + directories > limits.entries)
    problems.push(`more than ${limits.entries} entries (${files + directories})`);
  if (bytes > limits.bytes) problems.push(`more than ${limits.bytes} bytes (${bytes})`);
  if (depth > limits.depth) problems.push(`a path deeper than ${limits.depth} segments (${depth})`);
  return problems;
}

/**
 * Why `relative` is not a path the profile allows, or null: text of at most `pathBytes` UTF-8
 * bytes, relative and normalised (no leading slash, no empty, `.` or `..` segment), no backslash,
 * no control character, Unicode NFC, and at most `depth` segments.
 */
export function pathProblem(profile, relative) {
  if (typeof relative !== 'string') return 'a path that is not text';
  if (Buffer.byteLength(relative, 'utf8') > profile.limits.pathBytes)
    return `a path longer than ${profile.limits.pathBytes} bytes (${show(relative.slice(0, 120))})`;
  if (/[\u0000-\u001f\u007f\\]/.test(relative))
    return `a path with a control character or backslash (${show(relative)})`;
  if (relative.normalize('NFC') !== relative)
    return `a path that is not in Unicode NFC (${show(relative)})`;
  const segments = relative.split('/');
  if (segments.some(segment => segment === '' || segment === '.' || segment === '..'))
    return `a path that is not relative and normalised (${show(relative)})`;
  if (segments.length > profile.limits.depth)
    return `a path deeper than ${profile.limits.depth} segments (${segments.length})`;
  return null;
}

/** Every folder a path implies: a/b/c implies a and a/b. */
export const impliedDirectories = relative => {
  const parts = relative.split('/');
  return parts.slice(0, -1).map((_, index) => parts.slice(0, index + 1).join('/'));
};

const TYPES = new Set(['directory', 'file']);

/**
 * Validates the entries of one artifact against `profile` (from entryProfile), before anything is
 * written: `entries` are [{ path, type, size?, sha256? }], `type` 'file' or 'directory' as the
 * decoder read it ('symlink', 'hardlink', 'fifo', 'device' or anything else is refused, as is a
 * type the profile does not allow). The counts come first (directories once each, explicit and
 * implied), then every path, every file's extension, size and sha256 form, duplicates, case and
 * Unicode collisions, and a path that is both a file and a folder. Returns { files, directories,
 * implied, bytes, depth }; throws `${where} hold(s) …` on the first problems.
 */
export function validateEntries(profile, entries, { where = 'the entries' } = {}) {
  if (!profile || built.get(profile.name) !== profile)
    throw new Error('validateEntries needs a fixed profile from entryProfile');
  const fail = problems => {
    throw new Error(`${where} hold ${problems.slice(0, 5).join(', ')}`);
  };
  if (!Array.isArray(entries)) fail(['no list of entries']);
  // Types and the text of every path first: counting needs both.
  for (const entry of entries) {
    const type = entry?.type;
    if (!TYPES.has(type) || !profile.types.includes(type))
      fail([
        `${show(entry?.path)} as ${show(type)}, which is not a regular file or directory this profile allows (no link and no other type)`,
      ]);
    if (typeof entry.path !== 'string') fail(['a path that is not text']);
  }
  // The counts: files, directories once each (listed or implied by a path), bytes and depth.
  const explicit = entries.filter(entry => entry.type === 'directory').map(entry => entry.path);
  const files = entries.filter(entry => entry.type === 'file');
  const directories = new Set(explicit);
  let depth = 0;
  let bytes = 0;
  for (const entry of entries) {
    const segments = entry.path.split('/').length;
    if (segments > depth) depth = segments;
    // Only paths within the depth limit add their ancestors, so a deep path cannot make the set
    // large; it is refused for its depth below.
    if (segments <= profile.limits.depth)
      for (const folder of impliedDirectories(entry.path)) directories.add(folder);
  }
  for (const entry of files) {
    if (!Number.isSafeInteger(entry.size) || entry.size < 0)
      fail([`${show(entry.path)} with no valid size`]);
    bytes += entry.size;
  }
  const counted = entryCountProblems(
    { files: files.length, directories: directories.size, bytes, depth },
    profile.limits
  );
  if (counted.length) fail(counted);
  // Each path, extension and checksum form.
  for (const entry of entries) {
    const problem = pathProblem(profile, entry.path);
    if (problem) fail([problem]);
    if (entry.type === 'file') {
      const name = entry.path.split('/').at(-1);
      const dot = name.lastIndexOf('.');
      const extension = dot > 0 ? name.slice(dot) : '';
      if (!profile.extensions.includes(extension))
        fail([`${show(entry.path)}, whose extension this profile does not allow`]);
      if (typeof entry.sha256 !== 'string' || !HEX64.test(entry.sha256))
        fail([`${show(entry.path)} with no sha256 of 64 lowercase hex digits`]);
    }
  }
  // Duplicates and collisions: the same path twice, two paths that one case-insensitive or
  // Unicode-normalising file system would make one, and a file where a folder is (listed or
  // implied).
  const seen = new Set();
  const folded = new Map();
  const fold = item => item.normalize('NFC').toLowerCase();
  for (const entry of entries) {
    if (seen.has(entry.path)) fail([`${show(entry.path)} twice`]);
    seen.add(entry.path);
  }
  for (const item of [...files.map(entry => entry.path), ...directories]) {
    const key = fold(item);
    if (folded.has(key) && folded.get(key) !== item)
      fail([
        `${show(item)} twice when letter case is ignored (as ${show(folded.get(key))}): they collide`,
      ]);
    if (folded.has(key)) fail([`${show(item)} as a file and as a folder`]);
    folded.set(key, item);
  }
  return {
    files: files.length,
    directories: directories.size,
    implied: [...directories].filter(item => !explicit.includes(item)).sort(),
    bytes,
    depth,
  };
}

/**
 * Checks one file's bytes against its entry before they are written: exactly its declared size
 * and its sha256. Throws `${where}: …`.
 */
export function checkEntryData(entry, data, { where = 'the entry' } = {}) {
  if (!Buffer.isBuffer(data) || data.length !== entry.size)
    throw new Error(`${where} ${show(entry.path)} does not have its declared size`);
  if (sha256(data) !== entry.sha256)
    throw new Error(`${where} ${show(entry.path)} does not match its sha256`);
}
