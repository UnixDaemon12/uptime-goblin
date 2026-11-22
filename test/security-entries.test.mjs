// The shared entry validator (scripts/security-entries.mjs; Codex decision 3 of 2026-10-14;
// GATE-CONTRACT v4 C21 and C24, a draft that has not been reviewed): fixed trusted profiles, the
// same profile for every producer and consumer of one artifact, unknown profile, version or field
// failing closed, links and other types refused before anything is written, and each independent
// limit tried exactly at its value and one over. With the record-pack values the entry limit is
// not independent (16,384 is 8,192 files plus 8,192 directories), so it is shown with scaled
// limits only; a scaled case is labelled so and is not a full-capacity run. Synthetic data only.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const load = async () => ({
  entries: await import('../scripts/security-entries.mjs'),
  platform: await import('../scripts/security-platform.mjs'),
  catalog: await import('../scripts/security-catalog.mjs'),
});

function temporary(t, prefix) {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
const container = index => {
  let suffix = '';
  for (let n = index, i = 0; i < 6; i += 1, n = Math.floor(n / 36))
    suffix = alphabet[n % 36] + suffix;
  return `t8-container-24-${suffix}`;
};
const record = (index, pid = index + 1) =>
  `${pid}-${index.toString(16).padStart(8, '0')}-0000-4000-8000-000000000000.jsonl`;
const file = (name, size = 3) => ({ path: name, type: 'file', size, sha256: 'a'.repeat(64) });
const folder = name => ({ path: name, type: 'directory' });

test('the shared validator has fixed trusted profiles: an unknown, pending or other-version profile fails closed', async () => {
  const { entries, catalog } = await load();
  const profile = entries.entryProfile('record-pack', 1);
  assert.deepEqual(
    { ...profile.limits },
    {
      files: 8192,
      directories: 8192,
      entries: 16384,
      bytes: 40 * 1024 * 1024,
      depth: 3,
      pathBytes: 84,
      envelopeBytes: Math.ceil((40 * 1024 * 1024 * 4) / 3) + 4 * 1024 * 1024,
    }
  );
  assert.deepEqual([...profile.types], ['directory', 'file']);
  assert.deepEqual([...profile.extensions], ['.jsonl', '.tap']);
  assert.ok(Object.isFrozen(profile) && Object.isFrozen(profile.limits));
  // Its identity: the sha256 of the canonical JSON of its definition and the validator, which
  // names the validator module's own bytes.
  const { sha256, ...body } = profile;
  assert.equal(sha256, sha(catalog.canonicalJson(body)));
  assert.deepEqual(
    { ...profile.validator },
    {
      name: 'orbit-entry-validator',
      version: 1,
      sha256: sha(fs.readFileSync(new URL('../scripts/security-entries.mjs', import.meta.url))),
    }
  );
  assert.deepEqual(entries.profileIdentity(profile), { name: 'record-pack', sha256, version: 1 });
  for (const [name, version, pattern] of [
    ['record-pack', 2, /has no version 2/],
    ['record-pack', '1', /has no version "1"/],
    ['record-pack', undefined, /has no version/],
    ['captured-archive', 1, /is pending: .*proposals/],
    ['git-export', 1, /is unknown/],
    ['loose', 1, /is unknown/],
    [undefined, 1, /is unknown/],
  ])
    assert.throws(() => entries.entryProfile(name, version), pattern, `${name} ${version}`);
  // A caller cannot hand the validator a looser copy of a profile.
  const looser = { ...profile, limits: { ...profile.limits, files: 1e9 } };
  assert.throws(() => entries.validateEntries(looser, []), /needs a fixed profile/);
  assert.throws(
    () => entries.validateEntries(structuredClone(profile), []),
    /needs a fixed profile/
  );
});

test('every independent limit of the record-pack profile, exactly at its value and one over', async () => {
  const { entries } = await load();
  const profile = entries.entryProfile('record-pack', 1);
  const validate = list => entries.validateEntries(profile, list, { where: 'the pack' });
  // Files: 8,192 record files accepted, 8,193 refused.
  const files = count => Array.from({ length: count }, (_, index) => file(record(index)));
  assert.equal(validate(files(8192)).files, 8192);
  assert.throws(() => validate(files(8193)), /the pack hold more than 8192 files \(8193\)/);
  // Directories, listed: 8,192 accepted, 8,193 refused.
  const folders = count => Array.from({ length: count }, (_, index) => folder(container(index)));
  assert.equal(validate(folders(8192)).directories, 8192);
  assert.throws(() => validate(folders(8193)), /more than 8192 directories \(8193\)/);
  // Directories, implied by paths and counted once each: 4,096 containers with a record each
  // imply 8,192 folders; one more listed container makes 8,193.
  const nested = Array.from({ length: 4096 }, (_, index) =>
    file(`${container(index)}/records/${record(index)}`)
  );
  const implied = validate(nested);
  assert.equal(implied.directories, 8192);
  assert.equal(implied.implied.length, 8192);
  assert.throws(
    () => validate([...nested, folder(container(5000))]),
    /more than 8192 directories \(8193\)/
  );
  // A folder both listed and implied is one folder.
  assert.equal(validate([folder(container(0)), file(`${container(0)}/inner.tap`)]).directories, 1);
  // Bytes: exactly 40 MiB accepted, one byte more refused (declared sizes; no data needed).
  const limit = profile.limits.bytes;
  assert.equal(validate([file(record(0), limit)]).bytes, limit);
  assert.throws(
    () => validate([file(record(0), limit - 10), file(record(1), 11)]),
    /more than 41943040 bytes \(41943041\)/
  );
  // Depth: three segments accepted, four refused.
  assert.equal(validate([file(`${container(0)}/records/${record(0)}`)]).depth, 3);
  assert.throws(
    () => validate([file(`${container(0)}/records/deeper/${record(0)}`)]),
    /deeper than 3 segments \(4\)/
  );
  // Path bytes: 84 (a three-segment record path with a ten-digit pid) accepted, 85 refused.
  const longest = `${container(0)}/records/${record(0, 1234567890)}`;
  assert.equal(longest.length, 84);
  assert.equal(validate([file(longest)]).files, 1);
  const longer = `${container(0)}/records/x${record(0, 1234567890)}`;
  assert.equal(longer.length, 85);
  assert.throws(() => validate([file(longer)]), /a path longer than 84 bytes/);
  // Entries, scaled (not a full-capacity run): with the real values one more entry is always one
  // over the file or directory limit too, so the entry check is shown on its own with smaller
  // limits, at the limit and one over.
  const scaled = { files: 10, directories: 10, entries: 15, bytes: 100, depth: 3 };
  assert.deepEqual(
    entries.entryCountProblems({ files: 8, directories: 7, bytes: 0, depth: 1 }, scaled),
    []
  );
  assert.deepEqual(
    entries.entryCountProblems({ files: 8, directories: 8, bytes: 0, depth: 1 }, scaled),
    ['more than 15 entries (16)']
  );
  // With the real values: 8,192 files and 8,192 directories (16,384 entries) accepted; one more
  // folder is over both the directory and the entry limits.
  assert.deepEqual(
    entries.entryCountProblems(
      { files: 8192, directories: 8192, bytes: 0, depth: 3 },
      profile.limits
    ),
    []
  );
  assert.deepEqual(
    entries.entryCountProblems(
      { files: 8192, directories: 8193, bytes: 0, depth: 3 },
      profile.limits
    ),
    ['more than 8192 directories (8193)', 'more than 16384 entries (16385)']
  );
});

test('links and every other type are refused before anything is written, in the validator and on pack', async t => {
  const { entries, platform } = await load();
  const profile = entries.entryProfile('record-pack', 1);
  for (const type of ['symlink', 'link', 'hardlink', 'fifo', 'device', 'socket', 'pax-header', 7])
    assert.throws(
      () => entries.validateEntries(profile, [{ path: record(0), type, size: 0 }]),
      /not a regular file or directory this profile allows \(no link and no other type\)/,
      String(type)
    );
  assert.throws(
    () => entries.validateEntries(profile, [{ path: record(0), size: 0 }]),
    /not a regular file or directory/
  );
  // On pack: a link where a record file or a container folder would be, and a FIFO, are refused
  // before anything is packed.
  const target = temporary(t, 'orbit-entries-target-');
  fs.writeFileSync(path.join(target, 'outside.jsonl'), '{}\n');
  for (const [label, make] of [
    [
      'a link named as a record',
      dir => fs.symlinkSync(path.join(target, 'outside.jsonl'), path.join(dir, record(0))),
    ],
    ['a link named as a container', dir => fs.symlinkSync(target, path.join(dir, container(0)))],
    [
      'a FIFO named as a record',
      dir => assert.equal(spawnSync('/usr/bin/mkfifo', [path.join(dir, record(0))]).status, 0),
    ],
  ]) {
    const dir = temporary(t, 'orbit-entries-pack-');
    make(dir);
    assert.throws(
      () => platform.packRecords(dir),
      /is not a file or folder the harness writes there/,
      label
    );
  }
  // The records folder itself may not be a link.
  const real = temporary(t, 'orbit-entries-real-');
  const linked = path.join(temporary(t, 'orbit-entries-link-'), 'records');
  fs.symlinkSync(real, linked);
  assert.throws(() => platform.packRecords(linked), /not a directory \(or is a link\)/);
});

test('disallowed extensions, bad checksums and sizes, duplicates and collisions are refused before anything is written', async () => {
  const { entries } = await load();
  const profile = entries.entryProfile('record-pack', 1);
  const validate = list => entries.validateEntries(profile, list, { where: 'the pack' });
  for (const name of ['1-a.json', '1-a.JSONL', 'inner.TAP', 'noextension', '.jsonl', 'a.jsonl.sh'])
    assert.throws(() => validate([file(name)]), /extension this profile does not allow/, name);
  assert.equal(validate([file('inner.tap'), file('1-a.jsonl')]).files, 2);
  for (const sha256 of [undefined, 'A'.repeat(64), 'a'.repeat(63), ['a'.repeat(64)]])
    assert.throws(
      () => validate([{ ...file(record(0)), sha256 }]),
      /with no sha256 of 64 lowercase hex digits/
    );
  for (const size of [undefined, -1, 1.5, '3', 2 ** 53])
    assert.throws(() => validate([{ ...file(record(0)), size }]), /with no valid size/);
  // The bytes: exactly the declared size and the sha256, checked before they are written.
  const data = Buffer.from('{}\n');
  const entry = { path: record(0), type: 'file', size: data.length, sha256: sha(data) };
  assert.doesNotThrow(() => entries.checkEntryData(entry, data));
  assert.throws(
    () => entries.checkEntryData({ ...entry, size: 4 }, data),
    /does not have its declared size/
  );
  assert.throws(
    () => entries.checkEntryData({ ...entry, sha256: '0'.repeat(64) }, data),
    /does not match its sha256/
  );
  // Paths: not relative or normalised, control characters, backslashes, not NFC.
  for (const name of [
    `/${record(0)}`,
    `./${record(0)}`,
    `${container(0)}//${record(0)}`,
    `${container(0)}/../${record(0)}`,
    `${container(0)}/.`,
    `bad\u0001${record(0)}`,
    `bad\\${record(0)}`,
    `café-${record(0)}`,
  ])
    assert.throws(() => validate([file(name)]), /a path (?:that is not|with a control)/, name);
  // Duplicates, case collisions and a file where a folder is.
  assert.throws(() => validate([file(record(0)), file(record(0))]), /twice/);
  assert.throws(() => validate([folder(container(0)), folder(container(0))]), /twice/);
  assert.throws(
    () => validate([folder('t8-container-24-AAAAAA'), folder('t8-container-24-aaaaaa')]),
    /twice when letter case is ignored/
  );
  assert.throws(
    () => validate([file('a.jsonl'), file('A.jsonl')]),
    /twice when letter case is ignored/
  );
  assert.throws(
    () => validate([file(`${container(0)}.jsonl`), file(`${container(0)}.jsonl/x.jsonl`)]),
    /as a file and as a folder/
  );
});

test('the producer and every consumer of a pack use the same profile: another profile, version, digest, member or schema fails closed', async t => {
  const { entries, platform } = await load();
  const profile = entries.entryProfile('record-pack', 1);
  const dir = temporary(t, 'orbit-entries-producer-');
  fs.writeFileSync(path.join(dir, record(0)), '{}\n');
  const bytes = platform.packRecords(dir);
  const text = bytes.toString('utf8');
  const parsed = JSON.parse(text);
  assert.equal(parsed.schemaVersion, 2);
  assert.deepEqual(parsed.profile, entries.profileIdentity(profile));
  assert.equal(platform.validatePack(bytes).files.length, 1);
  const variant = change => Buffer.from(change(text));
  for (const [label, changed, pattern] of [
    [
      'schema 1',
      variant(s => s.replace('"schemaVersion":2', '"schemaVersion":1')),
      /schema 1, which names no entry profile/,
    ],
    [
      'schema 3',
      variant(s => s.replace('"schemaVersion":2', '"schemaVersion":3')),
      /unknown schema version 3/,
    ],
    [
      'another profile',
      variant(s => s.replace('"name":"record-pack"', '"name":"captured-archive"')),
      /entry profile this reader does not accept: .*pending/,
    ],
    [
      'an unknown profile',
      variant(s => s.replace('"name":"record-pack"', '"name":"record-pack-loose"')),
      /entry profile this reader does not accept: .*unknown/,
    ],
    [
      'another version',
      variant(s => s.replace('"version":1}', '"version":2}')),
      /has no version 2/,
    ],
    [
      'another digest',
      variant(s => s.replace(profile.sha256, '0'.repeat(64))),
      /not the record-pack profile/,
    ],
    [
      'an unknown member',
      variant(s => s.replace('"directories":', '"limits":{},"directories":')),
      /not in the canonical form/,
    ],
    [
      'a member out of order',
      variant(s =>
        s.replace(/^\{"schemaVersion":2,("profile":\{[^}]*\}),/, '{$1,"schemaVersion":2,')
      ),
      /not in the canonical form/,
    ],
    [
      'white space',
      variant(s => s.replace('"schemaVersion":2,', '"schemaVersion": 2,')),
      /not a number|canonical form/,
    ],
    [
      'an escape',
      variant(s => s.replace(record(0), record(0).replace('-', '\\u002d'))),
      /a byte the format does not allow/,
    ],
    [
      'a version with a leading zero',
      variant(s => s.replace('"version":1}', '"version":01}')),
      /a profile version that is not a number/,
    ],
    ['text after the end', variant(s => `${s} `), /continue after their end/],
  ]) {
    assert.throws(() => platform.validatePack(changed), pattern, label);
    // Every reader goes through the same check: unpacking and the finalizer's and guard's path.
    const into = temporary(t, 'orbit-entries-into-');
    assert.throws(() => platform.unpackRecords(changed, into), pattern, label);
    assert.deepEqual(fs.readdirSync(into), [], label);
    let used = false;
    assert.throws(
      () =>
        platform.withUnpackedRecords(changed, () => {
          used = true;
        }),
      pattern,
      label
    );
    assert.equal(used, false, label);
  }
});

test("the pack decoder's memory is bounded: a huge pack is refused at the first entry over a limit, without being read whole", async () => {
  const { entries, platform } = await load();
  const profile = entries.entryProfile('record-pack', 1);
  // verify-1's case at a smaller size: about 25 MB of short folder names, far over the folder
  // limit. The decoder stops at the 8,193rd folder, a few hundred kilobytes in.
  const names = [];
  for (let index = 0; index < 1_000_000; index += 1)
    names.push(`"${container(index % 2176782336)}"`);
  const head = `{"schemaVersion":2,"profile":${JSON.stringify(entries.profileIdentity(profile))},"directories":[`;
  const huge = Buffer.from(`${head}${names.join(',')}],"files":[]}\n`);
  assert.ok(huge.length > 20 * 1024 * 1024);
  let message = '';
  try {
    platform.validatePack(huge);
  } catch (error) {
    message = error.message;
  }
  const match = /more than 8192 directories \(8193\) \(at byte (\d+) of (\d+)\)/.exec(message);
  assert.ok(match, message);
  assert.ok(Number(match[1]) < 300 * 1024, `stopped at byte ${match[1]}`);
  assert.equal(Number(match[2]), huge.length);
  // One byte over the profile's envelope limit is refused before any byte is decoded; a pack of
  // exactly the limit is decoded (and refused for its content, not its size).
  const limit = profile.limits.envelopeBytes;
  const over = Buffer.alloc(limit + 1, 0x20);
  assert.throws(() => platform.validatePack(over), /larger than the record-pack profile allows/);
  const at = Buffer.alloc(limit, 0x20);
  assert.throws(
    () => platform.validatePack(at),
    error => !/larger than/.test(error.message) && /canonical form/.test(error.message)
  );
  // A base64 text longer than the remaining byte limit is refused while it is read.
  const big = `{"schemaVersion":2,"profile":${JSON.stringify(entries.profileIdentity(profile))},"directories":[],"files":[{"path":"${record(0)}","sha256":"${'a'.repeat(64)}","base64":"${'A'.repeat(Math.ceil(profile.limits.bytes / 3) * 4 + 4)}"}]}\n`;
  assert.throws(
    () => platform.validatePack(Buffer.from(big)),
    /a file over the byte limit longer than/
  );
});

test('the Git-export provenance-comment header is a separate narrow rule: no shared profile admits a header or metadata', async () => {
  const { entries } = await load();
  assert.throws(() => entries.entryProfile('git-export', 1), /is unknown/);
  const profile = entries.entryProfile('record-pack', 1);
  for (const type of ['pax-global-header', 'pax-extended-header', 'g', 'x'])
    assert.throws(
      () => entries.validateEntries(profile, [{ path: 'pax_global_header', type, size: 52 }]),
      /not a regular file or directory/
    );
  assert.deepEqual(Object.keys(entries.pendingProfiles), ['captured-archive']);
});
