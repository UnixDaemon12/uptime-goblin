// Sealed records packs (GATE-CONTRACT v4 C21, a draft; security review GD-02; maintainer decision 3): packing
// and unpacking, and so the finalizer and the commit guard, which read packs only through the same
// validator (the record-pack profile of scripts/security-entries.mjs), refuse a pack over any
// limit before anything is written. Files, directories, entries and bytes are decided limits
// (maintainer decision "C21 pack bounds"); the depth of three segments is the starting bound
// the security review of v3 accepted. Each limit is tried exactly at its value (accepted) and one
// over (refused); test/security-entries.test.mjs has the shared validator's own cases. The packs
// are synthetic; nothing here runs a test or a container.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';

const load = () => import('../scripts/security-platform.mjs');
const entries = await import('../scripts/security-entries.mjs');
const profile = entries.profileIdentity(entries.entryProfile('record-pack', 1));
const sha = bytes => createHash('sha256').update(bytes).digest('hex');

function temporary(t, prefix) {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  fs.chmodSync(directory, 0o700);
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

// Container folder names the harness writes (t8-container-<24|26>-<6 letters or digits>), lower
// case only, so that no two collide on a case-insensitive volume.
const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
const container = (index, runtime = '24') => {
  let suffix = '';
  for (let n = index, i = 0; i < 6; i += 1, n = Math.floor(n / 36))
    suffix = alphabet[n % 36] + suffix;
  return `t8-container-${runtime}-${suffix}`;
};
// Record file names the harness writes (<pid>-<uuid>.jsonl).
const record = index =>
  `${index + 1}-${index.toString(16).padStart(8, '0')}-0000-4000-8000-000000000000.jsonl`;
const entry = (name, bytes = Buffer.from('{}\n')) => ({
  path: name,
  sha256: sha(bytes),
  base64: bytes.toString('base64'),
});
/** A canonical pack, as packRecords writes it (schema 2, naming the record-pack profile). */
const pack = (directories, files = []) =>
  Buffer.from(
    `${JSON.stringify({
      schemaVersion: 2,
      profile,
      directories: [...directories].sort(),
      files: [...files].sort((a, b) => (a.path < b.path ? -1 : a.path > b.path ? 1 : 0)),
    })}\n`
  );

/** Unpacks into a new private folder: { error, written } (what the folder holds afterwards). */
function unpack(t, platform, bytes) {
  const into = temporary(t, 'orbit-packs-into-');
  let error = null;
  try {
    platform.unpackRecords(bytes, into);
  } catch (caught) {
    error = caught.message;
  }
  return { error, written: fs.readdirSync(into).length };
}

test('the pack limits are the decided ones, with the accepted starting depth', async () => {
  const platform = await load();
  assert.deepEqual(
    { ...platform.packLimits },
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
  assert.equal(platform.packLimits, entries.entryProfile('record-pack', 1).limits);
  // Each check works on its own (smaller limits only to show that; the gate uses packLimits).
  const limits = { files: 10, directories: 10, entries: 15, bytes: 100, depth: 3 };
  const counts = { files: 5, directories: 5, bytes: 50, depth: 3 };
  assert.deepEqual(platform.packCountProblems(counts, limits), []);
  for (const [change, pattern] of [
    [{ files: 11 }, /more than 10 files \(11\)/],
    [{ directories: 11 }, /more than 10 directories \(11\)/],
    [{ files: 8, directories: 8 }, /more than 15 entries \(16\)/],
    [{ bytes: 101 }, /more than 100 bytes \(101\)/],
    [{ depth: 4 }, /deeper than 3 segments \(4\)/],
  ])
    assert.match(platform.packCountProblems({ ...counts, ...change }, limits).join('; '), pattern);
  assert.deepEqual(
    platform.packCountProblems({ files: 8, directories: 7, bytes: 100, depth: 3 }, limits),
    []
  );
  // With the real limits, 16,384 entries is exactly 8,192 files and 8,192 directories: one more
  // entry is always one over another limit too, and is refused with both reasons.
  assert.deepEqual(
    platform.packCountProblems({ files: 8192, directories: 8192, bytes: 0, depth: 3 }),
    []
  );
  assert.match(
    platform.packCountProblems({ files: 8192, directories: 8193, bytes: 0, depth: 3 }).join('; '),
    /more than 8192 directories.*more than 16384 entries/
  );
});

test('GD-02: many empty directories in a small pack are refused before anything is written', async t => {
  const platform = await load();
  // The security review's fixture: 8,193 valid empty directories, 204,872 bytes in the schema 1 form, which
  // names no entry profile and is refused for that alone now; in schema 2 it is refused by count.
  const schema1 = Buffer.from(
    `${JSON.stringify({ schemaVersion: 1, directories: Array.from({ length: 8193 }, (_, index) => container(index)).sort(), files: [] })}\n`
  );
  assert.equal(schema1.length, 204872);
  assert.match(unpack(t, platform, schema1).error, /schema 1, which names no entry profile/);
  const over = pack(Array.from({ length: 8193 }, (_, index) => container(index)));
  const refused = unpack(t, platform, over);
  assert.match(refused.error, /more than 8192 directories \(8193\)/);
  assert.equal(refused.written, 0);
  assert.throws(() => platform.validatePack(over), /more than 8192 directories/);
  // At the limit: accepted, and every folder written.
  const atLimit = unpack(
    t,
    platform,
    pack(Array.from({ length: 8192 }, (_, index) => container(index)))
  );
  assert.deepEqual(atLimit, { error: null, written: 8192 });
});

test('paths that imply many ancestors count each folder once, listed or not', async t => {
  const platform = await load();
  // 4,096 container folders, each with its records folder and one record: 8,192 folders.
  const nested = count =>
    Array.from({ length: count }, (_, index) => container(index)).flatMap(name => [
      name,
      `${name}/records`,
    ]);
  const files = count =>
    Array.from({ length: count }, (_, index) =>
      entry(`${container(index)}/records/${record(index)}`)
    );
  const atLimit = unpack(t, platform, pack(nested(4096), files(4096)));
  assert.equal(atLimit.error, null);
  assert.equal(atLimit.written, 4096);
  // Listed: the decoder stops at the 8,193rd folder it reads, before it reads the rest.
  const over = unpack(t, platform, pack(nested(4097), files(4097)));
  assert.match(over.error, /more than 8192 directories \(8193\)/);
  assert.equal(over.written, 0);
  // The folders only implied by the files' paths count as well, before they are found unlisted.
  const implied = unpack(t, platform, pack([], files(4097)));
  assert.match(implied.error, /more than 8192 directories \(8194\)/);
  const unlisted = unpack(t, platform, pack([], files(1)));
  assert.match(unlisted.error, /a path inside .* without that folder/);
  assert.equal(unlisted.written, 0);
});

test('files, entries and bytes are refused one over their limit, on unpack and on pack', async t => {
  const platform = await load();
  const topFiles = count => Array.from({ length: count }, (_, index) => entry(record(index)));
  assert.deepEqual(unpack(t, platform, pack([], topFiles(8192))), { error: null, written: 8192 });
  const files = unpack(t, platform, pack([], topFiles(8193)));
  assert.match(files.error, /more than 8192 files \(8193\)/);
  assert.equal(files.written, 0);
  // 16,384 entries: 8,192 files and 8,192 folders, accepted; one more folder refused (with the real
  // values, one entry more is always one over the directory or file limit too, so the entry limit
  // is shown on its own only with smaller limits, in the first test and the shared validator's).
  const folders = count => Array.from({ length: count }, (_, index) => container(index));
  assert.deepEqual(unpack(t, platform, pack(folders(8192), topFiles(8192))), {
    error: null,
    written: 16384,
  });
  const oneMore = unpack(t, platform, pack(folders(8193), topFiles(8192)));
  assert.match(oneMore.error, /more than 8192 directories \(8193\)/);
  assert.equal(oneMore.written, 0);
  // Bytes: one record file of exactly the limit, then one byte more.
  const limit = platform.packLimits.bytes;
  const big = Buffer.alloc(limit, 0x61);
  assert.equal(unpack(t, platform, pack([], [entry(record(0), big)])).error, null);
  const bytes = unpack(t, platform, pack([], [entry(record(0), Buffer.alloc(limit + 1, 0x61))]));
  assert.match(bytes.error, /more than 41943040 bytes|too large/);
  assert.equal(bytes.written, 0);
  // Packing applies the same limits, folder by folder, before reading what is inside.
  const folder = temporary(t, 'orbit-packs-folder-');
  fs.writeFileSync(path.join(folder, record(0)), big);
  assert.equal(platform.validatePack(platform.packRecords(folder)).files.length, 1);
  fs.appendFileSync(path.join(folder, record(0)), 'a');
  assert.throws(
    () => platform.packRecords(folder),
    /larger than 41943040 bytes|more than 41943040 bytes/
  );
  fs.rmSync(path.join(folder, record(0)));
  for (let index = 0; index < 8193; index += 1)
    fs.writeFileSync(path.join(folder, record(index)), '{}\n');
  assert.throws(() => platform.packRecords(folder), /more than 8192 files/);
});

test('packing refuses a folder of more directories than the limit before going inside them', async t => {
  const platform = await load();
  const folder = temporary(t, 'orbit-packs-dirs-');
  for (let index = 0; index < 8192; index += 1) fs.mkdirSync(path.join(folder, container(index)));
  const atLimit = platform.packRecords(folder);
  assert.equal(platform.validatePack(atLimit).directories.length, 8192);
  fs.mkdirSync(path.join(folder, container(8192)));
  assert.throws(() => platform.packRecords(folder), /more than 8192 directories/);
});

test('a path one segment deeper than the proposed depth is refused; three segments are accepted', async t => {
  const platform = await load();
  const name = container(0);
  const three = pack([name, `${name}/records`], [entry(`${name}/records/${record(0)}`)]);
  assert.equal(unpack(t, platform, three).error, null);
  const four = pack(
    [name, `${name}/records`, `${name}/records/deeper`],
    [entry(`${name}/records/deeper/${record(0)}`)]
  );
  const refused = unpack(t, platform, four);
  assert.match(refused.error, /deeper than 3 segments \(4\)/);
  assert.equal(refused.written, 0);
});

test('nothing is written before the whole pack is accepted: a bad last file, a collision or a duplicate writes nothing', async t => {
  const platform = await load();
  const good = Array.from({ length: 5 }, (_, index) => entry(record(index)));
  const bad = { ...entry(record(5)), sha256: '0'.repeat(64) };
  const tampered = unpack(t, platform, pack([container(0)], [...good, bad]));
  assert.match(tampered.error, /does not match its sha256/);
  assert.equal(tampered.written, 0);
  // Two folder names that differ only in letter case are one folder on a case-insensitive volume.
  const collision = unpack(t, platform, pack(['t8-container-24-AAAAAA', 't8-container-24-aaaaaa']));
  assert.match(collision.error, /twice when letter case is ignored/);
  assert.equal(collision.written, 0);
  const twice = unpack(
    t,
    platform,
    Buffer.from(
      `${JSON.stringify({ schemaVersion: 2, profile, directories: [container(0), container(0)], files: [] })}\n`
    )
  );
  assert.match(twice.error, /twice/);
  assert.equal(twice.written, 0);
  // A path that is not text, or a list holding the path, is refused.
  for (const value of [[record(0)], 7])
    assert.throws(
      () =>
        platform.validatePack(
          Buffer.from(
            `${JSON.stringify({ schemaVersion: 2, profile, directories: [], files: [{ ...entry(record(0)), path: value }] })}\n`
          )
        ),
      /not text/
    );
});

test('the finalizer and the commit guard read packs only through the same validator', async t => {
  const platform = await load();
  const over = pack(Array.from({ length: 8193 }, (_, index) => container(index)));
  let used = false;
  assert.throws(
    () =>
      platform.withUnpackedRecords(over, () => {
        used = true;
      }),
    /more than 8192 directories/
  );
  assert.equal(used, false);
  // stageCoverage, which the finalizer and the guard run on every sealed test stage.
  const fixture = await import('./helpers/platform-run.mjs');
  const manifest = fixture.syntheticManifest();
  assert.throws(
    () =>
      platform.stageCoverage({
        manifest,
        manifestSha256: sha(fixture.manifestText(manifest)),
        runId: 'linux-full',
        runtime: '26',
        tap: '',
        pack: over,
        nonce: 'a'.repeat(64),
        allFiles: fixture.testFiles,
      }),
    /more than 8192 directories/
  );
  assert.ok(t);
});
