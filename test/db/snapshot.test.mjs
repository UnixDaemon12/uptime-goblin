// Snapshots of the data directory (lib/db/snapshot.mjs): consistent copies with checksums, the
// pinned way back to 1.4.x, retention, and restores that never lose a file.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { spawnSync } from 'node:child_process';
import {
  createSnapshot,
  listSnapshots,
  verifySnapshot,
  deleteSnapshot,
  pruneSnapshots,
  restoreSnapshot,
  isPre15,
  SnapshotError,
  snapshotsDirectory,
  interruptedRestore,
  restoreJournal,
  restoreTemporaries,
  removeRestoreLeftovers,
  removeEmptyRestoreFolders,
  unchangedSince,
} from '../../lib/db/snapshot.mjs';
import { acquireLock } from '../../lib/db/lock.mjs';
import { startControl } from '../../lib/db/control.mjs';
import { quickCheck } from '../../lib/db/sqlite.mjs';
import { temporary, mode, manualClock, fingerprint as fingerprintOf } from './helpers.mjs';

const day = 24 * 3600 * 1000;

// A data directory as Uptime Goblin leaves it: config, auth, and two WAL databases, one still open.
function dataDirectory(t) {
  const directory = temporary(t);
  fs.writeFileSync(path.join(directory, 'config.json'), '{"services":["a"]}\n', { mode: 0o600 });
  fs.writeFileSync(path.join(directory, 'auth.json'), '{"version":1}\n', { mode: 0o600 });
  const control = new DatabaseSync(path.join(directory, 'control.sqlite'));
  control.exec(
    "PRAGMA journal_mode=WAL; CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL); INSERT INTO meta VALUES ('who', 'before', 1)"
  );
  control.close();
  const history = new DatabaseSync(path.join(directory, 'history.sqlite'));
  history.exec(
    "PRAGMA journal_mode=WAL; CREATE TABLE readings (service TEXT, time INTEGER); INSERT INTO readings VALUES ('a', 1)"
  );
  t.after(() => history.isOpen && history.close());
  return { directory, history };
}
const read = (file, sqlText) => {
  const db = new DatabaseSync(file, { readOnly: true });
  try {
    return db.prepare(sqlText).all();
  } finally {
    db.close();
  }
};
const who = file => read(file, "SELECT value FROM meta WHERE key = 'who'")[0].value;
const locked = (t, directory) => {
  const lock = acquireLock(directory);
  t.after(() => lock.release());
  return lock;
};

test('createSnapshot copies the managed files consistently, with a manifest of checksums', async t => {
  const { directory, history } = dataDirectory(t);
  // Rows still only in the WAL of an open connection are in the copy.
  history.exec("INSERT INTO readings VALUES ('b', 2)");
  fs.writeFileSync(path.join(directory, 'secret.key'), 'a1'.repeat(32));
  const clock = manualClock(Date.UTC(2026, 8, 1, 12, 30, 45, 678));
  const snapshot = await createSnapshot(directory, { reason: 'manual', release: '1.5.0', clock });
  assert.equal(snapshot.id, 'manual-1.5.0-20260901T123045678Z');
  assert.equal(snapshot.path, path.join(directory, snapshotsDirectory, snapshot.id));
  assert.equal(mode(path.join(directory, snapshotsDirectory)), 0o700);
  assert.equal(mode(snapshot.path), 0o700);
  const files = fs.readdirSync(snapshot.path).sort();
  assert.deepEqual(files, [
    'auth.json',
    'config.json',
    'control.sqlite',
    'history.sqlite',
    'manifest.json',
  ]);
  for (const file of files) assert.equal(mode(path.join(snapshot.path, file)), 0o600, file);
  assert.equal(snapshot.manifest.pinned, false, 'a manual snapshot is not pinned');
  assert.deepEqual(snapshot.manifest.absent, []);
  assert.ok(snapshot.manifest.files.every(file => /^[0-9a-f]{64}$/.test(file.sha256)));
  assert.equal(
    read(path.join(snapshot.path, 'history.sqlite'), 'SELECT COUNT(*) AS n FROM readings')[0].n,
    2
  );
  assert.equal(
    read(path.join(snapshot.path, 'history.sqlite'), 'PRAGMA journal_mode')[0].journal_mode,
    'delete'
  );
  // Keys and the lock never enter a snapshot.
  assert.ok(
    !files.includes('secret.key') && !files.includes('goblin.lock') && !files.includes('orbit.lock')
  );
  // A second snapshot in the same millisecond gets its own id.
  const second = await createSnapshot(directory, { reason: 'manual', release: '1.5.0', clock });
  assert.equal(second.id, `${snapshot.id}-2`);
  assert.deepEqual(
    listSnapshots(directory).map(item => item.id),
    [second.id, snapshot.id]
  );
  assert.deepEqual((await verifySnapshot(directory, snapshot.id)).problems, []);
  await assert.rejects(
    createSnapshot(directory, { reason: 'Bad Reason' }),
    error => error instanceof SnapshotError && error.code === 'snapshot_reason'
  );
  // history: false leaves it out and records that.
  const lean = await createSnapshot(directory, { release: '1.5.0', history: false, clock });
  assert.ok(!lean.manifest.files.some(file => file.name === 'history.sqlite'));
  assert.deepEqual(lean.manifest.excluded, ['history.sqlite']);
});

test('the first pre-upgrade snapshot of data from before 1.5 is pinned; deleting it needs --force', async t => {
  const { directory } = dataDirectory(t);
  fs.rmSync(path.join(directory, 'control.sqlite'));
  assert.equal(isPre15(null), true);
  assert.equal(isPre15('1.4.3'), true);
  assert.equal(isPre15('1.5.0'), false);
  // A pre-release compares as its core release, so data a 1.5 pre-release wrote is never taken
  // for 1.4.x data (and pinned again).
  assert.equal(isPre15('1.5.0-dev.0'), false);
  assert.equal(isPre15('1.5.0-rc.1'), false);
  assert.equal(isPre15('1.4.3-rc.1'), true);
  const clock = manualClock();
  const pinned = await createSnapshot(directory, {
    reason: 'pre-upgrade',
    release: '1.5.0',
    fromRelease: null,
    clock,
  });
  assert.equal(pinned.manifest.pinned, true);
  assert.deepEqual(pinned.manifest.absent, ['control.sqlite']);
  clock.advance(1000);
  const later = await createSnapshot(directory, {
    reason: 'pre-upgrade',
    release: '1.5.0',
    fromRelease: null,
    clock,
  });
  assert.equal(later.manifest.pinned, false, 'only one pinned snapshot');
  assert.throws(
    () => deleteSnapshot(directory, pinned.id),
    error => error.code === 'snapshot_pinned' && /way back to Orbit 1\.4\.x/.test(error.message)
  );
  deleteSnapshot(directory, later.id);
  assert.throws(() => deleteSnapshot(directory, later.id), { code: 'snapshot_unknown' });
  assert.throws(() => deleteSnapshot(directory, '../escape'), { code: 'snapshot_unknown' });
  deleteSnapshot(directory, pinned.id, { force: true });
  assert.deepEqual(listSnapshots(directory), []);
});

test('verifySnapshot finds altered, missing and damaged files; a broken manifest lists as invalid', async t => {
  const { directory } = dataDirectory(t);
  const snapshot = await createSnapshot(directory, { release: '1.5.0' });
  fs.appendFileSync(path.join(snapshot.path, 'config.json'), ' ');
  fs.rmSync(path.join(snapshot.path, 'auth.json'));
  const result = await verifySnapshot(directory, snapshot.id);
  assert.equal(result.ok, false);
  assert.deepEqual(result.problems, [
    'config.json does not match its checksum',
    'auth.json is missing',
  ]);
  const broken = path.join(directory, snapshotsDirectory, 'manual-1.5.0-20260101T000000Z');
  fs.mkdirSync(broken);
  fs.writeFileSync(path.join(broken, 'manifest.json'), '{not json');
  const listed = listSnapshots(directory).find(item => item.id === path.basename(broken));
  assert.equal(listed.valid, false);
  assert.equal((await verifySnapshot(directory, path.basename(broken))).ok, false);
  await assert.rejects(verifySnapshot(directory, 'not an id'), { code: 'snapshot_unknown' });
});

// A table whose index no longer matches it: the index definition is swapped to another column
// through writable_schema, so its entries (built for column a) disagree with what it now names
// (column b). quick_check does not compare index entries with their table and passes it;
// integrity_check reports each row missing from the index.
function swapIndexDefinition(file) {
  const db = new DatabaseSync(file, { defensive: false });
  try {
    db.exec('CREATE TABLE swapped (a INTEGER, b INTEGER); CREATE INDEX swapped_a ON swapped (a)');
    const insert = db.prepare('INSERT INTO swapped VALUES (?, ?)');
    for (let n = 1; n <= 50; n += 1) insert.run(n, 1000 - n);
    db.exec('PRAGMA writable_schema=ON');
    db.exec(
      "UPDATE sqlite_master SET sql = 'CREATE INDEX swapped_a ON swapped (b)' WHERE name = 'swapped_a'"
    );
  } finally {
    db.close();
  }
}
// The manifest of snapshot `id` made to match its (altered) copy of `name`.
function rehash(directory, id, name) {
  const folder = path.join(directory, snapshotsDirectory, id);
  const manifestFile = path.join(folder, 'manifest.json');
  const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));
  const entry = manifest.files.find(file => file.name === name);
  const bytes = fs.readFileSync(path.join(folder, name));
  entry.bytes = bytes.length;
  entry.sha256 = fingerprintOf(folder, ['manifest.json'])[name];
  fs.writeFileSync(manifestFile, JSON.stringify(manifest));
}

// IUR-03: the copy was hashed but never checked, so a damaged live database left a snapshot
// that restoreSnapshot (verifySnapshot) then refused: the way back was found useless only when
// it was needed.
test('createSnapshot refuses a damaged live database (exit status 78) and leaves nothing in snapshots/', async t => {
  const { directory } = dataDirectory(t);
  swapIndexDefinition(path.join(directory, 'control.sqlite'));
  await assert.rejects(
    createSnapshot(directory, { reason: 'pre-upgrade', release: '1.5.1', fromRelease: '1.5.0' }),
    error =>
      error instanceof SnapshotError &&
      error.code === 'live_database_damaged' &&
      error.refusal === true &&
      error.file === 'control.sqlite' &&
      /^No snapshot was taken: control\.sqlite in the data directory is damaged \(row \d+ missing from index swapped_a/.test(
        error.message
      ) &&
      /Restore an earlier snapshot \(goblin-admin restore-snapshot\) or a backup before you upgrade or migrate/.test(
        error.message
      )
  );
  assert.deepEqual(fs.readdirSync(path.join(directory, snapshotsDirectory)), []);
  assert.deepEqual(listSnapshots(directory), []);
});

// BR-5: quick_check alone passed a copy whose index disagrees with its table, and the restore
// brought it back.
test('verifySnapshot runs integrity_check: an index that disagrees with its table fails verification and refuses the restore', async t => {
  const { directory, history } = dataDirectory(t);
  history.close();
  const snapshot = await createSnapshot(directory, { release: '1.5.0' });
  const copy = path.join(snapshot.path, 'history.sqlite');
  swapIndexDefinition(copy);
  rehash(directory, snapshot.id, 'history.sqlite');
  assert.equal(quickCheck(copy), 'ok', 'quick_check alone passes it');
  const result = await verifySnapshot(directory, snapshot.id);
  assert.equal(result.ok, false);
  assert.equal(result.problems.length, 1);
  assert.match(result.problems[0], /^history\.sqlite: row \d+ missing from index swapped_a/);
  const before = fingerprintOf(directory, [snapshotsDirectory, 'goblin.lock', 'orbit.lock']);
  await assert.rejects(
    restoreSnapshot(directory, snapshot.id, { lock: locked(t, directory) }),
    error =>
      error.code === 'snapshot_damaged' &&
      error.message.startsWith(`Snapshot ${snapshot.id} cannot be restored: history.sqlite: row `)
  );
  assert.deepEqual(
    fingerprintOf(directory, [snapshotsDirectory, 'goblin.lock', 'orbit.lock']),
    before
  );
});

// BR-4: goblin-admin snapshots --delete calls deleteSnapshot, which never removes what an
// interrupted restore still needs.
test('deleteSnapshot refuses the snapshots an interrupted restore needs, and every one while its journal cannot be read', async t => {
  const { directory } = dataDirectory(t);
  const clock = manualClock();
  const ids = [];
  for (let n = 0; n < 5; n += 1) {
    ids.push((await createSnapshot(directory, { release: '1.5.0', clock })).id);
    clock.advance(1000);
  }
  const [restoring, aside, kept, carried, free] = ids;
  const journal = path.join(directory, snapshotsDirectory, restoreJournal);
  fs.writeFileSync(
    journal,
    JSON.stringify({
      snapshot: restoring,
      aside,
      files: ['config.json'],
      keepHistory: true,
      copies: {},
      kept: [kept],
      absent: [],
      unfinished: { snapshot: carried, aside: carried, files: ['auth.json'], kept: [] },
    })
  );
  for (const id of [restoring, aside, kept, carried])
    for (const force of [false, true])
      assert.throws(
        () => deleteSnapshot(directory, id, { force }),
        error =>
          error.code === 'snapshot_needed' &&
          error.message ===
            `${id} was not deleted: the interrupted restore of ${restoring} needs it. Run that restore again to finish it (goblin-admin restore-snapshot ${restoring} --keep-history), then delete the snapshot.`,
        id
      );
  deleteSnapshot(directory, free);
  fs.writeFileSync(journal, '{not json');
  assert.throws(
    () => deleteSnapshot(directory, aside),
    error => error.code === 'snapshot_needed' && /record .* cannot be read/.test(error.message)
  );
  fs.rmSync(journal);
  deleteSnapshot(directory, aside);
  assert.deepEqual(
    listSnapshots(directory)
      .map(item => item.id)
      .sort(),
    [restoring, kept, carried].sort()
  );
});

test('pruneSnapshots keeps 3 pre-upgrade snapshots plus the pinned one, and pre-restore ones for 7 days', async t => {
  const { directory } = dataDirectory(t);
  const clock = manualClock();
  const make = async (reason, fromRelease = '1.5.0') => {
    clock.advance(60_000);
    return (await createSnapshot(directory, { reason, release: '1.5.1', fromRelease, clock })).id;
  };
  const pinned = await make('pre-upgrade', null);
  const upgrades = [];
  for (let i = 0; i < 5; i += 1) upgrades.push(await make('pre-upgrade'));
  const manual = await make('manual');
  const restore = await make('pre-restore');
  // A staging leftover from a crash, and an interrupted restore.
  const root = path.join(directory, snapshotsDirectory);
  fs.mkdirSync(path.join(root, '.staging-manual-1.5.1-x'));
  fs.mkdirSync(path.join(root, '.restoring-pre-restore-1.5.1-x'));
  fs.writeFileSync(path.join(root, '.restoring-pre-restore-1.5.1-x', 'config.json'), '{}');
  const removed = pruneSnapshots(directory, { now: clock() });
  assert.deepEqual(removed.sort(), upgrades.slice(0, 2).sort());
  const kept = listSnapshots(directory).map(item => item.id);
  for (const id of [pinned, manual, restore, ...upgrades.slice(2)]) assert.ok(kept.includes(id));
  // A day later nothing more goes; after 7 days the pre-restore snapshot and the staging
  // leftover go, but never the interrupted restore.
  assert.deepEqual(pruneSnapshots(directory, { now: clock() + day }), []);
  const staging = path.join(root, '.staging-manual-1.5.1-x');
  fs.utimesSync(staging, new Date(clock() - day), new Date(clock() - day));
  assert.deepEqual(
    pruneSnapshots(directory, { now: clock() + 8 * day }).sort(),
    ['.staging-manual-1.5.1-x', restore].sort()
  );
  const interrupted = listSnapshots(directory).find(item => item.interrupted);
  assert.equal(interrupted.id, '.restoring-pre-restore-1.5.1-x');
  assert.match(interrupted.problem, /interrupted restore/);
  assert.ok(fs.existsSync(path.join(root, interrupted.id, 'config.json')));
});

test('restoreSnapshot needs the lock, swaps the files in, and keeps the replaced ones as a pre-restore snapshot', async t => {
  const { directory, history } = dataDirectory(t);
  history.close();
  const clock = manualClock();
  const snapshot = await createSnapshot(directory, { release: '1.5.0', clock });
  // The data changes after the snapshot: a new config, a new database row, a new file.
  fs.writeFileSync(path.join(directory, 'config.json'), '{"services":["a","b"]}\n');
  const control = new DatabaseSync(path.join(directory, 'control.sqlite'));
  control.exec("UPDATE meta SET value = 'after' WHERE key = 'who'");
  control.close();
  await assert.rejects(
    restoreSnapshot(directory, snapshot.id, {}),
    error => error.code === 'snapshot_unlocked'
  );
  const lock = locked(t, directory);
  clock.advance(1000);
  const result = await restoreSnapshot(directory, snapshot.id, { lock, release: '1.5.0', clock });
  assert.deepEqual(result.restored, [
    'config.json',
    'auth.json',
    'control.sqlite',
    'history.sqlite',
  ]);
  assert.deepEqual(result.removed, []);
  assert.equal(
    fs.readFileSync(path.join(directory, 'config.json'), 'utf8'),
    '{"services":["a"]}\n'
  );
  assert.equal(who(path.join(directory, 'control.sqlite')), 'before');
  assert.equal(mode(path.join(directory, 'config.json')), 0o600);
  // No temporary or sidecar files are left in the data directory.
  assert.deepEqual(fs.readdirSync(directory).sort(), [
    'auth.json',
    'config.json',
    'control.sqlite',
    'goblin.lock',
    'history.sqlite',
    'orbit.lock',
    'snapshots',
  ]);
  // The replaced files form a complete pre-restore snapshot, and restoring it undoes the restore.
  const aside = listSnapshots(directory).find(item => item.id === result.aside);
  assert.equal(aside.reason, 'pre-restore');
  assert.equal((await verifySnapshot(directory, result.aside)).ok, true);
  assert.equal(
    who(path.join(directory, snapshotsDirectory, result.aside, 'control.sqlite')),
    'after'
  );
  await restoreSnapshot(directory, result.aside, { lock, release: '1.5.0', clock });
  assert.equal(who(path.join(directory, 'control.sqlite')), 'after');
  assert.match(fs.readFileSync(path.join(directory, 'config.json'), 'utf8'), /"b"/);
});

test('restoring a pre-1.5 snapshot removes control.sqlite; history can be kept as it is', async t => {
  const { directory, history } = dataDirectory(t);
  history.close();
  const control = path.join(directory, 'control.sqlite');
  fs.renameSync(control, path.join(directory, 'hold.sqlite'));
  const clock = manualClock();
  const pinned = await createSnapshot(directory, {
    reason: 'pre-upgrade',
    release: '1.5.0',
    clock,
  });
  fs.renameSync(path.join(directory, 'hold.sqlite'), control);
  // History grows after the upgrade.
  const writer = new DatabaseSync(path.join(directory, 'history.sqlite'));
  writer.exec("INSERT INTO readings VALUES ('new', 9)");
  writer.close();
  const lock = locked(t, directory);
  clock.advance(1000);
  const result = await restoreSnapshot(directory, pinned.id, {
    lock,
    history: false,
    release: '1.5.0',
    clock,
  });
  assert.deepEqual(result.restored, ['config.json', 'auth.json']);
  assert.deepEqual(result.removed, ['control.sqlite']);
  assert.equal(fs.existsSync(control), false, 'back to the 1.4.x layout');
  assert.equal(
    read(path.join(directory, 'history.sqlite'), 'SELECT COUNT(*) AS n FROM readings')[0].n,
    2,
    'history kept as it is'
  );
  const aside = listSnapshots(directory).find(item => item.id === result.aside);
  assert.deepEqual(aside.files.sort(), ['auth.json', 'config.json', 'control.sqlite']);
});

test('a damaged snapshot or a failed copy changes nothing in the data directory', async t => {
  const { directory, history } = dataDirectory(t);
  history.close();
  const snapshot = await createSnapshot(directory, { release: '1.5.0' });
  const lock = locked(t, directory);
  const before = fs.readdirSync(directory).sort();
  const config = fs.readFileSync(path.join(directory, 'config.json'), 'utf8');
  fs.appendFileSync(path.join(snapshot.path, 'history.sqlite'), 'x');
  await assert.rejects(
    restoreSnapshot(directory, snapshot.id, { lock }),
    error => error.code === 'snapshot_damaged' && /history\.sqlite/.test(error.message)
  );
  assert.deepEqual(fs.readdirSync(directory).sort(), before);
  // A copy that fails part-way (a temporary name already taken by a directory) is cleaned up.
  const fresh = await createSnapshot(directory, { release: '1.5.0', history: false });
  fs.mkdirSync(path.join(directory, '.control.sqlite.restoring'));
  await assert.rejects(restoreSnapshot(directory, fresh.id, { lock }));
  fs.rmdirSync(path.join(directory, '.control.sqlite.restoring'));
  assert.deepEqual(fs.readdirSync(directory).sort(), before);
  assert.equal(fs.readFileSync(path.join(directory, 'config.json'), 'utf8'), config);
  assert.ok(!listSnapshots(directory).some(item => item.reason === 'pre-restore'));
});

test('restoreSnapshot stamps meta.restored into the restored control.sqlite, leaving no -wal or -shm (D25)', async t => {
  const { directory, history } = dataDirectory(t);
  history.close();
  const clock = manualClock();
  const snapshot = await createSnapshot(directory, { release: '1.5.0-dev.0', clock });
  const lock = locked(t, directory);
  clock.advance(5000);
  const result = await restoreSnapshot(directory, snapshot.id, {
    lock,
    release: '1.5.0-dev.0',
    clock,
  });
  const file = path.join(directory, 'control.sqlite');
  const restored = read(file, "SELECT value, updated_at FROM meta WHERE key = 'restored'");
  assert.equal(restored.length, 1);
  assert.deepEqual(JSON.parse(restored[0].value), { snapshot: snapshot.id, at: clock() });
  assert.equal(restored[0].updated_at, clock());
  assert.equal(who(file), 'before', 'the rest of the database is the snapshot');
  assert.equal(mode(file), 0o600);
  for (const suffix of ['-wal', '-shm', '-journal'])
    assert.equal(fs.existsSync(file + suffix), false, suffix);
  assert.ok(!fs.readdirSync(directory).some(name => name.includes('.restoring')));
  // The snapshot itself is unchanged (it still verifies), and the pre-restore aside snapshot is
  // not stamped: restoring it later stamps it then.
  assert.equal((await verifySnapshot(directory, snapshot.id)).ok, true);
  const aside = path.join(directory, snapshotsDirectory, result.aside, 'control.sqlite');
  assert.deepEqual(read(aside, "SELECT value FROM meta WHERE key = 'restored'"), []);
  clock.advance(5000);
  await restoreSnapshot(directory, result.aside, { lock, release: '1.5.0-dev.0', clock });
  assert.deepEqual(
    JSON.parse(read(file, "SELECT value FROM meta WHERE key = 'restored'")[0].value),
    { snapshot: result.aside, at: clock() }
  );
});

test('restoreSnapshot stamps only a control database that has a meta table', async t => {
  const directory = temporary(t);
  fs.writeFileSync(path.join(directory, 'config.json'), '{"services":[]}\n');
  const bare = new DatabaseSync(path.join(directory, 'control.sqlite'));
  bare.exec("CREATE TABLE other (a TEXT); INSERT INTO other VALUES ('x')");
  bare.close();
  const snapshot = await createSnapshot(directory, { release: '1.5.0' });
  const lock = locked(t, directory);
  await restoreSnapshot(directory, snapshot.id, { lock, release: '1.5.0' });
  const tables = read(
    path.join(directory, 'control.sqlite'),
    "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
  ).map(row => row.name);
  assert.deepEqual(tables, ['other'], 'no meta table was created');
});

test('a stamping failure changes nothing in the data directory', async t => {
  const { directory, history } = dataDirectory(t);
  history.close();
  // A meta table without the columns Uptime Goblin writes: the upsert fails during step 1.
  const control = path.join(directory, 'control.sqlite');
  fs.rmSync(control);
  for (const suffix of ['-wal', '-shm']) fs.rmSync(control + suffix, { force: true });
  const odd = new DatabaseSync(control);
  odd.exec("CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT); INSERT INTO meta VALUES ('who', 'x')");
  odd.close();
  const snapshot = await createSnapshot(directory, { release: '1.5.0', history: false });
  fs.writeFileSync(path.join(directory, 'config.json'), '{"services":["changed"]}\n');
  const lock = locked(t, directory);
  const skip = ['goblin.lock', 'orbit.lock'];
  const before = fingerprintOf(directory, skip);
  await assert.rejects(restoreSnapshot(directory, snapshot.id, { lock, release: '1.5.0' }));
  assert.deepEqual(fingerprintOf(directory, skip), before, 'no byte changed, no temporary left');
  assert.ok(!listSnapshots(directory).some(item => item.reason === 'pre-restore'));
  assert.ok(!listSnapshots(directory).some(item => item.interrupted));
});

test('a restore interrupted part way leaves its journal until a restore finishes what it replaced', async t => {
  const { directory, history } = dataDirectory(t);
  history.close();
  const clock = manualClock();
  const lock = locked(t, directory);
  const wide = await createSnapshot(directory, { release: '1.5.0', clock });
  clock.advance(1000);
  const narrow = await createSnapshot(directory, { release: '1.5.0', history: false, clock });
  const journal = path.join(directory, snapshotsDirectory, restoreJournal);
  assert.equal(interruptedRestore(directory), null);
  // Interrupted after history.sqlite was moved aside, before its copy took its place.
  const rename = fs.renameSync;
  t.after(() => (fs.renameSync = rename));
  fs.renameSync = function (from, to) {
    if (String(from).endsWith('.history.sqlite.restoring')) throw new Error('power lost');
    return rename.call(this, from, to);
  };
  clock.advance(1000);
  await assert.rejects(restoreSnapshot(directory, wide.id, { lock, release: '1.5.0', clock }), {
    message: 'power lost',
  });
  fs.renameSync = rename;
  assert.equal(fs.existsSync(path.join(directory, 'history.sqlite')), false);
  assert.deepEqual(interruptedRestore(directory), {
    snapshot: wide.id,
    aside: interruptedRestore(directory).aside,
    files: ['config.json', 'auth.json', 'control.sqlite', 'history.sqlite'],
    keepHistory: false,
  });
  // Another restore that leaves history.sqlite alone does not finish it: the journal stays,
  // naming what is left, and the result says so.
  clock.advance(1000);
  const other = await restoreSnapshot(directory, narrow.id, { lock, release: '1.5.0', clock });
  assert.deepEqual(other.unfinished.files, ['history.sqlite']);
  assert.equal(other.unfinished.snapshot, wide.id);
  assert.equal(interruptedRestore(directory).snapshot, wide.id);
  // Running the interrupted restore again finishes it, and the journal goes.
  clock.advance(1000);
  const again = await restoreSnapshot(directory, wide.id, { lock, release: '1.5.0', clock });
  assert.equal(again.unfinished, null);
  assert.equal(fs.existsSync(journal), false);
  assert.equal(interruptedRestore(directory), null);
  assert.deepEqual(
    read(path.join(directory, 'history.sqlite'), 'SELECT service FROM readings').map(
      row => row.service
    ),
    ['a']
  );
  // A completed restore never leaves a journal; the journal file is not a snapshot.
  clock.advance(1000);
  await restoreSnapshot(directory, narrow.id, { lock, release: '1.5.0', clock });
  assert.equal(fs.existsSync(journal), false);
  assert.ok(!listSnapshots(directory).some(item => item.id === restoreJournal));
});

// A disk error leaves a database unreadable: its first bytes are no longer SQLite's header.
function damage(file) {
  const handle = fs.openSync(file, 'r+');
  try {
    fs.writeSync(handle, Buffer.from('this is no SQLite header at all'), 0, 31, 0);
  } finally {
    fs.closeSync(handle);
  }
}

test('a restore over a damaged database completes: the damaged file moves aside as it was, with its WAL', async t => {
  // A damaged live database is often why a snapshot is restored. It cannot be settled (its WAL
  // folded in); stopping there left the journal behind, so Uptime Goblin refused to start, and the
  // re-run its refusal asks for stopped on the same file (§16 C10).
  for (const name of ['control.sqlite', 'history.sqlite']) {
    const { directory, history } = dataDirectory(t);
    history.close();
    const clock = manualClock();
    const lock = locked(t, directory);
    const snapshot = await createSnapshot(directory, { release: '1.5.0', clock });
    const live = path.join(directory, name);
    damage(live);
    fs.writeFileSync(`${live}-wal`, 'frames the damaged database still had');
    const damagedBytes = fs.readFileSync(live);
    clock.advance(1000);
    const result = await restoreSnapshot(directory, snapshot.id, {
      lock,
      release: '1.5.0',
      clock,
    });
    assert.equal(result.damaged.length, 1, name);
    assert.equal(result.damaged[0].name, name);
    assert.match(result.damaged[0].problem, /file is not a database/);
    assert.equal(result.unfinished, null);
    assert.equal(interruptedRestore(directory), null, 'no journal: Uptime Goblin may start');
    assert.ok(!listSnapshots(directory).some(item => item.interrupted));
    // The snapshot's database is in place, readable, with no WAL beside it.
    if (name === 'control.sqlite') assert.equal(who(live), 'before');
    else
      assert.deepEqual(
        read(live, 'SELECT service FROM readings').map(row => row.service),
        ['a']
      );
    assert.equal(fs.existsSync(`${live}-wal`), false);
    // The damaged file and its WAL are kept, byte for byte, in the pre-restore snapshot, which
    // says so and cannot be restored as a whole.
    const aside = path.join(directory, snapshotsDirectory, result.aside);
    assert.deepEqual(fs.readFileSync(path.join(aside, name)), damagedBytes);
    assert.equal(
      fs.readFileSync(path.join(aside, `${name}-wal`), 'utf8'),
      'frames the damaged database still had'
    );
    assert.equal(mode(path.join(aside, `${name}-wal`)), 0o600);
    const manifest = JSON.parse(fs.readFileSync(path.join(aside, 'manifest.json'), 'utf8'));
    assert.deepEqual(
      manifest.damaged.map(item => [item.name, item.sidecars]),
      [[name, [`${name}-wal`]]]
    );
    const verified = await verifySnapshot(directory, result.aside);
    assert.equal(verified.ok, false);
    assert.deepEqual(verified.problems, [`${name}: file is not a database`]);
    await assert.rejects(
      restoreSnapshot(directory, result.aside, { lock, release: '1.5.0', clock }),
      error => error.code === 'snapshot_damaged'
    );
  }
});

test('running an interrupted restore again keeps what the directory held before it as the undo', async t => {
  // The first attempt moved config.json and auth.json aside and put the snapshot's copies in
  // their place, then stopped (a crash) with control.sqlite still in place (damaged, in the
  // second round). Running the same restore again, as Uptime Goblin's refusal says, must finish it, and
  // its pre-restore snapshot must hold what the data directory held before the first attempt,
  // not the first attempt's copies of the snapshot (§16 C10).
  for (const damaged of [false, true]) {
    const { directory, history } = dataDirectory(t);
    history.close();
    const clock = manualClock();
    const lock = locked(t, directory);
    const snapshot = await createSnapshot(directory, { release: '1.5.0', clock });
    fs.writeFileSync(path.join(directory, 'auth.json'), '{"version":1,"p":"changed since"}\n');
    fs.writeFileSync(path.join(directory, 'config.json'), '{"services":["a","b"]}\n');
    const control = path.join(directory, 'control.sqlite');
    if (damaged) damage(control);
    const before = {
      'auth.json': fs.readFileSync(path.join(directory, 'auth.json')),
      'config.json': fs.readFileSync(path.join(directory, 'config.json')),
      ...(damaged ? { 'control.sqlite': fs.readFileSync(control) } : {}),
    };
    const rename = fs.renameSync;
    fs.renameSync = function (from, to) {
      if (String(from) === control) throw new Error('power lost');
      return rename.call(this, from, to);
    };
    clock.advance(1000);
    try {
      await assert.rejects(
        restoreSnapshot(directory, snapshot.id, { lock, release: '1.5.0', clock }),
        { message: 'power lost' }
      );
    } finally {
      fs.renameSync = rename;
    }
    const first = interruptedRestore(directory);
    assert.equal(first.snapshot, snapshot.id);
    assert.equal(
      fs.readFileSync(path.join(directory, 'auth.json'), 'utf8'),
      '{"version":1}\n',
      'the first attempt put the snapshot’s copy in place'
    );
    clock.advance(1000);
    const again = await restoreSnapshot(directory, snapshot.id, {
      lock,
      release: '1.5.0',
      clock,
    });
    assert.equal(again.aside, first.aside, 'it continued in the first attempt’s folder');
    assert.deepEqual(
      again.damaged.map(item => item.name),
      damaged ? ['control.sqlite'] : []
    );
    assert.equal(interruptedRestore(directory), null);
    assert.ok(!listSnapshots(directory).some(item => item.interrupted), 'no folder left behind');
    assert.equal(who(control), 'before');
    // The undo holds the data directory as it was before the first attempt.
    const aside = path.join(directory, snapshotsDirectory, again.aside);
    for (const [name, bytes] of Object.entries(before))
      assert.deepEqual(fs.readFileSync(path.join(aside, name)), bytes, name);
    if (!damaged) {
      // Restoring it gives back the password and settings of before the restore.
      await restoreSnapshot(directory, again.aside, { lock, release: '1.5.0', clock });
      assert.equal(
        fs.readFileSync(path.join(directory, 'auth.json'), 'utf8'),
        '{"version":1,"p":"changed since"}\n'
      );
      assert.equal(
        fs.readFileSync(path.join(directory, 'config.json'), 'utf8'),
        '{"services":["a","b"]}\n'
      );
    }
  }
});

// The temporary copies of a restore in the data directory: .<file>.restoring and its sidecars.
const hiddenCopies = directory =>
  fs
    .readdirSync(directory)
    .filter(name => /^\..+\.restoring(?:-wal|-shm|-journal)?$/.test(name))
    .sort();

test('restoreTemporaries lists the copies a restore left; those a journal names are never removed', async t => {
  const { directory, history } = dataDirectory(t);
  history.close();
  const write = (name, bytes) =>
    fs.writeFileSync(path.join(directory, name), Buffer.alloc(bytes, 1), { mode: 0o600 });
  assert.deepEqual(restoreTemporaries(directory), []);
  assert.deepEqual(restoreTemporaries(path.join(directory, 'missing')), []);
  write('.history.sqlite.restoring', 3000);
  write('.control.sqlite.restoring', 1000);
  write('.control.sqlite.restoring-wal', 500);
  // Not a restore's copies: other names, and anything but a plain file.
  write('.secret.key.restoring', 10);
  write('history.sqlite.restoring', 10);
  fs.mkdirSync(path.join(directory, '.auth.json.restoring'));
  assert.deepEqual(
    restoreTemporaries(directory).map(item => [
      item.file,
      item.id,
      item.names,
      item.bytes,
      item.needed,
      item.snapshot,
    ]),
    [
      [
        'control.sqlite',
        '.control.sqlite.restoring',
        ['.control.sqlite.restoring', '.control.sqlite.restoring-wal'],
        1500,
        false,
        null,
      ],
      [
        'history.sqlite',
        '.history.sqlite.restoring',
        ['.history.sqlite.restoring'],
        3000,
        false,
        null,
      ],
    ]
  );
  // While an interrupted restore's journal names history.sqlite, its copy is that restore's.
  const journal = path.join(directory, snapshotsDirectory, restoreJournal);
  fs.mkdirSync(path.dirname(journal), { recursive: true });
  const record = JSON.stringify({
    snapshot: 'manual-1.5.0-20260901T000000Z',
    aside: 'pre-restore-1.5.0-20260901T000001Z',
    files: ['history.sqlite'],
    keepHistory: false,
  });
  fs.writeFileSync(journal, record);
  assert.deepEqual(
    restoreTemporaries(directory).map(item => [item.file, item.needed, item.snapshot]),
    [
      ['control.sqlite', false, 'manual-1.5.0-20260901T000000Z'],
      ['history.sqlite', true, 'manual-1.5.0-20260901T000000Z'],
    ]
  );
  // A journal that cannot be read keeps every copy.
  fs.writeFileSync(journal, '{not json');
  assert.ok(restoreTemporaries(directory).every(item => item.needed));
  assert.deepEqual(removeRestoreLeftovers(directory), []);
  assert.equal(hiddenCopies(directory).length, 5, 'nothing removed');
  // The readable journal again: only the copy it does not name goes.
  fs.writeFileSync(journal, record);
  assert.deepEqual(
    removeRestoreLeftovers(directory).map(item => item.id),
    ['.control.sqlite.restoring']
  );
  assert.deepEqual(hiddenCopies(directory), [
    '.auth.json.restoring',
    '.history.sqlite.restoring',
    '.secret.key.restoring',
  ]);
  // Without a journal nothing needs it; a directory under the name is never touched.
  fs.rmSync(journal);
  assert.deepEqual(
    removeRestoreLeftovers(directory).map(item => item.id),
    ['.history.sqlite.restoring']
  );
  assert.deepEqual(restoreTemporaries(directory), []);
  assert.equal(fs.statSync(path.join(directory, '.auth.json.restoring')).isDirectory(), true);
  assert.equal(fs.existsSync(path.join(directory, 'history.sqlite.restoring')), true);
});

test('the next restore removes the full-size copies a restore stopped while copying left behind', async t => {
  // A kill -9 or a power loss during step 1 (here while history.sqlite was copied) leaves the
  // copies made so far under hidden names, and no journal: nothing live had changed. A later
  // restore copies only its own snapshot's files, so before, a copy it did not make (here
  // history.sqlite, which the narrow snapshot leaves out) stayed for ever, as large as the file.
  const { directory, history } = dataDirectory(t);
  history.exec(
    "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 2000) INSERT INTO readings SELECT 'filler', i FROM n"
  );
  history.close();
  const clock = manualClock();
  const lock = locked(t, directory);
  const wide = await createSnapshot(directory, { release: '1.5.0', clock });
  clock.advance(1000);
  const narrow = await createSnapshot(directory, { release: '1.5.0', history: false, clock });
  const root = path.join(directory, snapshotsDirectory);
  for (const name of ['config.json', 'auth.json', 'control.sqlite', 'history.sqlite'])
    fs.copyFileSync(path.join(root, wide.id, name), path.join(directory, `.${name}.restoring`));
  fs.writeFileSync(path.join(directory, '.control.sqlite.restoring-wal'), 'frames of the stamp');
  const historyBytes = fs.statSync(path.join(root, wide.id, 'history.sqlite')).size;
  assert.ok(historyBytes > 16384);
  const liveHistory = fs.readFileSync(path.join(directory, 'history.sqlite'));
  clock.advance(1000);
  const result = await restoreSnapshot(directory, narrow.id, { lock, release: '1.5.0', clock });
  assert.deepEqual(hiddenCopies(directory), [], 'no copy is left in the data directory');
  assert.deepEqual(
    result.leftovers.map(item => [item.id, item.bytes]),
    [
      ['.config.json.restoring', fs.statSync(path.join(root, wide.id, 'config.json')).size],
      ['.auth.json.restoring', fs.statSync(path.join(root, wide.id, 'auth.json')).size],
      [
        '.control.sqlite.restoring',
        fs.statSync(path.join(root, wide.id, 'control.sqlite')).size + 'frames of the stamp'.length,
      ],
      ['.history.sqlite.restoring', historyBytes],
    ]
  );
  assert.deepEqual(
    fs.readFileSync(path.join(directory, 'history.sqlite')),
    liveHistory,
    'the live history is kept as it is'
  );
  assert.equal(interruptedRestore(directory), null);
  // A restore with nothing left over says so.
  clock.advance(1000);
  assert.deepEqual(
    (await restoreSnapshot(directory, narrow.id, { lock, release: '1.5.0', clock })).leftovers,
    []
  );
});

test('a copy an interrupted restore still needs stays until a restore takes its file over', async t => {
  // Interrupted mid-swap (after control.sqlite was moved aside, before its copy took its place):
  // the journal names every file, so the copies of control.sqlite and history.sqlite stay. A
  // restore of a pre-1.5 snapshot (no control.sqlite) with history kept takes control.sqlite over
  // without copying it, which left that copy behind for ever; history.sqlite stays named by the
  // journal it leaves, and so does its copy, until the interrupted restore is run again.
  const { directory, history } = dataDirectory(t);
  history.close();
  const clock = manualClock();
  const lock = locked(t, directory);
  const control = path.join(directory, 'control.sqlite');
  fs.renameSync(control, path.join(directory, 'hold.sqlite'));
  const pre15 = await createSnapshot(directory, { reason: 'pre-upgrade', release: '1.5.0', clock });
  fs.renameSync(path.join(directory, 'hold.sqlite'), control);
  clock.advance(1000);
  const wide = await createSnapshot(directory, { release: '1.5.0', clock });
  const rename = fs.renameSync;
  t.after(() => (fs.renameSync = rename));
  fs.renameSync = function (from, to) {
    if (String(from).endsWith('.control.sqlite.restoring')) throw new Error('power lost');
    return rename.call(this, from, to);
  };
  clock.advance(1000);
  await assert.rejects(restoreSnapshot(directory, wide.id, { lock, release: '1.5.0', clock }), {
    message: 'power lost',
  });
  fs.renameSync = rename;
  assert.deepEqual(hiddenCopies(directory), [
    '.control.sqlite.restoring',
    '.history.sqlite.restoring',
  ]);
  assert.ok(restoreTemporaries(directory).every(item => item.needed && item.snapshot === wide.id));

  clock.advance(1000);
  const other = await restoreSnapshot(directory, pre15.id, {
    lock,
    history: false,
    release: '1.5.0',
    clock,
  });
  assert.deepEqual(other.unfinished.files, ['history.sqlite']);
  assert.deepEqual(
    hiddenCopies(directory),
    ['.history.sqlite.restoring'],
    'the copy of control.sqlite went; the journal still names history.sqlite'
  );
  assert.deepEqual(
    other.leftovers.map(item => item.id),
    ['.control.sqlite.restoring']
  );
  assert.equal(fs.existsSync(control), false, 'the pre-1.5 layout');

  // Running the interrupted restore again finishes it: no journal and no copy are left.
  clock.advance(1000);
  const again = await restoreSnapshot(directory, wide.id, { lock, release: '1.5.0', clock });
  assert.equal(again.unfinished, null);
  assert.equal(interruptedRestore(directory), null);
  assert.deepEqual(hiddenCopies(directory), []);
  assert.equal(who(control), 'before');
});

// Orbit 1.4.x after a code rollback knows nothing of the restore journal: it starts on a
// directory a crash left part restored and writes to it. A settings or password change replaces
// config.json or auth.json (written whole and renamed into place), and a reading lands in
// history.sqlite, which it switches to WAL.
function writeAs14x(directory, { config, auth, reading }) {
  for (const [name, text] of [
    ['config.json', config],
    ['auth.json', auth],
  ])
    if (text !== undefined) {
      const file = path.join(directory, name);
      fs.writeFileSync(`${file}.tmp`, text, { mode: 0o600 });
      fs.renameSync(`${file}.tmp`, file);
    }
  if (reading) {
    const db = new DatabaseSync(path.join(directory, 'history.sqlite'));
    try {
      db.exec(
        'PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS readings (service TEXT, time INTEGER)'
      );
      db.prepare('INSERT INTO readings VALUES (?, ?)').run(...reading);
    } finally {
      db.close();
    }
  }
}
const services = file =>
  read(file, 'SELECT service FROM readings ORDER BY time').map(row => row.service);
// Makes the next restoreSnapshot throw (a crash) when `when(from, to)` matches a rename.
// The random part of a temporary file's name (<file>.<uuid>.tmp), and whether `file` is one of
// `name`'s temporary files.
const randomTmp = /\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.tmp$/;
const temporaryOf = (file, name) =>
  path.basename(String(file)).replace(randomTmp, '.tmp') === `${name}.tmp`;

function crashOnRename(t, when) {
  const rename = fs.renameSync;
  const restore = () => (fs.renameSync = rename);
  t.after(restore);
  fs.renameSync = function (from, to) {
    if (when(String(from), String(to))) throw new Error('power lost');
    return rename.call(this, from, to);
  };
  return restore;
}
const asideFolder = from => path.basename(from).startsWith('.restoring-pre-restore-');

test('running an interrupted restore again keeps what Orbit 1.4.x wrote in between in a snapshot of its own', async t => {
  // A restore killed after it had swapped every file (in step 3), then 1.4.x, which ignores the
  // journal, ran on the result: a new password, settings and readings. Running the restore again,
  // as the refusal and status say, deleted all three: it took every live file for the copy the
  // first attempt had put there (r4 finding "re-running an interrupted restore deletes what 1.4.x
  // wrote in the meantime").
  const { directory, history } = dataDirectory(t);
  history.close();
  const clock = manualClock();
  const lock = locked(t, directory);
  const snapshot = await createSnapshot(directory, { release: '1.5.0', clock });
  writeAs14x(directory, {
    config: '{"services":["a","b"]}\n',
    auth: '{"version":1,"p":"before the restore"}\n',
    reading: ['before the restore', 2],
  });
  const before = {
    'config.json': fs.readFileSync(path.join(directory, 'config.json')),
    'auth.json': fs.readFileSync(path.join(directory, 'auth.json')),
  };
  const stop = crashOnRename(t, asideFolder);
  clock.advance(1000);
  await assert.rejects(restoreSnapshot(directory, snapshot.id, { lock, release: '1.5.0', clock }), {
    message: 'power lost',
  });
  stop();
  const first = interruptedRestore(directory);
  assert.equal(first.snapshot, snapshot.id);

  const written = {
    'config.json': '{"services":["a","b","added under 1.4.x"]}\n',
    'auth.json': '{"version":1,"p":"changed under 1.4.x"}\n',
  };
  writeAs14x(directory, {
    config: written['config.json'],
    auth: written['auth.json'],
    reading: ['read under 1.4.x', 3],
  });
  const control = path.join(directory, 'control.sqlite');
  const stamped = fs.readFileSync(control);

  clock.advance(1000);
  const again = await restoreSnapshot(directory, snapshot.id, { lock, release: '1.5.0', clock });
  assert.equal(again.aside, first.aside, 'it continued in the first attempt’s folder');
  assert.equal(interruptedRestore(directory), null);
  assert.ok(!listSnapshots(directory).some(item => item.interrupted), 'no folder left behind');
  // The snapshot is in place.
  assert.deepEqual(services(path.join(directory, 'history.sqlite')), ['a']);
  assert.equal(fs.readFileSync(path.join(directory, 'auth.json'), 'utf8'), '{"version":1}\n');
  assert.equal(who(control), 'before');
  assert.notDeepEqual(fs.readFileSync(control), stamped, 'a fresh copy, stamped again');
  // What 1.4.x wrote is in a snapshot of its own; control.sqlite, which it never touches, was the
  // first attempt's copy and is not.
  assert.equal(again.kept.length, 1);
  const [kept] = again.kept;
  assert.deepEqual(kept.files, ['config.json', 'auth.json', 'history.sqlite']);
  assert.deepEqual(kept.damaged, []);
  assert.notEqual(kept.id, again.aside);
  const keptFolder = path.join(directory, snapshotsDirectory, kept.id);
  for (const [name, text] of Object.entries(written))
    assert.equal(fs.readFileSync(path.join(keptFolder, name), 'utf8'), text, name);
  assert.deepEqual(services(path.join(keptFolder, 'history.sqlite')), ['a', 'read under 1.4.x']);
  assert.equal(fs.existsSync(path.join(keptFolder, 'history.sqlite-wal')), false, 'settled');
  const manifest = JSON.parse(fs.readFileSync(path.join(keptFolder, 'manifest.json'), 'utf8'));
  assert.equal(manifest.reason, 'pre-restore');
  assert.equal(manifest.restoring, snapshot.id);
  assert.equal(manifest.changedAfter, again.aside);
  assert.deepEqual(manifest.excluded, ['control.sqlite']);
  assert.deepEqual(manifest.absent, []);
  assert.equal((await verifySnapshot(directory, kept.id)).ok, true);
  // The undo still holds the data directory as it was before the first attempt.
  const aside = path.join(directory, snapshotsDirectory, again.aside);
  for (const [name, bytes] of Object.entries(before))
    assert.deepEqual(fs.readFileSync(path.join(aside, name)), bytes, name);
  assert.deepEqual(services(path.join(aside, 'history.sqlite')), ['a', 'before the restore']);
  // Restoring the kept snapshot puts back what 1.4.x wrote, and only that.
  clock.advance(1000);
  const back = await restoreSnapshot(directory, kept.id, { lock, release: '1.5.0', clock });
  assert.deepEqual(back.restored, ['config.json', 'auth.json', 'history.sqlite']);
  for (const [name, text] of Object.entries(written))
    assert.equal(fs.readFileSync(path.join(directory, name), 'utf8'), text, name);
  assert.deepEqual(services(path.join(directory, 'history.sqlite')), ['a', 'read under 1.4.x']);
  assert.equal(who(control), 'before', 'control.sqlite left as it was');
});

test('a restore never leaves the data directory without config.json or auth.json', async t => {
  // auth.json was moved aside before the snapshot's copy was renamed into its place: a crash in
  // between left none, and Orbit 1.4.x, which ignores the journal, then started with the
  // GOBLIN_PASSWORD bootstrap password, or on loopback without any (r4 finding, second effect).
  // Now they are copied aside and the copy renamed over them, so one or the other is always
  // there, and a crash between the two leaves the current file, which a re-run recognises.
  const { directory, history } = dataDirectory(t);
  history.close();
  const clock = manualClock();
  const lock = locked(t, directory);
  const snapshot = await createSnapshot(directory, { release: '1.5.0', clock });
  writeAs14x(directory, {
    config: '{"services":["a","b"]}\n',
    auth: '{"version":1,"p":"current"}\n',
  });
  const current = name => fs.readFileSync(path.join(directory, name), 'utf8');
  const before = { config: current('config.json'), auth: current('auth.json') };
  // Every file operation of a whole restore, checked as it happens.
  const gaps = [];
  const watched = ['renameSync', 'rmSync', 'copyFileSync', 'unlinkSync'];
  const originals = Object.fromEntries(watched.map(name => [name, fs[name]]));
  const unwatch = () => Object.assign(fs, originals);
  t.after(unwatch);
  for (const name of watched)
    fs[name] = function (...args) {
      const result = originals[name].apply(this, args);
      for (const file of ['config.json', 'auth.json'])
        if (!fs.existsSync(path.join(directory, file))) gaps.push(`${file} after ${name}`);
      return result;
    };
  clock.advance(1000);
  const whole = await restoreSnapshot(directory, snapshot.id, { lock, release: '1.5.0', clock });
  unwatch();
  assert.deepEqual(gaps, []);
  const aside = path.join(directory, snapshotsDirectory, whole.aside);
  assert.equal(fs.readFileSync(path.join(aside, 'auth.json'), 'utf8'), before.auth);
  assert.equal(mode(path.join(aside, 'auth.json')), 0o600);

  // A crash right after auth.json was copied aside: the current one is still in place.
  writeAs14x(directory, { config: before.config, auth: before.auth });
  const copy = fs.copyFileSync;
  t.after(() => (fs.copyFileSync = copy));
  fs.copyFileSync = function (from, to, flags) {
    copy.call(this, from, to, flags);
    if (/\.restoring-pre-restore-[^/]+\/auth\.json$/.test(String(to)))
      throw new Error('power lost');
  };
  clock.advance(1000);
  await assert.rejects(restoreSnapshot(directory, snapshot.id, { lock, release: '1.5.0', clock }), {
    message: 'power lost',
  });
  fs.copyFileSync = copy;
  assert.equal(current('auth.json'), before.auth);
  assert.equal(current('config.json'), '{"services":["a"]}\n', 'the snapshot’s, already swapped');
  // Run again, it recognises both as what the first attempt left: nothing is kept apart.
  clock.advance(1000);
  const again = await restoreSnapshot(directory, snapshot.id, { lock, release: '1.5.0', clock });
  assert.deepEqual(again.kept, []);
  assert.equal(current('auth.json'), '{"version":1}\n');
  const undo = path.join(directory, snapshotsDirectory, again.aside);
  assert.equal(fs.readFileSync(path.join(undo, 'auth.json'), 'utf8'), before.auth);
  assert.equal(fs.readFileSync(path.join(undo, 'config.json'), 'utf8'), before.config);
  assert.equal(interruptedRestore(directory), null);
});

test('an attempt stopped while it kept changed files apart: the next one finishes their snapshot', async t => {
  // 1.4.x wrote between the first and the second attempt; the second was stopped too, part way
  // through its swap. The third must finish the snapshot the second began (the journal names
  // it), keep apart only what changed since, and take the second attempt's control.sqlite (a
  // copy stamped afresh, so unlike the first's) and the first's for what they are.
  const { directory, history } = dataDirectory(t);
  history.close();
  const clock = manualClock();
  const lock = locked(t, directory);
  const snapshot = await createSnapshot(directory, { release: '1.5.0', clock });
  let stop = crashOnRename(t, asideFolder);
  clock.advance(1000);
  await assert.rejects(restoreSnapshot(directory, snapshot.id, { lock, release: '1.5.0', clock }), {
    message: 'power lost',
  });
  stop();
  writeAs14x(directory, {
    config: '{"services":["written under 1.4.x"]}\n',
    reading: ['read under 1.4.x', 3],
  });
  // The second attempt stops as it renames its copy of control.sqlite into place: config.json is
  // kept apart and swapped, history.sqlite (changed) not reached.
  stop = crashOnRename(t, from => from.endsWith('.control.sqlite.restoring'));
  clock.advance(1000);
  await assert.rejects(restoreSnapshot(directory, snapshot.id, { lock, release: '1.5.0', clock }), {
    message: 'power lost',
  });
  stop();
  const partial = listSnapshots(directory).filter(item => item.interrupted);
  assert.equal(partial.length, 2, 'the aside folder and the one for changed files');

  clock.advance(1000);
  const third = await restoreSnapshot(directory, snapshot.id, { lock, release: '1.5.0', clock });
  assert.deepEqual(
    third.kept.map(item => item.files),
    [['config.json'], ['history.sqlite']]
  );
  assert.equal(interruptedRestore(directory), null);
  assert.ok(!listSnapshots(directory).some(item => item.interrupted), 'no folder left behind');
  const root = path.join(directory, snapshotsDirectory);
  assert.equal(
    fs.readFileSync(path.join(root, third.kept[0].id, 'config.json'), 'utf8'),
    '{"services":["written under 1.4.x"]}\n'
  );
  assert.deepEqual(services(path.join(root, third.kept[1].id, 'history.sqlite')), [
    'a',
    'read under 1.4.x',
  ]);
  for (const item of third.kept) assert.equal((await verifySnapshot(directory, item.id)).ok, true);
  assert.deepEqual(services(path.join(directory, 'history.sqlite')), ['a']);
  assert.equal(who(path.join(directory, 'control.sqlite')), 'before');
});

test('a restore run again after a narrower one never overwrites what its first attempt set aside', async t => {
  // The first attempt set config.json, auth.json and control.sqlite aside and was interrupted at
  // history.sqlite; a restore of a snapshot without history then replaced the other three and
  // rewrote the journal to name history.sqlite only. Running the first restore again continued in
  // its folder and moved the live config.json there, over the one from before the first attempt.
  const { directory, history } = dataDirectory(t);
  history.close();
  const clock = manualClock();
  const lock = locked(t, directory);
  const wide = await createSnapshot(directory, { release: '1.5.0', clock });
  writeAs14x(directory, { config: '{"services":["narrow"]}\n' });
  clock.advance(1000);
  const narrow = await createSnapshot(directory, { release: '1.5.0', history: false, clock });
  const original = '{"services":["before every restore"]}\n';
  writeAs14x(directory, { config: original });
  const stop = crashOnRename(t, from => from.endsWith('.history.sqlite.restoring'));
  clock.advance(1000);
  await assert.rejects(restoreSnapshot(directory, wide.id, { lock, release: '1.5.0', clock }), {
    message: 'power lost',
  });
  stop();
  const first = interruptedRestore(directory);
  clock.advance(1000);
  const other = await restoreSnapshot(directory, narrow.id, { lock, release: '1.5.0', clock });
  assert.deepEqual(other.unfinished.files, ['history.sqlite']);
  clock.advance(1000);
  const again = await restoreSnapshot(directory, wide.id, { lock, release: '1.5.0', clock });
  assert.equal(again.aside, first.aside);
  const root = path.join(directory, snapshotsDirectory);
  assert.equal(fs.readFileSync(path.join(root, again.aside, 'config.json'), 'utf8'), original);
  // What the narrower restore had put in place is kept apart, not lost either.
  const kept = again.kept.find(item => item.files.includes('config.json'));
  assert.equal(
    fs.readFileSync(path.join(root, kept.id, 'config.json'), 'utf8'),
    '{"services":["narrow"]}\n'
  );
  assert.equal(interruptedRestore(directory), null);
});

// A restore W of a snapshot with history, stopped after it had set history.sqlite aside and
// before its copy took its place (no history.sqlite in the data directory), then a restore N of a
// snapshot without history over it, stopped too as it renamed its copy of config.json into place.
// N's journal replaced W's. Resolves what the tests below need.
async function wideThenNarrowInterrupted(t) {
  const { directory, history } = dataDirectory(t);
  history.close();
  const clock = manualClock();
  const lock = locked(t, directory);
  const wide = await createSnapshot(directory, { release: '1.5.0', clock });
  clock.advance(1000);
  const narrow = await createSnapshot(directory, { release: '1.5.0', history: false, clock });
  // A second snapshot without history (one taken now, without history.sqlite in place, would
  // record it as absent: restoring it removes history.sqlite, and so finishes W).
  writeAs14x(directory, { config: '{"services":["other"]}\n' });
  clock.advance(1000);
  const other = await createSnapshot(directory, { release: '1.5.0', history: false, clock });
  // Recorded after the snapshots: only W's undo holds it.
  writeAs14x(directory, { reading: ['before the restores', 2] });
  const restore = (id, options = {}) => {
    clock.advance(1000);
    return restoreSnapshot(directory, id, { lock, release: '1.5.0', clock, ...options });
  };
  let stop = crashOnRename(t, from => from.endsWith('.history.sqlite.restoring'));
  await assert.rejects(restore(wide.id), { message: 'power lost' });
  stop();
  const first = interruptedRestore(directory);
  assert.equal(fs.existsSync(path.join(directory, 'history.sqlite')), false);
  stop = crashOnRename(t, from => from.endsWith('.config.json.restoring'));
  await assert.rejects(restore(narrow.id), { message: 'power lost' });
  stop();
  assert.equal(interruptedRestore(directory).snapshot, narrow.id);
  return { directory, lock, clock, wide, narrow, other, first, restore };
}
// The journal that says W is still to finish: what Uptime Goblin 1.5 refuses to start on.
const wideLeft = ({ wide, first }) => ({
  snapshot: wide.id,
  aside: first.aside,
  files: ['history.sqlite'],
  keepHistory: false,
});
async function refusesToStart(directory, lock) {
  await assert.rejects(
    startControl(directory, {
      lock,
      credentialConfigured: true,
      release: '1.5.0',
      env: {},
      keyring: 'existing',
      keySources: {
        credentialsDirectory: path.join(directory, 'no-credentials'),
        secretsDirectory: path.join(directory, 'no-secrets'),
      },
    }),
    { code: 'restore_interrupted' }
  );
}
// W run again completes it in its first attempt's folder: history.sqlite is the snapshot's again,
// the undo holds the data directory of before W, and no journal, copy or folder is left.
async function wideFinished(setup) {
  const { directory, wide, first, restore } = setup;
  const again = await restore(wide.id);
  assert.equal(again.aside, first.aside);
  assert.equal(again.unfinished, null);
  assert.equal(interruptedRestore(directory), null);
  assert.deepEqual(services(path.join(directory, 'history.sqlite')), ['a']);
  const root = path.join(directory, snapshotsDirectory);
  assert.deepEqual(services(path.join(root, first.aside, 'history.sqlite')), [
    'a',
    'before the restores',
  ]);
  assert.equal((await verifySnapshot(directory, first.aside)).ok, true);
  assert.deepEqual(hiddenCopies(directory), []);
  return again;
}

test('a narrower restore interrupted over an interrupted wider one keeps the wider one’s journal', async t => {
  // N replaced the journal with its own and, run again, completed and removed it: nothing named
  // W any more, so Uptime Goblin started without history.sqlite and began an empty history, and the
  // history of before W sat in a folder no journal named (r5 upgrade-rollback finding). N's
  // journal now carries what it leaves of W (`unfinished`) and puts it back as the journal.
  const setup = await wideThenNarrowInterrupted(t);
  const { directory, lock, wide, narrow, restore } = setup;
  // W's copy of history.sqlite is still W's, though N's journal is the one in place.
  assert.deepEqual(
    restoreTemporaries(directory).map(item => [item.file, item.needed, item.snapshot]),
    [
      ['config.json', true, narrow.id],
      ['auth.json', true, narrow.id],
      ['control.sqlite', true, narrow.id],
      ['history.sqlite', true, wide.id],
    ]
  );
  assert.deepEqual(removeRestoreLeftovers(directory), []);
  const again = await restore(narrow.id);
  assert.deepEqual(again.unfinished, wideLeft(setup));
  assert.deepEqual(interruptedRestore(directory), wideLeft(setup));
  assert.equal(fs.existsSync(path.join(directory, 'history.sqlite')), false);
  assert.deepEqual(hiddenCopies(directory), ['.history.sqlite.restoring']);
  await refusesToStart(directory, lock);
  const done = await wideFinished(setup);
  assert.ok(!listSnapshots(directory).some(item => item.interrupted), 'no folder left behind');
  // N's stamped control.sqlite was neither W's copy nor what W had set aside: kept apart.
  assert.deepEqual(
    done.kept.map(item => item.files),
    [['control.sqlite']]
  );
});

test('a restore that finishes the narrower one, or a crash as it puts the wider one’s journal back, still leaves that journal', async t => {
  // Another restore without history over the interrupted N finishes N (it replaces every file N
  // was replacing), but not W.
  const setup = await wideThenNarrowInterrupted(t);
  const { directory, lock } = setup;
  const done = await setup.restore(setup.other.id);
  assert.deepEqual(done.unfinished, wideLeft(setup));
  assert.deepEqual(interruptedRestore(directory), wideLeft(setup));
  await refusesToStart(directory, lock);
  await wideFinished(setup);
  // N's own folder is left as an interrupted restore's (it holds what N had set aside), as when
  // any restore finishes a narrower interrupted one.
  assert.deepEqual(
    listSnapshots(directory)
      .filter(item => item.interrupted)
      .map(item => item.empty ?? false),
    [false]
  );

  // N completed but was stopped as it put W's journal back in place of its own (step 3): its
  // folder has its final name, so it had finished, and running it again or another restore
  // still leaves W's journal.
  for (const next of ['same', 'other']) {
    const tc = await wideThenNarrowInterrupted(t);
    let renames = 0;
    const stop = crashOnRename(
      t,
      from => temporaryOf(from, restoreJournal) && (renames += 1) === 2
    );
    await assert.rejects(tc.restore(tc.narrow.id), { message: 'power lost' });
    stop();
    const stopped = interruptedRestore(tc.directory);
    assert.equal(stopped.snapshot, tc.narrow.id, next);
    assert.ok(
      listSnapshots(tc.directory).some(item => item.id === stopped.aside && item.valid),
      'its folder has its final name'
    );
    await refusesToStart(tc.directory, tc.lock);
    const result = await tc.restore(next === 'same' ? tc.narrow.id : tc.other.id);
    if (next === 'same') assert.equal(result.aside, stopped.aside, 'it reopened its snapshot');
    assert.deepEqual(result.unfinished, wideLeft(tc), next);
    assert.deepEqual(interruptedRestore(tc.directory), wideLeft(tc), next);
    await wideFinished(tc);
    assert.ok(!listSnapshots(tc.directory).some(item => item.interrupted), next);
  }
});

// Records, in order, the calls of a restore that decide what a power loss can leave behind: each
// fsync (with what it flushed), each rename, and the journal's removal. Paths are relative to
// `directory` ('.' is the data directory itself).
function recordDurability(t, directory) {
  const events = [];
  const opened = new Map();
  // A temporary file by its fixed part: writeJsonDurably names each one <file>.<uuid>.tmp.
  const short = file => (path.relative(directory, String(file)) || '.').replace(randomTmp, '.tmp');
  const after = {
    openSync: (args, handle) => opened.set(handle, short(args[0])),
    fsyncSync: args => events.push(`fsync ${opened.get(args[0])}`),
    renameSync: args => events.push(`rename ${short(args[0])} -> ${short(args[1])}`),
    rmSync: args => String(args[0]).endsWith(restoreJournal) && events.push(`rm ${short(args[0])}`),
  };
  const originals = Object.fromEntries(Object.keys(after).map(name => [name, fs[name]]));
  const stop = () => Object.assign(fs, originals);
  t.after(stop);
  for (const name of Object.keys(after))
    fs[name] = function (...args) {
      const result = originals[name].apply(this, args);
      after[name](args, result);
      return result;
    };
  const at = (event, from = 0) => {
    const index = events.indexOf(event, from);
    assert.notEqual(index, -1, `${event} (after #${from}) in:\n${events.join('\n')}`);
    return index;
  };
  return { events, stop, at };
}

test('a restore flushes what it put in place and its pre-restore snapshot before its journal goes', async t => {
  // The journal is what makes a start refuse. It was removed while the restored files and the
  // renames in the data directory could still be in the page cache only: after a power loss,
  // ext4 (delayed allocation) could leave an empty history.sqlite, which a start took for an
  // empty history without a word, an empty config.json, or an undo without its manifest.
  const { directory, history } = dataDirectory(t);
  history.close();
  const clock = manualClock();
  const lock = locked(t, directory);
  const snapshot = await createSnapshot(directory, { release: '1.5.0', clock });
  const { stop, at } = recordDurability(t, directory);
  clock.advance(1000);
  const result = await restoreSnapshot(directory, snapshot.id, { lock, release: '1.5.0', clock });
  stop();
  const root = snapshotsDirectory;
  const removed = at(`rm ${path.join(root, restoreJournal)}`);
  assert.deepEqual(result.restored, [
    'config.json',
    'auth.json',
    'control.sqlite',
    'history.sqlite',
  ]);
  // Each copy is on disk before its rename puts it under the live name.
  const renamed = result.restored.map(name => {
    const index = at(`rename .${name}.restoring -> ${name}`);
    assert.ok(at(`fsync .${name}.restoring`) < index, `${name} flushed before its rename`);
    return index;
  });
  // The data directory (those renames, and what was moved out of it) before the journal goes.
  assert.ok(at('fsync .', Math.max(...renamed)) < removed, 'the data directory is flushed first');
  // The pre-restore snapshot: its manifest and the folder's entries, then its final name.
  const folder = path.join(root, `.restoring-${result.aside}`);
  const manifest = path.join(folder, 'manifest.json');
  const written = at(`rename ${manifest}.tmp -> ${manifest}`);
  assert.ok(at(`fsync ${manifest}.tmp`) < written);
  const final = at(`rename ${folder} -> ${path.join(root, result.aside)}`);
  assert.ok(at(`fsync ${folder}`, written) < final, 'the folder’s entries before its final name');
  assert.ok(at(`fsync ${root}`, final) < removed, 'its final name before the journal goes');
  at(`fsync ${root}`, removed);
});

test('a snapshot is on disk when createSnapshot returns: its copies, manifest, folder and name flushed in order', async t => {
  // None of it was flushed (copyFileSync, a manifest written without fsync, the final rename):
  // a caller that went on to commit (the first start's migration of 1.4.x data) could outlive
  // its own way back after a power loss (r6). The databases too, uniformly.
  const { directory, history } = dataDirectory(t);
  history.close();
  assert.equal(fs.existsSync(path.join(directory, snapshotsDirectory)), false);
  const { stop, at } = recordDurability(t, directory);
  const snapshot = await createSnapshot(directory, { release: '1.5.0', clock: manualClock() });
  stop();
  const root = snapshotsDirectory;
  const staging = path.join(root, `.staging-${snapshot.id}`);
  const manifest = path.join(staging, 'manifest.json');
  const final = at(`rename ${staging} -> ${path.join(root, snapshot.id)}`);
  for (const name of ['config.json', 'auth.json', 'control.sqlite', 'history.sqlite'])
    assert.ok(at(`fsync ${path.join(staging, name)}`) < final, `${name} flushed`);
  const written = at(`rename ${manifest}.tmp -> ${manifest}`);
  assert.ok(at(`fsync ${manifest}.tmp`) < written);
  assert.ok(at(`fsync ${staging}`, written) < final);
  at(`fsync ${root}`, final);
  // snapshots/ was new here, so the data directory holds a new entry: flushed too.
  at('fsync .', final);
  assert.equal((await verifySnapshot(directory, snapshot.id)).ok, true);
});

test('a restore makes its folder only once its journal names it; an empty folder no journal names goes', async t => {
  // The folder was made before the journal was written: a kill -9 or a power loss in between
  // left it empty, without a journal. Uptime Goblin then started normally, but `snapshots` listed the
  // folder for ever as an interrupted restore's whose files "are kept until you delete them",
  // --verify failed, and running the restore again, as that said, made a folder of its own.
  const { directory, history } = dataDirectory(t);
  history.close();
  const clock = manualClock();
  const lock = locked(t, directory);
  const snapshot = await createSnapshot(directory, { release: '1.5.0', clock });
  const root = path.join(directory, snapshotsDirectory);
  const folders = () => fs.readdirSync(root).filter(name => name.startsWith('.restoring-'));
  // Stopped as it writes its journal: no folder yet, and nothing live changed.
  const open = fs.openSync;
  t.after(() => (fs.openSync = open));
  fs.openSync = function (file, ...rest) {
    if (temporaryOf(file, restoreJournal)) throw new Error('power lost');
    return open.call(this, file, ...rest);
  };
  clock.advance(1000);
  await assert.rejects(restoreSnapshot(directory, snapshot.id, { lock, release: '1.5.0', clock }), {
    message: 'power lost',
  });
  fs.openSync = open;
  assert.deepEqual(folders(), [], 'no folder without a journal');
  assert.equal(interruptedRestore(directory), null);
  assert.ok(!listSnapshots(directory).some(item => item.interrupted));

  // Stopped right after it made the folder: the journal names it, so it is that restore's, and
  // running the restore again continues in it.
  const mkdir = fs.mkdirSync;
  t.after(() => (fs.mkdirSync = mkdir));
  fs.mkdirSync = function (folder, ...rest) {
    const made = mkdir.call(this, folder, ...rest);
    if (path.basename(String(folder)).startsWith('.restoring-')) throw new Error('power lost');
    return made;
  };
  clock.advance(1000);
  await assert.rejects(restoreSnapshot(directory, snapshot.id, { lock, release: '1.5.0', clock }), {
    message: 'power lost',
  });
  fs.mkdirSync = mkdir;
  const first = interruptedRestore(directory);
  assert.deepEqual(folders(), [`.restoring-${first.aside}`]);
  const [waiting] = listSnapshots(directory).filter(item => item.interrupted);
  assert.equal(waiting.empty, true);
  assert.equal(
    waiting.problem,
    'An interrupted restore made this folder for the files it replaces and had moved none here yet. Run the restore again to finish it.'
  );
  assert.deepEqual(removeEmptyRestoreFolders(directory), [], 'the journal names it');
  clock.advance(1000);
  const again = await restoreSnapshot(directory, snapshot.id, { lock, release: '1.5.0', clock });
  assert.equal(again.aside, first.aside, 'it continued in that folder');
  assert.deepEqual(folders(), []);
  assert.equal(interruptedRestore(directory), null);

  // An empty folder that no journal names (made by a release that made it before its journal,
  // or by a restore whose journal a later one finished) says so, and the next restore removes it;
  // one with anything in it stays.
  const empty = '.restoring-pre-restore-1.5.0-20260901T000000Z';
  const full = '.restoring-pre-restore-1.5.0-20260901T000001Z';
  fs.mkdirSync(path.join(root, empty));
  fs.mkdirSync(path.join(root, full));
  fs.writeFileSync(path.join(root, full, 'config.json'), '{}');
  const listed = Object.fromEntries(
    listSnapshots(directory)
      .filter(item => item.interrupted)
      .map(item => [item.id, item])
  );
  assert.equal(listed[empty].empty, true);
  assert.equal(listed[empty].valid, false);
  assert.equal(
    listed[empty].problem,
    'Empty: a restore that a crash or a power loss stopped made this folder before it moved any file here. The next start of Uptime Goblin 1.5 or later, or the next restore-snapshot, removes it; Orbit 1.4.x leaves it (delete it by hand while Uptime Goblin is stopped).'
  );
  assert.equal(listed[full].empty, undefined);
  assert.match(listed[full].problem, /these files are kept until you delete them/);
  clock.advance(1000);
  await restoreSnapshot(directory, snapshot.id, { lock, release: '1.5.0', clock });
  assert.deepEqual(folders(), [full]);
  // removeEmptyRestoreFolders keeps every folder while a journal it cannot read exists.
  fs.mkdirSync(path.join(root, empty));
  const journal = path.join(root, restoreJournal);
  fs.writeFileSync(journal, '{not json');
  assert.equal(listSnapshots(directory).find(item => item.id === empty).empty, true);
  assert.match(listSnapshots(directory).find(item => item.id === empty).problem, /moved none/);
  assert.deepEqual(removeEmptyRestoreFolders(directory), []);
  fs.rmSync(journal);
  assert.deepEqual(removeEmptyRestoreFolders(directory), [empty]);
  assert.deepEqual(folders(), [full]);
  assert.deepEqual(removeEmptyRestoreFolders(path.join(directory, 'missing')), []);
});

// Makes the next restoreSnapshot throw (a crash) when it removes its journal: step 3 has given
// the aside folder its final name.
function crashOnJournalRemoval(t) {
  const rm = fs.rmSync;
  const restore = () => (fs.rmSync = rm);
  t.after(restore);
  fs.rmSync = function (file, ...rest) {
    if (String(file).endsWith(restoreJournal)) throw new Error('power lost');
    return rm.call(this, file, ...rest);
  };
  return restore;
}

test('a restore stopped after its folder got its final name keeps that snapshot as the undo when run again', async t => {
  // A kill or a power loss between step 3's rename of the folder and the journal's removal left a
  // completed restore and its journal: the start refuses and says to run the same restore again.
  // The re-run found no .restoring- folder to continue in, set the restored files (the snapshot's
  // own copies) aside and named that as the undo; the real pre-restore files sat in a snapshot
  // nothing named.
  const { directory, history } = dataDirectory(t);
  history.close();
  const clock = manualClock();
  const lock = locked(t, directory);
  const snapshot = await createSnapshot(directory, { release: '1.5.0', clock });
  const before = '{"services":["a"],"marker":"before the restore"}\n';
  writeAs14x(directory, { config: before, reading: ['before the restore', 2] });
  // auth.json was not there before the restore: undoing it removes it again.
  fs.rmSync(path.join(directory, 'auth.json'));
  const stop = crashOnJournalRemoval(t);
  clock.advance(1000);
  await assert.rejects(restoreSnapshot(directory, snapshot.id, { lock, release: '1.5.0', clock }), {
    message: 'power lost',
  });
  stop();
  const first = interruptedRestore(directory);
  assert.equal(first.snapshot, snapshot.id);
  const root = path.join(directory, snapshotsDirectory);
  assert.equal(fs.existsSync(path.join(root, first.aside)), true, 'the folder has its final name');
  assert.ok(!listSnapshots(directory).some(item => item.interrupted));
  // Orbit 1.4.x, which ignores the journal, records a reading meanwhile.
  writeAs14x(directory, { reading: ['read under 1.4.x', 3] });

  clock.advance(1000);
  const { stop: unrecord, at } = recordDurability(t, directory);
  const again = await restoreSnapshot(directory, snapshot.id, { lock, release: '1.5.0', clock });
  unrecord();
  assert.equal(again.aside, first.aside, 'the undo is still the first attempt’s snapshot');
  assert.equal(interruptedRestore(directory), null);
  assert.ok(!listSnapshots(directory).some(item => item.interrupted), 'no folder left behind');
  const aside = path.join(root, again.aside);
  assert.equal(fs.readFileSync(path.join(aside, 'config.json'), 'utf8'), before);
  assert.deepEqual(services(path.join(aside, 'history.sqlite')), ['a', 'before the restore']);
  const manifest = JSON.parse(fs.readFileSync(path.join(aside, 'manifest.json'), 'utf8'));
  assert.deepEqual(manifest.absent, ['auth.json'], 'auth.json was not there before');
  assert.deepEqual(
    manifest.files.map(file => file.name),
    ['config.json', 'control.sqlite', 'history.sqlite']
  );
  assert.equal(manifest.restoring, snapshot.id);
  assert.equal((await verifySnapshot(directory, again.aside)).ok, true);
  // What 1.4.x wrote is kept apart, not deleted, and the snapshot is in place.
  assert.deepEqual(
    again.kept.map(item => item.files),
    [['history.sqlite']]
  );
  const [kept] = again.kept;
  assert.deepEqual(services(path.join(root, kept.id, 'history.sqlite')), ['a', 'read under 1.4.x']);
  assert.deepEqual(services(path.join(directory, 'history.sqlite')), ['a']);
  assert.equal(fs.readFileSync(path.join(directory, 'auth.json'), 'utf8'), '{"version":1}\n');
  assert.equal(who(path.join(directory, 'control.sqlite')), 'before');
  // The kept folder's manifest and final name reach the disk before the journal goes too.
  const keptFolder = path.join(snapshotsDirectory, `.restoring-${kept.id}`);
  const keptManifest = path.join(keptFolder, 'manifest.json');
  const removed = at(`rm ${path.join(snapshotsDirectory, restoreJournal)}`);
  assert.ok(at(`fsync ${keptManifest}.tmp`) < at(`fsync ${keptFolder}`));
  const keptFinal = at(`rename ${keptFolder} -> ${path.join(snapshotsDirectory, kept.id)}`);
  assert.ok(at(`fsync ${snapshotsDirectory}`, keptFinal) < removed);
  // Nothing set the restored files aside again: the only pre-restore snapshots are these two.
  assert.deepEqual(
    listSnapshots(directory)
      .filter(item => item.reason === 'pre-restore')
      .map(item => item.id)
      .sort(),
    [again.aside, kept.id].sort()
  );
  // Undoing gives back the data directory as it was before the first attempt.
  clock.advance(1000);
  await restoreSnapshot(directory, again.aside, { lock, release: '1.5.0', clock });
  assert.equal(fs.readFileSync(path.join(directory, 'config.json'), 'utf8'), before);
  assert.equal(fs.existsSync(path.join(directory, 'auth.json')), false);
  assert.deepEqual(services(path.join(directory, 'history.sqlite')), ['a', 'before the restore']);

  // Another restore over a completed one leaves that one's snapshot as it is and keeps no
  // journal for it: nothing of it is left to finish.
  const narrow = await createSnapshot(directory, { release: '1.5.0', history: false, clock });
  const halt = crashOnJournalRemoval(t);
  clock.advance(1000);
  await assert.rejects(restoreSnapshot(directory, snapshot.id, { lock, release: '1.5.0', clock }), {
    message: 'power lost',
  });
  halt();
  const second = interruptedRestore(directory);
  clock.advance(1000);
  const other = await restoreSnapshot(directory, narrow.id, { lock, release: '1.5.0', clock });
  assert.equal(other.unfinished, null);
  assert.equal(interruptedRestore(directory), null);
  assert.notEqual(other.aside, second.aside);
  assert.equal((await verifySnapshot(directory, second.aside)).ok, true, 'kept as it was');
  assert.equal(
    fs.readFileSync(path.join(root, second.aside, 'config.json'), 'utf8'),
    before,
    'its undo still holds what was there before it'
  );
});

test('running an interrupted restore again records a file that was not there before as absent in its undo', async t => {
  // The first attempt put the snapshot's control.sqlite where there was none (data from before
  // 1.5) and stopped at history.sqlite. Run again, the restore took that copy for a file it
  // replaced and set it aside, so undoing it brought back the snapshot's control.sqlite (stamped
  // as restored) instead of the layout without one.
  const { directory, history } = dataDirectory(t);
  history.close();
  const clock = manualClock();
  const lock = locked(t, directory);
  const snapshot = await createSnapshot(directory, { release: '1.5.0', clock });
  const control = path.join(directory, 'control.sqlite');
  fs.rmSync(control);
  const stop = crashOnRename(t, from => from.endsWith('.history.sqlite.restoring'));
  clock.advance(1000);
  await assert.rejects(restoreSnapshot(directory, snapshot.id, { lock, release: '1.5.0', clock }), {
    message: 'power lost',
  });
  stop();
  assert.equal(who(control), 'before', 'the first attempt put the snapshot’s copy in place');
  clock.advance(1000);
  const again = await restoreSnapshot(directory, snapshot.id, { lock, release: '1.5.0', clock });
  assert.deepEqual(again.kept, []);
  const aside = path.join(directory, snapshotsDirectory, again.aside);
  const manifest = JSON.parse(fs.readFileSync(path.join(aside, 'manifest.json'), 'utf8'));
  assert.deepEqual(manifest.absent, ['control.sqlite']);
  assert.equal(fs.existsSync(path.join(aside, 'control.sqlite')), false);
  assert.equal(who(control), 'before');
  clock.advance(1000);
  await restoreSnapshot(directory, again.aside, { lock, release: '1.5.0', clock });
  assert.equal(fs.existsSync(control), false, 'undone: no control.sqlite, as before');
});

test('a database an interrupted attempt set aside damaged is still named damaged by the attempt that completes', async t => {
  // The first attempt moved the damaged history.sqlite aside as it was, with its WAL, and was
  // stopped: once at the next rename, once after its folder got its final name (reopened). The
  // attempt that completes did not open that file, so its undo said "restore it to undo",
  // although the snapshot cannot be restored as a whole.
  for (const stopAt of ['swap', 'journal']) {
    const { directory, history } = dataDirectory(t);
    history.close();
    const clock = manualClock();
    const lock = locked(t, directory);
    const snapshot = await createSnapshot(directory, { release: '1.5.0', clock });
    const live = path.join(directory, 'history.sqlite');
    damage(live);
    fs.writeFileSync(`${live}-wal`, 'frames the damaged database still had');
    const stop =
      stopAt === 'swap'
        ? crashOnRename(t, from => from.endsWith('.history.sqlite.restoring'))
        : crashOnJournalRemoval(t);
    clock.advance(1000);
    await assert.rejects(
      restoreSnapshot(directory, snapshot.id, { lock, release: '1.5.0', clock }),
      { message: 'power lost' },
      stopAt
    );
    stop();
    const first = interruptedRestore(directory);
    clock.advance(1000);
    const again = await restoreSnapshot(directory, snapshot.id, { lock, release: '1.5.0', clock });
    assert.equal(again.aside, first.aside, stopAt);
    assert.deepEqual(
      again.damaged.map(item => item.name),
      ['history.sqlite'],
      stopAt
    );
    assert.match(again.damaged[0].problem, /file is not a database/);
    const manifest = JSON.parse(
      fs.readFileSync(
        path.join(directory, snapshotsDirectory, again.aside, 'manifest.json'),
        'utf8'
      )
    );
    assert.deepEqual(
      manifest.damaged.map(item => [item.name, item.sidecars]),
      [['history.sqlite', ['history.sqlite-wal']]],
      stopAt
    );
    assert.deepEqual(services(live), ['a'], stopAt);
    assert.equal(interruptedRestore(directory), null, stopAt);
  }
});

// ---------------------------------------------------------------------------------------------
// Saved files read back as input: the journal, manifests and the files a snapshot copies.

const snapshotModule = new URL('../../lib/db/snapshot.mjs', import.meta.url).href;
// Runs `code` (a module) in a child process with a deadline, `args` after it: a read that waits
// for a FIFO's writer would otherwise hold this test process for good.
const inChild = (code, args = []) =>
  spawnSync(process.execPath, ['--input-type=module', '-e', code, ...args], {
    encoding: 'utf8',
    timeout: 5000,
    killSignal: 'SIGKILL',
  });
const mkfifo = file => assert.equal(spawnSync('mkfifo', [file]).status, 0, `mkfifo ${file}`);

test('a restore journal that is a FIFO, a directory, larger than 1 MiB or nested too deeply reads as unreadable at once, and the start refuses (78)', async t => {
  const fifo = temporary(t);
  fs.mkdirSync(path.join(fifo, snapshotsDirectory));
  mkfifo(path.join(fifo, snapshotsDirectory, restoreJournal));
  const child = inChild(
    `import { interruptedRestore } from ${JSON.stringify(snapshotModule)};
     process.stdout.write(JSON.stringify(interruptedRestore(process.argv[1])));`,
    [fifo]
  );
  assert.equal(child.error, undefined, 'the read returns before the deadline');
  assert.equal(child.status, 0, child.stderr);
  assert.equal(JSON.parse(child.stdout).snapshot, null);

  const id = 'manual-1.5.0-20260901T000000000Z';
  const level = `{"snapshot":"${id}","files":["config.json"]`;
  // `depth` journals, each carrying the next as `unfinished`: valid at every level.
  const nested = depth =>
    `${level},"unfinished":`.repeat(depth - 1) + `${level}}` + '}'.repeat(depth - 1);
  const unreadable = { snapshot: null, aside: null, files: [], keepHistory: false };
  for (const [what, make] of [
    ['a directory', file => fs.mkdirSync(file)],
    // A journal Uptime Goblin could have written, past the limit only by trailing spaces.
    ['larger than 1 MiB', file => fs.writeFileSync(file, nested(1).padEnd(2 ** 20 + 1, ' '))],
    // The recursive parse ran out of stack (RangeError, exit 1 and a restart for ever).
    ['20,000 levels deep', file => fs.writeFileSync(file, nested(20000))],
    ['17 levels deep', file => fs.writeFileSync(file, nested(17))],
  ]) {
    const directory = temporary(t);
    fs.mkdirSync(path.join(directory, snapshotsDirectory));
    make(path.join(directory, snapshotsDirectory, restoreJournal));
    assert.deepEqual(interruptedRestore(directory), unreadable, what);
    await assert.rejects(
      startControl(directory, {
        lock: locked(t, directory),
        credentialConfigured: true,
        keyring: 'existing',
        env: {},
      }),
      error => error.code === 'restore_interrupted' && error.exitCode === 78,
      what
    );
  }
  // 16 restores are still read: a real chain is one or two long.
  const directory = temporary(t);
  fs.mkdirSync(path.join(directory, snapshotsDirectory));
  fs.writeFileSync(path.join(directory, snapshotsDirectory, restoreJournal), nested(16));
  assert.equal(interruptedRestore(directory).snapshot, id);
});

test('a manifest that is a FIFO, larger than 1 MiB or not a manifest lists its snapshot as invalid at once, never quoting it', async t => {
  const id = 'manual-1.5.0-20260901T000000000Z';
  const fifo = temporary(t);
  fs.mkdirSync(path.join(fifo, snapshotsDirectory, id), { recursive: true });
  mkfifo(path.join(fifo, snapshotsDirectory, id, 'manifest.json'));
  const child = inChild(
    `import { listSnapshots } from ${JSON.stringify(snapshotModule)};
     process.stdout.write(JSON.stringify(listSnapshots(process.argv[1])));`,
    [fifo]
  );
  assert.equal(child.error, undefined, 'the listing returns before the deadline');
  assert.equal(child.status, 0, child.stderr);
  assert.deepEqual(
    JSON.parse(child.stdout).map(({ valid, problem }) => ({ valid, problem })),
    [{ valid: false, problem: 'manifest.json is not a regular file' }]
  );

  const directory = temporary(t);
  const folder = path.join(directory, snapshotsDirectory, id);
  fs.mkdirSync(folder, { recursive: true });
  const good = {
    format: 1,
    id,
    reason: 'manual',
    release: '1.5.0',
    fromRelease: null,
    createdAt: 1,
    pinned: false,
    files: [
      { name: 'config.json', bytes: 0, sha256: 'a'.repeat(64) },
      { name: 'auth.json', bytes: 57, sha256: 'b'.repeat(64) },
    ],
  };
  const listed = text => {
    fs.writeFileSync(path.join(folder, 'manifest.json'), text);
    const [item] = listSnapshots(directory);
    return item;
  };
  for (const [what, text, problem] of [
    // The parse error quoted the file: `snapshots` printed it.
    ['not JSON', 'SYNTH-MANIFEST-CANARY {', 'manifest.json is not valid JSON'],
    [
      'larger than 1 MiB',
      JSON.stringify(good).padEnd(2 ** 20 + 1, ' '),
      'manifest.json is larger than 1 MiB',
    ],
    // Sizes as text were added up as text: "057 B".
    [
      'a size as text',
      JSON.stringify({ ...good, files: good.files.map(file => ({ ...file, bytes: '57' })) }),
      'manifest.json is not a valid snapshot manifest',
    ],
    [
      'a file without a checksum',
      JSON.stringify({ ...good, files: [{ name: 'config.json', bytes: 1 }] }),
      'manifest.json is not a valid snapshot manifest',
    ],
  ]) {
    const item = listed(text);
    assert.equal(item.valid, false, what);
    assert.equal(item.problem, problem, what);
  }
  assert.equal(listed(JSON.stringify(good)).bytes, 57, 'whole sizes are added up');
});

test('a snapshot never waits for a FIFO: one in place of config.json refuses the snapshot, one in place of a copy fails --verify', async t => {
  const directory = temporary(t);
  mkfifo(path.join(directory, 'config.json'));
  const refused = inChild(
    `import { createSnapshot } from ${JSON.stringify(snapshotModule)};
     await createSnapshot(process.argv[1], { release: '1.5.0' }).then(
       () => process.stdout.write('taken'),
       error => process.stdout.write(JSON.stringify({ reason: error.reason, refusal: error.refusal }))
     );`,
    [directory]
  );
  assert.equal(refused.error, undefined, 'the snapshot returns before the deadline');
  assert.deepEqual(JSON.parse(refused.stdout), { reason: 'not-file', refusal: true });
  // Refused before anything is written: no staging folder, and no snapshots/ either.
  assert.equal(fs.existsSync(path.join(directory, snapshotsDirectory)), false);

  const data = dataDirectory(t);
  data.history.close();
  const snapshot = await createSnapshot(data.directory, { release: '1.5.0' });
  fs.rmSync(path.join(snapshot.path, 'config.json'));
  mkfifo(path.join(snapshot.path, 'config.json'));
  const verified = inChild(
    `import { verifySnapshot } from ${JSON.stringify(snapshotModule)};
     process.stdout.write(JSON.stringify(await verifySnapshot(process.argv[1], process.argv[2])));`,
    [data.directory, snapshot.id]
  );
  assert.equal(verified.error, undefined, 'the check returns before the deadline');
  assert.equal(verified.status, 0, verified.stderr);
  const { ok, problems } = JSON.parse(verified.stdout);
  assert.equal(ok, false);
  assert.deepEqual(problems, ['config.json is not a regular file']);
});

test('the restore journal is written through a temporary file of its own: a link planted at the fixed name it had is never followed', async t => {
  const { directory, history } = dataDirectory(t);
  history.close();
  const lock = locked(t, directory);
  const snapshot = await createSnapshot(directory, { release: '1.5.0' });
  // Outside the data directory: the restore wrote the journal through the link into it.
  const victim = path.join(temporary(t), 'victim.txt');
  fs.writeFileSync(victim, 'VICTIM-ORIGINAL-CONTENT');
  const root = path.join(directory, snapshotsDirectory);
  const planted = path.join(root, `${restoreJournal}.tmp`);
  fs.symlinkSync(victim, planted);
  await restoreSnapshot(directory, snapshot.id, { lock, release: '1.5.0' });
  assert.equal(fs.readFileSync(victim, 'utf8'), 'VICTIM-ORIGINAL-CONTENT');
  assert.ok(fs.lstatSync(planted).isSymbolicLink(), 'the link is left as it was');
  assert.equal(interruptedRestore(directory), null, 'the restore completed');
  assert.deepEqual(
    fs.readdirSync(root).filter(name => name.endsWith('.tmp')),
    [`${restoreJournal}.tmp`],
    'no temporary file of its own is left'
  );
});

test('unchangedSince never hashes a FIFO that took the place of config.json', async t => {
  const directory = temporary(t);
  // An empty config.json: the copy's size (0) matches a FIFO's, so only its hash would differ.
  fs.writeFileSync(path.join(directory, 'config.json'), '');
  const snapshot = await createSnapshot(directory, { release: '1.5.0' });
  fs.rmSync(path.join(directory, 'config.json'));
  mkfifo(path.join(directory, 'config.json'));
  const child = inChild(
    `import { unchangedSince } from ${JSON.stringify(snapshotModule)};
     process.stdout.write(String(await unchangedSince(process.argv[1], process.argv[2])));`,
    [directory, snapshot.id]
  );
  assert.equal(child.error, undefined, 'it returns before the deadline');
  assert.equal(child.stdout, 'false');
});

test('a link to nothing or a loop in place of a file a snapshot copies refuses it, writing nothing; left out, history.sqlite is excluded, never absent', async t => {
  // A volume that is not mounted: read as absent, the file was recorded so, and restoring the
  // snapshot once the volume was back moved the live file out of the data directory.
  for (const [name, loop] of [
    ['config.json', false],
    ['auth.json', false],
    ['control.sqlite', false],
    ['history.sqlite', false],
    ['control.sqlite', true],
  ]) {
    const { directory, history } = dataDirectory(t);
    history.close();
    const elsewhere = temporary(t);
    const live = path.join(directory, name);
    fs.rmSync(live);
    fs.symlinkSync(loop ? name : path.join(elsewhere, name), live);
    const what = `${name}${loop ? ' (loop)' : ''}`;
    await assert.rejects(
      createSnapshot(directory, { release: '1.5.0' }),
      error =>
        error instanceof SnapshotError &&
        error.code === 'live_file_unusable' &&
        error.refusal === true &&
        error.reason === (loop ? 'not-file' : 'dangling') &&
        error.message ===
          `No snapshot was taken: ${live} ${loop ? 'is not a regular file' : 'is a symbolic link to nothing that exists'}. Nothing was written to snapshots/. Put the file back in its place (mount the volume a link points to), or move what is there out of the data directory, then take the snapshot again.`,
      what
    );
    assert.equal(fs.existsSync(path.join(directory, snapshotsDirectory)), false, what);
    assert.deepEqual(fs.readdirSync(elsewhere), [], `${what}: nothing created through the link`);
    assert.ok(fs.lstatSync(live).isSymbolicLink(), `${what}: the link is left as it is`);
  }
  // history.sqlite left out is not read: recorded as left out (restoring keeps it), not absent.
  const { directory, history } = dataDirectory(t);
  history.close();
  fs.rmSync(path.join(directory, 'history.sqlite'));
  fs.symlinkSync(path.join(temporary(t), 'history.sqlite'), path.join(directory, 'history.sqlite'));
  const { manifest } = await createSnapshot(directory, { release: '1.5.0', history: false });
  assert.deepEqual(
    manifest.files.map(file => file.name),
    ['config.json', 'auth.json', 'control.sqlite']
  );
  assert.deepEqual(manifest.excluded, ['history.sqlite']);
  assert.deepEqual(manifest.absent, []);
});

test('unchangedSince counts a link to nothing where the snapshot found no file as a change', async t => {
  // Read as absent, a pre-upgrade snapshot that recorded auth.json absent was reused, and
  // restoring it removed the auth.json the link names once its volume was back.
  const directory = temporary(t);
  fs.writeFileSync(path.join(directory, 'config.json'), '{"services":[]}\n');
  const snapshot = await createSnapshot(directory, { release: '1.5.0' });
  assert.equal(await unchangedSince(directory, snapshot.id), true);
  fs.symlinkSync(path.join(temporary(t), 'auth.json'), path.join(directory, 'auth.json'));
  assert.equal(await unchangedSince(directory, snapshot.id), false);
});
