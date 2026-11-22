// The storage guard (lib/storage-guard.mjs, delivery spec §4.4, T8): the 8 MiB reserve, when
// the disk counts as full and when it stops, what a release frees, quotas and file systems that
// cannot be measured. statfs is faked; the reserve is written for real in a temporary directory.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import {
  createStorageGuard,
  isDiskFull,
  StorageFullError,
  RESERVE_FILE,
  RESERVE_BYTES,
  LOW_WATER_BYTES,
  HIGH_WATER_BYTES,
  storageFullMessage,
} from '../lib/storage-guard.mjs';
import { quietLogger } from './alerting/fake-clock.mjs';

const MiB = 2 ** 20;

function temporary(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-guard-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

/**
 * A disk whose free space is `disk.free` plus the reserve's size while the reserve is gone (a
 * release frees its blocks), unless `keepsBlocks` (a snapshot keeps them). `disk.fail` makes
 * statfs throw; `disk.blocks = 0` reports no size.
 */
function fakeDisk(directory, { free = 100 * MiB, reserveBytes = RESERVE_BYTES } = {}) {
  const disk = { free, keepsBlocks: false, fail: false, blocks: 1e6, calls: 0 };
  disk.statfs = () => {
    disk.calls++;
    if (disk.fail) throw Object.assign(new Error('not supported'), { code: 'ENOSYS' });
    const held = fs.existsSync(path.join(directory, RESERVE_FILE));
    const bytes = disk.free + (held || disk.keepsBlocks || !disk.reserveGone ? 0 : reserveBytes);
    return { bsize: 4096, frsize: 4096, blocks: disk.blocks, bavail: Math.floor(bytes / 4096) };
  };
  return disk;
}

function setup(t, options = {}) {
  const directory = options.directory ?? temporary(t);
  const disk = fakeDisk(directory, options);
  const logger = quietLogger(),
    changes = [];
  let mono = 0,
    wall = 1_800_000_000_000;
  const guard = createStorageGuard({
    directory,
    statfs: disk.statfs,
    clock: () => wall,
    monotonic: () => mono,
    logger,
    onChange: state => changes.push(state),
    ...options.guard,
  });
  return {
    directory,
    disk,
    guard,
    logger,
    changes,
    reserve: path.join(directory, RESERVE_FILE),
    advance(ms) {
      mono += ms;
      wall += ms;
    },
  };
}
// Space a full disk frees when the reserve goes (the fake counts it only once released).
const released = disk => (disk.reserveGone = true);

test('the thresholds and the error: 8 MiB reserve, full below 2 MiB, back at 24 MiB', () => {
  assert.equal(RESERVE_FILE, 'run/space-reserve');
  assert.equal(RESERVE_BYTES, 8 * MiB);
  assert.equal(LOW_WATER_BYTES, 2 * MiB);
  assert.equal(HIGH_WATER_BYTES, 24 * MiB);
  const error = new StorageFullError();
  assert.ok(error instanceof Error);
  assert.deepEqual(
    [error.status, error.code, error.retryAfter, error.message],
    [503, 'storage_full', 60, storageFullMessage]
  );
  assert.equal(
    storageFullMessage,
    "Uptime Goblin's disk is full, so this change was not saved. Free some space on the Uptime Goblin host, then try again. Sign-in and alert delivery keep working on space Uptime Goblin keeps in reserve."
  );
});

test('isDiskFull: ENOSPC, EDQUOT, a full control database and storage_full; never history SQLITE_FULL', () => {
  for (const error of [
    Object.assign(new Error('no space left on device'), { code: 'ENOSPC' }),
    Object.assign(new Error('quota exceeded'), { code: 'EDQUOT' }),
    { class: 'full', message: 'database or disk is full' },
    { code: 'storage_full' },
    new StorageFullError(),
  ])
    assert.equal(isDiskFull(error), true, JSON.stringify(error));
  for (const error of [
    // history.sqlite's own SQLITE_FULL: capped by its budget and recycling, so normal.
    Object.assign(new Error('database or disk is full'), { code: 'ERR_SQLITE_ERROR', errcode: 13 }),
    { class: 'unavailable' },
    { code: 'EACCES' },
    new TypeError('bad'),
    null,
    undefined,
    'ENOSPC',
  ])
    assert.equal(isDiskFull(error), false, JSON.stringify(error));
});

test('start() writes 8 MiB of random bytes (0600, run/ 0700); atStart() creates nothing', t => {
  const { directory, guard, reserve, disk } = setup(t);
  assert.equal(guard.atStart().full, false);
  assert.equal(fs.existsSync(path.join(directory, 'run')), false, 'atStart creates nothing');
  const state = guard.start();
  assert.equal(state.full, false);
  assert.equal(state.reserveHeld, true);
  assert.equal(fs.statSync(reserve).size, RESERVE_BYTES);
  assert.equal(fs.statSync(reserve).mode & 0o777, 0o600);
  assert.equal(fs.statSync(path.dirname(reserve)).mode & 0o777, 0o700);
  assert.equal(fs.existsSync(path.join(directory, 'run/.space-reserve.tmp')), false);
  // Random: it does not compress, and no 1 MiB chunk repeats another.
  const bytes = fs.readFileSync(reserve);
  assert.ok(zlib.deflateRawSync(bytes).length > RESERVE_BYTES * 0.99);
  const chunks = new Set();
  for (let at = 0; at < bytes.length; at += MiB)
    chunks.add(bytes.subarray(at, at + MiB).toString('base64'));
  assert.equal(chunks.size, 8);
  // A second start keeps it.
  const before = fs.statSync(reserve).mtimeMs;
  guard.start();
  assert.equal(fs.statSync(reserve).mtimeMs, before);
  assert.ok(disk.calls > 0);
});

test('a start below the high-water mark creates no reserve; a full start releases one left before', t => {
  const { directory, guard, disk, reserve, changes } = setup(t, { free: 10 * MiB });
  guard.start();
  assert.equal(fs.existsSync(reserve), false, 'between the marks: no new reserve');
  assert.equal(guard.state().full, false);
  // A reserve from an earlier run, on a disk that filled while Uptime Goblin was stopped.
  fs.mkdirSync(path.dirname(reserve), { recursive: true });
  fs.writeFileSync(reserve, Buffer.alloc(RESERVE_BYTES, 1));
  disk.free = MiB;
  released(disk);
  const state = guard.atStart();
  assert.equal(state.full, true);
  assert.equal(state.reserveReleased, true);
  assert.equal(state.freed, true);
  assert.equal(fs.existsSync(reserve), false);
  assert.deepEqual(fs.readdirSync(path.join(directory, 'run')), []);
  assert.equal(changes.length, 1);
});

test('a filling disk enters full: the reserve is released, settings refused, the banner shown', t => {
  const { guard, disk, reserve, logger, changes } = setup(t);
  guard.start();
  assert.equal(guard.banner(), null);
  assert.doesNotThrow(() => guard.admitConfigWrite());
  disk.free = LOW_WATER_BYTES + 1;
  assert.equal(guard.check().full, false, 'not below the low-water mark yet');
  disk.free = LOW_WATER_BYTES - 1;
  released(disk);
  const state = guard.check();
  assert.equal(state.full, true);
  assert.equal(state.since, 1_800_000_000_000);
  assert.equal(state.reserveHeld, false);
  assert.equal(state.reserveReleased, true);
  assert.equal(state.freed, true);
  assert.equal(state.freeBytes, Math.floor((LOW_WATER_BYTES - 1 + RESERVE_BYTES) / 4096) * 4096);
  assert.equal(fs.existsSync(reserve), false);
  assert.deepEqual(logger.lines.error, [
    'The disk of the Uptime Goblin host is full: Uptime Goblin released its 8 MiB reserve for sign-in and alert delivery; settings cannot be saved and readings are paused until space is freed.',
  ]);
  assert.deepEqual(guard.banner(), {
    full: true,
    since: 1_800_000_000_000,
    freeBytes: state.freeBytes,
    reserveReleased: true,
    freed: true,
  });
  assert.throws(() => guard.admitConfigWrite(), StorageFullError);
  assert.equal(changes.length, 1);
  assert.equal(changes[0].full, true);
  // Checks while full change nothing and log nothing more.
  guard.check();
  guard.check();
  assert.equal(logger.lines.error.length, 1);
  assert.equal(changes.length, 1);
});

test('a write error enters full at once; history SQLITE_FULL never does', t => {
  const { guard, reserve, changes } = setup(t);
  guard.start();
  const history = Object.assign(new Error('database or disk is full'), {
    code: 'ERR_SQLITE_ERROR',
    errcode: 13,
  });
  assert.equal(guard.noteWriteError(history), false);
  assert.equal(guard.noteWriteError(new Error('other')), false);
  assert.equal(guard.state().full, false);
  assert.equal(fs.existsSync(reserve), true);
  for (const error of [
    Object.assign(new Error('no space'), { code: 'ENOSPC' }),
    Object.assign(new Error('quota'), { code: 'EDQUOT' }),
    { class: 'full' },
    { code: 'storage_full' },
  ]) {
    assert.equal(guard.noteWriteError(error), true);
    assert.equal(guard.state().full, true);
  }
  assert.equal(changes.length, 1, 'entered once');
  assert.equal(fs.existsSync(reserve), false, 'released at once');
});

test('leaving full needs the high-water mark and the reserve written back (hysteresis)', t => {
  const { guard, disk, reserve, logger, changes } = setup(t);
  guard.start();
  disk.free = MiB;
  released(disk);
  guard.check();
  assert.equal(guard.state().full, true);
  // Space returns, but not enough: still full, nothing written.
  disk.free = HIGH_WATER_BYTES - RESERVE_BYTES - 1;
  assert.equal(guard.check().full, true, 'below the high-water mark with the reserve gone');
  assert.equal(fs.existsSync(reserve), false);
  disk.free = HIGH_WATER_BYTES;
  const state = guard.check();
  assert.equal(state.full, false);
  assert.equal(state.reserveHeld, true);
  assert.equal(fs.statSync(reserve).size, RESERVE_BYTES);
  assert.deepEqual(logger.lines.info, [
    'Disk space is back: settings can be saved and readings are saved again.',
  ]);
  assert.deepEqual(
    changes.map(item => item.full),
    [true, false]
  );
  assert.equal(guard.banner(), null);
  assert.doesNotThrow(() => guard.admitConfigWrite());
  assert.deepEqual(
    [state.since, state.reserveReleased, state.freed, state.nextRecreateAt],
    [null, false, null, null]
  );
});

test('a release that frees nothing (snapshots keep the blocks) says so', t => {
  const { guard, disk, logger } = setup(t);
  guard.start();
  disk.free = MiB;
  disk.keepsBlocks = true;
  const state = guard.check();
  assert.equal(state.full, true);
  assert.equal(state.reserveReleased, true);
  assert.equal(state.freed, false);
  assert.equal(guard.banner().freed, false);
  assert.deepEqual(logger.lines.error, [
    'The disk of the Uptime Goblin host is full: Uptime Goblin released its 8 MiB reserve, but the file system did not free the space (snapshots or a shared pool keep it); settings cannot be saved and readings are paused until space is freed.',
  ]);
});

test('a reserve that cannot be written back (a quota statfs does not show) waits 5 minutes between tries', t => {
  const { guard, disk, reserve, directory, advance, logger } = setup(t);
  guard.start();
  guard.noteWriteError(Object.assign(new Error('quota'), { code: 'EDQUOT' }));
  assert.equal(guard.state().full, true);
  // statfs shows plenty of space, but every write past 1 MiB hits the quota.
  disk.free = 500 * MiB;
  let writes = 0;
  const write = fs.writeSync;
  t.mock.method(fs, 'writeSync', function (descriptor, buffer, ...rest) {
    writes++;
    if (writes % 2 === 0) throw Object.assign(new Error('Disk quota exceeded'), { code: 'EDQUOT' });
    return write.call(fs, descriptor, buffer, ...rest);
  });
  let state = guard.check();
  assert.equal(state.full, true, 'still full');
  assert.equal(writes, 2);
  assert.equal(fs.existsSync(path.join(directory, 'run/.space-reserve.tmp')), false, 'cleaned up');
  assert.equal(fs.existsSync(reserve), false);
  assert.equal(state.nextRecreateAt, 1_800_000_000_000 + 300000);
  assert.match(logger.lines.warn[0], /could not write its 8 MiB disk reserve \(EDQUOT\)/);
  // No new try for 5 minutes (monotonic), however often the guard checks.
  for (let n = 0; n < 29; n++) {
    advance(10000);
    guard.check();
  }
  assert.equal(writes, 2, 'no 8 MiB write every 10 s');
  advance(10000);
  guard.check();
  assert.equal(writes, 4, 'tried again after 5 minutes');
  assert.equal(guard.state().full, true);
  // The quota is raised: the next try succeeds and the guard leaves full.
  t.mock.restoreAll();
  advance(300000);
  assert.equal(guard.check().full, false);
  assert.equal(fs.statSync(reserve).size, RESERVE_BYTES);
});

test('a file system that cannot be measured is full only after a failed write, and tries again later', t => {
  const { guard, disk, reserve, advance, changes } = setup(t);
  disk.fail = true;
  // Start: the reserve is written (there is no way to know the space; a failure would tell).
  assert.equal(guard.start().measurable, false);
  assert.equal(fs.existsSync(reserve), true);
  assert.equal(guard.check().full, false, 'never full by itself');
  guard.noteWriteError(Object.assign(new Error('no space'), { code: 'ENOSPC' }));
  let state = guard.state();
  assert.equal(state.full, true);
  assert.equal(state.reserveReleased, true);
  assert.equal(state.freed, null, 'unknown: nothing to measure');
  // The reserve is tried again 60 s later; written, the guard leaves full.
  advance(59000);
  assert.equal(guard.check().full, true);
  advance(1000);
  state = guard.check();
  assert.equal(state.full, false);
  assert.equal(fs.existsSync(reserve), true);
  // The next disk-full error enters again; a reserve write that fails backs off 5 minutes.
  guard.noteWriteError({ class: 'full' });
  t.mock.method(fs, 'openSync', () => {
    throw Object.assign(new Error('no space'), { code: 'ENOSPC' });
  });
  advance(60000);
  assert.equal(guard.check().full, true);
  advance(299000);
  assert.equal(guard.check().full, true);
  t.mock.restoreAll();
  advance(1000);
  assert.equal(guard.check().full, false);
  assert.deepEqual(
    changes.map(item => item.full),
    [true, false, true, false]
  );
  // A size of 0 counts as unmeasurable too.
  disk.fail = false;
  disk.blocks = 0;
  assert.equal(guard.check().measurable, false);
});

test('a deleted or damaged reserve is written again while there is room; a stale temporary file goes', t => {
  const { guard, reserve, directory } = setup(t);
  guard.start();
  fs.rmSync(reserve);
  assert.equal(guard.state().reserveHeld, false);
  assert.equal(guard.check().reserveHeld, true);
  fs.truncateSync(reserve, 100);
  assert.equal(guard.state().reserveHeld, false, 'a short file is not the reserve');
  guard.check();
  assert.equal(fs.statSync(reserve).size, RESERVE_BYTES);
  // A crash part way through a write left the temporary file: it is replaced, not appended to.
  fs.rmSync(reserve);
  fs.writeFileSync(path.join(directory, 'run/.space-reserve.tmp'), 'partial');
  guard.check();
  assert.equal(fs.statSync(reserve).size, RESERVE_BYTES);
  assert.equal(fs.existsSync(path.join(directory, 'run/.space-reserve.tmp')), false);
});

test('without a reserve (reserveBytes 0, the measurement run) nothing is written or released', t => {
  const { guard, disk, reserve, logger } = setup(t, { guard: { reserveBytes: 0 } });
  guard.start();
  assert.equal(fs.existsSync(reserve), false);
  disk.free = MiB;
  const state = guard.check();
  assert.deepEqual([state.full, state.reserveReleased, state.freed], [true, false, null]);
  assert.deepEqual(logger.lines.error, [
    'The disk of the Uptime Goblin host is full; settings cannot be saved and readings are paused until space is freed.',
  ]);
  disk.free = HIGH_WATER_BYTES;
  assert.equal(guard.check().full, false);
  assert.equal(fs.existsSync(reserve), false);
});

test('an onChange that throws never breaks the guard', t => {
  const directory = temporary(t);
  const disk = fakeDisk(directory, { free: MiB });
  const logger = quietLogger();
  const guard = createStorageGuard({
    directory,
    statfs: disk.statfs,
    logger,
    onChange: () => {
      throw new Error('the notice failed');
    },
  });
  assert.equal(guard.check().full, true);
  assert.ok(logger.lines.error.some(line => /notice could not be handled/.test(line)));
  assert.throws(() => createStorageGuard({}), TypeError);
  assert.throws(() => createStorageGuard({ directory, reserveBytes: -1 }), TypeError);
});
