// The storage guard (delivery spec §4.4, roadmap T8): what Uptime Goblin does when the disk of its data
// directory fills up.
//
// Without held-back space nothing can promise that a sign-in fits on a full disk: SQLite's WAL
// must grow again after a checkpoint has truncated it, and SQLite removes the WAL when Uptime Goblin
// stops, so the first writes after a restart always need new space. So the guard keeps an 8 MiB
// reserve file, <data>/run/space-reserve, of random bytes (compression and sparse files cannot
// fake it). When the disk is full it deletes the reserve, so sign-in, sessions and alert
// delivery keep working on the space it frees, while configuration writes are refused (503
// storage_full) and readings are paused (lib/store.mjs pauseReadings); the delivery service
// sends a notice. When space returns, the reserve is written again and everything resumes.
//
//   const guard = createStorageGuard({directory, onChange: state => …});
//   guard.atStart();          // before startControl: releases the reserve on a full disk
//   guard.start();            // once started: creates the reserve, or enters full
//   guard.check();            // every 10 s (job storage.guard)
//   guard.noteWriteError(e);  // a write failed: a disk-full error enters full at once
//   guard.admitConfigWrite(); // throws StorageFullError while full
//
// "Full" means less than `lowWater` (2 MiB) free for Uptime Goblin's user; it ends at `highWater`
// (8 MiB + 16 MiB) once the reserve could be written again, so the guard does not flap around
// one threshold. A file system that cannot be measured (statfs fails or reports no size) is
// full only after a failed write. Free space is bavail × (frsize || bsize): what a non-root
// user may use, as Uptime Goblin runs as `uptime-goblin` or `node`.
//
// Limits (docs/installation.md): on a copy-on-write file system with snapshots (btrfs, ZFS) or a
// full thin pool, deleting the reserve may free nothing; the guard measures that (`freed`) and
// says so. A user quota (EDQUOT) is seen only through failed writes; a reserve that cannot be
// written then is retried after `recreateBackoffMs` (5 minutes), so a quota never makes the
// guard write 8 MiB every check.
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';

export const RESERVE_FILE = 'run/space-reserve';
export const RESERVE_BYTES = 8 * 2 ** 20;
/** Full below this free space. */
export const LOW_WATER_BYTES = 2 * 2 ** 20;
/** Not full again at or above this free space (and only once the reserve is written again). */
export const HIGH_WATER_BYTES = RESERVE_BYTES + 16 * 2 ** 20;
const temporaryFile = 'run/.space-reserve.tmp';
const chunkBytes = 2 ** 20;
// An unmeasurable file system: the first try to recreate the reserve after a disk-full error.
const unmeasurableRetryMs = 60000;

export const storageFullMessage =
  "Uptime Goblin's disk is full, so this change was not saved. Free some space on the Uptime Goblin host, then try again. Sign-in and alert delivery keep working on space Uptime Goblin keeps in reserve.";

/** A configuration write refused while the disk is full: 503, code storage_full, Retry-After 60. */
export class StorageFullError extends Error {
  constructor(message = storageFullMessage) {
    super(message);
    this.name = 'StorageFullError';
    this.status = 503;
    this.code = 'storage_full';
    this.retryAfter = 60;
  }
}

/**
 * ENOSPC or EDQUOT (a file write, such as config.json), `error.class === 'full'` (the Db
 * wrapper's classification, used for control.sqlite), or `error.code === 'storage_full'`
 * (identity's AuthError and StorageFullError). A raw node:sqlite SQLITE_FULL without a class
 * comes only from lib/store.mjs (history, capped and recycling) and does not count.
 */
export function isDiskFull(error) {
  if (!error || typeof error !== 'object') return false;
  return (
    error.code === 'ENOSPC' ||
    error.code === 'EDQUOT' ||
    error.class === 'full' ||
    error.code === 'storage_full'
  );
}

const mib = bytes => `${Math.round((bytes / 2 ** 20) * 10) / 10} MiB`;

/**
 * The guard of `directory` (the data directory). Options: statfs, clock (wall, epoch ms),
 * monotonic (ms, for the back-off), logger, reserveBytes (0: no reserve, for measurements),
 * lowWater, highWater, recreateBackoffMs and onChange(state), called after every enter and
 * leave.
 */
export function createStorageGuard({
  directory,
  statfs = fs.statfsSync,
  clock = Date.now,
  monotonic = () => performance.now(),
  logger = console,
  reserveBytes = RESERVE_BYTES,
  lowWater = LOW_WATER_BYTES,
  highWater = HIGH_WATER_BYTES,
  recreateBackoffMs = 300000,
  onChange = () => {},
} = {}) {
  if (typeof directory !== 'string' || !directory)
    throw new TypeError('createStorageGuard needs the data directory');
  if (!Number.isSafeInteger(reserveBytes) || reserveBytes < 0)
    throw new TypeError('reserveBytes must be a whole number of bytes');
  const reserve = path.join(directory, RESERVE_FILE),
    temporary = path.join(directory, temporaryFile),
    runDirectory = path.dirname(reserve);
  let full = false,
    since = null,
    freeBytes = null,
    measurable = true,
    reserveReleased = false,
    freed = null,
    retryAt = null; // monotonic time before which no recreate is tried

  /** Free bytes for Uptime Goblin's user, or null when the file system cannot be measured. */
  function measure() {
    let stats;
    try {
      stats = statfs(directory);
    } catch {
      measurable = false;
      freeBytes = null;
      return null;
    }
    const unit = stats?.frsize || stats?.bsize;
    if (!(stats?.blocks > 0) || !(unit > 0) || !Number.isFinite(stats?.bavail)) {
      measurable = false;
      freeBytes = null;
      return null;
    }
    measurable = true;
    freeBytes = Math.max(0, stats.bavail * unit);
    return freeBytes;
  }

  // The reserve counts as held only when it is a regular file of the full size.
  function reserveHeld() {
    if (!reserveBytes) return false;
    try {
      const stat = fs.lstatSync(reserve);
      return stat.isFile() && stat.size >= reserveBytes;
    } catch {
      return false;
    }
  }
  const remove = file => {
    try {
      fs.unlinkSync(file);
      return true;
    } catch (error) {
      if (error.code === 'ENOENT') return false;
      throw error;
    }
  };

  /**
   * Writes the reserve: a temporary file (exclusive, 0600) of random 1 MiB chunks, fsynced,
   * then renamed into place. A failure deletes the partial file and throws.
   */
  function writeReserve() {
    fs.mkdirSync(runDirectory, { recursive: true, mode: 0o700 });
    // A temporary file left by a crash part way is not ours to keep.
    remove(temporary);
    let descriptor;
    try {
      descriptor = fs.openSync(temporary, 'wx', 0o600);
      for (let written = 0; written < reserveBytes; ) {
        const chunk = randomBytes(Math.min(chunkBytes, reserveBytes - written));
        let offset = 0;
        while (offset < chunk.length)
          offset += fs.writeSync(descriptor, chunk, offset, chunk.length - offset);
        written += chunk.length;
      }
      fs.fsyncSync(descriptor);
      const closing = descriptor;
      descriptor = undefined;
      fs.closeSync(closing);
      fs.renameSync(temporary, reserve);
    } catch (error) {
      if (descriptor !== undefined)
        try {
          fs.closeSync(descriptor);
        } catch {}
      try {
        remove(temporary);
      } catch {}
      throw error;
    }
  }

  const state = () => ({
    full,
    since,
    freeBytes,
    reserveHeld: reserveHeld(),
    reserveReleased,
    freed,
    measurable,
    nextRecreateAt: retryAt === null ? null : clock() + Math.max(0, retryAt - monotonic()),
  });
  const changed = () => {
    try {
      onChange(state());
    } catch (error) {
      logger.error?.('The disk-space notice could not be handled:', error?.message ?? error);
    }
  };

  // Enters "full": releases the reserve and checks the file system really freed its space.
  function enter() {
    if (full) return;
    full = true;
    since = clock();
    const before = measure();
    let released = false;
    if (reserveHeld())
      try {
        released = remove(reserve);
      } catch (error) {
        logger.error?.(
          `Uptime Goblin could not release its disk reserve (${error.code || error.message}).`
        );
      }
    reserveReleased = released;
    if (released) {
      const after = measure();
      freed = before === null || after === null ? null : after - before >= reserveBytes / 2;
    } else freed = null;
    // An unmeasurable file system shows no space coming back: try the reserve again later.
    retryAt = measurable ? null : monotonic() + unmeasurableRetryMs;
    logger.error?.(
      released
        ? freed === false
          ? `The disk of the Uptime Goblin host is full: Uptime Goblin released its ${mib(reserveBytes)} reserve, but the file system did not free the space (snapshots or a shared pool keep it); settings cannot be saved and readings are paused until space is freed.`
          : `The disk of the Uptime Goblin host is full: Uptime Goblin released its ${mib(reserveBytes)} reserve for sign-in and alert delivery; settings cannot be saved and readings are paused until space is freed.`
        : 'The disk of the Uptime Goblin host is full; settings cannot be saved and readings are paused until space is freed.'
    );
    changed();
  }

  function leave() {
    full = false;
    since = null;
    reserveReleased = false;
    freed = null;
    retryAt = null;
    logger.info?.('Disk space is back: settings can be saved and readings are saved again.');
    changed();
  }

  // Writes the reserve back. Returns whether it is held now; a failure starts the back-off.
  function recreate() {
    if (!reserveBytes || reserveHeld()) return true;
    try {
      writeReserve();
      retryAt = null;
      return true;
    } catch (error) {
      retryAt = monotonic() + recreateBackoffMs;
      logger.warn?.(
        `Uptime Goblin could not write its ${mib(reserveBytes)} disk reserve (${error.code || error.message}); it tries again in ${Math.round(recreateBackoffMs / 60000)} minute(s).`
      );
      // Writing it is what showed the disk is full (a quota statfs does not show).
      if (isDiskFull(error) && !full) enter();
      return false;
    }
  }
  const mayRecreate = () => retryAt === null || monotonic() >= retryAt;

  return Object.freeze({
    /**
     * Before anything else at start: a disk already full releases the reserve (so the start's
     * own writes fit). Measures only; creates nothing.
     */
    atStart() {
      const free = measure();
      if (free !== null && free < lowWater) enter();
      return state();
    },
    /** Once Uptime Goblin has started: creates a missing reserve when there is room, or enters full. */
    start() {
      const free = measure();
      if (free !== null && free < lowWater) enter();
      else if (!full && (free === null || free >= highWater)) recreate();
      return state();
    },
    /** The periodic check: enters or leaves "full" (leaving writes the reserve back). */
    check() {
      const free = measure();
      if (!full) {
        if (free !== null && free < lowWater) enter();
        // A reserve someone deleted is written again while there is plenty of room.
        else if (free !== null && free >= highWater && mayRecreate()) recreate();
        return state();
      }
      if ((free === null || free >= highWater) && mayRecreate() && recreate()) leave();
      return state();
    },
    /** A write failed: a disk-full error enters "full" at once. Returns whether it was one. */
    noteWriteError(error) {
      if (!isDiskFull(error)) return false;
      enter();
      return true;
    },
    /** Throws StorageFullError while the disk is full (configuration writes wait). */
    admitConfigWrite() {
      if (full) throw new StorageFullError();
    },
    state,
    /** The dashboard's `disk` field: null, or what the banner says. */
    banner: () => (full ? { full: true, since, freeBytes, reserveReleased, freed } : null),
  });
}
