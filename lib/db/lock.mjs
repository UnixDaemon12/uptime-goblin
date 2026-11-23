// The data-directory lock, <data>/goblin.lock (and orbit.lock, its name before 1.5) (roadmap §2.2 start step 1, §3.1).
//
// Exactly one Uptime Goblin process (or one offline goblin-admin command) may own a data directory. The
// lock is an exclusive SQLite lock on an empty database file: no dependency, and the operating
// system releases it when the holder exits, however it exits (kill -9 included), so a stale
// lock never needs clearing by hand.
//
// A start that finds the lock held exits 75: in the normal case it is the previous process
// still shutting down after `systemctl restart`, and the service manager starts it again 5 s
// later. Offline goblin-admin commands report "Uptime Goblin is running" instead.
//
// Never open, read or copy either lock file with fs while this process holds it: closing any file
// descriptor of the file drops the process's POSIX locks. Snapshots and backups skip it.
import fs from 'node:fs';
import path from 'node:path';
import { holdExclusive } from './sqlite.mjs';
import { assertDatabaseFiles, tightenMode } from '../saved-data.mjs';
import { LEGACY_LOCK_FILE } from '../legacy-names.mjs';

export const lockFile = 'goblin.lock';

/** Another process holds the lock. `exitCode` 75: start again shortly. */
export class LockHeldError extends Error {
  constructor(file) {
    super(
      `Another Uptime Goblin process (or a goblin-admin command) is using this data directory (${file} is locked). If Uptime Goblin is stopping, it starts again in a few seconds; otherwise stop the other process first.`
    );
    this.name = 'LockHeldError';
    this.code = 'GOBLIN_LOCKED';
    this.file = file;
    this.exitCode = 75;
  }
}

// Locks this process holds, by real path, so a second acquire in the same process is refused
// before it could touch the file (SQLite would refuse it too, but only after opening it).
const held = new Map();

/**
 * Takes <directory>/goblin.lock, and with it <directory>/orbit.lock, the name the lock had before
 * the rename to Uptime Goblin (lib/legacy-names.mjs): an Uptime Goblin release, which knows only that
 * name, must never run on this data directory beside this process (a rollback started while the
 * new release still runs, say). Returns {file, purpose, acquiredAt, release()}; release() is
 * idempotent and frees both, and both also end with the process. Throws LockHeldError when
 * another process (or another caller in this one) holds either; then neither is kept. The
 * directory is created (0700) if needed.
 */
export function acquireLock(directory, { purpose = 'server', clock = Date.now } = {}) {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const real = fs.realpathSync(directory);
  const file = path.join(real, lockFile);
  const legacy = path.join(real, LEGACY_LOCK_FILE);
  if (held.has(file)) throw new LockHeldError(file);
  if (held.has(legacy)) throw new LockHeldError(legacy);
  const handle = holdFile(file);
  let legacyHandle;
  try {
    legacyHandle = holdFile(legacy);
  } catch (error) {
    handle.release();
    throw error;
  }
  const lock = {
    file,
    legacyFile: legacy,
    purpose,
    acquiredAt: clock(),
    get held() {
      return handle.held;
    },
    release() {
      if (!handle.held) return;
      held.delete(file);
      held.delete(legacy);
      legacyHandle.release();
      handle.release();
    },
  };
  held.set(file, lock);
  held.set(legacy, lock);
  return lock;
}

// Holds the lock file `file` (a real path) for acquireLock().
function holdFile(file) {
  // Checked by its path before anything opens it (this process holds no lock on it yet). A FIFO
  // or a directory there, a symbolic link to nothing, or one in place of the journal SQLite
  // looks for beside it, fails every attempt the same way: a refusal (exit 78) that says to
  // remove it, instead of an error the service manager retries for ever (or a wait for good).
  try {
    assertDatabaseFiles(file);
  } catch (error) {
    if (error?.name !== 'UnusableFileError') throw error;
    const own = error.file === file;
    throw Object.assign(
      new Error(
        `${own ? 'The data-directory lock ' : ''}${error.file} ${error.problem}. Remove it with Uptime Goblin stopped${own ? ' (Uptime Goblin creates it again)' : ''}, then start Uptime Goblin again.`
      ),
      { code: error.code, refusal: true, cause: error }
    );
  }
  let handle;
  try {
    handle = holdExclusive(file);
  } catch (error) {
    if (error?.busy) throw new LockHeldError(file);
    throw Object.assign(
      new Error(
        `Cannot use the data-directory lock ${file}: ${error.code || ''} ${error.message}`.trim()
      ),
      { cause: error }
    );
  }
  // chmod works on the path and opens no descriptor, so it cannot drop the lock; a symbolic
  // link's target is left as it is.
  try {
    tightenMode(file, 0o600);
  } catch {}
  return handle;
}

/**
 * Whether <directory>/goblin.lock, or orbit.lock (its name before the rename, which an Uptime Goblin
 * release takes), is held right now, by this or another process. It probes by taking each lock
 * and releasing it at once, so call it only when not holding the lock and when a brief hold
 * cannot matter (status reports). A lock file that is not there is not held.
 */
export function isLocked(directory) {
  let real;
  try {
    real = fs.realpathSync(directory);
  } catch {
    return false;
  }
  return [lockFile, LEGACY_LOCK_FILE].some(name => {
    const file = path.join(real, name);
    if (held.has(file)) return true;
    if (!fs.existsSync(file)) return false;
    try {
      holdExclusive(file).release();
      return false;
    } catch (error) {
      if (error?.busy) return true;
      throw error;
    }
  });
}
