// What Uptime Goblin reads back from its data directory is input like any other: a hand edit, a restored
// backup, another program running as the same user, or a damaged disk decides what is there. So
// the small files a start or goblin-admin reads (the restore journal, snapshot manifests,
// run/status.json) are read through one descriptor that is checked before it is read, and saved
// text is cleaned before it reaches a log line or a terminal.
import fs from 'node:fs';
import path from 'node:path';

// What is wrong with an entry, as the end of a sentence that names it.
const problems = Object.freeze({
  'not-file': () => 'is not a regular file',
  symlink: () => 'is a symbolic link',
  dangling: () => 'is a symbolic link to nothing that exists',
  'too-large': limit =>
    `is larger than ${limit >= 2 ** 20 ? `${limit / 2 ** 20} MiB` : `${limit} bytes`}`,
  changed: () => 'changed while it was read',
});

/**
 * A data-directory entry that cannot be what Uptime Goblin expects there: not a regular file (a FIFO, a
 * socket, a device or a directory), a symbolic link where none is followed, larger than its
 * limit, or growing while it is read. A retry finds the same entry, so the error is a refusal
 * (exit 78) when it reaches a start; callers that can carry on without the file catch it.
 * `reason` is one of the keys above and `problem` its text; the message names the file by the
 * path given.
 */
export class UnusableFileError extends Error {
  constructor(file, reason, limit) {
    const problem = (problems[reason] ?? problems['not-file'])(limit);
    super(`${file} ${problem}`);
    this.name = 'UnusableFileError';
    this.code = 'file_unusable';
    this.file = file;
    this.reason = reason;
    this.problem = problem;
    this.refusal = true;
  }
}

// What open() reports for a path that names something other than a file: a directory (EISDIR
// on some systems), a socket (ENXIO on Linux, EOPNOTSUPP on macOS).
const notAFile = new Set(['EISDIR', 'ENXIO', 'EOPNOTSUPP']);

/**
 * The bytes of `file`, at most `limit` of them, or undefined when there is none (ENOENT, or
 * ENOTDIR: a parent is not a directory, so no file can be there). The file is opened without
 * waiting (O_NONBLOCK: a FIFO in its place would otherwise hold the caller, and goblin.lock with
 * it, until something writes to it) and, with `follow: false`, never through a symbolic link
 * (O_NOFOLLOW). The descriptor is what is checked and read: a regular file of at most `limit`
 * bytes, read no further than its checked size and one byte more, so a file that grows meanwhile
 * is refused instead of read without bound. Throws UnusableFileError for anything else there, and
 * any other system error (EACCES, EIO) unchanged: those say nothing about the file itself.
 */
export function readRegularFile(file, { limit, follow = true }) {
  const flags =
    fs.constants.O_RDONLY | fs.constants.O_NONBLOCK | (follow ? 0 : fs.constants.O_NOFOLLOW);
  let descriptor;
  try {
    descriptor = fs.openSync(file, flags);
  } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'ENOTDIR') return undefined;
    if (error.code === 'ELOOP') throw new UnusableFileError(file, follow ? 'not-file' : 'symlink');
    if (notAFile.has(error.code)) throw new UnusableFileError(file, 'not-file');
    throw error;
  }
  try {
    const stat = fs.fstatSync(descriptor);
    if (!stat.isFile()) throw new UnusableFileError(file, 'not-file');
    if (stat.size > limit) throw new UnusableFileError(file, 'too-large', limit);
    const buffer = Buffer.allocUnsafe(stat.size + 1);
    let length = 0;
    // A short read is not the end of the file: read until it ends or the buffer is full.
    while (length < buffer.length) {
      const read = fs.readSync(descriptor, buffer, length, buffer.length - length, length);
      if (!read) break;
      length += read;
    }
    if (length > stat.size) throw new UnusableFileError(file, 'changed');
    return buffer.subarray(0, length);
  } finally {
    fs.closeSync(descriptor);
  }
}

/**
 * The bytes of <dataDir>/run/status.json (readRegularFile, never through a symbolic link, at most
 * `limit`), or undefined when there is none. The uptime-goblin account owns run/ and its readers may run
 * as root (goblin-admin status, the healthcheck in the installer), so run/ itself is not followed
 * either: a link there named any directory, and status.json in it was any file root can read.
 * On Linux, where the installer runs it as root, the file is opened through the directory's own
 * descriptor (/proc/self/fd/<n>), so run/ cannot be swapped for a link between the two opens;
 * elsewhere (no /proc) through run/'s path. Throws UnusableFileError for a linked run/.
 */
export function readRunStatusFile(dataDir, limit) {
  const run = path.join(dataDir, 'run');
  let directory;
  try {
    directory = fs.openSync(
      run,
      fs.constants.O_RDONLY | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW
    );
  } catch (error) {
    if (error.code === 'ENOENT') return undefined;
    // A link (ELOOP) or anything but a directory (ENOTDIR).
    if (error.code === 'ELOOP' || error.code === 'ENOTDIR')
      throw new UnusableFileError(run, 'symlink');
    throw error;
  }
  try {
    const own = `/proc/self/fd/${directory}`;
    const base = fs.existsSync(own) ? own : run;
    return readRegularFile(path.join(base, 'status.json'), { limit, follow: false });
  } finally {
    fs.closeSync(directory);
  }
}

/**
 * Throws UnusableFileError when `file` exists but is not a regular file (a FIFO, a socket, a
 * device or a directory; a symbolic link to a regular file is one), for files another library
 * opens by their path: SQLite's databases and goblin.lock. A path check, never a descriptor: a
 * process loses its POSIX locks on a file when it closes any descriptor of that file, SQLite's
 * included, so opening a database file beside SQLite could drop the locks of a connection this
 * process holds. A missing file passes (the caller creates it, or reports it missing); a
 * symbolic link to nothing (an unmounted volume, say) or a loop of links does not: SQLite would
 * create a new file through the link, or fail every start the same way.
 */
export function assertRegularFile(file) {
  let stat;
  try {
    // The entry itself first; only a symbolic link is followed to what it names.
    stat = fs.lstatSync(file);
  } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'ENOTDIR') return;
    // A loop of links in a directory above it.
    if (error.code === 'ELOOP') throw new UnusableFileError(file, 'not-file');
    throw error;
  }
  if (stat.isSymbolicLink())
    try {
      stat = fs.statSync(file);
    } catch (error) {
      if (error.code === 'ENOENT' || error.code === 'ENOTDIR')
        throw new UnusableFileError(file, 'dangling');
      if (error.code === 'ELOOP') throw new UnusableFileError(file, 'not-file');
      throw error;
    }
  if (!stat.isFile()) throw new UnusableFileError(file, 'not-file');
}

// The files SQLite opens beside a database by their names: the rollback journal, which every
// open that may have to undo a crashed write checks (a read-only one included), and the WAL
// and its index.
export const sqliteSidecars = Object.freeze(['-journal', '-wal', '-shm']);

/**
 * assertRegularFile for the SQLite database `file` and each of its sidecars: a FIFO in place of
 * control.sqlite-journal holds an open, read-only ones included, as one in place of the
 * database does, and a FIFO -wal fails every write as a disk error. Missing sidecars pass.
 */
export function assertDatabaseFiles(file) {
  assertRegularFile(file);
  for (const suffix of sqliteSidecars) assertRegularFile(file + suffix);
}

/**
 * Sets `file`'s mode unless it is a symbolic link, whose target Uptime Goblin did not choose and must
 * not change. Returns whether it changed the mode. A path call, for the same reason as
 * assertRegularFile; what a link points at is left as it is.
 */
export function tightenMode(file, mode) {
  if (fs.lstatSync(file).isSymbolicLink()) return false;
  fs.chmodSync(file, mode);
  return true;
}

// Control characters (C0, DEL, C1), the line and paragraph separators, and the bidi embeddings,
// overrides and isolates: what lets a saved value forge a log line, clear a terminal or make one
// name read as another.
const unprintable = /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g;

/**
 * A saved value fit for one line of a log or a terminal: without the characters above, and cut
 * to `max` characters (200 by default) so that a value of any size stays one short line.
 */
export function printable(value, max = 200) {
  return String(value)
    .slice(0, max * 4)
    .replace(unprintable, '')
    .slice(0, max);
}
