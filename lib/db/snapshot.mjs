// Physical, local snapshots of the data directory (roadmap §2.2 start step 7, §3.1, §3.7).
//
// A snapshot is <data>/snapshots/<id>/ holding copies of config.json, auth.json,
// control.sqlite and (unless left out) history.sqlite, plus manifest.json with each file's size
// and SHA-256. SQLite files are copied with SQLite's online backup, so a copy is consistent
// even while Uptime Goblin writes. Snapshots are unencrypted and carry secrets, at the same trust as the
// data directory itself (0700 directories, 0600 files); they are never served over HTTP.
// Keys never enter a snapshot: secret.key and goblin.lock are not copied.
//
// A snapshot is assembled in snapshots/.staging-<id>/ and renamed into place once its manifest
// is written, so a crash never leaves a half snapshot that looks complete. Each database copy
// passes SQLite's integrity_check there first, the check a restore makes (verifySnapshot): a
// damaged live database refuses the snapshot (exit status 78) instead of leaving a way back that
// cannot be restored. Its files, manifest
// and name are flushed (fsync) before createSnapshot returns, so a power loss after the caller
// went on (a migration that commits) leaves the whole snapshot, not a staging folder or an
// empty file.
//
// Retention: pruneSnapshots() keeps the newest 3 pre-upgrade snapshots plus the pinned pre-1.5
// one, pre-restore and pre-import snapshots for 7 days, and manual snapshots until deleted, but
// nothing calls it in 1.5: every snapshot stays until it is deleted with goblin-admin snapshots
// --delete (deleteSnapshot, offline; docs/installation.md#snapshots, test/docs-keys.test.mjs).
//
// restoreSnapshot() is offline: the caller holds goblin.lock (Uptime Goblin stopped). The files it
// replaces are moved aside into a pre-restore snapshot, never deleted, and a crash part-way
// loses no file (see restoreSnapshot), nor what Orbit 1.4.x, which ignores the restore's journal,
// writes before the restore is run again. Its journal goes only once the restored files and the
// pre-restore snapshot are on disk (fsync), so a power loss does not either. The temporary copies
// a crashed restore leaves in the data directory are listed by restoreTemporaries() and removed by
// the next start of Uptime Goblin 1.5 or later or the next restore, except those its journal still names
// (removeRestoreLeftovers); Orbit 1.4.x leaves them. The same two remove the empty .restoring-*
// folders that no journal names (removeEmptyRestoreFolders).
import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import {
  backupDatabase,
  databaseProblem,
  integrityCheck,
  settleDatabase,
  openSqlite,
  plantedObjects,
} from './sqlite.mjs';
import { compareReleases, coreRelease, RefusalError } from './migrate.mjs';
import { sql, id } from './sql.mjs';
import defaultRegistry from './registry.mjs';
import {
  assertDatabaseFiles,
  assertRegularFile,
  printable,
  readRegularFile,
  UnusableFileError,
} from '../saved-data.mjs';

export const snapshotsDirectory = 'snapshots';
/** The files a snapshot manages, in the data directory. */
export const managedFiles = Object.freeze([
  Object.freeze({ name: 'config.json', kind: 'file' }),
  Object.freeze({ name: 'auth.json', kind: 'file' }),
  Object.freeze({ name: 'control.sqlite', kind: 'sqlite' }),
  Object.freeze({ name: 'history.sqlite', kind: 'sqlite' }),
]);
const sidecars = ['-wal', '-shm', '-journal'];
const idPattern = /^[a-z][a-z0-9-]{0,31}-[0-9A-Za-z.+-]{1,40}-\d{8}T\d{6}(?:\d{3})?Z(?:-\d+)?$/;
const reasonPattern = /^[a-z][a-z0-9-]{0,31}$/;
/** Whether `reason` can name a snapshot (createSnapshot's rule, for goblin-admin snapshot). */
export const isSnapshotReason = reason => typeof reason === 'string' && reasonPattern.test(reason);
// Free space a snapshot leaves on the filesystem, besides what it copies.
const spareBytes = 16 * 2 ** 20;
const hourMs = 3600000;
const dayMs = 24 * hourMs;

export class SnapshotError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'SnapshotError';
    this.code = code;
    Object.assign(this, details);
  }
}

const stamp = ms =>
  new Date(ms)
    .toISOString()
    .replace(/[-:]/g, '')
    .replace(/\.(\d{3})Z$/, '$1Z');
const safeRelease = value =>
  String(value ?? 'unknown')
    .replace(/[^0-9A-Za-z.+-]/g, '-')
    .slice(0, 40);
const rootOf = directory => path.join(directory, snapshotsDirectory);
const exists = file => fs.existsSync(file);
// Whether there is any entry by that name: a symbolic link to nothing (a volume that is not
// mounted) or a loop of links included, which exists() reads as no file at all.
const present = file => {
  try {
    fs.lstatSync(file);
    return true;
  } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'ENOTDIR') return false;
    throw error;
  }
};
const sizeOf = file => {
  try {
    return fs.statSync(file).size;
  } catch {
    return 0;
  }
};

/**
 * Throws RefusalError 'snapshots_not_directory' (exit status 78) unless <directory>/snapshots is
 * missing (the first snapshot creates it) or a directory, a symbolic link to one included: a file
 * or a FIFO there, a symbolic link to nothing (a volume that is not mounted) or a loop of links
 * would fail every later step the same way. A start refuses on it first (startControl), and so do
 * listSnapshots, interruptedRestore, createSnapshot and restoreSnapshot, for goblin-admin: read
 * as absent, a link to nothing listed no snapshots while the pinned way back to 1.4.x may be on
 * that volume, a loop read as a restore interrupted with a record that cannot be read, and a file
 * failed with the raw system error.
 */
export function assertSnapshotsDirectory(directory) {
  const root = rootOf(directory);
  let entry = null;
  try {
    entry = fs.statSync(root);
  } catch (error) {
    if (error.code !== 'ENOENT' && error.code !== 'ELOOP') throw error;
    // Missing is fine; a link that leads nowhere is not.
    if (present(root))
      throw new RefusalError(
        'snapshots_not_directory',
        `${root} is a symbolic link to no directory (it names a missing one, or a loop of links). Uptime Goblin keeps its snapshots there: point it at a directory, or remove it with Uptime Goblin stopped, then start Uptime Goblin (or run the command) again.`
      );
  }
  if (entry && !entry.isDirectory())
    throw new RefusalError(
      'snapshots_not_directory',
      `${root} is not a directory. Uptime Goblin keeps its snapshots there: move it out of the data directory with Uptime Goblin stopped, then start Uptime Goblin (or run the command) again.`
    );
}

async function sha256(file) {
  const hash = createHash('sha256');
  for await (const chunk of fs.createReadStream(file)) hash.update(chunk);
  return hash.digest('hex');
}

// Written durably (the data flushed before the rename, and the rename flushed): a power loss
// right after must find either no file or the whole of it. The temporary file has a name of its
// own, created exclusively (O_EXCL never follows a symbolic link), as every other writer of the
// data directory does: a fixed name could be a link planted beforehand, and the journal would be
// written through it to wherever it points. One this call created is removed when it fails.
function writeJsonDurably(file, value) {
  const temporary = `${file}.${randomUUID()}.tmp`;
  let handle,
    created = false;
  try {
    handle = fs.openSync(temporary, 'wx', 0o600);
    created = true;
    fs.writeSync(handle, JSON.stringify(value, null, 2) + '\n');
    fs.fsyncSync(handle);
    // close() can fail after releasing the number to another open file: never closed twice.
    const closing = handle;
    handle = undefined;
    fs.closeSync(closing);
    fs.renameSync(temporary, file);
  } catch (error) {
    if (handle !== undefined)
      try {
        fs.closeSync(handle);
      } catch {}
    if (created)
      try {
        fs.unlinkSync(temporary);
      } catch {}
    throw error;
  }
  syncDirectory(path.dirname(file));
}
function syncDirectory(folder) {
  let handle;
  try {
    handle = fs.openSync(folder, 'r');
    fs.fsyncSync(handle);
  } catch {
    // Not every platform can open a directory for fsync; the rename itself is still atomic.
  } finally {
    if (handle !== undefined) fs.closeSync(handle);
  }
}

/**
 * The journal of a restore in progress: snapshots/.restore-in-progress.json, written before
 * the first live file is moved and removed once the restore completed. Its presence means the
 * data directory may hold part of a snapshot and part of what it replaced (a crash or power
 * loss during restoreSnapshot step 2), so Uptime Goblin 1.5 and later must not start on it (startControl
 * refuses). Orbit 1.4.x knows nothing of it: after a code rollback it starts on such a directory
 * and writes to it, which restoreSnapshot allows for when the restore is run again.
 */
export const restoreJournal = '.restore-in-progress.json';

const sha256Pattern = /^[0-9a-f]{64}$/;
// What a restore journal or a snapshot manifest may weigh. Uptime Goblin writes a few kilobytes into
// each; anything near this is not one of them, and is not read into memory to find out.
const recordLimit = 2 ** 20;
// How many earlier interrupted restores a journal may carry (`unfinished`, one per restore that
// a crash stopped before the next one began). Real chains are one or two long; a deeper one is
// unreadable rather than walked to the end of the stack.
const journalDepthLimit = 16;

// The journal as restoreSnapshot reads it: interruptedRestore()'s fields, plus `copies` (per
// file, the size and SHA-256 of each copy of the snapshot that an attempt of this restore renamed
// into place, {name: [{bytes, sha256}, …]}: they differ for control.sqlite, stamped anew each
// time), `kept` (the ids of the folders that hold live files which had changed after an earlier
// attempt; see restoreSnapshot) and `absent` (the managed files the data directory did not hold
// when the first attempt began: what is in the place of one now was put there by an attempt or
// written since, never what the restore replaced), and `unfinished` when present: the journal of
// an earlier interrupted restore that this one does not finish, with only the files this one
// leaves as they are (see restoreSnapshot; it may carry an `unfinished` of its own). null without
// a journal; one that cannot be parsed reads as naming nothing, and so does anything but a regular
// file of at most recordLimit bytes in its place (a FIFO there must not hold every start), or a
// journal that carries more than journalDepthLimit earlier restores. Other system errors (EACCES,
// EIO) are thrown: the journal may be there.
function readJournal(directory) {
  const file = path.join(rootOf(directory), restoreJournal);
  let bytes;
  try {
    bytes = readRegularFile(file, { limit: recordLimit });
  } catch (error) {
    if (!(error instanceof UnusableFileError)) throw error;
    return parseJournal(null);
  }
  if (bytes === undefined) return null;
  let value = null;
  try {
    value = JSON.parse(bytes.toString('utf8'));
  } catch {}
  let depth = 0;
  for (let item = value; item && typeof item === 'object'; item = item.unfinished)
    if (++depth > journalDepthLimit) return parseJournal(null);
  return parseJournal(value);
}
function parseJournal(value) {
  if (!value || typeof value !== 'object')
    return {
      snapshot: null,
      aside: null,
      files: [],
      keepHistory: false,
      copies: {},
      kept: [],
      absent: [],
    };
  const copies = {};
  for (const { name } of managedFiles) {
    const valid = [value.copies?.[name] ?? []]
      .flat()
      .filter(copy => Number.isSafeInteger(copy?.bytes) && sha256Pattern.test(copy?.sha256 ?? ''))
      .map(({ bytes, sha256 }) => ({ bytes, sha256 }));
    if (valid.length) copies[name] = valid;
  }
  return {
    snapshot:
      typeof value.snapshot === 'string' && idPattern.test(value.snapshot) ? value.snapshot : null,
    aside: typeof value.aside === 'string' ? value.aside : null,
    // Only the managed files a restore replaces, as `absent`: any other name was never written
    // by a restore, and one carried on (unfinished) reached restore-snapshot's output as it was.
    files: Array.isArray(value.files)
      ? value.files.filter(name => managedFiles.some(file => file.name === name))
      : [],
    keepHistory: value.keepHistory === true,
    copies,
    kept: Array.isArray(value.kept)
      ? value.kept.filter(item => typeof item === 'string' && idPattern.test(item))
      : [],
    absent: Array.isArray(value.absent)
      ? value.absent.filter(name => managedFiles.some(file => file.name === name))
      : [],
    ...(value.unfinished && typeof value.unfinished === 'object'
      ? { unfinished: parseJournal(value.unfinished) }
      : {}),
  };
}

// A journal and those of the earlier interrupted restores it carries (`unfinished`), outermost
// first; [] for none.
function journalChain(journal) {
  const chain = [];
  for (let item = journal; item; item = item.unfinished) chain.push(item);
  return chain;
}

// The folder ids a journal and the journals it carries name: their aside folders and those of
// files kept apart.
const chainFolders = journal =>
  journalChain(journal)
    .flatMap(item => [item.aside, ...item.kept])
    .filter(item => typeof item === 'string');

// What of `journal` (and the earlier restores it carries) a restore that replaced the files
// `names` leaves unfinished: each one's files less those, without the ones that have none left
// (this restore finished them). null when nothing is left.
function unfinishedAfter(journal, names) {
  if (!journal) return null;
  const inner = unfinishedAfter(journal.unfinished, names);
  const files = journal.files.filter(name => !names.includes(name));
  if (!files.length) return inner;
  const left = { ...journal, files };
  delete left.unfinished;
  return inner ? { ...left, unfinished: inner } : left;
}

// The .restoring-* folders the journal names (its aside folder and those of files kept apart,
// and those of the earlier restores it carries): an empty set without a journal, null when one
// exists that cannot be read.
function journalFolders(directory) {
  let journal;
  try {
    journal = readJournal(directory);
  } catch {
    return null;
  }
  if (!journal) return new Set();
  if (journal.snapshot === null) return null;
  return new Set(chainFolders(journal).map(item => `.restoring-${item}`));
}

const isEmptyFolder = folder => {
  try {
    return fs.readdirSync(folder).length === 0;
  } catch {
    return false;
  }
};

/**
 * Removes the empty snapshots/.restoring-* folders that no restore journal names, and returns
 * their names. restoreSnapshot makes its folders only once its journal names them, so such a
 * folder belongs to a restore that a crash stopped before it set a file aside and whose journal a
 * later restore has since finished (or to a release that made the folder first): it holds nothing,
 * and no restore continues in a folder the journal does not name, so it was otherwise listed as an
 * interrupted restore's for ever. One the journal names stays (running that restore again
 * continues in it), and so does every folder while a journal exists that cannot be read. Call it
 * only under goblin.lock, so that no restore is filling one: startControl at every start, and
 * restoreSnapshot beside removeRestoreLeftovers.
 */
export function removeEmptyRestoreFolders(directory) {
  const root = rootOf(directory);
  let entries;
  try {
    entries = fs.readdirSync(root, { withFileTypes: true });
  } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'ENOTDIR') return [];
    throw error;
  }
  const folders = entries.filter(
    entry => entry.isDirectory() && entry.name.startsWith('.restoring-')
  );
  if (!folders.length) return [];
  const named = journalFolders(directory);
  if (named === null) return [];
  const removed = [];
  for (const { name } of folders) {
    if (named.has(name)) continue;
    try {
      // rmdir removes only an empty folder: one with anything in it stays, listed as an
      // interrupted restore's, since it may hold the only copy of files a restore moved aside.
      fs.rmdirSync(path.join(root, name));
      removed.push(name);
    } catch {}
  }
  if (removed.length) syncDirectory(root);
  return removed;
}

/**
 * The interrupted restore of this data directory, or null: `{snapshot, aside, files,
 * keepHistory}` from the journal (snapshot null when the journal cannot be read). An earlier one
 * that it carries (`unfinished`, see restoreSnapshot) is not named: it becomes the journal once
 * this one is run again and completes. A snapshots/ that is not a directory refuses
 * (assertSnapshotsDirectory): a loop of links read as a journal that cannot be read.
 */
export function interruptedRestore(directory) {
  assertSnapshotsDirectory(directory);
  const journal = readJournal(directory);
  if (!journal) return null;
  const { snapshot, aside, files, keepHistory } = journal;
  return { snapshot, aside, files, keepHistory };
}

// The temporary name restoreSnapshot step 1 copies a snapshot's file to, beside the live one.
const temporaryName = name => `.${name}.restoring`;
const temporaryPattern =
  /^\.(config\.json|auth\.json|control\.sqlite|history\.sqlite)\.restoring(-wal|-shm|-journal)?$/;

/**
 * The temporary copies of a snapshot's files that a restore left in the data directory, one entry
 * per managed file: {file, id (its temporary name), names (that name and any -wal, -shm or
 * -journal beside it), bytes, modifiedAt, needed, snapshot, keepHistory}. restoreSnapshot creates
 * them in step 1 and renames each into place in step 2, so outside a running restore they are
 * left by one that a crash or a power loss stopped: hidden, as large as the files they copy
 * (history.sqlite included), and taking the free space history needs.
 *
 * `needed` is true while the journal of an interrupted restore names the file (`snapshot` and
 * `keepHistory` are that restore's), or that of an earlier one it carries (`unfinished`: then
 * they are that one's), or the journal exists but cannot be read: the copy is that restore's, and
 * only running it again (or another restore that copies the same file, and so takes it over)
 * replaces it. Without a journal, or for a file no journal names, the copy is left by a restore
 * that stopped before it changed anything, or by an attempt a later restore finished: nothing
 * uses it (unless a restore is running right now: this reads without the lock).
 */
export function restoreTemporaries(directory) {
  let entries;
  try {
    entries = fs.readdirSync(directory);
  } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'ENOTDIR') return [];
    throw error;
  }
  const byFile = new Map();
  for (const name of entries) {
    const match = temporaryPattern.exec(name);
    if (!match) continue;
    let stats;
    try {
      stats = fs.lstatSync(path.join(directory, name));
    } catch {
      continue;
    }
    // Only plain files: restoreSnapshot never makes anything else under these names.
    if (!stats.isFile()) continue;
    const entry = byFile.get(match[1]) ?? { names: [], bytes: 0, modifiedAt: 0 };
    entry.names.push(name);
    entry.bytes += stats.size;
    entry.modifiedAt = Math.max(entry.modifiedAt, stats.mtimeMs);
    byFile.set(match[1], entry);
  }
  if (!byFile.size) return [];
  let journal;
  try {
    journal = readJournal(directory);
  } catch {
    // A journal that exists but cannot be read keeps every copy, as an unparsable one does.
    journal = { snapshot: null, files: [], keepHistory: false };
  }
  const chain = journalChain(journal);
  // In managed order, each copy's own name before its sidecars.
  return managedFiles
    .filter(managed => byFile.has(managed.name))
    .map(({ name: file }) => {
      const { names, bytes, modifiedAt } = byFile.get(file);
      const owner = chain.find(item => item.files.includes(file));
      return {
        file,
        id: temporaryName(file),
        names: names.sort(),
        bytes,
        modifiedAt,
        needed: journal !== null && (journal.snapshot === null || owner !== undefined),
        snapshot: (owner ?? journal)?.snapshot ?? null,
        keepHistory: (owner ?? journal)?.keepHistory === true,
      };
    });
}

/**
 * Removes the copies restoreTemporaries() finds that no interrupted restore needs, and returns
 * them. Call it only under goblin.lock, so that no restore is running: startControl at every start
 * (where any journal has already refused the start), and restoreSnapshot before its own copies
 * (they would share the free space it needs) and once it completed.
 */
export function removeRestoreLeftovers(directory) {
  const removed = [];
  for (const item of restoreTemporaries(directory)) {
    if (item.needed) continue;
    for (const name of item.names) fs.rmSync(path.join(directory, name), { force: true });
    removed.push(item);
  }
  return removed;
}

// A snapshot's manifest.json, checked as far as its readers rely on it: every file entry with a
// name, a whole size and a SHA-256, and the fields listSnapshots reports of the right types. A
// manifest that is not one throws SnapshotError 'snapshot_invalid', whose message never quotes
// the file (a parse error would), since `snapshots` prints it. Anything but a regular file of at
// most recordLimit bytes in its place is one too, so a FIFO there never holds a start.
function readManifest(folder) {
  const invalid = problem => new SnapshotError('snapshot_invalid', `manifest.json ${problem}`);
  let bytes;
  try {
    bytes = readRegularFile(path.join(folder, 'manifest.json'), { limit: recordLimit });
  } catch (error) {
    if (!(error instanceof UnusableFileError)) throw error;
    throw invalid(error.problem);
  }
  if (bytes === undefined) throw invalid('is missing');
  let manifest;
  try {
    manifest = JSON.parse(bytes.toString('utf8'));
  } catch {
    throw invalid('is not valid JSON');
  }
  const optionalText = value => value === undefined || value === null || typeof value === 'string';
  if (
    manifest?.format !== 1 ||
    !Array.isArray(manifest.files) ||
    !manifest.files.every(
      file =>
        typeof file?.name === 'string' &&
        Number.isSafeInteger(file.bytes) &&
        file.bytes >= 0 &&
        sha256Pattern.test(file.sha256 ?? '')
    ) ||
    typeof manifest.id !== 'string' ||
    typeof manifest.reason !== 'string' ||
    !optionalText(manifest.release) ||
    !optionalText(manifest.fromRelease) ||
    !Number.isSafeInteger(manifest.createdAt)
  )
    throw invalid('is not a valid snapshot manifest');
  return manifest;
}

/** Whether `id` has the form of a snapshot id (the folder names createSnapshot gives). */
export const isSnapshotId = id => typeof id === 'string' && idPattern.test(id);

function assertId(id) {
  if (!isSnapshotId(id))
    throw new SnapshotError('snapshot_unknown', `${JSON.stringify(id)} is not a snapshot id`);
}

/**
 * Whether `release` is older than 1.5.0 (or unknown: data from before control.sqlite). The core
 * release is compared, so data written by a 1.5 pre-release (1.5.0-dev.0) is never taken for
 * 1.4.x data and pinned again.
 */
export const isPre15 = release =>
  release == null || compareReleases(coreRelease(release), '1.5.0') < 0;

// Marks a restored control.sqlite (still under its temporary name) so the next start signs every
// session out (D25): the snapshot copies the database whole, and the restored auth.json matches
// the restored fingerprint, so without the marker every session revoked since the snapshot was
// taken (a lost device, "Sign out other devices", a password change) would work again. Only a
// copy with a meta table is stamped (a 1.5 database); the database is then settled back to one
// file, so no -wal or -shm is left beside it. control.mjs is not imported (it imports this
// file), so this is the upsert metaOps.set runs.
async function stampRestored(file, value, now) {
  const db = openSqlite(file, { registry: defaultRegistry });
  try {
    await db.write(tx => {
      const meta = tx.get(
        sql`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ${'meta'}`
      );
      if (!meta) return;
      tx.run(
        tx.dialect.upsert(
          'meta',
          ['key'],
          ['key', 'value', 'updated_at'],
          [['restored', value, now]]
        )
      );
    });
  } finally {
    db.close();
  }
  settleDatabase(file);
}

/**
 * Takes a snapshot. Options:
 *   reason       pre-upgrade | manual | pre-restore | pre-import | … (lower-case token)
 *   release      the release taking it (named in the id)
 *   fromRelease  for pre-upgrade: the release that wrote the data (null: before 1.5)
 *   pin          keep it until deleted by hand. Default: the first pre-upgrade snapshot of data
 *                from before 1.5 is pinned (the way back to 1.4.x, §3.8).
 *   history      false leaves history.sqlite out (it is kept as it is on restore)
 * Refuses with SnapshotError 'snapshot_space' when the copies would not fit.
 */
export async function createSnapshot(
  directory,
  { reason = 'manual', release, fromRelease = null, pin, history = true, clock = Date.now } = {}
) {
  if (!reasonPattern.test(reason))
    throw new SnapshotError('snapshot_reason', `Invalid snapshot reason ${JSON.stringify(reason)}`);
  // Before anything is written: mkdir through a link to nothing failed with a raw ENOENT.
  assertSnapshotsDirectory(directory);
  // Any entry counts as there, a symbolic link to nothing included: read as absent, it was
  // recorded so, and restoring the snapshot later, once the volume was mounted again, moved the
  // live file out of the data directory (the next start began an empty history). Each file to
  // copy must be a regular file, or a link to one, before anything is written: a link to
  // nothing, a loop of links, a FIFO or a directory refuses the snapshot (exit status 78), as it
  // refuses the start. history.sqlite left out (`history: false`) is not read, only kept.
  const there = new Set(
    managedFiles.filter(file => present(path.join(directory, file.name))).map(file => file.name)
  );
  const included = managedFiles.filter(
    file => there.has(file.name) && (history || file.name !== 'history.sqlite')
  );
  for (const file of included) {
    const live = path.join(directory, file.name);
    try {
      if (file.kind === 'sqlite') assertDatabaseFiles(live);
      else assertRegularFile(live);
    } catch (error) {
      if (!(error instanceof UnusableFileError)) throw error;
      throw new SnapshotError(
        'live_file_unusable',
        `No snapshot was taken: ${error.message}. Nothing was written to snapshots/. Put the file back in its place (mount the volume a link points to), or move what is there out of the data directory, then take the snapshot again.`,
        { refusal: true, file: error.file, reason: error.reason }
      );
    }
  }
  const root = rootOf(directory);
  // A new snapshots/ (the first start of 1.4.x data makes it) is an entry of the data directory,
  // flushed with it below: the snapshot in it is only as durable as that entry.
  const madeRoot = fs.mkdirSync(root, { recursive: true, mode: 0o700 }) !== undefined;
  fs.chmodSync(root, 0o700);
  const now = clock();
  let id = `${reason}-${safeRelease(release)}-${stamp(now)}`;
  for (let n = 2; exists(path.join(root, id)); n += 1)
    id = `${reason}-${safeRelease(release)}-${stamp(now)}-${n}`;

  const needed =
    included.reduce(
      (sum, file) =>
        sum +
        sizeOf(path.join(directory, file.name)) +
        (file.kind === 'sqlite' ? sizeOf(path.join(directory, `${file.name}-wal`)) : 0),
      0
    ) + spareBytes;
  const space = fs.statfsSync(root);
  const available = Number(space.bavail) * Number(space.bsize);
  if (available < needed)
    throw new SnapshotError(
      'snapshot_space',
      `A snapshot needs about ${Math.ceil(needed / 2 ** 20)} MiB but only ${Math.floor(available / 2 ** 20)} MiB are free in ${root}.`,
      { needed, available }
    );

  const pinned =
    pin ??
    (reason === 'pre-upgrade' &&
      isPre15(fromRelease) &&
      !listSnapshots(directory).some(item => item.pinned));
  const staging = path.join(root, `.staging-${id}`);
  fs.mkdirSync(staging, { mode: 0o700 });
  try {
    const files = [];
    for (const file of included) {
      const from = path.join(directory, file.name),
        to = path.join(staging, file.name);
      if (file.kind === 'sqlite') {
        await backupDatabase(from, to);
        // The backup copies pages as they are, damage included, and restoreSnapshot refuses a
        // copy that fails this same check (verifySnapshot): found only then, the snapshot that
        // was to be the way back is useless. Refused now, before a migration starts on the data.
        const check = databaseCheck(to);
        if (check !== 'ok')
          throw new SnapshotError(
            'live_database_damaged',
            `No snapshot was taken: ${file.name} in the data directory is damaged (${printable(check, 1000)}). Nothing was kept in snapshots/, and nothing was migrated. Restore an earlier snapshot (goblin-admin restore-snapshot) or a backup before you upgrade or migrate (docs/installation.md#snapshots).`,
            { refusal: true, file: file.name }
          );
      } else {
        // A FIFO in its place would hold the copy (and goblin.lock) until something wrote to it.
        assertRegularFile(from);
        fs.copyFileSync(from, to, fs.constants.COPYFILE_EXCL);
      }
      fs.chmodSync(to, 0o600);
      // On disk before the snapshot is renamed into place (copyFileSync never flushes; a
      // database copy is flushed by SQLite's commit already, so this costs it nothing).
      syncFile(to);
      files.push({ name: file.name, bytes: sizeOf(to), sha256: await sha256(to) });
    }
    const manifest = {
      format: 1,
      id,
      reason,
      release: release ?? null,
      fromRelease,
      createdAt: now,
      pinned: Boolean(pinned),
      files,
      // Managed files that did not exist: restoring removes them (moved aside).
      absent: managedFiles.filter(file => !there.has(file.name)).map(file => file.name),
      // Managed files deliberately left out: restoring keeps them as they are.
      excluded: history || !there.has('history.sqlite') ? [] : ['history.sqlite'],
    };
    // Durably, in this order: the copies and the manifest, the staging folder's entries
    // (writeJsonDurably flushes it), then its final name, then snapshots/ itself. The caller
    // commits what the snapshot is the way back from only once it returns: startControl's
    // migration of 1.4.x data, whose control.sqlite commit is fsynced. Had a power loss kept that
    // commit and lost the rename, the next start would have deleted .staging-<id> as a dead
    // process's leftover; had it lost the data, the pinned snapshot would be INVALID. Either way
    // no step was pending any more, so no snapshot was taken again: the way back to 1.4.x was gone.
    writeJsonDurably(path.join(staging, 'manifest.json'), manifest);
    fs.renameSync(staging, path.join(root, id));
    syncDirectory(root);
    if (madeRoot) syncDirectory(directory);
    return { id, path: path.join(root, id), manifest };
  } catch (error) {
    fs.rmSync(staging, { recursive: true, force: true });
    throw error;
  }
}

/**
 * Every snapshot, newest first: {id, reason, release, fromRelease, createdAt, pinned, bytes,
 * files, valid, problem?}. Staging leftovers are not listed. [] while snapshots/ is missing;
 * anything else that is not a directory there refuses (assertSnapshotsDirectory).
 */
export function listSnapshots(directory) {
  assertSnapshotsDirectory(directory);
  const root = rootOf(directory);
  if (!exists(root)) return [];
  const found = [];
  let named;
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    if (entry.isDirectory() && entry.name.startsWith('.restoring-')) {
      // Never pruned: it may hold the only copy of files a crashed restore moved aside. An empty
      // one holds nothing: unless the journal names it (running that restore again continues in
      // it), the next start or restore removes it (removeEmptyRestoreFolders).
      const folder = path.join(root, entry.name);
      const empty = isEmptyFolder(folder);
      if (empty && named === undefined) named = journalFolders(directory);
      found.push({
        id: entry.name,
        valid: false,
        interrupted: true,
        ...(empty ? { empty: true } : {}),
        problem: !empty
          ? 'An interrupted restore moved the files it replaced here. Run the restore again to finish it; these files are kept until you delete them.'
          : named === null || named.has(entry.name)
            ? 'An interrupted restore made this folder for the files it replaces and had moved none here yet. Run the restore again to finish it.'
            : 'Empty: a restore that a crash or a power loss stopped made this folder before it moved any file here. The next start of Uptime Goblin 1.5 or later, or the next restore-snapshot, removes it; Orbit 1.4.x leaves it (delete it by hand while Uptime Goblin is stopped).',
        createdAt: fs.statSync(folder).mtimeMs,
        pinned: false,
      });
      continue;
    }
    if (!entry.isDirectory() || entry.name.startsWith('.')) continue;
    try {
      const manifest = readManifest(path.join(root, entry.name));
      if (manifest.id !== entry.name) throw new SnapshotError('snapshot_invalid', 'id mismatch');
      found.push({
        id: manifest.id,
        reason: manifest.reason,
        release: manifest.release,
        fromRelease: manifest.fromRelease ?? null,
        createdAt: manifest.createdAt,
        pinned: manifest.pinned === true,
        bytes: manifest.files.reduce((sum, file) => sum + file.bytes, 0),
        files: manifest.files.map(file => file.name),
        valid: true,
      });
    } catch (error) {
      found.push({
        id: entry.name,
        valid: false,
        problem: error.message,
        createdAt: 0,
        pinned: false,
      });
    }
  }
  return found.sort((a, b) => b.createdAt - a.createdAt || (a.id < b.id ? 1 : -1));
}

/**
 * True when the data directory still holds what snapshot `id` copied: config.json and auth.json
 * have the size and SHA-256 its manifest records, and those it found absent are still absent:
 * no entry at all, since a symbolic link to nothing (a volume that is not mounted) read as absent
 * had the snapshot reused, and restoring it then removed the file the link names once the volume
 * was back (createSnapshot refuses such a link instead). The databases are not compared: a copy
 * taken with SQLite's backup is not byte for byte the live file, and a migration that failed
 * part way may have changed control.sqlite since (the crash loop this answers for). Every change
 * made under 1.4.x (settings, the password) is in config.json or auth.json.
 */
export async function unchangedSince(directory, id) {
  assertId(id);
  let manifest;
  try {
    manifest = readManifest(path.join(rootOf(directory), id));
  } catch {
    return false;
  }
  for (const managed of managedFiles) {
    if (managed.kind !== 'file') continue;
    const live = path.join(directory, managed.name);
    const copied = manifest.files.find(file => file.name === managed.name);
    if (copied) {
      if (
        !exists(live) ||
        // Not hashed unless it is a regular file: a FIFO would hold the hash for ever.
        !fs.statSync(live).isFile() ||
        sizeOf(live) !== copied.bytes ||
        (await sha256(live)) !== copied.sha256
      )
        return false;
    } else if (present(live)) return false;
  }
  return true;
}

// SQLite's integrity_check of a database copy (integrityCheck: also index against table, which
// quick_check skips), or the error that kept it from running: 'ok' or the problems.
function databaseCheck(copy) {
  try {
    return integrityCheck(copy);
  } catch (error) {
    // Not a database at all (a damaged file a restore moved aside as it was).
    return error?.message || String(error);
  }
}

/**
 * Re-hashes a snapshot's files and checks its databases with SQLite's integrity_check (not only
 * quick_check: an index that disagrees with its table is found too): {ok, problems}. Run before
 * every restore and by goblin-admin snapshots --verify.
 */
export async function verifySnapshot(directory, id) {
  assertId(id);
  const folder = path.join(rootOf(directory), id);
  const problems = [];
  let manifest;
  try {
    manifest = readManifest(folder);
  } catch (error) {
    return { ok: false, problems: [`manifest: ${error.message}`] };
  }
  for (const file of manifest.files) {
    const managed = managedFiles.find(item => item.name === file.name);
    const copy = path.join(folder, file.name);
    // The manifest's name is saved data, and the problems reach a terminal (restore-snapshot's
    // refusal, snapshots --verify): only a managed name is shown as it is.
    if (!managed) problems.push(`${printable(file.name, 100)} is not a file snapshots manage`);
    else if (!exists(copy)) problems.push(`${file.name} is missing`);
    // Hashing a FIFO would wait for a writer for ever.
    else if (!fs.statSync(copy).isFile()) problems.push(`${file.name} is not a regular file`);
    else if (sizeOf(copy) !== file.bytes || (await sha256(copy)) !== file.sha256)
      problems.push(`${file.name} does not match its checksum`);
    else if (managed.kind === 'sqlite') {
      const check = databaseCheck(copy);
      // SQLite's text quotes the copy's own table and column names (NULL value in
      // <table>.<column>, malformed database schema (<name>)): saved data, shown printable as
      // the names above.
      if (check !== 'ok') problems.push(`${file.name}: ${printable(check, 1000)}`);
      else {
        // Restoring it would bring a trigger into Uptime Goblin's writes, or a view or another catalog
        // row Uptime Goblin does not write (plantedObjects); the start refuses those (startControl), so
        // the restore does first.
        const reader = openSqlite(copy, { readOnly: true });
        try {
          const planted = plantedObjects(await reader.catalog());
          if (planted.length)
            problems.push(
              `${file.name} holds ${planted.join(', ')}, which Uptime Goblin never creates`
            );
        } finally {
          reader.close();
        }
      }
    }
  }
  return { ok: problems.length === 0, problems, manifest };
}

/**
 * Deletes a snapshot; a pinned one only with `force`. Never one an interrupted restore still
 * needs (`force` or not): the snapshot its journal restores, its pre-restore snapshot and the
 * snapshots of files it kept apart, of it and of the earlier restores it carries; while a journal
 * exists that cannot be read, none at all. A .restoring-* folder is no snapshot id (assertId).
 * Called offline, with goblin.lock held (goblin-admin snapshots --delete).
 */
export function deleteSnapshot(directory, id, { force = false } = {}) {
  assertId(id);
  assertSnapshotsDirectory(directory);
  const folder = path.join(rootOf(directory), id);
  if (!exists(folder)) throw new SnapshotError('snapshot_unknown', `There is no snapshot ${id}`);
  const journal = readJournal(directory);
  if (journal) {
    if (journal.snapshot === null)
      throw new SnapshotError(
        'snapshot_needed',
        `${id} was not deleted: a restore was interrupted and its record (snapshots/${restoreJournal}) cannot be read, so it may need this snapshot. Run that restore again to finish it, then delete the snapshot.`
      );
    const chain = journalChain(journal);
    const needed = new Set(
      chain.flatMap(item => [item.snapshot, item.aside, ...item.kept]).filter(Boolean)
    );
    if (needed.has(id))
      throw new SnapshotError(
        'snapshot_needed',
        `${id} was not deleted: the interrupted restore of ${journal.snapshot} needs it. Run that restore again to finish it (goblin-admin restore-snapshot ${journal.snapshot}${journal.keepHistory ? ' --keep-history' : ''}), then delete the snapshot.`
      );
  }
  let pinned = false;
  try {
    pinned = readManifest(folder).pinned === true;
  } catch {}
  if (pinned && !force)
    throw new SnapshotError(
      'snapshot_pinned',
      `${id} is pinned: it is the way back to Orbit 1.4.x. Delete it with --force if you are sure.`
    );
  fs.rmSync(folder, { recursive: true, force: true });
}

/**
 * Applies retention: keeps the newest `keepPreUpgrade` unpinned pre-upgrade snapshots, and
 * pre-restore / pre-import snapshots for `keepDays` days; removes staging leftovers older than
 * an hour. Pinned, manual and invalid snapshots are left alone. Returns the ids removed.
 */
export function pruneSnapshots(
  directory,
  { now = Date.now(), keepPreUpgrade = 3, keepDays = 7 } = {}
) {
  const root = rootOf(directory);
  if (!exists(root)) return [];
  const removed = [];
  const snapshots = listSnapshots(directory).filter(item => item.valid && !item.pinned);
  const upgrades = snapshots.filter(item => item.reason === 'pre-upgrade');
  for (const item of upgrades.slice(keepPreUpgrade)) removed.push(item.id);
  for (const item of snapshots)
    if (
      ['pre-restore', 'pre-import'].includes(item.reason) &&
      now - item.createdAt > keepDays * dayMs
    )
      removed.push(item.id);
  for (const id of removed) fs.rmSync(path.join(root, id), { recursive: true, force: true });
  for (const entry of fs.readdirSync(root, { withFileTypes: true }))
    if (entry.isDirectory() && entry.name.startsWith('.staging-')) {
      const folder = path.join(root, entry.name);
      if (now - fs.statSync(folder).mtimeMs > hourMs) {
        fs.rmSync(folder, { recursive: true, force: true });
        removed.push(entry.name);
      }
    }
  return removed;
}

// Sets a managed file of the data directory aside into `folder`. A database is moved (a rename,
// so it needs no space): it was settled first (restoreSnapshot), so the moved file alone is the
// whole database and its -wal and -shm can go. One that could not be settled (`unsettled`:
// damaged) keeps them: they move with it, so nothing in them is lost.
// config.json and auth.json are copied instead, when a copy of the snapshot's is renamed over
// them next (`replaced`): they are small, and the copy is on disk before that rename, so the data
// directory is never without them. That matters for auth.json: Orbit 1.4.x does not check the
// restore journal, and started without auth.json it would accept the GOBLIN_PASSWORD bootstrap
// password, or on loopback no password at all.
function setAside(directory, file, folder, { unsettled = false, replaced = false } = {}) {
  const from = path.join(directory, file.name),
    to = path.join(folder, file.name);
  if (file.kind === 'file' && replaced) {
    fs.copyFileSync(from, to, fs.constants.COPYFILE_EXCL);
    fs.chmodSync(to, 0o600);
    syncFile(to);
    syncDirectory(folder);
    return;
  }
  fs.renameSync(from, to);
  for (const suffix of sidecars) {
    if (unsettled && exists(from + suffix)) {
      fs.renameSync(from + suffix, to + suffix);
      fs.chmodSync(to + suffix, 0o600);
    } else fs.rmSync(from + suffix, { force: true });
  }
  fs.chmodSync(to, 0o600);
}
function syncFile(file) {
  const handle = fs.openSync(file, 'r+');
  try {
    fs.fsyncSync(handle);
  } finally {
    fs.closeSync(handle);
  }
}

// Whether `file` holds exactly one of `expected` ({bytes, sha256}, or a list of them): its size
// and SHA-256, with no WAL or rollback journal beside it that would change what a database reads.
// `hashOf` may answer from a cache (history.sqlite can be large).
async function holds(file, expected, hashOf = sha256) {
  if (!exists(file)) return false;
  if (sizeOf(`${file}-wal`) > 0 || sizeOf(`${file}-journal`) > 0) return false;
  const bytes = sizeOf(file);
  const candidates = [expected ?? []].flat().filter(item => item.bytes === bytes);
  if (!candidates.length) return false;
  const hash = await hashOf(file);
  return candidates.some(item => item.sha256 === hash);
}

// Finishes a folder of live files that had changed after an interrupted restore (restoreSnapshot
// step 2 sets them aside there instead of deleting them): its manifest makes it a pre-restore
// snapshot of those files only, so restoring it puts them back and keeps the others as they are.
// `known` maps a database this attempt found damaged to its problem; any other database in the
// folder is checked here, since a crash may have stopped the attempt that put it there.
// Resolves {id, files, damaged}, or null when the folder holds nothing (it is removed) or
// neither it nor a finished snapshot of that id exists.
async function finishKept(root, keptId, { id, asideId, release, now, known }) {
  const folder = path.join(root, `.restoring-${keptId}`);
  if (!exists(folder)) {
    // Finished by an attempt that a crash stopped after this step.
    try {
      const manifest = readManifest(path.join(root, keptId));
      return {
        id: keptId,
        files: manifest.files.map(file => file.name),
        damaged: (manifest.damaged ?? []).map(({ name, problem }) => ({ name, problem })),
      };
    } catch {
      return null;
    }
  }
  const present = managedFiles.filter(file => exists(path.join(folder, file.name)));
  if (!present.length) {
    // Made by an attempt that stopped before it set anything aside. Only an empty folder is
    // removed; anything else in it stays, listed as an interrupted restore's.
    try {
      fs.rmdirSync(folder);
    } catch {}
    return null;
  }
  const files = [],
    damaged = [];
  for (const file of present) {
    const copy = path.join(folder, file.name);
    files.push({ name: file.name, bytes: sizeOf(copy), sha256: await sha256(copy) });
    if (file.kind !== 'sqlite') continue;
    const problem = known.get(file.name) ?? databaseProblem(copy);
    if (problem)
      damaged.push({
        name: file.name,
        problem,
        sidecars: sidecars
          .map(suffix => file.name + suffix)
          .filter(item => exists(path.join(folder, item))),
      });
  }
  // Durably, with the folder's entries (the files moved into it): the folder's final name, which
  // restoreSnapshot flushes with the aside folder's before it removes the journal, must never
  // reach the disk before them.
  writeJsonDurably(path.join(folder, 'manifest.json'), {
    format: 1,
    id: keptId,
    reason: 'pre-restore',
    release: release ?? null,
    fromRelease: null,
    createdAt: now,
    pinned: false,
    files,
    absent: [],
    excluded: managedFiles.filter(file => !present.includes(file)).map(file => file.name),
    restoring: id,
    // These files had changed after the interrupted attempt whose pre-restore snapshot is
    // `changedAfter` (Orbit 1.4.x, which ignores the journal, ran on the data directory, say).
    changedAfter: asideId,
    ...(damaged.length ? { damaged } : {}),
  });
  fs.renameSync(folder, path.join(root, keptId));
  return {
    id: keptId,
    files: files.map(file => file.name),
    damaged: damaged.map(({ name, problem }) => ({ name, problem })),
  };
}

// The manifest of the pre-restore snapshot of the restore `journal` (from readJournal) records,
// when that restore had in fact completed: step 3 gave its folder the final name, and a crash or a
// power loss stopped it before the journal was removed. null otherwise (its folder still has the
// .restoring- name, or there is none: it was interrupted before it finished).
function finishedRestore(root, journal) {
  if (!journal?.snapshot || typeof journal.aside !== 'string' || !idPattern.test(journal.aside))
    return null;
  if (exists(path.join(root, `.restoring-${journal.aside}`))) return null;
  try {
    const manifest = readManifest(path.join(root, journal.aside));
    return manifest.id === journal.aside && manifest.restoring === journal.snapshot
      ? manifest
      : null;
  } catch {
    return null;
  }
}

/**
 * Restores snapshot `id` into the data directory. Uptime Goblin must be stopped: pass the held
 * goblin.lock as `lock`. history.sqlite is kept as it is when the snapshot left it out, or with
 * `history: false`. Resolves {restored, removed, aside, damaged, unfinished, kept, leftovers}:
 * `aside` is the pre-restore snapshot holding the files it replaced, so the restore can itself
 * be undone.
 *
 * Order, so that a failure, a crash or a power loss never loses a file:
 *   1. verify the snapshot, then copy its files into the data directory under temporary names,
 *      and stamp meta.restored = {snapshot, at} into the copy of control.sqlite, so the next
 *      start signs every session out (D25), each copy flushed to disk (fsync) before anything
 *      renames it (a failure here, for example a full disk, removes the temporaries and changes
 *      nothing else); then settle each live database to be replaced (its WAL folded in). One
 *      that cannot be (damaged, often the reason for the restore) is listed in `damaged` and
 *      moved aside as it is, with its -wal and -shm: the pre-restore snapshot keeps it, and fails
 *      verification, since it cannot be restored;
 *   2. write the journal (snapshots/.restore-in-progress.json, see restoreJournal), with the
 *      size and SHA-256 of each copy (control.sqlite's once stamped) and the files the data
 *      directory does not hold (`absent`); only then make snapshots/.restoring-<aside>/, so that
 *      a crash leaves no folder that no journal names (removeEmptyRestoreFolders); then per
 *      managed file: set the current one aside into it (see setAside: a database is renamed,
 *      config.json and auth.json are copied) and rename the temporary into its place (over
 *      config.json and auth.json, which are therefore never missing); then flush the data
 *      directory;
 *   3. write the aside manifest durably (with the folder), rename the folder to its final name,
 *      flush snapshots/, and only then remove the journal (flushed too). Once the journal is gone
 *      a start runs on the restored files, so they and the pre-restore snapshot are on disk by
 *      then: after a power loss, ext4 for one could otherwise leave an empty history.sqlite
 *      there, which a start takes for an empty history without a word.
 * A crash during step 2 leaves .restoring-<aside>/ holding the files set aside (listed as an
 * interrupted restore and never pruned) and the journal, so Uptime Goblin 1.5 refuses to start
 * (startControl) until the restore is run again, which completes it: running the same restore
 * again continues in that folder, so the files it had set aside (what the data directory held
 * before the first attempt) become the pre-restore snapshot. A live file in the place of one of
 * them, or of one the journal records as `absent`, is deleted only while it is still what that
 * attempt left there: its copy of this snapshot (the journal's size and SHA-256), or the file
 * itself before it was replaced (equal to the one set aside). Any other has changed since: Uptime Goblin
 * 1.4.x, which ignores the journal, ran on the directory after a code rollback (readings,
 * settings, a password) or created a file the attempt had moved away. It is set aside into a
 * snapshot of its own (`kept` in the result: {id, files, damaged}; a pre-restore snapshot of
 * those files only, see finishKept), never deleted; the journal names that folder, so a later
 * attempt finishes it if this one is stopped. A file `absent` when the first attempt began stays
 * absent in the pre-restore snapshot: the copy an attempt put in its place is never set aside as
 * if the restore had replaced it.
 * A crash in step 3 after the aside folder got its final name leaves a completed restore and its
 * journal (finishedRestore). Run again, the same restore reopens that pre-restore snapshot as its
 * folder (renamed back while the journal still names it) and continues in it as above, so the
 * undo stays what the data directory held before the first attempt, not the first attempt's
 * copies of this snapshot; any other restore leaves that snapshot as it is, and the journal of a
 * completed restore is not kept for it.
 * `unfinished` in the result names an earlier interrupted restore this one did not finish (it
 * replaced files this one leaves as they are): its journal stays. This restore's own journal
 * carries it from step 2 on (`unfinished` there too, with only those files), so that it survives
 * an interruption of this restore and the attempt that completes it puts it back.
 * Temporary copies an earlier restore left in the data directory (restoreTemporaries) are removed
 * before step 1 and again once this restore completed, except those of files a journal still
 * names: the earlier copies of files this restore copies are replaced by its own in step 1, and
 * `leftovers` in the result lists the copies it removed. Empty .restoring-* folders no journal
 * names are removed at the same two points (removeEmptyRestoreFolders).
 */
export async function restoreSnapshot(
  directory,
  id,
  { lock, history = true, release, clock = Date.now } = {}
) {
  if (!lock?.held || path.dirname(lock.file) !== fs.realpathSync(directory))
    throw new SnapshotError(
      'snapshot_unlocked',
      'Restoring a snapshot needs goblin.lock held for this data directory (Uptime Goblin stopped).'
    );
  assertSnapshotsDirectory(directory);
  const verified = await verifySnapshot(directory, id);
  if (!verified.ok)
    throw new SnapshotError(
      'snapshot_damaged',
      `Snapshot ${id} cannot be restored: ${verified.problems.join('; ')}`
    );
  const { manifest } = verified;
  const keep = new Set(manifest.excluded ?? []);
  if (!history) keep.add('history.sqlite');
  const incoming = manifest.files.filter(file => !keep.has(file.name));
  const replace = managedFiles.filter(
    file =>
      !keep.has(file.name) &&
      (incoming.some(item => item.name === file.name) || manifest.absent?.includes(file.name))
  );
  // Each live file this restore replaces is copied, renamed or hashed below: a FIFO in its place
  // (or in a database's journal's) would hold the restore for good, with goblin.lock and, once
  // it began, the journal that makes every start refuse. Refused before anything changes; the
  // entry is moved out of the data directory by hand, and the restore run again.
  for (const file of replace) {
    const live = path.join(directory, file.name);
    try {
      if (file.kind === 'sqlite') assertDatabaseFiles(live);
      else assertRegularFile(live);
    } catch (error) {
      if (error?.name !== 'UnusableFileError') throw error;
      throw new SnapshotError(
        'live_file_unusable',
        `Snapshot ${id} was not restored: ${error.message}, so it cannot be set aside. No file was replaced or set aside. Move it out of the data directory, then restore again.`
      );
    }
  }
  const root = rootOf(directory);
  const temporaryOf = name => path.join(directory, temporaryName(name));
  // Copies left by a restore that a crash stopped, which nothing will use, go first: each is as
  // large as the file it copies (history.sqlite included), and this restore needs the room. Those
  // an interrupted restore's journal names stay; they go once a restore takes their file over.
  const leftovers = removeRestoreLeftovers(directory);
  removeEmptyRestoreFolders(directory);

  // 1. The snapshot's files, copied in beside the live ones; the control database's copy is
  // stamped as restored (see stampRestored) before anything live changes. `copies` records what
  // each copy holds, so that a later attempt can tell it from a file written after this one.
  const copies = {};
  try {
    for (const file of incoming) {
      const temporary = temporaryOf(file.name);
      for (const suffix of ['', ...sidecars]) fs.rmSync(temporary + suffix, { force: true });
      fs.copyFileSync(path.join(root, id, file.name), temporary, fs.constants.COPYFILE_EXCL);
      fs.chmodSync(temporary, 0o600);
      if (sizeOf(temporary) !== file.bytes || (await sha256(temporary)) !== file.sha256)
        throw new SnapshotError('snapshot_damaged', `${file.name} changed while it was copied`);
      copies[file.name] = { bytes: file.bytes, sha256: file.sha256 };
      if (file.name === 'control.sqlite') {
        const at = clock();
        await stampRestored(temporary, JSON.stringify({ snapshot: id, at }), at);
        fs.chmodSync(temporary, 0o600);
        copies[file.name] = { bytes: sizeOf(temporary), sha256: await sha256(temporary) };
      }
      // On disk before step 2 renames it into place: a rename that reaches the disk before the
      // data it names leaves an empty or partial file under the live name after a power loss.
      syncFile(temporary);
    }
  } catch (error) {
    for (const file of incoming)
      for (const suffix of ['', ...sidecars])
        try {
          fs.rmSync(temporaryOf(file.name) + suffix, { force: true });
        } catch {}
    throw error;
  }

  // The same restore run again after it was interrupted (the same snapshot, every file it was
  // replacing): it continues in the earlier attempt's folder. The files there are what the data
  // directory held before that attempt began, so they stay this restore's pre-restore files.
  const earlier = readJournal(directory);
  const again =
    earlier?.snapshot === id &&
    typeof earlier.aside === 'string' &&
    idPattern.test(earlier.aside) &&
    earlier.files.every(name => replace.some(file => file.name === name));
  // An earlier restore whose folder already has its final name had completed: a crash or a power
  // loss stopped it only before its journal was removed. Its copies of the snapshot are in place,
  // so setting the live files aside again would make this restore's undo a copy of the snapshot
  // itself and leave the real one unnamed. Run again, it reopens that pre-restore snapshot as its
  // folder: renamed back while the journal names it, so a crash from here on leaves an ordinary
  // interrupted restore. Any other restore leaves that snapshot as it is: of that journal, only
  // the earlier restores it carries (`unfinished`) may be left to finish.
  const finished = finishedRestore(root, earlier);
  if (again && finished) {
    fs.renameSync(path.join(root, earlier.aside), path.join(root, `.restoring-${earlier.aside}`));
    syncDirectory(root);
  }
  const resumed =
    again && exists(path.join(root, `.restoring-${earlier.aside}`)) ? earlier.aside : null;
  const reopened = resumed && finished;
  // The earlier interrupted restores this one does not continue: the one in the journal (unless
  // this is that restore run again, or that one had completed) and those it carries. What this
  // restore leaves of them, the files it does not replace, goes into its own journal, so that an
  // interruption of this one, which replaces the journal, does not lose them: the journal step 3
  // leaves is that, and Uptime Goblin 1.5 keeps refusing to start until they are finished too. (Before,
  // a restore of a snapshot without history over one interrupted after it had set history.sqlite
  // aside, itself interrupted and run again, removed the journal: the start then ran without
  // history.sqlite and began an empty history.)
  const outer = earlier && (again || finished) ? (earlier.unfinished ?? null) : earlier;
  const carried = unfinishedAfter(
    outer,
    replace.map(file => file.name)
  );
  // Whatever that folder holds is kept as it is, whether or not the journal still names it (a
  // narrower restore in between rewrites it): a file there is never overwritten.
  const originals = new Set(
    replace
      .filter(file => resumed && exists(path.join(root, `.restoring-${resumed}`, file.name)))
      .map(file => file.name)
  );
  // The files the data directory did not hold when the first attempt began (the journal's, or
  // the reopened snapshot's `absent`): what is in their place now is not what this restore
  // replaces, so it never goes into the folder; the undo records them as absent.
  const absentBefore = new Set(
    (resumed ? [...earlier.absent, ...(reopened?.absent ?? [])] : []).filter(
      name => !originals.has(name)
    )
  );
  const fromEarlier = name => originals.has(name) || absentBefore.has(name);
  // The live file in the place of one that attempt set aside, or of one that was absent, is what
  // it left there (a copy of the snapshot, the file itself when it stopped between setting it
  // aside and replacing it, or nothing), unless something wrote to the data directory since: Uptime Goblin
  // 1.4.x, after a code rollback, starts on it regardless of the journal (or a narrower restore
  // replaced it). Such a file holds what may exist nowhere else, so it is set aside into a
  // snapshot of its own below, never deleted.
  const changed = new Set();
  const hashes = new Map();
  const hashOf = file => {
    if (!hashes.has(file)) hashes.set(file, sha256(file));
    return hashes.get(file);
  };
  for (const file of replace) {
    const live = path.join(directory, file.name);
    if (!fromEarlier(file.name) || !exists(live)) continue;
    if (await holds(live, earlier.copies[file.name], hashOf)) continue;
    if (originals.has(file.name)) {
      const before = path.join(root, `.restoring-${resumed}`, file.name);
      if (
        sizeOf(live) === sizeOf(before) &&
        (await holds(live, { bytes: sizeOf(before), sha256: await hashOf(before) }, hashOf))
      )
        continue;
    }
    changed.add(file.name);
  }
  // Each live database to set aside is settled now, before anything live changes, so the swap
  // is renames only. One that cannot be read (damaged: often why it is being restored) is not
  // opened the usual way, which would delete its WAL, and moves aside as it is; it must not
  // stop the restore, or the re-run that the refusal asks for would stop on it the same way.
  const damaged = new Map();
  for (const file of replace) {
    const live = path.join(directory, file.name);
    if (file.kind !== 'sqlite' || !exists(live)) continue;
    if (fromEarlier(file.name) && !changed.has(file.name)) continue;
    const problem = databaseProblem(live);
    if (problem) {
      damaged.set(file.name, problem);
      continue;
    }
    try {
      settleDatabase(live);
    } catch (error) {
      damaged.set(file.name, error?.message || String(error));
    }
  }

  // 2. Swap: the live file is set aside, the copy takes its place.
  const now = clock();
  // An id no snapshot, folder or journal entry of this restore, or of one it carries, has yet.
  const reserved = new Set([
    ...(resumed ? [resumed, ...earlier.kept] : []),
    ...chainFolders(carried),
  ]);
  const freshId = () => {
    let candidate = `pre-restore-${safeRelease(release ?? manifest.release)}-${stamp(now)}`;
    for (
      let n = 2;
      reserved.has(candidate) ||
      exists(path.join(root, candidate)) ||
      exists(path.join(root, `.restoring-${candidate}`));
      n += 1
    )
      candidate = `pre-restore-${safeRelease(release ?? manifest.release)}-${stamp(now)}-${n}`;
    reserved.add(candidate);
    return candidate;
  };
  const asideId = resumed ?? freshId();
  const folder = path.join(root, `.restoring-${asideId}`);
  // The live files that changed after the interrupted attempt get a folder of their own (each
  // attempt a new one, so nothing in an earlier one is ever overwritten); the journal names
  // every such folder of this restore, so the attempt that completes it finishes them all.
  const keptId = changed.size ? freshId() : null;
  const keptIds = [...new Set([...(resumed ? earlier.kept : []), ...(keptId ? [keptId] : [])])];
  // From here until step 3 completes the data directory is a mix of the snapshot and what it
  // replaces: the journal makes the next start refuse instead of running on it. An earlier
  // interrupted restore's journal is replaced; its files are kept in its own folder (which this
  // one continues in when it runs the same restore again), and what this one leaves of it is
  // carried in this journal (`unfinished`).
  const journal = path.join(root, restoreJournal);
  // The copies of every attempt of this restore count as its own: one that a crash stops part
  // way through this step leaves some files as the earlier attempt put them.
  for (const name of Object.keys(copies))
    copies[name] = [copies[name], ...((resumed && earlier.copies[name]) || [])].filter(
      (item, index, list) => list.findIndex(other => other.sha256 === item.sha256) === index
    );
  writeJsonDurably(journal, {
    snapshot: id,
    aside: asideId,
    files: replace.map(file => file.name),
    keepHistory: !history,
    startedAt: now,
    copies,
    absent: replace
      .filter(
        file =>
          absentBefore.has(file.name) ||
          (!originals.has(file.name) && !exists(path.join(directory, file.name)))
      )
      .map(file => file.name),
    ...(keptIds.length ? { kept: keptIds } : {}),
    ...(carried ? { unfinished: carried } : {}),
  });
  // The folders only once the journal names them: a crash in between leaves the journal (the
  // start refuses, and running the restore again makes them), never an empty folder that no
  // journal names, which the restore run again would not continue in either.
  const keptFolder = keptId && path.join(root, `.restoring-${keptId}`);
  if (!resumed) fs.mkdirSync(folder, { mode: 0o700 });
  if (keptId) fs.mkdirSync(keptFolder, { mode: 0o700 });
  if (!resumed || keptId) syncDirectory(root);
  const moved = [],
    restored = [];
  for (const file of replace) {
    const target = path.join(directory, file.name);
    const copied = incoming.some(item => item.name === file.name);
    const settings = { unsettled: damaged.has(file.name), replaced: copied };
    if (fromEarlier(file.name)) {
      // Kept from the interrupted attempt, or absent when it began. What is in its place now is
      // that attempt's copy of this snapshot (replaced below by a fresh one), the file before
      // that attempt replaced it (identical to the one kept), nothing, or a file that changed
      // since, set aside unseen.
      if (changed.has(file.name)) setAside(directory, file, keptFolder, settings);
      else if (!copied)
        for (const suffix of ['', ...sidecars]) fs.rmSync(target + suffix, { force: true });
      if (originals.has(file.name)) moved.push(file.name);
    } else if (exists(target)) {
      setAside(directory, file, folder, settings);
      moved.push(file.name);
    }
    if (copied) {
      for (const suffix of sidecars) fs.rmSync(target + suffix, { force: true });
      fs.renameSync(temporaryOf(file.name), target);
      restored.push(file.name);
    }
  }
  // The renames and removals in the data directory reach the disk before step 3 lets the journal
  // go (the copies themselves were flushed in step 1).
  syncDirectory(directory);

  // 3. The folders become pre-restore snapshots: first those of files that had changed after an
  // interrupted attempt, then the aside folder.
  const kept = [];
  for (const item of keptIds) {
    const done = await finishKept(root, item, {
      id,
      asideId,
      release,
      now,
      known: new Map(item === keptId ? [...damaged].filter(([name]) => changed.has(name)) : []),
    });
    if (done) kept.push(done);
  }
  const asideFiles = [];
  for (const name of moved) {
    const copy = path.join(folder, name);
    asideFiles.push({ name, bytes: sizeOf(copy), sha256: await sha256(copy) });
  }
  // A database an earlier attempt set aside was not opened by this one: it is checked here (as
  // finishKept does), so that a damaged one is named with its -wal and -shm and the undo is not
  // offered as restorable. A reopened snapshot's manifest already says which.
  const asideDamaged = new Map([...damaged].filter(([name]) => !changed.has(name)));
  const known = new Map((reopened?.damaged ?? []).map(({ name, problem }) => [name, problem]));
  for (const file of managedFiles) {
    if (file.kind !== 'sqlite' || !originals.has(file.name) || asideDamaged.has(file.name))
      continue;
    const problem = known.get(file.name) ?? databaseProblem(path.join(folder, file.name));
    if (problem) asideDamaged.set(file.name, problem);
  }
  const damagedFiles = [...asideDamaged].map(([name, problem]) => ({
    name,
    problem,
    sidecars: sidecars.map(suffix => name + suffix).filter(item => exists(path.join(folder, item))),
  }));
  // Durably, with the folder's entries, and the folder's final name flushed before the journal
  // goes: the pre-restore snapshot is the undo, and a power loss must not leave it without its
  // manifest (listed as invalid) once nothing refuses the start any more.
  writeJsonDurably(path.join(folder, 'manifest.json'), {
    format: 1,
    id: asideId,
    reason: 'pre-restore',
    release: release ?? null,
    fromRelease: null,
    createdAt: now,
    pinned: false,
    files: asideFiles,
    absent: replace.filter(file => !moved.includes(file.name)).map(file => file.name),
    excluded: managedFiles.filter(file => keep.has(file.name)).map(file => file.name),
    restoring: id,
    // Moved aside as they were, with their -wal and -shm: they could not be opened, so this
    // snapshot fails verification and cannot be restored as a whole.
    ...(damagedFiles.length ? { damaged: damagedFiles } : {}),
  });
  fs.renameSync(folder, path.join(root, asideId));
  syncDirectory(root);
  // Complete. An earlier restore that was interrupted is finished by this one only when this
  // one replaced every file that one was replacing (the same snapshot, or one at least as
  // wide): otherwise its journal stays (`carried`, with the earlier ones it carries), so Uptime Goblin
  // still refuses to start on a file it may have left half swapped (history.sqlite moved aside,
  // say), and `unfinished` names it. One that had completed (`finished`) leaves nothing to finish
  // of its own.
  if (carried) writeJsonDurably(journal, carried);
  else {
    fs.rmSync(journal, { force: true });
    syncDirectory(root);
  }
  // Every copy of this restore is in place now. What is left is an earlier attempt's copy of a
  // file this one took over without copying it (absent in this snapshot), or one of a file whose
  // journal this one finished: no journal names it any more. A file left in `unfinished` keeps
  // its copy.
  leftovers.push(...removeRestoreLeftovers(directory));
  removeEmptyRestoreFolders(directory);
  return {
    restored,
    removed: (manifest.absent ?? []).filter(name => !keep.has(name) && moved.includes(name)),
    aside: asideId,
    damaged: damagedFiles.map(({ name, problem }) => ({ name, problem })),
    unfinished: carried
      ? {
          snapshot: carried.snapshot,
          aside: carried.aside,
          files: carried.files,
          keepHistory: carried.keepHistory,
        }
      : null,
    kept,
    leftovers: leftovers.map(({ id, names, bytes }) => ({ id, names, bytes })),
  };
}
