// goblin-admin snapshots: list the snapshots in <data>/snapshots/, optionally re-checking each
// one's checksums and databases (read-only; SQLite's integrity_check, as before a restore). The
// temporary copies an interrupted restore left in the data directory are listed after them:
// hidden files, as large as what they copy. --delete <id> deletes one snapshot instead, offline
// (goblin.lock held, Uptime Goblin stopped): never a pinned one without --force, and never one an
// interrupted restore still needs (deleteSnapshot).
import {
  deleteSnapshot,
  isSnapshotId,
  listSnapshots,
  restoreTemporaries,
  verifySnapshot,
} from '../../db/snapshot.mjs';
import { printable } from '../../saved-data.mjs';
import { quoted } from '../../environment.mjs';
import { formatBytes, formatTime, withLock } from '../common.mjs';

export const summary =
  'List snapshots (--verify re-checks them; --delete <id> deletes one, Uptime Goblin stopped).';
export const usage = '[--verify | --delete <id> [--force]] [--data-dir <dir>] [--json]';
export const kind = 'read';
export const options = {
  verify: { type: 'boolean', default: false },
  delete: { type: 'string' },
  force: { type: 'boolean', default: false },
};
/** Listing only reads; --delete changes the data directory, so it takes goblin.lock. */
export const kindFor = values => (values.delete !== undefined ? 'offline' : 'read');
/** Checked before goblin.lock is taken (a usage error, exit status 2). */
export const optionProblem = (given, values) => {
  if (values.delete === undefined)
    return values.force ? '--force goes only with --delete <id>.' : null;
  if (values.verify) return '--verify and --delete cannot be given together.';
  if (!isSnapshotId(values.delete))
    return `--delete takes the id of a snapshot as goblin-admin snapshots lists it; ${quoted(values.delete, 60)} is not one.`;
  return null;
};

/**
 * What a restore's leftover copy (from restoreTemporaries) is, and what removes it. Only Uptime Goblin 1.5
 * and later know of these copies: after a code rollback, 1.4.x neither removes them nor checks an
 * interrupted restore's journal, which the texts say, since this runs from the kept 1.5 copy then.
 */
export function leftoverProblem(item) {
  // Not needed. While an interrupted restore's journal exists (of another file: `snapshot` is
  // set), a start refuses before it removes anything, so only a restore removes it.
  if (!item.needed)
    return `A copy of ${item.file} left by a snapshot restore that a crash or a power loss stopped; nothing uses it (unless a restore is running now). ${item.snapshot ? 'The next restore-snapshot removes it.' : 'The next start of Uptime Goblin 1.5 or later, or the next restore-snapshot, removes it; Orbit 1.4.x leaves it (delete it by hand while Uptime Goblin is stopped).'}`;
  return item.snapshot
    ? `A copy of ${item.file} made by the interrupted restore of ${item.snapshot}. Run that restore again, with Uptime Goblin stopped, to finish it (restore-snapshot ${item.snapshot}${item.keepHistory ? ' --keep-history' : ''}); it replaces this copy. Uptime Goblin 1.5 and later will not start until then (Orbit 1.4.x does not check: keep it stopped too).`
    : `A copy of ${item.file} made by an interrupted restore whose record cannot be read. Run the restore again, with Uptime Goblin stopped, to finish it; it replaces this copy. Uptime Goblin 1.5 and later will not start until then (Orbit 1.4.x does not check: keep it stopped too).`;
}

/** The leftover copies as entries of the snapshot list: never valid, never pinned. */
export const leftoverEntries = directory =>
  restoreTemporaries(directory).map(item => ({
    id: item.id,
    valid: false,
    interrupted: true,
    leftover: true,
    file: item.file,
    names: item.names,
    bytes: item.bytes,
    needed: item.needed,
    snapshot: item.snapshot,
    keepHistory: item.keepHistory,
    createdAt: item.modifiedAt,
    pinned: false,
    problem: leftoverProblem(item),
  }));

export async function run(context) {
  if (context.options.delete !== undefined) return remove(context);
  const snapshots = listSnapshots(context.dataDir);
  let failed = false;
  if (context.options.verify)
    for (const item of snapshots) {
      if (!item.valid) {
        failed = true;
        continue;
      }
      // A folder named otherwise (copied in by hand) holds a manifest, but no command can name
      // it: reported, never passed to verifySnapshot, which refuses such a name.
      if (!isSnapshotId(item.id)) {
        item.verified = false;
        item.problems = ['its folder name is not a snapshot id, so restore-snapshot cannot use it'];
        failed = true;
        continue;
      }
      const { ok, problems } = await verifySnapshot(context.dataDir, item.id);
      item.verified = ok;
      if (!ok) {
        item.problems = problems;
        failed = true;
      }
    }
  const leftovers = leftoverEntries(context.dataDir);
  if (context.options.verify && leftovers.length) failed = true;
  // Folder names, the file names a manifest lists and the problems found (a system error names a
  // path) are saved text: printed without control characters, one bounded line each.
  const shown = (value, max = 300) => printable(value, max);
  context.report([...snapshots, ...leftovers], list => [
    ...(snapshots.length
      ? snapshots.map(item =>
          item.valid
            ? `${shown(item.id)}  ${formatTime(item.createdAt)}  ${formatBytes(item.bytes)}  ${shown(item.files.join(', ')) || 'no files'}${item.pinned ? '  [pinned]' : ''}${item.verified === true ? '  verified' : item.verified === false ? `  DAMAGED: ${shown(item.problems.join('; '), 1000)}` : ''}`
            : `${shown(item.id)}  INVALID: ${shown(item.problem, 1000)}`
        )
      : ['No snapshots.']),
    ...list
      .filter(item => item.leftover)
      .map(
        item =>
          `${item.names.join(', ')} (in the data directory)  ${formatTime(item.createdAt)}  ${formatBytes(item.bytes)}  LEFTOVER: ${item.problem}`
      ),
  ]);
  return failed ? 1 : 0;
}

// --delete <id>: with Uptime Goblin stopped, as the other offline commands.
async function remove(context) {
  const id = context.options.delete;
  return withLock(context, 'goblin-admin snapshots --delete', async () => {
    deleteSnapshot(context.dataDir, id, { force: context.options.force });
    context.report({ deleted: id }, value => `Deleted snapshot ${value.deleted}.`);
    return 0;
  });
}
