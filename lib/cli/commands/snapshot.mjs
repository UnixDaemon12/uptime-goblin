// goblin-admin snapshot: a physical copy of config.json, auth.json and the databases in
// <data>/snapshots/ (roadmap §2.11, offline: Uptime Goblin stopped).
import { createSnapshot, isSnapshotReason } from '../../db/snapshot.mjs';
import { quoted } from '../../environment.mjs';
import { formatBytes, withLock } from '../common.mjs';

export const summary = 'Take a snapshot of the data directory (Uptime Goblin stopped).';
export const usage = '[--reason <word>] [--no-history] [--pin] [--data-dir <dir>] [--json]';
export const kind = 'offline';
export const options = {
  reason: { type: 'string', default: 'manual' },
  'no-history': { type: 'boolean', default: false },
  pin: { type: 'boolean', default: false },
};
/**
 * The reason becomes the snapshot's name: checked before goblin.lock is taken (a usage error,
 * exit status 2), where createSnapshot refused it only with the lock held, with exit status 1.
 */
export const optionProblem = (given, values) =>
  isSnapshotReason(values.reason)
    ? null
    : `--reason takes a lower-case word of letters, digits and hyphens (up to 32 characters, such as manual or before-move); ${quoted(values.reason)} is not one.`;

export async function run(context) {
  const { options, dataDir, release } = context;
  return withLock(context, 'goblin-admin snapshot', async () => {
    const snapshot = await createSnapshot(dataDir, {
      reason: options.reason,
      release,
      history: !options['no-history'],
      pin: options.pin || undefined,
      clock: context.clock,
    });
    const bytes = snapshot.manifest.files.reduce((sum, file) => sum + file.bytes, 0);
    context.report(
      {
        id: snapshot.id,
        path: snapshot.path,
        bytes,
        files: snapshot.manifest.files.map(f => f.name),
        pinned: snapshot.manifest.pinned,
      },
      value =>
        `Snapshot ${value.id} (${formatBytes(value.bytes)}: ${value.files.join(', ') || 'no files'})${value.pinned ? ', pinned' : ''}`
    );
    return 0;
  });
}
