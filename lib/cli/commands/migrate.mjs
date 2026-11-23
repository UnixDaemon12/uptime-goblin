// goblin-admin migrate --plan | --apply (roadmap §2.2, §2.11). --plan is read-only and works
// while Uptime Goblin runs; --apply is offline: it takes goblin.lock, snapshots the data first (unless
// --no-snapshot) and applies the pending steps of the control database.
import {
  controlExists,
  controlSteps,
  interruptedRestoreMessage,
  openControl,
  planFromScratch,
  takeMigrationSnapshot,
} from '../../db/control.mjs';
import { RefusalError } from '../../db/migrate.mjs';
import { interruptedRestore } from '../../db/snapshot.mjs';
import { CommandError, withLock } from '../common.mjs';

export const summary =
  'Show (--plan) or apply (--apply, Uptime Goblin stopped) pending schema migrations.';
export const usage = '--plan | --apply [--no-snapshot] [--data-dir <dir>] [--json]';
export const kind = 'offline';
export const kindFor = options => (options.apply ? 'offline' : 'read');
export const options = {
  plan: { type: 'boolean', default: false },
  apply: { type: 'boolean', default: false },
  'no-snapshot': { type: 'boolean', default: false },
};
/** --no-snapshot belongs to --apply: with --plan it was ignored (see goblin-admin.mjs main()). */
export const optionProblem = (given, values) =>
  given.has('no-snapshot') && !values.apply
    ? '--no-snapshot applies to migrate --apply only.'
    : null;

export async function run(context) {
  const { options, dataDir, release } = context;
  if (options.plan === options.apply)
    throw new CommandError('Give exactly one of --plan and --apply.', 2);
  if (options.plan) {
    let plan;
    if (!controlExists(dataDir)) plan = { steps: planFromScratch(), refusal: null, exists: false };
    else {
      const control = openControl(dataDir, { readOnly: true, release, env: {} });
      try {
        const state = await control.plan();
        plan = { steps: state.steps, refusal: state.refusal?.message ?? null, exists: true };
      } finally {
        control.close();
      }
    }
    context.report(plan, value => {
      const lines = [];
      if (value.refusal) lines.push(`Refused: ${value.refusal}`);
      if (!value.exists) lines.push('No control database yet; the first start creates it.');
      if (!value.steps.length) lines.push('Nothing to migrate.');
      for (const step of value.steps) {
        lines.push(`${step.id} (${step.kind}, ${step.db}): ${step.description}`);
        for (const ddl of step.ddl) lines.push(ddl.replace(/^/gm, '    ') + ';');
      }
      return lines;
    });
    return plan.refusal ? 78 : 0;
  }

  return withLock(context, 'goblin-admin migrate', async () => {
    // As at start: never migrate a directory a snapshot restore left half done (it may lack
    // control.sqlite, which this would then create empty).
    const interrupted = interruptedRestore(dataDir);
    if (interrupted)
      throw new RefusalError('restore_interrupted', interruptedRestoreMessage(interrupted));
    let before = null;
    if (controlExists(dataDir)) {
      const existing = openControl(dataDir, { readOnly: true, release, env: {} });
      try {
        const state = await existing.inspect();
        if (state.refusal) throw state.refusal;
        before = {
          pending: state.pending.length,
          lastVersion: (await existing.meta.get('last_version').catch(() => null)) ?? null,
        };
      } finally {
        existing.close();
      }
    }
    const pending = before ? before.pending : controlSteps.length;
    const snapshot =
      pending && !options['no-snapshot']
        ? await takeMigrationSnapshot(dataDir, {
            release,
            lastVersion: before?.lastVersion ?? null,
            clock: context.clock,
          })
        : null;
    if (snapshot && !context.json)
      context.out(`Snapshot ${snapshot.id} ${snapshot.reused ? 'reused' : 'taken'}.`);
    const control = openControl(dataDir, { release, env: context.env });
    try {
      const result = await control.migrate({
        snapshotHint: snapshot?.id,
        onProgress: ({ step, index, total }) => {
          if (!context.json) context.out(`[${index + 1}/${total}] ${step}`);
        },
      });
      context.report({ ...result, snapshot: snapshot?.id ?? null }, value =>
        value.applied.length ? `Applied ${value.applied.length} step(s).` : 'Nothing to migrate.'
      );
    } finally {
      control.close();
    }
    return 0;
  });
}
