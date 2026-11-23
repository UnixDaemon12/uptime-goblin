// Importing monitors from an Uptime Kuma 1.x backup as Website checks: a preview that changes
// nothing, and an apply that saves the same plan in one configuration revision.
//
// Both take the backup itself as the JSON body (at most the API's 150,000-byte request limit;
// the web app sends it reduced by public/shared/uptime-kuma.js, credentials redacted), need
// config:import and, as writes, the CSRF header. The preview answers the configuration revision
// it planned against; the apply requires that revision as If-Match (428 without, 409 when the
// configuration changed since), so it saves exactly what the preview showed. The apply is
// recorded as one configuration change (sources.import, with the configuration before and
// after); the preview is not recorded, as it changes and reveals nothing.
import { planKumaImport, publicPlan } from '../../import/uptime-kuma.mjs';
import { json } from '../body.mjs';
import { revisionConflict } from '../pipeline.mjs';
import { sourceSaved } from './sources.mjs';

/**
 * `app` (see createApp in server.mjs): config, store, exclusive(), storage {failed(), step()},
 * collection and configured(s) (see sources.mjs).
 */
export function importRoutes(app) {
  const { config, store, collection, storage } = app;
  return [
    {
      method: 'POST',
      path: '/api/import/uptime-kuma/preview',
      auth: 'session',
      permission: 'config:import',
      // A preview is answered from the backup and the saved configuration alone: replaying it
      // would only answer an older revision's plan.
      idempotent: false,
      summary: 'Preview what an Uptime Kuma backup would add, change and skip',
      async handler({ res, body }) {
        const backup = await body();
        const plan = planKumaImport(backup, config.value.services);
        json(res, 200, { ...publicPlan(plan), revision: config.value.revision });
      },
    },
    {
      method: 'POST',
      path: '/api/import/uptime-kuma',
      auth: 'session',
      permission: 'config:import',
      ifMatch: 'required',
      audit: 'config',
      summary: 'Import the monitors of an Uptime Kuma backup as Website checks',
      async handler({ req, res, access, body, gone, audit }) {
        const backup = await body();
        // A backup that cannot be imported is refused before the write takes its turn: no audit
        // row, no queue slot, and its 400 also while the disk is full.
        planKumaImport(backup, config.value.services);
        await app.exclusive({ access, abandoned: gone, audit }, apply, {
          action: 'sources.import',
          target: { type: 'sources', id: 'uptime-kuma', name: null },
          detail: { ifMatch: true },
        });
        async function apply(change) {
          if (revisionConflict(req, res, config.value.revision)) return;
          // The revision the preview planned against: the same plan.
          const plan = planKumaImport(backup, config.value.services),
            counts = {
              added: plan.add.length,
              changed: plan.change.length,
              skipped: plan.skip.length,
            };
          change.note({ detail: counts });
          const answer = (added, changed) =>
            json(res, 200, {
              revision: config.value.revision,
              added: added.map((service, i) => ({
                kumaId: plan.add[i].kumaId,
                id: service.id,
                name: service.name,
              })),
              changed: changed.map(([, service], i) => ({
                kumaId: plan.change[i].kumaId,
                id: service.id,
                name: service.name,
              })),
              skipped: counts.skipped,
            });
          if (!plan.inputs.add.length && !plan.inputs.change.length) {
            answer([], []);
            return;
          }
          const { added, changed } = config.importSources(plan.inputs);
          // As for a source changed alone (PATCH /api/services/:id). A change sets only a Website
          // check's address, method, statuses, interval and group, never a credential.
          for (const [old, next] of changed) sourceSaved(app, old, next);
          // As for a source added alone (sources.mjs): rows an older release left under a new
          // ID are removed while the scheduler is kept off it.
          for (const service of added) {
            await collection.hold(service.id, async () => {
              try {
                await store.forget(service.id);
              } catch (e) {
                storage.failed(e);
              }
            });
            collection.unschedule(service.id);
          }
          answer(added, changed);
        }
      },
    },
  ];
}
