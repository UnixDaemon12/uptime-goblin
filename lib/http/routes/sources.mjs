// Sources: add, change, remove, test a connection, collect now.
//
// Routes reach the scheduler only through `app.collection`, so the scheduler can move out of
// server.mjs (1.5 wave 2) behind the same calls:
//
//   collect(service, signal)      one logical collection (retries, deadline) -> readings
//   beginTest() / endTest(id)     a connection-test slot ({id, controller}, or null when two
//                                 tests already run) and its release
//   hold(id, task)                keep the scheduler off a source while task() runs
//   stop(id)                      abort the source's running collection
//   forget(id)                    drop the source's collector state and schedule
//   unschedule(id)                drop only its schedule
//   sourceChanged(id, old, next)  restart its collection when collection fields changed
//   restart()                     abort every collection and collect everything again
//   reschedule()                  collect everything again (running collections continue)
//   refresh()                     collect everything now, in the background
//   monitoringKey()               changes exactly when a setting that affects collection does
//   interval(s), timeoutMs(s), pending(), inflightCount()
import { collectorType, publicConfig } from '../../catalog.mjs';
import { assertKnownSource, validateService, InputError } from '../../config.mjs';
import { json } from '../body.mjs';
import { revisionConflict } from '../pipeline.mjs';

/** A saved source's ID, as config.json holds it (lib/config.mjs parseConfig). */
const sourceIdPattern = /^[a-zA-Z0-9_-]{1,80}$/;

// Whether a failed connection test ran out of time (its own deadline, or the collection's),
// rather than failing; a test whose browser went away was cancelled, which is neither.
function timedOut(failure, controller, res) {
  if (res.destroyed) return false;
  return (
    controller.signal.aborted || /exceeded its time limit/.test(String(failure?.message ?? ''))
  );
}

/**
 * What a saved change of source `old` to `service` sets off, for PATCH /api/services/:id and
 * the changes of an import (routes/import.mjs), so both react alike: its collection restarts when
 * a collection field changed, and its alert state and history follow (rules reconciled, alerts
 * cleared and a gap marked when it stopped or measures something else). A history error raises
 * the storage notice rather than failing the request. `app` as for sourceRoutes().
 */
export function sourceSaved(app, old, service) {
  const { collection, storage, store, configured } = app,
    id = service.id;
  collection.sourceChanged(id, old, service);
  storage.step(() => {
    const measurementsChanged =
      collectorType(old) !== collectorType(service) ||
      (old.nodeName || '') !== (service.nodeName || '');
    if (measurementsChanged) store.clearAlerts(id);
    else store.reconcileRules(id, old.rules, service.rules);
    const stopped = !service.enabled || !configured(service);
    if (stopped) store.clearAlerts(id);
    if (stopped || measurementsChanged || old.enabled !== service.enabled) store.markGap(id);
  });
}

/**
 * `app` (see createApp in server.mjs): config, store, exclusive(), mono(), storage
 * {failed(), step()}, collection (above), alerting (the delivery service: a deleted source's
 * waiting notifications are cancelled), and the source helpers configured(s), noCollector(s)
 * and collectionError(error, s).
 */
export function sourceRoutes(app) {
  const { config, store, collection, storage, configured, noCollector } = app;
  // Repeated refresh clicks within 5 s are coalesced (monotonic clock).
  let nextRefresh = 0;
  const publicSource = service => publicConfig({ services: [service] }).services[0];
  return [
    {
      method: 'POST',
      path: '/api/test-service',
      auth: 'session',
      permission: 'sources:test',
      // One row after the answer, best effort (audit spec §5.5): a test changes nothing stored.
      audit: 'operation',
      summary: 'Test a source connection without saving it',
      async handler({ res, body, assertCurrent, audit }) {
        const input = await body();
        if (!input || typeof input !== 'object' || Array.isArray(input))
          throw new InputError('Expected connection settings');
        for (const key of Object.keys(input))
          if (!['serviceId', 'settings'].includes(key))
            throw new InputError(`Unknown connection test field: ${key.slice(0, 60)}`);
        assertKnownSource(input.settings);
        // A saved source's ID, or null (the editor's new source, 1.4.x's too) or absent for
        // settings not saved yet. Any other value (a number, an object, an empty string) was
        // treated as "not saved" or "not found" depending on its type.
        const serviceId = input.serviceId ?? null;
        if (
          serviceId !== null &&
          (typeof serviceId !== 'string' || !sourceIdPattern.test(serviceId))
        )
          throw new InputError('serviceId must be the ID of a saved source, or null');
        const saved = serviceId === null ? undefined : config.get(serviceId);
        if (serviceId !== null && !saved) throw new InputError('Source not found');
        // A saved source is tested as updateCandidate checks a change to it: with its own type,
        // which the editor locks. Another type's collector would otherwise be handed the saved
        // credentials, for example a Proxmox token sent as SABnzbd's ?apikey= query parameter.
        const outcome = {},
          service = saved
            ? config.updateCandidate(saved.id, input.settings, outcome)
            : validateService(input.settings, undefined, outcome);
        if (noCollector(service))
          throw new InputError(
            'This source is a bookmark. Select a collector to test measurements.'
          );
        if (!configured(service)) throw new InputError('Enter a collection address first.');
        const test = collection.beginTest();
        if (!test) {
          json(res, 429, {
            error: 'Two connection tests are already running. Please wait for one to finish.',
          });
          return;
        }
        const { id, controller } = test,
          started = Date.now();
        // Never the address or an error text (they may name hosts or carry credentials): the
        // source, its type and whether saved credentials were used.
        const operation = audit.operation({
          action: 'source.test',
          target: { type: 'source', id: saved ? saved.id : null, name: service.name ?? null },
          detail: {
            type: service.type ?? null,
            savedCredentials: Boolean(saved && (saved.apiKey || saved.password)),
          },
        });
        const cancel = () => controller.abort();
        res.once('close', cancel);
        let metrics, failure;
        try {
          metrics = await collection.collect({ ...service, id }, controller.signal);
          if (controller.signal.aborted)
            throw new Error('Connection test exceeded its time limit.');
        } catch (e) {
          failure = e;
        } finally {
          res.off('close', cancel);
          collection.endTest(id);
        }
        // Noted before the client check: a test the browser abandoned (a new one started) is
        // still recorded, with no status and client_closed (settle).
        operation.note({
          outcome: failure ? 'failed' : 'ok',
          detail: {
            result: !failure
              ? 'connected'
              : timedOut(failure, controller, res)
                ? 'timeout'
                : 'failed',
            credentialsCleared: Boolean(outcome.credentialsCleared),
          },
        });
        if (res.destroyed) return;
        // A test may run up to its 120 s deadline: a session signed out meanwhile gets 401 and
        // the readings (which may show what the credentials can reach) are discarded (§6.5).
        assertCurrent();
        if (failure) {
          json(res, 422, {
            error: controller.signal.aborted
              ? 'Connection test exceeded its time limit.'
              : app.collectionError(failure, service),
          });
          return;
        }
        json(res, 200, {
          ok: true,
          metrics,
          // Readings a collector left out because of a limit, explained (collector notes).
          notes: Array.isArray(metrics.notes) ? metrics.notes : [],
          ...(outcome.credentialsCleared ? { credentialsCleared: true } : {}),
          elapsedMs: Date.now() - started,
          checkedAt: Date.now(),
        });
      },
    },
    {
      method: 'POST',
      path: '/api/services',
      auth: 'session',
      permission: 'sources:write',
      ifMatch: 'optional',
      audit: 'config',
      summary: 'Add a source',
      async handler({ req, res, access, body, gone, audit }) {
        const input = await body();
        assertKnownSource(input);
        // Checked before the write takes its turn: a malformed source writes no audit row, takes
        // no queue slot and gets its 400 also while the disk is full. add() checks it again.
        config.checkNew(input);
        // The id is known once the source is added: the result row names it (audit spec §5.4).
        await app.exclusive({ access, abandoned: gone, audit }, add, {
          action: 'source.create',
          target: {
            type: 'source',
            id: null,
            name: typeof input?.name === 'string' ? input.name : null,
          },
          detail: { ifMatch: req.headers['if-match'] !== undefined },
        });
        async function add(change) {
          // A retry after a lost answer names the revision it was based on: if the first
          // attempt was saved (even by a process since restarted), this refuses a duplicate.
          if (revisionConflict(req, res, config.value.revision)) return;
          const service = config.add(input);
          change.note({ target: { type: 'source', id: service.id, name: service.name ?? null } });
          // IDs are no longer reused, but rows left by an older release must not be
          // inherited. Holding the source keeps the scheduler from polling it until they
          // are gone; forget()'s last step would otherwise delete that first reading.
          await collection.hold(service.id, async () => {
            try {
              await store.forget(service.id);
            } catch (e) {
              storage.failed(e);
            }
          });
          collection.unschedule(service.id);
          json(res, 201, { service: publicSource(service), revision: config.value.revision });
        }
      },
    },
    {
      method: 'PATCH',
      path: '/api/services/:id',
      auth: 'session',
      permission: 'sources:write',
      ifMatch: 'optional',
      audit: 'config',
      summary: 'Change a source',
      async handler({ req, res, access, params: { id }, body, gone, audit }) {
        if (!config.get(id)) {
          json(res, 404, { error: 'Source not found' });
          return;
        }
        const input = await body();
        assertKnownSource(input);
        // As for a new source: checked against the source as it is now before the write takes
        // its turn, then again inside it (it may change while the write waits).
        config.updateCandidate(id, input);
        await app.exclusive({ access, abandoned: gone, audit }, update, {
          action: 'source.update',
          target: { type: 'source', id, name: config.get(id)?.name ?? null },
          detail: { ifMatch: req.headers['if-match'] !== undefined },
        });
        function update(change) {
          if (revisionConflict(req, res, config.value.revision)) return;
          // The source as it is now: it may have changed while the body arrived.
          const old = config.get(id);
          if (!old) {
            json(res, 404, { error: 'Source not found' });
            return;
          }
          const outcome = {},
            service = config.update(id, input, outcome);
          // Saved credentials that no longer fit the changed source were dropped.
          if (outcome.credentialsCleared) change.note({ detail: { credentialsCleared: true } });
          sourceSaved(app, old, service);
          json(res, 200, {
            service: publicSource(service),
            revision: config.value.revision,
            ...(outcome.credentialsCleared ? { credentialsCleared: true } : {}),
          });
        }
      },
    },
    {
      method: 'DELETE',
      path: '/api/services/:id',
      auth: 'session',
      permission: 'sources:write',
      body: 'empty',
      ifMatch: 'optional',
      audit: 'config',
      summary: 'Remove a source and its history',
      async handler({ req, res, access, params: { id }, gone, audit }) {
        if (!config.get(id)) {
          json(res, 404, { error: 'Source not found' });
          return;
        }
        await app.exclusive({ access, abandoned: gone, audit }, remove, {
          action: 'source.delete',
          target: { type: 'source', id, name: config.get(id)?.name ?? null },
          detail: { ifMatch: req.headers['if-match'] !== undefined },
        });
        async function remove(change) {
          if (revisionConflict(req, res, config.value.revision)) return;
          if (!config.get(id)) {
            json(res, 404, { error: 'Source not found' });
            return;
          }
          // Clear history first: if it fails, the source still exists and can be retried.
          // Clearing runs in steps; holding the source stops the scheduler from polling (and
          // alerting on) it meanwhile.
          collection.stop(id);
          await collection.hold(id, async () => {
            await store.forget(id);
            // Recorded as soon as it is true: a config.remove() that then fails leaves a
            // `failed` result whose history is gone all the same.
            change.note({ detail: { historyDeleted: true } });
            config.remove(id);
          });
          collection.forget(id);
          // Its notifications still waiting (retrying, held by a pause, in an email's quiet
          // window) are cancelled, so no alert arrives for a source that no longer exists and
          // will never recover (delivery spec D24). The source is already deleted: a failure
          // here is logged, not answered, and the send-time recheck skips those rows anyway.
          try {
            await app.alerting.forgetSource(id);
          } catch (error) {
            console.error(
              "Could not cancel the deleted source's waiting notifications:",
              error?.code || error?.name
            );
          }
          json(res, 200, { ok: true, revision: config.value.revision });
        }
      },
    },
    {
      method: 'POST',
      path: '/api/refresh',
      auth: 'session',
      permission: 'sources:operate',
      body: 'empty',
      // One row after the answer, best effort (audit spec §5.5); a coalesced click writes none.
      audit: 'operation',
      summary: 'Collect every source now',
      handler({ res, audit }) {
        // Coalesce repeated refresh clicks so upstream services are not hammered.
        if (app.mono() < nextRefresh) {
          json(res, 202, { ok: true, coalesced: true });
          return;
        }
        nextRefresh = app.mono() + 5000;
        audit.operation({
          action: 'sources.refresh',
          target: { type: 'sources', id: '*', name: null },
        });
        collection.refresh();
        json(res, 202, { ok: true });
      },
    },
  ];
}
