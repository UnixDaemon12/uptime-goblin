// The repositories (roadmap §2.1, amended by §10.4): one async boundary over every table, per
// store class. Nothing outside lib/repo, lib/series and lib/db issues SQL; callers get these
// objects and never a connection.
//
//   const stores = placeStores({databases: {control, history}});   // Dbs from lib/db
//   const repos = createRepositories({stores, budget});
//   await repos.series.append({service, time, metrics, error});      // ingest.append
//   await repos.state.alerts.transition(service, evaluate);          // state.transition
//
// 1.5 wave 1 builds these beside lib/store.mjs, which still serves every request; wave 2 moves
// the scheduler, ingest and dashboard onto them (see docs of each method for its Store twin).
import { createUnitRunner } from './unit.mjs';
import { createEvents } from './state/events.mjs';
import { createAlerts } from './state/alerts.mjs';
import { createStatus } from './state/status.mjs';
import { openSeriesStore } from '../series/store.mjs';

/**
 * Builds every repository on the placed stores (lib/repo/stores.mjs). `budget` is the disk
 * budget of the series Db's connection (lib/series/disk-budget.mjs over that Db's pages), which
 * caps history.sqlite below the free space; see createSeriesStoreV1.
 */
export function createRepositories({ stores, budget } = {}) {
  const units = createUnitRunner(stores);
  const events = createEvents({ db: stores.state, units });
  const alerts = createAlerts({ db: stores.state, events, units });
  const series = openSeriesStore({
    engine: stores.engine,
    db: stores.series,
    units,
    budget,
    // Recycling on a full disk drops events older than the history left, in the same
    // transaction; only possible while series and state share a database.
    recycled:
      stores.series === stores.state
        ? (tx, oldest) => events.tx.deleteBefore(tx, oldest)
        : undefined,
  });
  const status = createStatus({ series });
  return Object.freeze({
    stores,
    units,
    series,
    state: Object.freeze({ alerts, events, status }),
    /**
     * Store.forget(): a removed source's readings, latest row, notes, events and alert state.
     * Series first, then state: each part is idempotent, so a retry after a crash finishes it.
     * Like Store.forget(), a database closed meanwhile (shutdown) ends it quietly; the rest is
     * left for the next run.
     */
    async eraseTarget(service, options) {
      await series.eraseTarget(service, options);
      await events.eraseTarget(service, options);
      if (options?.signal?.aborted) return;
      try {
        await alerts.clear(service);
      } catch (error) {
        if (error.class !== 'unavailable') throw error;
      }
    },
    /**
     * Store.prune(): events and readings older than the retention. Events first, so the WAL
     * checkpoint and budget refresh that end the series retention follow every delete, as they
     * end Store.prune().
     */
    async applyRetention(profile) {
      const removed = await events.applyRetention(profile),
        readings = await series.applyRetention(profile);
      return { readings, events: removed };
    },
    /** Store.stats(): {samples, events, activeAlerts}. */
    async stats() {
      const [{ samples }, count, activeAlerts] = await Promise.all([
        series.stats(),
        events.count(),
        alerts.countFiring(),
      ]);
      return { samples, events: count, activeAlerts };
    },
  });
}
