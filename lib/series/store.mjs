// The SeriesStore seam (roadmap §10.4): the only way to reach series tables. Everything that
// writes or reads readings, latest values or (from 1.6) rollups goes through a SeriesStore, so
// the storage behind it can change per engine and release without touching callers:
//
//   v1  the 1.x tables (readings, latest, latest_notes): SQLite 1.5; PostgreSQL jsonb 1.7;
//       SQL Server JSON 1.8 (preview only)
//   v2  head, late samples, compressed blocks and packed rollups: server databases from 2.1;
//       never SQLite (O8)
//
// Only lib/series/* may name series tables in SQL (the import-graph rule, §10.4).
import { RepoError } from '../repo/errors.mjs';
import { createSeriesStoreV1 } from './v1.mjs';

/**
 * The interface every series store implements (all async):
 *   append(batch) -> {written, rejected}   readings of collections, or pause markers
 *   latest(ids) -> [latest]                one answer per id, in order (cached)
 *   query(q) -> chart                      q = {service, period, now, pollSeconds, timeoutSeconds, metrics}
 *   applyRetention(profile) -> rows        profile = {retentionDays, now, signal}
 *   eraseTarget(id)                        a removed source's series
 *   compact(shard, window, {verify})       v2 (2.1)
 *   materialize(tier, shard, period)       rollups (1.6) and packed rollups (2.1)
 */
export const SERIES_METHODS = Object.freeze([
  'append',
  'latest',
  'query',
  'applyRetention',
  'eraseTarget',
  'compact',
  'materialize',
]);

/** Throws unless `store` implements every SeriesStore method. Returns it. */
export function assertSeriesStore(store) {
  const missing = SERIES_METHODS.filter(name => typeof store?.[name] !== 'function');
  if (missing.length) throw new RepoError('fatal', `Not a series store: no ${missing.join(', ')}`);
  return store;
}

/**
 * Opens the series store for an engine. SQLite: v1 over history.sqlite (options as
 * createSeriesStoreV1). Server engines load their store with a dynamic import when they
 * arrive (1.7), so SQLite mode resolves none of their code.
 */
export function openSeriesStore({ engine = 'sqlite', version = 'v1', ...options } = {}) {
  if (engine !== 'sqlite')
    throw new RepoError('unavailable', `The ${engine} series store arrives in 1.7`);
  if (version !== 'v1')
    throw new RepoError(
      'unavailable',
      'SQLite keeps the v1 series store (series v2 is for server databases)'
    );
  return assertSeriesStore(createSeriesStoreV1(options));
}
