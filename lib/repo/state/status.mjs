// Source status (class state). In SQLite mode a source's status is derived from its `latest`
// row (attempted, success, error), which the series store reads, and from the configuration;
// nothing is stored for it. sourceState() is the rule server.mjs's dashboard() applies in
// 1.4.3, word for word, so the dashboard can move onto the repositories without changing what
// a browser sees (the contract test compares it with a live createApp).
import { collectorType, configured, noCollector } from '../../catalog.mjs';

/**
 * The status of one source: disabled | link | unconfigured | error | stale | collecting | live.
 * `latest` is the series store's latest() answer; `cycleSeconds` the source's collection cycle
 * (config.mjs cycleSeconds). A source that has not succeeded within two cycles is stale.
 */
export function sourceStatus(service, latest, { now = Date.now(), cycleSeconds }) {
  return !service.enabled
    ? 'disabled'
    : noCollector(service)
      ? 'link'
      : !configured(service)
        ? 'unconfigured'
        : latest.error
          ? latest.lastSuccess
            ? 'stale'
            : 'error'
          : !latest.lastSuccess
            ? 'collecting'
            : now - latest.lastSuccess > cycleSeconds * 2000
              ? 'stale'
              : 'live';
}

/**
 * A source's entry in the dashboard's `services` list: its latest readings plus status.
 * `cycleSeconds(service)` gives its collection cycle; `collecting` is the set of source IDs
 * being collected now.
 */
export function sourceState(service, latest, { now = Date.now(), cycleSeconds, collecting }) {
  const status = sourceStatus(service, latest, {
    now,
    cycleSeconds: typeof cycleSeconds === 'function' ? cycleSeconds(service) : cycleSeconds,
  });
  return {
    ...latest,
    // Collector notes of the latest successful collection, e.g. a capped library.
    notes: Array.isArray(latest.notes) ? latest.notes : [],
    status,
    collecting: Boolean(collecting?.has(service.id)),
    configured: configured(service),
    collector: collectorType(service),
  };
}

/**
 * Status of many sources through the series store: `states(services, options)` reads every
 * latest row it needs in one call (from the latest cache when it holds them).
 */
export function createStatus({ series }) {
  return Object.freeze({
    async states(services, options) {
      const latest = await series.latest(services.map(service => service.id));
      return services.map((service, index) => sourceState(service, latest[index], options));
    },
  });
}
