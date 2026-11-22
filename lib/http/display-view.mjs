// What a wall display reads (B6 design §8): GET /api/dashboard and GET /api/history/:id for an
// access without `config:read`. Both are built from explicit key lists, never by removing keys
// from the admin's answer, so a key added there later reaches a display only once it is listed
// here. Left out: source addresses (`url` is always ""), user names, site and node ids, collector
// settings, metric paths, the email server, collector error text and every stored alert or event
// message (rebuilt from the rule instead, since a message can quote what a source sent).
// Sources hidden from the dashboard (showOnDashboard false) are left out entirely, and their
// history answers as an unknown source's.
import { noteMessages } from '../collectors.mjs';

const pick = (value, keys) => {
  const out = {};
  for (const key of keys) if (value && Object.hasOwn(value, key)) out[key] = value[key];
  return out;
};

const appearanceKeys = [
  'accent',
  'density',
  'columns',
  'defaultRange',
  'sortBy',
  'showSummary',
  'showPaused',
  'showUnconfigured',
  'openInNewTab',
  'reduceMotion',
  'timezone',
  'timeFormat',
];
const sourceKeys = [
  'id',
  'type',
  'name',
  'group',
  'color',
  'icon',
  'labels',
  'enabled',
  'showOnDashboard',
  'pollSeconds',
  'apiKeyConfigured',
  'passwordConfigured',
];
const stateKeys = [
  'id',
  'status',
  'lastAttempt',
  'lastSuccess',
  'collecting',
  'configured',
  'collector',
];
const catalogKeys = ['type', 'name', 'group', 'color', 'icon', 'labels'];
const diskKeys = ['full', 'since', 'freeBytes', 'reserveReleased', 'freed'];
const collectionFailed = 'Collection failed.';

/** Whether a source shows on a wall display. */
export const shownOnDisplay = source => Boolean(source) && source.showOnDashboard !== false;

// The text of a collector note, rebuilt from its code (fixed text and counts only).
function noteText(note, product) {
  const build = Object.hasOwn(noteMessages, note?.code) ? noteMessages[note.code] : undefined;
  if (typeof build !== 'function') return null;
  const omitted = Number.isSafeInteger(note.omitted) ? note.omitted : 0;
  try {
    return { code: note.code, message: build({ omitted, product }) };
  } catch {
    return null;
  }
}

/**
 * An alert's or event's message as a display reads it: from the rule the source still has (the
 * metric's label, the comparison, the threshold and the unit), never the stored text.
 */
function ruleMessage({ rule, state }, source, metrics) {
  if (rule === '__availability')
    return state === 'resolved' ? 'Connection restored.' : 'Source is unavailable.';
  const configured = source?.rules?.find(candidate => candidate?.key === rule);
  if (!configured || !['gt', 'lt'].includes(configured.operator))
    return state === 'resolved' ? 'An alert resolved.' : 'An alert fired.';
  const metric = metrics?.find(candidate => candidate?.key === rule);
  const label = typeof metric?.label === 'string' && metric.label ? metric.label : rule;
  if (state === 'resolved') return `${label} returned within its recovery boundary`;
  const unit = typeof metric?.unit === 'string' && metric.unit ? ` ${metric.unit}` : '';
  return `${label} is ${configured.operator === 'gt' ? 'above' : 'below'} ${configured.threshold}${unit}`;
}

/** GET /api/dashboard for a wall display, from the admin's answer `full`. */
export function displayDashboard(full) {
  const config = full?.config ?? {};
  const sources = (config.services ?? []).filter(shownOnDisplay);
  const shown = new Map(sources.map(source => [source.id, source]));
  const products = new Map((full?.catalog ?? []).map(entry => [entry.type, entry.name]));
  const states = (full?.services ?? []).filter(state => shown.has(state.id));
  const metricsOf = new Map(states.map(state => [state.id, state.metrics]));
  return {
    config: {
      ...pick(config, ['title', 'subtitle', 'pollSeconds', 'retentionDays', 'revision']),
      appearance: pick(config.appearance, appearanceKeys),
      alerts: { enabled: Boolean(config.alerts?.enabled) },
      email: {
        enabled: Boolean(config.email?.enabled),
        passwordConfigured: Boolean(config.email?.passwordConfigured),
      },
      services: sources.map(source => ({
        ...pick(source, sourceKeys),
        url: '',
        rules: (Array.isArray(source.rules) ? source.rules : []).map(rule =>
          pick(rule, ['key', 'operator', 'threshold'])
        ),
      })),
    },
    catalog: (full?.catalog ?? []).map(entry => pick(entry, catalogKeys)),
    services: states.map(state => ({
      ...pick(state, stateKeys),
      error: state.error === null || state.error === undefined ? null : collectionFailed,
      metrics: (Array.isArray(state.metrics) ? state.metrics : []).map(metric =>
        pick(metric, ['key', 'label', 'value', 'unit'])
      ),
      notes: (Array.isArray(state.notes) ? state.notes : [])
        .map(note => noteText(note, products.get(shown.get(state.id)?.type) ?? 'library'))
        .filter(Boolean),
    })),
    alerts: (full?.alerts ?? [])
      .filter(alert => shown.has(alert.service))
      .map(alert => ({
        ...pick(alert, ['service', 'rule', 'name', 'since', 'updated']),
        message: ruleMessage(
          { rule: alert.rule, state: 'firing' },
          shown.get(alert.service),
          metricsOf.get(alert.service)
        ),
      })),
    events: (full?.events ?? [])
      .filter(event => shown.has(event.service))
      .map(event => ({
        ...pick(event, ['id', 'service', 'name', 'time', 'kind', 'category', 'rule']),
        message: ruleMessage(
          { rule: event.rule, state: event.kind },
          shown.get(event.service),
          metricsOf.get(event.service)
        ),
      })),
    lastCollected: full?.lastCollected ?? null,
    storage: full?.storage ? pick(full.storage, ['since', 'code']) : null,
    notifications: displayNotifications(full?.notifications),
    disk: full?.disk ? pick(full.disk, diskKeys) : null,
  };
}

// The dashboard's `notifications`, with the keys external widgets read and every reason a
// channel paused left out (a reason can quote what a mail server answered).
function displayNotifications(value) {
  if (!value || typeof value !== 'object') return value ?? null;
  const email = value.email ?? {};
  return {
    configured: Boolean(value.configured),
    lastError: value.lastError ?? null,
    webhook: pick(value.webhook, ['configured', 'lastError']),
    email: {
      ...pick(email, [
        'enabled',
        'configured',
        'state',
        'pending',
        'failedCount',
        'lastAttempt',
        'lastAccepted',
        'channelState',
        'nextAttemptAt',
        'waiting',
        'retrying',
        'failed',
      ]),
      pausedReason: null,
    },
    available: Boolean(value.available),
    updatedAt: value.updatedAt ?? null,
    saving: Boolean(value.saving),
    unsavedSince: value.unsavedSince ?? null,
    attention: pick(value.attention, ['waiting', 'retrying', 'failed', 'paused', 'refusing']),
    channels: (Array.isArray(value.channels) ? value.channels : []).map(channel => ({
      ...pick(channel, ['id', 'state', 'nextAttemptAt', 'lastAttempt']),
      pausedReason: null,
    })),
  };
}

/** GET /api/history/:id for a wall display, from the admin's answer `full`. */
export function displayHistory(full) {
  return {
    ...pick(full, ['from', 'to', 'totalSamples', 'maxGapMs', 'aggregation', 'pollSeconds']),
    points: (Array.isArray(full?.points) ? full.points : []).map(point => ({
      ...pick(point, ['time', 'ok', 'gapBefore', 'gap']),
      metrics: (Array.isArray(point.metrics) ? point.metrics : []).map(metric =>
        pick(metric, ['key', 'label', 'value', 'unit'])
      ),
      error: point.error === null || point.error === undefined ? null : collectionFailed,
    })),
  };
}
