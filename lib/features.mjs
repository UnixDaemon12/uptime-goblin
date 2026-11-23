// Feature flags (roadmap §2.7). There are no remote flags. Three classes, listed read-only for
// admins (/api/system.features, wired in wave 2):
//
// 1. capability  on when configured (environment). One exception: legacy Basic sign-in is on
//                by default for installs upgraded from before 1.5 (with a deprecation banner)
//                and off for data directories created by 1.5 or later (G2). From 1.6 it is off
//                on upgraded installs too unless GOBLIN_LEGACY_BASIC=1 (revised D-2); 2.0 removes
//                it.
// 2. toggle      admin switches kept in the settings document platform/features.
// 3. experimental dark-launch flags: GOBLIN_EXPERIMENTAL=<name,…>. Each ships off, is listed in
//                the CHANGELOG and is removed within two releases.
//
// Fences (lib/db/migrate.mjs) are separate from flags. Entries carry `since`; a feature newer
// than the running release is not listed (list({all: true}) shows every entry).
import { defineSetting, validators } from './settings.mjs';
import { compareReleases, coreRelease } from './db/migrate.mjs';
import {
  flagValue,
  flagWarning,
  insecureHttpSessionsSetting,
  legacyBasicSetting,
  quoted,
} from './environment.mjs';

export const featureClasses = Object.freeze(['capability', 'toggle', 'experimental']);

// GOBLIN_EXPERIMENTAL names listed in the start warnings at most; the rest are counted.
const MAX_EXPERIMENT_WARNINGS = 16;

/** Capabilities by configuration. `configured(env)` → true | false | null (not set). */
export const capabilities = Object.freeze([
  {
    name: 'legacyBasic',
    since: '1.5.0',
    until: '2.0.0',
    env: 'GOBLIN_LEGACY_BASIC',
    description:
      'HTTP Basic sign-in for scripts (deprecated). On for installs upgraded from before 1.5 until 1.6; off for new installs.',
  },
  {
    name: 'insecureHttpSessions',
    since: '1.5.0',
    env: 'GOBLIN_INSECURE_HTTP_SESSIONS',
    description:
      'Sign-in over plain HTTP on a trusted LAN, for sessions and legacy Basic (shows a banner).',
  },
  {
    name: 'forwardAuth',
    since: '1.7.0',
    env: 'GOBLIN_FORWARD_AUTH_HEADER',
    presence: true,
    description: 'Sign-in by a trusted reverse proxy (with its shared secret).',
  },
  {
    name: 'oidc',
    since: '1.7.0',
    description: 'Single sign-on with OpenID Connect providers.',
  },
  {
    name: 'postgres',
    since: '1.7.0',
    env: 'GOBLIN_DATABASE_URL',
    presence: true,
    description: 'PostgreSQL instead of SQLite (preview in 1.7 and 1.8).',
  },
  {
    name: 'agentEnrolment',
    since: '1.8.0',
    description: 'Remote collection agents.',
  },
  {
    name: 'statusListener',
    since: '1.8.1',
    env: 'GOBLIN_STATUS_LISTEN',
    presence: true,
    description: 'The public status page on its own listener.',
  },
]);

/** Admin toggles: fields of the settings document platform/features. */
export const toggles = Object.freeze([
  {
    name: 'lifecycleNotice',
    since: '1.5.0',
    description: 'Send "Uptime Goblin X started" when Uptime Goblin starts.',
  },
  {
    name: 'heartbeat',
    since: '1.5.0',
    description: 'Call the heartbeat URL while Uptime Goblin runs.',
  },
  { name: 'readingsExport', since: '1.6.0', description: 'Allow raw readings exports.' },
  {
    name: 'operatorsManageSources',
    since: '1.6.0',
    description: 'Operators may add, change and remove sources.',
  },
  {
    name: 'mfaPolicy',
    since: '1.6.0',
    values: ['off', 'admins', 'everyone'],
    description: 'Who must sign in with a second factor.',
  },
  { name: 'statusPage', since: '1.8.1', description: 'The public status page.' },
]);

/** Dark-launch experiments known to this release (none in 1.5). */
export const experiments = Object.freeze([]);

/** The settings document that holds the admin toggles. */
export const featureToggles = defineSetting({
  component: 'platform',
  key: 'features',
  schema: 1,
  description: 'Admin feature toggles (roadmap §2.7).',
  fields: Object.fromEntries(
    toggles.map(toggle => [
      toggle.name,
      toggle.values
        ? { default: toggle.values[0], validate: validators.oneOf(...toggle.values) }
        : { default: false, validate: validators.boolean },
    ])
  ),
});

/**
 * The flags of this process. meta: {get(key)} (control.sqlite's meta); settings: the settings
 * service with featureToggles defined (optional: toggles read their defaults without it).
 */
export function createFeatures({ env = process.env, meta = null, settings = null, release } = {}) {
  if (!release) throw new TypeError('createFeatures needs the running release');
  // A pre-release of x.y.z has the features of x.y.z.
  const core = coreRelease(release);
  const available = entry =>
    compareReleases(core, entry.since) >= 0 &&
    (!entry.until || compareReleases(core, entry.until) < 0);
  const warnings = [];
  const requested = String(env.GOBLIN_EXPERIMENTAL ?? '')
    .split(',')
    .map(name => name.trim())
    .filter(Boolean);
  const knownExperiments = new Set(experiments.filter(available).map(entry => entry.name));
  // A name is shown escaped and cut (it came from the environment, and could carry a terminal
  // escape or a line break that forges a log line), and only the first few of a long list.
  const unknownExperiments = [...new Set(requested.filter(name => !knownExperiments.has(name)))];
  for (const name of unknownExperiments.slice(0, MAX_EXPERIMENT_WARNINGS))
    warnings.push(
      `GOBLIN_EXPERIMENTAL names ${quoted(name)}, which this release does not have; it is ignored.`
    );
  if (unknownExperiments.length > MAX_EXPERIMENT_WARNINGS)
    warnings.push(
      `GOBLIN_EXPERIMENTAL names ${unknownExperiments.length - MAX_EXPERIMENT_WARNINGS} more experiments this release does not have; they are ignored.`
    );
  const experimental = new Set(requested.filter(name => knownExperiments.has(name)));
  for (const entry of capabilities) {
    const text = entry.env ? env[entry.env] : undefined;
    if (text === undefined || text === '') continue;
    // Set for a feature this release does not have (a later one's, or one removed): said once,
    // by name only, since a value such as GOBLIN_DATABASE_URL's can hold a password.
    if (!available(entry))
      warnings.push(
        compareReleases(core, entry.since) < 0
          ? `${entry.env} is set, but this release does not have that feature (it comes with ${entry.since}); it is ignored.`
          : `${entry.env} is set, but this release no longer has that feature (removed in ${entry.until}); it is ignored.`
      );
    else if (entry.name === 'insecureHttpSessions') {
      // Read with what decides compose.yaml's default (lib/environment.mjs): only a value that
      // is no yes or no, compose-default outside Compose included, is warned about here.
      const { warning } = insecureHttpSessionsSetting(env);
      if (warning) warnings.push(warning);
    } else if (!entry.presence && flagValue(text) === undefined) {
      // Legacy Basic is on by default for upgraded installs, so a value that is neither yes nor
      // no refuses (exit status 78) instead of leaving it on; server.mjs refuses it first, before
      // anything is written. Any other capability warns and keeps its default (off).
      if (entry.name === 'legacyBasic') legacyBasicSetting(text);
      warnings.push(flagWarning(entry.env, text));
    }
  }

  let createdBy;
  const createdByRelease = async () => {
    if (createdBy === undefined)
      createdBy = meta ? ((await meta.get('created_by_release')) ?? null) : null;
    return createdBy;
  };

  async function capability(entry) {
    const text = entry.env ? env[entry.env] : undefined;
    const set = text !== undefined && text !== '';
    // GOBLIN_INSECURE_HTTP_SESSIONS: the one rule the start uses too, compose.yaml's
    // compose-default included (source 'compose').
    if (entry.name === 'insecureHttpSessions') {
      const { enabled, source } = insecureHttpSessionsSetting(env);
      return { enabled, source };
    }
    if (set && entry.presence) return { enabled: true, source: 'env' };
    if (set && flagValue(text) === true) return { enabled: true, source: 'env' };
    if (set && flagValue(text) === false) return { enabled: false, source: 'env' };
    if (entry.name === 'legacyBasic') {
      // Upgraded installs (no created_by_release) keep Basic through 1.5.x only.
      const upgraded = (await createdByRelease()) === null;
      return { enabled: upgraded && compareReleases(core, '1.6.0') < 0, source: 'default' };
    }
    return { enabled: false, source: 'default' };
  }

  async function toggle(entry) {
    if (!settings?.has?.('platform', 'features'))
      return { enabled: entry.values ? entry.values[0] : false, source: 'default' };
    const { value, version } = await settings.get('platform', 'features');
    return { enabled: value[entry.name], source: version ? 'settings' : 'default' };
  }

  const classOf = name =>
    capabilities.some(entry => entry.name === name)
      ? 'capability'
      : toggles.some(entry => entry.name === name)
        ? 'toggle'
        : experiments.some(entry => entry.name === name)
          ? 'experimental'
          : null;

  async function state(name) {
    const kind = classOf(name);
    if (!kind) throw new TypeError(`Unknown feature ${name}`);
    const entry = [...capabilities, ...toggles, ...experiments].find(item => item.name === name);
    if (!available(entry)) return { enabled: false, source: 'unavailable' };
    if (kind === 'capability') return capability(entry);
    if (kind === 'toggle') return toggle(entry);
    return { enabled: experimental.has(name), source: experimental.has(name) ? 'env' : 'default' };
  }

  return Object.freeze({
    release,
    warnings,
    /** Whether the feature is on (a toggle with values resolves to its value). */
    async enabled(name) {
      return (await state(name)).enabled;
    },
    /** Whether a dark-launch experiment is on (synchronous: the environment only). */
    experimental: name => experimental.has(name),
    /**
     * Rows for the admin list: {name, class, enabled, source, since, description, env?}.
     * Features newer than this release are left out unless `all`.
     */
    async list({ all = false } = {}) {
      const rows = [];
      for (const [kind, entries] of [
        ['capability', capabilities],
        ['toggle', toggles],
        ['experimental', experiments],
      ])
        for (const entry of entries) {
          if (!all && !available(entry)) continue;
          const { enabled, source } = await state(entry.name);
          rows.push({
            name: entry.name,
            class: kind,
            enabled,
            source,
            since: entry.since,
            description: entry.description,
            ...(entry.env ? { env: entry.env } : {}),
          });
        }
      return rows;
    },
  });
}
