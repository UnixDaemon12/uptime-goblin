// The names Uptime Goblin had before 1.5, when it was called Orbit, and the one place that still
// accepts them, so that installs, scripts, browsers and webhook receivers made for those names
// keep working after the rename (docs/installation.md, "Renamed from Orbit"). Every old name is
// accepted in 1.5 and 1.6 and is removed in 1.7; each use of one says so where it can.
//
// - Environment: each GOBLIN_X falls back to ORBIT_X while GOBLIN_X is unset. Both set to
//   different values refuses the start (exit status 78), naming both, never the values; the same
//   value twice is accepted. A start that relied on an old name says once which names to change.
//   Under Docker Compose, which resolves compose.yaml's fallback before the container starts,
//   compose.yaml also passes each ORBIT_X of .env as GOBLIN_COMPOSE_LEGACY_X (compose-unset when
//   .env does not set it), compared here with what the container got, so the refusal and the
//   notice hold there too.
// - Request headers: X-Goblin-<name>, else X-Orbit-<name> (a present new header decides alone, so
//   an old one beside it can never loosen a check). Answers carry both names, so a script or a
//   1.4.x browser tab that reads the old one keeps working; outgoing webhooks carry both too.
// - The session cookie: goblin_session (__Host-goblin_session on HTTPS). orbit_session is read
//   only while the new cookie is absent, and replaced by the new one on the same answer.
// - The data-directory lock: goblin.lock, and orbit.lock taken with it, so an Orbit release that
//   knows only the old name can never run on the same data directory at the same time.
// - The admin command: lib/cli/orbit-admin.mjs runs lib/cli/goblin-admin.mjs.
// - The container's data volume: mounted at /var/lib/uptime-goblin; one still mounted only at
//   /app/data, where Orbit's image kept it, is used there, with a notice at every start.
// The key file names Docker Compose and systemd hand over (orbit_secret_key, orbit-secret-key) are
// unchanged in this step: compose.secret.yaml's recipes and the systemd unit name them.

import fs from 'node:fs';
import { inContainer } from './container.mjs';

/** The prefix of the environment variables Uptime Goblin reads. */
export const ENV_PREFIX = 'GOBLIN_';
/** The prefix they had before 1.5 (Orbit). */
export const LEGACY_ENV_PREFIX = 'ORBIT_';
/** The release that stops reading the old names. */
export const LEGACY_REMOVAL = '1.7';

const refusal = message => Object.assign(new Error(message), { refusal: true });

/** The GOBLIN_ name of an ORBIT_ one (`ORBIT_DATA_DIR` → `GOBLIN_DATA_DIR`), else null. */
export function currentVariableName(name) {
  return typeof name === 'string' && name.startsWith(LEGACY_ENV_PREFIX)
    ? ENV_PREFIX + name.slice(LEGACY_ENV_PREFIX.length)
    : null;
}

// A name as a refusal or a notice may show it: an ORBIT_ name of capitals, digits and
// underscores as it is, anything else (a name with a line break, say) escaped and cut.
const shownName = name =>
  /^[A-Z0-9_]{1,64}$/.test(name) ? name : JSON.stringify(name.slice(0, 64));

/**
 * The prefix under which compose.yaml passes each ORBIT_X that .env sets (GOBLIN_COMPOSE_LEGACY_X),
 * so that a conflict and the use of an old name can be told inside the container: Compose has
 * already resolved GOBLIN_X from GOBLIN_X, else ORBIT_X, by then. Its value is COMPOSE_UNSET when
 * .env does not set ORBIT_X. Only compared, never read as a setting, and removed at once.
 */
export const COMPOSE_LEGACY_PREFIX = 'GOBLIN_COMPOSE_LEGACY_';
/** What compose.yaml passes as GOBLIN_COMPOSE_LEGACY_X when .env does not set ORBIT_X. */
export const COMPOSE_UNSET = 'compose-unset';
// Settings that compose.yaml itself uses, not the container: what the container gets in their
// place, to compare the old name with (GOBLIN_BIND_ADDRESS publishes the port, and reaches the
// container as GOBLIN_PUBLISHED_ADDRESS).
const composeOnly = new Map([['ORBIT_BIND_ADDRESS', 'GOBLIN_PUBLISHED_ADDRESS']]);
// Settings whose empty value compose.yaml reads as unset (`:-`, so that an empty one never
// publishes the port on every address or empties the allowed host names): an empty ORBIT_ line
// of these is not compared.
const composeEmptyIsUnset = new Set(['ORBIT_BIND_ADDRESS', 'ORBIT_ALLOWED_HOSTS']);

// The ORBIT_ names compose.yaml passed as GOBLIN_COMPOSE_LEGACY_X, with their values, where .env
// sets them and the environment does not hold that ORBIT_ name itself (which then decides).
function composeLegacy(env) {
  const found = new Map();
  for (const name of Object.keys(env)) {
    if (!name.startsWith(COMPOSE_LEGACY_PREFIX) || env[name] === COMPOSE_UNSET) continue;
    const legacy = LEGACY_ENV_PREFIX + name.slice(COMPOSE_LEGACY_PREFIX.length);
    if (env[name] === '' && composeEmptyIsUnset.has(legacy)) continue;
    if (!Object.hasOwn(env, legacy)) found.set(legacy, env[name]);
  }
  return found;
}

/**
 * Moves every ORBIT_X of `env` to GOBLIN_X while GOBLIN_X is unset, and deletes ORBIT_X in every
 * case, so nothing later reads it twice and a secret (ORBIT_PASSWORD, ORBIT_SECRET_KEY) leaves
 * the environment with its new name when that is deleted. `env` is changed in place (server.mjs
 * and goblin-admin pass process.env before anything reads it). Returns {renamed, duplicates}: the
 * old names whose value was taken, and those that repeated their GOBLIN_ name's value (dropped).
 * Throws a refusal (exit status 78) when an ORBIT_X and its GOBLIN_X are both set and differ (an
 * empty value counts as set, as every reader takes empty for "the default"): which one was meant
 * cannot be known, and the values are never shown. `env` is unchanged then.
 *
 * Under Docker Compose the ORBIT_ names reach the container as GOBLIN_COMPOSE_LEGACY_X
 * (composeLegacy above): each is compared with the GOBLIN_X that Compose passed (for
 * ORBIT_BIND_ADDRESS, with GOBLIN_PUBLISHED_ADDRESS), refused where they differ and otherwise
 * counted as renamed, and every GOBLIN_COMPOSE_LEGACY_X is removed.
 */
export function adoptLegacyEnvironment(env) {
  const composed = composeLegacy(env);
  const names = Object.keys(env).filter(name => name.startsWith(LEGACY_ENV_PREFIX));
  const value = name => (Object.hasOwn(env, name) ? env[name] : composed.get(name));
  const compared = name => composeOnly.get(name) ?? currentVariableName(name);
  const conflicts = [...names, ...composed.keys()].filter(name => {
    const current = composed.has(name) ? compared(name) : currentVariableName(name);
    return Object.hasOwn(env, current) && env[current] !== value(name);
  });
  if (conflicts.length)
    throw refusal(
      `${conflicts.map(name => `${shownName(currentVariableName(name))} and ${shownName(name)}`).join(', ')} ${conflicts.length === 1 ? 'are both' : 'are each'} set, to different values, so which was meant cannot be told. ${shownName(LEGACY_ENV_PREFIX)} is the prefix from before the rename to Uptime Goblin: keep the ${ENV_PREFIX} name${conflicts.length === 1 ? '' : 's'} and remove the ${LEGACY_ENV_PREFIX} one${conflicts.length === 1 ? '' : 's'} (natively in /etc/uptime-goblin.env, under Docker Compose in .env).`
    );
  const renamed = [],
    duplicates = [];
  for (const name of names) {
    const current = currentVariableName(name);
    if (Object.hasOwn(env, current)) duplicates.push(name);
    else {
      env[current] = env[name];
      renamed.push(name);
    }
    delete env[name];
  }
  // Under Compose the GOBLIN_ name always arrives (compose.yaml resolved it from either name), so
  // an old name .env sets is one to rename, whether or not .env holds its new name too.
  for (const [name, legacyValue] of composed) {
    const current = currentVariableName(name);
    if (!composeOnly.has(name) && !Object.hasOwn(env, current)) env[current] = legacyValue;
    renamed.push(name);
  }
  for (const name of Object.keys(env)) if (name.startsWith(COMPOSE_LEGACY_PREFIX)) delete env[name];
  return { renamed, duplicates };
}

/**
 * The one start notice for what adoptLegacyEnvironment() returned, or null when no old name was
 * set. It lists the names to change (at most 12, then how many more), never a value.
 */
export function legacyEnvironmentNotice({ renamed = [], duplicates = [] } = {}) {
  const all = [...renamed, ...duplicates];
  if (!all.length) return null;
  const listed = all
    .slice(0, 12)
    .map(name => `${shownName(name)} → ${shownName(currentVariableName(name))}`)
    .join(', ');
  const more = all.length > 12 ? ` and ${all.length - 12} more` : '';
  return `Deprecated settings: ${listed}${more}. ${LEGACY_ENV_PREFIX} is the prefix from before the rename to Uptime Goblin; it is still read in this release and no longer from ${LEGACY_REMOVAL}. Rename ${all.length === 1 ? 'it' : 'them'} (natively in /etc/uptime-goblin.env, under Docker Compose in .env)${duplicates.length ? '; where both names are set to the same value, remove the old one' : ''}.`;
}

/**
 * A copy of `env` with the old names adopted as adoptLegacyEnvironment() adopts them, for a
 * caller that checks settings it read from a file (the installer's preflight) without changing
 * the process's environment. Throws the same refusal.
 */
export function withCurrentNames(env) {
  const copy = { ...env };
  adoptLegacyEnvironment(copy);
  return copy;
}

/** The header name prefixes, as Node gives request headers (lower case) and as answers send them. */
export const HEADER_PREFIX = 'X-Goblin-';
export const LEGACY_HEADER_PREFIX = 'X-Orbit-';

/**
 * A request header `name` (`Request`, `Activity`, `Client`) of `headers` (req.headers): the
 * X-Goblin- one when it is present, else the X-Orbit- one, else undefined. A present new header
 * decides alone, so an old one beside it cannot make a refused value pass.
 */
export function requestHeader(headers, name) {
  const lower = name.toLowerCase();
  const current = headers?.[`x-goblin-${lower}`];
  return current !== undefined ? current : headers?.[`x-orbit-${lower}`];
}

/** Both names of answer header `name` (`Build`): [X-Goblin-Build, X-Orbit-Build]. */
export const headerNames = name => [HEADER_PREFIX + name, LEGACY_HEADER_PREFIX + name];

/** Sets answer header `name` under both names, so readers of the old one keep working. */
export function setHeaderPair(res, name, value) {
  for (const header of headerNames(name)) res.setHeader(header, value);
}

/** Removes answer header `name` under both names. */
export function removeHeaderPair(res, name) {
  for (const header of headerNames(name)) res.removeHeader(header);
}

/** `name` and `value` as header entries under both names, for an object of headers. */
export const headerPairEntries = (name, value) =>
  Object.fromEntries(headerNames(name).map(header => [header, value]));

/** The session cookie's name before 1.5 on a transport: read while the new one is absent. */
export function legacySessionCookieName(kind) {
  return kind === 'https' ? '__Host-orbit_session' : 'orbit_session';
}

/** The data-directory lock file's name before 1.5, taken beside the new one. */
export const LEGACY_LOCK_FILE = 'orbit.lock';

/** The admin command's file before 1.5: a shim that runs goblin-admin.mjs. */
export const LEGACY_ADMIN_FILE = 'orbit-admin.mjs';

/**
 * The product's name for a release `version`: Orbit for one before 1.5 (1.4.3, 1.4.2-rc.1),
 * whose own messages and documents use that name, else Uptime Goblin, an unknown version
 * included.
 */
export function productName(version) {
  const match = /^(\d+)\.(\d+)\./.exec(String(version ?? ''));
  return match && (Number(match[1]) < 1 || (Number(match[1]) === 1 && Number(match[2]) < 5))
    ? 'Orbit'
    : 'Uptime Goblin';
}

/** The container image's data directory (GOBLIN_DATA_DIR in the Dockerfile). */
export const IMAGE_DATA_DIR = '/var/lib/uptime-goblin';
/** Where Orbit's image kept it before 1.5. */
export const LEGACY_IMAGE_DATA_DIR = '/app/data';

/**
 * In the container image only (in a container, `appRoot` the image's /app, and GOBLIN_DATA_DIR the
 * image's own IMAGE_DATA_DIR): a volume still mounted at /app/data, where Orbit's image kept its
 * data, while it is the only one of the two directories with anything in it. The image has no
 * /app/data, so that directory is there only when something is mounted on it (a compose.yaml or a
 * docker run -v from before 1.5). Sets env.GOBLIN_DATA_DIR to it and returns the notice to log at
 * every start; returns null where nothing changes. Throws a refusal (exit status 78) when both
 * directories hold data: which one is meant cannot be told. `container` and `files` are for tests.
 */
export function adoptLegacyDataMount(env, { appRoot, container = inContainer(), files = fs } = {}) {
  if (!container || appRoot !== '/app' || env.GOBLIN_DATA_DIR !== IMAGE_DATA_DIR) return null;
  const entries = directory => {
    try {
      return files.readdirSync(directory);
    } catch (error) {
      if (error.code === 'ENOENT' || error.code === 'ENOTDIR') return null;
      throw error;
    }
  };
  if (!entries(LEGACY_IMAGE_DATA_DIR)?.length) return null;
  if (entries(IMAGE_DATA_DIR)?.length)
    throw refusal(
      `Both ${IMAGE_DATA_DIR} and ${LEGACY_IMAGE_DATA_DIR} hold data, so which one is meant cannot be told. ${LEGACY_IMAGE_DATA_DIR} is where the image kept its data before the rename to Uptime Goblin: mount the data volume at ${IMAGE_DATA_DIR} alone (compose.yaml: - orbit-data:${IMAGE_DATA_DIR}), and nothing at ${LEGACY_IMAGE_DATA_DIR}.`
    );
  env.GOBLIN_DATA_DIR = LEGACY_IMAGE_DATA_DIR;
  return `The data volume is mounted at ${LEGACY_IMAGE_DATA_DIR}, where the image kept its data before the rename to Uptime Goblin, and is used there. Mount it at ${IMAGE_DATA_DIR} instead (compose.yaml: - orbit-data:${IMAGE_DATA_DIR}); ${LEGACY_IMAGE_DATA_DIR} is no longer read from ${LEGACY_REMOVAL}.`;
}
