// The route table. Every route declares who may reach it (`auth`), what it needs
// (`permission`) and how its request is handled (CSRF, body limit, Idempotency-Key, If-Match,
// audit); the router answers 404 and 405 (with Allow) from the table itself. A table that
// leaves any of that out stops Uptime Goblin from starting (roadmap §2.4).
import { bodyLimit as defaultBodyLimit, emptyBodyLimit } from './body.mjs';
import { ACTIONS, AUDIT_KINDS } from '../audit/actions.mjs';
import { LOCK_NAMES, ADMIN_ACTIONS, adminRoute, adminPreviewRoute } from '../admin/actions.mjs';

export const methods = Object.freeze(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE']);
const safeMethods = new Set(['GET', 'HEAD']);

/**
 * How a route is reached. `public` needs no credential; `session` needs a signed-in person
 * (in 1.4.x the admin's Basic credential, or loopback use without a password). The others are
 * reserved for later releases (tokens, agents, kiosks) and are refused until the pipeline
 * serving the table supports them.
 */
export const authKinds = Object.freeze(['public', 'session', 'any', 'token', 'agent', 'kiosk']);

/**
 * Every permission a route may require (roadmap §2.5). Anything not listed is refused.
 * `session:self` is who this session is and signing it out (B6 design §2): a wall display holds
 * it with `dashboard:read`, and nothing else; `account:self` (the password, the sessions list)
 * stays the admin's.
 */
export const permissions = Object.freeze([
  'dashboard:read',
  'session:self',
  'reports:read',
  'dashboards:own',
  'account:self',
  'tokens:own',
  'config:read',
  'config:export',
  'history:export',
  'notifications:read',
  'sources:operate',
  'sources:write',
  'sources:test',
  'alerts:ack',
  'alerts:silence',
  'maintenance:write',
  'notifications:operate',
  'reports:write',
  'dashboards:shared',
  'kiosk:manage',
  'statuspage:notes',
  'settings:write',
  'channels:write',
  'statuspage:admin',
  'users:read',
  'users:write',
  'tokens:manage',
  'identity:write',
  'system:read',
  'audit:read',
  'agents:manage',
  'cluster:manage',
  'backup:manage',
  'restore',
  'config:import',
  'config:export-secrets',
  'backup:read',
  'metrics:read',
  'agent:ingest',
]);
const knownPermissions = new Set(permissions);

/** A route table that cannot be served. Uptime Goblin refuses to start (exit 78) rather than guess. */
export class RouteError extends Error {
  constructor(message) {
    super(`Route table: ${message}`);
    this.name = 'RouteError';
    this.refusal = true;
  }
}

const recordKeys = new Set([
  'method',
  'path',
  'auth',
  'permission',
  'summary',
  'handler',
  'head',
  'csrf',
  'body',
  'bodyLimit',
  'contentType',
  'idempotent',
  'ifMatch',
  'audit',
  'refusals',
  'stepUp',
  'lock',
  'action',
  'bodyPermissions',
  'schema',
  'responses',
  'deprecated',
  'sunset',
  'multipleSessions',
  'endedSession',
]);
const parameterValue = /^[\w-]+$/;

/**
 * Route features that change what a request must prove or send. The pipeline serving a table
 * says which of them it enforces (createRouter's `supports`); a route that asks for one it
 * does not enforce stops the start, so a declared protection is never silently skipped.
 */
export const enforcedFeatures = Object.freeze(['stepUp', 'lock', 'schema', 'bodyPermissions']);

/**
 * A route's `deprecated` or `sunset` date: an ISO 8601 date (`2027-01-31`) or date and time
 * with a zone (`2027-01-31T00:00:00Z`). Returns the time in milliseconds, or NaN.
 */
export function routeDate(value) {
  const parts =
    typeof value === 'string' &&
    /^(\d{4})-(\d{2})-(\d{2})(?:T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,3})?)?(?:Z|[+-]\d{2}:\d{2}))?$/.exec(
      value
    );
  if (!parts) return NaN;
  // Date.parse would roll an impossible day (2027-02-30) over into the next month.
  const [year, month, day] = parts.slice(1, 4).map(Number),
    calendar = new Date(Date.UTC(year, month - 1, day));
  if (calendar.getUTCMonth() !== month - 1 || calendar.getUTCDate() !== day) return NaN;
  return Date.parse(value);
}

/**
 * Compiles a path pattern. Segments are literal text, `:name` (one segment of letters, digits,
 * `_` or `-`) or a final `*`, which matches the rest of the path (possibly empty, but the slash
 * before it must be there: `/api/*` matches `/api/` and `/api/x/y`, not `/api`).
 */
export function compilePath(pattern) {
  if (typeof pattern !== 'string' || !pattern.startsWith('/'))
    throw new RouteError(`path ${JSON.stringify(pattern)} must start with /`);
  const parts = pattern.split('/').slice(1),
    names = new Set();
  const segments = parts.map((part, index) => {
    if (part === '*') {
      if (index !== parts.length - 1) throw new RouteError(`${pattern}: * must come last`);
      return { kind: 'rest' };
    }
    if (part.startsWith(':')) {
      const name = part.slice(1);
      if (!/^[A-Za-z_]\w*$/.test(name) || names.has(name))
        throw new RouteError(`${pattern}: invalid or repeated parameter ${JSON.stringify(part)}`);
      names.add(name);
      return { kind: 'param', name };
    }
    if (!/^[A-Za-z0-9._~-]*$/.test(part))
      throw new RouteError(`${pattern}: invalid segment ${JSON.stringify(part)}`);
    return { kind: 'literal', value: part };
  });
  // Two patterns with the same shape would match the same paths: a table must not have both.
  const shape =
    '/' +
    segments.map(s => (s.kind === 'literal' ? s.value : s.kind === 'param' ? ':' : '*')).join('/');
  return { pattern, segments, shape };
}

// Literal segments beat parameters, which beat the rest wildcard, compared left to right.
function test(compiled, parts) {
  const params = {},
    score = [];
  for (const [index, segment] of compiled.segments.entries()) {
    if (segment.kind === 'rest') {
      if (index >= parts.length) return null;
      params['*'] = parts.slice(index).join('/');
      score.push(1);
      return { params, score };
    }
    if (index >= parts.length) return null;
    const part = parts[index];
    if (segment.kind === 'literal') {
      if (part !== segment.value) return null;
      score.push(3);
    } else {
      if (!parameterValue.test(part)) return null;
      params[segment.name] = part;
      score.push(2);
    }
  }
  return parts.length === compiled.segments.length ? { params, score } : null;
}
function better(a, b) {
  for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] > b[i];
  return a.length > b.length;
}

/**
 * Checks one route record and fills in its defaults. Throws RouteError when it is incomplete,
 * or when it needs an auth kind (`auth`) or a feature (`supports`, see enforcedFeatures) that
 * the serving pipeline does not provide.
 */
export function defineRoute(record, { auth: supported = authKinds, supports = [] } = {}) {
  if (!record || typeof record !== 'object') throw new RouteError('every route must be an object');
  const where = `${record.method ?? '?'} ${record.path ?? '?'}`;
  for (const key of Object.keys(record))
    if (!recordKeys.has(key)) throw new RouteError(`${where}: unknown field ${key}`);
  if (!methods.includes(record.method)) throw new RouteError(`${where}: unknown method`);
  const compiled = compilePath(record.path);
  if (!Object.hasOwn(record, 'auth') || !authKinds.includes(record.auth))
    throw new RouteError(`${where}: auth must be one of ${authKinds.join(', ')}`);
  if (!supported.includes(record.auth))
    throw new RouteError(`${where}: auth ${record.auth} is not supported by this release`);
  if (!Object.hasOwn(record, 'permission'))
    throw new RouteError(`${where}: every route must declare its permission`);
  if (
    record.auth === 'public'
      ? record.permission !== null
      : !knownPermissions.has(record.permission) &&
        !ADMIN_ACTIONS.some(
          row => row.name === record.action && row.permission === record.permission
        )
  )
    throw new RouteError(
      record.auth === 'public'
        ? `${where}: a public route needs permission null`
        : `${where}: unknown permission ${JSON.stringify(record.permission)}`
    );
  if (typeof record.summary !== 'string' || !record.summary.trim())
    throw new RouteError(`${where}: every route needs a summary`);
  if (typeof record.handler !== 'function')
    throw new RouteError(`${where}: handler must be a function`);
  // Each runs instead of a refusal for a sign-out: of two or more session cookies (§19 G1), or
  // of a session cookie that no longer signs in (§20 H1). So only a signed-in write held to the
  // CSRF rule may have one.
  for (const hook of ['multipleSessions', 'endedSession'])
    if (
      record[hook] !== undefined &&
      (typeof record[hook] !== 'function' ||
        record.auth !== 'session' ||
        safeMethods.has(record.method) ||
        record.csrf === false)
    )
      throw new RouteError(
        `${where}: ${hook} must be a function, on a session write that keeps CSRF`
      );
  const unsafe = !safeMethods.has(record.method);
  // What a request may carry (`body`): a read takes none; a write a JSON body its handler reads
  // with body() (`json`), or nothing beyond `{}` (`empty`, checked by the pipeline before the
  // handler runs). `bodyLimit` follows: a body announced larger than it is refused 413, unread,
  // a public route's as soon as the route is matched and any other's once the credential signed
  // in (before that, every request is held to the default limit), so a read's is 0.
  const body = record.body ?? (unsafe ? 'json' : 'none');
  if (!(unsafe ? ['json', 'empty'] : ['none']).includes(body))
    throw new RouteError(`${where}: body must be ${unsafe ? 'json or empty' : 'none'}`);
  const route = {
    head: false,
    csrf: unsafe,
    body,
    bodyLimit: body === 'none' ? 0 : body === 'empty' ? emptyBodyLimit : defaultBodyLimit,
    contentType: unsafe ? 'json' : 'none',
    // A stored reply is scoped to the credential that made the request, so only signed-in
    // writes can be replayed.
    idempotent: unsafe && record.auth !== 'public',
    ifMatch: 'none',
    audit: 'none',
    stepUp: false,
    lock: null,
    ...record,
  };
  if (route.head !== false && (route.head !== true || route.method !== 'GET'))
    throw new RouteError(`${where}: head is only for GET routes`);
  for (const flag of ['csrf', 'idempotent', 'stepUp'])
    if (typeof route[flag] !== 'boolean')
      throw new RouteError(`${where}: ${flag} must be true or false`);
  if (!Number.isSafeInteger(route.bodyLimit) || route.bodyLimit < 0)
    throw new RouteError(`${where}: bodyLimit must be a byte count`);
  if (route.body === 'none' && route.bodyLimit !== 0)
    throw new RouteError(`${where}: a read takes no body (bodyLimit 0)`);
  // Until a credential signs in, the pipeline holds every request that is not to a public route
  // to the default limit, so a larger limit there would answer 413 before the credential is
  // checked: such a route could never be reached with the body it declares.
  if (route.auth !== 'public' && route.bodyLimit > defaultBodyLimit)
    throw new RouteError(
      `${where}: bodyLimit ${route.bodyLimit} is over ${defaultBodyLimit}, the limit every request that is not to a public route is held to before it signs in`
    );
  if (!['json', 'none'].includes(route.contentType))
    throw new RouteError(`${where}: contentType must be json or none`);
  if (!['none', 'optional', 'required'].includes(route.ifMatch))
    throw new RouteError(`${where}: ifMatch must be none, optional or required`);
  // A closed list (audit spec D18): the pipeline records per kind, so a misspelt kind would be a
  // route that silently records nothing.
  if (!AUDIT_KINDS.includes(route.audit))
    throw new RouteError(`${where}: audit must be one of ${AUDIT_KINDS.join(', ')}`);
  // The aggregated row a sign-in route's refusals are counted into (audit spec §5.2): only an
  // identity route, and only an action the catalogue aggregates, so a refusal never becomes a
  // row of its own.
  if (
    route.refusals !== undefined &&
    (route.audit !== 'identity' ||
      !Object.hasOwn(ACTIONS, route.refusals) ||
      !ACTIONS[route.refusals].modes.includes('A'))
  )
    throw new RouteError(`${where}: refusals must name an aggregated action of an identity route`);
  if (route.idempotent && route.auth === 'public')
    throw new RouteError(`${where}: a public route cannot be replayed (idempotent)`);
  if (
    route.lock !== null &&
    (!LOCK_NAMES.includes(route.lock) || !unsafe || route.auth === 'public')
  )
    throw new RouteError(`${where}: lock must name a recognized lock on an authenticated mutation`);
  // Closed registry binding: an action is not a label that can be transplanted to a
  // different path, permission or guard. The only derived route is the documented audit
  // accept GET preview; it cannot inherit mutation metadata from the canonical POST row.
  if (route.action !== undefined) {
    const entry = ADMIN_ACTIONS.find(row => row.name === route.action);
    if (!entry) throw new RouteError(`${where}: unknown admin action`);
    const preview = route.action === 'audit-accept' && route.method === 'GET';
    const expected = preview ? adminPreviewRoute(route.action) : adminRoute(route.action);
    if (
      route.path !== entry.route.path ||
      route.method !== (preview ? 'GET' : entry.route.method) ||
      route.auth !== 'session' ||
      ['permission', 'stepUp', 'lock', 'audit'].some(key => route[key] !== expected[key])
    )
      throw new RouteError(`${where}: admin action does not match its registry route`);
    if (unsafe && (!route.csrf || route.contentType !== 'json' || route.idempotent))
      throw new RouteError(`${where}: admin mutations require CSRF and JSON without replay`);
    if (route.multipleSessions !== undefined || route.endedSession !== undefined)
      throw new RouteError(`${where}: admin actions cannot use sign-out hooks`);
  } else if (
    route.path === '/api/admin' ||
    route.path.startsWith('/api/admin/') ||
    route.path === '/api/audit/accept'
  ) {
    throw new RouteError(`${where}: admin route requires a registry action`);
  }
  // Declared but not enforced would look like a protection that is not there.
  const asked = {
    stepUp: route.stepUp === true,
    lock: route.lock !== null,
    schema: route.schema !== undefined,
    bodyPermissions: route.bodyPermissions !== undefined,
  };
  for (const feature of enforcedFeatures)
    if (asked[feature] && !supports.includes(feature))
      throw new RouteError(`${where}: ${feature} is not enforced by this release`);
  // A password-bearing request must never enter replay storage or bypass the strict
  // authenticated JSON-write path, even in a fixture that explicitly enables stepUp.
  if (
    route.stepUp &&
    (!unsafe ||
      route.auth !== 'session' ||
      route.idempotent ||
      !route.csrf ||
      route.contentType !== 'json' ||
      route.body !== 'json')
  )
    throw new RouteError(
      `${where}: stepUp requires a non-replayable authenticated JSON mutation with CSRF`
    );
  if (
    route.responses !== undefined &&
    (route.responses === null || typeof route.responses !== 'object')
  )
    throw new RouteError(`${where}: responses must be an object`);
  let deprecatedAt = null,
    sunsetAt = null;
  if (route.deprecated !== undefined) {
    deprecatedAt = routeDate(route.deprecated);
    if (Number.isNaN(deprecatedAt))
      throw new RouteError(`${where}: deprecated must be an ISO 8601 date`);
  }
  if (route.sunset !== undefined) {
    sunsetAt = routeDate(route.sunset);
    if (Number.isNaN(sunsetAt)) throw new RouteError(`${where}: sunset must be an ISO 8601 date`);
    if (deprecatedAt === null)
      throw new RouteError(`${where}: a route with a sunset must also be deprecated`);
    if (sunsetAt < deprecatedAt)
      throw new RouteError(`${where}: sunset must not come before deprecated`);
  }
  // Answers of a deprecated route say so (RFC 9745 Deprecation, RFC 8594 Sunset).
  const headers = {};
  if (deprecatedAt !== null) headers.Deprecation = `@${Math.floor(deprecatedAt / 1000)}`;
  if (sunsetAt !== null) headers.Sunset = new Date(sunsetAt).toUTCString();
  return Object.freeze({ ...route, compiled, headers: Object.freeze(headers) });
}

/**
 * Builds the router for a table. `reserved` lists path patterns that answer 404 unless a more
 * specific route matches (for example `/api/*`, so an unknown API path is never a static file).
 * `auth` lists the auth kinds the serving pipeline supports, and `supports` the features of
 * enforcedFeatures it enforces; a route needing anything else refuses the start.
 *
 * match(method, pathname) returns
 *   { route, params }    the route to run (HEAD runs a GET route declared with head: true);
 *   { allow, routes }    the path exists but not for this method: answer 405 with Allow;
 *   null                 no route: answer 404.
 */
export function createRouter(records, { reserved = [], auth = authKinds, supports = [] } = {}) {
  if (!Array.isArray(records)) throw new RouteError('routes must be a list');
  const routes = records.map(record => defineRoute(record, { auth, supports }));
  // One entry per path shape, in the order first declared; methods keep declaration order.
  const patterns = new Map();
  for (const route of routes) {
    const { shape, pattern } = route.compiled;
    let entry = patterns.get(shape);
    if (!entry) patterns.set(shape, (entry = { compiled: route.compiled, routes: [] }));
    else if (entry.compiled.pattern !== pattern)
      throw new RouteError(`${pattern} and ${entry.compiled.pattern} match the same paths`);
    if (entry.routes.some(other => other.method === route.method))
      throw new RouteError(`${route.method} ${pattern} is declared twice`);
    if (route.method === 'HEAD' && entry.routes.some(other => other.method === 'GET' && other.head))
      throw new RouteError(`HEAD ${pattern} is declared twice`);
    if (route.head && entry.routes.some(other => other.method === 'HEAD'))
      throw new RouteError(`HEAD ${pattern} is declared twice`);
    entry.routes.push(route);
  }
  for (const pattern of reserved) {
    const compiled = compilePath(pattern);
    if (!patterns.has(compiled.shape)) patterns.set(compiled.shape, { compiled, routes: [] });
  }
  const entries = [...patterns.values()].map(entry => ({
    ...entry,
    allow: entry.routes
      .flatMap(route => (route.head ? [route.method, 'HEAD'] : [route.method]))
      .join(', '),
  }));
  function match(method, pathname) {
    const parts = String(pathname).split('/').slice(1);
    let best = null;
    for (const entry of entries) {
      const found = test(entry.compiled, parts);
      if (found && (!best || better(found.score, best.found.score))) best = { entry, found };
    }
    if (!best || !best.entry.routes.length) return null;
    const { entry, found } = best;
    const route =
      entry.routes.find(r => r.method === method) ??
      (method === 'HEAD' ? entry.routes.find(r => r.method === 'GET' && r.head) : undefined);
    if (route) return { route, params: found.params };
    return { allow: entry.allow, routes: entry.routes };
  }
  return { routes: Object.freeze(routes), match };
}
