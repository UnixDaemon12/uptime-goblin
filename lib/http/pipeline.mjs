// The request pipeline (roadmap §2.4, sessions spec §6.5). Every request passes the same steps
// in the same order:
//
//   request id → stopping? → security headers → exactly one Host → Host allowlist → address
//   (origin-form only) → proxy observation → route match → announced body length (413: the
//   default limit for every request, a public route's own for a public route)
//   → transport, client, browser context, cookies (every later answer names the
//   build) → public routes (strict CSRF and JSON for writes, then the handler)
//   → no-credential proxy guard → sign-in lockout (credentials that will be checked)
//   → exactly one credential (a sign-out sent with several session cookies: its own body
//   limit, strict CSRF and JSON, then its multipleSessions handler) → authenticate (a session
//   cookie only from Uptime Goblin's own pages; a sign-out whose one session cookie does not sign in:
//   its own body limit, strict CSRF and JSON, then its endedSession handler)
//   → release headers → the matched route's own announced body limit (413) → CSRF and JSON
//   (writes) → principal kind and permission (matched routes) → Idempotency-Key (writes) → 404/405 from the table
//   → If-Match required, and a revision when sent → a body-less write's body → handler
//
// A body is read only by a handler (or the Idempotency-Key step), and only then is a client
// that waits for it sent 100 Continue. An answer given while more of a body is due than the
// route takes closes the connection instead of reading the rest (answerClosing below).
//
// This is the 1.4.3 order with sessions added; later releases insert their steps (stage gate,
// step-up, schema) at the places §2.4 names without reordering these. A route that needs a step
// this pipeline does not enforce refuses the start (see router.mjs).
//
// The audit (audit spec §4.4) is not a step of its own: every handler gets `audit`, the
// request's recorder, and every handler run ends with settle(), which writes the result row of
// each change the handler began and the row of each operation it made, after the answer.
// Exports are held to the cross-origin rule of D29 before their handler runs, and refusals of
// sign-in, of the password change and of Basic are counted into their aggregated rows (§5.2).
import { randomUUID } from 'node:crypto';
import { AdminError, adminError } from '../admin/errors.mjs';
import { withStepUpPassword } from '../admin/step-up.mjs';
import { lockdownSetting } from '../admin/actions.mjs';
import { principalRouteAllowed } from './principal-routes.mjs';
import { AuthError, credential } from '../auth.mjs';
import {
  clientAddress,
  connectionLimits,
  connectionsPerClient,
  throttleKey,
} from '../throttle.mjs';
import { InputError } from '../config.mjs';
import { identityError } from '../identity/errors.mjs';
import { DeliveryError } from '../alerting/errors.mjs';
import { AuditError } from '../audit/errors.mjs';
import { eventFrom } from '../audit/actions.mjs';
import { noopAudit } from '../audit/noop.mjs';
import { StorageFullError, isDiskFull, storageFullMessage } from '../storage-guard.mjs';
import { BusyError } from './exclusive.mjs';
import {
  bodyLimit,
  readBody,
  readSensitiveBody,
  parseJson,
  assertEmptyBody,
  json,
  recordedAnswer,
  announcedBytes,
  unboundedRemainder,
  TooLargeError,
} from './body.mjs';
import {
  expiredLegacySessionCookies,
  readCookies,
  sessionCookie as newSessionCookie,
  sessionCookieName,
} from './cookies.mjs';
import {
  browserContext,
  decideTransport,
  isLoopbackHost,
  isLoopbackPeer,
  originHost,
} from './transport.mjs';
import {
  legacySessionCookieName,
  removeHeaderPair,
  requestHeader,
  setHeaderPair,
} from '../legacy-names.mjs';

/** Sent with every answer except the one given while Uptime Goblin stops. */
export const securityHeaders = Object.freeze({
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
});
export function applySecurityHeaders(res) {
  for (const [name, value] of Object.entries(securityHeaders)) res.setHeader(name, value);
}

/** What an inbound X-Request-Id must look like to be kept (X9). */
export const requestIdPattern = /^[A-Za-z0-9._-]{1,64}$/;

/**
 * The id of this request, sent back as X-Request-Id. A trusted proxy's id is kept when it is
 * well formed, so the proxy's and Uptime Goblin's logs line up; any other id is replaced, so a client
 * cannot put arbitrary text into logs or other answers.
 */
export function requestId(req, trusted = null) {
  const inbound = req.headers['x-request-id'];
  if (
    typeof inbound === 'string' &&
    requestIdPattern.test(inbound) &&
    typeof trusted === 'function' &&
    trusted(req.socket?.remoteAddress)
  )
    return inbound;
  return randomUUID();
}

/**
 * The sign-in lockout key of the Uptime Goblin host itself: every request whose peer is a loopback
 * address (127.0.0.0/8, ::1 or an IPv4-mapped 127.x: the connection's own address, which no
 * header can change) that GOBLIN_TRUST_PROXY does not name, whatever its Host or forwarding
 * headers say. That is the loopback transport (a browser or script on this computer, such as the
 * documented `ssh -L` way in, D18), and anything a proxy on this host that Uptime Goblin does not trust
 * relays over loopback. A proxy or script on this host that connects to Uptime Goblin's own network
 * address (HOST=0.0.0.0) arrives from that address and is keyed by it, as any other peer. It is
 * not an address, so no header a trusted proxy forwards can produce it.
 *
 * One key for everything that arrives untrusted from a loopback peer: Uptime Goblin does not believe
 * what such a proxy says about its clients, so they and the host's own browsers count against one
 * lockout. A client of such a proxy cannot reach a second one by the Host it asks for (a
 * loopback Host is the loopback transport, any other `http`) or by adding a forwarding header
 * (X-Real-IP, Forwarded, X-Forwarded-*): it can lock out the ssh tunnel, but never gets twice
 * the guesses (§16 C1). What the Host still decides is the transport: through a proxy on this
 * host that sends no forwarding headers, a request that keeps a loopback Host (nginx's default
 * 127.0.0.1:<port>, or a client's own Host passed on) is the loopback transport, the only one
 * exempt from the global lock (globallyLocked()), whatever page address it carries.
 *
 * A peer that GOBLIN_TRUST_PROXY names (GOBLIN_TRUST_PROXY=loopback for a proxy on this host)
 * gets its key from its forwarding headers, as any trusted proxy does (clientAddress(): the last
 * X-Forwarded-For entry, else the proxy's own address, 127.0.0.1 for one on this host); only
 * its loopback-transport requests get this key. Uptime Goblin names a proxy on this host that sends no
 * forwarding headers in the log once it sees one (see createPipeline), and the docs say to make
 * every proxy on the host send forwarding headers and to name it in GOBLIN_TRUST_PROXY.
 */
export const loopbackClient = 'loopback';

/**
 * The sign-in lockout key of a request, which is also the address a session it signs in
 * records and the client its audit rows show: loopbackClient on the loopback transport and for
 * every other request from a loopback peer that `trusted` does not name, otherwise
 * clientAddress() (the last X-Forwarded-For entry from a trusted proxy, else the peer). Keyed on
 * the transport and the peer: a header the client chooses (Host, Origin, a forwarding header)
 * never picks the key unless a trusted proxy passed it on (one that sends no forwarding headers
 * of its own passes on whatever the client wrote, its Host included), so no client of an
 * untrusted proxy that connects from a loopback address can choose between the Uptime Goblin host's own
 * key and another one.
 */
export function requestClient(req, transport, trusted = null) {
  if (transport.kind === 'loopback') return loopbackClient;
  const peer = req.socket?.remoteAddress;
  if (isLoopbackPeer(peer) && !(typeof trusted === 'function' && trusted(peer)))
    return loopbackClient;
  return clientAddress(req, trusted);
}

/**
 * True when the global sign-in lock refuses `client` (the request's requestClient()) on
 * `transport` now: failures from everywhere exceed the budget, the request is not on the loopback
 * transport (D18: the Uptime Goblin host itself, the only exemption), and its client did not prove the
 * password recently (trusted). The `loopback` key off the loopback transport is never trusted
 * here, whatever password any request with that key proved (through the ssh tunnel or the proxy
 * itself): it is a proxy on this host that GOBLIN_TRUST_PROXY does not name, whose clients all
 * share the key. The sign-in route, a script's Basic and a password change all use it.
 */
export function globallyLocked(loginThrottle, client, transport) {
  if (transport?.kind === 'loopback' || !loginThrottle.globalLocked()) return false;
  return client === loopbackClient || !loginThrottle.trusted(client);
}

/** Every Authorization header of a request, in order (Node joins none of them). */
function authorizationHeaders(req) {
  return (
    req.headersDistinct?.authorization ??
    (req.headers.authorization === undefined ? [] : [req.headers.authorization])
  );
}
const scheme = value => /^\s*([A-Za-z][\w.+-]*)/.exec(value)?.[1]?.toLowerCase();

/**
 * The credentials a request presents, one entry each (X1: with more than one it is refused,
 * never "first match wins"):
 *
 * - every Authorization header (`basic`, `bearer` or `authorization` for another scheme),
 *   unless the request comes from a browser page (`browser`, D12): a browser that cached 1.4.x
 *   Basic credentials sends them with every request, including ones carrying the session
 *   cookie, and they are never evaluated, so they are not counted either;
 * - every value of the session cookie `cookieName` in `cookies` (from readCookies()); null
 *   when this transport reads no session (plain HTTP without the opt-in, D16);
 * - forward-auth when `forwardAuth(req)` says the trusted proxy vouched for a user (unused
 *   until forward-auth arrives).
 */
export function presentedCredentials(
  req,
  { cookieName = null, cookies = null, browser = false, forwardAuth = null } = {}
) {
  const found = [];
  if (!browser)
    for (const value of authorizationHeaders(req)) {
      const kind = scheme(value);
      found.push({ kind: kind === 'basic' || kind === 'bearer' ? kind : 'authorization', value });
    }
  if (cookieName && cookies)
    for (const value of cookies.all(cookieName)) found.push({ kind: 'session', value });
  if (forwardAuth?.(req)) found.push({ kind: 'forward' });
  return found;
}

/**
 * The 1.4.3 rule for writes made with Basic, which every export (D29) follows too, whatever its
 * credential and transport: X-Goblin-Request: 1 (or X-Orbit-Request: 1, its name before 1.5), an Origin (when sent) naming this Host, and not
 * Sec-Fetch-Site: cross-site. True when refused.
 */
export function crossOrigin(req) {
  const origin = req.headers.origin;
  let sameOrigin = false;
  if (origin) {
    try {
      sameOrigin = new URL(origin).host === req.headers.host;
    } catch {}
  }
  return (
    requestHeader(req.headers, 'Request') !== '1' ||
    Boolean(origin && !sameOrigin) ||
    req.headers['sec-fetch-site'] === 'cross-site'
  );
}

/**
 * The rule for writes made with a session cookie and for public writes (sign-in, §6.7): a
 * cookie is sent by the browser on its own, so the request must prove it comes from Uptime Goblin's
 * page. X-Goblin-Request: 1 (or X-Orbit-Request: 1) is required, an Origin is required and its host must be the Host
 * header or one of `configuredHosts` (GOBLIN_ALLOWED_HOSTS, lower case: a proxy that does not
 * forward Host still passes, D20), and Sec-Fetch-Site must be same-origin or absent.
 * Returns null when the write may continue, else why not: 'request-header', 'origin-missing',
 * 'origin-host' or 'fetch-site'.
 */
export function strictCrossOrigin(req, configuredHosts = new Set()) {
  if (requestHeader(req.headers, 'Request') !== '1') return 'request-header';
  const host = originHost(req.headers.origin);
  if (!host) return 'origin-missing';
  if (host !== String(req.headers.host ?? '').toLowerCase() && !configuredHosts.has(host))
    return 'origin-host';
  const site = req.headers['sec-fetch-site'];
  if (site !== undefined && site !== 'same-origin') return 'fetch-site';
  return null;
}

/**
 * The address of a request, or null when Uptime Goblin does not serve it. Only an origin-form target
 * (RFC 9112 §3.2.1: one '/', then the path) is read, against a fixed origin. The URL parser
 * would resolve '//host/p' and '/\host/p' (a backslash is a slash in a path) as another
 * authority and an absolute 'http://host/p' as itself, and Uptime Goblin would then serve '/p'; a
 * reverse proxy matches its locations against the target as written ('/host/p' once slashes are
 * merged), so a rule it applies to one path (a rate limit on sign-in) would not see the request
 * Uptime Goblin serves. A backslash in the query is data and stays allowed.
 */
export function requestTarget(target) {
  if (
    typeof target !== 'string' ||
    !target.startsWith('/') ||
    target.startsWith('//') ||
    target.split('?')[0].includes('\\')
  )
    return null;
  try {
    const url = new URL(target, 'http://localhost');
    return url.origin === 'http://localhost' ? url : null;
  } catch {
    return null;
  }
}

/**
 * How many Host header lines a request has. Node keeps only the first in req.headers, and a
 * front end that honours another one could reach another allowlist decision than Uptime Goblin's, so
 * anything but exactly one is refused (RFC 9112 §3.2).
 */
export function hostLines(req) {
  return req.headersDistinct?.host?.length ?? (req.headers.host === undefined ? 0 : 1);
}

/**
 * The one value of query parameter `name`, or null. Given twice it is refused (400): which one
 * was meant cannot be told, and a proxy or log may read the other one.
 */
export function queryValue(url, name) {
  const all = url.searchParams.getAll(name);
  if (all.length > 1) throw new InputError(`${name} may be given only once`);
  return all.length ? all[0] : null;
}

// The charset labels that name UTF-8 (WHATWG Encoding), with or without quotes.
const utf8Charset = /^"?utf-?8"?$/i;

/**
 * Whether a request's body is declared as JSON Uptime Goblin can read: `application/json` (media types
 * are case-insensitive and may have spaces before parameters) with no charset or UTF-8. A body
 * in another charset would be decoded as UTF-8 and saved garbled, so it is refused too.
 */
export function jsonRequest(req) {
  const [type, ...parameters] = (req.headers['content-type'] ?? '').split(';');
  if (type.trim().toLowerCase() !== 'application/json') return false;
  return parameters.every(parameter => {
    const at = parameter.indexOf('=');
    if (at < 0 || parameter.slice(0, at).trim().toLowerCase() !== 'charset') return true;
    return utf8Charset.test(parameter.slice(at + 1).trim());
  });
}

// An If-Match Uptime Goblin can compare: one configuration revision, as a number or an entity tag, weak
// or strong. Anything else, '*' and lists included, names no revision: Uptime Goblin's If-Match carries
// the revision a change was based on, and '*' would skip the check a script asked for. The weak
// prefix belongs to an entity tag only: W/12 is neither form.
const revisionTag = /^\s*(?:(?:W\/)?"(0|[1-9][0-9]{0,15})"|(0|[1-9][0-9]{0,15}))\s*$/;

/** The revision an If-Match header names, or null when it names none (see revisionTag). */
export function ifMatchRevision(header) {
  const match = typeof header === 'string' ? revisionTag.exec(header) : null;
  return match ? Number(match[1] ?? match[2]) : null;
}

/**
 * Optimistic concurrency: a write carrying If-Match with an older configuration revision
 * (another browser saved in the meantime) is refused with 409 instead of overwriting that
 * change. Returns true when it answered. The pipeline has already refused (400) an If-Match that
 * names no revision on a route that compares one.
 */
export function revisionConflict(req, res, revision) {
  const header = req.headers['if-match'];
  if (header === undefined) return false;
  if (ifMatchRevision(header) === revision) return false;
  json(res, 409, {
    error: 'Settings were changed in another browser or device. Reload to see the latest.',
    revision,
  });
  return true;
}

/**
 * A request value as it may appear in a log line: control characters removed (no forged
 * lines), at most 200 characters.
 */
export function logValue(value) {
  return String(value ?? '')
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, '')
    .slice(0, 200);
}

/** `scheme://host` of an Origin header for a log line (never a path), or ''. */
export function logOrigin(origin) {
  try {
    return logValue(new URL(origin).origin);
  } catch {
    return '';
  }
}

/**
 * Operator diagnostics (§6.13): each kind of line is written at most once an hour, so a proxy
 * that is set up wrongly is named in the journal without a line per request.
 */
export function createDiagnostics({ log = console, now = Date.now, everyMs = 3600e3 } = {}) {
  const last = new Map();
  return function diagnose(kind, line) {
    const at = now(),
      previous = last.get(kind);
    if (previous !== undefined && at - previous < everyMs) return false;
    last.set(kind, at);
    try {
      log.warn(line);
    } catch {}
    return true;
  };
}

// What fail() needs to answer an AuthError the way the request asked (§6.6): recorded by the
// pipeline for each response once its transport and browser context are known. fail() keeps
// its two-argument signature, so every caller (the pipeline, server.mjs's idempotency loop)
// answers a refusal with the same context without passing it along.
const answerContexts = new WeakMap();

// The storage guard (lib/storage-guard.mjs) of the pipeline that is answering a response, so
// fail() can report a full disk to it whoever calls fail() (delivery spec §4.4, §6.8).
const storageGuards = new WeakMap();

/** The 401 body's transport part: what the sign-in page needs to explain a refusal. */
function transportPart(context) {
  return { kind: context.transportKind, insecureAllowed: context.insecureAllowed };
}

/** The answer to a write a full disk refused (delivery spec §6.6, `storage_full`). */
export { storageFullMessage };

// Retry-After for a 429 or 503: the error's own `retryAfter` (seconds), else `fallback`.
function retryAfter(res, e, fallback) {
  const seconds = Number(e?.retryAfter);
  res.setHeader(
    'Retry-After',
    String(Number.isFinite(seconds) && seconds >= 0 ? Math.ceil(seconds) : fallback)
  );
}

/**
 * The status fail() answers `e` with: an AuthError, a DeliveryError and an AuditError their own
 * (an AuditError is 503, or 400 for audit_query_invalid); StorageFullError, BusyError and any
 * other disk-full error 503; a body over its route's limit (TooLargeError) 413; any other
 * InputError 400; anything else 500. fail() answers with it, and the audit's settle() records it
 * as a failed request's status, so the two cannot drift.
 */
export function answerStatus(e) {
  if (
    e instanceof AuthError ||
    e instanceof DeliveryError ||
    e instanceof AuditError ||
    e instanceof AdminError
  )
    return e.status;
  if (e instanceof StorageFullError || e instanceof BusyError || isDiskFull(e)) return 503;
  if (e instanceof TooLargeError) return 413;
  return e instanceof InputError ? 400 : 500;
}

/**
 * The listener's own limits: how long a client may take to send its headers and its whole
 * request (Node's defaults, 60 s and 300 s, let a slow client hold a connection for minutes),
 * how often Node looks for a request past either limit (408, then closed), how many
 * connections may be open at once, and how many of them one client may hold by default
 * (GOBLIN_MAX_CONNECTIONS_PER_CLIENT changes it, see connectionsPerClient()), so that one client
 * cannot take all of them. Node's default check interval, 30 s, would let a request run up to
 * 30 s past either limit: up to 50 s for its headers and 60 s in all.
 */
export const serverLimits = Object.freeze({
  headersTimeoutMs: 20000,
  requestTimeoutMs: 30000,
  checkIntervalMs: 1000,
  ...connectionLimits,
});

// GOBLIN_MAX_CONNECTIONS_PER_CLIENT (connectionsPerClient()) and the two connection limits are
// read by one rule in lib/throttle.mjs, a module without package dependencies (it, and the Uptime Goblin
// modules it imports, use only node: built-ins), which the native installer runs too.
export { connectionsPerClient };

/**
 * The options for http.createServer() that serverLimits needs at creation: Node takes the check
 * interval only there. applyServerLimits() sets the rest.
 */
export const serverOptions = Object.freeze({
  connectionsCheckingInterval: serverLimits.checkIntervalMs,
});

/**
 * Applies serverLimits to `server`, an http.Server answering with `handle` (a pipeline) and
 * created with serverOptions, and gives `handle` the requests that ask for 100 Continue too.
 * Without that Node sends 100 Continue on its own as soon as the headers arrive, inviting the
 * body of a request with any Host and no credential; the pipeline sends it only when a handler
 * reads the body, after every check before it. Returns `server`.
 */
export function applyServerLimits(
  server,
  handle,
  { perClient = serverLimits.maxConnectionsPerClient, trusted = null } = {}
) {
  server.headersTimeout = serverLimits.headersTimeoutMs;
  server.requestTimeout = serverLimits.requestTimeoutMs;
  server.maxConnections = serverLimits.maxConnections;
  limitConnectionsPerClient(server, { limit: perClient, trusted });
  server.on('checkContinue', handle);
  return server;
}

/**
 * Holds every client of `server` to `limit` connections open at once: one more is closed as
 * soon as it is accepted, before a byte of it is read, and without an answer. A client is its
 * peer address, an IPv6 one by its /64 (throttleKey(): one client normally controls a whole
 * /64), never anything a request says; 127.0.0.1 and ::1 are two clients here, though the
 * sign-in lockout counts both as `loopback` (requestClient()). A peer that `trusted` names
 * (GOBLIN_TRUST_PROXY) carries the connections of many clients, so it is held only to the
 * listener's own cap (server.maxConnections), which every connection counts toward. A peer
 * whose address cannot be read (the connection already went) is closed. Returns `server`.
 *
 * Many users behind one peer address (Docker's gateway, a proxy GOBLIN_TRUST_PROXY does not name,
 * this computer, one IPv6 /64) share one client's connections: a documented tradeoff whose
 * remedies are GOBLIN_TRUST_PROXY and GOBLIN_MAX_CONNECTIONS_PER_CLIENT. So that a refusal can be
 * told apart from a network fault, closing one writes a line to `log.warn`, at most one every
 * `everyMs` (a minute) for all clients together, naming the last client refused and how many
 * connections were closed since the previous line (or the start). One closed within `everyMs` of
 * a line is written by a timer once `everyMs` has passed (unref'd, so it keeps no process
 * running; cleared when the server closes), so a burst is reported even when nothing follows it.
 * `now` is a monotonic clock in milliseconds: a wall-clock step cannot hold lines back. Nothing a
 * connection sent is ever written: none of it is read.
 */
export function limitConnectionsPerClient(
  server,
  { limit, trusted = null, log = console, now = () => performance.now(), everyMs = 60e3 }
) {
  const open = new Map();
  let closed = 0,
    last = null,
    lastLine = null,
    timer = null;
  const write = () => {
    timer = null;
    if (!closed) return;
    lastLine = now();
    const count = closed;
    closed = 0;
    try {
      log.warn(
        `Uptime Goblin closed ${count === 1 ? 'a connection' : `${count} connections`} without an answer since the last such line (or the start) because the client already held ${limit} connections at once, one client's share (GOBLIN_MAX_CONNECTIONS_PER_CLIENT); the last came from ${logValue(last)}. Where many browsers or scripts reach Uptime Goblin from one address (a reverse proxy, Docker's gateway, this computer), name the proxy in GOBLIN_TRUST_PROXY or raise GOBLIN_MAX_CONNECTIONS_PER_CLIENT.`
      );
    } catch {}
  };
  const refuse = (socket, key) => {
    socket.destroy();
    closed++;
    last = key;
    const wait = lastLine === null ? 0 : lastLine + everyMs - now();
    if (wait <= 0) {
      clearTimeout(timer);
      return write();
    }
    if (timer) return;
    timer = setTimeout(write, wait);
    timer.unref?.();
  };
  server.once('close', () => {
    clearTimeout(timer);
    timer = null;
  });
  server.on('connection', socket => {
    const peer = socket.remoteAddress;
    if (typeof peer !== 'string') {
      socket.destroy();
      return;
    }
    if (typeof trusted === 'function' && trusted(peer)) return;
    const key = throttleKey(peer);
    const held = open.get(key) ?? 0;
    if (held >= limit) {
      refuse(socket, key);
      return;
    }
    open.set(key, held + 1);
    socket.once('close', () => {
      const left = (open.get(key) ?? 1) - 1;
      if (left > 0) open.set(key, left);
      else open.delete(key);
    });
  });
  return server;
}

/**
 * Tracks the connections of `server`, so that a stop can end those that never received a byte:
 * a browser opens one before it has a request to send (a preconnect). On Node 24, server.close()
 * waits for such a connection and closeIdleConnections() does not end it (it is new, not idle),
 * so Uptime Goblin's stop waited its whole 10 s for open requests; Node 26 does not wait, but leaves it
 * open. A connection that received any byte (a request in progress, or part of one) is left to
 * the stop's other steps: finished, or ended after 10 s. Returns { closeUnused }, which ends them
 * and returns how many it ended.
 */
export function trackConnections(server) {
  const open = new Set();
  server.on('connection', socket => {
    open.add(socket);
    socket.once('close', () => open.delete(socket));
  });
  return {
    closeUnused() {
      let ended = 0;
      for (const socket of open)
        if (socket.bytesRead === 0) {
          socket.destroy();
          ended++;
        }
      return ended;
    },
  };
}

/**
 * Closes the connection with every answer to `req` given while more of its body is due than
 * `limit()` bytes (see unboundedRemainder): Node would otherwise read and discard the rest,
 * up to the whole request time limit, for a client Uptime Goblin refused or answered without reading.
 * A body within the limit is still read to its end after the answer, so the connection can be
 * reused. Node writes every answer's headers through writeHead (an implicit one too), so this
 * covers JSON answers, static files and the 204s alike.
 *
 * `Connection: close` alone does not stop the reading: Node goes on discarding the body until
 * its own side of the connection has finished closing, at least one more turn of the event
 * loop, in which it reads up to 32 × 64 KiB while the client keeps sending. So once the answer
 * is with the kernel the socket is destroyed, and nothing after the answer is read. A client
 * still sending may then see the connection reset after the answer instead of closed.
 */
export function answerClosing(req, res, limit) {
  const writeHead = res.writeHead;
  res.writeHead = function writeHeadClosing(...args) {
    if (!this.headersSent && unboundedRemainder(req, limit())) {
      this.setHeader('Connection', 'close');
      const socket = req.socket;
      this.once('finish', () => socket?.destroy());
    }
    return writeHead.apply(this, args);
  };
}

/**
 * The code a failed request's audit row names (detail.code, audit spec §4.4): the Uptime Goblin error
 * code fail() answers (an AuthError's, a DeliveryError's or an AuditError's; `storage_full` for a
 * full disk; `busy` for a write that could not start), else a storage error's class; never the
 * error's text, which may come from a remote system. Null when there is none.
 */
export function answerCode(e) {
  if (
    e instanceof AuthError ||
    e instanceof DeliveryError ||
    e instanceof AuditError ||
    e instanceof AdminError
  )
    return typeof e.code === 'string' ? e.code : null;
  if (e instanceof StorageFullError || isDiskFull(e)) return 'storage_full';
  if (e instanceof BusyError) return 'busy';
  return typeof e?.class === 'string' && /^[a-z_]{1,32}$/.test(e.class) ? e.class : null;
}

/**
 * The outcome of a result or operation row from the status its request was answered with
 * (audit spec §4.4), when the handler noted none and the change was not applied: 2xx `ok`; 409
 * `conflict`, except a DeliveryError other than signing_conflict, which refuses the delivery's
 * state (`denied`, MEC-14); 401, 403 and 429 `denied`; anything else `failed`.
 */
export function settledOutcome(status, error = null) {
  if (status >= 200 && status < 300) return 'ok';
  if (status === 409)
    return error instanceof DeliveryError && error.code !== 'signing_conflict'
      ? 'denied'
      : 'conflict';
  return [401, 403, 429].includes(status) ? 'denied' : 'failed';
}

/**
 * Answers a request that failed with `e`. Only unexpected failures are logged, with the
 * request's X-Request-Id so the line can be matched to the answer (and the proxy's log).
 *
 * An AuthError is answered with `{error, code}`; a 401 also carries `transport` and, only where
 * Basic would be accepted (legacy Basic on, and on the `http` transport the plain-HTTP opt-in)
 * and only for a request that is not a browser page's (browserContext()), the Basic challenge:
 * Uptime Goblin's page never gets the native prompt. A browser sends no Sec-Fetch-Site to a plain-HTTP
 * address on the network (it does to localhost, 127.x and [::1]), so a request it makes there on
 * its own (a typed address, a link, an image) is challenged like a script's. 429 and 503 carry
 * Retry-After (the error's `retryAfter`, else 5 s).
 *
 * A full disk (delivery spec §6.8): every disk-full error (isDiskFull: ENOSPC, EDQUOT, a full
 * control database, identity's and the guard's `storage_full`) is first reported to the storage
 * guard of the pipeline serving `res`, so the guard enters "full" at once instead of at its next
 * check. Identity's own `storage_full` keeps its answer; StorageFullError and any other disk-full
 * error a handler let escape (ConfigStore.save's ENOSPC, for example) are 503 `storage_full`
 * with Retry-After: 60. A DeliveryError (lib/alerting/errors.mjs) is answered with its status,
 * `{error, code}` and, for 429 and 503, its Retry-After.
 *
 * An AuditError (audit spec §6.5) is answered `{error, code}` (plus `parameter`) with its
 * Retry-After on a 503. When its cause is a disk-full error (an attempt row the full disk
 * refused), that cause is reported to the guard as well (§4.8), so a full disk found by the
 * audit raises the disk notice and refuses configuration writes like any other.
 */
export function fail(res, e) {
  const id = res.getHeader?.('x-request-id'),
    request = id ? [`(request ${id})`] : [];
  const full = isDiskFull(e);
  const reported = full ? e : isDiskFull(e?.cause) ? e.cause : null;
  if (reported) {
    // Reported even when the answer has started: the guard needs to know either way.
    try {
      storageGuards.get(res)?.noteWriteError(reported);
    } catch {}
  }
  if (res.headersSent) {
    if (!res.writableEnded) res.destroy();
    console.error('Request failed after its answer started:', e?.code || e?.name, ...request);
    return;
  }
  const context = answerContexts.get(res);
  if (context && !context.healthRoute) setHeaderPair(res, 'Build', context.build);
  const status = answerStatus(e);
  if (e instanceof AuthError) {
    const body = { error: e.message };
    if (typeof e.code === 'string') body.code = e.code;
    if (status === 401) {
      // A refusal is not a signed-in answer, even when the request was signed in until a
      // re-check (assertCurrent) found its session ended.
      removeHeaderPair(res, 'Version');
      if (context) body.transport = transportPart(context);
      if (context ? context.challenge : true)
        res.setHeader('WWW-Authenticate', 'Basic realm="Orbit", charset="UTF-8"');
      else res.removeHeader('WWW-Authenticate');
    }
    if (status === 429 || status === 503) retryAfter(res, e, 5);
    json(res, status, body);
    return;
  }
  if (e instanceof AdminError) {
    if (e.retryAfter !== undefined) retryAfter(res, e, 5);
    json(res, status, e.body);
    return;
  }
  if (e instanceof DeliveryError) {
    if (status === 429 || status === 503) retryAfter(res, e, 5);
    json(res, status, { error: e.message, code: e.code });
    return;
  }
  if (e instanceof AuditError) {
    if (status === 503) {
      retryAfter(res, e, 30);
      // Nothing was changed, exported or shown; the operator needs to know why (the cause's
      // code or class only, never its text).
      const cause = e.cause;
      console.error(
        `Request refused: ${e.code === 'audit_read_unavailable' ? 'Uptime Goblin could not read its audit log' : 'Uptime Goblin could not write its audit log'}:`,
        cause?.code || cause?.class || cause?.name || e.code,
        ...request
      );
    }
    json(res, status, e.body);
    return;
  }
  if (e instanceof StorageFullError) {
    retryAfter(res, e, 60);
    json(res, status, { error: e.message || storageFullMessage, code: 'storage_full' });
    return;
  }
  if (e instanceof BusyError) {
    res.setHeader('Retry-After', '5');
    json(res, status, { error: e.message, code: 'busy' });
    return;
  }
  if (full) {
    // Not a server fault, but worth one line: the operator needs to free space.
    res.setHeader('Retry-After', '60');
    json(res, status, { error: storageFullMessage, code: 'storage_full' });
    console.error(
      'Request refused: the disk of the Uptime Goblin host is full:',
      e?.code || e?.class || e?.name,
      ...request
    );
    return;
  }
  json(res, status, {
    error: e instanceof InputError ? e.message : 'Uptime Goblin could not complete this request',
  });
  if (!(e instanceof InputError)) console.error('Request failed:', e?.code || e?.name, ...request);
}

// What a header-less proxy's request looked like, for its journal line: where it came from,
// the Host it asked for, and the page's address when that is not a loopback one.
function describeHeaderless(req, peer) {
  const host = originHost(req.headers.origin);
  const page = host !== null && !isLoopbackHost(host) ? logOrigin(req.headers.origin) : '';
  return `a request from ${logValue(peer)} for Host ${logValue(req.headers.host)}${page ? ` from a page at ${page}` : ''}`;
}

/** When a Basic-authenticated answer says Basic is deprecated (RFC 9745): 2026-10-01. */
export const basicDeprecation = '@1790812800';

// The actor of audit rows (audit spec §4.1, D25) made with no access: nobody signed in.
const anonymousActor = Object.freeze({
  type: 'anonymous',
  id: null,
  name: null,
  via: null,
  sessionId: null,
});

/**
 * The actor of the audit rows a request with `access` causes (audit spec §4.1): the admin, by
 * session (with its public session id, D25), by a wall display's session (`kiosk`) or by
 * Basic; or, without an access, nobody (`anonymous`).
 */
export function auditActor(access) {
  if (!access) return anonymousActor;
  return Object.freeze({
    type: 'user',
    id: access.principal?.userId ?? null,
    name: access.principal?.login ?? null,
    via: access.via === 'basic' ? 'basic' : access.kind === 'kiosk' ? 'kiosk' : 'session',
    sessionId: access.sessionId ?? null,
  });
}

// The route.audit kinds whose changes have an attempt row and a result (audit spec §4.4).
const attemptKinds = Object.freeze(['config', 'delivery', 'channel', 'secret']);

// Refusals already counted into their aggregated rows (audit spec §5.2): each once, however
// many of the pipeline's catches it passes on its way to fail().
const counted = new WeakSet();
// Aggregated refusals are `failed` when a password was checked and was wrong, else `denied`
// (audit spec §5.2): the sign-in's and Basic's invalid_credentials, the password change's
// current_password_incorrect. Independent review A5: a script's Bearer header refused before a
// password change signed in (invalid_credentials) checked no password of the change: denied.
// A display code that redeems nothing (display_code_invalid) is a sign-in's wrong secret: failed.
const refusalOutcome = (action, code) =>
  code ===
    (action === 'account.password.changed'
      ? 'current_password_incorrect'
      : 'invalid_credentials') ||
  (action === 'session.login' && code === 'display_code_invalid')
    ? 'failed'
    : 'denied';

/**
 * The name a Basic `Authorization` header gives (the part before the first colon), for the
 * aggregated refusal row, which reduces it to `admin` or `other` at once (audit spec D9); null
 * when the header is not Basic. The decoded bytes, which hold the password, are wiped.
 */
export function basicLogin(header) {
  const match =
    typeof header === 'string' && header.length <= 4096
      ? /^\s*basic\s+([A-Za-z0-9+/]+={0,2})\s*$/i.exec(header)
      : null;
  if (!match) return null;
  const decoded = Buffer.from(match[1], 'base64');
  try {
    const colon = decoded.indexOf(0x3a);
    return colon < 0 ? null : decoded.subarray(0, colon).toString('utf8');
  } finally {
    decoded.fill(0);
  }
}

/**
 * The request handler for a route table.
 *
 * - `router`: from createRouter(); `identity`: the identity service (lib/identity/index.mjs);
 *   `loginThrottle`: a LoginThrottle.
 * - `release`: `{build, version}`: every answer after the Host allowlist names the build
 *   (except /health), so an open page can tell that Uptime Goblin was updated even when it is signed
 *   out; only signed-in answers name the version.
 * - `allowedHost(host)`: the Host allowlist; `configuredHosts`: the lower-case
 *   GOBLIN_ALLOWED_HOSTS entries, which a session write's Origin may also name (D20).
 *   `trusted(address)`: the trusted-proxy check or null.
 * - `isClosed()`: true while Uptime Goblin stops. `observe(req)`: sees every request with a valid
 *   address (the forwarded-protocol record). `noteClient(req, url)`: sees signed-in requests.
 * - `idempotency(req, res, {key, scope, body, access}, run)`: answers a write carrying
 *   Idempotency-Key, calling run() at most once per key and scope; `scope` names the principal
 *   (`access.scope`, D22), method and path. It rechecks `access` before running run() or
 *   answering from a kept reply, and keeps `res.orbitCommitted` (see committed() below), when
 *   there is one, as the key's reply instead of the answer the request got. Without it the
 *   header is ignored.
 * - `permitted(access, permission)`: the access's permissions (the admin holds them all).
 * - `legacyBasic`: scripts may sign in with HTTP Basic (never a browser page's request; over
 *   plain HTTP to an address on the network, not localhost, a request a browser makes on its
 *   own carries no fetch metadata, so a 1.4.x Basic login it remembers is checked like a
 *   script's). `insecureHttpSessions`:
 *   GOBLIN_INSECURE_HTTP_SESSIONS=1, sessions on the plain-HTTP transport, and Basic there too:
 *   Basic sends the password itself with every request, so on the `http` transport it follows
 *   the sessions' opt-in and without it gets the refusal a sign-in gets there (https_required).
 * - `forwardAuth`: a further credential type (see presentedCredentials()); `log`: where the
 *   operator diagnostics go (console).
 * - `guard`: the storage guard (lib/storage-guard.mjs), told of every disk-full error a request
 *   fails with (see fail()); null when there is none.
 *
 * - `audit`: the audit service (lib/audit, §4.1 of the audit spec); noopAudit() when none.
 *
 * A handler receives `{req, res, url, params, route, access, client, requestId, transport,
 * browser, presentedSessions, insecureCookies, audit, body(), assertCurrent(), committed(),
 * gone()}`:
 * body() reads and parses the JSON body once (then re-checks the credential, so a session ended
 * while the body arrived stops the request); assertCurrent() is the same re-check, for a handler
 * that awaits other work before answering; committed(status, value) is for a handler whose
 * write has been applied: it records that JSON answer as the write's outcome
 * (`res.orbitCommitted`), then re-checks and answers with it. A session that ended meanwhile
 * still gets only the 401, but a retry with the same Idempotency-Key, signed in again, is
 * answered from the recorded outcome instead of applying the write twice (delivery spec A62).
 * gone() is true once the client left.
 * `presentedSessions` is every value of this transport's session cookie, in the order sent;
 * `insecureCookies`, on `https` only, every `orbit_session` value (the one a plain-HTTP sign-in
 * left, and any another site set); both frozen arrays, possibly empty.
 *
 * `audit` records what the request does (audit spec §4.4), with `audit.request`, the frozen
 * facts its rows carry ({requestId, route, client, userAgent, actor}):
 * - `begin({action, target, detail, configRevision})` writes the attempt row of a change made
 *   outside control.sqlite, before it is made, and resolves a Change ({seq, note(values)}); it
 *   rejects AuditError audit_unavailable (503: nothing was changed) when the row cannot be
 *   written. The caller calls assertCurrent() again after it, before acting.
 * - `inUnit({action, target})` is the recorder for a change made in control.sqlite: a function
 *   `(tx, {diff})` its store calls inside the change's own unit (settings.update's `audit`).
 * - `single({action, target, detail})` writes an export's row before the answer; it rejects as
 *   begin() does.
 * - `operation({action, target, detail})` makes an Operation ({note(values)}), whose one row is
 *   written after the answer, best effort.
 * - `loginGiven(name)`: the login name a sign-in gave, for the aggregated row its refusal is
 *   counted into (§5.2), which keeps only its class (`admin` or `other`, D9).
 * Once the handler finished (or threw), the pipeline's settle() ends every Change begun and every
 * Operation made, in order, with the status the request was answered with (res.orbitCommitted,
 * else the error's, else res.orbitResponse; null with `client_closed` when there was no answer)
 * and the outcome noted, else `ok` for a change noted `applied`, else the status's (see
 * settledOutcome()). It is awaited and never rejects: the rows are written before the request is
 * finished, and a row that cannot be written goes to stderr (the audit's own concern).
 *
 * A route's `multipleSessions(context)` runs instead of the one-credential refusal when the
 * request's only credentials are two or more session cookies (a sign-out, §19 G1), after the
 * strict CSRF and JSON checks; `access` is null. Its `endedSession(context)` runs the same way
 * instead of the 401 session_expired when the one credential is a session cookie that does not
 * sign in (a sign-out whose delete failed, sent again: §20 H1).
 *
 * What the table declares is applied here: `csrf` and `contentType` for writes (public ones
 * too), `permission`, `idempotent`, `ifMatch: 'required'` (428 without If-Match; the handler
 * still compares the revision, inside its exclusive() turn) and the Deprecation and Sunset
 * headers of a deprecated route. `bodyLimit` is checked against the announced length right
 * after the route is matched for a public route, and otherwise once the credential signed in
 * (before that every request is held to the default limit, so a 413 tells no one without a
 * credential which paths exist or what they take), before a sign-out's multipleSessions or
 * endedSession handler, and again wherever the body is read; `body: 'empty'` is
 * checked before the handler; an If-Match that names no revision gets 400 if_match_invalid on
 * a route that compares it (`ifMatch` optional or required). A route whose
 * `audit` is `export` is refused to any request, whatever its credential and transport, that
 * fails crossOrigin() (403 cross_origin, its `read` text; audit spec D29) before its handler
 * builds anything: a cookie still reaches Uptime Goblin from same-site pages (other ports, sibling
 * hosts), and wherever a browser sends no fetch metadata (plain HTTP to an address on the
 * network, Uptime Goblin's own or a proxy's on this host that sends no forwarding headers; a browser
 * that predates it)
 * its cached Basic login on a load
 * another site's page starts reads as a script's; neither must mint audit rows or 16 MiB
 * exports. A route's `refusals` (an aggregated action: the sign-in's
 * and the password change's) is the row every AuthError refusal of the route is counted into, once,
 * whether its handler or the pipeline (its cross-origin refusal) refused it; the sign-in's with
 * the login name its handler gave (audit.loginGiven), its class only. A refusal of a signed-in
 * route made before its credential signed in counts too (independent review A5), with the anonymous
 * actor, unless the Basic rule already counted it into auth.basic.failed.
 */
export function createPipeline({
  router,
  identity,
  loginThrottle,
  release,
  allowedHost,
  configuredHosts = new Set(),
  trusted = null,
  isClosed = () => false,
  observe = () => {},
  noteClient = () => {},
  idempotency = null,
  permitted = (access, permission) => access.permissions.has(permission),
  legacyBasic = false,
  insecureHttpSessions = false,
  forwardAuth = null,
  log = console,
  guard = null,
  audit = noopAudit(),
  adminUiLock,
  adminDeployment = {},
}) {
  const diagnose = createDiagnostics({ log });
  // Capture once. No request reads environment or mutates this private lock snapshot.
  const locks = lockdownSetting(adminUiLock);
  const deployment = Object.freeze({ ...adminDeployment });
  if (locks.warning) log.warn(locks.warning);
  return async function handle(req, res) {
    if (guard) storageGuards.set(res, guard);
    const id = requestId(req, trusted);
    res.setHeader('X-Request-Id', id);
    // How much of a body Uptime Goblin reads to its end after an answer given without reading it: the
    // default limit until the request signs in (a public route's own limit once it is matched,
    // and a sign-out's own before its handler for two session cookies or an ended session), then
    // the matched route's (an unknown path or a wrong method keeps the default). Any more closes
    // the connection with the answer.
    let drainLimit = bodyLimit;
    answerClosing(req, res, () => drainLimit);
    // Refuses a body announced larger than `limit` (a body of unknown length, chunked, only when
    // the limit is 0: a read) with 413, unread, closing the connection, and holds what Uptime Goblin
    // reads after any later answer to `limit`. True when refused.
    const tooLarge = limit => {
      drainLimit = limit;
      const announced = announcedBytes(req);
      if (announced === Infinity ? limit === 0 : announced > limit) {
        json(res, 413, { error: 'Request is too large' });
        return true;
      }
      return false;
    };
    if (isClosed()) {
      res.setHeader('Connection', 'close');
      if (/^\/health(?:\?|$)/.test(req.url)) json(res, 503, { status: 'stopping' });
      else json(res, 503, { error: 'Uptime Goblin is stopping.' });
      return;
    }
    applySecurityHeaders(res);
    let url,
      client = null,
      transport = null,
      browser = false,
      presentedSessions = [],
      insecureCookies = [],
      access = null,
      found = null,
      raw = null,
      abandoned = false;
    // A browser that gave up on this request (closed the connection) before its write
    // started: the write is skipped, so nothing is applied behind its back.
    res.once('close', () => (abandoned = !res.writableFinished));
    const userAgent =
      typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : null;
    // The facts every audit row of this request carries (audit spec §4.1); built when a route
    // runs, once the access (and so the actor) is known.
    const facts = route =>
      Object.freeze({
        requestId: id,
        route: route ? `${route.method} ${route.path}` : null,
        client,
        userAgent,
        actor: auditActor(access),
      });
    // The login name this request's sign-in gave (its handler's audit.loginGiven()).
    let givenLogin = null;
    // Counts an AuthError refusal into its aggregated row once (audit spec §5.2): `action` the
    // row, `login` the name a sign-in gave (count() keeps only its class), `actor` the access's
    // for an action whose rows name the admin, `code` the code to count it under when not its
    // own. Never throws: a refusal is answered whatever the audit does with it.
    const refused = (error, { action, login = null, actor, code: as } = {}) => {
      if (
        !(error instanceof AuthError || error instanceof AdminError) ||
        counted.has(error) ||
        !action
      )
        return error;
      counted.add(error);
      const code = as ?? (typeof error.code === 'string' ? error.code : 'refused');
      try {
        audit.count({
          action,
          outcome: refusalOutcome(action, code),
          ...(actor ? { actor } : {}),
          client,
          userAgent,
          login,
          detail: { code },
        });
      } catch {}
      return error;
    };
    // The changes begun and the operations made by this request's handler, in order, each with
    // what the handler noted that settle() decides by (an outcome; whether the change applied).
    const made = [];
    const track = item => {
      const entry = { item, noted: {}, ended: false };
      made.push(entry);
      return values => {
        if (values?.outcome !== undefined) entry.noted.outcome = values.outcome;
        if (values?.applied !== undefined) entry.noted.applied = values.applied;
        item.note(values);
      };
    };
    // The recorder of a route's handler. Each way of recording is open only to the routes whose
    // `audit` kind declares it (D18), so the table says what every route records: a route left
    // `none` that records anyway is a defect (TypeError, 500) before anything is done.
    const recorder = route => {
      const request = facts(route);
      const kind = route?.audit ?? 'none';
      const declared = (method, kinds) => {
        if (!kinds.includes(kind))
          throw new TypeError(`${request.route}: audit ${kind} does not record with ${method}()`);
      };
      return Object.freeze({
        request,
        async begin({ action, target = null, detail = null, configRevision = null } = {}) {
          declared('begin', attemptKinds);
          const change = await audit.begin(request, { action, target, detail, configRevision });
          return Object.freeze({ seq: change.seq, note: track(change) });
        },
        inUnit({ action, target = null }) {
          declared('inUnit', ['secret']);
          return (tx, { diff } = {}) =>
            audit.record(
              tx,
              eventFrom(request, {
                action,
                outcome: 'ok',
                target,
                detail: diff === undefined ? null : { diff },
              })
            );
        },
        async single({ action, target = null, detail = null } = {}) {
          declared('single', ['export']);
          await audit.single(request, { action, target, detail });
        },
        operation({ action, target = null, detail = null } = {}) {
          declared('operation', ['operation']);
          const operation = audit.operation(request, { action, target, detail });
          return Object.freeze({ note: track(operation) });
        },
        loginGiven(value) {
          declared('loginGiven', ['identity']);
          givenLogin = typeof value === 'string' ? value : null;
        },
      });
    };
    // Ends every Change and Operation of the handler (audit spec §4.4), after its answer. The
    // status is the answer's: a write applied as its session ended keeps the outcome committed()
    // recorded (delivery spec A62), a thrown error the status fail() answers it with, and a
    // request that was never answered (the client went away) has none.
    const settle = async error => {
      for (const entry of made) {
        if (entry.ended) continue;
        entry.ended = true;
        const status =
          res.orbitCommitted?.status ??
          (error ? answerStatus(error) : (res.orbitResponse?.status ?? null));
        const outcome =
          entry.noted.outcome ??
          (entry.noted.applied === true
            ? 'ok'
            : status === null
              ? 'failed'
              : settledOutcome(status, error));
        const code = status === null ? 'client_closed' : error ? answerCode(error) : null;
        try {
          await entry.item.end({ status, outcome, code });
        } catch {}
      }
    };
    // The one way the body is read (a handler's body(), the Idempotency-Key step, the check of a
    // write that takes no body), at most `limit` bytes. A client waiting for 100 Continue gets
    // it only now, after every check before the handler (Node no longer sends it on its own:
    // applyServerLimits), so a refused client is never invited to send its body.
    let continued = false;
    let sanitizedBody;
    const readRequest = (limit, sensitive = false) => {
      if (
        !continued &&
        !res.headersSent &&
        req.httpVersion === '1.1' &&
        /(?:^|,)\s*100-continue\s*(?:,|$)/i.test(req.headers.expect ?? '')
      ) {
        continued = true;
        res.writeContinue();
      }
      return (sensitive ? readSensitiveBody : readBody)(req, limit);
    };
    const context = route => ({
      req,
      res,
      url,
      params: found.params,
      route,
      access,
      client,
      requestId: id,
      transport,
      browser,
      presentedSessions,
      insecureCookies,
      audit: recorder(route),
      body: async () => {
        if (route.stepUp) {
          identity.assertCurrent(access);
          return sanitizedBody;
        }
        raw ??= await readRequest(route.bodyLimit);
        const value = parseJson(raw);
        if (route.auth !== 'public') identity.assertCurrent(access);
        return value;
      },
      assertCurrent: () => {
        if (route.auth !== 'public') identity.assertCurrent(access);
      },
      // Recorded before the re-check: the write happened whatever this request is answered.
      committed: (status, value) => {
        res.orbitCommitted = recordedAnswer(res, status, value);
        if (route.auth !== 'public') identity.assertCurrent(access);
        json(res, status, value);
      },
      gone: () => abandoned,
    });
    const write = req.method !== 'GET' && req.method !== 'HEAD';
    // Writes must come from Uptime Goblin's own page, as JSON, unless the route says otherwise (an
    // unknown route or method is held to both). `strict` is the session and sign-in rule.
    // Throws cross_origin, or answers 415 and returns true.
    const refusedWrite = (route, strict) => {
      if (!write) return false;
      if (route?.csrf ?? true) {
        const reason = strict
          ? strictCrossOrigin(req, configuredHosts)
          : crossOrigin(req)
            ? 'legacy'
            : null;
        if (reason) {
          if (reason === 'origin-host' && route?.auth === 'public') diagnoseHost();
          throw identityError('cross_origin');
        }
      }
      if ((route?.contentType ?? 'json') === 'json' && !jsonRequest(req)) {
        // JSON in another charset is named as such: the media type itself was right.
        const otherCharset = /^\s*application\/json\s*;/i.test(req.headers['content-type'] ?? '');
        json(res, 415, {
          error: otherCharset ? 'Request bodies must be UTF-8 JSON' : 'JSON requests are required',
        });
        return true;
      }
      return false;
    };
    // A sign-in whose page address is neither the Host header nor an allowed host: almost
    // always a proxy that does not forward Host (nginx's default), which no opt-in fixes.
    const diagnoseHost = () => {
      const originText = logOrigin(req.headers.origin),
        wanted = logValue(originHost(req.headers.origin));
      diagnose(
        'cross_origin',
        `Sign-in refused: the browser's address ${originText} does not match the Host header ${logValue(req.headers.host)}, and ${wanted} is not in GOBLIN_ALLOWED_HOSTS. Make the reverse proxy forward the Host header (nginx: proxy_set_header Host $http_host;) or add ${wanted} to GOBLIN_ALLOWED_HOSTS.`
      );
    };
    // The headers a route declares (Deprecation, Sunset), on every answer the route itself
    // gives, a stored reply included, but not on refusals made before the route was reached.
    const declare = route => {
      for (const [name, value] of Object.entries(route.headers ?? {})) res.setHeader(name, value);
    };
    // Runs one of a route's handlers, then settle(): the rows of what it began are written
    // before the request is finished, whatever it threw (the error is then answered by fail()).
    const invoke = async (route, handler) => {
      try {
        // A write that takes no body (`body: 'empty'`) reads at most its few bytes and refuses
        // anything but nothing or {} before its handler (or sign-out hook) runs.
        if (route.body === 'empty') assertEmptyBody((raw ??= await readRequest(route.bodyLimit)));
        await handler(context(route));
      } catch (error) {
        await settle(error);
        throw error;
      }
      await settle(null);
    };
    // Runs a matched route: If-Match when required, and one that names a revision when sent to
    // a route that compares it (before the handler takes a write turn or an audit row), then the
    // handler.
    const run = async route => {
      const ifMatch = req.headers['if-match'];
      if (route.ifMatch === 'required' && ifMatch === undefined) {
        json(res, 428, {
          error: 'Send If-Match with the revision this change is based on.',
          code: 'if_match_required',
        });
        return;
      }
      if (route.ifMatch !== 'none' && ifMatch !== undefined && ifMatchRevision(ifMatch) === null) {
        json(res, 400, {
          error: 'If-Match must name one configuration revision, such as "12".',
          code: 'if_match_invalid',
        });
        return;
      }
      if (route.stepUp) {
        // Opt-in fixtures only until the coordinated creation/secureOnly contract lands.
        // Generic Basic is unavailable; no path or header grants a Basic exception here.
        raw = await readRequest(route.bodyLimit, true);
        try {
          identity.assertCurrent(access);
          if (
            access.kind !== 'interactive' ||
            access.via !== 'session' ||
            typeof identity.verifyPassword !== 'function'
          )
            throw adminError('step_up_unavailable', {
              variant: access.kind === 'basic' ? 'basic' : 'local',
            });
          await withStepUpPassword(raw, async (bytes, body) => {
            if (globallyLocked(loginThrottle, client, transport))
              throw identityError('locked', { retryAfter: 60 });
            const locked = loginThrottle.retryAfter(client);
            if (locked) throw identityError('locked', { retryAfter: Math.ceil(locked / 1000) });
            const releaseCheck = loginThrottle.begin(client);
            if (!releaseCheck) throw identityError('busy', { scope: 'client' });
            let matches;
            try {
              matches = await identity.verifyPassword(access, bytes);
            } finally {
              releaseCheck();
            }
            identity.assertCurrent(access);
            if (!matches) {
              loginThrottle.failure(client);
              throw adminError('step_up_failed');
            }
            loginThrottle.success(client);
            // Never lend password bytes to the handler. Finish the envelope lifetime first.
            sanitizedBody = body;
          });
          identity.assertCurrent(access);
          if (abandoned) return;
        } catch (error) {
          throw refused(error, {
            action: error instanceof AdminError ? 'auth.step-up' : null,
            actor: auditActor(access),
          });
        } finally {
          raw?.fill(0);
        }
      }
      await invoke(route, route.handler);
    };
    // The answer from the table: 404, 405 with Allow, or the route's own.
    const dispatch = async () => {
      if (!found) {
        json(res, 404, { error: 'Route not found' });
        return;
      }
      if (!found.route) {
        // A known route with the wrong method is a 405 with Allow, not a missing route.
        res.setHeader('Allow', found.allow);
        json(res, 405, {
          error: url.pathname.startsWith('/api/')
            ? `Use ${found.allow} for this route`
            : 'Method not allowed',
        });
        return;
      }
      await run(found.route);
    };
    try {
      if (hostLines(req) !== 1) {
        json(res, 400, { error: 'Send exactly one Host header.' });
        return;
      }
      if (!allowedHost(req.headers.host)) {
        json(res, 403, {
          error: 'Host is not allowed. Add this hostname and port to GOBLIN_ALLOWED_HOSTS.',
        });
        return;
      }
      // A request-target that is not origin-form, or that the URL parser cannot read, is the
      // client's mistake: answer 400, before sign-in, without logging it as a server failure.
      url = requestTarget(req.url);
      if (!url) {
        setHeaderPair(res, 'Build', release.build);
        json(res, 400, { error: 'Malformed request address' });
        return;
      }
      // Health probes stay version-free: a load balancer or the installer needs no build.
      const healthRoute = url.pathname === '/health' || url.pathname.startsWith('/health/');
      // From here every answer names the build, 401 and 403 included: a 1.4.3 tab reloads
      // itself into the sign-in view when a 401 names a build other than its own (D10).
      if (!healthRoute) setHeaderPair(res, 'Build', release.build);
      observe(req);
      found = router.match(req.method, url.pathname);
      // A body announced larger than Uptime Goblin takes is refused here, after the Host and target
      // checks above and before the credential is checked, and unread: the answer closes the
      // connection. Until a credential signed in, every request is held to the same default
      // limit, so a known route, an unknown path and a wrong method get the same answer and no
      // one learns from a 413 which paths exist or what they take. A public route (the sign-in,
      // the web app's files, /health) is held to its own limit here: it is public anyway. Any
      // other matched route's own limit (a read takes none) applies once the credential signed
      // in (signedIn()), or before a sign-out's own handlers below. A body of unknown length
      // (chunked) is refused there only on a route whose limit is 0 (a read); otherwise it is
      // held to the limit while a handler reads it, after the credential and the route's own
      // checks.
      const publicRoute = found?.route?.auth === 'public' ? found.route : null;
      if (tooLarge(publicRoute?.bodyLimit ?? bodyLimit)) return;
      transport = decideTransport({
        peer: req.socket?.remoteAddress,
        headers: req.headers,
        trusted,
      });
      client = requestClient(req, transport, trusted);
      const peer = req.socket?.remoteAddress;
      // A proxy on this host that sends no forwarding headers at all: its requests that keep a
      // loopback Host are the loopback transport, the Uptime Goblin host's own (§16 C1). Untrusted, all
      // of its requests share the host's lockout key whatever their Host (requestClient()).
      if (headerlessProxy(req, transport, peer))
        diagnose(
          'headerless_proxy',
          `A reverse proxy on this computer sends Uptime Goblin requests without any forwarding header (seen: ${describeHeaderless(req, peer)}). Uptime Goblin cannot tell its clients from this computer's own browsers and scripts whenever they keep a loopback Host, so they share the ssh tunnel's sign-in lockout (failed sign-ins through the proxy can lock out the tunnel) and are not held by the global sign-in lock. Make the proxy send X-Forwarded-For and X-Forwarded-Proto (nginx: proxy_set_header X-Forwarded-For $remote_addr; proxy_set_header X-Forwarded-Proto $scheme;) with GOBLIN_TRUST_PROXY=loopback. If the tunnel is locked out meanwhile, restart Uptime Goblin and sign in through the tunnel at once.`
        );
      // A proxy on this host that GOBLIN_TRUST_PROXY does not name and that sends forwarding
      // headers, while plain-HTTP sign-in is allowed: Uptime Goblin believes none of its headers, so
      // everything it relays is the `http` transport, which the opt-in accepts, from wherever
      // the proxy took it. Only the connection's own address is logged, nothing it sent.
      if (
        insecureHttpSessions &&
        transport.proxied &&
        isLoopbackPeer(peer) &&
        !(typeof trusted === 'function' && trusted(peer))
      )
        diagnose(
          'untrusted_local_proxy',
          `A reverse proxy on this computer that GOBLIN_TRUST_PROXY does not name sends Uptime Goblin requests with forwarding headers (from ${logValue(peer)}), and plain-HTTP sign-in is allowed (GOBLIN_INSECURE_HTTP_SESSIONS): Uptime Goblin believes nothing such a proxy says, so sign-ins through it, and scripts' Basic passwords while legacy Basic is on, are accepted as plain HTTP from wherever the proxy took them. Name the proxy in GOBLIN_TRUST_PROXY (loopback for one on this computer) and make it serve Uptime Goblin over HTTPS (nginx: proxy_set_header X-Forwarded-Proto $scheme;).`
        );
      // A trusted proxy that does not name its client: everyone behind it shares the proxy's
      // lockout key, so one client's failed sign-ins lock out all the others.
      if (
        transport.proxied &&
        typeof trusted === 'function' &&
        trusted(peer) &&
        client === throttleKey(peer)
      )
        diagnose(
          'forwarded_for_missing',
          `Requests from the trusted proxy ${logValue(peer)} do not name their client in X-Forwarded-For, so every client behind it shares one sign-in lockout: one client's failed sign-ins lock out the others. Make the proxy send it (nginx: proxy_set_header X-Forwarded-For $remote_addr;).`
        );
      browser = browserContext(req.headers);
      const cookies = readCookies(req.headersDistinct?.cookie);
      // Sessions are never read on plain HTTP unless GOBLIN_INSECURE_HTTP_SESSIONS=1 (D16):
      // one rule for signing in and for using a session.
      const cookieName =
        transport.kind !== 'http' || insecureHttpSessions
          ? sessionCookieName(transport.kind)
          : null;
      // The cookie's name before 1.5 (orbit_session, lib/legacy-names.mjs) is read only while no
      // cookie of the new name came: a present new cookie decides alone. A session signed in by
      // the old one gets the new cookie, with the same value, on this answer (below).
      let sessionCookie = cookieName,
        sessionValues = cookieName ? cookies.all(cookieName) : [];
      if (cookieName && !sessionValues.length) {
        const legacyValues = cookies.all(legacySessionCookieName(transport.kind));
        if (legacyValues.length) {
          sessionCookie = legacySessionCookieName(transport.kind);
          sessionValues = legacyValues;
        }
      }
      // Every value, not only a single one: a cookie of Uptime Goblin's name that another site set is
      // sent beside the browser's own, and a sign-in, a sign-out and the https end of a
      // plain-HTTP session must still end the browser's own (§19 G1).
      presentedSessions = Object.freeze([...sessionValues]);
      if (transport.kind === 'https')
        insecureCookies = Object.freeze([
          ...cookies.all(sessionCookieName('http')),
          ...cookies.all(legacySessionCookieName('http')),
        ]);
      // Basic carries the password in every request, so it takes the sessions' rule for plain
      // HTTP (D16): on the `http` transport only with GOBLIN_INSECURE_HTTP_SESSIONS=1.
      const basicAccepted =
        Boolean(legacyBasic) && (transport.kind !== 'http' || insecureHttpSessions);
      answerContexts.set(res, {
        browser,
        transportKind: transport.kind,
        insecureAllowed: Boolean(insecureHttpSessions),
        legacyBasic: Boolean(legacyBasic),
        // Only a script is challenged, only where Basic would be accepted.
        challenge: !browser && basicAccepted,
        build: release.build,
        healthRoute,
      });
      if (found?.route?.auth === 'public') {
        try {
          if (refusedWrite(found.route, true)) return;
          declare(found.route);
          await run(found.route);
        } catch (error) {
          // Every refusal of the sign-in, its handler's and the cross-origin one (the body was
          // not read then: no name).
          throw refused(error, { action: found.route.refusals, login: givenLogin });
        }
        return;
      }
      const presented = presentedCredentials(req, {
        cookieName: sessionCookie,
        cookies,
        browser,
        forwardAuth,
      });
      const authorizations = presented.filter(c => c.kind !== 'session' && c.kind !== 'forward');
      // Only credentials that will be checked are held to the lockout: a script's Authorization
      // (Basic only while legacy Basic is on, and on this transport). Session and browser
      // requests never are, so a lockout cannot sign out the owner's open pages, and a browser's
      // cached 1.4.x Basic header cannot lock anyone out (T22).
      const attempted = authorizations.some(c => c.kind !== 'basic' || basicAccepted);
      // A script's Basic credential, whose refusals are counted into the aggregated
      // auth.basic.failed row (audit spec §5.2) with the name it gave.
      const basicHeader = authorizations.find(c => c.kind === 'basic')?.value;
      const basicRefused = (error, code) =>
        basicHeader === undefined
          ? error
          : refused(error, { action: 'auth.basic.failed', login: basicLogin(basicHeader), code });
      if (attempted) {
        // During a many-address guessing attack only recently trusted clients may try, and
        // anyone on the loopback transport (D18: the Uptime Goblin host itself, globallyLocked()).
        // These refusals check no password, so they reveal nothing and are not counted as
        // guesses: counting them would let polling scripts hold the lock on forever. (The
        // audit's aggregated row still counts them: it bounds its rows, not the refusals.)
        if (globallyLocked(loginThrottle, client, transport))
          throw basicRefused(identityError('locked', { retryAfter: 60 }));
        const locked = loginThrottle.retryAfter(client);
        if (locked)
          throw basicRefused(identityError('locked', { retryAfter: Math.ceil(locked / 1000) }));
      }
      // Exactly one credential (X1): with two, which one signed in would depend on the order
      // they are read in. Nothing is checked, so the refusal is not counted as a guess.
      if (presented.length > 1) {
        if (sessionValues.length > 1)
          diagnose(
            'multiple_credentials',
            `A browser sent two ${sessionCookie} cookies, so its requests are refused until this site's cookies are cleared. Another site on a parent domain may set a cookie with the same name.`
          );
        // A sign-out still ends what the browser holds (§19 G1). Refusing it would leave the
        // browser's own session and cookie as they were while the owner walks away believing
        // the browser signed out, and once the other cookie went (it expired, or its site
        // removed it) the browser would be signed in again. The route's multipleSessions
        // handler may only end the sessions whose secrets the request carries and expire
        // Uptime Goblin's own cookie, which needs no proof of who the browser is. Only cookies: an
        // Authorization beside them is a script's mistake, refused as before.
        const route = found?.route;
        if (route?.multipleSessions && presented.every(c => c.kind === 'session')) {
          if (tooLarge(route.bodyLimit) || refusedWrite(route, true)) return;
          declare(route);
          await invoke(route, route.multipleSessions);
          return;
        }
        throw basicRefused(identityError('multiple_credentials'));
      }
      access = await authenticate(presented[0], basicRefused);
      if (access === null) {
        // One session cookie that does not sign in (unknown, expired or ended). A sign-out
        // still deletes the session it names while that is stored (§20 H1): a sign-out whose
        // delete failed is refused only in this process, a restart before its row goes would
        // accept it again, and pressing Sign out again with that cookie is the only way the
        // browser can name it. As for multipleSessions, the handler may only end the sessions
        // whose secrets the request carries and expire Uptime Goblin's own cookie.
        const route = found?.route;
        if (route?.endedSession) {
          if (tooLarge(route.bodyLimit) || refusedWrite(route, true)) return;
          declare(route);
          await invoke(route, route.endedSession);
          return;
        }
        throw identityError('session_expired');
      }
      // authenticate() checked the credential before it resolved, but this continuation runs
      // a microtask or more later: a sign-out, an expiry or a password change can land in
      // between. Check again, synchronously, before the request is trusted or dispatched; the
      // keyed-write path checks once more before it runs or replays.
      identity.assertCurrent(access);
      // Signed in by the cookie's name before 1.5: the same session under the new name, and the
      // old cookie removed. A handler that sets or ends the cookie itself replaces both.
      if (sessionCookie !== cookieName && access.via === 'session') {
        const { persistent, expiresAt } = access.session ?? {};
        res.setHeader('Set-Cookie', [
          newSessionCookie({
            kind: transport.kind,
            value: presented[0].value,
            maxAgeSeconds: persistent
              ? Math.max(0, Math.floor((expiresAt - Date.now()) / 1000))
              : null,
          }),
          ...expiredLegacySessionCookies(cookies),
        ]);
      }
      // Only a fully verified password clears failures. Basic always carries the password (a
      // cached check proves it too), so it keeps its client trusted during a many-address
      // attack. A session proves only that its holder has the cookie, which a lost device or a
      // copied cookie also has, and revoking the session would not end a trust it had made: it
      // keeps a client trusted that a password already made trusted, and never makes one. A
      // wall display's session never does either: no password made it, and a lobby display's
      // polls must not keep its address exempt from the global lock.
      if (access.via === 'basic' && access.verified) loginThrottle.success(client);
      else if (access.via === 'basic') loginThrottle.trust(client);
      else if (access.via === 'session' && access.kind !== 'kiosk' && loginThrottle.trusted(client))
        loginThrottle.trust(client);
      setHeaderPair(res, 'Version', release.version);
      if (access.via === 'basic') {
        // Scripts learn that Basic is going away, and where to read about signing in.
        res.setHeader('Deprecation', basicDeprecation);
        res.setHeader('Link', '</api/docs?doc=authentication>; rel="deprecation"');
        // Who still uses Basic, aggregated per UTC day (audit spec D31): never throws.
        try {
          audit.count({
            action: 'auth.basic.used',
            outcome: 'ok',
            actor: auditActor(access),
            client,
            userAgent,
          });
        } catch {}
      }
      noteClient(req, url);
      await signedIn(found?.route);
    } catch (e) {
      // Every refusal of the password change (a route's `refusals`), counted once (audit spec
      // §5.2): its handler's and the cross-origin one under the access's actor, and, independent
      // review A5, one made before a credential signed in (none sent: signin_required; an
      // ended session: session_expired; two cookies, another site's page, a Bearer header) as
      // nobody signed in, the access still null. A refusal already counted is not counted
      // again: the sign-in's, in its branch above with the name it gave, and a Basic
      // credential's, into auth.basic.failed. (Both password routes refuse replays, so no
      // refusal is answered inside the Idempotency-Key handling, out of sight here.)
      fail(res, refused(e, { action: found?.route?.refusals, actor: auditActor(access) }));
    }

    // The signed-in part of a request: the route's own body limit, CSRF, permission, the export
    // rule, Idempotency-Key, and the route's own answer.
    async function signedIn(route) {
      // A matched route's own limit, now that the request is signed in (an unknown route or a
      // wrong method keeps the default limit it was held to before the credential).
      if (route && tooLarge(route.bodyLimit)) return;
      if (refusedWrite(route, route?.stepUp || access.via === 'session')) return;
      // Only for a route that would run: 404 and 405 answers need no permission.
      if (route) {
        if (!principalRouteAllowed(access, route) || !permitted(access, route.permission))
          throw refused(identityError('forbidden'), {
            action: 'auth.forbidden',
            actor: auditActor(access),
          });
        // Authorization and applicable CSRF precede lockdown. Locked requests never reach
        // replay, If-Match, body reading, password verification, or their handler.
        if (route.lock && locks.locked.has(route.lock))
          throw refused(adminError('admin_ui_locked', { lock: route.lock, deployment }), {
            action: 'auth.step-up',
            actor: auditActor(access),
          });
        // D29: an export only from Uptime Goblin's own page or a script, with every credential on every
        // transport. A cookie reaches Uptime Goblin from any same-site page (another port, a sibling
        // host). A browser that remembers a 1.4.x Basic login sends it on a load another site's
        // page starts (an image, a navigation), and wherever the browser sends no fetch
        // metadata that load cannot be told from a script: at a plain-HTTP address on the
        // network (not localhost, 127.x or [::1]), Uptime Goblin's own or that of a proxy on this host
        // that sends no forwarding headers and keeps a loopback Host (the loopback transport,
        // which looks like this computer's own scripts), and over HTTPS from a browser that
        // predates fetch metadata. The custom header needs a CORS preflight, which
        // Uptime Goblin never grants, so no other site's page can send it. Refused before the export is
        // built or its audit entry written (the Basic sign-in itself was already checked and
        // counted). Scripts send the header, as with every change (finding F4: Basic exports
        // on the loopback and https transports kept 1.4.3's rule, without it, before).
        if (route.audit === 'export' && crossOrigin(req))
          throw identityError('cross_origin', { variant: 'read' });
        declare(route);
      }
      if (write) {
        // A route may opt out of replays (sign-in and password changes are never replayed;
        // the page handles a lost answer itself). Unknown routes and wrong methods are
        // replayable.
        const replayable = route
          ? route.idempotent
          : !(found?.routes ?? []).some(
              other => other.method !== 'GET' && other.method !== 'HEAD' && !other.idempotent
            );
        // Only interactive and Basic principals may occupy the shared replay store (B6).
        // Displays, future token kinds and unknown kinds must never consume its capacity.
        if (
          idempotency &&
          ['interactive', 'basic'].includes(access.kind) &&
          replayable &&
          req.headers['idempotency-key'] !== undefined
        ) {
          raw = await readRequest(route?.bodyLimit ?? bodyLimit);
          await idempotency(
            req,
            res,
            {
              key: req.headers['idempotency-key'],
              // The principal, not the session (D22): a retry sent after signing in again
              // (a new session) joins or replays its first attempt instead of running twice.
              scope: [access.scope, req.method, url.pathname].join('\n'),
              body: raw,
              access,
            },
            dispatch
          );
          return;
        }
      }
      await dispatch();
    }

    // True for a request a proxy on this computer relayed without any forwarding header (§16
    // C1): it comes from a loopback peer with none of them, but asks for one of Uptime Goblin's other
    // names (a proxy that forwards the Host; the allowlist already admitted it) or comes from a
    // page served under one, a GOBLIN_ALLOWED_HOSTS name (a proxy that keeps nginx's default
    // Host 127.0.0.1:<port>). A page at any other address is another site's, which a browser on
    // this computer was made to send (cross-site, refused as such), not a proxy.
    function headerlessProxy(request, decided, peerAddress) {
      if (decided.proxied || !isLoopbackPeer(peerAddress)) return false;
      if (!isLoopbackHost(request.headers.host)) return true;
      const page = originHost(request.headers.origin);
      return page !== null && !isLoopbackHost(page) && configuredHosts.has(page);
    }

    // The access for the one credential presented (or none), or null for a session cookie that
    // does not sign in (the caller answers session_expired, or runs the route's endedSession).
    // Throws the refusal otherwise; a Basic refusal goes through `basicRefused` (counted).
    async function authenticate(presentedCredential, basicRefused) {
      // No credential, no access: only the routes the table declares 'public' answer without
      // one (above), whatever the peer, so a header-less request from this computer gets 401.
      if (!presentedCredential) throw identityError('signin_required');
      if (presentedCredential.kind === 'session') {
        // Only Uptime Goblin's own pages use a session. A request another page made the browser send
        // (Sec-Fetch-Site: same-site, such as another app under the same parent domain or
        // another port of localhost, which the SameSite=Strict cookie still reaches; it never
        // goes cross-site) is refused before the session is read, so it cannot keep an idle
        // session alive or touch it at all. A typed address or bookmark (none) is the owner's.
        // Over plain HTTP browsers send fetch metadata only to localhost, 127.x and [::1], so on
        // the opt-in `http` transport this holds only for a browser at such an address.
        const site = req.headers['sec-fetch-site'];
        if (site !== undefined && site !== 'same-origin' && site !== 'none')
          throw identityError('cross_origin', write ? {} : { variant: 'read' });
        const activity =
          requestHeader(req.headers, 'Activity') === 'background' ? 'background' : 'foreground';
        // The transport too: a session is accepted only as the cookie it was issued as.
        const session = await identity.authenticateSession(presentedCredential.value, {
          activity,
          transport: transport.kind,
        });
        return session || null;
      }
      if (presentedCredential.kind === 'basic') {
        if (!legacyBasic) throw basicRefused(identityError('basic_disabled'));
        // Plain HTTP without the opt-in: the refusal a sign-in gets there, before the password
        // is checked (so it counts as no guess), and one log line an hour that names the fix.
        if (transport.kind === 'http' && !insecureHttpSessions) {
          diagnose(
            'basic_https_required',
            `A script's HTTP Basic sign-in from ${logValue(req.socket?.remoteAddress)} over plain HTTP was refused (https_required): Basic sends the password in clear with every request. Call Uptime Goblin through its HTTPS address (a reverse proxy named in GOBLIN_TRUST_PROXY), or from the Uptime Goblin computer itself; or set GOBLIN_INSECURE_HTTP_SESSIONS=1 on a network you trust.`
          );
          throw basicRefused(identityError('https_required'));
        }
        return authenticateBasic(presentedCredential.value, basicRefused);
      }
      // Forward-auth is counted by the one-credential rule but not accepted before it arrives:
      // nothing was checked, so nothing is counted.
      if (presentedCredential.kind === 'forward') throw identityError('signin_required');
      // Bearer and other schemes: nothing accepts them yet, and each try counts as a guess.
      loginThrottle.failure(client);
      throw identityError('invalid_credentials', { variant: 'basic' });
    }

    // Every refusal goes through `basicRefused`, into the aggregated auth.basic.failed row; a
    // password replaced within the last day as `retired_password` (audit spec §5.2), though the
    // answer stays invalid_credentials.
    async function authenticateBasic(header, basicRefused) {
      const bytes = credential(header);
      if (!bytes) {
        loginThrottle.failure(client);
        throw basicRefused(identityError('invalid_credentials', { variant: 'basic' }));
      }
      const refusedAs = (error, retired) =>
        basicRefused(
          error,
          retired && error?.code === 'invalid_credentials' ? 'retired_password' : undefined
        );
      try {
        let basic;
        try {
          basic = await identity.authenticateBasic(bytes, {
            // At most a few checks per client at once: parallel guesses get no more checks
            // than sequential ones (1.4.3). This refusal counts, since it answers a guess.
            admit: () => {
              const releaseCheck = loginThrottle.begin(client);
              if (!releaseCheck) throw identityError('busy', { scope: 'client' });
              return releaseCheck;
            },
          });
        } catch (error) {
          // A full hasher queue (other clients' checks) says nothing about this client's
          // password and must not count against it; its own parallel burst does.
          const guess =
            error?.code === 'invalid_credentials' ||
            (error?.code === 'busy' && error.scope === 'client');
          const retired = identity.isRetiredBasic(bytes);
          if (guess && !retired) loginThrottle.failure(client);
          throw refusedAs(error, retired);
        }
        if (!basic) {
          // A password replaced within the last day is refused but not counted as a guess,
          // so other devices still using it cannot lock the owner out.
          const retired = identity.isRetiredBasic(bytes);
          if (!retired) loginThrottle.failure(client);
          throw refusedAs(identityError('invalid_credentials', { variant: 'basic' }), retired);
        }
        return basic;
      } finally {
        bytes.fill(0);
      }
    }
  };
}
