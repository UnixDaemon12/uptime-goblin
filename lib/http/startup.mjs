// The listener while Uptime Goblin starts (roadmap §2.2 step 2, U6). Uptime Goblin binds its port first and
// answers in startup mode while it takes the lock, loads the keyring, opens and migrates its
// databases; then it switches the same listener to the full pipeline. The installer and load
// balancers therefore see "starting" (with progress in run/status.json) instead of a refused
// connection, and no request reaches half-opened stores.
import { timingSafeEqual, createHash } from 'node:crypto';
import { json } from './body.mjs';
import {
  answerClosing,
  applySecurityHeaders,
  hostLines,
  queryValue,
  requestId,
  requestTarget,
} from './pipeline.mjs';
import { setHeaderPair } from '../legacy-names.mjs';

/** Compares a secret with a candidate without revealing, through timing, how much matched. */
export function sameSecret(candidate, secret) {
  const digest = value => createHash('sha256').update(String(value)).digest();
  return timingSafeEqual(digest(candidate), digest(secret));
}

/**
 * The startup-mode handler.
 *
 * - `/health` (GET, HEAD): 503 `{status}` where status is `starting`, or `stopping` once
 *   phase() says so; `?instance=<nonce>` adds `instance: match|mismatch`, never the nonce.
 * - `/health/ready` (GET, HEAD): 503 `{status}`.
 * - Anything else: 503 `{error, code: 'starting'}` with Retry-After.
 *
 * Every answer carries the security headers, X-Request-Id and X-Goblin-Build with X-Orbit-Build (IR-4). As in
 * normal mode, a request with no Host or several Host lines (400), then one whose Host is
 * outside the allowlist (403), then one whose address is not origin-form (400) is refused
 * first, `instance` given twice is refused (400), and an answer given while a body is still
 * arriving closes the connection: nothing here reads a body.
 * `phase()` returns the phase written to run/status.json: starting, migrating, refused or
 * stopping.
 */
export function createStartupHandler({
  build,
  nonce = null,
  allowedHost = () => true,
  trusted = null,
  phase = () => 'starting',
  retryAfterSeconds = 5,
}) {
  return function startup(req, res) {
    answerClosing(req, res, () => 0);
    res.setHeader('X-Request-Id', requestId(req, trusted));
    applySecurityHeaders(res);
    setHeaderPair(res, 'Build', build);
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
    const url = requestTarget(req.url);
    if (!url) {
      json(res, 400, { error: 'Malformed request address' });
      return;
    }
    const status = phase() === 'stopping' ? 'stopping' : 'starting',
      probe = req.method === 'GET' || req.method === 'HEAD';
    if (probe && url.pathname === '/health') {
      let instance;
      try {
        instance = queryValue(url, 'instance');
      } catch (error) {
        json(res, 400, { error: error.message });
        return;
      }
      json(res, 503, {
        status,
        ...(instance === null || nonce === null
          ? {}
          : { instance: sameSecret(instance, nonce) ? 'match' : 'mismatch' }),
      });
      return;
    }
    if (probe && url.pathname === '/health/ready') {
      json(res, 503, { status });
      return;
    }
    res.setHeader('Retry-After', String(retryAfterSeconds));
    json(res, 503, {
      error:
        status === 'stopping'
          ? 'Uptime Goblin is stopping.'
          : 'Uptime Goblin is starting. Try again in a few seconds.',
      code: status,
    });
  };
}

/**
 * A request handler that can be replaced while the server listens:
 * `http.createServer(handler)` in startup mode, then `handler.use(pipeline)` once ready.
 */
export function switchableHandler(initial) {
  let current = initial;
  const handler = (req, res) => current(req, res);
  handler.use = next => {
    if (typeof next !== 'function') throw new TypeError('A request handler is required');
    current = next;
  };
  return handler;
}
