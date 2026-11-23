// Health probes: public, version-free, and answered right after the Host allowlist.
import { json } from '../body.mjs';
import { queryValue } from '../pipeline.mjs';
import { sameSecret } from '../startup.mjs';

/**
 * `/health?instance=<nonce>` tells the installer whether the process answering is the one that
 * wrote run/status.json, without revealing the nonce. `instance` given twice is refused (400).
 */
export function healthRoutes({ nonce }) {
  return [
    {
      method: 'GET',
      path: '/health',
      head: true,
      auth: 'public',
      permission: null,
      summary:
        'Whether Uptime Goblin is serving (and whether this is the process that wrote run/status.json)',
      handler({ res, url }) {
        const instance = queryValue(url, 'instance');
        json(res, 200, {
          status: 'ok',
          ...(instance === null
            ? {}
            : { instance: sameSecret(instance, nonce) ? 'match' : 'mismatch' }),
        });
      },
    },
  ];
}

/**
 * `/health/ready` for load balancers (roadmap §2.9): 200 `{status: 'ok'}` while `ready()`
 * holds, otherwise 503 `{status: 'unavailable'}`. Not in the 1.5 wave-1 table; wave 2 adds it
 * next to /health (startup mode already answers it with 503).
 */
export function readinessRoute({ ready = () => true } = {}) {
  return {
    method: 'GET',
    path: '/health/ready',
    head: true,
    auth: 'public',
    permission: null,
    summary: 'Whether this node should receive traffic',
    handler({ res }) {
      if (ready()) json(res, 200, { status: 'ok' });
      else json(res, 503, { status: 'unavailable' });
    },
  };
}
