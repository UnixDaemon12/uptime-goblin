// The whole route table (lib/http/routes.mjs) through the real pipeline, over stand-ins: the
// in-memory audit service (test/helpers/fake-audit.mjs), identity (fake-identity.mjs) and
// delivery service (fake-alerting.mjs), a real ConfigStore in a temporary directory (so a test
// can compare config.json byte for byte), a stub scheduler, history and test-email sender, the
// real exclusive() queue and Idempotency-Key handling. For the audit stage of the pipeline
// (audit spec §4.4, §5.2-§5.5, §6) without a database or a key.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { LoginThrottle, trustedProxies } from '../../lib/throttle.mjs';
import { ConfigStore } from '../../lib/config.mjs';
import { collectorType } from '../../lib/catalog.mjs';
import { createRouter } from '../../lib/http/router.mjs';
import {
  routeTable,
  reservedPaths,
  supportedAuth,
  supportedFeatures,
} from '../../lib/http/routes.mjs';
import { createPipeline, fail } from '../../lib/http/pipeline.mjs';
import { createExclusive } from '../../lib/http/exclusive.mjs';
import { createIdempotency, createIdempotencyHandler } from '../../lib/http/idempotency.mjs';
import { StorageFullError } from '../../lib/storage-guard.mjs';
import { fakeAudit } from '../helpers/fake-audit.mjs';
import { fakeIdentity } from '../helpers/fake-identity.mjs';
import { fakeAlerting } from '../helpers/fake-alerting.mjs';
import { password, build, version, raw, browserWrite, cookieFrom, basic } from './harness.mjs';

export { password, raw, basic };

/** A promise and the function that resolves it, to hold a call until a test lets it go. */
export function gate() {
  let open;
  const promise = new Promise(resolve => (open = resolve));
  return { promise, open };
}

/** Waits until `ready()` is true (a few event-loop turns, at most about 2 s). */
export async function until(ready, what = 'the condition') {
  for (let i = 0; i < 400; i++) {
    if (ready()) return;
    await new Promise(resolve => setTimeout(resolve, 5));
  }
  throw new Error(`Timed out waiting for ${what}`);
}

/**
 * Serves the route table. Options: `legacyBasic` (true), `insecureHttpSessions` (false),
 * `trustProxy` (a GOBLIN_TRUST_PROXY value; none), `permitted` (the pipeline's permission
 * check), `collect(service, signal)` (the connection test's collection; default: one reading),
 * `send()` (the test email's send; default: accepted). Resolves to {port, origin, audit,
 * identity, alerting, config, guard, calls, app}: `calls` lists the stub scheduler's, history's
 * and sender's calls; `guard` is a stand-in storage guard (`setFull`, `noted`).
 */
export async function serveAudited(
  t,
  {
    legacyBasic = true,
    insecureHttpSessions = false,
    trustProxy = '',
    permitted,
    collect = async () => [{ key: 'up', label: 'Up', value: 1, unit: '' }],
    send = async () => ({ accepted: true, acceptedAt: 1 }),
  } = {}
) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-audit-pipeline-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const audit = fakeAudit();
  const identity = fakeIdentity({ password, audit, insecureHttpSessions });
  const trusted = trustedProxies(trustProxy);
  const alerting = fakeAlerting();
  const config = new ConfigStore(directory);
  const loginThrottle = new LoginThrottle();
  const calls = [];
  const noted = [];
  let full = false;
  const guard = {
    noted,
    setFull: value => (full = value),
    admitConfigWrite() {
      if (full) throw new StorageFullError();
    },
    noteWriteError(error) {
      noted.push(error);
      return true;
    },
    state: () => ({ full }),
    banner: () => null,
  };
  const tests = new Map();
  let testCount = 0;
  const collection = {
    collect: (service, signal) => collect(service, signal),
    beginTest() {
      if (tests.size >= 2) return null;
      const id = `test-${++testCount}`,
        controller = new AbortController();
      tests.set(id, controller);
      return { id, controller };
    },
    endTest: id => void tests.delete(id),
    hold: async (id, task) => task(),
    stop: id => calls.push(['stop', id]),
    forget: id => calls.push(['forget', id]),
    unschedule: id => calls.push(['unschedule', id]),
    sourceChanged: id => calls.push(['sourceChanged', id]),
    restart: () => calls.push(['restart']),
    reschedule: () => calls.push(['reschedule']),
    refresh: () => calls.push(['refresh']),
    monitoringKey: () => JSON.stringify(config.value.monitoring),
    interval: () => 60,
    timeoutMs: () => 30000,
    pending: () => 0,
    inflightCount: () => 0,
  };
  const store = {
    forget: async id => calls.push(['history.forget', id]),
    clearAlerts: id => calls.push(['clearAlerts', id]),
    clearAllAlerts: () => calls.push(['clearAllAlerts']),
    reconcileRules: id => calls.push(['reconcileRules', id]),
    markGap: id => calls.push(['markGap', id]),
    prune: async () => calls.push(['prune']),
  };
  const email = {
    reconfigure: () => calls.push(['email.reconfigure']),
    status: () => ({ pending: false }),
    send: async (...args) => {
      calls.push(['email.send']);
      return send(...args);
    },
  };
  let mono = 0;
  const noCollector = s => collectorType(s) === 'none';
  const exclusive = createExclusive({
    assertCurrent: access => identity.assertCurrent(access),
    admit: () => guard.admitConfigWrite(),
    onError: error => guard.noteWriteError(error),
    snapshot: () => audit.configSnapshot(config.value),
  });
  const log = { warn() {}, error() {} };
  const app = {
    identity,
    loginThrottle,
    legacyBasic,
    insecureHttpSessions,
    trusted,
    config,
    store,
    email,
    directory,
    docsDirectory: directory,
    release: { version, build, startedAt: Date.now() },
    nonce: 'n',
    dashboard: () => ({}),
    lastCollected: () => null,
    openClients: () => [],
    storage: { failure: () => null, failed() {}, step: step => step() },
    collection,
    exclusive,
    // Tests move it on to pass the email-test and refresh limits.
    mono: () => mono,
    settingsPruneMs: 10,
    webhookConfigured: true,
    configured: s => !noCollector(s) && Boolean(s.apiUrl || (collectorType(s) === 'http' && s.url)),
    noCollector,
    collectionError: () => 'Collection failed. Check the endpoint.',
    alerting,
    guard,
    reserveBytes: 0,
    keyStatus: {},
    audit,
    log,
    site: { build, publicFiles: new Map(), indexPage: Buffer.from(''), releases: null },
  };
  let port;
  const handle = createPipeline({
    router: createRouter(routeTable(app), {
      reserved: reservedPaths,
      auth: supportedAuth,
      supports: supportedFeatures,
    }),
    identity,
    loginThrottle,
    release: { build, version },
    allowedHost: host => [`127.0.0.1:${port}`, `localhost:${port}`].includes(String(host)),
    idempotency: createIdempotencyHandler(createIdempotency(), {
      fail,
      assertCurrent: access => identity.assertCurrent(access),
    }),
    trusted,
    legacyBasic,
    insecureHttpSessions,
    ...(permitted ? { permitted } : {}),
    guard,
    audit,
    log,
  });
  const server = http.createServer(handle);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  port = server.address().port;
  t.after(() => new Promise(resolve => server.close(resolve)));
  const origin = `http://127.0.0.1:${port}`;
  return {
    port,
    origin,
    audit,
    identity,
    alerting,
    config,
    guard,
    calls,
    app,
    tests,
    advance: ms => (mono += ms),
    /** Signs in through the login route; resolves to the session cookie. */
    async signIn() {
      const answer = await raw(
        port,
        ['POST /api/auth/login HTTP/1.1', ...browserWrite(origin)],
        JSON.stringify({ login: 'admin', password })
      );
      if (answer.status !== 200) throw new Error(`sign-in failed: ${answer.body}`);
      return cookieFrom(answer);
    },
    /** A request from Uptime Goblin's page with the session cookie (writes: CSRF headers and JSON). */
    page(cookie, method, target, { body, lines = [] } = {}) {
      const write = method !== 'GET';
      return raw(
        port,
        [
          `${method} ${target} HTTP/1.1`,
          `Cookie: ${cookie}`,
          ...(write
            ? browserWrite(origin)
            : ['X-Goblin-Request: 1', 'Sec-Fetch-Site: same-origin', 'X-Goblin-Client: web/test']),
          ...lines,
        ],
        write ? JSON.stringify(body ?? {}) : ''
      );
    },
    /** A script's request with Basic (writes: X-Goblin-Request and JSON). */
    script(method, target, { body, lines = [], credential = basic() } = {}) {
      const write = method !== 'GET';
      return raw(
        port,
        [
          `${method} ${target} HTTP/1.1`,
          `Authorization: ${credential}`,
          ...(write ? ['X-Goblin-Request: 1', 'Content-Type: application/json'] : []),
          ...lines,
        ],
        write ? JSON.stringify(body ?? {}) : ''
      );
    },
    /** The audit rows of `action` (every mode), in order. */
    rowsOf: action => audit.rows.filter(row => row.action === action),
  };
}
