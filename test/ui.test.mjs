// Browser tests for the web app (public/boot.js and public/modules/). They serve public/ the way
// Uptime Goblin does, with a scripted /api mock on loopback, and drive a local headless Chrome over the
// DevTools protocol (test/helpers/cdp.mjs), so they need no npm packages. Set CHROME_PATH to use
// a specific browser; the tests are skipped when none can start, unless TEST_REQUIRE lists
// 'browser'.
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Page as BrowserPage, delay, openPage, startBrowser } from './helpers/cdp.mjs';
import { spawnSync } from 'node:child_process';
import { auditBody, concreteBody } from './helpers/fake-audit.mjs';
import { call, signInBrowser, startOrbit, temporaryDirectory } from './helpers/orbit.mjs';
import {
  ACTIONS,
  ANCHOR_TEXTS,
  AUDIT_TEXTS,
  CODE_WORDS,
  PROBLEM_TEXTS,
  UNVERIFIABLE_TEXTS,
} from '../lib/audit/actions.mjs';
import { securityHeaders } from '../lib/http/pipeline.mjs';
import { generateSigningKey, publicSigningKey } from '../lib/notify/sign.mjs';

const publicDir = fileURLToPath(new URL('../public/', import.meta.url));

const spans = {
  '1h': 3600000,
  '6h': 21600000,
  '24h': 86400000,
  '7d': 604800000,
  '30d': 2592000000,
};
const metrics = (value = 50) => [
  { key: 'cpu', label: 'CPU', value, unit: '%' },
  { key: 'memory', label: 'Memory', value, unit: '%' },
  { key: 'disk', label: 'Disk', value, unit: '%' },
];
const catalog = [
  ['linux', 'Linux', 'Servers', 'cyan', 'terminal', ['CPU', 'Memory', 'Disk']],
  ['cosmos', 'Cosmos', 'Utilities', 'violet', 'server', ['Containers']],
  ['sonarr', 'Sonarr', 'Media', 'blue', 'tv', ['Queue']],
  ['http', 'Website', 'Utilities', 'blue', 'globe', ['Response', 'Available']],
  ['link', 'Bookmark', 'Utilities', 'violet', 'external', []],
].map(([type, name, group, color, icon, labels]) => ({ type, name, group, color, icon, labels }));
function source(overrides = {}) {
  return {
    id: 'linux',
    type: 'linux',
    name: 'Linux host',
    group: 'Servers',
    color: 'cyan',
    icon: 'terminal',
    labels: ['CPU', 'Memory', 'Disk'],
    enabled: true,
    showOnDashboard: true,
    pollSeconds: 0,
    url: '',
    apiUrl: 'http://127.0.0.1:9100',
    username: '',
    collector: 'native',
    metricPath: '',
    metrics: [],
    rules: [],
    monitoring: {},
    alerts: {},
    ...overrides,
  };
}
function sourceState(overrides = {}) {
  const time = Date.now();
  return {
    id: 'linux',
    status: 'live',
    configured: true,
    collector: 'linux',
    collecting: false,
    lastAttempt: time,
    lastSuccess: time,
    error: null,
    metrics: metrics(),
    ...overrides,
  };
}
function dashboard() {
  return {
    config: {
      title: 'Uptime Goblin',
      subtitle: '',
      pollSeconds: 60,
      retentionDays: 30,
      revision: 7,
      appearance: {
        accent: 'cyan',
        density: 'comfortable',
        columns: 'auto',
        defaultRange: '24h',
        sortBy: 'manual',
        showSummary: true,
        showPaused: true,
        showUnconfigured: true,
        openInNewTab: true,
        reduceMotion: false,
        timezone: 'local',
        timeFormat: 'auto',
      },
      monitoring: {
        concurrency: 4,
        timeoutSeconds: 90,
        retryCount: 2,
        retryDelaySeconds: 2,
        availabilityFailures: 2,
        availabilitySeconds: 60,
        recoverySuccesses: 2,
        recoverySeconds: 60,
      },
      alerts: {
        enabled: true,
        notifyOnAlert: true,
        notifyOnRecovery: true,
        notifyAvailability: true,
        notifyMeasurements: true,
      },
      email: {
        host: 'smtp.gmail.com',
        port: 465,
        secure: true,
        from: '',
        to: '',
        enabled: false,
        passwordConfigured: false,
      },
      services: [source()],
    },
    catalog,
    services: [sourceState()],
    alerts: [],
    events: [],
    lastCollected: Date.now(),
    storage: null,
    // 1.4.x's notification fields, and the delivery milestone's (spec §6.5) beside them: no
    // channel set up, the status readable. Tests of delivery set their own (useStatus()).
    notifications: {
      configured: false,
      lastError: null,
      webhook: { configured: false, lastError: null },
      email: {
        enabled: false,
        configured: false,
        state: 'disabled',
        pending: 0,
        lastAttempt: null,
        lastAccepted: null,
        lastError: null,
        failedCount: 0,
        channelState: 'not-configured',
        pausedReason: null,
        nextAttemptAt: null,
        waiting: 0,
        failed: 0,
      },
      available: true,
      updatedAt: Date.now(),
      saving: true,
      unsavedSince: null,
      attention: { waiting: 0, retrying: 0, failed: 0, paused: [], refusing: [] },
      channels: [
        {
          id: 'email',
          state: 'not-configured',
          pausedReason: null,
          nextAttemptAt: null,
          lastAttempt: null,
        },
        {
          id: 'env-webhook',
          state: 'not-configured',
          pausedReason: null,
          nextAttemptAt: null,
          lastAttempt: null,
        },
      ],
    },
    disk: null,
  };
}
/** Evenly spaced successful readings; `value(i, n)` sets every metric of reading i. */
function history(range, value = () => 50, { count = 120, failed = () => false } = {}) {
  const to = Date.now(),
    from = to - spans[range],
    step = spans[range] / count;
  return {
    from,
    to,
    totalSamples: count,
    maxGapMs: spans[range],
    pollSeconds: 60,
    points: Array.from({ length: count }, (_, i) =>
      failed(i)
        ? { time: from + (i + 0.5) * step, ok: false, gapBefore: false, metrics: [], error: 'Down' }
        : {
            time: from + (i + 0.5) * step,
            ok: true,
            gapBefore: false,
            metrics: metrics(value(i, count)),
          }
    ),
  };
}

// Uptime Goblin's sign-in answers. The mocked bodies are those test/contract/identity-bodies.json pins
// (the contract the http lane's pipeline is tested against), so the web app is tested against
// what Uptime Goblin really sends. Until that fixture exists these tests use the same bodies written
// out from the 1.5 sessions spec (§5.3, §6.2, §6.6, §6.11); once it exists, every body the
// tests use must be in it.
const identityFixture = (() => {
  try {
    return JSON.parse(
      fs.readFileSync(new URL('./contract/identity-bodies.json', import.meta.url), 'utf8')
    );
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
})();
/** Every object in `value`, depth first, whatever the fixture's layout. */
function* objects(value) {
  if (!value || typeof value !== 'object') return;
  if (!Array.isArray(value)) yield value;
  for (const child of Object.values(value)) yield* objects(child);
}
const sessionId = 's_AbCdEfGhIjKlMnOp';
/** A fixture body with its placeholders ("<id>", "<ms>", "<build>") made concrete. */
function concrete(value) {
  if (value === '<id>') return sessionId;
  if (value === '<ms>') return Date.now();
  if (value === '<build>') return web.build;
  if (Array.isArray(value)) return value.map(concrete);
  if (value && typeof value === 'object')
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, concrete(v)]));
  return value;
}
function fromFixture(what, predicate) {
  if (!identityFixture) return null;
  for (const body of objects(identityFixture)) if (predicate(body)) return concrete(body);
  throw new Error(`test/contract/identity-bodies.json has no ${what}`);
}
const identityMessages = {
  signin_required: 'Sign in to Uptime Goblin.',
  session_expired: 'Your session has ended. Sign in again.',
  invalid_credentials: 'The login name or password is incorrect.',
  multiple_credentials: 'Send one credential per request.',
  https_required:
    'Sign-in needs HTTPS, or a browser on this computer. Open Uptime Goblin through its HTTPS address. GOBLIN_INSECURE_HTTP_SESSIONS=1 allows sign-in over plain HTTP, but the password and the sign-in cookie then cross the network unencrypted: set it only on a network you trust.',
  proxy_proto_missing:
    'Your browser uses HTTPS, but the reverse proxy does not tell Uptime Goblin so. Make the proxy send X-Forwarded-Proto: https (nginx: proxy_set_header X-Forwarded-Proto $scheme;) and make sure GOBLIN_TRUST_PROXY names it, or set GOBLIN_INSECURE_HTTP_SESSIONS=1 until it is fixed.',
  proxy_proto_mismatch:
    "Your browser uses plain HTTP (http://), but the reverse proxy tells Uptime Goblin the connection is HTTPS, so the browser would drop Uptime Goblin's secure sign-in cookie. Make the proxy send the real scheme (nginx: proxy_set_header X-Forwarded-Proto $scheme;), or open Uptime Goblin at its https:// address.",
  cross_origin: 'Cross-origin changes are not allowed',
  current_password_incorrect: 'The current password is incorrect.',
  locked: 'Too many failed sign-in attempts. Wait before trying again.',
  busy: 'Sign-in is busy. Please wait a moment and try again.',
  storage_full:
    "Uptime Goblin's disk is full, so it cannot save your sign-in or password change. Anyone already signed in stays signed in. Free some space on the Uptime Goblin host, then try again.",
};
const identity = {
  /** A 401 body: `{error, code, transport: {kind, insecureAllowed}}`. */
  unauthorized(code, kind = 'loopback', { insecureAllowed = false } = {}) {
    const body = fromFixture(
      `401 ${code} for transport ${kind}`,
      b => b.code === code && b.transport?.kind === kind && typeof b.error === 'string'
    ) ?? { error: identityMessages[code], code, transport: { kind, insecureAllowed } };
    body.transport.insecureAllowed = insecureAllowed;
    return { status: 401, body };
  },
  /** A 403 body: `{error, code}`. */
  forbidden(code) {
    const body = fromFixture(
      `403 ${code}`,
      b => b.code === code && typeof b.error === 'string' && !b.transport
    ) ?? { error: identityMessages[code], code };
    return { status: 403, body };
  },
  /** 429 and 503 bodies are `{error, code}` with Retry-After (not in the fixture). */
  refused(status, code, retryAfter) {
    return {
      status,
      headers: { 'Retry-After': String(retryAfter) },
      body: { error: identityMessages[code], code },
    };
  },
  /** GET /api/session for `via` session or basic, with `overrides` merged in. */
  session(via = 'session', { session = {}, ...overrides } = {}) {
    const now = Date.now();
    const body = fromFixture(
      `GET /api/session for via ${via}`,
      b => b.via === via && b.user && Array.isArray(b.permissions)
    ) ?? {
      user: {
        id: 'u_admin',
        login: 'admin',
        display: 'Administrator',
        role: 'admin',
        kind: 'person',
        builtin: true,
      },
      via,
      permissions: ['account:self', 'config:export', 'dashboard:read', 'settings:write'],
      session: via === 'session' ? {} : null,
      transport: { kind: 'loopback', https: false, insecure: false, insecureAllowed: false },
      legacyBasic: false,
      mirrorPending: false,
      build: web.build,
    };
    if (body.session)
      Object.assign(
        body.session,
        {
          id: sessionId,
          createdAt: now - 3600000,
          lastSeenAt: now,
          expiresAt: now + 6 * 86400000,
          idleExpiresAt: now + 12 * 3600000,
          persistent: false,
        },
        session
      );
    return Object.assign(body, overrides);
  },
};

const mock = { requests: [], routes: new Map(), inflight: 0 };
function resetMock() {
  mock.dashboard = dashboard();
  mock.history = (id, range) => history(range);
  mock.routes = new Map();
  mock.requests = [];
  // Like Uptime Goblin's session: signed in as the admin until a test signs out or revokes it. Signed
  // out, Uptime Goblin answers session_expired to a browser whose cookie it no longer knows (revoked
  // elsewhere) and signin_required to one without a cookie (never signed in, or signed out).
  mock.signedIn = true;
  mock.signedOutAs = 'session_expired';
  mock.sessionBody = () => identity.session('session');
  mock.password = 'correct horse battery staple';
  // GET /api/notifications and its deliveries (see the delivery tests below).
  mock.status = () => ({ body: notificationStatus() });
  mock.deliveries = () => ({ body: { deliveries: [], nextCursor: null, unsaved: 0 } });
  // The ntfy and Gotify settings and test (see the push notification test below).
  mock.push = pushMock();
  // The audit routes (see the Audit log tests below): an empty log until a test says otherwise.
  mock.audit = () => ({ body: concreteBody('list.empty', { now: Date.now() }) });
  mock.auditVerify = () => ({ body: concreteBody('verify.empty', { now: Date.now() }) });
  mock.auditExport = () => auditExport('export.csv');
}
const requests = (method, prefix) =>
  mock.requests.filter(r => r.method === method && r.path.startsWith(prefix));
function defaultRoute(method, url, { headers = {}, body = '' } = {}) {
  const config = mock.dashboard.config,
    input = body ? JSON.parse(body) : {},
    id = url.pathname.split('/').pop();
  if (method === 'POST' && url.pathname === '/api/auth/login') {
    if (input.login?.trim().toLowerCase() !== 'admin' || input.password !== mock.password)
      return identity.unauthorized('invalid_credentials');
    mock.signedIn = true;
    return { body: mock.sessionBody() };
  }
  // A signed-out browser gets Uptime Goblin's 401 for everything else.
  if (!mock.signedIn) return identity.unauthorized(mock.signedOutAs);
  if (method === 'GET' && url.pathname === '/api/session') return { body: mock.sessionBody() };
  if (method === 'POST' && url.pathname === '/api/auth/logout') {
    mock.signedIn = false;
    mock.signedOutAs = 'signin_required';
    return { status: 204 };
  }
  if (method === 'GET' && url.pathname === '/api/dashboard') return { body: mock.dashboard };
  if (method === 'GET' && url.pathname.startsWith('/api/history/'))
    return { body: mock.history(id, url.searchParams.get('range')) };
  // Like Uptime Goblin, configuration writes apply in order and refuse an older If-Match.
  if (
    method !== 'GET' &&
    (url.pathname === '/api/settings' || url.pathname.startsWith('/api/services')) &&
    headers['if-match'] !== undefined &&
    Number(headers['if-match']) !== config.revision
  )
    return { status: 409, body: { error: 'Changed elsewhere', revision: config.revision } };
  if (method === 'PATCH' && url.pathname.startsWith('/api/services/')) {
    const service = config.services.find(s => s.id === id);
    Object.assign(service, input);
    return { body: { service, revision: ++config.revision } };
  }
  if (method === 'POST' && url.pathname === '/api/services') {
    const service = source({ ...input, id: `${input.type}-${config.services.length + 1}` });
    config.services.push(service);
    return { status: 201, body: { service, revision: ++config.revision } };
  }
  if (method === 'DELETE' && url.pathname.startsWith('/api/services/')) {
    config.services = config.services.filter(s => s.id !== id);
    return { body: { ok: true, revision: ++config.revision } };
  }
  if (method === 'PATCH' && url.pathname === '/api/settings') {
    for (const [key, value] of Object.entries(input))
      config[key] = value && typeof value === 'object' ? { ...config[key], ...value } : value;
    return { body: { ok: true, revision: ++config.revision } };
  }
  if (method === 'GET' && url.pathname === '/api/docs')
    return { body: { title: 'Configuration', markdown: '# Configuration\n\nHello.' } };
  if (method === 'GET' && url.pathname === '/api/notifications') return mock.status(url);
  if (method === 'GET' && url.pathname === '/api/notifications/deliveries')
    return mock.deliveries(url);
  const push = /^\/api\/notifications\/channels\/(ntfy|gotify)\/(settings|test)$/.exec(
    url.pathname
  );
  if (push) return mock.push(method, push[1], push[2], input);
  if (method === 'GET' && url.pathname === '/api/audit') return mock.audit(url);
  if (method === 'GET' && url.pathname === '/api/audit/verify') return mock.auditVerify(url);
  if (method === 'GET' && url.pathname === '/api/audit/export') return mock.auditExport(url);
  return { status: 404, body: { error: 'Not found' } };
}
const types = {
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.css': 'text/css',
  '.svg': 'image/svg+xml',
};
/**
 * The web app as Uptime Goblin serves it from 1.5: index.html with its build in <meta name="orbit-build">
 * and its stylesheet at /assets/<build>/style.css; /boot.js, which loads
 * /assets/<build>/modules/main.js; /assets/<build>/<path> is public/<path> for the build Uptime Goblin
 * has (and for `web.previous`, the release before it, when set), and 404 for any other; /app.js
 * (the shim for pages from before 1.5), /boot.js, /favicon.svg and /style.css keep their own
 * paths. Nothing else is served outside /assets/, so a module loaded from anywhere else fails
 * these tests. `web.files` records every request; `web.page(load)` may answer the nth page load
 * itself (an older or cached index.html), and `web.asset(build, path)` may answer an asset with
 * another status, or with 'drop' close the connection without an answer (Uptime Goblin went away).
 */
const web = { build: 'a1b2c3d4e5f6' };
function resetWeb() {
  Object.assign(web, { files: [], page: null, asset: null, previous: null });
}
resetWeb();
const indexTemplate = () => fs.readFileSync(path.join(publicDir, 'index.html'), 'utf8');
/** index.html as Uptime Goblin renders it for `build`. */
const renderIndex = (html, build) =>
  html
    .replace(/<meta charset="UTF-8" \/>/, `$&\n    <meta name="orbit-build" content="${build}" />`)
    .replace('href="/style.css"', `href="/assets/${build}/style.css"`);
const pageLoads = () => web.files.filter(f => f.method === 'GET' && f.path === '/').length;
function serveWeb(req, res, url) {
  web.files.push({ method: req.method, path: url.pathname, search: url.search });
  const send = (status, type, body) => {
    // Not cached, so every load shows up in web.files.
    res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store' });
    res.end(req.method === 'HEAD' ? undefined : body);
  };
  if (url.pathname === '/' || url.pathname === '/index.html') {
    // Like Uptime Goblin, the page answers only GET and HEAD: a form the browser submits itself gets
    // 405, and its body is never read.
    if (req.method !== 'GET' && req.method !== 'HEAD')
      return send(405, 'text/plain', 'Method not allowed');
    const html = web.page?.(pageLoads()) ?? renderIndex(indexTemplate(), web.build);
    // Uptime Goblin's Content-Security-Policy, so a page that breaks it fails here too.
    res.setHeader('Content-Security-Policy', securityHeaders['Content-Security-Policy']);
    send(200, 'text/html', html);
    return;
  }
  let relative = null;
  const asset = /^\/assets\/([^/]+)\/(.+)$/.exec(url.pathname);
  if (asset) {
    const status = web.asset?.(asset[1], asset[2]);
    if (status === 'drop') return void req.socket.destroy();
    if (status) return send(status, 'text/plain', 'Unavailable');
    if (asset[1] === web.build || asset[1] === web.previous) relative = asset[2];
  } else if (['/boot.js', '/app.js', '/favicon.svg', '/style.css'].includes(url.pathname))
    relative = url.pathname.slice(1);
  const file = relative && path.join(publicDir, relative);
  if (
    !file ||
    !file.startsWith(publicDir) ||
    !fs.statSync(file, { throwIfNoEntry: false })?.isFile()
  )
    return send(404, 'text/plain', 'Not found');
  send(200, types[path.extname(file)] || 'application/octet-stream', fs.readFileSync(file));
}
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  if (!url.pathname.startsWith('/api/')) {
    serveWeb(req, res, url);
    return;
  }
  mock.inflight++;
  try {
    let body = '';
    for await (const chunk of req) body += chunk;
    const request = { method: req.method, path: url.pathname, url, headers: req.headers, body };
    mock.requests.push(request);
    const route = mock.routes.get(`${req.method} ${url.pathname}`);
    const reply = (route && (await route(request))) || defaultRoute(req.method, url, request);
    if (reply.delay) await delay(reply.delay);
    // No answer at all, as when Uptime Goblin stops or the network drops.
    if (reply.drop) return void req.socket.destroy();
    if (!res.destroyed) {
      // Like Uptime Goblin, every answer names the release it runs (`build: null`: a release before
      // 1.5, whose refusals did not).
      const build = reply.build === undefined ? web.build : reply.build;
      res.writeHead(reply.status || 200, {
        'Content-Type': 'application/json',
        ...(build ? { 'X-Goblin-Build': build } : {}),
        ...reply.headers,
      });
      // `raw`: a body sent as it is (a download), not as JSON.
      res.end(reply.status === 204 ? undefined : (reply.raw ?? JSON.stringify(reply.body)));
    }
  } finally {
    mock.inflight--;
  }
});

// Runs before the web app: records the 15 s dashboard poll and the 5-minute version probe so
// tests can run them on demand, lets tests move the page's clocks forward, hide the page, or
// hold back request time limits (as a throttled background timer would), and answers
// confirm() prompts.
const prelude = `
  window.__cspViolations = [];
  document.addEventListener('securitypolicyviolation', e =>
    window.__cspViolations.push(e.violatedDirective + ' ' + e.blockedURI)
  );
  window.__confirmAnswer = true;
  window.__confirmCalls = 0;
  window.confirm = () => (window.__confirmCalls++, window.__confirmAnswer);
  window.__skew = 0;
  const realNow = Date.now;
  Date.now = () => realNow() + window.__skew;
  window.__perfSkew = 0;
  const realPerformanceNow = performance.now.bind(performance);
  performance.now = () => realPerformanceNow() + window.__perfSkew;
  window.__hidden = false;
  Object.defineProperty(Document.prototype, 'hidden', { configurable: true, get: () => window.__hidden });
  window.__holdTimers = false;
  const realSetTimeout = window.setTimeout;
  window.setTimeout = (fn, ms, ...rest) =>
    window.__holdTimers && ms >= 20000 ? 0 : realSetTimeout(fn, ms, ...rest);
  window.__bodyDelay = 0;
  // Every Blob a download is made of, as hex (after downloadGuard, which records its text).
  window.__blobBytes = [];
  const createBlobUrl = URL.createObjectURL;
  URL.createObjectURL = object => {
    if (object instanceof Blob) {
      const entry = { hex: null };
      window.__blobBytes.push(entry);
      object.arrayBuffer().then(data => (entry.hex = [...new Uint8Array(data)].map(b => b.toString(16).padStart(2, '0')).join('')));
    }
    return createBlobUrl.call(URL, object);
  };
  const realText = Response.prototype.text;
  Response.prototype.text = async function () {
    const body = await realText.call(this);
    if (window.__bodyDelay) await new Promise(resolve => realSetTimeout(resolve, window.__bodyDelay));
    return body;
  };
  // Uptime Goblin reads each API response with text(). Keep it pending until that body is
  // consumed in Chrome, not merely until the mock server has sent it.
  window.__requests = new Set();
  window.__requestGeneration = 0;
  const realFetch = window.fetch.bind(window);
  window.fetch = async (...args) => {
    const request = {};
    window.__requests.add(request);
    window.__requestGeneration++;
    try {
      const response = await realFetch(...args);
      const text = response.text.bind(response);
      response.text = async () => {
        try { return await text(); }
        finally { window.__requests.delete(request); }
      };
      // A download (api()'s as: 'bytes') reads its body as bytes instead.
      const bytes = response.arrayBuffer.bind(response);
      response.arrayBuffer = async () => {
        try { return await bytes(); }
        finally { window.__requests.delete(request); }
      };
      return response;
    } catch (error) {
      window.__requests.delete(request);
      throw error;
    }
  };
  const realSetInterval = window.setInterval;
  window.setInterval = (fn, ms, ...rest) =>
    ms === 15000
      ? ((window.__poll = fn), 0)
      : ms === 300000
        ? ((window.__probe = fn), 0)
        : realSetInterval(fn, ms, ...rest);
`;
class Page extends BrowserPage {
  /** Waits for browser response consumption and two paints without a follow-up request. */
  async settle() {
    const deadline = Date.now() + 5000;
    for (;;) {
      await this.waitFor('window.__requests.size === 0', Math.max(1, deadline - Date.now()));
      const generation = await this.eval('window.__requestGeneration');
      await this.eval('new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))');
      if (
        await this.eval(
          `window.__requests.size === 0 && window.__requestGeneration === ${generation}`
        )
      )
        return;
      if (Date.now() >= deadline)
        throw new Error('Timed out waiting for browser requests to settle');
    }
  }
  async poll() {
    const before = requests('GET', '/api/dashboard').length;
    await this.eval('window.__poll()');
    while (requests('GET', '/api/dashboard').length === before) await delay(10);
    await this.settle();
  }
}

const { browser, skip } = await startBrowser();
const cdp = browser?.cdp;
let base;
const pages = [];
async function open(hash = '') {
  const page = await openPage(cdp, base + '/' + hash, { prelude, PageClass: Page });
  pages.push(page);
  await page.waitFor(
    hash.startsWith('#configure')
      ? "document.querySelector('#configuration-nav a')"
      : "document.querySelector('#services > *')"
  );
  await page.settle();
  return page;
}
const js = value => JSON.stringify(value);
const text = (page, selector) =>
  page.eval(`document.querySelector(${js(selector)})?.textContent ?? null`);
async function setValue(page, selector, value) {
  await page.eval(`(() => {
    const field = document.querySelector(${js(selector)});
    field.value = ${js(value)};
    field.dispatchEvent(new Event('input', { bubbles: true }));
    field.dispatchEvent(new Event('change', { bubbles: true }));
  })()`);
}
async function expand(page, id = 'linux') {
  await page.eval(`document.querySelector('[data-expand=${js(id)}]').click()`);
  await page.settle();
}
async function openDrawer(page, id = 'linux') {
  await page.eval(`(() => {
    const button = document.createElement('button');
    button.dataset.configure = ${js(id)};
    document.body.append(button);
    button.click();
    button.remove();
  })()`);
  await page.waitFor("document.querySelector('#settings-dialog').open");
  await settled(page, 'settings-dialog');
}
/** Waits until a dialog's entry animation has finished, so clicks land where it rests. */
function settled(page, id) {
  return page.waitFor(
    `document.querySelector('#${id}').getAnimations({ subtree: true }).every(a => a.playState !== 'running')`
  );
}

before(async () => {
  if (skip) return;
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(async () => {
  if (!browser) return;
  await browser.close();
  if (server.listening) await new Promise(resolve => server.close(resolve));
});
// gate-prep, open item 7: the test browser kept state outside its --user-data-dir, in the
// account's home folder. On macOS that is its crash database (Library/Application
// Support/Google/Chrome/Crashpad) and its RLZ store, in the folder CFFIXED_USER_HOME names (else
// the account's home), and on Linux the folders HOME and XDG_* name. Here those variables name an
// empty folder while this test starts its own browser: Chrome must write nothing there, a crash
// handler it starts must keep its database in the throwaway profile, and nothing of it may run
// once it is closed. (The processes are read with ps; this file's other browser is not involved.)
const crashDatabases = () => {
  const listed = spawnSync('ps', ['-ww', '-axo', 'pid=,command='], { encoding: 'utf8' });
  assert.equal(listed.status, 0, listed.stderr);
  return listed.stdout
    .split('\n')
    .filter(line => /crashpad_handler/.test(line))
    .map(line => /--database=(.*?)(?: --[a-z]|$)/.exec(line)?.[1] ?? '');
};
const shortForm = file => file.replace(/^\/private(?=\/(?:tmp|var)\/)/, '');
test(
  'the test browser keeps its files in its throwaway profile: nothing in the home folder, its crash database in the profile, nothing left running',
  { skip, timeout: 60000 },
  async t => {
    const home = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-ui-home-')));
    t.after(() => fs.rmSync(home, { recursive: true, force: true }));
    const variables = {
      HOME: home,
      CFFIXED_USER_HOME: home,
      XDG_CONFIG_HOME: path.join(home, '.config'),
      XDG_CACHE_HOME: path.join(home, '.cache'),
      XDG_DATA_HOME: path.join(home, '.local', 'share'),
    };
    const saved = Object.fromEntries(Object.keys(variables).map(name => [name, process.env[name]]));
    Object.assign(process.env, variables);
    let own;
    try {
      own = (await startBrowser()).browser;
    } finally {
      for (const [name, value] of Object.entries(saved))
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
    }
    assert.ok(own, 'the browser started');
    let closed = false;
    t.after(() => closed || own.close());
    const page = await openPage(own.cdp, 'about:blank');
    assert.equal(await page.eval('6 * 7'), 42);
    // Long enough for what Chrome writes at its start (the crash database and the RLZ store).
    await delay(1500);
    const mentions = (database, folder) =>
      [folder, shortForm(folder)].some(
        name => database === name || database.startsWith(`${name}/`)
      );
    const databases = crashDatabases().filter(
      database => mentions(database, home) || mentions(database, own.profile)
    );
    for (const database of databases)
      assert.ok(
        mentions(database, own.profile),
        `a crash database outside the profile: ${database}`
      );
    assert.deepEqual(fs.readdirSync(home), [], 'nothing was written in the home folder');
    const profile = own.profile;
    await own.close();
    closed = true;
    assert.equal(fs.existsSync(profile), false, 'the profile is removed');
    assert.deepEqual(
      crashDatabases().filter(database => mentions(database, profile)),
      [],
      'no crash handler of it is left running'
    );
    assert.deepEqual(fs.readdirSync(home), [], 'nor anything written there since');
  }
);

beforeEach(async () => {
  // A tab that is closing gets 'visibilitychange', and one that still reported itself visible
  // (see the prelude) would poll then, into the next test's mock. It says it is hidden first,
  // as a real closing tab does.
  while (pages.length) {
    const page = pages.pop();
    await page.eval('window.__hidden = true').catch(() => {});
    await page.close();
  }
  resetMock();
  resetWeb();
});

test(
  'a dashboard poll keeps the open chart, its focus and the metric list in place',
  { skip },
  async () => {
    const page = await open();
    await expand(page);
    await page.waitFor("document.querySelector('#graph-linux svg.chart')");
    await page.eval(`(() => {
    window.__select = document.querySelector('#metric-select');
    window.__select.focus();
    window.__sawLoading = false;
    new MutationObserver(records => {
      for (const r of records)
        for (const node of r.addedNodes)
          if (node.nodeType === 1 && (node.matches('.loading') || node.querySelector('.loading')))
            window.__sawLoading = true;
    }).observe(document.querySelector('#services'), { childList: true, subtree: true });
  })()`);
    mock.dashboard.services[0].metrics = metrics(61);
    mock.dashboard.services[0].lastAttempt = mock.dashboard.services[0].lastSuccess = Date.now();
    await page.poll();
    await page.poll();
    assert.equal(await page.eval('window.__sawLoading'), false);
    assert.equal(await page.eval('document.activeElement === window.__select'), true);
    assert.ok(await page.eval("document.querySelector('#graph-linux svg.chart')"));
    // The readings beside the chart still follow the poll.
    assert.match(await text(page, '#graph-linux .detail-stats'), /61%/);
  }
);

test(
  'an open chart refetches history once its window has moved on a bucket, and not while configuring',
  { skip },
  async () => {
    const page = await open();
    await expand(page);
    await page.waitFor("document.querySelector('#graph-linux svg.chart')");
    assert.equal(requests('GET', '/api/history/').length, 1);
    await page.poll();
    await page.poll();
    assert.equal(requests('GET', '/api/history/').length, 1, 'unchanged source: no refetch');
    // A new reading within the chart's current bucket (24h / 300 = 4.8 min) waits for it.
    mock.dashboard.services[0].lastAttempt = Date.now() + 1;
    await page.eval('window.__skew = 2 * 60 * 1000');
    await page.poll();
    assert.equal(requests('GET', '/api/history/').length, 1, 'same bucket: no refetch');
    await page.eval('window.__skew = 10 * 60 * 1000');
    await page.poll();
    assert.equal(requests('GET', '/api/history/').length, 2);
    await page.eval("location.hash = '#configure/overview'");
    await page.waitFor("document.querySelector('#configuration-section-title')");
    mock.dashboard.services[0].lastAttempt = Date.now() + 2;
    await page.eval('window.__skew = 20 * 60 * 1000');
    await page.poll();
    assert.equal(requests('GET', '/api/history/').length, 2, 'hidden chart: no refetch');
  }
);

test('a chart never shows history cached for a different range', { skip }, async () => {
  const page = await open();
  await expand(page);
  await page.waitFor("document.querySelector('#graph-linux svg.chart')");
  mock.routes.set('GET /api/history/linux', ({ url }) =>
    url.searchParams.get('range') === '30d' ? { status: 502, body: { error: 'Bad gateway' } } : null
  );
  await page.eval('document.querySelector(\'[data-range="30d"]\').click()');
  await page.waitFor(
    "/History is unavailable/.test(document.querySelector('#graph-linux').textContent)"
  );
  await page.eval("window.dispatchEvent(new Event('resize'))");
  await page.settle();
  assert.equal(await page.eval("!!document.querySelector('#graph-linux svg.chart')"), false);
  assert.match(await text(page, '#graph-linux'), /History is unavailable/);

  // A slow 24h response that lands after a newer 7d one is not drawn under 7d.
  mock.routes.clear();
  mock.history = (id, range) => history(range, () => (range === '7d' ? 7 : 24));
  mock.routes.set('GET /api/history/linux', ({ url }) =>
    url.searchParams.get('range') === '24h'
      ? { delay: 600, body: mock.history('linux', '24h') }
      : null
  );
  await page.eval('document.querySelector(\'[data-range="24h"]\').click()');
  await delay(50);
  await page.eval('document.querySelector(\'[data-range="7d"]\').click()');
  await page.waitFor(
    "/Lowest 7%/.test(document.querySelector('#graph-linux svg.chart')?.getAttribute('aria-label'))"
  );
  await delay(700);
  await page.settle();
  await setValue(page, '#metric-select', 'memory');
  await page.settle();
  assert.match(
    await page.eval("document.querySelector('#graph-linux svg.chart').getAttribute('aria-label')"),
    /^Memory history.*Lowest 7%/
  );
});

test('a reading between two failed collections is still drawn', { skip }, async () => {
  mock.history = () => history('24h', () => 40, { failed: i => i % 2 === 1 });
  const page = await open();
  await expand(page);
  const line = await page.waitFor(
    "document.querySelector('#graph-linux .chart-line')?.getAttribute('d')"
  );
  const segments = line.trim().split('M').filter(Boolean);
  assert.ok(segments.length >= 50);
  for (const segment of segments)
    assert.match(segment, /[LlHh]/, `segment "M${segment}" draws nothing`);
});

test('the chart tooltip reads the point under the pointer', { skip }, async () => {
  mock.history = (id, range) => history(range, (i, n) => (i * 100) / n, { count: 300 });
  const page = await open();
  await expand(page);
  await page.waitFor("document.querySelector('#graph-linux svg.chart circle')");
  const { x, y } = await page.center('#graph-linux svg.chart circle');
  await page.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x, y });
  await page.settle();
  assert.match(await text(page, '#graph-tooltip'), /· 99\.7%$/);
});

test(
  'Enter in the rule builder adds the rule, and an unadded rule blocks saving',
  { skip },
  async () => {
    const page = await open();
    await openDrawer(page);
    await setValue(page, '#rule-key', 'cpu');
    await setValue(page, '#rule-threshold', '90');
    await page.eval("document.querySelector('#rule-threshold').focus()");
    await page.press('Enter');
    await page.settle();
    assert.equal(requests('PATCH', '/api/services/').length, 0);
    assert.match(await text(page, '#rule-list'), /cpu\s+above 90/);
    await setValue(page, '#rule-key', 'memory');
    await setValue(page, '#rule-threshold', '80');
    await page.eval("document.querySelector('#connection-form [type=submit]').click()");
    await page.settle();
    assert.equal(requests('PATCH', '/api/services/').length, 0);
    assert.equal(await page.eval("document.querySelector('#settings-dialog').open"), true);
    assert.match(await text(page, '#form-error'), /rule you started/);
  }
);

test(
  'a blank or unreadable rule duration is rejected instead of becoming 0 s',
  { skip },
  async () => {
    const page = await open();
    await openDrawer(page);
    await setValue(page, '#rule-key', 'cpu');
    await setValue(page, '#rule-threshold', '90');
    await setValue(page, '#rule-duration', '');
    await page.eval("document.querySelector('#add-rule').click()");
    assert.equal(await text(page, '#rule-list'), '');
    assert.match(await text(page, '#toast'), /whole seconds/);
  }
);

test(
  'a rule keeps the white space of a key the list offers, and of the rule being edited',
  { skip },
  async () => {
    // Keys made from a source's ID or path keep white space at either end (upstreamId in
    // lib/collectors.mjs), and a rule matches its key exactly: trimmed, it never fired.
    mock.dashboard.services[0].metrics = [
      ...metrics(),
      { key: 'disk_/mnt/data ', label: '/mnt/data · Used', value: 40, unit: '%' },
    ];
    // A saved rule whose reading this collection did not report.
    mock.dashboard.config.services[0].rules = [
      { key: ' qemu/100.cpu', operator: 'gt', threshold: 90, forSeconds: 60 },
    ];
    mock.routes.set('POST /api/test-service', () => ({
      body: {
        ok: true,
        metrics: [{ key: 'disk_free_/srv ', label: '/srv · Free', value: 1, unit: 'bytes' }],
        elapsedMs: 5,
        checkedAt: Date.now(),
      },
    }));
    const page = await open();
    await openDrawer(page);
    const add = async (key, threshold) => {
      // What choosing an option of the list (or typing) leaves in the field.
      await setValue(page, '#rule-key', key);
      await setValue(page, '#rule-threshold', threshold);
      await page.eval("document.querySelector('#add-rule').click()");
    };
    await add('disk_/mnt/data ', '50');
    // Typed: trimmed, as before.
    await add('  memory ', '80');
    // An option of the last connection test.
    await click(page, '#test-connection');
    await page.waitFor("/Connected/.test(document.querySelector('#connection-test').textContent)");
    await add('disk_free_/srv ', '10');
    // Edited: the threshold changes, the key stays.
    await page.eval('document.querySelector(\'[data-edit-rule="0"]\').click()');
    await setValue(page, '#rule-threshold', '95');
    await page.eval("document.querySelector('#add-rule').click()");
    await page.eval("document.querySelector('#connection-form [type=submit]').click()");
    await page.settle();
    const [save] = requests('PATCH', '/api/services/linux');
    assert.deepEqual(
      JSON.parse(save.body).rules.map(r => [r.key, r.threshold]),
      [
        [' qemu/100.cpu', 95],
        ['disk_/mnt/data ', 50],
        ['memory', 80],
        ['disk_free_/srv ', 10],
      ]
    );
  }
);

test('a failed save during a connection test leaves Test connection usable', { skip }, async () => {
  mock.routes.set('POST /api/test-service', () => ({
    delay: 1500,
    body: { metrics: metrics(), elapsedMs: 1500 },
  }));
  mock.routes.set('PATCH /api/services/linux', () => ({
    status: 500,
    body: { error: 'Uptime Goblin could not complete this request' },
  }));
  const page = await open();
  await openDrawer(page);
  await page.eval("document.querySelector('#test-connection').click()");
  await page.waitFor("document.querySelector('#test-connection').disabled");
  await page.eval("document.querySelector('#connection-form [type=submit]').click()");
  await page.waitFor("!document.querySelector('#form-error').hidden");
  await page.settle();
  assert.deepEqual(
    await page.eval(
      "(b => [b.disabled, b.textContent])(document.querySelector('#test-connection'))"
    ),
    [false, 'Test connection']
  );
});

test(
  'pressing Escape twice keeps a drawer whose changes the user chose to keep',
  { skip },
  async () => {
    const page = await open();
    await openDrawer(page);
    await page.click('#source-name');
    await page.send('Input.insertText', { text: ' 2' });
    await page.eval('window.__confirmAnswer = false');
    await page.press('Escape');
    await page.settle();
    await page.press('Escape');
    await page.settle();
    assert.equal(await page.eval('window.__confirmCalls'), 2);
    assert.equal(await page.eval("document.querySelector('#settings-dialog').open"), true);
    assert.equal(await page.eval("document.querySelector('#source-name').value"), 'Linux host 2');
  }
);

test('editing a source that was removed elsewhere explains what happened', { skip }, async () => {
  const page = await open();
  const loads = requests('GET', '/api/dashboard').length;
  await page.eval(`(() => {
    const button = document.createElement('button');
    button.dataset.configure = 'gone';
    document.body.append(button);
    button.click();
  })()`);
  await page.settle();
  assert.deepEqual(page.exceptions, []);
  assert.equal(await page.eval("document.querySelector('#settings-dialog').open"), false);
  assert.match(await text(page, '#toast'), /no longer exists/);
  assert.ok(requests('GET', '/api/dashboard').length > loads, 'reloads the latest data');
});

test('the source list and sidebar count follow the dashboard poll', { skip }, async () => {
  const page = await open('#configure/sources');
  await page.waitFor("document.querySelector('#configured-sources article')");
  assert.equal(await text(page, '#configuration-nav a[href="#configure/sources"] small'), '1');
  mock.dashboard.config.services.push(source({ id: 'linux-2', name: 'Second host' }));
  mock.dashboard.services.push(sourceState({ id: 'linux-2' }));
  mock.dashboard.services[0].status = 'error';
  await page.poll();
  assert.equal(await text(page, '#configuration-nav a[href="#configure/sources"] small'), '2');
  assert.equal(await text(page, '#source-results-count'), '2 of 2 sources');
  assert.match(await text(page, '#configured-sources'), /Check failed/);
});

test('website and bookmark cards describe their real collector', { skip }, async () => {
  mock.dashboard.config.services = [
    source({
      id: 'site',
      type: 'http',
      name: 'Site',
      collector: 'none',
      url: 'https://site.test',
      labels: ['Response', 'Available'],
    }),
    source({
      id: 'link-3',
      type: 'link',
      name: 'Heimdall',
      collector: 'http',
      apiUrl: '',
      url: 'https://heimdall.test',
      labels: [],
    }),
  ];
  mock.dashboard.services = [
    sourceState({
      id: 'site',
      status: 'link',
      configured: false,
      collector: 'none',
      metrics: [],
      lastSuccess: null,
    }),
    sourceState({
      id: 'link-3',
      status: 'error',
      configured: true,
      collector: 'http',
      metrics: [],
      lastSuccess: null,
      error: 'Connection timed out',
    }),
  ];
  const page = await open();
  assert.equal(
    await page.eval('!!document.querySelector(\'[data-id="site"] .mini-metrics\')'),
    false
  );
  assert.ok(await page.eval('document.querySelector(\'[data-id="site"] .utility-note\')'));
  await expand(page, 'link-3');
  const button = await text(page, '#detail-link-3 .empty-history button');
  assert.match(button, /Edit connection/);
  assert.doesNotMatch(await text(page, '#detail-link-3'), /Connect Heimdall|Ready when you are/);
});

test('native integrations hide the mapping and path fields they ignore', { skip }, async () => {
  mock.dashboard.config.services.push(
    source({ id: 'sonarr', type: 'sonarr', name: 'Sonarr', labels: ['Queue'] }),
    source({ id: 'site', type: 'http', name: 'Site', url: 'https://site.test', labels: [] })
  );
  const page = await open();
  const visible = selector =>
    page.eval(`!document.querySelector(${js(selector)}).closest('[hidden]')`);
  await openDrawer(page, 'sonarr');
  assert.equal(await visible('#metric-mappings'), false);
  assert.equal(await visible('#metric-path'), false);
  await page.eval("document.querySelector('#settings-dialog').close()");
  await openDrawer(page, 'linux');
  assert.equal(await visible('#metric-mappings'), true);
  assert.equal(await visible('#metric-path'), true);
  await page.eval("document.querySelector('#settings-dialog').close()");
  await openDrawer(page, 'site');
  assert.equal(await visible('#metric-mappings'), false);
  assert.equal(await visible('#metric-path'), true);
});

test('history CSV exports start with a UTF-8 byte order mark', { skip }, async () => {
  const page = await open();
  await expand(page);
  await page.eval(`(() => {
    URL.createObjectURL = blob => ((window.__blob = blob), 'blob:orbit-test');
    HTMLAnchorElement.prototype.click = () => {};
    document.querySelector('[data-export-history]').click();
  })()`);
  await page.waitFor('window.__blob');
  const bytes = await page.eval(
    'window.__blob.arrayBuffer().then(b => [...new Uint8Array(b, 0, 3)])'
  );
  assert.deepEqual(bytes, [0xef, 0xbb, 0xbf]);
});

test(
  'history CSV neutralises formulas in upstream labels, keys, units and error text',
  { skip },
  async () => {
    // Keys, labels and units come from a source's API and errors describe what it sent: a
    // spreadsheet must show them as text, never run them.
    const time = Date.now();
    mock.history = () => ({
      from: time - 3600000,
      to: time,
      totalSamples: 2,
      maxGapMs: 3600000,
      pollSeconds: 60,
      points: [
        {
          time: time - 120000,
          ok: true,
          gapBefore: false,
          metrics: [{ key: '+cmd', label: '=HYPERLINK("http://x","y")', value: -1, unit: '@x' }],
        },
        { time: time - 60000, ok: false, gapBefore: false, metrics: [], error: '-1+2' },
      ],
    });
    const page = await open();
    await expand(page);
    await page.eval(`(() => {
      URL.createObjectURL = blob => ((window.__blob = blob), 'blob:orbit-test');
      HTMLAnchorElement.prototype.click = () => {};
      document.querySelector('[data-export-history]').click();
    })()`);
    await page.waitFor('window.__blob');
    const rows = (await page.eval('window.__blob.text()')).replace(/^\ufeff/, '').split('\r\n');
    const [, reading, failure] = rows;
    assert.match(
      reading,
      /^"[^"]+","ok","false","'\+cmd","'=HYPERLINK\(""http:\/\/x"",""y""\)",-1,"'@x",""$/
    );
    assert.match(failure, /^"[^"]+","failed","false","","","","","'-1\+2"$/);
  }
);

test(
  'Back after declining to discard changes keeps the history stack intact',
  { skip },
  async () => {
    const page = await open('#configure/appearance');
    await page.waitFor("document.querySelector('#workspace-title')");
    await page.eval("location.hash = '#configure/monitoring'");
    await page.waitFor("document.querySelector('#poll-seconds')");
    await page.eval("location.hash = '#configure/appearance'");
    await page.waitFor("document.querySelector('#workspace-title')");
    await setValue(page, '#workspace-title', 'Uptime Goblin 2');
    await page.eval('window.__confirmAnswer = false; history.back()');
    await delay(300);
    await page.settle();
    assert.equal(await page.eval('location.hash'), '#configure/appearance');
    assert.equal(
      await page.eval("document.querySelector('#workspace-title').value"),
      'Uptime Goblin 2'
    );
    await page.eval('window.__confirmAnswer = true; history.back()');
    await page.waitFor(
      "location.hash === '#configure/monitoring' && document.querySelector('#poll-seconds')",
      2000
    );
    assert.equal(await page.eval('window.__confirmCalls'), 2);
  }
);

test(
  'a time zone this browser rejects falls back to local time instead of blanking the page',
  { skip },
  async () => {
    mock.dashboard.config.appearance.timezone = 'Bogus/Zone';
    const page = await open();
    assert.equal(await page.eval("document.querySelectorAll('#services article').length"), 1);
    assert.notEqual(await text(page, '#connection'), 'Collector unavailable');
    assert.notEqual(await text(page, '#clock'), '');
    await page.eval("location.hash = '#configure/appearance'");
    await page.waitFor("document.querySelector('#workspace-title')");
    assert.match(await text(page, '#timezone-note'), /Bogus\/Zone/);
    assert.equal(
      await page.eval("document.querySelector('#appearance-timezone').value"),
      'Bogus/Zone'
    );
  }
);

test(
  'source writes carry the drawer revision and a conflict keeps the draft',
  { skip },
  async () => {
    mock.routes.set('PATCH /api/services/linux', () => ({
      status: 409,
      body: { error: 'Changed elsewhere', revision: 8 },
    }));
    mock.routes.set('DELETE /api/services/linux', () => ({
      status: 409,
      body: { error: 'Changed elsewhere', revision: 8 },
    }));
    const page = await open();
    await openDrawer(page);
    await setValue(page, '#source-name', 'Renamed host');
    mock.dashboard.config.revision = 8;
    const loads = requests('GET', '/api/dashboard').length;
    await page.eval("document.querySelector('#connection-form [type=submit]').click()");
    await page.waitFor("!document.querySelector('#form-error').hidden");
    await page.settle();
    assert.equal(requests('PATCH', '/api/services/linux')[0].headers['if-match'], '7');
    assert.match(await text(page, '#form-error'), /another device/);
    assert.equal(await page.eval("document.querySelector('#settings-dialog').open"), true);
    assert.equal(await page.eval("document.querySelector('#source-name').value"), 'Renamed host');
    assert.ok(requests('GET', '/api/dashboard').length > loads, 'reloads the latest data');

    await page.eval("document.querySelector('#form-error').hidden = true");
    mock.dashboard.config.services[0].group = 'Changed elsewhere';
    await page.eval("document.querySelector('#delete-source').click()");
    await page.settle();
    assert.equal(requests('DELETE', '/api/services/linux')[0].headers['if-match'], '7');
    assert.equal(await page.eval("document.querySelector('#settings-dialog').open"), true);
    assert.match(await text(page, '#form-error'), /another device/);
    assert.equal(await page.eval("document.querySelector('#form-error').hidden"), false);

    // The user can then replace the draft with the latest saved settings.
    await page.eval("document.querySelector('[data-reload-source]').click()");
    await page.settle();
    assert.equal(
      await page.eval("document.querySelector('#source-group').value"),
      'Changed elsewhere'
    );
  }
);

test(
  'a blocked conflict reload keeps the draft protected until it can be discarded',
  { skip },
  async () => {
    const page = await open();
    await openDrawer(page);
    await setValue(page, '#source-name', 'Keep this draft');
    mock.dashboard.config.revision++;
    mock.dashboard.config.services[0].name = 'Changed elsewhere';
    let release;
    const heldReload = new Promise(resolve => (release = resolve));
    mock.routes.set('GET /api/dashboard', async () => {
      await heldReload;
      return { body: mock.dashboard };
    });
    try {
      await click(page, '#connection-form [type=submit]');
      await page.waitFor("document.querySelector('[data-reload-source]')");
      await click(page, '[data-reload-source]');
      assert.match(await text(page, '#toast'), /Finishing the connection change/);
      assert.equal(
        await page.eval("document.querySelector('#source-name').value"),
        'Keep this draft'
      );
      assert.equal(await page.eval("document.querySelector('#source-name').disabled"), true);
      await page.press('Escape');
      assert.equal(await page.eval('window.__confirmCalls'), 0, 'the pending change stays locked');
      assert.equal(await page.eval("document.querySelector('#settings-dialog').open"), true);
    } finally {
      release();
    }
    await page.settle();
    await page.eval('window.__confirmAnswer = false');
    await page.press('Escape');
    assert.equal(
      await page.eval('window.__confirmCalls'),
      1,
      'a refused reload never clears the baseline'
    );
    assert.equal(await page.eval("document.querySelector('#settings-dialog').open"), true);
    assert.equal(
      await page.eval("document.querySelector('#source-name').value"),
      'Keep this draft'
    );
    // This button itself expresses the discard choice; it needs no second confirmation.
    await click(page, '[data-reload-source]');
    assert.equal(await page.eval('window.__confirmCalls'), 1);
    assert.equal(
      await page.eval("document.querySelector('#source-name').value"),
      'Changed elsewhere'
    );
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'pausing a source from the dashboard sends the revision it was drawn from',
  { skip },
  async () => {
    const page = await open();
    await page.eval('document.querySelector(\'[data-toggle="linux"]\').click()');
    await page.settle();
    assert.equal(requests('PATCH', '/api/services/linux')[0].headers['if-match'], '7');
  }
);

test(
  'settings writes carry the page revision, and clean forms follow other devices',
  { skip },
  async () => {
    mock.routes.set('PATCH /api/settings', () => ({
      status: 409,
      body: { error: 'Changed elsewhere', revision: 8 },
    }));
    const page = await open('#configure/alerts');
    await page.waitFor("document.querySelector('#alerts-recovery')");
    await page.eval("document.querySelector('#alerts-recovery').click()");
    mock.dashboard.config.revision = 8;
    await page.eval("document.querySelector('#settings-form [type=submit]').click()");
    await page.waitFor("!document.querySelector('#settings-error').hidden");
    await page.settle();
    assert.equal(requests('PATCH', '/api/settings')[0].headers['if-match'], '7');
    assert.match(await text(page, '#settings-error'), /another device/);
    assert.equal(await page.eval("document.querySelector('#alerts-recovery').checked"), false);

    // Discarding loads the latest values; a clean form then follows later changes.
    await page.eval("document.querySelector('[data-discard]').click()");
    await page.settle();
    mock.dashboard.config.alerts.enabled = false;
    mock.dashboard.config.revision = 9;
    await page.poll();
    assert.equal(await page.eval("document.querySelector('#alerts-enabled').checked"), false);
  }
);

/** Adds sources as [id, name, group] next to the default 'linux' one. */
function addHosts(...hosts) {
  for (const [id, name, group = 'Servers'] of hosts) {
    mock.dashboard.config.services.push(source({ id, name, group }));
    mock.dashboard.services.push(sourceState({ id }));
  }
}
/** Holds back the dashboard reload that follows a write, as a slow link would. */
function slowReload(ms) {
  mock.routes.set('GET /api/dashboard', () => ({ delay: ms, body: mock.dashboard }));
}
/** Answers writes to this path as usual, but only after `ms`. */
function slowWrites(method, path, ms) {
  mock.routes.set(`${method} ${path}`, request => ({
    ...defaultRoute(method, request.url, request),
    delay: ms,
  }));
}
async function waitForRequests(method, prefix, count) {
  const end = Date.now() + 5000;
  while (requests(method, prefix).length < count) {
    if (Date.now() > end) throw new Error(`Timed out waiting for ${method} ${prefix}`);
    await delay(10);
  }
}
/** Configuration writes as "METHOD path If-Match". */
const writes = () =>
  mock.requests
    .filter(r => r.method !== 'GET' && r.path !== '/api/refresh')
    .map(r => `${r.method} ${r.path} ${r.headers['if-match'] ?? '-'}`);
async function recordToasts(page) {
  await page.eval(`(() => {
    window.__toasts = [];
    const toast = document.querySelector('#toast');
    new MutationObserver(() => window.__toasts.push(toast.textContent)).observe(toast, {
      childList: true,
      characterData: true,
      subtree: true,
    });
  })()`);
}
const click = (page, selector) => page.eval(`document.querySelector(${js(selector)}).click()`);
const drawerSettled =
  "!document.querySelector('#settings-dialog').open || !document.querySelector('#form-error').hidden";

test(
  'a second quick change in the same tab builds on the revision the first one created',
  { skip },
  async () => {
    addHosts(['linux-2', 'Second host']);
    const page = await open('#configure/sources');
    await page.waitFor("document.querySelector('#configured-sources article')");
    await recordToasts(page);
    // The reload after the first write is still on its way when the second click comes.
    slowReload(600);
    const loads = requests('GET', '/api/dashboard').length;
    await click(page, '#configured-sources [data-toggle="linux"]');
    await waitForRequests('GET', '/api/dashboard', loads + 1);
    await click(page, '#configured-sources [data-visibility="linux-2"]');
    await page.settle();
    assert.deepEqual(writes(), ['PATCH /api/services/linux 7', 'PATCH /api/services/linux-2 8']);
    assert.equal(mock.dashboard.config.services[0].enabled, false);
    assert.equal(mock.dashboard.config.services[1].showOnDashboard, false);
    assert.ok(!(await page.eval('window.__toasts')).some(t => /another device/.test(t)));
  }
);

test(
  'a click while this tab’s previous write is still out waits for it instead of conflicting',
  { skip },
  async () => {
    addHosts(['linux-2', 'Second host']);
    slowWrites('PATCH', '/api/services/linux', 300);
    const page = await open();
    await recordToasts(page);
    await click(page, '.pause-control[data-toggle="linux"]');
    await delay(40);
    await click(page, '.pause-control[data-toggle="linux-2"]');
    await waitForRequests('PATCH', '/api/services/linux-2', 1);
    await page.settle();
    assert.deepEqual(writes(), ['PATCH /api/services/linux 7', 'PATCH /api/services/linux-2 8']);
    assert.deepEqual(
      mock.dashboard.config.services.map(s => s.enabled),
      [false, false]
    );
    assert.ok(!(await page.eval('window.__toasts')).some(t => /another device/.test(t)));
  }
);

test(
  'a drawer opened just after a save starts from the revision that save created',
  { skip },
  async () => {
    addHosts(['linux-2', 'Second host']);
    const page = await open();
    slowReload(600);
    await openDrawer(page, 'linux');
    await setValue(page, '#source-name', 'Renamed host');
    await click(page, '#connection-form [type=submit]');
    await page.waitFor("!document.querySelector('#settings-dialog').open");
    await openDrawer(page, 'linux-2');
    await setValue(page, '#source-group', 'Media');
    // Every reload has finished before this save.
    await page.settle();
    await click(page, '#connection-form [type=submit]');
    await page.waitFor(drawerSettled);
    await page.settle();
    assert.deepEqual(writes(), ['PATCH /api/services/linux 7', 'PATCH /api/services/linux-2 8']);
    assert.equal(await page.eval("document.querySelector('#settings-dialog').open"), false);
    assert.equal(mock.dashboard.config.services[1].group, 'Media');
  }
);

test(
  'a drawer for a source this tab just paused shows the pause and never saves over it',
  { skip },
  async () => {
    addHosts(['linux-2', 'Second host']);
    const page = await open();
    slowReload(600);
    // Opened after the pause was saved, before the reload: the drawer shows it paused.
    let loads = requests('GET', '/api/dashboard').length;
    await click(page, '.pause-control[data-toggle="linux"]');
    await waitForRequests('GET', '/api/dashboard', loads + 1);
    await openDrawer(page, 'linux');
    assert.equal(await page.eval("document.querySelector('#source-enabled').checked"), false);
    await setValue(page, '#source-group', 'Media');
    await click(page, '#connection-form [type=submit]');
    await page.waitFor(drawerSettled);
    await page.settle();
    assert.deepEqual(writes(), ['PATCH /api/services/linux 7', 'PATCH /api/services/linux 8']);
    assert.equal(mock.dashboard.config.services[0].enabled, false);
    assert.equal(mock.dashboard.config.services[0].group, 'Media');

    // Opened while the pause is still on its way, the drawer shows the source as it was, so
    // its save is refused instead of silently resuming the source.
    slowWrites('PATCH', '/api/services/linux-2', 300);
    loads = requests('GET', '/api/dashboard').length;
    await click(page, '.pause-control[data-toggle="linux-2"]');
    await openDrawer(page, 'linux-2');
    assert.equal(await page.eval("document.querySelector('#source-enabled').checked"), true);
    await setValue(page, '#source-group', 'Media');
    await waitForRequests('GET', '/api/dashboard', loads + 1);
    await page.settle();
    await click(page, '#connection-form [type=submit]');
    await page.waitFor(drawerSettled);
    await page.settle();
    assert.deepEqual(writes().slice(2), [
      'PATCH /api/services/linux-2 9',
      'PATCH /api/services/linux-2 9',
    ]);
    assert.match(await text(page, '#form-error'), /another device/);
    assert.equal(mock.dashboard.config.services[1].enabled, false);
  }
);

test('adding or removing a source lets the next quick change build on it', { skip }, async () => {
  addHosts(['linux-2', 'Second host']);
  const page = await open();
  slowReload(600);
  await click(page, '#add-source');
  await page.waitFor("document.querySelector('#settings-dialog').open");
  await setValue(page, '#source-name', 'New host');
  await click(page, '#connection-form [type=submit]');
  await page.waitFor("!document.querySelector('#settings-dialog').open");
  await click(page, '.pause-control[data-toggle="linux"]');
  await page.settle();
  await openDrawer(page, 'linux-2');
  await click(page, '#delete-source');
  await page.waitFor("!document.querySelector('#settings-dialog').open");
  await click(page, '.pause-control[data-toggle="linux"]');
  await page.settle();
  // Adding a source names its revision too, so a retry after a lost answer cannot add it twice.
  assert.deepEqual(writes(), [
    'POST /api/services 7',
    'PATCH /api/services/linux 8',
    'DELETE /api/services/linux-2 9',
    'PATCH /api/services/linux 10',
  ]);
  assert.deepEqual(
    mock.dashboard.config.services.map(s => [s.name, s.enabled]),
    [
      ['Linux host', true],
      ['New host', true],
    ]
  );
});

test('removing a source keeps its drawer locked until the outcome is known', { skip }, async () => {
  addHosts(['linux-2', 'Second host']);
  slowWrites('DELETE', '/api/services/linux', 500);
  const page = await open();
  await openDrawer(page, 'linux');
  await click(page, '#delete-source');
  await waitForRequests('DELETE', '/api/services/linux', 1);

  // A delayed removal must not let the user start a second source's draft and then close
  // that draft when the first source's response arrives.
  await setValue(page, '#source-picker', 'linux-2');
  assert.equal(await page.eval("document.querySelector('#source-picker').value"), 'linux');
  assert.equal(await page.eval("document.querySelector('#source-name').disabled"), true);
  await page.press('Escape');
  assert.equal(await page.eval("document.querySelector('#settings-dialog').open"), true);
  await page.waitFor("!document.querySelector('#settings-dialog').open");
  await page.settle();
  assert.deepEqual(writes(), ['DELETE /api/services/linux 7']);
  assert.equal(mock.dashboard.config.services[0].name, 'Second host');
  assert.deepEqual(page.exceptions, []);
});

test(
  'a refused source removal unlocks the original draft and connection test',
  { skip },
  async () => {
    mock.routes.set('DELETE /api/services/linux', () => ({
      status: 500,
      body: { error: 'Could not save configuration' },
    }));
    const page = await open();
    await openDrawer(page);
    await setValue(page, '#source-name', 'Keep this draft');
    await click(page, '#delete-source');
    await page.settle();
    assert.equal(await page.eval("document.querySelector('#settings-dialog').open"), true);
    assert.equal(
      await page.eval("document.querySelector('#source-name').value"),
      'Keep this draft'
    );
    for (const selector of ['#source-name', '#test-connection', '#delete-source'])
      assert.equal(await page.eval(`document.querySelector(${js(selector)}).disabled`), false);
    assert.match(await text(page, '#toast'), /Could not save configuration/);
    assert.deepEqual(page.exceptions, []);
  }
);

for (const action of ['remove', 'discard'])
  test(`after a conflict, ${action} closes the editor for a missing source`, { skip }, async () => {
    mock.routes.set('DELETE /api/services/linux', () => {
      mock.dashboard.config.services = [];
      mock.dashboard.config.revision++;
      return { status: 409, body: { error: 'Changed elsewhere' } };
    });
    const page = await open();
    await openDrawer(page);
    await click(page, '#delete-source');
    await page.settle();
    assert.match(await text(page, '#form-error'), /another device/);
    await click(page, action === 'remove' ? '#delete-source' : '[data-reload-source]');
    await page.waitFor("!document.querySelector('#settings-dialog').open");
    await page.settle();
    assert.match(await text(page, '#toast'), /source no longer exists/);
    assert.equal(requests('DELETE', '/api/services/linux').length, 1);
    assert.equal(
      await page.eval('window.__confirmCalls'),
      1,
      'only the original removal was confirmed'
    );
    assert.deepEqual(page.exceptions, []);
  });

for (const action of ['save', 'remove']) {
  test(`a refused ${action} clears the canceled connection test status`, { skip }, async () => {
    let releaseTest;
    const pendingTest = new Promise(resolve => (releaseTest = resolve));
    mock.routes.set('POST /api/test-service', async () => {
      await pendingTest;
      return { body: { metrics: metrics(), notes: [], elapsedMs: 100 } };
    });
    mock.routes.set(`${action === 'save' ? 'PATCH' : 'DELETE'} /api/services/linux`, () => ({
      status: 500,
      body: { error: 'Could not save configuration' },
    }));
    const page = await open();
    await openDrawer(page);
    await setValue(page, '#source-name', 'Keep this draft');
    await click(page, '#test-connection');
    await waitForRequests('POST', '/api/test-service', 1);
    assert.match(await text(page, '#connection-test'), /Connecting/);
    try {
      await click(page, action === 'save' ? '#connection-form [type=submit]' : '#delete-source');
      await page.settle();
      assert.equal(await page.eval("document.querySelector('#connection-test').hidden"), true);
      assert.equal(
        await page.eval("document.querySelector('#source-name').value"),
        'Keep this draft'
      );
      assert.equal(await page.eval("document.querySelector('#test-connection').disabled"), false);
      assert.equal(await text(page, '#test-connection'), 'Test connection');
    } finally {
      releaseTest();
    }
    // The canceled response cannot revive the old status, and a fresh test still works.
    await page.settle();
    assert.equal(await page.eval("document.querySelector('#connection-test').hidden"), true);
    await click(page, '#test-connection');
    await page.settle();
    assert.match(await text(page, '#connection-test'), /Connected/);
    // A completed test remains useful when an unrelated save/removal is refused.
    await click(page, action === 'save' ? '#connection-form [type=submit]' : '#delete-source');
    await page.settle();
    assert.equal(await page.eval("document.querySelector('#connection-test').hidden"), false);
    assert.match(await text(page, '#connection-test'), /Connected/);
    assert.deepEqual(page.exceptions, []);
  });

  test(
    `a completed ${action} does not lock a new drawer during its dashboard reload`,
    { skip },
    async () => {
      addHosts(['linux-2', 'Second host']);
      const page = await open();
      await openDrawer(page);
      let releaseReload;
      const pendingReload = new Promise(resolve => (releaseReload = resolve));
      mock.routes.set('GET /api/dashboard', async () => {
        await pendingReload;
        return { body: mock.dashboard };
      });
      try {
        await click(page, action === 'save' ? '#connection-form [type=submit]' : '#delete-source');
        await page.waitFor("!document.querySelector('#settings-dialog').open");
        await openDrawer(page, 'linux-2');
        await setValue(page, '#source-name', 'A fresh unsaved draft');
        await page.eval('window.__confirmCalls = 0; window.__confirmAnswer = false');
        await page.press('Escape');
        assert.equal(
          await page.eval('window.__confirmCalls'),
          1,
          'the new draft asks before discarding'
        );
        assert.equal(await page.eval("document.querySelector('#settings-dialog').open"), true);
        assert.equal(
          await page.eval("document.querySelector('#source-name').value"),
          'A fresh unsaved draft'
        );
        await page.eval('window.__confirmAnswer = true');
        await page.press('Escape');
        await page.waitFor("!document.querySelector('#settings-dialog').open");
      } finally {
        releaseReload();
      }
      await page.settle();
      assert.deepEqual(page.exceptions, []);
    }
  );
}

for (const action of ['save', 'remove'])
  test(
    `${action} of a source already deleted on another device closes its stale editor`,
    { skip },
    async t => {
      const orbit = await startOrbit({ directory: temporaryDirectory(t) });
      t.after(() => orbit.close());
      // Uptime Goblin always requires a password: the page is signed in by the session cookie, which the
      // mocked Uptime Goblin of the other tests must not see afterwards.
      await signInBrowser(cdp, orbit);
      t.after(() => cdp.send('Storage.clearCookies'));
      const page = await openPage(cdp, orbit.url + '/', {
        prelude,
        ready: "document.querySelector('#services article')",
      });
      t.after(() => page.close());
      await openDrawer(page, 'linux');
      if (action === 'save') await setValue(page, '#source-name', 'A draft for the removed source');
      // Real Uptime Goblin answers 404 for an absent source before comparing If-Match revisions.
      assert.equal((await call(orbit.url, '/api/services/linux', 'DELETE', {})).status, 200);
      await click(page, action === 'save' ? '#connection-form [type=submit]' : '#delete-source');
      await page.waitFor("!document.querySelector('#settings-dialog').open");
      await page.waitFor("!document.querySelector('#services article[data-id=linux]')");
      assert.equal(await page.eval('window.__confirmCalls'), action === 'save' ? 0 : 1);
      assert.match(await text(page, '#toast'), /already removed|no longer exists/);
      await openDrawer(page, 'proxmox');
      assert.equal(
        await page.eval("!!document.querySelector('#source-picker option[value=linux]')"),
        false
      );
      assert.deepEqual(page.exceptions, []);
    }
  );

test(
  'a settings save counts for the next change even when the reload after it fails',
  { skip },
  async () => {
    const page = await open('#configure/alerts');
    await page.waitFor("document.querySelector('#alerts-recovery')");
    mock.routes.set('GET /api/dashboard', () => {
      mock.routes.delete('GET /api/dashboard');
      return { status: 502, body: { error: 'Bad gateway' } };
    });
    await click(page, '#alerts-recovery');
    await click(page, '#settings-form [type=submit]');
    await page.waitFor("/saved/.test(document.querySelector('#toast').textContent)");
    await page.eval("location.hash = '#configure/sources'");
    await page.waitFor("document.querySelector('#configured-sources article')");
    await click(page, '#configured-sources [data-toggle="linux"]');
    await page.settle();
    assert.deepEqual(writes(), ['PATCH /api/settings 7', 'PATCH /api/services/linux 8']);
    assert.equal(mock.dashboard.config.services[0].enabled, false);
  }
);

const historyRequests = () => requests('GET', '/api/history/').length;
const chartLabel = page =>
  page.eval("document.querySelector('#graph-linux svg.chart')?.getAttribute('aria-label') ?? ''");
async function openChart(page, chosen) {
  await expand(page);
  await click(page, `[data-range="${chosen}"]`);
  await page.waitFor("document.querySelector('#graph-linux svg.chart')");
  await page.settle();
}

test(
  'pausing the open card’s source redraws its chart, and a paused chart keeps moving',
  { skip },
  async () => {
    mock.routes.set('PATCH /api/services/linux', request => {
      mock.dashboard.services[0].status = 'disabled';
      return defaultRoute('PATCH', request.url, request);
    });
    const page = await open();
    await openChart(page, '1h');
    let before = historyRequests();
    await click(page, '.pause-control[data-toggle="linux"]');
    await page.settle();
    assert.equal(historyRequests(), before + 1, 'the pause is drawn at once');
    // A paused source records no new readings, but its window still moves on.
    before = historyRequests();
    await page.poll();
    assert.equal(historyRequests(), before, 'not on every poll');
    await page.eval('window.__skew = 60 * 60 * 1000');
    await page.poll();
    assert.equal(historyRequests(), before + 1, 'once the window has moved by a bucket');
    // A status change made elsewhere is drawn at once too.
    mock.dashboard.services[0].status = 'live';
    await page.poll();
    assert.equal(historyRequests(), before + 2);
  }
);

test('Refresh shows the refreshed reading in the open chart', { skip }, async () => {
  mock.dashboard.config.services[0].pollSeconds = 3600;
  let value = 50;
  mock.history = (id, range) => ({ ...history(range, () => value), pollSeconds: 3600 });
  // The collector answers a moment after the refresh request, as it does in Uptime Goblin.
  mock.routes.set('POST /api/refresh', () => {
    setTimeout(() => {
      const state = mock.dashboard.services[0];
      value = 90;
      state.metrics = metrics(90);
      state.lastAttempt = state.lastSuccess = Date.now();
    }, 300);
    return { status: 202, body: { ok: true } };
  });
  const page = await open();
  await openChart(page, '1h');
  assert.match(await chartLabel(page), /highest 50%/);
  await click(page, '#refresh');
  await page.waitFor(
    "/highest 90%/.test(document.querySelector('#graph-linux svg.chart')?.getAttribute('aria-label'))",
    4000
  );
});

test(
  'a measurement added by saving the open card’s source is charted with its next reading',
  { skip },
  async () => {
    let added = false;
    const temp = { key: 'temp', label: 'Temp', value: 42, unit: '' };
    mock.history = (id, range) => {
      const result = history(range);
      if (added) result.points.at(-1).metrics.push(temp);
      return result;
    };
    const page = await open();
    await openChart(page, '7d');
    const before = historyRequests();
    await openDrawer(page);
    await click(page, '#connection-form [type=submit]');
    await page.waitFor("!document.querySelector('#settings-dialog').open");
    await page.settle();
    assert.equal(historyRequests(), before + 1, 'refetched after the save');
    // The server can finish before Chrome consumes its response, especially under load.
    await page.eval('window.__bodyDelay = 350');
    added = true;
    const state = mock.dashboard.services[0];
    state.metrics = [...metrics(), temp];
    state.lastAttempt = state.lastSuccess = Date.now() + 1;
    await page.poll();
    assert.equal(historyRequests(), before + 2, 'refetched with the next reading');
    // The chart asks only for the measurement it draws, so choosing another one fetches it.
    await setValue(page, '#metric-select', 'temp');
    await page.settle();
    assert.match(await chartLabel(page), /^Temp history/);
    assert.equal(historyRequests(), before + 3);
    assert.equal(requests('GET', '/api/history/').at(-1).url.searchParams.get('metric'), 'temp');
    // After that, the 7-day chart waits for its window to move on again.
    state.lastAttempt = Date.now() + 2;
    await page.poll();
    assert.equal(historyRequests(), before + 3);
  }
);

/** Remembers the cards, the open chart and the focused element before a poll. */
async function rememberCards(page, focus) {
  await page.eval(`(() => {
    window.__cards = Object.fromEntries(
      [...document.querySelectorAll('#services article[data-id]')].map(a => [a.dataset.id, a])
    );
    window.__groups = [...document.querySelectorAll('#services section')];
    window.__chart = document.querySelector('svg.chart');
    window.__select = document.querySelector('#metric-select');
    document.querySelector(${js(focus)}).focus();
    window.__focused = document.activeElement;
  })()`);
}
const cardsAfterPoll = page =>
  page.eval(`({
    order: [...document.querySelectorAll('#services article[data-id]')].map(a => a.dataset.id),
    rebuilt: [...document.querySelectorAll('#services article[data-id]')]
      .filter(a => window.__cards[a.dataset.id] !== a)
      .map(a => a.dataset.id),
    sameGroups: [...document.querySelectorAll('#services section')].every(s => window.__groups.includes(s)),
    sameChart: document.querySelector('svg.chart') === window.__chart,
    sameSelect: document.querySelector('#metric-select') === window.__select,
    focusKept: document.activeElement === window.__focused,
  })`);

test(
  'a poll that reorders cards moves them, keeping the open chart and its focus',
  { skip },
  async () => {
    mock.dashboard.config.appearance.sortBy = 'status';
    addHosts(['linux-2', 'Second host'], ['linux-3', 'Third host']);
    const page = await open();
    await expand(page);
    await page.waitFor("document.querySelector('#graph-linux svg.chart')");
    // Cards after the open one move in front of it.
    await rememberCards(page, '[data-id="linux"] [data-range="7d"]');
    mock.dashboard.services[1].status = 'error';
    await page.poll();
    assert.deepEqual(await cardsAfterPoll(page), {
      order: ['linux-2', 'linux', 'linux-3'],
      rebuilt: [],
      sameGroups: true,
      sameChart: true,
      sameSelect: true,
      focusKept: true,
    });
    // The open card moves in front of the others.
    await rememberCards(page, '#metric-select');
    await page.eval('window.__bodyDelay = 350');
    mock.dashboard.services[1].status = 'live';
    mock.dashboard.services[0].status = 'error';
    await page.poll();
    assert.deepEqual(await cardsAfterPoll(page), {
      order: ['linux', 'linux-2', 'linux-3'],
      rebuilt: [],
      sameGroups: true,
      sameChart: true,
      sameSelect: true,
      focusKept: true,
    });
    await rememberCards(page, '#graph-linux svg.chart');
    mock.dashboard.services[0].status = 'live';
    mock.dashboard.services[2].status = 'stale';
    await page.poll();
    assert.deepEqual(await cardsAfterPoll(page), {
      order: ['linux-3', 'linux', 'linux-2'],
      rebuilt: [],
      sameGroups: true,
      sameChart: true,
      sameSelect: true,
      focusKept: true,
    });
  }
);

test('a poll that reorders groups keeps the open chart and its focus', { skip }, async () => {
  mock.dashboard.config.appearance.sortBy = 'status';
  addHosts(['linux-2', 'Second host', 'Media']);
  const page = await open();
  await expand(page);
  await page.waitFor("document.querySelector('#graph-linux svg.chart')");
  await rememberCards(page, '[data-id="linux"] [data-range="7d"]');
  mock.dashboard.services[1].status = 'error';
  await page.poll();
  assert.deepEqual(
    await page.eval("[...document.querySelectorAll('#services h2')].map(h => h.textContent)"),
    ['Media', 'Servers']
  );
  assert.deepEqual(await cardsAfterPoll(page), {
    order: ['linux-2', 'linux'],
    rebuilt: [],
    sameGroups: true,
    sameChart: true,
    sameSelect: true,
    focusKept: true,
  });
});

test(
  'a dashboard snapshot taken before this tab’s write cannot roll its revision back',
  { skip },
  async () => {
    addHosts(['linux-2', 'Second host']);
    const page = await open('#configure/sources');
    await page.waitFor("document.querySelector('#configured-sources article')");
    await recordToasts(page);
    // The server builds this answer when the request arrives, before the write below, and
    // it reaches the browser after the write's own answer.
    let stale = true;
    mock.routes.set('GET /api/dashboard', () => {
      const body = structuredClone(mock.dashboard);
      const late = stale;
      stale = false;
      // The reload that follows is slow too, so the old snapshot is what the next click sees.
      return { body, delay: late ? 500 : 400 };
    });
    const loads = requests('GET', '/api/dashboard').length;
    await page.eval("document.dispatchEvent(new Event('visibilitychange'))");
    await waitForRequests('GET', '/api/dashboard', loads + 1);
    await click(page, '#configured-sources [data-toggle="linux"]');
    await waitForRequests('PATCH', '/api/services/linux', 1);
    // Let the old snapshot land, then act at once.
    await delay(550);
    await click(page, '#configured-sources [data-visibility="linux-2"]');
    await page.settle();
    assert.deepEqual(writes(), ['PATCH /api/services/linux 7', 'PATCH /api/services/linux-2 8']);
    assert.equal(mock.dashboard.config.services[1].showOnDashboard, false);
    assert.ok(!(await page.eval('window.__toasts')).some(t => /another device/.test(t)));
  }
);

test(
  'a long burst of quick changes on a slow link never falls back to an old revision',
  { skip },
  async () => {
    addHosts(['linux-2', 'Second host']);
    const page = await open('#configure/sources');
    await page.waitFor("document.querySelector('#configured-sources article')");
    await recordToasts(page);
    // Every dashboard answer reflects the moment its request arrived and lands 250 ms later,
    // so each reload overlaps the next quick change.
    mock.routes.set('GET /api/dashboard', () => ({
      body: structuredClone(mock.dashboard),
      delay: 300,
    }));
    for (let i = 0; i < 16; i++) {
      await click(page, `#configured-sources [data-toggle="${i % 2 ? 'linux-2' : 'linux'}"]`);
      await waitForRequests('PATCH', '/api/services/', i + 1);
      await delay(100);
    }
    await page.settle();
    assert.deepEqual(
      writes().map(w => w.split(' ').pop()),
      Array.from({ length: 16 }, (_, i) => String(7 + i))
    );
    assert.ok(!(await page.eval('window.__toasts')).some(t => /another device/.test(t)));
  }
);

test('the open chart asks only for the measurement it draws', { skip }, async () => {
  const page = await open();
  await expand(page);
  await page.waitFor("document.querySelector('#graph-linux svg.chart')");
  const asked = () =>
    requests('GET', '/api/history/').map(r => r.url.searchParams.getAll('metric'));
  assert.deepEqual(asked(), [['cpu']]);
  await setValue(page, '#metric-select', 'memory');
  await page.settle();
  assert.deepEqual(asked(), [['cpu'], ['memory']]);
  assert.match(await chartLabel(page), /^Memory history/);
  // The CSV export still has every measurement.
  await click(page, '[data-export-history="linux"]');
  await page.settle();
  assert.deepEqual(asked().at(-1), []);
});

// Browser tests once left every export in the user's own Downloads folder (about 800 files).
// Browser.setDownloadBehavior then sent finished downloads to the throwaway profile, but Chrome
// still wrote each download in progress in ~/Downloads (a hidden .com.google.Chrome.* file) and
// moved it from there: the developer's folder changed for a moment on every run, and a run killed
// mid-download could leave a file behind. Pages now cancel the downloads they start and record
// them (downloadGuard in helpers/cdp.mjs), so Chrome starts none.
test(
  'an export is recorded by the page, and neither Chrome nor ~/Downloads ever sees it',
  { skip },
  async () => {
    const home = path.join(os.homedir(), 'Downloads');
    const existed = fs.existsSync(home);
    // Names only, and only Chrome's or an export's, so the user's own downloads do not count.
    const related = name => /chrome|crdownload|unconfirmed|\.csv$|orbit|goblin/i.test(name);
    const listing = () => fs.readdirSync(home).filter(related).sort();
    const before = existed ? listing() : null;
    const touched = [];
    const watcher = existed
      ? fs.watch(home, (event, name) => {
          if (name === null || related(name)) touched.push(`${event} ${name}`);
        })
      : null;
    let recorded;
    try {
      const page = await open();
      await expand(page);
      await page.waitFor("document.querySelector('#graph-linux svg.chart')");
      await click(page, '[data-export-history="linux"]');
      await page.waitFor('window.__downloads.length === 1 && window.__downloads[0].text !== null');
      recorded = await page.eval('window.__downloads[0]');
      // Anything Chrome or the file system would still do arrives within this.
      await delay(500);
    } finally {
      watcher?.close();
    }
    assert.match(recorded.name, /^uptime-goblin-linux-.+\.csv$/);
    assert.match(recorded.type, /^text\/csv/);
    assert.match(recorded.text.slice(0, 40), /^\ufeff"timestamp_utc","status",/);
    assert.deepEqual(touched, [], `${home} was written to while the export ran`);
    // Chrome makes the profile's download folder only when it starts a download.
    const started = fs.existsSync(browser.downloads) ? fs.readdirSync(browser.downloads) : [];
    assert.deepEqual(started, [], 'Chrome started no download');
    if (existed) assert.deepEqual(listing(), before);
    else assert.equal(fs.existsSync(home), false, `${home} was created`);
  }
);

test('collector notes show on the card and in the connection test, as text', { skip }, async () => {
  const note = 'Only the first 512 measurements are kept. <img src=x>';
  mock.dashboard.services[0].notes = [{ code: 'measurements_capped', message: note }];
  mock.routes.set('POST /api/test-service', () => ({
    body: {
      ok: true,
      metrics: metrics(),
      notes: [{ code: 'unifi_devices_capped', message: 'Only the first 64 devices are read.' }],
      elapsedMs: 5,
      checkedAt: Date.now(),
    },
  }));
  const page = await open();
  assert.equal(await text(page, '#services article[data-id="linux"] .source-notes li'), note);
  assert.equal(await page.eval("document.querySelectorAll('#services img').length"), 0);
  await openDrawer(page);
  await click(page, '#test-connection');
  await page.waitFor("/Connected/.test(document.querySelector('#connection-test').textContent)");
  assert.match(await text(page, '#connection-test .source-notes'), /first 64 devices/);
  await page.eval("document.querySelector('#settings-dialog').close()");
  // A paused source shows none: its notes describe collections that are not running.
  mock.dashboard.config.services[0].enabled = false;
  await page.poll();
  assert.equal(await text(page, '#services article[data-id="linux"] .source-notes'), null);
});

test(
  'a fixed-offset time zone shows the same wall-clock time in any browser',
  { skip },
  async () => {
    Object.assign(mock.dashboard.config.appearance, { timezone: 'UTC+05:45', timeFormat: '24h' });
    mock.dashboard.services[0].lastSuccess = Date.UTC(2026, 0, 1, 0, 0);
    const shifted = ms => new Date(ms + (5 * 60 + 45) * 60000).toISOString().slice(11, 16);
    const page = await open();
    const clock = await text(page, '#clock');
    assert.ok(
      [shifted(Date.now()), shifted(Date.now() - 60000)].some(t => clock.includes(t)),
      clock
    );
    await expand(page);
    assert.match(await text(page, '#detail-linux .detail-top p'), /05:45/);
    await page.eval("location.hash = '#configure/appearance'");
    await page.waitFor("document.querySelector('#workspace-title')");
    assert.equal(await text(page, '#timezone-note'), '');
  }
);

test('a dashboard load stuck for three polls is dropped and started again', { skip }, async t => {
  const page = await open();
  // The dashboard request gets no answer, and (as for a throttled background timer) its
  // time limit does not fire either.
  let unhang = () => {};
  mock.routes.set('GET /api/dashboard', () => new Promise(resolve => (unhang = resolve)));
  t.after(() => {
    mock.routes.delete('GET /api/dashboard');
    unhang(null);
  });
  await page.eval('window.__holdTimers = true');
  const before = requests('GET', '/api/dashboard').length;
  await page.eval('window.__poll()');
  while (requests('GET', '/api/dashboard').length === before) await delay(10);
  // A poll soon after waits for it.
  await page.eval('window.__poll()');
  await delay(200);
  assert.equal(requests('GET', '/api/dashboard').length, before + 1);
  mock.routes.delete('GET /api/dashboard');
  mock.dashboard.config.title = 'Recovered';
  await page.eval('window.__perfSkew = 46000');
  await page.eval('window.__poll()');
  await page.waitFor("document.querySelector('#dashboard-title').textContent === 'Recovered'");
  assert.equal(requests('GET', '/api/dashboard').length, before + 2);
});

test(
  'each change carries its own Idempotency-Key; a hidden tab checks the version in the background',
  { skip },
  async () => {
    mock.routes.set('GET /api/version', () => ({
      body: { version: '1.4.3', build: 'abcdef012345' },
    }));
    const page = await open();
    for (let i = 0; i < 2; i++) {
      await click(page, '.pause-control[data-toggle="linux"]');
      await page.settle();
    }
    const keys = mock.requests
      .filter(r => r.method === 'PATCH')
      .map(r => r.headers['idempotency-key']);
    assert.equal(keys.length, 2);
    for (const key of keys)
      assert.match(key, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    assert.notEqual(keys[0], keys[1]);
    assert.equal(requests('GET', '/api/dashboard').at(-1).headers['idempotency-key'], undefined);
    // A visible tab polls the dashboard instead.
    await page.eval('window.__probe()');
    await page.settle();
    assert.equal(requests('GET', '/api/version').length, 0);
    await page.eval('window.__hidden = true');
    await page.eval('window.__probe()');
    await page.settle();
    const [probe] = requests('GET', '/api/version');
    assert.equal(probe.headers['x-goblin-activity'], 'background');
  }
);

test('the System page shows the build and the open tabs by version', { skip }, async () => {
  mock.routes.set('GET /api/system', () => ({
    body: {
      version: '1.4.3',
      build: 'abcdef012345',
      clients: [
        { build: 'abcdef012345', current: true, lastSeen: Date.now() },
        { build: '0123456789ab', current: false, lastSeen: Date.now() },
        { build: null, current: false, lastSeen: Date.now() },
      ],
      uptimeSeconds: 10,
      startedAt: Date.now(),
      authenticationRequired: true,
      authentication: {},
      data: {
        databaseBytes: 0,
        writeFailure: null,
        configBytes: 0,
        samples: 0,
        events: 0,
        activeAlerts: 0,
      },
      collection: {
        inflight: 0,
        pending: 0,
        concurrency: 4,
        timeoutSeconds: 90,
        lastCollected: null,
      },
      limits: { sources: 200, mappingsPerSource: 100, rulesPerSource: 30 },
      notifications: {},
    },
  }));
  const page = await open('#configure/system');
  await page.waitFor("document.querySelector('#system-details .system-facts')");
  const details = await text(page, '#system-details');
  for (const expected of [
    'Buildabcdef012345',
    'Open tabs by version',
    'This version (abcdef012345)',
    'Older build 0123456789ab',
    'Before 1.4.3',
  ])
    assert.ok(details.includes(expected), expected);
});

// GOBLIN_ALLOW_UNLIMITED lowers a security control, so it is set only in Uptime Goblin's environment; the
// System page shows it, with what a supervised start found of its memory, CPU and process limits:
// plain text, no control that could change it, every value escaped.
test(
  'the System page shows the resource limits and GOBLIN_ALLOW_UNLIMITED read-only',
  { skip },
  async () => {
    const body = resourceLimits => ({ ...deliverySystemBody(), resourceLimits });
    const block = page =>
      page.eval(`(() => {
      const found = [...document.querySelectorAll('#system-details .settings-block')].find(
        b => b.querySelector('h3').textContent === 'Resource limits'
      );
      return found && {
        text: found.textContent,
        rows: [...found.querySelectorAll('dl > div')].map(d => [d.querySelector('dt').textContent, d.querySelector('dd').textContent]),
        controls: found.querySelectorAll('input, select, textarea, button, [contenteditable], a[href]').length,
        images: found.querySelectorAll('img').length,
      };
    })()`);
    const forged = '<img src=x onerror="window.limitsForged = 1">';
    mock.routes.set('GET /api/system', () => ({
      body: body({
        supervised: true,
        allowUnlimited: ['cpu', 'pids'],
        limits: {
          memory: { state: 'enforced', detail: 'memory.max 1073741824', allowed: false },
          cpu: { state: 'missing', detail: `cpu.max is max ${forged}`, allowed: true },
          pids: {
            state: 'unverifiable',
            detail: 'Uptime Goblin cannot read pids.max',
            allowed: true,
          },
        },
      }),
    }));
    const page = await open('#configure/system');
    await page.waitFor("document.querySelector('#system-details .system-facts')");
    const shown = await block(page);
    assert.ok(shown, 'a Resource limits block');
    assert.deepEqual(shown.rows, [
      ['Memory', 'Enforced (memory.max 1073741824)'],
      ['CPU', `Not enforced: allowed by GOBLIN_ALLOW_UNLIMITED (cpu.max is max ${forged})`],
      [
        'Processes',
        'Not verified: allowed by GOBLIN_ALLOW_UNLIMITED (Uptime Goblin cannot read pids.max)',
      ],
      ['GOBLIN_ALLOW_UNLIMITED', 'cpu,pids'],
    ]);
    assert.equal(shown.controls, 0);
    assert.equal(shown.images, 0, 'the detail is text, not markup');
    assert.equal(await page.eval('window.limitsForged ?? null'), null);
    // What the start found, not the limits now: a limit lifted while Uptime Goblin runs shows only after
    // the next start, which refuses.
    assert.match(
      shown.text,
      /As Uptime Goblin found them when it started\..*a limit lifted while Uptime Goblin runs shows here only after the next start, which then refuses\./
    );
    // Not supervised, and an older Uptime Goblin that does not say.
    for (const [resourceLimits, expected] of [
      [
        { supervised: false },
        /Not checked: Uptime Goblin was started without supervision \(neither --supervised nor GOBLIN_SUPERVISED=1, which the systemd unit and the Docker image give\)/,
      ],
      [undefined, /LimitsUnknown/],
    ]) {
      mock.routes.set('GET /api/system', () => ({ body: body(resourceLimits) }));
      await page.eval("document.querySelector('#refresh-system').click()");
      await page.waitFor(
        `(() => { const b = [...document.querySelectorAll('#system-details .settings-block')].find(b => b.querySelector('h3').textContent === 'Resource limits'); return b && ${expected}.test(b.textContent); })()`
      );
      const again = await block(page);
      assert.match(again.text, expected);
      assert.equal(again.controls, 0);
    }
    // Every limit in force, no setting.
    mock.routes.set('GET /api/system', () => ({
      body: body({
        supervised: true,
        allowUnlimited: [],
        limits: {
          memory: { state: 'enforced', detail: 'memory.max 1073741824' },
          cpu: { state: 'enforced', detail: 'cpu.max 100000 100000: 1 CPU' },
          pids: { state: 'enforced', detail: 'pids.max 256' },
        },
      }),
    }));
    await page.eval("document.querySelector('#refresh-system').click()");
    await page.waitFor(
      "document.querySelector('#system-details').textContent.includes('Enforced (cpu.max 100000 100000: 1 CPU)')"
    );
    assert.deepEqual((await block(page)).rows.at(-1), ['GOBLIN_ALLOW_UNLIMITED', 'Not set']);
    assert.deepEqual(page.exceptions, []);
  }
);

// Loading the web app (public/boot.js, 1.5): every page runs the current /boot.js, which loads
// the page's own build from /assets/<build>/ and moves a page whose build is gone, or a page
// from before 1.5, to the current release.
const stale = 'dead00000000';
const reloadLog = page =>
  page.eval("JSON.parse(sessionStorage.getItem('orbit-update-reloads') || '[]').length");
async function openBare(ready) {
  const page = await openPage(cdp, base + '/', { prelude, PageClass: Page, ready });
  pages.push(page);
  return page;
}
/** index.html as 1.4.3 served it: the whole app from /app.js, its build in `?v=`. */
const index143 = build =>
  indexTemplate()
    .replace('<meta charset="UTF-8" />', `$&\n    <meta name="orbit-build" content="${build}" />`)
    .replace('src="/boot.js"', `src="/app.js?v=${build}"`)
    .replace('href="/style.css"', `href="/style.css?v=${build}"`);
/** index.html as 1.4.2 served it: no build, no update banner. */
const index142 = () =>
  indexTemplate()
    .replace('src="/boot.js"', 'src="/app.js"')
    .replace(/<div id="update-banner"[\s\S]*?<\/div>\n/, '');
const cards = "document.querySelector('#services > *')";
const bannerShown = "document.querySelector('#update-banner')?.hidden === false";

test('the page loads its build’s web app from /assets/ through /boot.js', { skip }, async () => {
  const page = await open();
  assert.equal(
    await page.eval(`document.querySelector('meta[name="orbit-build"]').content`),
    web.build
  );
  const scripts = await page.eval(
    "performance.getEntriesByType('resource').filter(e => e.initiatorType === 'script' || e.name.endsWith('.js')).map(e => new URL(e.name).pathname)"
  );
  const prefix = `/assets/${web.build}/`;
  assert.ok(scripts.includes(`${prefix}modules/main.js`), 'main.js from the build');
  assert.ok(scripts.includes(`${prefix}shared/timezone.js`), 'shared modules from the build');
  for (const script of scripts)
    assert.ok(script === '/boot.js' || script.startsWith(prefix), `${script} is build-stamped`);
  assert.ok(web.files.some(f => f.path === `${prefix}style.css`));
  assert.equal(web.files.filter(f => f.path === '/app.js').length, 0, 'the shim is not used');
  assert.equal(pageLoads(), 1);
  assert.equal(await reloadLog(page), 0);
  assert.deepEqual(page.exceptions, []);
});

test(
  'a page whose build is gone reloads once through /boot.js and opens the current release',
  { skip },
  async () => {
    // The first load is a page Uptime Goblin wrote before it was updated (an old tab reloading, or a
    // copy a cache kept); its build's files are no longer served.
    web.page = load => (load === 1 ? renderIndex(indexTemplate(), stale) : null);
    // Hold the reloaded page's first answer from Uptime Goblin (from 1.5 the session check, which
    // comes before the dashboard), to see its reload while it is pending.
    let release;
    const held = new Promise(resolve => (release = resolve));
    mock.routes.set('GET /api/session', async () => {
      await held;
      return { body: mock.sessionBody() };
    });
    // Ready once the reloaded page, of the current build, waits for that answer.
    const page = await openBare(
      `document.querySelector('meta[name="orbit-build"]')?.content === ${js(web.build)} && window.__requests.size > 0`
    );
    try {
      await waitForRequests('GET', '/api/session', 1);
      assert.equal(requests('GET', '/api/dashboard').length, 0, 'nothing before the session');
      assert.equal(pageLoads(), 2);
      assert.ok(
        web.files.some(f => f.method === 'HEAD' && f.path === `/assets/${stale}/modules/main.js`)
      );
      assert.equal(
        await page.eval(`document.querySelector('meta[name="orbit-build"]').content`),
        web.build
      );
      // The reload counts against the update check's allowance of 2 per 10 minutes.
      assert.equal(await reloadLog(page), 1);
    } finally {
      release();
    }
    await page.waitFor(cards);
    assert.equal(pageLoads(), 2);
    // Uptime Goblin's answer names this page's build, so the reload worked: like any successful update
    // reload (1.4.x), it no longer counts against the allowance.
    assert.equal(await reloadLog(page), 0);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'a cache that keeps serving a page whose build is gone gets two reloads, then an explanation',
  { skip },
  async () => {
    web.page = () => renderIndex(indexTemplate(), stale);
    const page = await openBare(bannerShown);
    assert.match(await text(page, '#update-text'), /still the older version after reloading/);
    assert.equal(pageLoads(), 3, 'the first load and two automatic reloads');
    await delay(1000);
    assert.equal(pageLoads(), 3, 'no further automatic reload');
    // The banner's button still reloads on request.
    await page.eval("document.querySelector('#update-reload').click()");
    await page.waitFor(bannerShown);
    assert.equal(pageLoads(), 4);
    assert.deepEqual(page.exceptions, []);
  }
);

test('a 1.4.3 page asking for /app.js moves to the current release', { skip }, async () => {
  web.page = load => (load === 1 ? index143('0123456789ab') : null);
  const page = await openBare(cards);
  assert.ok(web.files.some(f => f.path === '/app.js' && f.search === '?v=0123456789ab'));
  assert.equal(pageLoads(), 2);
  assert.equal(
    await page.eval(`document.querySelector('meta[name="orbit-build"]').content`),
    web.build
  );
  assert.equal(await page.eval("document.querySelectorAll('#update-banner').length"), 1);
  await page.settle();
  assert.deepEqual(page.exceptions, []);
});

test(
  'a 1.4.2 page kept by a cache stops after two reloads and says why, without an update banner of its own',
  { skip },
  async () => {
    web.page = () => index142();
    const page = await openBare(bannerShown);
    assert.equal(pageLoads(), 3);
    assert.match(await text(page, '#update-text'), /still the older version after reloading/);
    assert.equal(await page.eval("document.querySelectorAll('#update-banner').length"), 1);
    // The 1.5 app never ran in the old page.
    assert.equal(await page.eval("document.querySelector('#services').children.length"), 0);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'when Uptime Goblin answers but does not deliver the web app, the page reloads twice at most and says so',
  { skip },
  async () => {
    web.asset = (build, file) => (file === 'modules/main.js' ? 500 : null);
    const page = await openBare(bannerShown);
    assert.equal(pageLoads(), 3);
    assert.match(await text(page, '#update-text'), /could not be loaded/);
    assert.doesNotMatch(await text(page, '#update-text'), /older version/);
    await delay(1500);
    assert.equal(pageLoads(), 3, 'no further automatic reload');
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'while Uptime Goblin does not answer, the page says so and waits, then opens by itself once Uptime Goblin is back',
  { skip },
  async () => {
    // Uptime Goblin restarting: a proxy in front of it answers 502 or 503, or nothing answers at all.
    // Reloading then would show the browser's error page (or the proxy's) instead of Uptime Goblin.
    for (const outage of [502, 503, 'drop']) {
      resetWeb();
      let down = true;
      web.asset = (build, file) => (down && file === 'modules/main.js' ? outage : null);
      const page = await openBare(bannerShown);
      assert.match(await text(page, '#update-text'), /not answering/, String(outage));
      const probe = `/assets/${web.build}/modules/main.js`,
        probes = () => web.files.filter(f => f.method === 'HEAD' && f.path === probe).length;
      for (const end = Date.now() + 8000; probes() < 2 && Date.now() < end; ) await delay(50);
      assert.ok(probes() >= 2, `${outage}: it asks again`);
      assert.equal(pageLoads(), 1, `${outage}: no reload while Uptime Goblin does not answer`);
      assert.equal(await reloadLog(page), 0, `${outage}: waiting uses none of the allowance`);
      down = false;
      await page.waitFor(cards, 8000);
      assert.equal(pageLoads(), 2, `${outage}: one reload once Uptime Goblin answered`);
      assert.equal(await page.eval("document.querySelector('#update-banner').hidden"), true);
      assert.deepEqual(page.exceptions, [], String(outage));
      await pages.pop().close();
    }
  }
);

test(
  'every module can be loaded first and starts nothing, so import cycles cannot break the page',
  { skip },
  async () => {
    // Only main.js runs code when it is loaded; every other module just declares. So whichever
    // module a future page or test loads first, none reads a binding of a module that has not
    // run yet (a TDZ error in an import cycle), and loading one never starts the web app.
    const modules = fs
      .readdirSync(path.join(publicDir, 'modules'), { recursive: true })
      .map(file => `modules/${file.split(path.sep).join('/')}`)
      .filter(file => file.endsWith('.js') && file !== 'modules/main.js')
      .sort();
    assert.ok(modules.length > 10);
    // The page without its loader: nothing loads the web app by itself.
    web.page = () =>
      renderIndex(indexTemplate(), web.build).replace(
        '<script type="module" src="/boot.js"></script>',
        ''
      );
    for (const file of modules) {
      const page = await openBare("document.readyState === 'complete'");
      // Every request the web app makes goes through fetch(); record this page's own.
      await page.eval(`(() => {
        window.__fetches = [];
        const realFetch = window.fetch.bind(window);
        window.fetch = (input, init) => (window.__fetches.push(String(input)), realFetch(input, init));
      })()`);
      const url = `/assets/${web.build}/${file}`;
      assert.equal(
        await page.eval(`import(${js(url)}).then(() => 'loaded', error => String(error))`),
        'loaded',
        file
      );
      await page.settle();
      assert.deepEqual(await page.eval('window.__fetches'), [], `${file} starts nothing`);
      assert.equal(await page.eval("document.querySelector('#services').children.length"), 0);
      assert.deepEqual(page.exceptions, [], file);
      await pages.pop().close();
    }
  }
);

test(
  'a page that does not load /boot.js itself is never run in place, even when its build’s files exist',
  { skip },
  async () => {
    // Only a page from 1.5 on has the markup the modules expect; an older one is replaced.
    web.page = load => (load === 1 ? index143(web.build) : null);
    const page = await openBare(cards);
    assert.equal(pageLoads(), 2);
    assert.equal(
      await page.eval(`document.querySelector('script[type="module"]').getAttribute('src')`),
      '/boot.js'
    );
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'a page of the previous release, whose files Uptime Goblin still has, runs as it is, then moves to the current one by itself',
  { skip },
  async () => {
    web.previous = '0123abcd4567';
    web.page = load => (load === 1 ? renderIndex(indexTemplate(), web.previous) : null);
    const page = await openBare(cards);
    assert.equal(pageLoads(), 1, 'no reload to start');
    assert.ok(web.files.some(f => f.path === `/assets/${web.previous}/modules/main.js`));
    // Its first answer from Uptime Goblin names the current release: the update check reloads.
    await page.waitFor(
      `document.querySelector('meta[name="orbit-build"]')?.content === ${js(web.build)}`,
      8000
    );
    await page.waitFor(cards);
    assert.equal(pageLoads(), 2);
    assert.deepEqual(page.exceptions, []);
  }
);

// Owner request: a click outside a pop-up closes it, with a short, subtle exit motion.
async function clickAt(page, x, y) {
  for (const type of ['mousePressed', 'mouseReleased'])
    await page.send('Input.dispatchMouseEvent', { type, x, y, button: 'left', clickCount: 1 });
}
const isOpen = id => `document.querySelector('#${id}').open`;
const isLeaving = id => `document.querySelector('#${id}').classList.contains('closing')`;

test(
  'clicking outside the alerts dialog closes it with a short exit motion',
  { skip },
  async () => {
    const page = await open();
    await page.click('#alerts-button');
    await page.waitFor(isOpen('alerts-dialog'));
    await page.settle();
    await clickAt(page, 12, 12);
    // It leaves over a moment rather than vanishing.
    assert.equal(await page.eval(isOpen('alerts-dialog')), true);
    assert.equal(await page.eval(isLeaving('alerts-dialog')), true);
    await page.waitFor(`!${isOpen('alerts-dialog')}`, 2000);
    assert.equal(await page.eval(isLeaving('alerts-dialog')), false);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'clicking outside the drawer closes it, and asks first when there are unsaved changes',
  { skip },
  async () => {
    const page = await open();
    await openDrawer(page);
    await page.settle();
    await clickAt(page, 40, 300);
    // Reopen in the same task as the close, before its late 'close' event runs.
    await page.waitFor(`document.querySelector('#settings-dialog').classList.contains('closing')`);
    await page.eval(`new Promise(resolve => {
      const drawer = document.querySelector('#settings-dialog');
      new MutationObserver((changes, observer) => {
        if (drawer.open) return;
        observer.disconnect();
        const button = document.createElement('button');
        button.dataset.configure = 'linux';
        document.body.append(button);
        button.click();
        button.remove();
        resolve();
      }).observe(drawer, { attributes: true, attributeFilter: ['open'] });
    })`);
    await page.waitFor(isOpen('settings-dialog'));
    await settled(page, 'settings-dialog');
    await page.click('#source-name');
    await page.send('Input.insertText', { text: ' 2' });
    await page.eval('window.__confirmAnswer = false; window.__confirmCalls = 0');
    await clickAt(page, 40, 300);
    await page.settle();
    assert.equal(await page.eval('window.__confirmCalls'), 1);
    assert.equal(await page.eval(isOpen('settings-dialog')), true);
    assert.equal(await page.eval(isLeaving('settings-dialog')), false);
    assert.equal(await page.eval("document.querySelector('#source-name').value"), 'Linux host 2');
    await page.eval('window.__confirmAnswer = true');
    await clickAt(page, 40, 300);
    await page.waitFor(`!${isOpen('settings-dialog')}`, 2000);
    assert.deepEqual(page.exceptions, []);
  }
);

test('a press inside the drawer that is released outside it closes nothing', { skip }, async () => {
  const page = await open();
  await openDrawer(page);
  await page.settle();
  const { x, y } = await page.center('#source-name');
  await page.send('Input.dispatchMouseEvent', {
    type: 'mousePressed',
    x,
    y,
    button: 'left',
    clickCount: 1,
  });
  await page.send('Input.dispatchMouseEvent', {
    type: 'mouseMoved',
    x: 40,
    y: 300,
    button: 'left',
  });
  await page.send('Input.dispatchMouseEvent', {
    type: 'mouseReleased',
    x: 40,
    y: 300,
    button: 'left',
    clickCount: 1,
  });
  await delay(400);
  assert.equal(await page.eval(isOpen('settings-dialog')), true);
});

test(
  'clicking elsewhere on the dashboard folds the expanded card away; clicks inside it or on controls do not',
  { skip },
  async () => {
    const page = await open();
    await expand(page);
    await page.waitFor("document.querySelector('#graph-linux svg.chart')");
    await page.click('#detail-linux h4');
    await page.click('#refresh');
    await delay(400);
    assert.equal(
      await page.eval("document.querySelector('.service.expanded')?.dataset.id"),
      'linux'
    );
    await page.click('#dashboard-title');
    // The details fade away before the card folds.
    assert.equal(await page.eval("!!document.querySelector('.service.expanded.collapsing')"), true);
    await page.waitFor("!document.querySelector('.service.expanded')", 2000);
    assert.equal(await page.eval("!!document.querySelector('.service.collapsing')"), false);
    // The card's own button folds it the same way, and opens it again.
    await expand(page);
    await page.click('[data-expand="linux"]');
    await page.waitFor("!document.querySelector('.service.expanded')", 2000);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'the click that closes the user menu, and clicks on the menu or the session banner, leave the open card open',
  { skip },
  async () => {
    // These folded the card, and its chart, metric and range went with it: the user menu and the
    // session banner were not exempt like the dialogs and #update-banner (§18 F6).
    mock.sessionBody = () => identity.session('session', { mirrorPending: true });
    const page = await open();
    await page.waitFor("document.querySelector('#session-banner').hidden === false");
    await expand(page);
    await page.waitFor("document.querySelector('#graph-linux svg.chart')");
    const cardOpen = "document.querySelector('.service.expanded')?.dataset.id === 'linux'";
    const menuOpen = "!document.querySelector('#user-menu').hidden";
    // Where a trusted click lands, and what is there.
    const point = where =>
      page.eval(`(r => ({ x: ${where.x}, y: ${where.y} }))(${where.of}.getBoundingClientRect())`);
    const hits = ({ x, y }, selector) =>
      page.eval(`!!document.elementFromPoint(${x}, ${y})?.matches(${js(selector)})`);
    const cases = [
      // The menu's own padding, with the menu open: it stays open.
      {
        name: 'the menu padding',
        menu: true,
        where: { of: "document.querySelector('#user-menu')", x: 'r.left + 3', y: 'r.top + 3' },
        expect: { hit: '#user-menu', menu: true },
      },
      // The click outside the open menu that closes it (§7.6), on the heading's eyebrow text.
      {
        name: 'outside the menu',
        menu: true,
        where: {
          of: "document.querySelector('.page-heading .eyebrow')",
          x: 'r.left + 4',
          y: 'r.top + r.height / 2',
        },
        expect: { hit: '.page-heading .eyebrow', menu: false },
      },
      // The session banner's text, with the menu closed.
      {
        name: 'the session banner',
        menu: false,
        where: {
          of: "document.querySelector('#session-banner p')",
          x: 'r.left + 10',
          y: 'r.top + r.height / 2',
        },
        expect: { hit: '#session-banner p', menu: false },
      },
    ];
    for (const { name, menu, where, expect } of cases) {
      if (menu) {
        await page.click('#user-chip');
        await page.waitFor(menuOpen);
      }
      await page.settle();
      const at = await point(where);
      assert.equal(await hits(at, expect.hit), true, `${name}: where the click lands`);
      await clickAt(page, at.x, at.y);
      await page.settle();
      await delay(400);
      assert.equal(await page.eval(menuOpen), expect.menu, `${name}: the menu`);
      assert.equal(await page.eval(cardOpen), true, `${name}: the card stays open`);
      assert.equal(await page.eval("!!document.querySelector('#graph-linux svg.chart')"), true);
      if (await page.eval(menuOpen)) await page.click('#user-chip');
      await page.waitFor(`!(${menuOpen})`);
    }
    // With the menu closed, the same click outside still folds the card.
    const at = await point(cases[1].where);
    await clickAt(page, at.x, at.y);
    await page.waitFor("!document.querySelector('.service.expanded')", 2000);
    assert.deepEqual(page.exceptions, []);
  }
);

test('the × button and Escape close dialogs with the same exit motion', { skip }, async () => {
  const page = await open();
  await openDrawer(page);
  await page.settle();
  await page.click('#settings-dialog .dialog-heading .icon-button');
  assert.equal(await page.eval(isLeaving('settings-dialog')), true);
  await page.waitFor(`!${isOpen('settings-dialog')}`, 2000);
  await page.click('#alerts-button');
  await page.waitFor(isOpen('alerts-dialog'));
  await settled(page, 'alerts-dialog');
  await page.press('Escape');
  assert.equal(await page.eval(isLeaving('alerts-dialog')), true);
  await page.waitFor(`!${isOpen('alerts-dialog')}`, 2000);
});

test('with reduced motion, pop-ups and card details close at once', { skip }, async () => {
  const page = await open();
  await page.send('Emulation.setEmulatedMedia', {
    features: [{ name: 'prefers-reduced-motion', value: 'reduce' }],
  });
  await page.click('#alerts-button');
  await page.waitFor(isOpen('alerts-dialog'));
  await clickAt(page, 12, 12);
  assert.equal(await page.eval(isOpen('alerts-dialog')), false);
  await expand(page);
  await page.click('#dashboard-title');
  assert.equal(await page.eval("!!document.querySelector('.service.expanded')"), false);
});

test('reopening a dialog while it is leaving keeps it open', { skip }, async () => {
  const page = await open();
  await page.click('#alerts-button');
  await page.waitFor(isOpen('alerts-dialog'));
  await settled(page, 'alerts-dialog');
  await page.press('Escape');
  assert.equal(await page.eval(isLeaving('alerts-dialog')), true);
  await page.eval(`(() => {
    const button = document.createElement('button');
    button.dataset.viewAlerts = '';
    document.querySelector('#alerts-content').append(button);
    button.click();
    button.remove();
  })()`);
  await delay(400);
  assert.equal(await page.eval(isOpen('alerts-dialog')), true);
  assert.equal(await page.eval(isLeaving('alerts-dialog')), false);
});

// Regressions from Codex's review of f58a853: a leaving drawer must not accept a second save,
// and an obsolete fold must not close a card that was opened again.
test(
  'a second click or Enter during the exit motion after a save cannot add the same source twice',
  { skip },
  async () => {
    const page = await open();
    await click(page, '#add-source');
    await page.waitFor(isOpen('settings-dialog'));
    await settled(page, 'settings-dialog');
    await setValue(page, '#source-name', 'Double-click host');
    await page.eval(
      "document.querySelector('#connection-form [type=submit]').scrollIntoView({ block: 'center' })"
    );
    const submit = await page.center('#connection-form [type=submit]');
    await page.click('#connection-form [type=submit]');
    await page.waitFor(isLeaving('settings-dialog'));
    // A trusted click where the button still shows, then Enter, while the drawer leaves.
    await clickAt(page, submit.x, submit.y);
    await page.press('Enter');
    await page.waitFor(`!${isOpen('settings-dialog')}`, 2000);
    await delay(250);
    assert.equal(requests('POST', '/api/services').length, 1);
    assert.equal(
      mock.dashboard.config.services.filter(s => s.name === 'Double-click host').length,
      1
    );
    // The confirmation is shown on the page, not inside the drawer that faded away.
    assert.equal(
      await page.eval("document.querySelector('#toast').parentElement === document.body"),
      true
    );
  }
);

// The test above looks only after the drawer has closed, when its 'close' handler has already
// moved the toast back to the page, so it passes even if toast() put the message in the leaving
// drawer (a plain dialog[open] selector). There the message would fade out with the drawer and
// reappear on the page when the drawer closes. This checks where it goes while the drawer leaves.
test(
  'a confirmation raised while the drawer is leaving goes to the page, not the drawer',
  { skip },
  async () => {
    const page = await open();
    await openDrawer(page);
    // Stretch the drawer's exit timer (exitMs, from the same module instance the app runs) so the
    // save's dashboard reload and its toast land during the exit however slow the machine is, and
    // record where the toast is the moment it is raised: its mutation callback runs as a
    // microtask right after toast(), long before the late 'close' handler could move it.
    await page.eval(`(async () => {
      const { exitMs } = await import(${js(`/assets/${web.build}/modules/core/dom.js`)});
      const realSetTimeout = window.setTimeout;
      window.setTimeout = (fn, ms, ...rest) =>
        realSetTimeout(fn, ms === exitMs ? 1500 : ms, ...rest);
      const drawer = document.querySelector('#settings-dialog'),
        toast = document.querySelector('#toast');
      window.__raised = [];
      new MutationObserver(() =>
        window.__raised.push({
          text: toast.textContent,
          onPage: toast.parentElement === document.body,
          drawerOpen: drawer.open,
          drawerLeaving: drawer.classList.contains('closing'),
        })
      ).observe(toast, { childList: true, characterData: true, subtree: true });
    })()`);
    await click(page, '#connection-form [type=submit]');
    await page.waitFor('window.__raised.length > 0', 3000);
    assert.deepEqual(await page.eval('window.__raised'), [
      { text: 'Linux host saved', onPage: true, drawerOpen: true, drawerLeaving: true },
    ]);
    // It is still on the page, and showing, once the drawer has gone.
    await page.waitFor(`!${isOpen('settings-dialog')}`, 3000);
    assert.deepEqual(
      await page.eval(
        "(t => [t.parentElement === document.body, t.hidden])(document.querySelector('#toast'))"
      ),
      [true, false]
    );
    assert.deepEqual(page.exceptions, []);
  }
);

// The drawer's 'close' event arrives in a later task than close(). A drawer closed and opened
// again before then (as the click-outside test above does) is new work: the late event must not
// cancel a connection test started in the reopened drawer.
test(
  "a late 'close' event does not cancel a connection test started in the reopened drawer",
  { skip },
  async () => {
    // The answer waits until the late event has run, so the test is certainly still in flight.
    let answerTest;
    const testAnswered = new Promise(resolve => (answerTest = resolve));
    mock.routes.set('POST /api/test-service', async () => {
      await testAnswered;
      return { body: { metrics: metrics(), notes: [], elapsedMs: 100 } };
    });
    const page = await open();
    await openDrawer(page);
    try {
      // One task: close the drawer, open it again through configure() (openDialog), and start a
      // test. A capturing listener on window sees the late 'close' event before the drawer's own.
      await page.eval(`(() => {
        const drawer = document.querySelector('#settings-dialog');
        window.__lateClose = [];
        window.addEventListener(
          'close',
          e => {
            if (e.target === drawer)
              window.__lateClose.push({
                open: drawer.open,
                testing: document.querySelector('#test-connection').disabled,
              });
          },
          true
        );
        drawer.close();
        const button = document.createElement('button');
        button.dataset.configure = 'linux';
        document.body.append(button);
        button.click();
        button.remove();
        document.querySelector('#test-connection').click();
      })()`);
      await page.waitFor('window.__lateClose.length > 0', 3000);
      assert.deepEqual(await page.eval('window.__lateClose'), [{ open: true, testing: true }]);
      assert.equal(await page.eval("document.querySelector('#connection-test').hidden"), false);
      assert.match(await text(page, '#connection-test'), /Connecting/);
    } finally {
      answerTest();
    }
    await page.waitFor("!document.querySelector('#test-connection').disabled", 3000);
    await page.settle();
    assert.equal(await page.eval(isOpen('settings-dialog')), true);
    assert.equal(await page.eval("document.querySelector('#connection-test').hidden"), false);
    assert.match(await text(page, '#connection-test'), /Connected · 3 measurements/);
    assert.equal(await text(page, '#test-connection'), 'Test connection');
    assert.equal(requests('POST', '/api/test-service').length, 1);
    assert.deepEqual(page.exceptions, []);
  }
);

test('reopening a card after switching cards cancels its earlier fold', { skip }, async () => {
  addHosts(['linux-2', 'Second host']);
  const page = await open();
  await expand(page);
  await page.eval(`(() => {
    document.querySelector('[data-expand="linux"]').click();
    document.querySelector('[data-expand="linux-2"]').click();
    document.querySelector('[data-expand="linux"]').click();
  })()`);
  await delay(400);
  assert.equal(await page.eval("document.querySelector('.service.expanded')?.dataset.id"), 'linux');
  assert.equal(await page.eval("!!document.querySelector('.service.collapsing')"), false);
});

// Signing in (1.5): the sign-in view, the sign-in dialog that keeps drafts open, the user chip,
// the session banners and the Account page, against Uptime Goblin's sign-in answers (see `identity`).
const signInView = "document.querySelector('#signin-page')?.hidden === false";
const cspViolations = page => page.eval('window.__cspViolations');
/** Opens the page while Uptime Goblin has no session for this browser. */
async function openSignedOut(hash = '') {
  mock.signedIn = false;
  mock.signedOutAs = 'signin_required';
  const page = await openPage(cdp, base + '/' + hash, {
    prelude,
    PageClass: Page,
    ready: signInView,
  });
  pages.push(page);
  await page.settle();
  return page;
}
/** Fills in one of the two sign-in forms (`signin` or `reauth`) and submits it. */
async function submitSignIn(page, form, password = mock.password, { remember = false } = {}) {
  await setValue(page, `#${form}-login`, 'admin');
  await setValue(page, `#${form}-password`, password);
  await page.eval(`document.querySelector('#${form}-remember').checked = ${remember}`);
  await page.eval(`document.querySelector('#${form}-submit').click()`);
}
/** Records whether the sign-in dialog ever opened. */
const watchSignInDialog = page =>
  page.eval(`(() => {
    window.__signInShown = 0;
    new MutationObserver(() => {
      if (document.querySelector('#signin-dialog').open) window.__signInShown++;
    }).observe(document.querySelector('#signin-dialog'), { attributes: true, attributeFilter: ['open'] });
  })()`);
/** What the web app shows for each code (spec §7.10), as text (code parts unquoted). */
const signInTexts = {
  invalid_credentials: 'The login name or password is incorrect.',
  https_required:
    'Sign-in needs HTTPS, or a browser on the Uptime Goblin computer itself. Open Uptime Goblin at its https:// address. You can allow plain HTTP on a network you trust, but your password and sign-in cookie then cross it unencrypted: set GOBLIN_INSECURE_HTTP_SESSIONS=1 in Uptime Goblin’s environment and restart Uptime Goblin (Docker: in .env, then docker compose up -d) (see docs/authentication.md).',
  proxy_proto_missing:
    'Your browser uses HTTPS, but the reverse proxy in front of Uptime Goblin does not tell Uptime Goblin so. In nginx add proxy_set_header X-Forwarded-Proto $scheme; to Uptime Goblin’s location and reload nginx; GOBLIN_TRUST_PROXY must name the proxy (loopback when it runs on the same computer). Until then GOBLIN_INSECURE_HTTP_SESSIONS=1 lets you sign in (see docs/authentication.md).',
  proxy_proto_mismatch:
    'This page uses plain HTTP (http://), but the reverse proxy in front of Uptime Goblin tells Uptime Goblin the connection is HTTPS, so your browser would drop the sign-in cookie. In nginx use proxy_set_header X-Forwarded-Proto $scheme; instead of a fixed https and reload nginx, or open Uptime Goblin at its https:// address (see docs/authentication.md).',
  cross_origin:
    'Uptime Goblin refused this sign-in because this page’s address does not match what the reverse proxy tells Uptime Goblin. In nginx add proxy_set_header Host $http_host; to Uptime Goblin’s location, or add this hostname to GOBLIN_ALLOWED_HOSTS and restart Uptime Goblin (see docs/authentication.md).',
  multiple_credentials:
    'Your browser sent two Uptime Goblin sign-in cookies. Remove this site’s cookies, then sign in.',
  signed_out_other_cookie:
    'You are signed out, but this browser still has an Uptime Goblin sign-in cookie that another site set. Remove this site’s cookies in the browser before you sign in again.',
  session_expired: 'Your session has ended. Sign in again.',
  plain_http:
    'This page uses plain HTTP, so your password crosses the network unencrypted when you sign in (GOBLIN_INSECURE_HTTP_SESSIONS allows it). Sign in only on a network you trust, and serve Uptime Goblin over HTTPS.',
  cookie_not_stored:
    'You signed in, but this browser did not keep Uptime Goblin’s sign-in cookie. If this address starts with http://, open the https:// address instead.',
  network: 'Uptime Goblin is not answering. Try again in a moment.',
};

test(
  'the page asks who is signed in before anything else, and names itself on every request',
  { skip },
  async () => {
    const page = await open();
    const calls = mock.requests.filter(r => r.path.startsWith('/api/'));
    assert.equal(`${calls[0].method} ${calls[0].path}`, 'GET /api/session');
    assert.ok(calls.some(r => r.path === '/api/dashboard'));
    for (const r of calls) {
      assert.equal(r.headers['x-goblin-client'], `web/${web.build}`, r.path);
      assert.equal(r.headers['x-goblin-request'], '1', r.path);
      assert.equal(r.headers.authorization, undefined, r.path);
    }
    assert.equal(await page.eval("document.querySelector('#user-chip').hidden"), false);
    assert.equal(await text(page, '#user-chip-name'), 'Administrator');
    assert.equal(await page.eval("document.querySelector('#sign-out').hidden"), false);
    assert.equal(await page.eval("document.querySelector('#signin-page').hidden"), true);
    assert.equal(await page.eval("document.querySelector('#session-banner').hidden"), true);
    assert.deepEqual(await cspViolations(page), []);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'a signed-out page shows only the sign-in view, and starts the web app once signed in',
  { skip },
  async () => {
    const page = await openSignedOut();
    assert.equal(requests('GET', '/api/dashboard').length, 0, 'nothing loads before sign-in');
    assert.equal(await page.eval('typeof window.__poll'), 'undefined', 'no polls either');
    for (const selector of [
      '#dashboard-page',
      '#configuration-page',
      '#refresh',
      '#settings',
      '#user-chip',
    ])
      assert.equal(await page.eval(`document.querySelector('${selector}').hidden`), true, selector);
    assert.equal(await text(page, '#signin-title'), 'Sign in to Uptime Goblin');
    assert.equal(await page.eval('document.title'), 'Uptime Goblin · Homelab');
    assert.match(await text(page, '.brand'), /Uptime Goblin/);
    assert.equal(await page.eval('document.activeElement.id'), 'signin-title');
    // Visible labels, hints by aria-describedby, and what password managers look for.
    // As read out: white space collapsed.
    const fields = await page.eval(`[...document.querySelectorAll('#signin-form input')].map(i => ({
      id: i.id,
      label: document.querySelector('label[for=' + i.id + ']')?.textContent.replace(/\\s+/g, ' ').trim(),
      hint: i.getAttribute('aria-describedby') && document.getElementById(i.getAttribute('aria-describedby'))?.textContent.replace(/\\s+/g, ' ').trim(),
      autocomplete: i.getAttribute('autocomplete'),
      required: i.required,
    }))`);
    assert.deepEqual(fields, [
      {
        id: 'signin-login',
        label: 'Login name',
        hint: 'The built-in login name is admin.',
        autocomplete: 'username',
        required: true,
      },
      {
        id: 'signin-password',
        label: 'Password',
        hint: null,
        autocomplete: 'current-password',
        required: true,
      },
      {
        id: 'signin-remember',
        label: 'Keep me signed in on this device',
        // The cookie has no Max-Age without the box, so the browser decides when it ends: one
        // that reopens the previous tabs keeps it (docs audit, sessions).
        hint: 'Stays signed in on this device for up to 30 days, as long as you use Uptime Goblin at least every 12 hours. Without it, closing the browser signs you out (a browser that reopens your previous tabs may keep you signed in).',
        autocomplete: null,
        required: false,
      },
    ]);
    assert.equal(
      await page.eval("document.querySelector('#signin-error').getAttribute('role')"),
      'alert'
    );
    // Loopback needs no transport notice.
    assert.equal(await page.eval("document.querySelector('#signin-notice').hidden"), true);

    await submitSignIn(page, 'signin', mock.password, { remember: true });
    await page.waitFor(cards);
    const [login] = requests('POST', '/api/auth/login');
    assert.deepEqual(JSON.parse(login.body), {
      login: 'admin',
      password: mock.password,
      remember: true,
    });
    assert.equal(login.url.search, '');
    // The session is checked again after the login: that the browser kept the cookie.
    const order = mock.requests.map(r => `${r.method} ${r.path}`);
    assert.equal(order[order.indexOf('POST /api/auth/login') + 1], 'GET /api/session');
    assert.equal(await page.eval("document.querySelector('#signin-page').hidden"), true);
    assert.equal(await page.eval("document.querySelector('#signin-password').value"), '');
    assert.equal(await page.eval("document.querySelector('#user-chip').hidden"), false);
    assert.equal(
      await page.eval(
        "document.activeElement === document.querySelector('#dashboard-title').closest('h1')"
      ),
      true
    );
    assert.equal(await page.eval('typeof window.__poll'), 'function', 'polls start now');
    assert.deepEqual(await cspViolations(page), []);
    assert.deepEqual(page.exceptions, []);
  }
);

// The email form and the source drawer take passwords that Uptime Goblin passes on (to the mail server,
// to a source), never Uptime Goblin's own sign-in. The sender field carried autocomplete="username"
// beside the app password, which marks the pair as a sign-in form. No input in either carries a
// sign-in token; the password fields keep new-password.
test(
  'the email form and the source credentials carry no sign-in autocomplete (username, current-password, email)',
  { skip },
  async () => {
    const signIn = new Set(['username', 'current-password', 'email']);
    const inputsOf = (page, selector) =>
      page.eval(`[...document.querySelectorAll(${js(`${selector} input`)})].map(i => ({
        id: i.id,
        type: i.type,
        autocomplete: i.getAttribute('autocomplete'),
      }))`);
    const check = (inputs, where) => {
      assert.ok(inputs.length, `${where} has inputs`);
      for (const { id, type, autocomplete } of inputs) {
        const tokens = (autocomplete ?? '').toLowerCase().split(/\s+/).filter(Boolean);
        assert.ok(
          !tokens.some(token => signIn.has(token)),
          `${where} #${id}: autocomplete="${autocomplete}"`
        );
        if (type === 'password') assert.equal(autocomplete, 'new-password', `${where} #${id}`);
      }
    };
    const email = await open('#configure/email');
    await email.waitFor("document.querySelector('#email-form #email-from')");
    const fields = await inputsOf(email, '#email-form');
    check(fields, '#email-form');
    assert.equal(fields.find(field => field.id === 'email-from').autocomplete, 'off');
    assert.deepEqual(
      fields.filter(field => field.type === 'password').map(field => field.id),
      ['email-password']
    );
    // A source with a login name, a password and an API key (UniFi), and one with a key only.
    mock.dashboard.catalog = [
      ...catalog,
      { type: 'unifi', name: 'UniFi', group: 'Network', color: 'blue', icon: 'server', labels: [] },
    ];
    mock.dashboard.config.services.push(
      source({ id: 'unifi', type: 'unifi', name: 'UniFi', group: 'Network', labels: [] })
    );
    const page = await open();
    for (const [id, ids] of [
      ['unifi', ['source-username', 'source-password', 'source-key']],
      ['linux', ['source-key']],
    ]) {
      await openDrawer(page, id);
      const credentials = await inputsOf(page, '#credential-fields');
      assert.deepEqual(
        credentials.map(field => field.id),
        ids,
        id
      );
      check(credentials, `#credential-fields (${id})`);
      await page.eval("document.querySelector('#settings-dialog').close()");
    }
    assert.deepEqual(email.exceptions, []);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'signing in on a configuration address opens that page and focuses its heading',
  { skip },
  async () => {
    const page = await openSignedOut('#configure/alerts');
    await submitSignIn(page, 'signin');
    await page.waitFor("document.querySelector('#configuration-section-title')");
    await page.waitFor(
      "document.activeElement === document.querySelector('#configuration-section-title')"
    );
    assert.equal(await page.eval("document.querySelector('#dashboard-page').hidden"), true);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'the sign-in forms post, and submitting never navigates or puts the password in the address',
  { skip },
  async () => {
    const page = await openSignedOut();
    for (const id of ['signin-form', 'reauth-form'])
      assert.equal(
        await page.eval(`document.querySelector('#${id}').getAttribute('method')`),
        'post'
      );
    await setValue(page, '#signin-login', 'admin');
    await setValue(page, '#signin-password', 'not the password at all');
    await page.eval("document.querySelector('#signin-password').focus()");
    await page.press('Enter');
    await page.waitFor("document.querySelector('#signin-error').hidden === false");
    assert.equal(await text(page, '#signin-error'), signInTexts.invalid_credentials);
    assert.equal(requests('POST', '/api/auth/login').length, 1);
    assert.equal(pageLoads(), 1, 'no navigation');
    assert.equal(web.files.filter(f => f.method !== 'GET' && f.method !== 'HEAD').length, 0);
    assert.equal(await page.eval('location.search + location.hash'), '');
    // The password is cleared after an answer, and focus is back in its field.
    assert.equal(await page.eval("document.querySelector('#signin-password').value"), '');
    assert.equal(await page.eval('document.activeElement.id'), 'signin-password');
    // Should the web app's handler be missing (a script error), the browser posts the form to
    // the page's own address, which refuses it without reading it: never a GET with a query.
    await setValue(page, '#signin-password', 'not the password at all');
    await page.eval(
      "HTMLFormElement.prototype.submit.call(document.querySelector('#signin-form'))"
    );
    const end = Date.now() + 5000;
    while (!web.files.some(f => f.method === 'POST') && Date.now() < end) await delay(20);
    const native = web.files.filter(f => f.method === 'POST');
    assert.deepEqual(
      native.map(f => f.path + f.search),
      ['/'],
      'posted to the page itself'
    );
    assert.ok(!web.files.some(f => f.search.includes('password')));
  }
);

test(
  'the sign-in view explains a transport Uptime Goblin will refuse, before any attempt',
  { skip },
  async () => {
    // [reply, notice, form hidden]. This page is plain HTTP (http://127.0.0.1). Where Uptime Goblin
    // will refuse any sign-in from it (https_required, proxy_proto_mismatch), it would refuse
    // only once the password had crossed the network unencrypted (B11): no form asks for it,
    // as for a 403. Every other notice keeps the form: signing in can still succeed. Plain
    // HTTP allowed, a page at a loopback name is not warned: its browser reaches Uptime Goblin on its
    // own computer (Docker Compose's published port answers `http`).
    const cases = [
      [identity.unauthorized('signin_required', 'http'), signInTexts.https_required, true],
      [identity.unauthorized('signin_required', 'https'), signInTexts.proxy_proto_mismatch, true],
      [identity.unauthorized('signin_required', 'http', { insecureAllowed: true }), null, false],
      [
        identity.unauthorized('signin_required', 'loopback', { insecureAllowed: true }),
        null,
        false,
      ],
      [identity.unauthorized('signin_required', 'loopback'), null, false],
      [identity.unauthorized('session_expired', 'loopback'), signInTexts.session_expired, false],
      [
        identity.unauthorized('multiple_credentials', 'loopback'),
        signInTexts.multiple_credentials,
        false,
      ],
    ];
    for (const [reply, expected, noForm] of cases) {
      mock.routes.set('GET /api/session', () => reply);
      const page = await openSignedOut();
      const what = `${reply.body.code} over ${reply.body.transport.kind}`;
      assert.equal(
        await page.eval("document.querySelector('#signin-notice').hidden"),
        expected === null,
        what
      );
      if (expected) assert.equal(await text(page, '#signin-notice'), expected, what);
      assert.equal(await page.eval("document.querySelector('#signin-form').hidden"), noForm, what);
      // Nothing to type into, so nothing a press of Enter could send.
      if (noForm)
        assert.equal(
          await page.eval(
            "!!document.querySelector('#signin-password').checkVisibility() || document.activeElement.closest('form') !== null"
          ),
          false,
          what
        );
      if (expected === signInTexts.proxy_proto_mismatch)
        assert.equal(
          await text(page, '#signin-notice code'),
          'proxy_set_header X-Forwarded-Proto $scheme;',
          'configuration shows as code'
        );
      assert.deepEqual(await cspViolations(page), []);
      assert.deepEqual(page.exceptions, [], what);
      await pages.pop().close();
    }
    // A page under a name that is not a loopback one (Chrome takes *.localhost to this
    // computer), as a browser elsewhere opens Uptime Goblin. Where Uptime Goblin allows plain HTTP, the notice
    // says, before the password is typed, that it crosses the network unencrypted (B12). Where
    // Uptime Goblin answers `loopback`, a proxy on the Uptime Goblin host sends no forwarding headers and keeps
    // a loopback Host, nginx's default with a bare proxy_pass: Uptime Goblin treats such a browser as
    // plain HTTP (S21 shows it through a real proxy), so with plain-HTTP sessions off it
    // refuses the sign-in once the password has crossed, and no form asks for it (B11).
    const proxied = base.replace('127.0.0.1', 'orbit.localhost') + '/';
    for (const [reply, expected, noForm] of [
      [identity.unauthorized('signin_required', 'loopback'), signInTexts.https_required, true],
      [
        identity.unauthorized('signin_required', 'loopback', { insecureAllowed: true }),
        signInTexts.plain_http,
        false,
      ],
      [
        identity.unauthorized('signin_required', 'http', { insecureAllowed: true }),
        signInTexts.plain_http,
        false,
      ],
      [
        identity.unauthorized('session_expired', 'http', { insecureAllowed: true }),
        `${signInTexts.session_expired} ${signInTexts.plain_http}`,
        false,
      ],
    ]) {
      mock.routes.set('GET /api/session', () => reply);
      const page = await openPage(cdp, proxied, { prelude, PageClass: Page, ready: signInView });
      pages.push(page);
      await page.settle();
      const what = `${reply.body.code} over ${reply.body.transport.kind}, insecureAllowed ${reply.body.transport.insecureAllowed}`;
      assert.equal(await page.eval('location.host'), new URL(proxied).host);
      assert.equal(await text(page, '#signin-notice'), expected, what);
      assert.equal(await page.eval("document.querySelector('#signin-form').hidden"), noForm, what);
      assert.deepEqual(await cspViolations(page), []);
      assert.deepEqual(page.exceptions, [], what);
      await pages.pop().close();
    }
    mock.routes.delete('GET /api/session');
    // A page opened over HTTPS whose proxy does not say so (the mock serves plain HTTP, so the
    // protocol is passed in). The browser's own connection is encrypted: the form stays, and
    // its attempt shows Uptime Goblin's refusal (S11 shows it through a real proxy).
    const page = await openSignedOut();
    assert.equal(
      await page.eval(
        `import('/assets/${web.build}/modules/identity/signin.js').then(m => m.transportNotice({ kind: 'http', insecureAllowed: false }, 'https:').replaceAll('\`', ''))`
      ),
      signInTexts.proxy_proto_missing
    );
    assert.deepEqual(
      await page.eval(
        `import('/assets/${web.build}/modules/identity/signin.js').then(m => [[{ kind: 'http', insecureAllowed: false }, 'https:'], [{ kind: 'http', insecureAllowed: false }, 'http:'], [{ kind: 'https', insecureAllowed: false }, 'http:'], [{ kind: 'https', insecureAllowed: false }, 'https:'], [{ kind: 'http', insecureAllowed: true }, 'http:'], [{ kind: 'loopback', insecureAllowed: false }, 'http:'], [undefined, 'http:']].map(([transport, protocol]) => m.refusedInClear(transport, protocol)))`
      ),
      [null, 'https_required', 'proxy_proto_mismatch', null, null, null, null]
    );
    // [transport, protocol, host]: `loopback` to a page whose own address is a loopback name is
    // a browser on the Uptime Goblin computer; to any other name, a proxy on it that sends no forwarding
    // headers, which Uptime Goblin treats as plain HTTP.
    const hosts = [
      [{ kind: 'loopback', insecureAllowed: false }, 'http:', 'localhost:4317'],
      [{ kind: 'loopback', insecureAllowed: false }, 'http:', '127.0.0.1:4317'],
      [{ kind: 'loopback', insecureAllowed: false }, 'http:', '[::1]:4317'],
      [{ kind: 'loopback', insecureAllowed: false }, 'http:', 'goblin.example'],
      [{ kind: 'loopback', insecureAllowed: false }, 'https:', 'goblin.example'],
      [{ kind: 'loopback', insecureAllowed: true }, 'http:', 'goblin.example'],
      [{ kind: 'loopback', insecureAllowed: true }, 'http:', 'localhost:4317'],
      [{ kind: 'http', insecureAllowed: true }, 'http:', 'goblin.example'],
      [{ kind: 'http', insecureAllowed: true }, 'http:', 'localhost:4317'],
      [{ kind: 'http', insecureAllowed: true }, 'https:', 'goblin.example'],
      [{ kind: 'https', insecureAllowed: true }, 'https:', 'goblin.example'],
    ];
    assert.deepEqual(
      await page.eval(
        `import('/assets/${web.build}/modules/identity/signin.js').then(m => ${JSON.stringify(hosts)}.map(([transport, protocol, host]) => [m.refusedInClear(transport, protocol, host), m.transportNotice(transport, protocol, host).slice(0, 40), m.plainHttpWarning(transport, protocol, host) !== '']))`
      ),
      [
        [null, '', false],
        [null, '', false],
        [null, '', false],
        ['https_required', signInTexts.https_required.slice(0, 40), false],
        [null, 'Your browser uses HTTPS, but the reverse', false],
        [null, '', true],
        [null, '', false],
        [null, '', true],
        [null, '', false],
        [null, '', false],
        [null, '', false],
      ]
    );
  }
);

test('a refused sign-in says what to do, by code', { skip }, async () => {
  const cases = [
    [identity.forbidden('https_required'), signInTexts.https_required],
    [identity.forbidden('proxy_proto_missing'), signInTexts.proxy_proto_missing],
    [identity.forbidden('proxy_proto_mismatch'), signInTexts.proxy_proto_mismatch],
    [identity.forbidden('cross_origin'), signInTexts.cross_origin],
    [identity.unauthorized('invalid_credentials'), signInTexts.invalid_credentials],
    [identity.refused(429, 'busy', 5), identityMessages.busy],
    [identity.refused(503, 'storage_full', 30), identityMessages.storage_full],
    [{ drop: true }, signInTexts.network],
  ];
  const page = await openSignedOut();
  for (const [reply, expected] of cases) {
    mock.routes.set('POST /api/auth/login', () => reply);
    const before = requests('POST', '/api/auth/login').length;
    await submitSignIn(page, 'signin');
    await waitForRequests('POST', '/api/auth/login', before + 1);
    await page.waitFor(
      `document.querySelector('#signin-error').textContent === ${js(expected)} && !document.querySelector('#signin-submit').disabled`
    );
    assert.equal(await page.eval("document.querySelector('#signin-error').hidden"), false);
    // Only a lost answer keeps the password, to send it again.
    assert.equal(
      await page.eval("document.querySelector('#signin-password').value"),
      reply.drop ? mock.password : ''
    );
    assert.equal(await page.eval('document.activeElement.id'), 'signin-password');
  }
  assert.equal(await page.eval("document.querySelector('#signin-page').hidden"), false);
  assert.deepEqual(await cspViolations(page), []);
  assert.deepEqual(page.exceptions, []);
});

test('a refusal before sign-in shows Uptime Goblin’s reason and no form', { skip }, async () => {
  // A browser address outside the Host allowlist is refused with 403 before any sign-in.
  const reason = 'Host is not allowed. Add this hostname and port to GOBLIN_ALLOWED_HOSTS.';
  mock.routes.set('GET /api/session', () => ({ status: 403, body: { error: reason } }));
  const page = await openSignedOut();
  assert.equal(await text(page, '#signin-notice'), reason);
  assert.equal(await page.eval("document.querySelector('#signin-form').hidden"), true);
  assert.equal(requests('GET', '/api/dashboard').length, 0);
  // The admin adds the host to GOBLIN_ALLOWED_HOSTS and restarts Uptime Goblin, as the reason says: the next
  // look at the tab finds out and offers the form, in the same page (Codex's checkpoint-2
  // review, CLIENT-1).
  mock.routes.delete('GET /api/session');
  await page.eval("window.__samePage = true; window.dispatchEvent(new Event('focus'))");
  await page.waitFor("document.querySelector('#signin-form').hidden === false");
  assert.equal(await page.eval("document.querySelector('#signin-notice').hidden"), true);
  assert.equal(await page.eval('window.__samePage'), true, 'no reload');
  assert.equal(requests('GET', '/api/dashboard').length, 0);
  assert.deepEqual(page.exceptions, []);
});

test(
  'a session that ends where Uptime Goblin refuses any sign-in from this plain-HTTP page asks for no password: the notices say why, and Sign in returns once that changes',
  { skip },
  async () => {
    // B11: plain-HTTP sessions were turned off while the page was open (=0 and a restart), or a
    // proxy now claims HTTPS for this http:// page. Every request gets 401 signin_required for
    // that transport. The sign-in dialog asked for the password, sent it over plain HTTP, and
    // only then did Uptime Goblin refuse it (https_required, proxy_proto_mismatch).
    const notices = page =>
      page.eval(
        "['#notice', '#configuration-notice'].map(s => document.querySelector(s)).map(e => [e.hidden, e.textContent, e.querySelectorAll('button').length])"
      );
    const focusTab = page => page.eval("window.dispatchEvent(new Event('focus'))");
    const routes = ['GET /api/dashboard', 'GET /api/session', 'PATCH /api/services/linux'];
    for (const [kind, code] of [
      ['http', 'https_required'],
      ['https', 'proxy_proto_mismatch'],
    ]) {
      const page = await open();
      await watchSignInDialog(page);
      await openDrawer(page);
      await setValue(page, '#source-name', `A draft over ${kind}`);
      mock.signedIn = false;
      mock.signedOutAs = 'signin_required';
      for (const route of routes)
        mock.routes.set(route, () => identity.unauthorized('signin_required', kind));
      // A person's action finds the session gone: Save.
      await click(page, '#connection-form [type=submit]');
      const shown = signInTexts[code];
      await page.waitFor(`document.querySelector('#notice').textContent === ${js(shown)}`);
      await page.waitFor("document.querySelector('#form-error').hidden === false");
      await page.settle();
      // The Save says the same, not Uptime Goblin's "Sign in to Uptime Goblin.", which nothing here can follow.
      assert.equal(await text(page, '#form-error'), shown, `${code}: the Save's error`);
      assert.equal(await page.eval('window.__signInShown'), 0, `${code}: no dialog`);
      assert.deepEqual(
        await notices(page),
        [
          [false, shown, 0],
          [false, shown, 0],
        ],
        code
      );
      assert.equal(
        await text(page, '#notice code'),
        code === 'https_required' ? null : 'proxy_set_header X-Forwarded-Proto $scheme;',
        'configuration shows as code'
      );
      assert.equal(await text(page, '#connection'), 'Signed out');
      // The draft stays, and no password was asked for or sent.
      assert.equal(await page.eval(isOpen('settings-dialog')), true);
      assert.equal(
        await page.eval("document.querySelector('#source-name').value"),
        `A draft over ${kind}`
      );
      assert.equal(requests('POST', '/api/auth/login').length, 0);
      // Polls stop, as after Cancel: each would only be refused again.
      const polls = requests('GET', '/api/dashboard').length;
      await page.eval('window.__poll()');
      await delay(200);
      assert.equal(requests('GET', '/api/dashboard').length, polls, 'no poll');
      // A look at the tab asks again. Still refused: the notice is not drawn again.
      await page.eval(`(() => {
        window.__changes = 0;
        new MutationObserver(list => (window.__changes += list.length)).observe(
          document.querySelector('#notice'),
          { childList: true, subtree: true, characterData: true, attributes: true }
        );
      })()`);
      const probes = requests('GET', '/api/session').length;
      await focusTab(page);
      await waitForRequests('GET', '/api/session', probes + 1);
      await page.settle();
      assert.equal(await page.eval('window.__changes'), 0, 'the notice was not drawn again');
      assert.equal(await page.eval('window.__signInShown'), 0);
      if (kind === 'https') {
        // Signed in again elsewhere (another tab, at the right address): the next look at the
        // tab finds the session working, and the refusal notices go at once, before the load
        // that follows has answered (clearSignedOut()).
        for (const route of routes) mock.routes.delete(route);
        mock.signedIn = true;
        mock.routes.set('GET /api/dashboard', request => ({
          ...defaultRoute(request.method, request.url, request),
          delay: 3000,
        }));
        await focusTab(page);
        await page.waitFor("document.querySelector('#connection').textContent !== 'Signed out'");
        assert.deepEqual(
          await notices(page),
          [
            [true, shown, 0],
            [true, shown, 0],
          ],
          'the notices went before the load answered'
        );
        mock.routes.delete('GET /api/dashboard');
        // The held load answers; the notices stay hidden.
        for (const end = Date.now() + 8000; mock.inflight && Date.now() < end; ) await delay(50);
        await page.settle();
        assert.equal(await page.eval("document.querySelector('#notice').hidden"), true);
        assert.deepEqual(await cspViolations(page), []);
        assert.deepEqual(page.exceptions, []);
        await closeNewest();
        break;
      }
      // Uptime Goblin allows this sign-in again (here: plain-HTTP sessions back on): the next look at
      // the tab offers Sign in, and the dialog signs in as usual.
      for (const route of routes) mock.routes.delete(route);
      for (const route of ['GET /api/dashboard', 'GET /api/session'])
        mock.routes.set(route, () =>
          mock.signedIn
            ? null
            : identity.unauthorized('signin_required', 'http', { insecureAllowed: true })
        );
      await focusTab(page);
      await page.waitFor("document.querySelector('#notice-sign-in')");
      const signedOut = 'Signed out. Sign in to see current readings. Sign in';
      assert.deepEqual(await notices(page), [
        [false, signedOut, 1],
        [false, signedOut, 1],
      ]);
      await page.eval("document.querySelector('#notice-sign-in').click()");
      await page.waitFor(isOpen('signin-dialog'));
      await settled(page, 'signin-dialog');
      await submitSignIn(page, 'reauth');
      await page.waitFor(`!${isOpen('signin-dialog')}`);
      await page.waitFor("document.querySelector('#notice').hidden");
      assert.equal(requests('POST', '/api/auth/login').length, 1);
      assert.equal(
        await page.eval("document.querySelector('#source-name').value"),
        `A draft over ${kind}`
      );
      assert.deepEqual(await cspViolations(page), []);
      assert.deepEqual(page.exceptions, []);
      await closeNewest();
      resetMock();
    }
  }
);

test(
  'a sign-in dialog left open when Uptime Goblin starts refusing any sign-in from this plain-HTTP page closes at the next look at the tab, before its password is sent',
  { skip },
  async () => {
    // The session ended while plain-HTTP sessions were allowed, so the dialog asked for the
    // password. Then they were turned off (=0 and a restart) while it waited: a submit would
    // send the password over plain HTTP and only then be refused (https_required).
    const page = await open();
    await watchSignInDialog(page);
    mock.signedIn = false;
    mock.signedOutAs = 'signin_required';
    const answer = insecureAllowed => () =>
      identity.unauthorized('signin_required', 'http', { insecureAllowed });
    for (const route of ['GET /api/dashboard', 'GET /api/session'])
      mock.routes.set(route, answer(true));
    await page.eval('window.__poll()');
    await page.waitFor(isOpen('signin-dialog'));
    await settled(page, 'signin-dialog');
    await setValue(page, '#reauth-password', mock.password);
    for (const route of ['GET /api/dashboard', 'GET /api/session'])
      mock.routes.set(route, answer(false));
    // The next look at the tab (the window gets the focus back) asks Uptime Goblin again.
    await page.eval("window.dispatchEvent(new Event('focus'))");
    await page.waitFor(`!${isOpen('signin-dialog')}`);
    await page.waitFor(
      `document.querySelector('#notice').textContent === ${js(signInTexts.https_required)}`
    );
    assert.equal(await page.eval("document.querySelector('#reauth-password').value"), '');
    assert.equal(
      await page.eval("!!document.querySelector('#notice-sign-in, #configuration-sign-in')"),
      false,
      'no Sign in'
    );
    assert.equal(await text(page, '#connection'), 'Signed out');
    assert.equal(requests('POST', '/api/auth/login').length, 0);
    // Polls stop, as after Cancel.
    const polls = requests('GET', '/api/dashboard').length;
    await page.eval('window.__poll()');
    await delay(200);
    assert.equal(requests('GET', '/api/dashboard').length, polls, 'no poll');
    assert.deepEqual(await cspViolations(page), []);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'requests that share one sign-in all learn that Uptime Goblin now refuses any sign-in from this plain-HTTP page: a dashboard load that joined draws no Sign in over the refusal',
  { skip },
  async () => {
    // Codex's checkpoint-2 review (CLIENT-2). A poll and a Refresh both found the session gone
    // while Uptime Goblin still allowed plain-HTTP sessions, so they shared one sign-in request. Its
    // GET /api/session answered after plain-HTTP sessions were turned off (=0 and a restart):
    // Uptime Goblin now refuses any sign-in from this page. Only the request that asked first was told.
    // The other kept its own 401, from when Uptime Goblin allowed it: a dashboard load then drew
    // "Signed out" and a Sign in over the refusal, which nothing on the page could follow, and
    // a Refresh said Uptime Goblin's "Sign in to Uptime Goblin.". Both orders are tried.
    const refusal = signInTexts.https_required;
    const answer = insecureAllowed =>
      identity.unauthorized('signin_required', 'http', { insecureAllowed });
    const routes = { poll: 'GET /api/dashboard', refresh: 'POST /api/refresh' };
    const send = {
      poll: page => page.eval('window.__poll()'),
      refresh: page => click(page, '#refresh'),
    };
    const notices = page =>
      page.eval(
        "['#notice', '#configuration-notice'].map(s => document.querySelector(s)).map(e => [e.hidden, e.textContent, e.querySelectorAll('button').length])"
      );
    for (const [first, joined] of [
      ['refresh', 'poll'],
      ['poll', 'refresh'],
    ]) {
      const page = await open();
      await watchSignInDialog(page);
      mock.signedIn = false;
      mock.signedOutAs = 'signin_required';
      // The first request's 401 starts the sign-in request, whose GET /api/session the mock
      // holds. The joined request's 401 is sent only once that has arrived, so the page has a
      // sign-in request to join; the held answer goes once the page has read that 401.
      let arrive, release;
      const arrived = new Promise(resolve => (arrive = resolve));
      const released = new Promise(resolve => (release = resolve));
      mock.routes.set(routes[first], () => answer(true));
      mock.routes.set(routes[joined], async () => {
        await arrived;
        return answer(true);
      });
      mock.routes.set('GET /api/session', async () => {
        arrive();
        // Bounded, so a failure below does not leave the connection open for good.
        await Promise.race([released, delay(10000)]);
        return answer(false);
      });
      const [joinedMethod, joinedPath] = routes[joined].split(' ');
      const sent = requests(joinedMethod, joinedPath).length,
        probes = requests('GET', '/api/session').length;
      await send[joined](page);
      await waitForRequests(joinedMethod, joinedPath, sent + 1);
      await send[first](page);
      await waitForRequests('GET', '/api/session', probes + 1);
      // Only the held GET /api/session is left on its way: the page has read the joined 401.
      await page.waitFor('window.__requests.size === 1');
      release();
      await page.waitFor("document.querySelector('#toast').hidden === false");
      await page.settle();
      const order = `${first} first, ${joined} joined`;
      assert.equal(requests('GET', '/api/session').length, probes + 1, `${order}: one question`);
      assert.deepEqual(
        await notices(page),
        [
          [false, refusal, 0],
          [false, refusal, 0],
        ],
        `${order}: the refusal stays, with no Sign in`
      );
      // The Refresh says the same, whether it asked first or joined.
      assert.equal(await text(page, '#toast'), refusal, `${order}: the Refresh's error`);
      assert.equal(await text(page, '#connection'), 'Signed out');
      assert.equal(await page.eval('window.__signInShown'), 0, `${order}: no dialog`);
      assert.equal(requests('POST', '/api/auth/login').length, 0);
      // Polls stop, as after Cancel: each would only be refused again.
      const polls = requests('GET', '/api/dashboard').length;
      await page.eval('window.__poll()');
      await delay(200);
      assert.equal(requests('GET', '/api/dashboard').length, polls, `${order}: no poll`);
      assert.deepEqual(await cspViolations(page), []);
      assert.deepEqual(page.exceptions, []);
      await closeNewest();
      resetMock();
    }
  }
);

test(
  'while Uptime Goblin does not answer at start, the page says so and asks again',
  { skip },
  async () => {
    let answers = 0;
    mock.routes.set('GET /api/session', () =>
      ++answers === 1 ? { status: 503, body: { error: 'Uptime Goblin is stopping.' } } : null
    );
    const page = await openPage(cdp, base + '/', {
      prelude,
      PageClass: Page,
      ready: "document.querySelector('#notice').hidden === false",
    });
    pages.push(page);
    assert.match(await text(page, '#notice'), /Uptime Goblin is not answering/);
    assert.equal(await page.eval("document.querySelector('#signin-page').hidden"), true);
    // Asked again after 5 s, then the web app starts.
    await page.waitFor(cards, 8000);
    assert.equal(answers, 2);
    assert.equal(await page.eval("document.querySelector('#notice').hidden"), true);
    assert.deepEqual(page.exceptions, []);
  }
);

test('a lockout counts down from Retry-After, then allows the next attempt', { skip }, async () => {
  mock.routes.set('POST /api/auth/login', () => identity.refused(429, 'locked', 2));
  const page = await openSignedOut();
  await submitSignIn(page, 'signin', 'a wrong password again');
  await page.waitFor("document.querySelector('#signin-countdown').hidden === false");
  assert.equal(await text(page, '#signin-error'), 'Too many attempts. You can try again in 2 s.');
  assert.match(await text(page, '#signin-countdown'), /^You can try again in [12] s\.$/);
  assert.equal(
    await page.eval("document.querySelector('#signin-countdown').getAttribute('aria-live')"),
    'off'
  );
  assert.equal(
    await page.eval("document.querySelector('#signin-countdown').closest('[role=alert]')"),
    null,
    'the countdown is not announced every second'
  );
  assert.equal(await page.eval("document.querySelector('#signin-submit').disabled"), true);
  assert.equal(await page.eval('document.activeElement.id'), 'signin-password');
  // Enter while locked sends nothing.
  await setValue(page, '#signin-password', 'another try');
  await page.press('Enter');
  await delay(100);
  assert.equal(requests('POST', '/api/auth/login').length, 1);
  await page.waitFor("!document.querySelector('#signin-submit').disabled", 4000);
  assert.equal(await text(page, '#signin-error'), 'You can try again now.');
  assert.equal(await page.eval("document.querySelector('#signin-countdown').hidden"), true);
  assert.equal(await page.eval('document.activeElement.id'), 'signin-password');
  mock.routes.delete('POST /api/auth/login');
  await submitSignIn(page, 'signin');
  await page.waitFor(cards);
  assert.deepEqual(page.exceptions, []);
});

test(
  'a sign-in the browser did not keep is explained, and so are two cookies',
  { skip },
  async () => {
    // Uptime Goblin answers the login, but the next request still has no session: the browser dropped
    // the cookie (for example a Secure cookie on a plain-HTTP page).
    mock.routes.set('POST /api/auth/login', () => ({ body: mock.sessionBody() }));
    const page = await openSignedOut();
    await submitSignIn(page, 'signin');
    await page.waitFor(
      `document.querySelector('#signin-error').textContent === ${js(signInTexts.cookie_not_stored)}`
    );
    mock.routes.set('GET /api/session', () => identity.unauthorized('multiple_credentials'));
    await submitSignIn(page, 'signin');
    await page.waitFor(
      `document.querySelector('#signin-error').textContent === ${js(signInTexts.multiple_credentials)}`
    );
    assert.equal(await page.eval("document.querySelector('#signin-page').hidden"), false);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'a session that ends during a save asks to sign in over the drawer, keeps the draft, and retries once with the same key',
  { skip },
  async () => {
    const page = await open();
    await openDrawer(page);
    await setValue(page, '#source-name', 'A draft kept across sign-in');
    // Revoked elsewhere (another device signed it out, or the password changed).
    mock.signedIn = false;
    await click(page, '#connection-form [type=submit]');
    await page.waitFor(isOpen('signin-dialog'));
    await settled(page, 'signin-dialog');
    assert.equal(await page.eval(isOpen('settings-dialog')), true, 'the drawer stays open');
    assert.equal(
      await page.eval("document.querySelector('#source-name').value"),
      'A draft kept across sign-in'
    );
    assert.equal(await page.eval("document.querySelector('#reauth-login').value"), 'admin');
    assert.equal(await page.eval('document.activeElement.id'), 'reauth-password');
    // The dialog is above the drawer.
    const { x, y } = await page.center('#reauth-password');
    assert.equal(await page.eval(`document.elementFromPoint(${x}, ${y})?.id`), 'reauth-password');
    assert.equal(requests('PATCH', '/api/services/linux').length, 1);
    // While it is open, polls wait.
    const polls = requests('GET', '/api/dashboard').length;
    await page.eval('window.__poll()');
    await delay(100);
    assert.equal(requests('GET', '/api/dashboard').length, polls);

    await submitSignIn(page, 'reauth');
    await page.waitFor(`!${isOpen('signin-dialog')}`);
    await page.waitFor(`!${isOpen('settings-dialog')}`);
    const patches = requests('PATCH', '/api/services/linux');
    assert.equal(patches.length, 2, 'sent once more');
    assert.equal(patches[1].headers['idempotency-key'], patches[0].headers['idempotency-key']);
    assert.equal(patches[1].headers['if-match'], patches[0].headers['if-match']);
    assert.equal(mock.dashboard.config.services[0].name, 'A draft kept across sign-in');
    assert.deepEqual(await cspViolations(page), []);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'a 401 when another tab has signed in meanwhile retries once without asking',
  { skip },
  async () => {
    const page = await open();
    await watchSignInDialog(page);
    let refused = 0;
    mock.routes.set('PATCH /api/services/linux', () =>
      refused++ ? null : identity.unauthorized('session_expired')
    );
    await click(page, '.pause-control[data-toggle="linux"]');
    await waitForRequests('PATCH', '/api/services/linux', 2);
    await page.settle();
    const patches = requests('PATCH', '/api/services/linux');
    assert.equal(patches[1].headers['idempotency-key'], patches[0].headers['idempotency-key']);
    assert.equal(mock.dashboard.config.services[0].enabled, false);
    assert.equal(await page.eval('window.__signInShown'), 0);
    // The check was a background request: it does not keep an idle session alive.
    const check = requests('GET', '/api/session').at(-1);
    assert.equal(check.headers['x-goblin-activity'], 'background');
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'a write without a key of its own is sent again after signing in with the key api() chose',
  { skip },
  async () => {
    // Refresh sends no Idempotency-Key of its own: api() chooses one, and the retry after
    // signing in again must reuse it, so a first attempt that ran is not applied twice.
    const page = await open();
    mock.routes.set('POST /api/refresh', () =>
      mock.signedIn ? { body: { ok: true } } : identity.unauthorized('session_expired')
    );
    mock.signedIn = false;
    await click(page, '#refresh');
    await page.waitFor(isOpen('signin-dialog'));
    await settled(page, 'signin-dialog');
    await submitSignIn(page, 'reauth');
    await waitForRequests('POST', '/api/refresh', 2);
    const [first, retry] = requests('POST', '/api/refresh');
    assert.match(first.headers['idempotency-key'], /^[0-9a-f-]{36}$/);
    assert.equal(retry.headers['idempotency-key'], first.headers['idempotency-key']);
    assert.equal(retry.body, first.body);
    await page.settle();
    assert.equal(requests('POST', '/api/refresh').length, 2, 'once more, not again and again');
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'a 401 without a code (Uptime Goblin rolled back to 1.4.x) asks nobody to sign in and offers the reload',
  { skip },
  async () => {
    const page = await open();
    await watchSignInDialog(page);
    await openDrawer(page);
    await setValue(page, '#source-name', 'Unsaved while Uptime Goblin went back');
    // 1.4.3 answered 401 without a code and without naming its build.
    mock.routes.set('PATCH /api/services/linux', () => ({
      status: 401,
      build: null,
      body: { error: 'Authentication required' },
    }));
    await click(page, '#connection-form [type=submit]');
    await page.waitFor("document.querySelector('#form-error').hidden === false");
    assert.equal(await page.eval('window.__signInShown'), 0);
    assert.equal(requests('GET', '/api/session').length, 1, 'only the check at start');
    // The draft is kept, so the reload is offered rather than done.
    await page.waitFor(bannerShown);
    assert.match(await text(page, '#update-text'), /Uptime Goblin was updated/);
    assert.equal(
      await page.eval("document.querySelector('#source-name').value"),
      'Unsaved while Uptime Goblin went back'
    );
    assert.equal(pageLoads(), 1);
    assert.deepEqual(page.exceptions, []);
  }
);

test('a clean page reloads by itself when a poll gets a 401 without a code', { skip }, async () => {
  const page = await open();
  mock.routes.set('GET /api/dashboard', () => ({
    status: 401,
    build: null,
    body: { error: 'Authentication required' },
  }));
  await page.eval('window.__poll()');
  const end = Date.now() + 8000;
  while (pageLoads() < 2 && Date.now() < end) await delay(50);
  assert.equal(pageLoads(), 2);
  assert.equal(
    requests('GET', '/api/session').filter(r => r.headers['x-goblin-activity'] === 'background')
      .length,
    0,
    'no sign-in was asked for'
  );
  mock.routes.delete('GET /api/dashboard');
});

// After a rollback to 1.4.x a page with unsaved changes stays (the update banner offers the
// reload). It said "Signed out. Sign in to see current readings." with a Sign in whose dialog
// could never succeed against 1.4.x, which has neither /api/session nor /api/auth/login: each
// attempt only brought up the browser's Basic prompt, and the right password failed with 1.4.x's
// "Sign in to Uptime Goblin" (§18 F7).
const olderReleaseText =
  'Uptime Goblin now runs an older release, which this page cannot sign in to, so what it shows is no longer updated. Reload the page to use that release.';
/** Orbit 1.4.x answers in place of this release: a 401 without a code, as 1.4.3 sends it. */
function rollBack() {
  const refused = () => ({ status: 401, build: null, body: { error: 'Sign in to Uptime Goblin' } });
  for (const route of [
    'GET /api/dashboard',
    'GET /api/session',
    'POST /api/auth/login',
    'GET /api/version',
  ])
    mock.routes.set(route, refused);
}
/** Opens Appearance and changes the workspace's name without saving it. */
async function openWithDraft() {
  const page = await open('#configure/appearance');
  await page.waitFor("document.querySelector('#workspace-title')");
  await setValue(page, '#workspace-title', 'A draft across the rollback');
  return page;
}
const draftKept = page =>
  page.eval(
    "document.querySelector('#workspace-title')?.value === 'A draft across the rollback' && document.querySelector('#dirty-status')?.textContent === 'You have unsaved changes'"
  );

test(
  'after a rollback to 1.4.x a page with a draft says to reload instead of offering a Sign in',
  { skip },
  async () => {
    const page = await openWithDraft();
    await watchSignInDialog(page);
    const checks = requests('GET', '/api/session').length;
    rollBack();
    await page.eval('window.__poll()');
    await page.waitFor(bannerShown);
    await page.waitFor("document.querySelector('#configuration-notice').hidden === false");
    assert.equal(await text(page, '#configuration-notice'), olderReleaseText);
    assert.equal(await text(page, '#notice'), olderReleaseText);
    assert.equal(
      await page.eval("!!document.querySelector('#configuration-sign-in, #notice-sign-in')"),
      false,
      'no Sign in'
    );
    assert.equal(await text(page, '#connection'), 'Reload needed');
    await delay(300);
    assert.equal(await page.eval('window.__signInShown'), 0);
    assert.equal(requests('GET', '/api/session').length, checks, 'nothing asked to sign in');
    assert.equal(await draftKept(page), true);
    assert.equal(pageLoads(), 1);
    assert.deepEqual(await cspViolations(page), []);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'Sign in on a signed-out page after a rollback to 1.4.x opens no dialog, and says to reload',
  { skip },
  async () => {
    // Signed out under 1.5 (the dialog was cancelled), then Uptime Goblin went back to 1.4.x: the
    // notice's Sign in checked GET /api/session, and on any failure opened the dialog.
    const page = await openWithDraft();
    mock.signedIn = false;
    await page.eval('window.__poll()');
    await page.waitFor(isOpen('signin-dialog'));
    await settled(page, 'signin-dialog');
    await page.click('#reauth-cancel');
    await page.waitFor(`!${isOpen('signin-dialog')}`);
    await page.waitFor("!!document.querySelector('#configuration-sign-in')");
    await page.settle();
    await watchSignInDialog(page);
    rollBack();
    const checks = requests('GET', '/api/session').length;
    await page.click('#configuration-sign-in');
    await waitForRequests('GET', '/api/session', checks + 1);
    await page.settle();
    await delay(300);
    assert.equal(await page.eval('window.__signInShown'), 0, 'no dialog');
    assert.equal(await text(page, '#configuration-notice'), olderReleaseText);
    assert.equal(await page.eval("!!document.querySelector('#configuration-sign-in')"), false);
    await page.waitFor(bannerShown);
    assert.equal(requests('POST', '/api/auth/login').length, 0);
    // The Sign in that had the focus is gone: the page's heading takes it.
    assert.equal(await page.eval('document.activeElement.id'), 'configuration-section-title');
    assert.equal(await draftKept(page), true);
    assert.equal(pageLoads(), 1);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'a sign-in dialog open when Uptime Goblin goes back to 1.4.x says to reload, not that the password is wrong',
  { skip },
  async () => {
    const page = await open();
    await openDrawer(page);
    await setValue(page, '#source-name', 'A draft across the rollback');
    mock.signedIn = false;
    await click(page, '#connection-form [type=submit]');
    await page.waitFor(isOpen('signin-dialog'));
    await settled(page, 'signin-dialog');
    rollBack();
    await submitSignIn(page, 'reauth');
    await page.waitFor("document.querySelector('#reauth-error').hidden === false");
    assert.equal(await text(page, '#reauth-error'), olderReleaseText);
    await page.waitFor(bannerShown);
    assert.equal(await page.eval(isOpen('signin-dialog')), true);
    assert.equal(
      await page.eval("document.querySelector('#source-name').value"),
      'A draft across the rollback'
    );
    assert.equal(pageLoads(), 1);
    assert.deepEqual(page.exceptions, []);
  }
);

// B42, a residual of Codex's review of F4. A poll and a Refresh both found the session gone under
// 1.5, so they shared one sign-in request. Its GET /api/session was answered by 1.4.x (Uptime Goblin was
// rolled back meanwhile): nobody was asked, and the page said to reload. The dashboard load,
// whether it asked first or joined, kept its own 401 from 1.5 (signin_required) and drew "Signed
// out" and a Sign in over that notice, whose dialog could never succeed against 1.4.x; a Refresh
// said 1.5's "Sign in to Uptime Goblin.". Each order is a test of its own, on a page whose draft keeps it
// from reloading into 1.4.x by itself.
for (const [first, joined] of [
  ['refresh', 'poll'],
  ['poll', 'refresh'],
])
  test(
    `requests that share one sign-in all learn that Uptime Goblin went back to 1.4.x: a dashboard load draws no Sign in over the notice that says to reload (${first} first, ${joined} joined)`,
    { skip },
    async () => {
      const routes = { poll: 'GET /api/dashboard', refresh: 'POST /api/refresh' };
      const send = {
        poll: page => page.eval('window.__poll()'),
        refresh: page => click(page, '#refresh'),
      };
      const notices = page =>
        page.eval(
          "['#notice', '#configuration-notice'].map(s => document.querySelector(s)).map(e => [e.hidden, e.textContent, e.querySelectorAll('button').length])"
        );
      const shown = [
        [false, olderReleaseText, 0],
        [false, olderReleaseText, 0],
      ];
      // Each notice is a status region, which reads out every change: how often each was drawn.
      const draws = page => page.eval("['notice', 'configuration-notice'].map(id => __draws[id])");
      const page = await openWithDraft();
      await watchSignInDialog(page);
      await page.eval(`(() => {
        window.__draws = {};
        for (const id of ['notice', 'configuration-notice']) {
          __draws[id] = 0;
          new MutationObserver(records => {
            __draws[id] += records.filter(r => r.addedNodes.length).length;
          }).observe(document.getElementById(id), { childList: true, subtree: true });
        }
      })()`);
      mock.signedIn = false;
      mock.signedOutAs = 'signin_required';
      // The first request's 401 starts the sign-in request, whose GET /api/session the mock
      // holds. The joined request's 401 is sent only once that has arrived, so the page has a
      // sign-in request to join; the held answer, from 1.4.x, goes once the page has read it.
      let arrive, release;
      const arrived = new Promise(resolve => (arrive = resolve));
      const released = new Promise(resolve => (release = resolve));
      mock.routes.set(routes[first], () => identity.unauthorized('signin_required'));
      mock.routes.set(routes[joined], async () => {
        await arrived;
        return identity.unauthorized('signin_required');
      });
      mock.routes.set('GET /api/session', async () => {
        arrive();
        // Bounded, so a failure below does not leave the connection open for good.
        await Promise.race([released, delay(10000)]);
        return { status: 401, build: null, body: { error: 'Sign in to Uptime Goblin' } };
      });
      const [joinedMethod, joinedPath] = routes[joined].split(' ');
      const sent = requests(joinedMethod, joinedPath).length,
        probes = requests('GET', '/api/session').length;
      await send[joined](page);
      await waitForRequests(joinedMethod, joinedPath, sent + 1);
      await send[first](page);
      await waitForRequests('GET', '/api/session', probes + 1);
      // Only the held GET /api/session is left on its way: the page has read the joined 401.
      await page.waitFor('window.__requests.size === 1');
      // From here on 1.4.x answers.
      rollBack();
      release();
      await page.waitFor("document.querySelector('#toast').hidden === false");
      await page.settle();
      assert.equal(requests('GET', '/api/session').length, probes + 1, 'one question');
      assert.deepEqual(await notices(page), shown, 'the notice stays, with no Sign in');
      assert.deepEqual(await draws(page), [1, 1], 'each notice drawn once');
      // The Refresh says the same, whether it asked first or joined.
      assert.equal(await text(page, '#toast'), olderReleaseText, "the Refresh's error");
      assert.equal(await text(page, '#connection'), 'Reload needed');
      await page.waitFor(bannerShown);
      assert.equal(await page.eval('window.__signInShown'), 0, 'no dialog');
      assert.equal(requests('POST', '/api/auth/login').length, 0);
      // The next poll, which 1.4.x refuses too, leaves the notice as it is.
      await page.poll();
      assert.deepEqual(await notices(page), shown, 'after the next poll');
      assert.deepEqual(await draws(page), [1, 1], 'not drawn again by the next poll');
      assert.equal(await draftKept(page), true);
      assert.equal(pageLoads(), 1);
      assert.deepEqual(await cspViolations(page), []);
      assert.deepEqual(page.exceptions, []);
    }
  );

test(
  'Escape cancels signing in again: the drawer and its draft stay, and the save says why',
  { skip },
  async () => {
    const page = await open();
    await openDrawer(page);
    await setValue(page, '#source-name', 'Kept after Cancel');
    mock.signedIn = false;
    await click(page, '#connection-form [type=submit]');
    await page.waitFor(isOpen('signin-dialog'));
    await settled(page, 'signin-dialog');
    await page.eval('window.__confirmCalls = 0');
    await page.press('Escape');
    await page.waitFor(`!${isOpen('signin-dialog')}`);
    await page.waitFor("document.querySelector('#form-error').hidden === false");
    assert.equal(await page.eval(isOpen('settings-dialog')), true, 'the drawer stays open');
    assert.equal(await page.eval('window.__confirmCalls'), 0, 'nothing asked about the draft');
    assert.equal(
      await page.eval("document.querySelector('#source-name').value"),
      'Kept after Cancel'
    );
    assert.equal(await text(page, '#form-error'), identityMessages.session_expired);
    assert.equal(requests('PATCH', '/api/services/linux').length, 1, 'not sent again');
    // Signed out: polls wait instead of asking again every 15 s.
    const polls = requests('GET', '/api/dashboard').length;
    await page.eval('window.__poll()');
    await delay(100);
    assert.equal(requests('GET', '/api/dashboard').length, polls);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'a poll that finds the session gone asks to sign in; after Cancel the dashboard says it is signed out',
  { skip },
  async () => {
    const page = await open();
    mock.signedIn = false;
    await page.eval('window.__poll()');
    await page.waitFor(isOpen('signin-dialog'));
    await settled(page, 'signin-dialog');
    // The poll that found out was a background request.
    assert.equal(
      requests('GET', '/api/dashboard').at(-1).headers['x-goblin-activity'],
      'background'
    );
    // While the dialog is open, polls wait rather than pile up behind it.
    const asked = requests('GET', '/api/dashboard').length;
    await page.eval('window.__poll()');
    await delay(100);
    assert.equal(requests('GET', '/api/dashboard').length, asked);
    await page.eval("document.querySelector('#reauth-cancel').click()");
    await page.waitFor(`!${isOpen('signin-dialog')}`);
    await page.waitFor(
      "document.querySelector('#notice').textContent.startsWith('Signed out. Sign in to see current readings.')"
    );
    assert.equal(await text(page, '#connection'), 'Signed out');
    // Cancelled: the next polls neither ask Uptime Goblin nor open the dialog again every 15 s.
    await page.eval('window.__poll()');
    await delay(200);
    assert.equal(requests('GET', '/api/dashboard').length, asked);
    assert.equal(await page.eval(isOpen('signin-dialog')), false);
    // The notice offers the way back in.
    await page.eval("document.querySelector('#notice-sign-in').click()");
    await page.waitFor(isOpen('signin-dialog'));
    await settled(page, 'signin-dialog');
    await submitSignIn(page, 'reauth');
    await page.waitFor(`!${isOpen('signin-dialog')}`);
    await page.waitFor("document.querySelector('#notice').hidden");
    const loads = requests('GET', '/api/dashboard').length;
    await page.poll();
    assert.equal(requests('GET', '/api/dashboard').length, loads + 1, 'polls resume');
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'the sign-in dialog closes by itself when the tab comes back signed in elsewhere',
  { skip },
  async () => {
    const page = await open();
    mock.signedIn = false;
    await page.eval('window.__poll()');
    await page.waitFor(isOpen('signin-dialog'));
    await settled(page, 'signin-dialog');
    // Another tab of this browser signed in: the cookie is shared.
    mock.signedIn = true;
    await page.eval("window.dispatchEvent(new Event('focus'))");
    await page.waitFor(`!${isOpen('signin-dialog')}`);
    await page.waitFor("document.querySelector('#notice').hidden");
    assert.equal(requests('POST', '/api/auth/login').length, 0);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'polls and kiosk reads are background requests; ordinary user actions are foreground',
  { skip },
  async () => {
    const page = await open();
    const lastLoad = () => requests('GET', '/api/dashboard').at(-1).headers['x-goblin-activity'];
    assert.equal(lastLoad(), undefined, 'the first load');
    await page.poll();
    assert.equal(lastLoad(), 'background', 'a poll');
    // A visible tab's catch-up after coming back is a poll too.
    const loads = requests('GET', '/api/dashboard').length;
    await page.eval(
      "window.__hidden = false; document.dispatchEvent(new Event('visibilitychange'))"
    );
    await waitForRequests('GET', '/api/dashboard', loads + 1);
    assert.equal(lastLoad(), 'background');
    mock.routes.set('POST /api/refresh', () => ({ body: { ok: true } }));
    await click(page, '#refresh');
    await waitForRequests('POST', '/api/refresh', 1);
    await page.settle();
    assert.equal(requests('POST', '/api/refresh')[0].headers['x-goblin-activity'], undefined);
    assert.equal(lastLoad(), undefined, 'the load after Refresh');
    await pages.pop().close();

    const kiosk = await open('?kiosk=1');
    assert.equal(lastLoad(), 'background', 'the first kiosk load');
    await kiosk.poll();
    assert.equal(lastLoad(), 'background', 'a kiosk poll does not extend idle');
    for (const r of mock.requests)
      assert.equal(r.headers['x-goblin-client'], `web/${web.build}`, r.path);
  }
);

test('history polls and all kiosk history reads are background requests', { skip }, async () => {
  // Otherwise a visible tab with an expanded card would extend the idle limit every few
  // minutes (each time the chart's window moves on a bucket), and never be signed out.
  const page = await open();
  await expand(page);
  await page.waitFor("document.querySelector('#graph-linux svg.chart')");
  const history = () => requests('GET', '/api/history/');
  const lastHistory = () => history().at(-1).headers['x-goblin-activity'];
  assert.equal(lastHistory(), undefined, 'expanding the card');
  // The chart's window (24h / 300 = 4.8 min) has moved on, so the next poll fetches it again.
  let before = history().length;
  await page.eval('window.__skew = 10 * 60 * 1000');
  await page.poll();
  await waitForRequests('GET', '/api/history/', before + 1);
  assert.equal(lastHistory(), 'background', 'a poll');
  // A range the user chose is the user's action.
  before = history().length;
  await click(page, '[data-range="7d"]');
  await waitForRequests('GET', '/api/history/', before + 1);
  await page.settle();
  assert.equal(lastHistory(), undefined, 'choosing a range');
  await pages.pop().close();

  const kiosk = await open('?kiosk=1');
  await expand(kiosk);
  await kiosk.waitFor("document.querySelector('#graph-linux svg.chart')");
  before = history().length;
  await kiosk.eval('window.__skew = 10 * 60 * 1000');
  await kiosk.poll();
  await waitForRequests('GET', '/api/history/', before + 1);
  assert.equal(lastHistory(), 'background', 'a kiosk history poll does not extend idle');
  assert.deepEqual([...page.exceptions, ...kiosk.exceptions], []);
});

test(
  'every kiosk read stays background through 100 reloads, history, probes and an update',
  { skip },
  async () => {
    mock.routes.set('GET /api/version', () => ({ body: { version: '1.5.0', build: web.build } }));
    mock.routes.set('HEAD /api/version', () => ({ status: 204 }));
    mock.routes.set('POST /api/refresh', () => ({ body: { ok: true } }));
    const kiosk = await open('?kiosk=1');
    const dashboard = () => requests('GET', '/api/dashboard');
    const reads = () => mock.requests.filter(request => ['GET', 'HEAD'].includes(request.method));
    const assertBackground = () => {
      for (const request of reads())
        assert.equal(
          request.headers['x-goblin-activity'],
          'background',
          `${request.method} ${request.path}`
        );
    };
    assertBackground();
    const before = dashboard().length;
    for (let i = 0; i < 100; i += 1) await kiosk.poll();
    assert.equal(dashboard().length, before + 100, '100 completed dashboard reloads');
    await expand(kiosk);
    await kiosk.waitFor("document.querySelector('#graph-linux svg.chart')");
    const history = requests('GET', '/api/history/').length;
    assert.ok(history > 0, 'opening history performed a read');
    await kiosk.eval('window.__skew = 10 * 60 * 1000');
    await kiosk.poll();
    await waitForRequests('GET', '/api/history/', history + 1);
    await kiosk.eval(`import(${js(`/assets/${web.build}/modules/core/api.js`)}).then(async ({ api }) => {
    await api('/api/session', { background: false });
    await api('/api/version', { background: false });
    await api('/api/version', { method: 'HEAD', background: false });
    await api('/api/refresh', { method: 'POST', background: true });
  })`);
    await kiosk.eval('window.__hidden = true; window.__probe()');
    await kiosk.settle();
    await kiosk.eval('window.__hidden = false');
    assert.ok(requests('GET', '/api/session').length > 0);
    assert.ok(requests('GET', '/api/version').length >= 2);
    assert.equal(requests('HEAD', '/api/version').length, 1);
    const writes = requests('POST', '/api/refresh');
    assert.equal(writes.length, 1);
    assert.equal(
      writes[0].headers['x-goblin-activity'],
      undefined,
      'writes ignore background: true'
    );
    assert.ok(writes[0].headers['idempotency-key'], 'the write retains its idempotency key');
    assertBackground();
    const oldLoads = pageLoads();
    web.previous = web.build;
    web.build = 'b2c3d4e5f6a7';
    await kiosk.eval('window.__poll()');
    await kiosk.waitFor(
      `document.querySelector('meta[name="orbit-build"]')?.content === ${js(web.build)}`,
      8000
    );
    await kiosk.waitFor(cards);
    await kiosk.settle();
    assert.equal(pageLoads(), oldLoads + 1, 'the update caused a real page reload');
    assert.equal(await kiosk.eval('location.search'), '?kiosk=1');
    assertBackground();
    assert.deepEqual(kiosk.exceptions, []);
  }
);

test(
  'the user chip is a disclosure button that keyboard and pointer can use',
  { skip },
  async () => {
    const page = await open();
    const expanded = () =>
      page.eval("document.querySelector('#user-chip').getAttribute('aria-expanded')");
    const menuHidden = () => page.eval("document.querySelector('#user-menu').hidden");
    assert.equal(
      await page.eval("document.querySelector('#user-chip').getAttribute('aria-controls')"),
      'user-menu'
    );
    assert.equal(
      await page.eval("document.querySelector('#user-menu').getAttribute('role')"),
      null
    );
    await page.eval("document.querySelector('#user-chip').focus()");
    await page.press('Enter');
    assert.equal(await expanded(), 'true');
    assert.equal(await menuHidden(), false);
    assert.deepEqual(
      await page.eval(
        "[...document.querySelectorAll('#user-menu a, #user-menu button')].map(e => e.textContent)"
      ),
      ['Account', 'Sign out']
    );
    await page.press('Escape');
    assert.equal(await expanded(), 'false');
    assert.equal(await menuHidden(), true);
    assert.equal(await page.eval('document.activeElement.id'), 'user-chip');
    // Space toggles it as well.
    for (const type of ['keyDown', 'keyUp'])
      await page.send('Input.dispatchKeyEvent', {
        type,
        key: ' ',
        code: 'Space',
        windowsVirtualKeyCode: 32,
        ...(type === 'keyDown' ? { text: ' ' } : {}),
      });
    assert.equal(await menuHidden(), false);
    // A click elsewhere closes it.
    await page.click('#dashboard-title');
    assert.equal(await menuHidden(), true);
    assert.equal(await expanded(), 'false');
    // Account opens the Account page and closes the menu.
    await page.click('#user-chip');
    await page.click('#user-account');
    await page.waitFor("location.hash === '#configure/account'");
    await page.waitFor("document.querySelector('#account-details')");
    assert.equal(await menuHidden(), true);
    assert.deepEqual(page.exceptions, []);
  }
);

test('the Security page’s old address opens the Account page', { skip }, async () => {
  const page = await open('#configure/security');
  await page.waitFor("document.querySelector('#account-details')");
  assert.equal(await page.eval('location.hash'), '#configure/account');
  assert.equal(
    await page.eval("document.querySelector('#configuration-nav [aria-current=page]').textContent"),
    'Account'
  );
  assert.equal(await text(page, '#configuration-section-title'), 'Your sign-in and sessions.');
  assert.equal(
    await page.eval(
      "[...document.querySelectorAll('#configuration-nav a')].some(a => a.textContent === 'Security')"
    ),
    false
  );
  // Following a link to it from inside the app lands there too.
  await page.eval("location.hash = '#configure/overview'");
  await page.waitFor("document.querySelector('.configuration-welcome')");
  await page.eval("location.hash = '#configure/security'");
  await page.waitFor(
    "location.hash === '#configure/account' && document.querySelector('#account-details')"
  );
  assert.deepEqual(page.exceptions, []);
});

test(
  'the session banners warn about plain HTTP and a pending auth.json update',
  { skip },
  async () => {
    mock.sessionBody = () =>
      identity.session('session', {
        transport: { kind: 'http', https: false, insecure: true, insecureAllowed: true },
        mirrorPending: true,
      });
    const page = await open();
    assert.equal(await page.eval("document.querySelector('#session-banner').hidden"), false);
    assert.equal(
      await page.eval("document.querySelector('#session-banner').getAttribute('role')"),
      'status'
    );
    assert.deepEqual(
      await page.eval(
        "[...document.querySelectorAll('#session-banner p')].map(p => p.textContent)"
      ),
      [
        'This session uses plain HTTP, so anyone who can watch the traffic between your browser and Uptime Goblin can see its sign-in cookie, and your password each time you sign in or change it. Serve Uptime Goblin over HTTPS, then set GOBLIN_INSECURE_HTTP_SESSIONS=0 and restart Uptime Goblin (Docker: in .env, then docker compose up -d).',
        'Uptime Goblin saved the admin password but could not update auth.json. Until it does, a rollback to 1.4.x would still use the previous password. Uptime Goblin retries hourly.',
      ]
    );
    // On an https: page the session is plain HTTP only because the proxy does not say the page
    // is https: the banner names that fix instead (§17 E9; S11 shows it through a real proxy).
    assert.match(
      await page.eval(
        `import('/assets/${web.build}/modules/identity/session.js').then(m => m.insecureBanner({ kind: 'http', insecure: true }, 'https:'))`
      ),
      /^Your browser uses HTTPS, but the reverse proxy in front of Uptime Goblin does not tell Uptime Goblin so, .* In nginx add `proxy_set_header X-Forwarded-Proto \$scheme;` .* then set GOBLIN_INSECURE_HTTP_SESSIONS=0, restart Uptime Goblin \(Docker: in \.env, then docker compose up -d\) and sign in again\.$/
    );
    // B12: the way back is =0 in every install mode. Under Docker Compose an unset variable
    // means compose-default, on for a loopback publish, so "remove it" changes nothing there.
    assert.deepEqual(
      await page.eval(
        `import('/assets/${web.build}/modules/identity/session.js').then(m => Object.values(m.bannerTexts).filter(t => /remove GOBLIN_INSECURE_HTTP_SESSIONS/i.test(t)))`
      ),
      []
    );
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'an open page reads the session again every five minutes, so its banners follow Uptime Goblin',
  { skip },
  async () => {
    // The banners came only from GET /api/session, which a signed-in page read at start and
    // then only on the Account page: after Uptime Goblin's hourly retry wrote auth.json the banner
    // stayed until a reload, and a tab open during another tab's password change never showed
    // it (§19 G8).
    let pending = true;
    mock.sessionBody = () => identity.session('session', { mirrorPending: pending });
    const page = await open();
    const banner = "document.querySelector('#session-banner')";
    const reads = () => requests('GET', '/api/session').length;
    assert.equal(await page.eval(`${banner}.hidden`), false);
    // Uptime Goblin's retry wrote auth.json.
    pending = false;
    const before = reads();
    await page.poll();
    assert.equal(reads(), before, 'not read again within five minutes');
    assert.equal(await page.eval(`${banner}.hidden`), false);
    await page.eval('window.__perfSkew += 300001');
    await page.poll();
    await page.waitFor(`${banner}.hidden`);
    assert.equal(reads(), before + 1);
    assert.equal(
      requests('GET', '/api/session').at(-1).headers['x-goblin-activity'],
      'background',
      'the read keeps no idle session signed in'
    );
    // Another tab changed the password and could not write auth.json.
    pending = true;
    await page.eval('window.__perfSkew += 300001');
    await page.poll();
    await page.waitFor(`!${banner}.hidden`);
    assert.equal(
      await text(page, '#session-banner'),
      'Uptime Goblin saved the admin password but could not update auth.json. Until it does, a rollback to 1.4.x would still use the previous password. Uptime Goblin retries hourly.'
    );
    // A session read without an answer changes nothing. (Chrome sends a GET again itself when
    // a kept-alive connection closes without an answer, so the count only grows.)
    mock.routes.set('GET /api/session', () => ({ drop: true }));
    pending = false;
    await page.eval('window.__perfSkew += 300001');
    await page.poll();
    await page.settle();
    assert.ok(reads() > before + 2);
    assert.equal(await page.eval(`${banner}.hidden`), false);
    // A poll that did not load reads nothing more (a release before 1.5 would refuse it too).
    mock.routes.delete('GET /api/session');
    mock.routes.set('GET /api/dashboard', () => ({
      status: 503,
      body: { error: 'Uptime Goblin cannot reach its collector.' },
    }));
    const unloaded = reads();
    await page.eval('window.__perfSkew += 300001');
    await page.poll();
    await page.settle();
    assert.equal(reads(), unloaded);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'the session banners are drawn again only when they change, so they are not read out again',
  { skip },
  async () => {
    // #session-banner is a role="status" region: replacing its paragraphs at every read of the
    // session (the Account page's, and every five minutes) read the same warnings out again.
    let insecure = true;
    mock.sessionBody = () =>
      identity.session('session', {
        transport: { kind: 'http', https: false, insecure, insecureAllowed: true },
        mirrorPending: true,
      });
    const page = await open();
    const banner = "document.querySelector('#session-banner')";
    await page.eval(`(() => {
      window.__bannerChanges = 0;
      new MutationObserver(records => (window.__bannerChanges += records.length)).observe(
        ${banner},
        { childList: true, subtree: true, characterData: true }
      );
    })()`);
    const reads = requests('GET', '/api/session').length;
    await page.eval("location.hash = '#configure/account'");
    await page.waitFor("document.querySelector('#account-sign-in dl')");
    await page.settle();
    assert.equal(requests('GET', '/api/session').length, reads + 1);
    assert.equal(await page.eval('window.__bannerChanges'), 0, 'not drawn again');
    await page.eval('window.__perfSkew += 300001');
    await page.poll();
    await page.settle();
    assert.equal(requests('GET', '/api/session').length, reads + 2);
    assert.equal(await page.eval('window.__bannerChanges'), 0, 'not drawn again');
    assert.equal(await page.eval(`${banner}.querySelectorAll('p').length`), 2);
    // Uptime Goblin is served over HTTPS now: one banner goes, the other stays.
    insecure = false;
    await page.eval('window.__perfSkew += 300001');
    await page.poll();
    await page.waitFor(`${banner}.querySelectorAll('p').length === 1`);
    assert.match(await text(page, '#session-banner'), /^Uptime Goblin saved the admin password/);
    assert.deepEqual(page.exceptions, []);
  }
);

test('Sign out ends the session and starts again at the sign-in view', { skip }, async () => {
  const page = await open('#configure/appearance');
  await page.waitFor("document.querySelector('#workspace-title')");
  await setValue(page, '#workspace-title', 'An unsaved title');
  await page.eval("document.querySelector('#user-chip').click()");
  await page.eval('window.__confirmAnswer = false');
  await page.eval("document.querySelector('#sign-out').click()");
  assert.equal(await page.eval('window.__confirmCalls'), 1, 'unsaved changes ask first');
  assert.equal(requests('POST', '/api/auth/logout').length, 0);
  await page.eval('window.__confirmAnswer = true');
  await page.eval("document.querySelector('#sign-out').click()");
  // No "leave page?" prompt holds the page: it starts again.
  const end = Date.now() + 5000;
  while (pageLoads() < 2 && Date.now() < end) await delay(20);
  assert.equal(pageLoads(), 2);
  const [logout] = requests('POST', '/api/auth/logout');
  assert.equal(logout.headers['content-type'], 'application/json');
  assert.equal(logout.headers['x-goblin-request'], '1');
  await page.waitFor(signInView);
  // The address lost its hash, and nothing of the signed-in page is left.
  assert.equal(await page.eval('location.hash'), '');
  assert.equal(await page.eval("document.querySelector('#services').children.length"), 0);
  assert.equal(await page.eval("document.body.textContent.includes('Linux host')"), false);
});

// What the user menu says when Uptime Goblin did not confirm a sign-out (identity/session.js).
const signOutTexts = {
  unanswered:
    'Uptime Goblin did not confirm the sign-out, so this browser may still be signed in. Try again.',
  failed: message => `Uptime Goblin could not record the sign-out (${message}). Try again.`,
  twoCookies:
    'Uptime Goblin could not sign this browser out: it sent two Uptime Goblin sign-in cookies, and another site set one of them. Remove this site’s cookies in the browser to sign out.',
};
test(
  'a sign-out Uptime Goblin does not confirm keeps the page and says so; one it confirms starts again',
  { skip },
  async () => {
    // Without an answer the cookie and the session may both still be valid: a new page would
    // sign itself back in without a word (§16 C5). An error from Uptime Goblin means it did not record
    // the sign-out. Only a 204 (or a 401: the session had already ended) starts the page again.
    const page = await open();
    await page.eval("document.querySelector('#user-chip').click()");
    const alert = "document.querySelector('#sign-out-error')";
    for (const [reply, expected] of [
      [{ drop: true }, signOutTexts.unanswered],
      [identity.refused(503, 'storage_full', 30), identityMessages.storage_full],
      [
        { status: 500, body: { error: 'Uptime Goblin could not complete this request' } },
        signOutTexts.failed('Uptime Goblin could not complete this request'),
      ],
    ]) {
      mock.routes.set('POST /api/auth/logout', () => reply);
      await page.eval("document.querySelector('#sign-out').click()");
      await page.waitFor(`${alert}.hidden === false`);
      assert.equal(await text(page, '#sign-out-error'), expected);
      assert.equal(await page.eval(`${alert}.getAttribute('role')`), 'alert');
      assert.equal(await page.eval("document.querySelector('#sign-out').disabled"), false);
      assert.equal(await text(page, '#sign-out'), 'Sign out');
      await delay(300);
      assert.equal(pageLoads(), 1, 'the page did not start again');
    }
    // While the request is on its way the button says so.
    let answer;
    mock.routes.set('POST /api/auth/logout', () => new Promise(resolve => (answer = resolve)));
    await page.eval("document.querySelector('#sign-out').click()");
    await page.waitFor("document.querySelector('#sign-out').textContent === 'Signing out…'");
    assert.equal(await page.eval("document.querySelector('#sign-out').disabled"), true);
    assert.equal(await page.eval(`${alert}.hidden`), true);
    mock.signedIn = false;
    mock.signedOutAs = 'signin_required';
    answer({ status: 204 });
    const end = Date.now() + 5000;
    while (pageLoads() < 2 && Date.now() < end) await delay(20);
    assert.equal(pageLoads(), 2);
    await page.waitFor(signInView);
    // A 401 (the session had already ended) is a sign-out too.
    mock.signedIn = true;
    mock.routes.set('POST /api/auth/logout', () => identity.unauthorized('session_expired'));
    const again = await open();
    await again.eval("document.querySelector('#user-chip').click()");
    await again.eval("document.querySelector('#sign-out').click()");
    const until = Date.now() + 5000;
    while (pageLoads() < 4 && Date.now() < until) await delay(20);
    assert.equal(pageLoads(), 4);
  }
);

test(
  'a sign-out with another site’s cookie of Uptime Goblin’s name: refused, the page stays; ended, the sign-in view says to remove the cookies',
  { skip },
  async () => {
    // §19 G1. A 401 multiple_credentials ended nothing: the browser keeps its session, so the
    // page must not start again as if it had signed out (it did before, as for any 401).
    const page = await open();
    await page.eval("document.querySelector('#user-chip').click()");
    const alert = "document.querySelector('#sign-out-error')";
    mock.routes.set('POST /api/auth/logout', () => identity.unauthorized('multiple_credentials'));
    await page.eval("document.querySelector('#sign-out').click()");
    await page.waitFor(`${alert}.hidden === false`);
    assert.equal(await text(page, '#sign-out-error'), signOutTexts.twoCookies);
    assert.equal(await page.eval("document.querySelector('#sign-out').disabled"), false);
    await delay(300);
    assert.equal(pageLoads(), 1, 'the page did not start again');
    // Uptime Goblin ended every session the browser sent and expired its own cookie; the other site's
    // stays, and alone it is no session (session_expired). The page starts again, and its
    // sign-in view says why signing in would fail, once.
    mock.routes.set('POST /api/auth/logout', () => {
      mock.signedIn = false;
      mock.signedOutAs = 'session_expired';
      return {
        body: {
          signedOut: true,
          code: 'multiple_credentials',
          message: 'Signed out. This browser also sent an Uptime Goblin sign-in cookie …',
        },
      };
    });
    await page.eval("document.querySelector('#sign-out').click()");
    const end = Date.now() + 5000;
    while (pageLoads() < 2 && Date.now() < end) await delay(20);
    assert.equal(pageLoads(), 2);
    await page.waitFor(signInView);
    await page.settle();
    assert.equal(await text(page, '#signin-notice'), signInTexts.signed_out_other_cookie);
    assert.equal(await page.eval("document.querySelector('#signin-notice').hidden"), false);
    await page.eval('location.reload()');
    const until = Date.now() + 5000;
    while (pageLoads() < 3 && Date.now() < until) await delay(20);
    await page.waitFor(signInView);
    await page.settle();
    assert.equal(await text(page, '#signin-notice'), signInTexts.session_expired);
    assert.deepEqual(page.exceptions, []);
  }
);

/** The sessions Uptime Goblin lists on the Account page, current first. */
function accountSessions() {
  const now = Date.now();
  return [
    {
      id: sessionId,
      current: true,
      createdAt: now - 3600000,
      lastSeenAt: now,
      expiresAt: now + 6 * 86400000,
      idleExpiresAt: now + 12 * 3600000,
      persistent: false,
      client: '127.0.0.1',
      userAgent:
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36',
    },
    {
      id: 's_PhonePhonePhone',
      current: false,
      createdAt: now - 86400000,
      lastSeenAt: now - 7200000,
      expiresAt: now + 29 * 86400000,
      idleExpiresAt: now + 3600000,
      persistent: true,
      client: '192.168.1.20',
      userAgent:
        'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1',
    },
    {
      id: 's_ScriptScriptScr',
      current: false,
      createdAt: now - 2 * 86400000,
      lastSeenAt: now - 86400000,
      expiresAt: now + 5 * 86400000,
      idleExpiresAt: now + 3600000,
      persistent: false,
      client: null,
      userAgent: null,
    },
  ];
}
function serveSessions() {
  let sessions = accountSessions();
  mock.routes.set('GET /api/account/sessions', () => ({ body: { sessions } }));
  mock.routes.set('DELETE /api/account/sessions', () => {
    const revoked = sessions.filter(s => !s.current).length;
    sessions = sessions.filter(s => s.current);
    return { body: { revoked } };
  });
  return {
    revokeOne: request => {
      const id = decodeURIComponent(request.path.split('/').pop());
      if (!sessions.some(s => s.id === id))
        return { status: 404, body: { error: 'Session not found', code: 'not_found' } };
      sessions = sessions.filter(s => s.id !== id);
      return { status: 204 };
    },
  };
}

test('the Account page lists your sessions and signs other devices out', { skip }, async () => {
  const served = serveSessions();
  for (const id of ['s_PhonePhonePhone', 's_ScriptScriptScr'])
    mock.routes.set(`DELETE /api/account/sessions/${id}`, served.revokeOne);
  const page = await open('#configure/account');
  await page.waitFor("document.querySelector('#sessions-list tbody [data-session]')");
  assert.match(await text(page, '#account-details'), /Your sign-in/);
  assert.match(await text(page, '#account-details'), /admin/);
  assert.match(await text(page, '#account-details'), /Signed in/);
  assert.match(await text(page, '#account-details'), /Ends/);
  assert.equal(await text(page, '#sessions-list caption'), 'Sessions');
  assert.deepEqual(
    await page.eval(
      "[...document.querySelectorAll('#sessions-list thead th')].map(th => th.textContent)"
    ),
    ['Device', 'Address', 'Signed in', 'Last active', 'Ends', 'Action']
  );
  const rows = () =>
    page.eval(`[...document.querySelectorAll('#sessions-list tbody tr')].map(tr => ({
      id: tr.dataset.session,
      device: tr.cells[0].textContent,
      address: tr.cells[1].textContent,
      action: tr.cells[5].textContent,
      button: !!tr.querySelector('button'),
    }))`);
  assert.deepEqual(await rows(), [
    {
      id: sessionId,
      device: 'Chrome on macOS',
      address: '127.0.0.1',
      action: 'This device',
      button: false,
    },
    {
      id: 's_PhonePhonePhone',
      device: 'Safari on iOSKept signed in',
      address: '192.168.1.20',
      action: 'Sign out',
      button: true,
    },
    {
      id: 's_ScriptScriptScr',
      device: 'Unknown device',
      address: 'Unknown',
      action: 'Sign out',
      button: true,
    },
  ]);
  assert.match(
    await page.eval(
      "document.querySelector('[data-revoke-session=s_PhonePhonePhone]').getAttribute('aria-label')"
    ),
    /^Sign out Safari on iOS, last active /
  );
  assert.equal(await page.eval("document.querySelector('#sign-out-others').disabled"), false);

  await page.eval("document.querySelector('[data-revoke-session=s_PhonePhonePhone]').click()");
  await page.waitFor("!document.querySelector('[data-session=s_PhonePhonePhone]')");
  assert.equal(requests('DELETE', '/api/account/sessions/s_PhonePhonePhone').length, 1);
  assert.equal(await text(page, '#sessions-result'), 'That device is signed out.');
  assert.equal(await page.eval('document.activeElement.id'), 'sessions-title');

  await page.eval("document.querySelector('#sign-out-others').click()");
  await page.waitFor(
    "document.querySelectorAll('#sessions-list tbody [data-session]').length === 1"
  );
  assert.equal(
    requests('DELETE', '/api/account/sessions').filter(r => r.path === '/api/account/sessions')
      .length,
    1
  );
  assert.equal(await text(page, '#sessions-result'), 'Signed out 1 other device.');
  assert.equal(await page.eval("document.querySelector('#sign-out-others').disabled"), true);
  // Removing a session that already ended says so.
  mock.routes.set('DELETE /api/account/sessions/s_Gone', served.revokeOne);
  await page.eval(`(() => {
    const button = document.createElement('button');
    button.dataset.revokeSession = 's_Gone';
    document.querySelector('#account-sessions').append(button);
    button.click();
  })()`);
  await page.waitFor("document.querySelector('#sessions-error').hidden === false");
  assert.equal(await text(page, '#sessions-error'), 'That session had already ended.');
  assert.deepEqual(await cspViolations(page), []);
  assert.deepEqual(page.exceptions, []);
});

test(
  'the Account page says when Uptime Goblin did not answer a sign-out or a read, not the browser’s words',
  { skip },
  async () => {
    // Without an answer (a restart, a dropped network) api() throws the browser's own error,
    // and the page showed "Failed to fetch": the owner could not tell whether a lost device
    // was signed out, nor read the list again with any hint of why (§19 G6).
    const unanswered = {
      revoke:
        'Uptime Goblin did not confirm the sign-out, so that device may still be signed in. If it is still listed, sign it out again.',
      revokeOthers:
        'Uptime Goblin did not confirm the sign-out, so your other devices may still be signed in. If any are still listed, sign them out again.',
      read: 'Uptime Goblin is not answering. Try again in a moment.',
    };
    serveSessions();
    const list = mock.routes.get('GET /api/account/sessions');
    const page = await open('#configure/account');
    const rows = "document.querySelectorAll('#sessions-list tbody [data-session]').length";
    await page.waitFor(`${rows} === 3`);
    // Uptime Goblin stops while the owner signs out a lost device: the list read after it fails too.
    mock.routes.set('DELETE /api/account/sessions/s_PhonePhonePhone', () => ({ drop: true }));
    mock.routes.set('GET /api/account/sessions', () => ({ drop: true }));
    await page.eval("document.querySelector('[data-revoke-session=s_PhonePhonePhone]').click()");
    await page.waitFor("document.querySelector('#sessions-list [data-retry-account]')");
    await page.settle();
    assert.equal(await page.eval("document.querySelector('#sessions-error').hidden"), false);
    assert.equal(await text(page, '#sessions-error'), unanswered.revoke);
    assert.equal(
      await text(page, '#sessions-list tbody .field-error'),
      unanswered.read,
      'the list says Uptime Goblin is not answering'
    );
    // Back: the list shows the device still signed in.
    mock.routes.set('GET /api/account/sessions', list);
    await page.eval("document.querySelector('#sessions-list [data-retry-account]').click()");
    await page.waitFor(`${rows} === 3`);
    mock.routes.set('DELETE /api/account/sessions', () => ({ drop: true }));
    await page.eval("document.querySelector('#sign-out-others').click()");
    await page.waitFor("document.querySelector('#sessions-error').hidden === false");
    await page.settle();
    assert.equal(await text(page, '#sessions-error'), unanswered.revokeOthers);
    // The page's own reads, opened while Uptime Goblin does not answer.
    mock.routes.set('GET /api/session', () => ({ drop: true }));
    mock.routes.set('GET /api/account/sessions', () => ({ drop: true }));
    await page.eval("location.hash = '#configure/overview'");
    await page.waitFor("document.querySelector('.configuration-welcome')");
    await page.eval("location.hash = '#configure/account'");
    await page.waitFor("document.querySelector('#account-sign-in [data-retry-account]')");
    await page.waitFor("document.querySelector('#sessions-list [data-retry-account]')");
    await page.settle();
    assert.equal(await text(page, '#account-sign-in .field-error'), unanswered.read);
    assert.equal(await text(page, '#sessions-list tbody .field-error'), unanswered.read);
    // A refusal Uptime Goblin explains keeps its own words.
    mock.routes.set('GET /api/account/sessions', () => ({
      status: 503,
      body: {
        error: 'Uptime Goblin cannot read its control database.',
        code: 'storage_unavailable',
      },
    }));
    await page.eval("document.querySelector('#sessions-list [data-retry-account]').click()");
    await page.waitFor(
      "document.querySelector('#sessions-list tbody .field-error')?.textContent === 'Uptime Goblin cannot read its control database.'"
    );
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'the Account page offers no Sign out for a device that signed in later, and says why',
  { skip },
  async () => {
    // Uptime Goblin refuses a sign-out of a session that signed in after this one (session_newer): a
    // cookie from a lost device must not end the sign-ins that prove the password.
    let sessions = accountSessions().map(s =>
      s.id === 's_PhonePhonePhone' ? { ...s, newer: true } : { ...s, newer: false }
    );
    mock.routes.set('GET /api/account/sessions', () => ({ body: { sessions } }));
    mock.routes.set('DELETE /api/account/sessions', () => {
      const revoked = sessions.filter(s => !s.current && !s.newer).length;
      sessions = sessions.filter(s => s.current || s.newer);
      return { body: { revoked, kept: 1 } };
    });
    const newerText =
      'That session signed in after this one, so only a newer sign-in can end it. If you do not recognise it, change your password, which signs out every other session; otherwise sign out here and sign in again first.';
    mock.routes.set('DELETE /api/account/sessions/s_PhonePhonePhone', () => ({
      status: 403,
      body: { error: newerText, code: 'session_newer' },
    }));
    const page = await open('#configure/account');
    await page.waitFor("document.querySelector('#sessions-list tbody [data-session]')");
    const actions = () =>
      page.eval(`[...document.querySelectorAll('#sessions-list tbody tr')].map(tr => [
        tr.dataset.session, tr.cells[5].textContent, !!tr.querySelector('button')])`);
    assert.deepEqual(await actions(), [
      [sessionId, 'This device', false],
      ['s_PhonePhonePhone', 'Signed in later', false],
      ['s_ScriptScriptScr', 'Sign out', true],
    ]);
    assert.equal(await page.eval("document.querySelector('#sessions-newer').hidden"), false);
    assert.equal(
      await text(page, '#sessions-newer'),
      '“Signed in later”: that device signed in after this one, so only a newer sign-in can sign it out. If you do not recognise it, change your password, which signs out every other device. Otherwise sign out here and sign in again, then sign it out.'
    );
    assert.equal(await page.eval("document.querySelector('#sign-out-others').disabled"), false);

    await page.eval("document.querySelector('#sign-out-others').click()");
    await page.waitFor("!document.querySelector('[data-session=s_ScriptScriptScr]')");
    assert.equal(
      await text(page, '#sessions-result'),
      'Signed out 1 other device. 1 device that signed in later is still signed in.'
    );
    // Only a later device is left: nothing here can sign it out.
    assert.equal(await page.eval("document.querySelector('#sign-out-others').disabled"), true);
    assert.equal(await page.eval("document.querySelector('#sessions-newer').hidden"), false);

    // A Sign out that Uptime Goblin refuses all the same (a list read in another way): its text is
    // shown, and the list read again marks the row.
    await page.eval(`(() => {
      const button = document.createElement('button');
      button.dataset.revokeSession = 's_PhonePhonePhone';
      document.querySelector('#account-sessions').append(button);
      button.click();
    })()`);
    await page.waitFor("document.querySelector('#sessions-error').hidden === false");
    assert.equal(await text(page, '#sessions-error'), newerText);
    assert.equal(requests('DELETE', '/api/account/sessions/s_PhonePhonePhone').length, 1);
    await page.waitFor(
      "document.querySelector('[data-session=s_PhonePhonePhone]')?.cells[5].textContent === 'Signed in later'"
    );
    assert.deepEqual(await cspViolations(page), []);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'the Account page changes the password and keeps this device signed in',
  { skip },
  async () => {
    serveSessions();
    let answer = { ok: true, revokedOtherSessions: 2, mirrorPending: false, reauthenticate: false };
    mock.routes.set('POST /api/account/password', request =>
      JSON.parse(request.body).currentPassword === mock.password
        ? { body: answer }
        : identity.forbidden('current_password_incorrect')
    );
    const page = await open('#configure/account');
    await page.waitFor("document.querySelector('#password-form')");
    const fill = async current => {
      await setValue(page, '#current-password', current);
      await setValue(page, '#new-password', 'a new long passphrase');
      await setValue(page, '#confirm-new-password', 'a new long passphrase');
    };
    assert.equal(await text(page, '#dirty-status'), 'Your sign-in is unchanged');
    await fill('not the current one');
    assert.equal(await text(page, '#dirty-status'), 'New password not saved');
    await page.eval("document.querySelector('#password-form [type=submit]').click()");
    await page.waitFor("document.querySelector('#password-error').hidden === false");
    assert.equal(await text(page, '#password-error'), identityMessages.current_password_incorrect);
    // Checked here first: too short, then not matching.
    await setValue(page, '#new-password', 'short');
    await page.eval("document.querySelector('#password-form [type=submit]').click()");
    assert.equal(
      await text(page, '#password-error'),
      'Use at least 12 characters for your new password.'
    );
    assert.equal(requests('POST', '/api/account/password').length, 1);

    await fill(mock.password);
    await page.eval("document.querySelector('#password-form [type=submit]').click()");
    await page.waitFor("document.querySelector('#password-result').hidden === false");
    assert.equal(
      await text(page, '#password-result'),
      'Password changed. Other devices were signed out.'
    );
    assert.equal(
      await page.eval("document.querySelector('#password-result').getAttribute('role')"),
      'status'
    );
    const [, change] = requests('POST', '/api/account/password');
    assert.deepEqual(JSON.parse(change.body), {
      currentPassword: mock.password,
      password: 'a new long passphrase',
      confirmPassword: 'a new long passphrase',
    });
    for (const id of ['current-password', 'new-password', 'confirm-new-password'])
      assert.equal(await page.eval(`document.querySelector('#${id}').value`), '', id);
    assert.equal(await text(page, '#dirty-status'), 'Your sign-in is unchanged');
    // The session and its list are read again (the answer rotated this browser's session).
    await page.settle();
    assert.ok(requests('GET', '/api/session').length >= 3);
    assert.equal(await page.eval("document.querySelector('#signin-dialog').open"), false);

    // auth.json could not be updated: the result says so too, and the banner shows.
    answer = { ...answer, mirrorPending: true };
    mock.sessionBody = () => identity.session('session', { mirrorPending: true });
    await fill(mock.password);
    await page.eval("document.querySelector('#password-form [type=submit]').click()");
    await page.waitFor("document.querySelector('#session-banner').hidden === false");
    assert.match(await text(page, '#password-result'), /could not update auth\.json/);
    assert.deepEqual(await cspViolations(page), []);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'a new release found while the sign-in view has text in it is offered, not reloaded',
  { skip },
  async () => {
    const page = await openSignedOut();
    // Signed in, but the check that follows is answered by a newer Uptime Goblin (it was updated in
    // between), which does not know the session: the view stays, with what was typed.
    mock.routes.set('POST /api/auth/login', () => ({ body: mock.sessionBody() }));
    mock.routes.set('GET /api/session', () => ({
      ...identity.unauthorized('signin_required'),
      build: 'fedcba987654',
    }));
    await submitSignIn(page, 'signin', 'the right password, then an update');
    await page.waitFor(bannerShown);
    await delay(1500);
    assert.equal(pageLoads(), 1, 'the login name is still typed in');
    assert.equal(await page.eval("document.querySelector('#signin-login').value"), 'admin');
    await pages.pop().close();
    mock.routes.delete('POST /api/auth/login');
    // With nothing typed, the view reloads into the new release by itself.
    resetWeb();
    let first = true;
    mock.routes.set('GET /api/session', () => {
      const reply = {
        ...identity.unauthorized('signin_required'),
        build: first ? 'fedcba987654' : web.build,
      };
      first = false;
      return reply;
    });
    await openSignedOut();
    const end = Date.now() + 8000;
    while (pageLoads() < 2 && Date.now() < end) await delay(20);
    assert.equal(pageLoads(), 2);
  }
);

// Round 4 of the 1.5 review (sessions spec §17): what the page does around a cancelled sign-in,
// a sign-out without an answer, and phone widths.

/** Routes already set answer only while signed in; signed out, Uptime Goblin's 401 (defaultRoute). */
function onlySignedIn() {
  for (const [key, route] of mock.routes)
    mock.routes.set(key, request => (mock.signedIn ? route(request) : null));
}
/** Closes the newest tab, as beforeEach does, so it neither polls nor probes into the next. */
async function closeNewest() {
  const page = pages.pop();
  await page.eval('window.__hidden = true').catch(() => {});
  await page.close();
}
const signedOutNotice = 'Signed out. Sign in to see current readings.';

test(
  'one Cancel closes the sign-in dialog for actions that read again after a failure, and the focus returns to them',
  { skip },
  async () => {
    // Sign out on a session's row, Sign out other devices, Send test email and Save email
    // settings each sent another request after a failure. After Cancel that one was refused as
    // well and asked again while the dialog was closing, which kept it open: it took a second
    // Cancel, and the first one seemed to do nothing (§17 E4).
    const served = serveSessions();
    mock.routes.set('DELETE /api/account/sessions/s_PhonePhonePhone', served.revokeOne);
    onlySignedIn();
    for (const [hash, action, how] of [
      ['#configure/account', '[data-revoke-session=s_PhonePhonePhone]', 'Escape'],
      ['#configure/account', '#sign-out-others', 'Cancel'],
      ['#configure/email', '#test-email', 'Escape'],
      ['#configure/email', '#email-form [type=submit]', 'Cancel'],
    ]) {
      mock.signedIn = true;
      const page = await open(hash);
      await page.waitFor(`document.querySelector(${js(action)})?.disabled === false`);
      await page.settle();
      await watchSignInDialog(page);
      const followUp =
          hash === '#configure/account'
            ? ['GET', '/api/account/sessions']
            : ['GET', '/api/dashboard'],
        before = requests(...followUp).length;
      // The session ends elsewhere; the action is taken from the keyboard.
      mock.signedIn = false;
      await page.eval(`document.querySelector(${js(action)}).focus()`);
      await page.press('Enter');
      await page.waitFor(isOpen('signin-dialog'));
      await settled(page, 'signin-dialog');
      if (how === 'Escape') await page.press('Escape');
      else await page.click('#reauth-cancel');
      await page.waitFor(`!${isOpen('signin-dialog')}`, 2000).catch(() => {});
      await page.settle();
      await delay(300);
      assert.equal(await page.eval(isOpen('signin-dialog')), false, `${action}: one ${how}`);
      assert.equal(await page.eval('window.__signInShown'), 1, `${action}: asked once`);
      // The read that followed the failure (the list, or the dashboard for the email form).
      assert.equal(requests(...followUp).length, before, `${action}: nothing read after ${how}`);
      assert.equal(
        await page.eval("document.querySelector('#configuration-notice').hidden"),
        false
      );
      assert.ok((await text(page, '#configuration-notice')).startsWith(signedOutNotice), action);
      assert.equal(await text(page, '#connection'), 'Signed out');
      assert.equal(
        await page.eval(`document.activeElement === document.querySelector(${js(action)})`),
        true,
        `${action}: the focus is back on it`
      );
      if (hash === '#configure/account') {
        // The refusal stays beside the list until signing in again shows it as it is now.
        assert.equal(await text(page, '#sessions-error'), identityMessages.session_expired);
        await page.eval("document.querySelector('#configuration-sign-in').click()");
        await page.waitFor(isOpen('signin-dialog'));
        await settled(page, 'signin-dialog');
        await submitSignIn(page, 'reauth');
        await page.waitFor(`!${isOpen('signin-dialog')}`);
        await page.waitFor("document.querySelector('#sessions-error').hidden");
      }
      assert.deepEqual(await cspViolations(page), []);
      assert.deepEqual(page.exceptions, []);
      await closeNewest();
    }
  }
);

test(
  'signing in again for a session’s Sign out ends with the focus on the list, not the page heading',
  { skip },
  async () => {
    // The dialog closes while the retried request is still out, its button still disabled: the
    // focus waits for the answer (page.busyFocus), which removes the row and focuses the list.
    const served = serveSessions();
    mock.routes.set('DELETE /api/account/sessions/s_PhonePhonePhone', request => ({
      ...served.revokeOne(request),
      delay: 600,
    }));
    onlySignedIn();
    const page = await open('#configure/account');
    const action = '[data-revoke-session=s_PhonePhonePhone]';
    await page.waitFor(`document.querySelector(${js(action)})`);
    mock.signedIn = false;
    await page.eval(`document.querySelector(${js(action)}).focus()`);
    await page.press('Enter');
    await page.waitFor(isOpen('signin-dialog'));
    await settled(page, 'signin-dialog');
    await submitSignIn(page, 'reauth');
    await page.waitFor(`!${isOpen('signin-dialog')}`);
    await page.waitFor("!document.querySelector('[data-session=s_PhonePhonePhone]')");
    await page.settle();
    assert.equal(await text(page, '#sessions-result'), 'That device is signed out.');
    assert.equal(await page.eval('document.activeElement.id'), 'sessions-title');
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'the exports and Test connection give the keyboard focus back, after the sign-in dialog too',
  { skip },
  async () => {
    // Each disables itself while its request is out, which drops the focus to <body>. They did
    // not hold it (page.busyFocus), so the dialog gave it back to <body>, and so did the button
    // without any dialog: a keyboard user started again at the top of the page (§19 G5). A
    // source's Show/Hide on the Sources page did the same (§20 H6).
    mock.routes.set('GET /api/config/export', () => ({ body: { services: [] } }));
    mock.routes.set('POST /api/test-service', () => ({
      delay: 300,
      body: {
        metrics: [{ key: 'cpu', label: 'CPU', value: 5, unit: '%' }],
        notes: [],
        elapsedMs: 100,
      },
    }));
    onlySignedIn();
    for (const [hash, action] of [
      ['#configure/data', '#export-config'],
      ['#configure/data', '#export-history'],
      ['', '[data-export-history=linux]'],
      ['', '#test-connection'],
      // Patched in place by the load after its write: the same button, saying the opposite.
      ['#configure/sources', '[data-visibility=linux]'],
    ])
      for (const how of ['no dialog', 'Escape', 'Cancel', 'sign in']) {
        mock.signedIn = true;
        const page = await open(hash);
        if (action.startsWith('[data-export-history')) await expand(page);
        if (action === '#test-connection') await openDrawer(page);
        const button = `document.querySelector(${js(action)})`;
        await page.waitFor(`${button}?.disabled === false`);
        await page.eval(`${button}.focus()`);
        // The session ends elsewhere; the button is used from the keyboard.
        if (how !== 'no dialog') mock.signedIn = false;
        await page.press('Enter');
        if (how !== 'no dialog') {
          await page.waitFor(isOpen('signin-dialog'));
          await settled(page, 'signin-dialog');
          if (how === 'Escape') await page.press('Escape');
          else if (how === 'Cancel') await page.click('#reauth-cancel');
          else await submitSignIn(page, 'reauth');
          await page.waitFor(`!${isOpen('signin-dialog')}`);
        }
        await page.waitFor(`${button}.disabled === false`);
        await page.settle();
        await delay(300);
        assert.equal(
          await page.eval(`document.activeElement === ${button}`),
          true,
          `${action}, ${how}: the focus is back on it`
        );
        assert.deepEqual(page.exceptions, []);
        await closeNewest();
      }
  }
);

const systemBody = () => ({
  version: '1.5.0',
  build: web.build,
  clients: [],
  uptimeSeconds: 10,
  startedAt: Date.now(),
  authenticationRequired: true,
  authentication: {},
  data: {
    databaseBytes: 0,
    writeFailure: null,
    configBytes: 0,
    samples: 0,
    events: 0,
    activeAlerts: 0,
  },
  collection: { inflight: 0, pending: 0, concurrency: 4, timeoutSeconds: 90, lastCollected: null },
  limits: { sources: 200, mappingsPerSource: 100, rulesPerSource: 30 },
  notifications: {},
});
const sessionEnded = identityMessages.session_expired;

test(
  'signing in again after Cancel shows the Account and System pages and the Help guide as they are now',
  { skip },
  async () => {
    // Their own requests got the refusal after Cancel. load() does not read them again, so the
    // pages went on saying "Your session has ended. Sign in again." while signed in, with an
    // empty sessions list and Sign out other devices disabled (§17 E5).
    serveSessions();
    mock.routes.set('GET /api/system', () => ({ body: systemBody() }));
    onlySignedIn();
    const page = await open('#configure/overview');
    const cancelOn = async hash => {
      mock.signedIn = false;
      await page.eval(`location.hash = ${js(hash)}`);
      await page.waitFor(isOpen('signin-dialog'));
      await settled(page, 'signin-dialog');
      await page.click('#reauth-cancel');
      await page.waitFor(`!${isOpen('signin-dialog')}`);
      await page.waitFor("document.querySelector('#configuration-notice').hidden === false");
      await page.settle();
    };
    const content = () => text(page, '#configuration-content');
    const signInFromNotice = async () => {
      await page.eval("document.querySelector('#configuration-sign-in').click()");
      await page.waitFor(isOpen('signin-dialog'));
      await settled(page, 'signin-dialog');
      await submitSignIn(page, 'reauth');
      await page.waitFor(
        `!${isOpen('signin-dialog')} && document.querySelector('#configuration-notice').hidden`
      );
      await page.settle();
    };

    await cancelOn('#configure/account');
    assert.ok((await content()).includes(sessionEnded));
    // Two refusals, two Try again buttons: neither by an id that the other also has.
    assert.equal(await page.eval("document.querySelectorAll('[data-retry-account]').length"), 2);
    assert.equal(
      await page.eval(
        "(ids => ids.length === new Set(ids).size)([...document.querySelectorAll('[id]')].map(e => e.id))"
      ),
      true,
      'ids are unique'
    );
    await signInFromNotice();
    await page.waitFor(
      "document.querySelectorAll('#sessions-list tbody [data-session]').length === 3"
    );
    assert.equal((await content()).includes(sessionEnded), false);
    assert.match(await text(page, '#account-sign-in'), /Login name/);
    assert.equal(await page.eval("document.querySelector('#sign-out-others').disabled"), false);
    assert.equal(await page.eval("document.querySelector('#sessions-error').hidden"), true);

    await cancelOn('#configure/system');
    assert.ok((await text(page, '#system-details')).includes(sessionEnded));
    // Another tab signs in; this one finds out when it is looked at again.
    mock.signedIn = true;
    await page.eval("window.dispatchEvent(new Event('focus'))");
    await page.waitFor("document.querySelector('#configuration-notice').hidden");
    await page.waitFor("document.querySelector('#system-details .system-facts')");
    assert.equal((await content()).includes(sessionEnded), false);
    assert.match(await text(page, '#system-details'), /Uptime Goblin is online/);

    await cancelOn('#configure/help');
    assert.ok((await text(page, '#documentation')).includes(sessionEnded));
    await signInFromNotice();
    await page.waitFor("document.querySelector('#documentation .documentation-body')");
    assert.equal((await content()).includes(sessionEnded), false);
    assert.deepEqual(await cspViolations(page), []);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'after a sign-in through the dialog the Account page lists the new session as this device',
  { skip },
  async () => {
    // A poll found the session gone and the user signed in again: the page showed the session
    // that had ended as this device's until something else read the list again (§17 E5).
    let sessions = accountSessions();
    mock.routes.set('GET /api/account/sessions', () => ({ body: { sessions } }));
    onlySignedIn();
    const page = await open('#configure/account');
    await page.waitFor("document.querySelectorAll('#sessions-list tbody [data-session]').length");
    mock.signedIn = false;
    await page.eval('window.__poll()');
    await page.waitFor(isOpen('signin-dialog'));
    await settled(page, 'signin-dialog');
    sessions = [{ ...sessions[0], id: 's_NewNewNewNewNewN' }, ...sessions.slice(1)];
    await submitSignIn(page, 'reauth');
    await page.waitFor(`!${isOpen('signin-dialog')}`);
    await page.waitFor(
      "document.querySelector('#sessions-list tbody tr.current-session')?.dataset.session === 's_NewNewNewNewNewN'"
    );
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'a sign-out failure that arrives after the menu closed is said at once and kept until the menu shows it',
  { skip },
  async () => {
    // The request can take a minute. Written into the closed menu, its alert was neither shown
    // nor announced, and reopening the menu hid it unseen: the user could leave believing this
    // browser was signed out (§17 E6).
    const page = await open();
    // Held until the menu has closed. Chrome sends a request again once when its connection
    // closes without an answer: that one is dropped at once.
    let answer;
    mock.routes.set('POST /api/auth/logout', () =>
      answer ? { drop: true } : new Promise(resolve => (answer = resolve))
    );
    await page.click('#user-chip');
    await page.click('#sign-out');
    await page.waitFor("document.querySelector('#sign-out').textContent === 'Signing out…'");
    await page.click('#dashboard-title');
    assert.equal(await page.eval("document.querySelector('#user-menu').hidden"), true);
    answer({ drop: true });
    await page.waitFor("document.querySelector('#toast').hidden === false");
    assert.equal(await text(page, '#toast'), signOutTexts.unanswered);
    assert.equal(
      await page.eval("document.querySelector('#toast').getAttribute('role')"),
      'status'
    );
    // Opening the menu shows it, once.
    await page.click('#user-chip');
    assert.equal(await page.eval("document.querySelector('#sign-out-error').hidden"), false);
    assert.equal(await text(page, '#sign-out-error'), signOutTexts.unanswered);
    await page.click('#user-chip');
    await page.click('#user-chip');
    assert.equal(await page.eval("document.querySelector('#sign-out-error').hidden"), true);
    // One that arrives with the menu open shows there and needs no toast.
    await page.eval("document.querySelector('#toast').hidden = true");
    mock.routes.set('POST /api/auth/logout', () => ({ drop: true }));
    await page.click('#sign-out');
    await page.waitFor("document.querySelector('#sign-out-error').hidden === false");
    await delay(100);
    assert.equal(await page.eval("document.querySelector('#toast').hidden"), true);
    assert.equal(pageLoads(), 1, 'the page did not start again');
    assert.deepEqual(page.exceptions, []);
  }
);

test('a failed sign-out gives the keyboard focus back to Sign out', { skip }, async () => {
  // Disabling the button while the request is out drops its focus to <body>; a keyboard user's
  // next Tab would start again from the top of the page (§17 E6).
  const page = await open();
  let answer;
  mock.routes.set('POST /api/auth/logout', () => new Promise(resolve => (answer = resolve)));
  await page.eval("document.querySelector('#user-chip').focus()");
  await page.press('Enter');
  await page.eval("document.querySelector('#sign-out').focus()");
  await page.press('Enter');
  await page.waitFor("document.querySelector('#sign-out').disabled");
  answer({ status: 500, body: { error: 'Uptime Goblin could not complete that request.' } });
  await page.waitFor("document.querySelector('#sign-out-error').hidden === false");
  assert.equal(
    await text(page, '#sign-out-error'),
    signOutTexts.failed('Uptime Goblin could not complete that request.')
  );
  assert.equal(await page.eval('document.activeElement.id'), 'sign-out');
  assert.deepEqual(page.exceptions, []);
});

/** A trusted mouse drag from `from` to `to` (viewport points), as when selecting text. */
async function drag(page, from, to) {
  await page.send('Input.dispatchMouseEvent', {
    type: 'mousePressed',
    ...from,
    button: 'left',
    clickCount: 1,
  });
  for (let i = 1; i <= 5; i++)
    await page.send('Input.dispatchMouseEvent', {
      type: 'mouseMoved',
      x: from.x + ((to.x - from.x) * i) / 5,
      y: from.y + ((to.y - from.y) * i) / 5,
      button: 'left',
      buttons: 1,
    });
  await page.send('Input.dispatchMouseEvent', {
    type: 'mouseReleased',
    ...to,
    button: 'left',
    clickCount: 1,
  });
}

test(
  'the user menu stays open for a press inside it released outside, so a sign-out error can be copied',
  { skip },
  async () => {
    // A press inside the menu that is released outside clicks their common ancestor, outside
    // the menu, which closed it; reopening it then hid #sign-out-error, the only record that
    // the sign-out did not happen. The dialogs' rule applies: only a press that starts and ends
    // outside closes (the drawer's counterpart: 'a press inside the drawer…') (§19 G7).
    const page = await open();
    await page.click('#user-chip');
    mock.routes.set('POST /api/auth/logout', () => ({
      status: 500,
      body: { error: 'Uptime Goblin could not complete that request.' },
    }));
    await page.click('#sign-out');
    await page.waitFor("document.querySelector('#sign-out-error').hidden === false");
    await page.settle();
    const box = selector =>
      page.eval(
        `(r => ({ left: r.left, right: r.right, top: r.top, bottom: r.bottom }))(document.querySelector(${js(selector)}).getBoundingClientRect())`
      );
    const error = await box('#sign-out-error'),
      menu = await box('#user-menu');
    const menuHidden = () => page.eval("document.querySelector('#user-menu').hidden");
    // Selects the error's text, released below the menu.
    await drag(
      page,
      { x: error.left + 2, y: error.top + 6 },
      { x: error.right - 10, y: menu.bottom + 25 }
    );
    await page.settle();
    assert.notEqual(await page.eval('String(getSelection())'), '', 'text was selected');
    assert.equal(await menuHidden(), false, 'the menu stays open');
    assert.equal(await page.eval("document.querySelector('#sign-out-error').hidden"), false);
    // A press that starts outside and is released inside closes nothing either.
    await drag(
      page,
      { x: menu.left - 40, y: menu.bottom + 25 },
      { x: error.left + 4, y: error.top + 6 }
    );
    await page.settle();
    assert.equal(await menuHidden(), false);
    // A click outside still closes it, and so does a keyboard's click on a control outside,
    // whatever press came before.
    await page.click('#dashboard-title');
    assert.equal(await menuHidden(), true);
    await page.click('#user-chip');
    assert.equal(await menuHidden(), false);
    await drag(
      page,
      { x: menu.left + 10, y: menu.top + 10 },
      { x: menu.left - 40, y: menu.bottom + 25 }
    );
    await page.eval("document.querySelector('#refresh').focus()");
    await page.press('Enter');
    assert.equal(await menuHidden(), true);
    assert.deepEqual(page.exceptions, []);
  }
);

/** The page at `hash` on a phone `width` CSS pixels wide, as a phone's browser lays it out. */
async function openOnPhone(width, hash = '') {
  const page = await openPage(cdp, 'about:blank', { prelude, PageClass: Page, width });
  pages.push(page);
  await page.send('Emulation.setDeviceMetricsOverride', {
    width,
    height: 740,
    deviceScaleFactor: 2,
    mobile: true,
  });
  await page.send('Page.navigate', { url: base + '/' + hash });
  await page.waitFor(
    hash.startsWith('#configure')
      ? "document.querySelector('#configuration-nav a')"
      : "document.querySelector('#services > *')"
  );
  await page.settle();
  return page;
}
/**
 * How wide the page lays out, what of the top bar is off the screen, and whether the actions
 * come closer than 6 px to the brand ('crowded').
 */
const pageWidth = page =>
  page.eval(`({
    innerWidth,
    scrollWidth: document.documentElement.scrollWidth,
    off: ['.brand', '#user-chip', '#refresh', '#settings', '#user-menu']
      .map(s => [s, document.querySelector(s)])
      .filter(([, e]) => e.getClientRects().length)
      .filter(([, e]) => { const r = e.getBoundingClientRect(); return r.left < 0 || r.right > innerWidth; })
      .map(([s]) => s)
      .concat(
        [...document.querySelector('.top-actions').children].some(e => e.getClientRects().length &&
          e.getBoundingClientRect().left < document.querySelector('.brand').getBoundingClientRect().right + 6)
          ? ['crowded'] : []
      ),
  })`);

/**
 * For each row of the sessions list, scrolled to the start or the end of its scroll box: whether
 * its action (Sign out, or what the row says instead) is inside the box, and for a Sign out,
 * whether a tap at its centre reaches it. Also whether the table is wider than its box.
 */
const sessionActions = (page, end) =>
  page.eval(`(() => {
    const box = document.querySelector('#sessions-list').closest('.table-scroll');
    box.scrollLeft = ${end === 'end' ? 'box.scrollWidth' : '0'};
    const rows = [...box.querySelectorAll('tbody [data-session]')].map(row => {
      // Only the page scrolls up or down to the row (at once: the page scrolls smoothly); the
      // box keeps its scroll.
      window.scrollBy({ top: row.getBoundingClientRect().top - innerHeight / 2, behavior: 'instant' });
      const edge = box.getBoundingClientRect(),
        action = row.lastElementChild.firstElementChild,
        r = action.getBoundingClientRect(),
        inside = r.left >= edge.left - 0.5 && r.right <= edge.right + 0.5;
      if (action.localName !== 'button') return inside;
      return inside && document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2) === action;
    });
    return { scrolls: box.scrollWidth > box.clientWidth, rows };
  })()`);

test(
  'on a phone nothing is wider than the screen: the top bar, the Account page (its sessions’ Sign out in view) and the sign-in dialog',
  { skip },
  async () => {
    // With the user chip the top bar was 383 px wide at 360 px (390 with Dashboard), and the
    // sessions table's hidden Action heading escaped its scroll box, making the Account page
    // about 690 px wide; a phone then widened the page, clipping the sign-in dialog
    // (§17 E7, E8). Down to the 320 px the page supports.
    serveSessions();
    onlySignedIn();
    for (const width of [320, 360, 375, 414, 480, 667]) {
      const expected = { innerWidth: width, scrollWidth: width, off: [] };
      const page = await openOnPhone(width);
      assert.deepEqual(await pageWidth(page), expected, `${width} dashboard`);
      // The chip is never squeezed narrower than what it shows (its icon or name, and its
      // caret): at 320 px the longer name Uptime Goblin left it 18 px wide, under Refresh.
      assert.equal(
        await page.eval(
          "(e => e.scrollWidth <= e.clientWidth)(document.querySelector('#user-chip'))"
        ),
        true,
        `${width} chip`
      );
      // Up to 440 px the chip shows an icon instead of the name, and still says whose it is.
      assert.equal(
        await page.eval(
          "getComputedStyle(document.querySelector('.user-chip-icon')).display !== 'none'"
        ),
        width <= 440
      );
      assert.equal(await text(page, '#user-chip-name'), 'Administrator');
      // Wider, the name shows, in full: the chip does not give way to the HOMELAB label.
      if (width > 440)
        assert.equal(
          await page.eval(
            "(e => e.getClientRects().length && e.scrollWidth <= e.clientWidth)(document.querySelector('#user-chip-name'))"
          ),
          true,
          `${width} name`
        );
      const { x, y } = await page.center('#user-chip');
      assert.equal(
        await page.eval(`document.elementFromPoint(${x}, ${y})?.closest('#user-chip')?.id`),
        'user-chip'
      );
      await page.click('#user-chip');
      assert.deepEqual(await pageWidth(page), expected, `${width} menu`);
      await page.click('#user-chip');
      await page.eval("location.hash = '#configure/account'");
      await page.waitFor(
        "document.querySelectorAll('#sessions-list tbody [data-session]').length === 3"
      );
      await page.settle();
      assert.deepEqual(await pageWidth(page), expected, `${width} Account`);
      // The table is wider than its box on a phone, and a row's Sign out, at its end, was some
      // 370 px past the visible edge, where a touch user would not know to look (§18 F8). It
      // stays in the box wherever the table is scrolled.
      for (const end of ['start', 'end'])
        assert.deepEqual(
          await sessionActions(page, end),
          { scrolls: true, rows: [true, true, true] },
          `${width} sessions list, scrolled to its ${end}`
        );
      mock.signedIn = false;
      await page.eval('window.__poll()');
      await page.waitFor(isOpen('signin-dialog'));
      await settled(page, 'signin-dialog');
      assert.deepEqual(await pageWidth(page), expected, `${width} sign-in dialog`);
      const dialog = await page.eval(
        "(r => [r.left, r.right])(document.querySelector('#signin-dialog').getBoundingClientRect())"
      );
      assert.ok(dialog[0] >= 0 && dialog[1] <= width, `${width} dialog ${dialog}`);
      assert.deepEqual(await cspViolations(page), []);
      assert.deepEqual(page.exceptions, []);
      mock.signedIn = true;
      await closeNewest();
    }
    // A longer name than Administrator: the chip shortens it, and nothing else gives way.
    mock.sessionBody = () =>
      identity.session('session', {
        user: { ...identity.session('session').user, display: 'Administrator of this homelab' },
      });
    const page = await openOnPhone(667);
    assert.deepEqual(await pageWidth(page), { innerWidth: 667, scrollWidth: 667, off: [] });
    assert.deepEqual(
      await page.eval(
        "['#refresh', '#settings', '#connection'].map(s => document.querySelector(s)).map(e => e.scrollWidth <= e.clientWidth && e.getBoundingClientRect().width >= 37)"
      ),
      [true, true, true]
    );
    assert.equal(
      await page.eval(
        "(e => e.scrollWidth > e.clientWidth)(document.querySelector('#user-chip-name'))"
      ),
      true,
      'the name is shortened'
    );
  }
);

// Round 7 of the 1.5 review (sessions spec §20): the signed-out notices and the user menu.

/** Counts the changes to `selector` and everything in it from now on (window.__changes). */
const watchChanges = (page, selector) =>
  page.eval(`(() => {
    window.__changes = 0;
    new MutationObserver(list => (window.__changes += list.length)).observe(
      document.querySelector(${js(selector)}),
      { childList: true, subtree: true, characterData: true, attributes: true }
    );
  })()`);

test(
  'a poll refused for two cookies of Uptime Goblin’s name says to remove them and stops polling; Sign in returns once they are gone',
  { skip },
  async () => {
    // §20 H5. Another site set a cookie of Uptime Goblin's name beside the browser's own while the page
    // was open (a page on another port of the same host), so Uptime Goblin refuses every request with
    // 401 multiple_credentials, and api() asks nobody. The page said "Signed out. Sign in to see
    // current readings." with a Sign in that fails the same way, went on polling, and drew the
    // notice again at each poll: read out again every 15 s, and the keyboard focus on its
    // Sign in dropped to <body>.
    const twoCookies = () => identity.unauthorized('multiple_credentials');
    const refuse = () => {
      mock.routes.set('GET /api/dashboard', twoCookies);
      mock.routes.set('GET /api/session', twoCookies);
    };
    const accept = () => {
      mock.routes.delete('GET /api/dashboard');
      mock.routes.delete('GET /api/session');
    };
    const notices = page =>
      page.eval(
        "['#notice', '#configuration-notice'].map(s => document.querySelector(s)).map(e => [e.hidden, e.textContent, e.querySelectorAll('button').length])"
      );
    const saysTwoCookies = `document.querySelector('#notice').textContent === ${js(signInTexts.multiple_credentials)}`;
    const focusTab = page => page.eval("window.dispatchEvent(new Event('focus'))");

    let page = await open();
    refuse();
    await page.poll();
    await page.waitFor(saysTwoCookies);
    assert.deepEqual(await notices(page), [
      [false, signInTexts.multiple_credentials, 0],
      [false, signInTexts.multiple_credentials, 0],
    ]);
    assert.equal(await text(page, '#connection'), 'Signed out');
    assert.equal(await page.eval(isOpen('signin-dialog')), false);
    await watchChanges(page, '#notice');
    // Polls stop: each would only be refused again.
    const polls = requests('GET', '/api/dashboard').length;
    await page.eval('window.__poll()');
    await delay(200);
    assert.equal(requests('GET', '/api/dashboard').length, polls, 'no poll');
    // A look at the tab asks Uptime Goblin again. Still two cookies: the notice stays as it is.
    const probes = requests('GET', '/api/session').length;
    await focusTab(page);
    await waitForRequests('GET', '/api/session', probes + 1);
    await page.settle();
    assert.equal(await page.eval('window.__changes'), 0, 'the notice was not drawn again');
    // This site's cookies were removed: Uptime Goblin asks for a sign-in, which can succeed now, and
    // the notice offers it at the next look at the tab.
    accept();
    mock.signedIn = false;
    mock.signedOutAs = 'signin_required';
    await focusTab(page);
    await page.waitFor("document.querySelector('#notice-sign-in')");
    assert.deepEqual(await notices(page), [
      [false, `${signedOutNotice} Sign in`, 1],
      [false, `${signedOutNotice} Sign in`, 1],
    ]);
    await page.eval("document.querySelector('#notice-sign-in').click()");
    await page.waitFor(isOpen('signin-dialog'));
    await settled(page, 'signin-dialog');
    await submitSignIn(page, 'reauth');
    await page.waitFor(`!${isOpen('signin-dialog')}`);
    await page.waitFor("document.querySelector('#notice').hidden");
    const loads = requests('GET', '/api/dashboard').length;
    await page.poll();
    assert.equal(requests('GET', '/api/dashboard').length, loads + 1, 'polls resume');
    assert.deepEqual(await cspViolations(page), []);
    assert.deepEqual(page.exceptions, []);
    await closeNewest();

    // The other site's cookie went by itself: Uptime Goblin knows this browser again, and the next look
    // at the tab carries on where the page stopped.
    page = await open();
    refuse();
    await page.poll();
    await page.waitFor(saysTwoCookies);
    accept();
    const before = requests('GET', '/api/dashboard').length;
    await focusTab(page);
    await waitForRequests('GET', '/api/dashboard', before + 1);
    await page.waitFor("document.querySelector('#notice').hidden");
    await page.settle();
    assert.equal(await page.eval("document.querySelector('#configuration-notice').hidden"), true);
    assert.notEqual(await text(page, '#connection'), 'Signed out');
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'Cancel in the dialog that the signed-out notice’s Sign in opened returns the focus to that Sign in',
  { skip },
  async () => {
    // §20 H7. Cancel showed the signed-out notices again, which drew them anew with a new
    // Sign in: the dialog found the button it had come from gone, and the focus went to the
    // page's heading. A notice that already says so is left as it is now.
    const page = await open();
    mock.signedIn = false;
    await page.eval('window.__poll()');
    await page.waitFor(isOpen('signin-dialog'));
    await settled(page, 'signin-dialog');
    await page.press('Escape');
    await page.waitFor(`!${isOpen('signin-dialog')}`);
    await page.waitFor("document.querySelector('#notice-sign-in')");
    await page.settle();
    for (const [hash, notice, button] of [
      ['', '#notice', '#notice-sign-in'],
      ['#configure/overview', '#configuration-notice', '#configuration-sign-in'],
    ]) {
      if (hash) {
        await page.eval(`location.hash = ${js(hash)}`);
        await page.waitFor(`document.querySelector(${js(button)})?.getClientRects().length > 0`);
        await page.settle();
      }
      await page.eval(`window.__signIn = document.querySelector(${js(button)})`);
      await watchChanges(page, notice);
      for (const how of ['Escape', 'Cancel']) {
        await page.eval('window.__signIn.focus()');
        await page.waitFor('document.activeElement === window.__signIn');
        await page.press('Enter');
        await page.waitFor(isOpen('signin-dialog'), 10000);
        await settled(page, 'signin-dialog');
        if (how === 'Escape') await page.press('Escape');
        else await page.click('#reauth-cancel');
        await page.waitFor(`!${isOpen('signin-dialog')}`);
        await page.settle();
        await delay(300);
        assert.equal(
          await page.eval('document.activeElement === window.__signIn'),
          true,
          `${button}, ${how}: the focus is back on it`
        );
      }
      assert.equal(await page.eval('window.__changes'), 0, `${notice} was not drawn again`);
      assert.equal(await text(page, notice), `${signedOutNotice} Sign in`);
    }
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'Account in the user menu gives the focus to the chip when no page opens, and to the Account page’s heading when it does',
  { skip },
  async () => {
    // §20 H8. The menu closed with its Account link, which had the focus, expecting the
    // Account page to take it. On the Account page already, or with unsaved changes kept at
    // the prompt, no page opened, and the focus dropped to <body>.
    const page = await open('#configure/account');
    await page.waitFor("document.querySelector('#account-details')");
    const account = async () => {
      await page.eval("document.querySelector('#user-chip').focus()");
      await page.waitFor("document.activeElement.id === 'user-chip'");
      await page.press('Enter');
      await page.waitFor("!document.querySelector('#user-menu').hidden");
      await page.eval("document.querySelector('#user-account').focus()");
      await page.waitFor("document.activeElement.id === 'user-account'");
      await page.press('Enter');
      await page.waitFor("document.querySelector('#user-menu').hidden");
      await page.settle();
      assert.equal(await page.eval("document.querySelector('#user-menu').hidden"), true);
      assert.equal(
        await page.eval("document.querySelector('#user-chip').getAttribute('aria-expanded')"),
        'false'
      );
    };
    const focused = () => page.eval('document.activeElement.id');
    await account();
    assert.equal(await page.eval('location.hash'), '#configure/account');
    assert.equal(await focused(), 'user-chip', 'already on the Account page');
    await page.eval("location.hash = '#configure/appearance'");
    await page.waitFor("document.querySelector('#workspace-title')");
    await setValue(page, '#workspace-title', 'A draft');
    await page.eval('window.__confirmAnswer = false; window.__confirmCalls = 0');
    await account();
    assert.equal(await page.eval('window.__confirmCalls'), 1);
    assert.equal(await page.eval('location.hash'), '#configure/appearance');
    assert.equal(await focused(), 'user-chip', 'the draft kept');
    assert.equal(await page.eval("document.querySelector('#workspace-title').value"), 'A draft');
    await page.eval('window.__confirmAnswer = true');
    await account();
    await page.waitFor("location.hash === '#configure/account'");
    await page.waitFor("document.activeElement?.id === 'configuration-section-title'");
    assert.deepEqual(page.exceptions, []);
  }
);

// Durable alert delivery (1.5 delivery spec §6.5–§7.4, §8.1 U): Configure → Notifications, its
// dialogs, the banners, and the delivery texts of the Email, Alerts and System pages and of the
// alerts dialog. The mocked answers are those test/contract/notifications-bodies.json pins (the
// contract the http lane's routes are tested against), so the web app is tested against what
// Uptime Goblin sends. Until that fixture exists (the delivery milestone's Phase 0 adds it) these tests
// use the same bodies written out from the spec (§6.5 shapes, §6.6 texts); once it exists, every
// error body used here must be in it, and every mocked shape must have exactly its keys.
const notificationsFixture = (() => {
  try {
    return JSON.parse(
      fs.readFileSync(new URL('./contract/notifications-bodies.json', import.meta.url), 'utf8')
    );
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
})();
/** The keys of `mine` and `theirs` agree, recursively through objects and first array items. */
function assertSameKeys(mine, theirs, where) {
  if (!mine || !theirs || typeof mine !== 'object' || typeof theirs !== 'object') return;
  if (Array.isArray(mine) || Array.isArray(theirs)) {
    if (Array.isArray(mine) && Array.isArray(theirs) && mine.length && theirs.length)
      assertSameKeys(mine[0], theirs[0], `${where}[0]`);
    return;
  }
  assert.deepEqual(
    Object.keys(mine).sort(),
    Object.keys(theirs).sort(),
    `${where}: the mocked keys differ from test/contract/notifications-bodies.json`
  );
  for (const key of Object.keys(mine)) assertSameKeys(mine[key], theirs[key], `${where}.${key}`);
}
let fixtureShapesChecked = false;
/** Once per run, with the fixture present: the Status, Delivery and list shapes match it. */
function checkFixtureShapes() {
  if (!notificationsFixture || fixtureShapesChecked) return;
  fixtureShapesChecked = true;
  const find = (what, predicate) => {
    for (const body of objects(notificationsFixture)) if (predicate(body)) return body;
    throw new Error(`test/contract/notifications-bodies.json has no ${what}`);
  };
  const status = find('Status', b => Array.isArray(b.channels) && b.totals && 'saving' in b);
  assertSameKeys(
    notificationStatus({
      channels: [channelBody('email'), channelBody('env-webhook')],
      signing: { configured: true, saved: true, createdAt: 1, previousUntil: null },
    }),
    status,
    'Status'
  );
  const list = find('deliveries list', b => Array.isArray(b.deliveries) && 'nextCursor' in b);
  assertSameKeys(
    { deliveries: [deliveryBody()], nextCursor: null, unsaved: 0 },
    list,
    'deliveries list'
  );
  const delivery = find('Delivery', b => typeof b.uid === 'string' && b.alert && 'retryable' in b);
  assertSameKeys(deliveryBody(), delivery, 'Delivery');
  // The dashboard's notifications: 1.4.x's fields and the additive ones (§6.5, D12).
  const dashboardFields = find('dashboard notifications', b => b.attention && b.webhook && b.email);
  assertSameKeys(
    dashboardNotifications(
      notificationStatus({ channels: [channelBody('email'), channelBody('env-webhook')] })
    ),
    dashboardFields,
    'dashboard notifications'
  );
}
// §6.6, verbatim. "{name}" and the like are filled in per use.
const deliveryMessages = {
  invalid_request: [400, 'This request is not valid: {detail}.'],
  delivery_not_found: [404, "That notification is no longer in Uptime Goblin's delivery history."],
  'delivery_not_retryable:sending': [409, 'This notification is being sent right now.'],
  'delivery_not_retryable:waiting': [409, 'This notification has not had its first attempt yet.'],
  'delivery_not_retryable:finished': [
    409,
    'Only failed notifications and notifications waiting to retry can be retried.',
  ],
  delivery_outdated: [
    409,
    'A later notification for the same alert was already delivered or is being sent on this channel, so sending this one now would arrive out of order.',
  ],
  channel_paused: [
    409,
    '{name} notifications are paused: {reason} Resume the channel to send them.',
  ],
  channel_unknown: [404, 'There is no notification channel with that name.'],
  webhook_not_configured: [
    404,
    'The alert webhook is not set up: set GOBLIN_WEBHOOK_URL on the Uptime Goblin server and restart Uptime Goblin.',
  ],
  signing_unavailable: [
    503,
    'The webhook signing key cannot be read right now. Uptime Goblin replaces it at its next start if the encryption key changed.',
  ],
  signing_compatibility: [
    409,
    'A newer Uptime Goblin saved these signing settings. Upgrade Uptime Goblin or restore a compatible backup before changing them.',
  ],
  signing_conflict: [
    409,
    'The signing key was just replaced elsewhere. Reload to see the current one.',
  ],
  delivery_status_unavailable: [
    503,
    'Delivery status is unavailable: Uptime Goblin could not read its control database.',
  ],
  storage_full: [
    503,
    "Uptime Goblin's disk is full, so this change was not saved. Free some space on the Uptime Goblin host, then try again. Sign-in and alert delivery keep working on space Uptime Goblin keeps in reserve.",
  ],
};
const deliveryRetryAfter = {
  signing_unavailable: 60,
  delivery_status_unavailable: 15,
  storage_full: 60,
};
/** A §6.6 refusal: `{status, headers, body: {error, code}}`, checked against the fixture. */
function deliveryError(code, { variant, name = '', reason = '', detail = '' } = {}) {
  const [status, template] = deliveryMessages[variant ? `${code}:${variant}` : code];
  const error = template
    .replace('{name}', name)
    .replace('{reason}', reason)
    .replace('{detail}', detail);
  if (notificationsFixture) {
    const pattern = new RegExp(
      `^${template.replace(/[.*+?^$()|[\]\\]/g, '\\$&').replace(/\{\w+\}/g, '.+')}$`
    );
    let found = false;
    for (const body of objects(notificationsFixture))
      if (body.code === code && typeof body.error === 'string' && pattern.test(body.error))
        found = true;
    if (!found)
      throw new Error(`test/contract/notifications-bodies.json has no ${code} body "${template}"`);
  }
  const retryAfter = deliveryRetryAfter[code];
  return {
    status,
    headers: retryAfter ? { 'Retry-After': String(retryAfter) } : {},
    body: { error, code },
  };
}
const counts0 = () => ({ waiting: 0, retrying: 0, sending: 0, paused: 0, failed: 0 });
/** A §6.5 Channel: set up, enabled and working, nothing sent yet, unless `overrides` say so. */
function channelBody(id, overrides = {}) {
  return {
    id,
    name: id === 'email' ? 'Email' : 'Webhook',
    configured: true,
    enabled: true,
    state: 'ok',
    pausedReason: null,
    pausedSince: null,
    nextAttemptAt: null,
    consecutiveFailures: 0,
    consecutiveRefusals: 0,
    deliveredTotal: 0,
    failedTotal: 0,
    lastAttempt: null,
    lastSuccess: null,
    lastFailure: null,
    lastError: null,
    failedSince: Date.now() - 86400000,
    oldestWaitingAt: null,
    host: id === 'env-webhook' ? 'hooks.example.test' : null,
    notQueued: 0,
    notQueuedAt: null,
    ...overrides,
    counts: { ...counts0(), ...overrides.counts },
  };
}
const notSetUp = id =>
  channelBody(id, { configured: false, enabled: false, state: 'not-configured', host: null });
/**
 * A §6.5 Status over `channels` (by default: neither channel set up), its totals the sum of the
 * channels' counts. `signing` defaults to signed when the webhook is set up, else null.
 */
/**
 * Uptime Goblin's ntfy and Gotify settings routes, as test/contract/notifications-bodies.json pins them:
 * secrets kept here, answered only as {set}; a PATCH merges (null or '' clears a secret) and
 * bumps the version; a test is accepted once the channel is set up.
 */
function pushMock() {
  const secretNames = ['token', 'password'];
  const docs = {
    ntfy: {
      version: 0,
      value: {
        enabled: false,
        server: 'https://ntfy.sh',
        topic: '',
        username: '',
        password: null,
        token: null,
        priorityFiring: 4,
        priorityResolved: 3,
        tags: [],
        dashboardUrl: '',
        allowPlainHttp: false,
      },
    },
    gotify: {
      version: 0,
      value: {
        enabled: false,
        server: '',
        token: null,
        priorityFiring: 8,
        priorityResolved: 4,
        dashboardUrl: '',
        allowPlainHttp: false,
      },
    },
  };
  const answer = id => {
    const body = {
      channel: id,
      version: docs[id].version,
      readOnly: false,
      unreadable: [],
      settings: Object.fromEntries(
        Object.entries(docs[id].value).map(([key, value]) => [
          key,
          secretNames.includes(key) ? { set: value !== null && value !== '' } : value,
        ])
      ),
      updatedAt: docs[id].version ? Date.now() : null,
    };
    if (notificationsFixture)
      assertSameKeys(
        body,
        notificationsFixture.answers[id === 'ntfy' ? 'pushSettings' : 'pushSettingsGotify'],
        `${id} settings`
      );
    return { body };
  };
  const handler = (method, id, what, input) => {
    if (what === 'settings' && method === 'GET') return answer(id);
    if (what === 'settings' && method === 'PATCH') {
      const { version, ...change } = input;
      if (version !== undefined && version !== docs[id].version)
        return {
          status: 409,
          body: notificationsFixture?.errors.channel_settings_conflict.body ?? {
            error: 'These settings were changed elsewhere meanwhile.',
            code: 'channel_settings_conflict',
          },
        };
      for (const [key, value] of Object.entries(change))
        docs[id].value[key] = secretNames.includes(key) && value === '' ? null : value;
      docs[id].version++;
      return answer(id);
    }
    if (what === 'test' && method === 'POST') {
      const v = docs[id].value;
      if (!(id === 'ntfy' ? v.topic : v.server && v.token))
        return notificationsFixture?.errors[`channel_not_set_up/${id}-test`] ?? { status: 409 };
      return {
        body: {
          ok: true,
          accepted: true,
          message: `${id === 'ntfy' ? 'ntfy' : 'Gotify'} accepted the test notification.`,
        },
      };
    }
    return { status: 405, body: { error: 'Method not allowed' } };
  };
  handler.docs = docs;
  return handler;
}
function notificationStatus({ channels, signing, ...overrides } = {}) {
  checkFixtureShapes();
  const list = channels ?? [notSetUp('email'), notSetUp('env-webhook')];
  const totals = counts0();
  for (const c of list) for (const key of Object.keys(totals)) totals[key] += c.counts[key];
  const oldest = list.map(c => c.oldestWaitingAt).filter(Boolean);
  const webhook = list.find(c => c.id === 'env-webhook');
  return {
    available: true,
    saving: true,
    unsavedSince: null,
    unsavedReason: null,
    updatedAt: Date.now(),
    totals,
    oldestWaitingAt: oldest.length ? Math.min(...oldest) : null,
    notQueued: 0,
    channels: list,
    signing:
      signing !== undefined
        ? signing
        : webhook?.configured
          ? { configured: true, saved: true, createdAt: Date.now() - 86400000, previousUntil: null }
          : null,
    ...overrides,
  };
}
/**
 * The answer of GET /api/notifications/webhook/public-key for a new test key: public material
 * only, as test/contract/notifications-bodies.json pins it. `previous` (true) lists another key
 * as the previous one, until `previousUntil`.
 */
function publicKeyBody({ createdAt = Date.now(), previous = false, previousUntil = null } = {}) {
  const part = key => {
    const { keyId, publicKey, publicKeyRaw } = publicSigningKey(key);
    return { keyId, publicKey, publicKeyRaw };
  };
  const body = {
    ...publicSigningKey(generateSigningKey()),
    createdAt,
    previousUntil: previous ? previousUntil : null,
    previous: previous ? part(generateSigningKey()) : null,
  };
  if (notificationsFixture)
    assertSameKeys(body, notificationsFixture.answers.publicKey, 'public key');
  return body;
}
/**
 * The dashboard's `notifications` for `status`, as the spec's §6.5 and D12 derive them: the 1.4.x
 * fields, and the additive ones. `email.waiting` counts the email rows not yet sent (waiting,
 * retrying or held), `email.retrying` those waiting to retry (A44).
 */
function dashboardNotifications(status, overrides = {}) {
  const setUp = status.channels.filter(c => c.configured && c.enabled);
  const email = status.channels.find(c => c.id === 'email'),
    webhook = status.channels.find(c => c.id === 'env-webhook'),
    webhookError =
      webhook?.lastFailure && webhook.lastFailure > (webhook.lastSuccess ?? 0)
        ? webhook.lastFailure
        : null;
  const enabled = !!email?.enabled,
    configured = !!email?.configured;
  const emailError =
    email?.lastError && (!email.lastSuccess || email.lastError.time >= email.lastSuccess);
  return {
    configured: !!webhook?.configured,
    lastError: webhookError,
    webhook: { configured: !!webhook?.configured, lastError: webhookError },
    email: {
      enabled,
      configured,
      state: !enabled
        ? 'disabled'
        : !configured
          ? 'unconfigured'
          : ['paused', 'refusing'].includes(email.state) || emailError
            ? 'error'
            : email.lastSuccess
              ? 'accepted'
              : 'ready',
      pending: email ? email.counts.waiting + email.counts.retrying + email.counts.sending : 0,
      lastAttempt: email?.lastAttempt ?? null,
      lastAccepted: email?.lastSuccess ?? null,
      lastError: email?.lastError ?? null,
      failedCount: email?.failedTotal ?? 0,
      channelState: email?.state ?? 'not-configured',
      pausedReason: email?.pausedReason ?? null,
      nextAttemptAt: email?.nextAttemptAt ?? null,
      waiting: email ? email.counts.waiting + email.counts.retrying + email.counts.paused : 0,
      retrying: email?.counts.retrying ?? 0,
      failed: email?.counts.failed ?? 0,
    },
    available: status.available,
    updatedAt: status.updatedAt,
    saving: status.saving,
    unsavedSince: status.unsavedSince,
    // Over the channels that are set up and on, as the server counts them.
    attention: {
      waiting: setUp.reduce((n, c) => n + c.counts.waiting, 0),
      retrying: setUp.reduce((n, c) => n + c.counts.retrying, 0),
      failed: setUp.reduce((n, c) => n + c.counts.failed, 0),
      paused: setUp.filter(c => c.state === 'paused').map(c => c.id),
      refusing: setUp.filter(c => c.state === 'refusing').map(c => c.id),
      notQueued: setUp
        .filter(c => c.notQueued > 0 && c.notQueuedAt > status.updatedAt - 86400000)
        .map(c => c.id),
    },
    channels: status.channels.map(c => ({
      id: c.id,
      state: c.state,
      pausedReason: c.pausedReason,
      nextAttemptAt: c.nextAttemptAt,
      lastAttempt: c.lastAttempt,
      notQueued: c.notQueued,
      notQueuedAt: c.notQueuedAt,
    })),
    ...overrides,
  };
}
/** Uptime Goblin answers `status` from now on, and the dashboard says the same. */
function useStatus(status, dashboardOverrides = {}) {
  mock.status = () => ({ body: status });
  mock.dashboard.notifications = dashboardNotifications(status, dashboardOverrides);
  return status;
}
const base32 = 'abcdefghijklmnopqrstuvwxyz234567';
let deliveryCount = 0;
/** A delivery id, `d_` and 26 base32 characters, as Uptime Goblin makes them. */
const deliveryUid = () =>
  'd_' +
  Array.from({ length: 26 }, (_, i) => base32[Math.floor(++deliveryCount / 32 ** (i % 5)) % 32])
    .join('')
    .slice(0, 26);
/** A §6.5 Delivery: a webhook firing of Plex that failed, unless `overrides` say otherwise. */
function deliveryBody({ alert = {}, ...overrides } = {}) {
  const time = Date.now() - 3600000;
  return {
    uid: deliveryUid(),
    channel: 'env-webhook',
    kind: 'firing',
    status: 'failed',
    state: 'dead',
    alert: {
      service: 'plex',
      name: 'Plex',
      category: 'availability',
      rule: '__availability',
      message: 'Source is unavailable: connection refused',
      time,
      ...alert,
    },
    createdAt: time,
    updatedAt: time + 60000,
    attempts: 3,
    nextAttemptAt: null,
    sentAt: null,
    lastStatus: 500,
    lastError: 'The webhook answered 500.',
    batch: null,
    saved: true,
    retryable: true,
    ...overrides,
  };
}
const statusRequests = () =>
  mock.requests.filter(r => r.method === 'GET' && r.path === '/api/notifications');
/** Configure → Notifications, once its status and both lists have been read. */
async function openNotifications() {
  const page = await open('#configure/notifications');
  await page.waitFor(`(() => {
    const summary = document.querySelector('#notifications-summary');
    return summary && !summary.textContent.startsWith('Reading') &&
      [...document.querySelectorAll('#attention-list, #history-list')].every(l => !l.textContent.includes('Reading notifications'));
  })()`);
  await page.settle();
  return page;
}
/** Presses Refresh and waits until the page has read the status (and the lists) again. */
async function refreshPage(page) {
  const before = statusRequests().length;
  await page.eval("document.querySelector('#notifications-refresh').click()");
  while (statusRequests().length === before) await delay(10);
  await page.settle();
}
/** Presses a key on the focused element, as a keyboard would (Tab, Enter, Escape, Space). */
async function pressKey(page, key, { shift = false } = {}) {
  const keys = {
    Tab: { code: 'Tab', keyCode: 9 },
    Enter: { code: 'Enter', keyCode: 13, text: '\r' },
    Escape: { code: 'Escape', keyCode: 27 },
    ' ': { code: 'Space', keyCode: 32, text: ' ' },
  };
  const { code, keyCode, text } = keys[key];
  const common = { key, code, windowsVirtualKeyCode: keyCode, modifiers: shift ? 8 : 0 };
  await page.send('Input.dispatchKeyEvent', {
    type: text ? 'keyDown' : 'rawKeyDown',
    ...common,
    ...(text ? { text } : {}),
  });
  await page.send('Input.dispatchKeyEvent', { type: 'keyUp', ...common });
}
/** The element that has the focus, described for assertions. */
const focused = page =>
  page.eval(`(() => {
    const e = document.activeElement;
    return e ? (e.id ? '#' + e.id : e.getAttribute('aria-label') || e.dataset.id || e.localName) : null;
  })()`);
const allText = (page, selector) =>
  page.eval(
    `[...document.querySelectorAll(${js(selector)})].map(e => e.textContent.replace(/\\s+/g, ' ').trim())`
  );

test(
  'Configure → Notifications: the ntfy and Gotify forms check their input, save secrets write-only and send a test',
  { skip },
  async () => {
    const page = await openNotifications();
    await page.waitFor(
      "document.querySelector('#push-ntfy-form') && document.querySelector('#push-gotify-form')"
    );
    assert.equal(await text(page, '#push-title'), 'Push notifications');
    const property = (selector, name) =>
      page.eval(`document.querySelector(${js(selector)})[${js(name)}]`);
    assert.equal(await property('#push-ntfy-server', 'value'), 'https://ntfy.sh');
    assert.equal(await property('#push-ntfy-token', 'placeholder'), 'Not saved');
    assert.equal(await property('#push-ntfy-token', 'type'), 'password');
    const patches = () =>
      mock.requests.filter(r => r.method === 'PATCH' && r.path.endsWith('/ntfy/settings'));
    const patched = async n => {
      while (patches().length < n) await delay(10);
      await page.settle();
      return JSON.parse(patches()[n - 1].body);
    };
    const submit = async id => {
      await page.eval(`document.querySelector('#push-${id}-form').requestSubmit()`);
      await page.settle();
    };
    const check = (selector, value) =>
      page.eval(`document.querySelector(${js(selector)}).checked = ${js(value)}`);
    // Checked here before anything is sent: a topic while it is on, its characters, the address.
    await check('#push-ntfy-enabled', true);
    await submit('ntfy');
    assert.equal(await text(page, '#push-ntfy-result'), 'Enter the ntfy topic to send to.');
    await setValue(page, '#push-ntfy-topic', 'has spaces');
    await submit('ntfy');
    assert.match(await text(page, '#push-ntfy-result'), /letters, digits, _ and -/);
    await setValue(page, '#push-ntfy-topic', 'orbit-alerts');
    await setValue(page, '#push-ntfy-server', 'http://192.0.2.10');
    await submit('ntfy');
    assert.match(await text(page, '#push-ntfy-result'), /plain HTTP to another computer/);
    await setValue(page, '#push-ntfy-tags', 'a, b, c, d, e, f');
    await check('#push-ntfy-plain', true);
    await submit('ntfy');
    assert.equal(await text(page, '#push-ntfy-result'), 'Enter at most 5 tags.');
    assert.equal(patches().length, 0, 'nothing was sent while the form had a problem');
    // Saved: the token goes once, then reads as saved and is never shown again.
    const secret = 'tk_ui-canary-0001';
    await setValue(page, '#push-ntfy-tags', 'house');
    await setValue(page, '#push-ntfy-server', 'https://ntfy.example.test');
    await check('#push-ntfy-plain', false);
    await setValue(page, '#push-ntfy-token', secret);
    await submit('ntfy');
    assert.deepEqual(await patched(1), {
      version: 0,
      enabled: true,
      server: 'https://ntfy.example.test',
      priorityFiring: 4,
      priorityResolved: 3,
      dashboardUrl: '',
      allowPlainHttp: false,
      topic: 'orbit-alerts',
      tags: ['house'],
      token: secret,
      password: null,
      username: '',
    });
    await page.waitFor(
      "document.querySelector('#push-ntfy-result')?.textContent === 'ntfy settings saved.'"
    );
    assert.equal(await property('#push-ntfy-token', 'placeholder'), 'Saved · leave blank to keep');
    assert.equal(await property('#push-ntfy-token', 'value'), '');
    assert.equal(
      await page.eval(`document.documentElement.outerHTML.includes(${js(secret)})`),
      false,
      'the page never holds the saved token'
    );
    // A second save without typing it again keeps it (not sent), at the new version.
    await submit('ntfy');
    const second = await patched(2);
    assert.equal(second.version, 1);
    assert.equal('token' in second, false);
    // Send test notification, and Gotify refusing a test before it is set up.
    await page.eval('document.querySelector(\'[data-push-test="ntfy"]\').click()');
    await page.waitFor(
      "document.querySelector('#push-ntfy-result')?.textContent === 'ntfy accepted the test notification.'"
    );
    await page.eval('document.querySelector(\'[data-push-test="gotify"]\').click()');
    await page.waitFor(
      "/Save a Gotify server/.test(document.querySelector('#push-gotify-result')?.textContent)"
    );
    assert.equal(
      await page.eval("document.querySelector('#push-gotify-result').classList.contains('failed')"),
      true
    );
    // Gotify needs a token when it is switched on.
    await check('#push-gotify-enabled', true);
    await setValue(page, '#push-gotify-server', 'https://gotify.example.test');
    await submit('gotify');
    assert.equal(await text(page, '#push-gotify-result'), 'Enter the Gotify application token.');
    // Clearing the saved ntfy token sends null for it.
    await check('#push-ntfy-clear', true);
    await submit('ntfy');
    const cleared = await patched(3);
    assert.equal(cleared.token, null);
    assert.equal(cleared.password, null);
  }
);

test(
  'Configure → Notifications says what is true in each state, and nothing as current when the status cannot be read',
  { skip },
  async () => {
    const page = await openNotifications();
    // Its place in the navigation: after Email.
    assert.deepEqual((await allText(page, '#configuration-nav a')).slice(5, 7), [
      'Email',
      'Notifications',
    ]);
    assert.equal(
      await text(page, '#configuration-section-title'),
      'Know that every alert got through.'
    );
    assert.equal(
      await page.eval("document.querySelector('#notifications-summary').getAttribute('role')"),
      'status'
    );
    const summary = () => text(page, '#notifications-summary');
    const states = () => allText(page, '#notification-channels .channel-state');
    assert.equal(await summary(), 'No notification channel is set up.');
    assert.deepEqual(await states(), ['Not set up', 'Not set up']);
    assert.match(await text(page, '#notification-channels'), /Set GOBLIN_WEBHOOK_URL/);

    // Set up, nothing sent yet.
    useStatus(notificationStatus({ channels: [channelBody('email'), channelBody('env-webhook')] }));
    await refreshPage(page);
    assert.equal(await summary(), 'Nothing has been sent yet.');
    assert.deepEqual(await states(), ['Ready (nothing sent yet)', 'Ready (nothing sent yet)']);
    assert.equal(
      await text(page, '[data-id="env-webhook"] .channel-signing'),
      'Requests are signed (X-Goblin-Signature).'
    );
    assert.match(await text(page, '[data-id="env-webhook"]'), /Sends tohooks\.example\.test/);
    assert.match(await text(page, '[data-id="email"] .channel-facts'), /Last successNever/);

    // Everything delivered: "delivered" leads to what it means, without leaving the page.
    const now = Date.now();
    useStatus(
      notificationStatus({
        channels: [
          channelBody('email', { lastAttempt: now, lastSuccess: now, deliveredTotal: 4 }),
          channelBody('env-webhook', { lastAttempt: now, lastSuccess: now, deliveredTotal: 2 }),
        ],
      })
    );
    await refreshPage(page);
    assert.equal(await summary(), 'All notifications were delivered.');
    assert.deepEqual(await states(), ['Working', 'Working']);
    await page.eval("document.querySelector('#notifications-summary a[data-in-page]').focus()");
    await pressKey(page, 'Enter');
    await page.settle();
    assert.equal(await focused(page), '#delivered-meaning');
    assert.equal(
      await text(page, '#delivered-meaning'),
      'Delivered means the mail server or the receiver accepted it. Uptime Goblin cannot know whether someone has read it.'
    );
    assert.equal(await page.eval('location.hash'), '#configure/notifications');

    const scenarios = [
      [
        'retrying',
        [
          channelBody('email', { lastAttempt: now, lastSuccess: now }),
          channelBody('env-webhook', {
            state: 'retrying',
            lastAttempt: now,
            lastFailure: now,
            nextAttemptAt: now + 120000,
            counts: { retrying: 2 },
          }),
        ],
        /^2 notifications waiting to retry \(next attempt .+\)\.$/,
        [/^Working$/, /^Retrying \(next attempt .+\)$/],
      ],
      [
        'paused, with a probe to come',
        [
          channelBody('email', { lastAttempt: now }),
          channelBody('env-webhook', {
            state: 'paused',
            pausedReason: 'The webhook answered 404 (not found).',
            pausedSince: now,
            nextAttemptAt: now + 900000,
            counts: { paused: 3 },
          }),
        ],
        /^Webhook is paused: The webhook answered 404 \(not found\)\.$/,
        [
          /^Working$/,
          /^Paused: The webhook answered 404 \(not found\)\. Uptime Goblin tries again at .+\.$/,
        ],
      ],
      [
        'paused until a change',
        [
          channelBody('email', {
            state: 'paused',
            pausedReason: 'Sign-in failed: the mail server refused the app password',
            pausedSince: now,
            counts: { paused: 1 },
          }),
          channelBody('env-webhook', { lastAttempt: now }),
        ],
        /^Email is paused: Sign-in failed: the mail server refused the app password\.$/,
        [/^Paused: Sign-in failed: the mail server refused the app password\.$/, /^Working$/],
      ],
      [
        'refusing',
        [
          channelBody('email', { lastAttempt: now }),
          channelBody('env-webhook', {
            state: 'refusing',
            consecutiveRefusals: 3,
            lastAttempt: now,
            lastFailure: now,
            lastError: { time: now, message: 'The webhook answered 422.' },
            counts: { failed: 3 },
          }),
        ],
        /^Webhook is refusing notifications: The webhook answered 422\.$/,
        [/^Working$/, /^Refusing notifications: The webhook answered 422\.$/],
      ],
      [
        'failed',
        [
          channelBody('email', { lastAttempt: now }),
          channelBody('env-webhook', { lastAttempt: now, lastFailure: now, counts: { failed: 3 } }),
        ],
        /^3 notifications failed\.$/,
        [/^Working$/, /^Working$/],
      ],
      [
        'waiting before the next try',
        [
          channelBody('email', { lastAttempt: now }),
          channelBody('env-webhook', {
            state: 'circuit-open',
            lastAttempt: now,
            nextAttemptAt: now + 60000,
            counts: { retrying: 1 },
          }),
        ],
        /^1 notification waiting to retry \(next attempt .+\)\.$/,
        [/^Working$/, /^Waiting before the next try \(until .+\)$/],
      ],
      [
        'switched off',
        [
          channelBody('email', { enabled: false, state: 'off', lastAttempt: now }),
          channelBody('env-webhook', { lastAttempt: now, deliveredTotal: 1 }),
        ],
        /^All notifications were delivered\.$/,
        [/^Off$/, /^Working$/],
      ],
    ];
    for (const [name, channels, expected, expectedStates] of scenarios) {
      useStatus(notificationStatus({ channels }));
      await refreshPage(page);
      assert.match(await summary(), expected, name);
      const shown = await states();
      expectedStates.forEach((pattern, i) => assert.match(shown[i], pattern, `${name}: ${i}`));
    }
    // The failed count says since when it counts.
    useStatus(
      notificationStatus({
        channels: [
          channelBody('email', { lastAttempt: now }),
          channelBody('env-webhook', { lastAttempt: now, counts: { failed: 3 } }),
        ],
      })
    );
    await refreshPage(page);
    assert.match(await text(page, '[data-id="env-webhook"] .channel-facts'), /Failed since .+3/);
    // A paused channel offers Resume, named for its channel.
    useStatus(notificationStatus({ channels: scenarios[1][1] }));
    await refreshPage(page);
    assert.equal(
      await page.eval(
        "document.querySelector('[data-resume-channel=\"env-webhook\"]').getAttribute('aria-label')"
      ),
      'Resume Webhook notifications'
    );

    // Not being saved: the memory path (D15), with the reason Uptime Goblin gives
    // (lib/alerting/service.mjs), a whole sentence: said once, with one full stop.
    useStatus(
      notificationStatus({
        channels: [channelBody('email', { lastAttempt: now }), channelBody('env-webhook')],
        saving: false,
        unsavedSince: now - 60000,
        unsavedReason: 'Uptime Goblin cannot write its control database (SQLITE_FULL).',
      })
    );
    await refreshPage(page);
    assert.match(
      await summary(),
      /^Notifications are not being saved \(since [^)]+\): Uptime Goblin cannot write its control database \(SQLITE_FULL\)\. Alerts are still sent\.$/
    );
    // Without a reason, the same sentence.
    useStatus(
      notificationStatus({
        channels: [channelBody('email', { lastAttempt: now }), channelBody('env-webhook')],
        saving: false,
        unsavedSince: now - 60000,
      })
    );
    await refreshPage(page);
    assert.match(
      await summary(),
      /^Notifications are not being saved \(since [^)]+\): Uptime Goblin cannot write its control database\. Alerts are still sent\.$/
    );

    // Not signed yet: the key could not be saved (D27). Nothing to show or replace.
    useStatus(
      notificationStatus({
        channels: [channelBody('email'), channelBody('env-webhook')],
        signing: { configured: false, saved: false, createdAt: null, previousUntil: null },
      })
    );
    await refreshPage(page);
    assert.equal(
      await text(page, '[data-id="env-webhook"] .channel-signing'),
      'Not signed yet: Uptime Goblin could not save the signing key (disk full).'
    );
    assert.equal(await page.eval("!!document.querySelector('[data-public-key]')"), false);

    // Unavailable: Uptime Goblin's 503, then no answer at all. The figures read before are not shown
    // as current: no state, no count, no Resume.
    const counted = notificationStatus({ channels: scenarios[1][1] });
    useStatus(counted);
    await refreshPage(page);
    mock.status = () => deliveryError('delivery_status_unavailable');
    await refreshPage(page);
    assert.equal(
      await summary(),
      'Delivery status is unavailable: Uptime Goblin could not read its control database.'
    );
    // Every built-in channel, ntfy and Gotify included, whatever the last status listed.
    assert.deepEqual(await states(), [
      'Delivery status is unavailable.',
      'Delivery status is unavailable.',
      'Delivery status is unavailable.',
      'Delivery status is unavailable.',
    ]);
    const cards = await text(page, '#notification-channels');
    assert.match(cards, /Last successUnknown/);
    assert.doesNotMatch(cards, /Waiting|Held|Failed|Paused|\d/);
    assert.equal(await page.eval("!!document.querySelector('[data-resume-channel]')"), false);
    assert.match(await text(page, '#notifications-updated'), /^Could not read the status at /);
    // The lists say so too, with a way to try again.
    assert.match(await text(page, '#attention-list'), /^Delivery status is unavailable: /);
    mock.status = () => ({ drop: true });
    await refreshPage(page);
    assert.equal(
      await summary(),
      'Delivery status is unavailable: Uptime Goblin is not answering.'
    );
    assert.match(await text(page, '#notification-channels'), /Last successUnknown/);
    // And back.
    useStatus(counted);
    await refreshPage(page);
    assert.match(await summary(), /^Webhook is paused: /);
    assert.deepEqual(await cspViolations(page), []);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'the status is read every 15 s with the dashboard, in the background, and drawn again only when it changed',
  { skip },
  async () => {
    const now = Date.now();
    useStatus(
      notificationStatus({
        channels: [channelBody('email', { lastAttempt: now }), channelBody('env-webhook')],
      })
    );
    const page = await openNotifications();
    await watchChanges(page, '#notifications-summary');
    const before = statusRequests().length;
    await page.poll();
    while (statusRequests().length === before) await delay(10);
    await page.settle();
    const poll = statusRequests().at(-1);
    assert.equal(poll.headers['x-goblin-activity'], 'background');
    // The same sentence is not drawn again (a live region reads out every change).
    assert.equal(await page.eval('window.__changes'), 0);
    // The lists are read again only after an action or Refresh.
    const lists = requests('GET', '/api/notifications/deliveries').length;
    useStatus(
      notificationStatus({
        channels: [
          channelBody('email', { lastAttempt: now }),
          channelBody('env-webhook', { state: 'retrying', counts: { retrying: 1 } }),
        ],
      })
    );
    await page.poll();
    await page.waitFor(
      "document.querySelector('#notifications-summary').textContent.startsWith('1 notification waiting to retry')"
    );
    assert.equal(requests('GET', '/api/notifications/deliveries').length, lists);
    // A person's Refresh is not a background request.
    await refreshPage(page);
    assert.equal(statusRequests().at(-1).headers['x-goblin-activity'], undefined);
  }
);

test(
  'Retry and Resume send one request each, say what happened and keep the keyboard focus where it was, or move it on',
  { skip },
  async () => {
    const now = Date.now();
    const paused = channelBody('env-webhook', {
      state: 'paused',
      pausedReason: 'The webhook answered 401 (sign-in required).',
      pausedSince: now - 60000,
      lastAttempt: now - 60000,
      counts: { paused: 2, failed: 2 },
    });
    useStatus(
      notificationStatus({
        channels: [channelBody('email', { lastAttempt: now, lastSuccess: now }), paused],
      })
    );
    const plex = deliveryBody({ updatedAt: now - 1000 }),
      sonarr = deliveryBody({
        alert: { service: 'sonarr', name: 'Sonarr' },
        kind: 'resolved',
        updatedAt: now - 2000,
      }),
      radarr = deliveryBody({
        alert: { service: 'radarr', name: 'Radarr' },
        updatedAt: now - 3000,
      });
    let rows = [plex, sonarr, radarr];
    mock.deliveries = () => ({ body: { deliveries: rows, nextCursor: null, unsaved: 0 } });
    const retried = [];
    for (const delivery of [plex, sonarr, radarr])
      mock.routes.set(`POST /api/notifications/deliveries/${delivery.uid}/retry`, request => {
        retried.push(request);
        // Plex can be retried again at once (it is waiting to retry); Sonarr and Radarr cannot.
        rows = rows.map(d =>
          d.uid !== delivery.uid
            ? d
            : delivery === plex
              ? { ...d, status: 'retrying', state: 'queued', nextAttemptAt: Date.now() }
              : { ...d, status: 'waiting', state: 'queued', retryable: false, attempts: 0 }
        );
        return { body: { retried: 1, delivery: rows.find(d => d.uid === delivery.uid) } };
      });
    const page = await openNotifications();
    const retry = (list, uid) => `#${list} [data-id="${uid}"] [data-retry-delivery]`;
    assert.equal(
      await page.eval(
        `document.querySelector(${js(retry('history-list', plex.uid))}).getAttribute('aria-label')`
      ),
      'Retry the Plex alert on Webhook'
    );
    assert.equal(
      await page.eval(
        `document.querySelector(${js(retry('history-list', sonarr.uid))}).getAttribute('aria-label')`
      ),
      'Retry the Sonarr recovery on Webhook'
    );
    // All failed after the channel's last success: all need attention.
    assert.equal(
      await page.eval("document.querySelectorAll('#attention-list .delivery').length"),
      3
    );

    // Retry by keyboard: one request, the result in the status region, the focus kept.
    await page.eval(`document.querySelector(${js(retry('history-list', plex.uid))}).focus()`);
    await pressKey(page, 'Enter');
    await page.waitFor("document.querySelector('#notifications-result').hidden === false");
    await page.settle();
    assert.equal(retried.length, 1);
    assert.equal(retried[0].body, '{}');
    assert.equal(
      await text(page, '#notifications-result'),
      'Uptime Goblin sends this notification again now.'
    );
    assert.equal(
      await page.eval("document.querySelector('#notifications-result').getAttribute('role')"),
      'status'
    );
    assert.equal(await focused(page), 'Retry the Plex alert on Webhook');
    assert.equal(await page.eval('document.activeElement.closest("ul").id'), 'history-list');
    assert.match(
      await text(page, `#history-list [data-id="${plex.uid}"] .delivery-status`),
      /^Waiting to retry$/
    );
    // A double click still sends one request: the button waits for the answer.
    await page.eval(`(() => {
      const b = document.querySelector(${js(retry('history-list', plex.uid))});
      b.click();
      b.click();
    })()`);
    while (retried.length < 2) await delay(10);
    await page.settle();
    assert.equal(retried.length, 2);

    // A Retry that goes after its request: the focus moves to its row, which has no other
    // control, in the same list.
    await page.eval(`document.querySelector(${js(retry('history-list', sonarr.uid))}).focus()`);
    await pressKey(page, ' ');
    while (retried.length < 3) await delay(10);
    await page.waitFor(
      `!document.querySelector(${js(retry('history-list', sonarr.uid))}) && document.activeElement !== document.body`
    );
    await page.settle();
    assert.equal(await page.eval('document.activeElement.dataset.id'), sonarr.uid);
    assert.equal(await page.eval('document.activeElement.closest("ul")?.id'), 'history-list');
    // It waits for its first attempt now, so it no longer needs attention.
    assert.equal(
      await page.eval(`!!document.querySelector('#attention-list [data-id="${sonarr.uid}"]')`),
      false
    );
    // A row that leaves Needs attention with its Retry: the focus goes to the list's heading.
    await page.eval(`document.querySelector(${js(retry('attention-list', radarr.uid))}).focus()`);
    await pressKey(page, 'Enter');
    while (retried.length < 4) await delay(10);
    await page.waitFor(
      `!document.querySelector('#attention-list [data-id="${radarr.uid}"]') && document.activeElement !== document.body`
    );
    await page.settle();
    assert.equal(await focused(page), '#attention-title');

    // A refusal is said, as Uptime Goblin words it.
    mock.routes.set(`POST /api/notifications/deliveries/${plex.uid}/retry`, () =>
      deliveryError('delivery_outdated')
    );
    await page.eval(`document.querySelector(${js(retry('history-list', plex.uid))}).click()`);
    await page.waitFor(
      "document.querySelector('#notifications-result').textContent.startsWith('A later notification')"
    );
    assert.equal(
      await page.eval(
        "document.querySelector('#notifications-result').classList.contains('failed')"
      ),
      true
    );

    // Resume by keyboard: one request; Resume then goes, and the focus moves to the next
    // control of the Webhook card.
    const resumed = [];
    mock.routes.set('POST /api/notifications/channels/env-webhook/resume', request => {
      resumed.push(request);
      useStatus(
        notificationStatus({
          channels: [
            channelBody('email', { lastAttempt: now, lastSuccess: now }),
            channelBody('env-webhook', { lastAttempt: Date.now(), counts: { sending: 1 } }),
          ],
        })
      );
      return {
        body: { released: 2, channel: mock.status().body.channels[1] },
      };
    });
    await page.eval('document.querySelector(\'[data-resume-channel="env-webhook"]\').focus()');
    await pressKey(page, 'Enter');
    await page.waitFor("!document.querySelector('[data-resume-channel]')");
    await page.settle();
    assert.equal(resumed.length, 1);
    assert.equal(
      await text(page, '#notifications-result'),
      'Webhook notifications resumed: 2 held notifications are sent now.'
    );
    assert.equal(await page.eval('document.activeElement.textContent'), 'Show public key');
    // The banners were read again with the action, not 15 s later.
    assert.ok(requests('GET', '/api/dashboard').length >= 2);
    assert.deepEqual(await cspViolations(page), []);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'Retry of a notification that may have arrived asks first, with Cancel focused; Cancel and Escape send nothing',
  { skip },
  async () => {
    const now = Date.now();
    useStatus(
      notificationStatus({
        channels: [
          channelBody('email', { lastAttempt: now }),
          channelBody('env-webhook', { lastAttempt: now, counts: { failed: 1 } }),
        ],
      })
    );
    const maybe = deliveryBody({
      status: 'unconfirmed',
      lastStatus: null,
      lastError: 'No answer within 8 seconds.',
      updatedAt: now,
    });
    mock.deliveries = () => ({ body: { deliveries: [maybe], nextCursor: null, unsaved: 0 } });
    const retried = [];
    mock.routes.set(`POST /api/notifications/deliveries/${maybe.uid}/retry`, request => {
      retried.push(request);
      return { body: { retried: 1, delivery: maybe } };
    });
    const page = await openNotifications();
    assert.equal(
      await text(page, `#history-list [data-id="${maybe.uid}"] .delivery-status`),
      'May have arrived; Uptime Goblin could not confirm it.'
    );
    const button = `#history-list [data-id="${maybe.uid}"] [data-retry-delivery]`;
    const ask = async how => {
      await page.eval(`document.querySelector(${js(button)}).focus()`);
      await pressKey(page, 'Enter');
      await page.waitFor(isOpen('delivery-confirm-dialog'));
      await settled(page, 'delivery-confirm-dialog');
      assert.equal(await focused(page), '#delivery-confirm-cancel');
      assert.equal(
        await text(page, '#delivery-confirm-text'),
        'This notification may already have arrived. Send it again?'
      );
      await pressKey(page, how);
      await page.waitFor(`!${isOpen('delivery-confirm-dialog')}`);
      await page.settle();
    };
    await ask('Enter'); // Enter on the focused Cancel
    assert.equal(retried.length, 0);
    assert.equal(await focused(page), 'Retry the Plex alert on Webhook');
    await ask('Escape');
    assert.equal(retried.length, 0);
    assert.equal(await focused(page), 'Retry the Plex alert on Webhook');
    // Send again: one request, and the focus back on Retry once it is answered.
    await page.eval(`document.querySelector(${js(button)}).focus()`);
    await pressKey(page, 'Enter');
    await page.waitFor(isOpen('delivery-confirm-dialog'));
    await settled(page, 'delivery-confirm-dialog');
    await page.eval("document.querySelector('#delivery-confirm-accept').focus()");
    await pressKey(page, 'Enter');
    while (!retried.length) await delay(10);
    await page.waitFor("document.querySelector('#notifications-result').hidden === false");
    await page.settle();
    assert.equal(retried.length, 1);
    assert.equal(await focused(page), 'Retry the Plex alert on Webhook');
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'the history follows its filters and Load more, lists unsaved rows first, and Needs attention keeps what failed since the last success',
  { skip },
  async () => {
    const now = Date.now();
    useStatus(
      notificationStatus({
        saving: false,
        unsavedSince: now - 60000,
        channels: [
          channelBody('email', {
            lastAttempt: now,
            lastSuccess: now - 7200000,
            failedSince: now - 7200000,
            counts: { failed: 1, retrying: 1 },
          }),
          channelBody('env-webhook', {
            state: 'paused',
            pausedReason: 'The webhook answered 403 (forbidden).',
            failedSince: now - 600000,
            counts: { paused: 1, failed: 1 },
          }),
        ],
      })
    );
    const memory = [
      deliveryBody({
        status: 'retrying',
        state: 'queued',
        saved: false,
        nextAttemptAt: now + 30000,
      }),
      deliveryBody({
        status: 'waiting',
        state: 'queued',
        saved: false,
        attempts: 0,
        retryable: false,
      }),
    ];
    const first = Array.from({ length: 48 }, (_, i) =>
      deliveryBody({
        alert: { name: `Source ${i}` },
        status: 'delivered',
        state: 'delivered',
        retryable: false,
        lastStatus: 200,
        lastError: null,
        sentAt: now - i * 1000,
      })
    );
    const second = [
      deliveryBody({
        alert: { name: 'Proxmox' },
        channel: 'email',
        status: 'delivered',
        state: 'delivered',
        batch: 'g_abcdefghijklmnopqrstuvwxyz',
        retryable: false,
        lastStatus: 250,
        lastError: null,
      }),
      deliveryBody({
        alert: { name: 'Deleted source' },
        status: 'not-sent',
        state: 'cancelled',
        retryable: false,
        lastStatus: null,
        lastError: 'Not sent: the source was deleted.',
      }),
    ];
    // Problems: one retrying, one held, a failure after each channel's failedSince and one
    // before it (it no longer counts for attention).
    const problems = [
      deliveryBody({
        channel: 'email',
        status: 'retrying',
        state: 'queued',
        updatedAt: now - 5000,
      }),
      deliveryBody({ status: 'paused', state: 'held', retryable: false, updatedAt: now - 4000 }),
      deliveryBody({ alert: { name: 'Recent' }, updatedAt: now - 3000 }),
      deliveryBody({ alert: { name: 'Old' }, updatedAt: now - 3600000 }),
    ];
    mock.deliveries = url => {
      const q = url.searchParams;
      if (q.get('filter') === 'problems' && q.get('limit') === '100')
        return { body: { deliveries: problems, nextCursor: null, unsaved: 0 } };
      if (q.get('cursor') === '120')
        return { body: { deliveries: second, nextCursor: null, unsaved: 2 } };
      return { body: { deliveries: [...memory, ...first], nextCursor: '120', unsaved: 2 } };
    };
    const page = await openNotifications();
    // Needs attention: retrying, held and the recent failure; not the old one.
    assert.deepEqual(await allText(page, '#attention-list .delivery-head strong'), [
      'Plex',
      'Plex',
      'Recent',
    ]);
    // The first page: the rows kept in memory first, said to be unsaved.
    assert.equal(
      await page.eval("document.querySelectorAll('#history-list .delivery').length"),
      50
    );
    assert.match(
      await text(page, `#history-list [data-id="${memory[0].uid}"]`),
      /Not saved \(kept in memory\)/
    );
    assert.equal(
      await text(page, '#history-unsaved'),
      '2 notifications are kept in memory only, because Uptime Goblin cannot write its control database. They are listed first.'
    );
    const listQuery = () =>
      requests('GET', '/api/notifications/deliveries')
        .map(r => r.url.searchParams)
        .filter(q => q.get('limit') === '50')
        .at(-1);
    assert.equal(listQuery().get('filter'), 'all');
    assert.equal(listQuery().get('cursor'), null);
    // Load more, by keyboard: the cursor is followed; the last page has no Load more, and the
    // focus moves to the first row it added.
    await page.eval("document.querySelector('#history-more').focus()");
    await pressKey(page, 'Enter');
    await page.waitFor("document.querySelectorAll('#history-list .delivery').length === 52");
    await page.settle();
    assert.equal(listQuery().get('cursor'), '120');
    assert.equal(await page.eval("document.querySelector('#history-more').hidden"), true);
    assert.equal(await page.eval('document.activeElement.dataset.id'), second[0].uid);
    const batch = await text(page, `#history-list [data-id="${second[0].uid}"]`);
    assert.match(batch, /Sent as one email with others/);
    assert.match(batch, /Last answerSMTP 250/);
    assert.match(
      await text(page, `#history-list [data-id="${second[1].uid}"]`),
      /Not sent.*ReasonNot sent: the source was deleted\./
    );
    // The filters ask Uptime Goblin for what they show.
    await page.setValue('#history-filter', 'problems');
    await page.settle();
    assert.equal(listQuery().get('filter'), 'problems');
    await page.setValue('#history-channel', 'email');
    await page.settle();
    assert.equal(listQuery().get('channel'), 'email');
    assert.equal(listQuery().get('filter'), 'problems');
    assert.deepEqual(await allText(page, '#history-filter option'), [
      'All',
      'Waiting and retrying',
      'Problems',
      'Delivered',
    ]);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'rows still in memory once Uptime Goblin saves again are not said to be unsaved because it cannot write',
  { skip },
  async () => {
    const now = Date.now();
    // Saving again: one row queued while Uptime Goblin could not write is still in progress in memory.
    useStatus(
      notificationStatus({
        saving: true,
        channels: [
          channelBody('email'),
          channelBody('env-webhook', { lastAttempt: now, counts: { retrying: 1 } }),
        ],
      })
    );
    const kept = deliveryBody({
      status: 'retrying',
      state: 'queued',
      saved: false,
      nextAttemptAt: now + 30000,
    });
    mock.deliveries = () => ({ body: { deliveries: [kept], nextCursor: null, unsaved: 1 } });
    const page = await openNotifications();
    assert.equal(
      await text(page, '#history-unsaved'),
      '1 notification is still kept in memory: it was queued while Uptime Goblin could not write its control database, and is saved once finished. It is listed first.'
    );
    // The status now says Uptime Goblin cannot write: the note says so too, without a new history read.
    useStatus(notificationStatus({ saving: false, unsavedSince: now - 60000 }));
    await refreshPage(page);
    assert.equal(
      await text(page, '#history-unsaved'),
      '1 notification is kept in memory only, because Uptime Goblin cannot write its control database. It is listed first.'
    );
    // Nothing kept in memory: no note.
    useStatus(notificationStatus({ saving: true }));
    mock.deliveries = () => ({ body: { deliveries: [], nextCursor: null, unsaved: 0 } });
    await refreshPage(page);
    await page.waitFor("document.querySelector('#history-unsaved').hidden === true");
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'A59: an email of several notifications is "Sent as one email" only once it went out; before then, or never accepted, it is "Grouped into one email"',
  { skip },
  async () => {
    const now = Date.now();
    const email = channelBody('email', {
      lastAttempt: now,
      counts: { retrying: 1, paused: 1, failed: 1 },
    });
    useStatus(notificationStatus({ channels: [email, channelBody('env-webhook')] }));
    const batch = 'g_abcdefghijklmnopqrstuvwxyz';
    const row = (status, state, extra = {}) =>
      deliveryBody({
        channel: 'email',
        status,
        state,
        batch,
        lastStatus: null,
        lastError: 'Email sign-in failed. Check the sender address and Gmail app password.',
        updatedAt: now - 1000,
        ...extra,
      });
    const rows = {
      waiting: row('waiting', 'queued', { attempts: 0, lastError: null, retryable: false }),
      retrying: row('retrying', 'queued', { attempts: 1, nextAttemptAt: now + 60000 }),
      sending: row('sending', 'sending', { retryable: false }),
      paused: row('paused', 'held', { retryable: false }),
      failed: row('failed', 'dead'),
      expired: row('expired', 'dead'),
      delivered: row('delivered', 'delivered', {
        lastStatus: 250,
        lastError: null,
        sentAt: now - 2000,
        retryable: false,
      }),
      unconfirmed: row('unconfirmed', 'dead', { lastError: 'The mail server did not confirm it.' }),
      alone: deliveryBody({ channel: 'email', status: 'failed', state: 'dead', batch: null }),
    };
    mock.deliveries = () => ({
      body: { deliveries: Object.values(rows), nextCursor: null, unsaved: 0 },
    });
    const page = await openNotifications();
    const notes = async (list, uid) =>
      page.eval(
        `document.querySelector('#${list}-list [data-id="${uid}"] .delivery-notes')?.textContent ?? null`
      );
    const sent = 'Sent as one email with others',
      grouped = 'Grouped into one email with others';
    const expected = {
      waiting: grouped,
      retrying: grouped,
      sending: grouped,
      paused: grouped,
      failed: grouped,
      expired: grouped,
      delivered: sent,
      unconfirmed: sent,
      alone: null,
    };
    for (const [name, note] of Object.entries(expected))
      assert.equal(await notes('history', rows[name].uid), note, name);
    // Needs attention (the held and failed rows, and the one waiting to retry) says the same.
    for (const name of ['retrying', 'paused', 'failed'])
      assert.equal(await notes('attention', rows[name].uid), grouped, name);
    assert.match(
      await text(page, `#attention-list [data-id="${rows.paused.uid}"]`),
      /Held: the channel is paused.*Grouped into one email with others/
    );
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'Needs attention reads past a page of failures from before the last success to what still needs it, at most 5 pages, then says what it did not check',
  { skip },
  async () => {
    const now = Date.now();
    useStatus(
      notificationStatus({
        channels: [
          channelBody('email', { lastAttempt: now, counts: { retrying: 1 } }),
          channelBody('env-webhook', {
            lastAttempt: now,
            lastSuccess: now - 600000,
            failedSince: now - 600000,
          }),
        ],
      })
    );
    // 100 webhook failures from before its last success (they no longer need attention), all
    // newer than an email that still waits to retry.
    const old = () =>
      Array.from({ length: 100 }, (_, i) =>
        deliveryBody({ alert: { name: `Old ${i}` }, updatedAt: now - 3600000 - i })
      );
    const retrying = (name, channel = 'email') =>
      deliveryBody({
        alert: { name },
        channel,
        status: 'retrying',
        state: 'queued',
        nextAttemptAt: now + 60000,
        updatedAt: now - 5000,
      });
    const proxmox = retrying('Proxmox');
    mock.deliveries = url => {
      const q = url.searchParams;
      if (q.get('filter') !== 'problems')
        return { body: { deliveries: [], nextCursor: null, unsaved: 0 } };
      return q.get('cursor') === '900'
        ? { body: { deliveries: [proxmox], nextCursor: null, unsaved: 0 } }
        : { body: { deliveries: old(), nextCursor: '900', unsaved: 0 } };
    };
    const reads = () =>
      requests('GET', '/api/notifications/deliveries')
        .map(r => r.url.searchParams)
        .filter(q => q.get('filter') === 'problems' && q.get('limit') === '100');
    const page = await openNotifications();
    assert.deepEqual(await allText(page, '#attention-list .delivery-head strong'), ['Proxmox']);
    assert.equal(
      await page.eval(
        "document.querySelector('#attention-list [data-retry-delivery]').getAttribute('aria-label')"
      ),
      'Retry the Proxmox alert on Email'
    );
    assert.deepEqual(
      reads().map(q => q.get('cursor')),
      [null, '900']
    );

    // Older failures without end: 5 pages are read, then the list says what it did not check
    // instead of "Nothing needs attention."
    let cursor = 1000;
    mock.deliveries = url =>
      url.searchParams.get('filter') === 'problems'
        ? { body: { deliveries: old(), nextCursor: String((cursor -= 100)), unsaved: 0 } }
        : { body: { deliveries: [], nextCursor: null, unsaved: 0 } };
    const before = reads().length;
    await refreshPage(page);
    assert.equal(reads().length - before, 5);
    assert.equal(
      await text(page, '#attention-list'),
      'None of the newest 500 notifications with problems needs attention. Older notifications were not checked: choose Problems under Delivery history to see them all.'
    );
    // Some found within the 5 pages: they are listed, and the same note follows them.
    mock.deliveries = url =>
      url.searchParams.get('filter') === 'problems'
        ? {
            body: {
              deliveries: [...old().slice(1), retrying(`Source ${cursor}`, 'env-webhook')],
              nextCursor: String((cursor -= 100)),
              unsaved: 0,
            },
          }
        : { body: { deliveries: [], nextCursor: null, unsaved: 0 } };
    await refreshPage(page);
    assert.equal(
      await page.eval("document.querySelectorAll('#attention-list .delivery').length"),
      5
    );
    assert.equal(
      await text(page, '#attention-list .delivery-empty'),
      'Older notifications were not checked: choose Problems under Delivery history to see them all.'
    );
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'a Load more that fails says so beside the button, and keeps the rows shown, the focus and the way to try again',
  { skip },
  async () => {
    const now = Date.now();
    useStatus(
      notificationStatus({
        channels: [
          channelBody('email'),
          channelBody('env-webhook', { lastAttempt: now, lastSuccess: now, deliveredTotal: 100 }),
        ],
      })
    );
    const delivered = from =>
      Array.from({ length: 50 }, (_, i) =>
        deliveryBody({
          alert: { name: `Source ${from + i}` },
          status: 'delivered',
          state: 'delivered',
          retryable: false,
          lastStatus: 200,
          lastError: null,
        })
      );
    const first = delivered(0),
      second = delivered(50);
    let older = () => ({ drop: true });
    mock.deliveries = url =>
      url.searchParams.get('cursor')
        ? older(url)
        : { body: { deliveries: first, nextCursor: '100', unsaved: 0 } };
    const page = await openNotifications();
    const result = '#history-more-result';
    const rows = () => page.eval("document.querySelectorAll('#history-list .delivery').length");
    const moreUsable = () =>
      page.eval(
        "(b => !b.hidden && !b.disabled && document.activeElement === b)(document.querySelector('#history-more'))"
      );
    assert.equal(
      await page.eval(`document.querySelector(${js(result)}).getAttribute('role')`),
      'status'
    );
    assert.equal(await page.eval(`document.querySelector(${js(result)}).hidden`), true);

    // Uptime Goblin does not answer: the older rows were not read, and the page says so.
    await page.eval("document.querySelector('#history-more').focus()");
    await pressKey(page, 'Enter');
    await page.waitFor(`document.querySelector(${js(result)}).hidden === false`);
    await page.settle();
    assert.equal(
      await text(page, result),
      'Delivery status is unavailable: Uptime Goblin is not answering. Older notifications were not read: press Load more to try again.'
    );
    assert.equal(await rows(), 50);
    assert.equal(await moreUsable(), true);
    // Uptime Goblin cannot read its control database (503): its reason.
    older = () => deliveryError('delivery_status_unavailable');
    await pressKey(page, 'Enter');
    await page.waitFor(
      `document.querySelector(${js(result)}).textContent.startsWith('Delivery status is unavailable: Uptime Goblin could not read')`
    );
    await page.settle();
    assert.equal(
      await text(page, result),
      'Delivery status is unavailable: Uptime Goblin could not read its control database. Older notifications were not read: press Load more to try again.'
    );
    assert.equal(await rows(), 50);
    assert.equal(await moreUsable(), true);
    // It works again: the older rows come, and the note goes.
    older = () => ({ body: { deliveries: second, nextCursor: null, unsaved: 0 } });
    await pressKey(page, 'Enter');
    await page.waitFor("document.querySelectorAll('#history-list .delivery').length === 100");
    await page.settle();
    assert.equal(await page.eval(`document.querySelector(${js(result)}).hidden`), true);
    assert.equal(await text(page, result), '');
    assert.equal(await page.eval('document.activeElement.dataset.id'), second[0].uid);
    // Each try asked for the page after the rows shown: a failure kept the cursor. (Chrome may
    // send a GET again itself when the connection is dropped, so the count is not fixed.)
    const cursors = requests('GET', '/api/notifications/deliveries')
      .map(r => r.url.searchParams.get('cursor'))
      .filter(Boolean);
    assert.ok(cursors.length >= 3, String(cursors));
    assert.deepEqual(new Set(cursors), new Set(['100']));
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'Try again in Needs attention and in Delivery history moves the focus to the first row once the read works, never to the page',
  { skip },
  async () => {
    const now = Date.now();
    const retrying = channelBody('env-webhook', {
      state: 'retrying',
      lastAttempt: now,
      nextAttemptAt: now + 60000,
      counts: { retrying: 1 },
    });
    const status = notificationStatus({ channels: [channelBody('email'), retrying] });
    const plex = deliveryBody({
      status: 'retrying',
      state: 'queued',
      attempts: 1,
      nextAttemptAt: now + 60000,
      updatedAt: now,
    });
    // Uptime Goblin cannot read its control database: the status and both lists say so, each list
    // with Try again.
    let failing = true;
    mock.status = () => (failing ? deliveryError('delivery_status_unavailable') : { body: status });
    mock.dashboard.notifications = dashboardNotifications(status);
    mock.deliveries = () =>
      failing
        ? deliveryError('delivery_status_unavailable')
        : { body: { deliveries: [plex], nextCursor: null, unsaved: 0 } };
    const page = await openNotifications();
    const tryAgain = list => `#${list} [data-reload-notifications]`;
    for (const list of ['attention-list', 'history-list'])
      assert.match(
        await text(page, `#${list}`),
        /^Delivery status is unavailable: Uptime Goblin could not read its control database\. Try again$/
      );
    const focusedIs = selector =>
      page.eval(`document.activeElement === document.querySelector(${js(selector)})`);
    // Pressed while the reads still fail: the same message, and the focus stays on Try again.
    await page.eval(`document.querySelector(${js(tryAgain('attention-list'))}).focus()`);
    const reads = statusRequests().length;
    await pressKey(page, 'Enter');
    while (statusRequests().length === reads) await delay(10);
    await page.settle();
    assert.equal(await focusedIs(tryAgain('attention-list')), true);
    // The reads work again: Try again goes with the message, and the focus moves to the first
    // row of its list, never to <body>.
    failing = false;
    await pressKey(page, 'Enter');
    await page.waitFor(`!!document.querySelector('#attention-list > li.delivery')`);
    await page.settle();
    assert.equal(await page.eval('document.activeElement.dataset.id'), plex.uid);
    assert.equal(await focusedIs('#attention-list > li.delivery'), true);
    // The same in Delivery history.
    failing = true;
    await refreshPage(page);
    await page.eval(`document.querySelector(${js(tryAgain('history-list'))}).focus()`);
    failing = false;
    await pressKey(page, 'Enter');
    await page.waitFor(`!!document.querySelector('#history-list > li.delivery')`);
    await page.settle();
    assert.equal(await focusedIs('#history-list > li.delivery'), true);
    // A list that has no row once the read works (nothing needs attention) gives the focus to
    // its heading.
    failing = true;
    await refreshPage(page);
    await page.eval(`document.querySelector(${js(tryAgain('attention-list'))}).focus()`);
    failing = false;
    mock.deliveries = () => ({ body: { deliveries: [], nextCursor: null, unsaved: 0 } });
    await pressKey(page, 'Enter');
    await page.waitFor(
      "document.querySelector('#attention-list').textContent === 'Nothing needs attention.'"
    );
    await page.settle();
    assert.equal(await focused(page), '#attention-title');
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'a channel that is not set up needs no attention: the summary and Needs attention leave its notifications out, and offer no Retry',
  { skip },
  async () => {
    const now = Date.now();
    // GOBLIN_WEBHOOK_URL was removed at a restart: the webhook still holds a row waiting to
    // retry and a failed one, which it skips when it comes to send them.
    const removed = channelBody('env-webhook', {
      configured: false,
      enabled: false,
      state: 'not-configured',
      host: null,
      lastAttempt: now - 600000,
      lastFailure: now - 600000,
      failedSince: now - 86400000,
      counts: { retrying: 1, failed: 1 },
    });
    const status = notificationStatus({
      channels: [
        channelBody('email', { lastAttempt: now, lastSuccess: now, deliveredTotal: 3 }),
        removed,
      ],
      signing: null,
    });
    useStatus(status);
    const retrying = deliveryBody({
        status: 'retrying',
        state: 'queued',
        attempts: 1,
        nextAttemptAt: now + 600000,
        updatedAt: now - 600000,
        retryable: false,
      }),
      failed = deliveryBody({
        alert: { service: 'nas', name: 'NAS' },
        updatedAt: now - 600000,
        retryable: false,
      });
    mock.deliveries = () => ({
      body: { deliveries: [retrying, failed], nextCursor: null, unsaved: 0 },
    });
    const page = await openNotifications();
    assert.equal(await text(page, '#notifications-summary'), 'All notifications were delivered.');
    assert.equal(await text(page, '#attention-list'), 'Nothing needs attention.');
    assert.equal(
      await page.eval("document.querySelectorAll('#history-list > li.delivery').length"),
      2
    );
    assert.equal(await page.eval("document.querySelectorAll('[data-retry-delivery]').length"), 0);
    assert.match(await text(page, '[data-id="env-webhook"] .channel-state'), /^Not set up$/);
    // The dashboard's banner agrees: nothing needs attention.
    await page.eval("location.hash = ''");
    await page.poll();
    await page.settle();
    assert.equal(await page.eval("document.querySelector('#notice').hidden"), true);
    // The same rows on a channel that is set up do need attention.
    useStatus(
      notificationStatus({
        channels: [
          channelBody('email', { lastAttempt: now, lastSuccess: now, deliveredTotal: 3 }),
          channelBody('env-webhook', {
            state: 'retrying',
            lastAttempt: now - 600000,
            lastFailure: now - 600000,
            failedSince: now - 86400000,
            counts: { retrying: 1, failed: 1 },
          }),
        ],
      })
    );
    const again = await openNotifications();
    assert.equal(await text(again, '#notifications-summary'), '1 notification failed.');
    assert.equal(
      await again.eval("document.querySelectorAll('#attention-list > li.delivery').length"),
      2
    );
    assert.deepEqual(page.exceptions, []);
    assert.deepEqual(again.exceptions, []);
  }
);

test(
  'a Load more that adds nothing moves the focus to the last row, never to the page',
  { skip },
  async () => {
    const now = Date.now();
    useStatus(
      notificationStatus({
        channels: [
          channelBody('email'),
          channelBody('env-webhook', { lastAttempt: now, lastSuccess: now, deliveredTotal: 50 }),
        ],
      })
    );
    const rows = Array.from({ length: 50 }, (_, i) =>
      deliveryBody({
        alert: { name: `Source ${i}` },
        status: 'delivered',
        state: 'delivered',
        retryable: false,
        lastStatus: 200,
        lastError: null,
      })
    );
    // The older rows went meanwhile (pruned): the next page is empty, and the last.
    mock.deliveries = url =>
      url.searchParams.get('cursor')
        ? { body: { deliveries: [], nextCursor: null, unsaved: 0 } }
        : { body: { deliveries: rows, nextCursor: '50', unsaved: 0 } };
    const page = await openNotifications();
    await page.eval("document.querySelector('#history-more').focus()");
    await pressKey(page, 'Enter');
    await page.waitFor("document.querySelector('#history-more').hidden === true");
    await page.settle();
    assert.equal(
      await page.eval("document.querySelectorAll('#history-list .delivery').length"),
      50
    );
    assert.equal(await page.eval('document.activeElement.dataset.id'), rows.at(-1).uid);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'Retry on a row that Load more brought in keeps every page read, that row and the focus on its Retry',
  { skip },
  async () => {
    const now = Date.now();
    useStatus(
      notificationStatus({
        channels: [
          channelBody('email'),
          channelBody('env-webhook', { lastAttempt: now, counts: { failed: 50 } }),
        ],
      })
    );
    const delivered = name =>
      deliveryBody({
        alert: { name },
        status: 'delivered',
        state: 'delivered',
        retryable: false,
        lastStatus: 200,
        lastError: null,
      });
    // 200 rows with ids 1000 down to 801, newest first; those of the third page failed.
    let rows = Array.from({ length: 200 }, (_, i) => ({
      id: 1000 - i,
      body:
        i >= 100 && i < 150
          ? deliveryBody({ alert: { name: `Flood ${200 - i}` } })
          : delivered(`Flood ${200 - i}`),
    }));
    mock.deliveries = url => {
      const q = url.searchParams,
        limit = Number(q.get('limit')),
        cursor = q.get('cursor');
      if (q.get('filter') !== 'all')
        return { body: { deliveries: [], nextCursor: null, unsaved: 0 } };
      const older = rows.filter(row => cursor === null || row.id < Number(cursor)),
        shown = older.slice(0, limit);
      return {
        body: {
          deliveries: shown.map(row => row.body),
          nextCursor: older.length > limit ? String(shown.at(-1).id) : null,
          unsaved: 0,
        },
      };
    };
    // Retry waits to retry again, and a new alert arrives meanwhile, pushing every row down.
    const target = rows[120].body;
    let retried = 0;
    mock.routes.set(`POST /api/notifications/deliveries/${target.uid}/retry`, () => {
      retried++;
      rows = [
        { id: 1001, body: delivered('Newcomer') },
        ...rows.map(row =>
          row.body.uid === target.uid
            ? {
                ...row,
                body: { ...row.body, status: 'retrying', state: 'queued', nextAttemptAt: now },
              }
            : row
        ),
      ];
      return { body: { retried: 1, delivery: rows.find(row => row.body.uid === target.uid).body } };
    });
    const page = await openNotifications();
    const count = () => page.eval("document.querySelectorAll('#history-list .delivery').length");
    // Load more twice, by keyboard: three pages.
    for (const expected of [100, 150]) {
      await page.eval("document.querySelector('#history-more').focus()");
      await pressKey(page, 'Enter');
      await page.waitFor(
        `document.querySelectorAll('#history-list .delivery').length === ${expected}`
      );
      await page.settle();
    }
    const historyReads = () =>
      requests('GET', '/api/notifications/deliveries').filter(
        r => r.url.searchParams.get('filter') === 'all'
      ).length;
    const reads = historyReads();
    const button = `#history-list [data-id="${target.uid}"] [data-retry-delivery]`;
    await page.eval(`document.querySelector(${js(button)}).focus()`);
    await pressKey(page, 'Enter');
    // Done once the history shows the new alert and the focus has been given back.
    await page.waitFor(
      "!document.querySelector('#notifications-result').hidden && document.querySelector('#history-list > li:first-child')?.textContent.includes('Newcomer') && document.activeElement !== document.body"
    );
    await page.settle();
    assert.equal(retried, 1);
    assert.equal(
      await text(page, '#notifications-result'),
      'Uptime Goblin sends this notification again now.'
    );
    // The history is read as deep as it was shown: four pages now, since the new alert pushed
    // the oldest row shown onto the fourth; Load more still leads further.
    assert.equal(historyReads() - reads, 4);
    assert.equal(await count(), 200);
    assert.equal(
      await text(page, '#history-list > li:first-child .delivery-head strong'),
      'Newcomer'
    );
    assert.ok(
      await page.eval(
        `[...document.querySelectorAll('#history-list .delivery-head strong')].some(e => e.textContent === 'Flood 51')`
      ),
      'the oldest row shown before is still shown'
    );
    assert.equal(await page.eval("document.querySelector('#history-more').hidden"), false);
    assert.equal(
      await text(page, `#history-list [data-id="${target.uid}"] .delivery-status`),
      'Waiting to retry'
    );
    // The focus stays on the same Retry.
    assert.equal(await focused(page), 'Retry the Flood 80 alert on Webhook');
    assert.equal(
      await page.eval(`document.activeElement === document.querySelector(${js(button)})`),
      true
    );
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'rows kept in memory past a page are reached with Load more, and the note says which of them a filter lists',
  { skip },
  async () => {
    const now = Date.now();
    useStatus(
      notificationStatus({
        saving: false,
        unsavedSince: now - 60000,
        channels: [
          channelBody('email'),
          channelBody('env-webhook', { lastAttempt: now, counts: { waiting: 41, retrying: 20 } }),
        ],
      })
    );
    // 61 webhook rows in memory (m:61 … m:1; the 20 newest retrying, the rest waiting for a
    // first try), then 30 saved rows that were delivered.
    let memory = Array.from({ length: 61 }, (_, i) => ({
      id: `m:${61 - i}`,
      body: deliveryBody({
        alert: { name: `Kept ${61 - i}` },
        saved: false,
        ...(i < 20
          ? { status: 'retrying', state: 'queued', nextAttemptAt: now + 60000 }
          : {
              status: 'waiting',
              state: 'queued',
              attempts: 0,
              retryable: false,
              lastStatus: null,
              lastError: null,
            }),
      }),
    }));
    const saved = Array.from({ length: 30 }, (_, i) => ({
      id: String(500 - i),
      body: deliveryBody({
        alert: { name: `Saved ${30 - i}` },
        status: 'delivered',
        state: 'delivered',
        retryable: false,
        lastStatus: 200,
        lastError: null,
      }),
    }));
    const filters = {
      all: () => true,
      active: d => ['waiting', 'retrying', 'sending', 'paused'].includes(d.status),
      problems: d => ['retrying', 'paused', 'failed', 'expired', 'unconfirmed'].includes(d.status),
      delivered: d => d.status === 'delivered',
    };
    // As Uptime Goblin pages them (A30): the memory rows first, page by page, then the saved rows
    // filling the page; at most `limit` rows a page.
    mock.deliveries = url => {
      const q = url.searchParams,
        limit = Number(q.get('limit')),
        cursor = q.get('cursor'),
        memoryCursor = cursor?.startsWith('m:') ? Number(cursor.slice(2)) : null;
      const keep = row =>
        filters[q.get('filter') ?? 'all'](row.body) &&
        (!q.get('channel') || row.body.channel === q.get('channel'));
      let shown = [],
        next = null;
      const savedRows = saved.filter(keep);
      if (cursor === null || memoryCursor !== null) {
        const kept = memory
          .filter(keep)
          .filter(row => memoryCursor === null || Number(row.id.slice(2)) < memoryCursor);
        shown = kept.slice(0, limit);
        if (shown.length >= limit && (kept.length > limit || savedRows.length))
          next = shown.at(-1).id;
      }
      if (shown.length < limit) {
        const older = savedRows.filter(
            row => cursor === null || memoryCursor !== null || Number(row.id) < Number(cursor)
          ),
          room = limit - shown.length;
        shown = [...shown, ...older.slice(0, room)];
        if (older.length > room) next = older[room - 1].id;
      }
      return {
        body: { deliveries: shown.map(row => row.body), nextCursor: next, unsaved: memory.length },
      };
    };
    const page = await openNotifications();
    const unsavedShown = () =>
      page.eval(
        "[...document.querySelectorAll('#history-list .delivery')].filter(e => e.textContent.includes('Not saved (kept in memory)')).length"
      );
    const cannotWrite =
      '61 notifications are kept in memory only, because Uptime Goblin cannot write its control database.';
    // All of them: the first 50, then the other 11 with Load more, every one of them reachable.
    assert.equal(await unsavedShown(), 50);
    assert.equal(await text(page, '#history-unsaved'), `${cannotWrite} They are listed first.`);
    await page.eval("document.querySelector('#history-more').focus()");
    await pressKey(page, 'Enter');
    await page.waitFor("document.querySelector('#history-more').hidden === true");
    await page.settle();
    assert.equal(
      requests('GET', '/api/notifications/deliveries')
        .map(r => r.url.searchParams.get('cursor'))
        .at(-1),
      'm:12'
    );
    assert.equal(await unsavedShown(), 61);
    assert.equal(
      await page.eval("document.querySelectorAll('#history-list .delivery').length"),
      91
    );
    assert.equal(await text(page, '#history-unsaved'), `${cannotWrite} They are listed first.`);
    // A filter that none of them matches: the note says so, not that they are listed first.
    await page.setValue('#history-filter', 'delivered');
    await page.waitFor("document.querySelectorAll('#history-list .delivery').length === 30");
    await page.settle();
    assert.equal(
      await text(page, '#history-unsaved'),
      `${cannotWrite} None of them matches these filters.`
    );
    await page.setValue('#history-filter', 'all');
    await page.setValue('#history-channel', 'email');
    await page.waitFor(
      "document.querySelector('#history-list').textContent.includes('No notification matches these filters.')"
    );
    await page.settle();
    assert.equal(
      await text(page, '#history-unsaved'),
      `${cannotWrite} None of them matches these filters.`
    );
    // A filter that some of them match: those are listed first.
    await page.setValue('#history-channel', '');
    await page.setValue('#history-filter', 'problems');
    await page.waitFor("document.querySelectorAll('#history-list .delivery').length === 20");
    await page.settle();
    assert.equal(await unsavedShown(), 20);
    assert.equal(
      await text(page, '#history-unsaved'),
      `${cannotWrite} Those that match these filters are listed first.`
    );
    // One row kept in memory, which the filter leaves out.
    memory = memory.slice(-1);
    await page.setValue('#history-filter', 'delivered');
    await page.waitFor(
      "document.querySelector('#history-unsaved').textContent.startsWith('1 notification')"
    );
    assert.equal(
      await text(page, '#history-unsaved'),
      '1 notification is kept in memory only, because Uptime Goblin cannot write its control database. It does not match these filters.'
    );
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'a poll that adds or removes Resume leaves the focus on the same action, and the public-key dialog gives it back to Show public key',
  { skip },
  async () => {
    const now = Date.now();
    const working = channelBody('env-webhook', {
        lastAttempt: now,
        lastSuccess: now,
        deliveredTotal: 1,
      }),
      paused = channelBody('env-webhook', {
        state: 'paused',
        pausedReason: 'The webhook answered 401 (sign-in required).',
        pausedSince: now,
        lastAttempt: now,
        lastFailure: now,
        counts: { paused: 1 },
      });
    const webhookIs = webhook =>
      useStatus(
        notificationStatus({ channels: [channelBody('email', { lastAttempt: now }), webhook] })
      );
    webhookIs(working);
    const reads = [],
      resumes = [];
    const keys = publicKeyBody({ createdAt: now });
    mock.routes.set('GET /api/notifications/webhook/public-key', request => {
      reads.push(request);
      return { body: keys };
    });
    mock.routes.set('POST /api/notifications/channels/env-webhook/resume', request => {
      resumes.push(request);
      return { body: { released: 0, channel: working } };
    });
    const page = await openNotifications();
    const actions = () => allText(page, '[data-id="env-webhook"] .channel-actions button');
    const focusedAction = () =>
      page.eval(`(e => !e || e === document.body ? 'the page itself' :
        e.textContent + ' | ' + (e.getAttribute('aria-label') || '-'))(document.activeElement)`);
    assert.deepEqual(await actions(), ['Show public key', 'Replace signing key']);
    await page.eval("(window.__show = document.querySelector('[data-public-key]')).focus()");

    // The webhook pauses: Resume comes first in its card. The focus stays on Show public key,
    // the same button, so Enter shows the key and resumes nothing.
    webhookIs(paused);
    await page.poll();
    assert.deepEqual(await actions(), ['Resume', 'Show public key', 'Replace signing key']);
    assert.equal(await focusedAction(), 'Show public key | -');
    assert.equal(await page.eval('document.activeElement === window.__show'), true);
    await pressKey(page, 'Enter');
    await page.waitFor(isOpen('signing-key-dialog'));
    await settled(page, 'signing-key-dialog');
    assert.equal(reads.length, 1);
    assert.equal(resumes.length, 0);

    // It works again while the dialog is open: Resume goes. Escape gives the focus back to Show
    // public key, not to the button now in its place.
    webhookIs(working);
    await page.poll();
    assert.deepEqual(await actions(), ['Show public key', 'Replace signing key']);
    await pressKey(page, 'Escape');
    await page.waitFor(`!${isOpen('signing-key-dialog')}`);
    await page.settle();
    assert.equal(await focusedAction(), 'Show public key | -');

    // The status could not be read while the dialog was open, so the card lost its buttons,
    // then it could again: Close gives the focus to the Show public key the card has now.
    await pressKey(page, 'Enter');
    await page.waitFor(isOpen('signing-key-dialog'));
    await settled(page, 'signing-key-dialog');
    mock.status = () => deliveryError('delivery_status_unavailable');
    await page.poll();
    assert.equal(await page.eval("!!document.querySelector('[data-public-key]')"), false);
    webhookIs(working);
    await page.poll();
    assert.equal(await page.eval('window.__show.isConnected'), false);
    await page.click('#signing-key-close');
    await page.waitFor(`!${isOpen('signing-key-dialog')}`);
    await page.settle();
    assert.equal(await focusedAction(), 'Show public key | -');
    assert.equal(resumes.length, 0);
    assert.deepEqual(await cspViolations(page), []);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'the public-key dialog: a GET, focus, the key id, Copy, Escape and Close, Replace asks first and shows the new key, a refusal is said',
  { skip },
  async () => {
    const now = Date.now();
    useStatus(
      notificationStatus({
        channels: [channelBody('email'), channelBody('env-webhook', { lastAttempt: now })],
      })
    );
    let keys = publicKeyBody({ createdAt: now });
    const first = keys;
    const reads = [],
      rotations = [];
    mock.routes.set('GET /api/notifications/webhook/public-key', request => {
      reads.push(request);
      return { body: keys };
    });
    mock.routes.set('POST /api/notifications/webhook/signing-secret', request => {
      rotations.push(request);
      const previousUntil = Date.now() + 86400000;
      keys = {
        ...publicKeyBody({ createdAt: Date.now() }),
        previousUntil,
        previous: {
          keyId: first.keyId,
          publicKey: first.publicKey,
          publicKeyRaw: first.publicKeyRaw,
        },
      };
      useStatus(
        notificationStatus({
          channels: [channelBody('email'), channelBody('env-webhook', { lastAttempt: now })],
          signing: { configured: true, saved: true, createdAt: Date.now(), previousUntil },
        })
      );
      return { body: { createdAt: Date.now(), previousUntil } };
    });
    const page = await openNotifications();
    const show = '[data-public-key]',
      replace = '[data-rotate-key]';
    const field = () => page.eval("document.querySelector('#signing-key-value').value");
    const openKey = async () => {
      await page.eval(`document.querySelector(${js(show)}).focus()`);
      await pressKey(page, 'Enter');
      await page.waitFor(isOpen('signing-key-dialog'));
      await settled(page, 'signing-key-dialog');
    };
    await openKey();
    assert.equal(reads.length, 1);
    assert.equal(reads[0].method, 'GET');
    assert.equal(await focused(page), '#signing-key-value');
    // The PEM whole, its line breaks kept (a textarea), and the key id beside it.
    assert.equal(await field(), first.publicKey);
    assert.match(
      (await text(page, '#signing-key-text')).replace(/\s+/g, ' '),
      /Receivers verify X-Goblin-Signature with this Ed25519 public key \(see Help → Alerts and notifications\)\. It is not a secret\./
    );
    assert.equal(
      await text(page, '#signing-key-id'),
      `Key id ${first.keyId} (X-Goblin-Signature names it in each v1a).`
    );
    assert.equal(await page.eval("document.querySelector('#signing-key-previous').hidden"), true);
    // Copy, with the Clipboard API.
    await page.eval(`Object.defineProperty(navigator.clipboard, 'writeText', {
      configurable: true, value: async text => { window.__copied = text; } })`);
    await page.click('#signing-key-copy');
    await page.waitFor(
      "document.querySelector('#signing-key-copy-result').textContent === 'Copied.'"
    );
    assert.equal(await page.eval('window.__copied'), first.publicKey);
    // Escape closes it, gives the focus back to Show public key, and empties the dialog.
    await pressKey(page, 'Escape');
    await page.waitFor(`!${isOpen('signing-key-dialog')}`);
    await page.settle();
    assert.equal(await page.eval('document.activeElement.textContent'), 'Show public key');
    assert.equal(await field(), '');
    // Close does the same.
    await openKey();
    assert.equal(reads.length, 2);
    await page.click('#signing-key-close');
    await page.waitFor(`!${isOpen('signing-key-dialog')}`);
    await page.settle();
    assert.equal(await page.eval('document.activeElement.textContent'), 'Show public key');
    assert.equal(await field(), '');
    // The page never asks for the reveal of the pre-release builds.
    assert.ok(mock.requests.every(r => !r.url.pathname.endsWith('/signing-secret/reveal')));

    // Replace asks first; Escape replaces nothing.
    await page.eval(`document.querySelector(${js(replace)}).focus()`);
    await pressKey(page, 'Enter');
    await page.waitFor(isOpen('delivery-confirm-dialog'));
    await settled(page, 'delivery-confirm-dialog');
    assert.equal(await focused(page), '#delivery-confirm-cancel');
    assert.match(
      await text(page, '#delivery-confirm-text'),
      /^Receivers that check signatures need the new public key within 24 hours/
    );
    assert.equal(await text(page, '#delivery-confirm-accept'), 'Replace signing key');
    await pressKey(page, 'Escape');
    await page.waitFor(`!${isOpen('delivery-confirm-dialog')}`);
    await page.settle();
    assert.equal(rotations.length, 0);
    assert.equal(await page.eval('document.activeElement.textContent'), 'Replace signing key');
    // Replace it: one rotation, then the new public key is shown, with the old one's overlap.
    await pressKey(page, 'Enter');
    await page.waitFor(isOpen('delivery-confirm-dialog'));
    await settled(page, 'delivery-confirm-dialog');
    await page.click('#delivery-confirm-accept');
    await page.waitFor(isOpen('signing-key-dialog'));
    await settled(page, 'signing-key-dialog');
    assert.equal(rotations.length, 1);
    assert.equal(await field(), keys.publicKey);
    assert.notEqual(keys.publicKey, first.publicKey);
    assert.match(
      await text(page, '#signing-key-previous'),
      new RegExp(`^The previous key \\(key id ${first.keyId}\\) also signs until .+\\.$`)
    );
    await pressKey(page, 'Escape');
    await page.waitFor(`!${isOpen('signing-key-dialog')}`);
    await page.settle();
    assert.equal(await page.eval('document.activeElement.textContent'), 'Replace signing key');
    assert.match(
      await text(page, '#notifications-result'),
      /^Uptime Goblin replaced the signing key\. The previous one also signs until .+\.$/
    );
    assert.match(
      await text(page, '[data-id="env-webhook"] .channel-signing'),
      /The previous key also signs until/
    );

    // A refusal (the key cannot be read) is said in the status region, and no dialog opens.
    mock.routes.set('GET /api/notifications/webhook/public-key', () =>
      deliveryError('signing_unavailable')
    );
    await page.click(show);
    await page.waitFor(
      "document.querySelector('#notifications-result').textContent.startsWith('The webhook signing key cannot be read')"
    );
    assert.equal(await page.eval(isOpen('signing-key-dialog')), false);
    // An immutable newer schema is a compatibility refusal, not a successful rotation.
    mock.routes.set('POST /api/notifications/webhook/signing-secret', () =>
      deliveryError('signing_compatibility')
    );
    await page.click('[data-rotate-key]');
    await page.waitFor(isOpen('delivery-confirm-dialog'));
    await page.click('#delivery-confirm-accept');
    await page.waitFor(
      "document.querySelector('#notifications-result').textContent.startsWith('A newer Uptime Goblin saved')"
    );
    assert.equal(await page.eval(isOpen('signing-key-dialog')), false);
    assert.equal(rotations.length, 1);
    assert.deepEqual(await cspViolations(page), []);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'A56: Replace signing key while the previous key still signs says it stops signing now; a public key that cannot be read just after a Replace is said',
  { skip },
  async () => {
    const now = Date.now(),
      previousUntil = now + 20 * 3600000;
    const webhook = channelBody('env-webhook', { lastAttempt: now });
    useStatus(
      notificationStatus({
        channels: [channelBody('email'), webhook],
        signing: { configured: true, saved: true, createdAt: now - 4 * 3600000, previousUntil },
      })
    );
    const rotations = [];
    mock.routes.set('POST /api/notifications/webhook/signing-secret', request => {
      rotations.push(request);
      return { body: { createdAt: Date.now(), previousUntil: Date.now() + 86400000 } };
    });
    mock.routes.set('GET /api/notifications/webhook/public-key', () =>
      deliveryError('signing_unavailable')
    );
    const page = await openNotifications();
    const replace = '[data-rotate-key]';
    const ask = async () => {
      await page.eval(`document.querySelector(${js(replace)}).focus()`);
      await pressKey(page, 'Enter');
      await page.waitFor(isOpen('delivery-confirm-dialog'));
      await settled(page, 'delivery-confirm-dialog');
      return text(page, '#delivery-confirm-text');
    };
    const cancel = async () => {
      await pressKey(page, 'Escape');
      await page.waitFor(`!${isOpen('delivery-confirm-dialog')}`);
      await page.settle();
    };
    // The card says until when the previous key signs; the confirmation says that this
    // Replace ends it now, naming the same time.
    const card = await text(page, '[data-id="env-webhook"] .channel-signing');
    const until = card.match(/The previous key also signs until (.+)\.$/)?.[1];
    assert.ok(until, card);
    assert.equal(
      await ask(),
      `Receivers that check signatures need the new public key within 24 hours: until then the current key also signs. Uptime Goblin keeps only one previous key, so the one that signs until ${until} stops signing now: receivers that still use it reject alerts until they have the new public key.`
    );
    await cancel();
    assert.equal(rotations.length, 0);
    // Without a previous key still signing (none, or its 24 hours are over), nothing ends.
    for (const ended of [null, now - 1000]) {
      useStatus(
        notificationStatus({
          channels: [channelBody('email'), webhook],
          signing: { configured: true, saved: true, createdAt: now, previousUntil: ended },
        })
      );
      await refreshPage(page);
      assert.equal(
        await ask(),
        'Receivers that check signatures need the new public key within 24 hours: until then the current key also signs.'
      );
      await cancel();
    }
    // Replaced, but the new public key cannot be read: the page says so, with Uptime Goblin's reason.
    await ask();
    await page.click('#delivery-confirm-accept');
    await page.waitFor(
      "document.querySelector('#notifications-result').textContent.startsWith('Uptime Goblin replaced the signing key, but')"
    );
    assert.equal(rotations.length, 1);
    assert.equal(await page.eval(isOpen('signing-key-dialog')), false);
    assert.equal(
      await text(page, '#notifications-result'),
      'Uptime Goblin replaced the signing key, but could not show its public key: The webhook signing key cannot be read right now. Uptime Goblin replaces it at its next start if the encryption key changed.'
    );
    assert.deepEqual(await cspViolations(page), []);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'Copy without the Clipboard API (a plain-HTTP LAN address) selects the public key and says how to copy it',
  { skip },
  async () => {
    useStatus(
      notificationStatus({
        channels: [channelBody('email'), channelBody('env-webhook', { lastAttempt: Date.now() })],
      })
    );
    const keys = publicKeyBody();
    mock.routes.set('GET /api/notifications/webhook/public-key', () => ({ body: keys }));
    // 127.0.0.1 is a secure context, so Chrome has navigator.clipboard there; a page on a
    // plain-HTTP LAN address has none.
    const page = await openPage(cdp, base + '/#configure/notifications', {
      prelude:
        prelude +
        "\nObject.defineProperty(Navigator.prototype, 'clipboard', { configurable: true, get: () => undefined });",
      PageClass: Page,
    });
    pages.push(page);
    await page.waitFor("document.querySelector('[data-public-key]')");
    await page.settle();
    assert.equal(await page.eval('navigator.clipboard'), undefined);
    await page.eval("document.querySelector('[data-public-key]').click()");
    await page.waitFor(isOpen('signing-key-dialog'));
    await settled(page, 'signing-key-dialog');
    await page.click('#signing-key-copy');
    await page.waitFor(
      "document.querySelector('#signing-key-copy-result').textContent === 'Press Ctrl+C (⌘C on a Mac) to copy.'"
    );
    assert.deepEqual(
      await page.eval(`(() => { const f = document.querySelector('#signing-key-value');
        return [document.activeElement === f, f.selectionStart, f.selectionEnd]; })()`),
      [true, 0, keys.publicKey.length]
    );
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'the banners come one at a time, the most urgent first, and are not drawn again unchanged',
  { skip },
  async () => {
    const now = Date.now();
    const status = useStatus(
      notificationStatus({
        channels: [channelBody('email', { lastAttempt: now }), channelBody('env-webhook')],
      })
    );
    const page = await open();
    const notices = () =>
      page.eval(
        "['#notice', '#configuration-notice'].map(s => document.querySelector(s)).map(e => e.hidden ? null : e.textContent)"
      );
    const step = async (change, expected) => {
      change();
      await page.poll();
      if (expected instanceof RegExp)
        await page.waitFor(
          `${expected}.test(document.querySelector('#notice').textContent) && !document.querySelector('#notice').hidden`
        );
      const [dashboardNotice, configurationNotice] = await notices();
      if (expected === null) assert.deepEqual([dashboardNotice, configurationNotice], [null, null]);
      else {
        assert.match(
          dashboardNotice,
          expected instanceof RegExp ? expected : new RegExp(`^${expected}`)
        );
        // The same banner on configuration pages.
        assert.equal(configurationNotice, dashboardNotice);
      }
      return dashboardNotice;
    };
    const disk = {
      full: true,
      since: now - 60000,
      freeBytes: 0,
      reserveReleased: true,
      freed: true,
    };
    mock.dashboard.storage = { since: now - 30000, code: 'SQLITE_FULL' };
    mock.dashboard.notifications.saving = false;
    mock.dashboard.notifications.unsavedSince = now - 20000;
    await step(
      () => (mock.dashboard.disk = disk),
      /^The Uptime Goblin host's disk is full \(since .+\)\. Settings cannot be saved until space is freed\. Sign-in and alert delivery use space Uptime Goblin keeps in reserve; readings are not saved meanwhile\.$/
    );
    await step(
      () => (mock.dashboard.disk = { ...disk, freed: false }),
      /^The Uptime Goblin host's disk is full \(since .+\)\. Settings cannot be saved until space is freed\. Uptime Goblin released the space it keeps in reserve, but the file system did not free it \(snapshots or a shared pool keep it\), so sign-in and alert delivery may fail too\. Free space on the Uptime Goblin host\.$/
    );
    // The history notice keeps its place after the disk one.
    await step(
      () => (mock.dashboard.disk = null),
      /^Uptime Goblin cannot save new readings to its history database \(SQLITE_FULL\)/
    );
    await step(
      () => (mock.dashboard.storage = null),
      /^Notifications are not being saved \(since .+\): Uptime Goblin cannot write its control database\. Alerts are still sent\. If Uptime Goblin restarts meanwhile, alerts not yet delivered are sent again after the restart, and Uptime Goblin's own notices still waiting are lost\. Free disk space on the Uptime Goblin host\.$/
    );
    // Unavailable comes before the figures it makes uncertain.
    await step(
      () => (mock.dashboard.notifications.available = false),
      /^Delivery status is unavailable: Uptime Goblin could not read its control database, so this page cannot tell whether alerts are being delivered\. Open Notifications$/
    );
    const paused = channelBody('env-webhook', {
      state: 'paused',
      pausedReason: 'The webhook answered 401 (sign-in required).',
      counts: { paused: 1, failed: 2 },
    });
    await step(
      () => useStatus(notificationStatus({ channels: [status.channels[0], paused] })),
      'Webhook notifications are paused: The webhook answered 401 \\(sign-in required\\)\\. Open Notifications$'
    );
    // Not read out again at the next poll when it says the same.
    await watchChanges(page, '#notice');
    await page.poll();
    assert.equal(await page.eval('window.__changes'), 0);
    // A refusing webhook is named with its last error, which only the delivery status carries.
    const refusing = channelBody('env-webhook', {
      state: 'refusing',
      lastError: { time: now, message: 'The webhook answered 422.' },
      counts: { failed: 3 },
    });
    await step(
      () => useStatus(notificationStatus({ channels: [status.channels[0], refusing] })),
      /^Webhook is refusing notifications: The webhook answered 422\. Open Notifications$/
    );
    const refusingEmail = channelBody('email', {
      state: 'refusing',
      lastError: { time: now, message: '550 Daily sending quota exceeded' },
      counts: { failed: 3 },
    });
    await step(
      () =>
        useStatus(notificationStatus({ channels: [refusingEmail, channelBody('env-webhook')] })),
      'Email is refusing notifications: 550 Daily sending quota exceeded\\. Open Notifications$'
    );
    await step(
      () =>
        useStatus(
          notificationStatus({
            channels: [status.channels[0], channelBody('env-webhook', { counts: { failed: 2 } })],
          })
        ),
      '2 notifications could not be delivered since the last successful one\\. Open Notifications$'
    );
    await step(() => useStatus(status), null);
    // Open Notifications leads there.
    useStatus(notificationStatus({ channels: [status.channels[0], paused] }));
    await page.poll();
    await page.waitFor("!document.querySelector('#notice').hidden");
    await page.click('#notice .notice-action');
    await page.waitFor("document.querySelector('#notifications-page')");
    assert.equal(await page.eval('location.hash'), '#configure/notifications');
    assert.deepEqual(await cspViolations(page), []);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'the Email page, the Alerts page and the alerts dialog say what each channel needs',
  { skip },
  async () => {
    const now = Date.now();
    const emailPaused = channelBody('email', {
      state: 'paused',
      pausedReason: 'Sign-in failed: the mail server refused the app password.',
      lastAttempt: now,
      counts: { paused: 1 },
    });
    const webhookRetrying = channelBody('env-webhook', {
      state: 'retrying',
      lastAttempt: now,
      nextAttemptAt: now + 60000,
      counts: { retrying: 2, failed: 1 },
    });
    mock.dashboard.config.email = {
      ...mock.dashboard.config.email,
      enabled: true,
      from: 'orbit@example.test',
      to: 'dana@example.test',
      passwordConfigured: true,
    };
    useStatus(notificationStatus({ channels: [emailPaused, webhookRetrying] }));
    const page = await open('#configure/email');
    assert.equal(
      await text(page, '#email-status'),
      'Email alerts are paused: Sign-in failed: the mail server refused the app password. Save corrected settings, send a test email, or press Resume on the Notifications page.'
    );
    assert.equal(
      await page.eval("document.querySelector('.email-history-link a').getAttribute('href')"),
      '#configure/notifications'
    );
    assert.equal(await text(page, '.email-history-link a'), 'Delivery history');
    // The Email page follows the dashboard poll.
    useStatus(
      notificationStatus({
        channels: [
          channelBody('email', {
            state: 'refusing',
            lastAttempt: now,
            lastError: { time: now, message: '550 Daily sending quota exceeded' },
          }),
          webhookRetrying,
        ],
      })
    );
    await page.poll();
    assert.equal(
      await text(page, '#email-status'),
      'Email is refusing notifications: 550 Daily sending quota exceeded.'
    );
    useStatus(
      notificationStatus({
        channels: [
          channelBody('email', {
            state: 'retrying',
            lastAttempt: now,
            nextAttemptAt: now + 60000,
            counts: { retrying: 2 },
          }),
          webhookRetrying,
        ],
      })
    );
    await page.poll();
    assert.match(
      await text(page, '#email-status'),
      /^2 messages waiting to retry \(next attempt .+\)\.$/
    );
    useStatus(
      notificationStatus({
        channels: [channelBody('email', { lastAttempt: now, lastSuccess: now }), webhookRetrying],
      })
    );
    await page.poll();
    assert.match(
      await text(page, '#email-status'),
      /^Email alerts are enabled\. Last accepted by the mail server: /
    );

    // The Alerts page: each channel's state, the webhook's signing, and View deliveries.
    useStatus(notificationStatus({ channels: [emailPaused, webhookRetrying] }));
    await page.eval("location.hash = '#configure/alerts'");
    await page.waitFor(
      "document.querySelector('#alerts-delivery') && !document.querySelector('#alerts-delivery').textContent.includes('Reading')"
    );
    await page.settle();
    const rows = await allText(page, '#alerts-delivery .delivery-row p');
    assert.equal(rows[0], 'Paused: Sign-in failed: the mail server refused the app password.');
    assert.match(rows[1], /^Retrying \(next attempt .+\) · Signed$/);
    assert.doesNotMatch(
      await text(page, '#alerts-delivery'),
      /Configured on the Uptime Goblin server/
    );
    assert.equal(
      await page.eval(
        'document.querySelector(\'#configuration-content a[href="#configure/notifications"]\').textContent'
      ),
      'View deliveries'
    );
    useStatus(
      notificationStatus({
        channels: [emailPaused, webhookRetrying],
        signing: { configured: false, saved: false, createdAt: null, previousUntil: null },
      })
    );
    await page.poll();
    await page.waitFor(
      "document.querySelector('#alerts-delivery').textContent.includes('Not signed yet')"
    );
    // The Setup guide opens the alerts and notifications guide.
    await page.eval("document.querySelector('#alerts-delivery [data-help]').click()");
    await page.waitFor(
      'document.querySelector(\'[data-doc="notifications"][aria-pressed="true"]\')'
    );
    assert.equal(requests('GET', '/api/docs').at(-1).url.searchParams.get('doc'), 'notifications');

    // The alerts dialog: one line per channel that needs attention, then the failures.
    useStatus(notificationStatus({ channels: [emailPaused, webhookRetrying] }));
    await page.eval("location.hash = ''");
    await page.waitFor("!document.querySelector('#dashboard-page').hidden");
    await page.poll();
    const dialogLines = async () => {
      await page.click('#alerts-button');
      await page.waitFor(isOpen('alerts-dialog'));
      await page.waitFor(
        "!document.querySelector('#alerts-delivery-lines').textContent.includes('Reading')"
      );
      await page.settle();
      return allText(page, '#alerts-delivery-lines p.detail-error');
    };
    const lines = await dialogLines();
    assert.equal(
      lines[0],
      'Email: Sign-in failed: the mail server refused the app password. These in-app alerts remain available.'
    );
    assert.match(
      lines[1],
      /^Webhook: 2 notifications waiting to retry \(next attempt .+\)\. These in-app alerts remain available\.$/
    );
    assert.equal(
      lines[2],
      '1 notification could not be delivered. These in-app alerts remain available.'
    );
    assert.doesNotMatch(await text(page, '#alerts-content'), /Webhook delivery failed/);
    // View deliveries, by keyboard, leads there, and the dialog goes at once: the focus is on
    // the page's title, not on <body> (the dialog would give it back to the alerts button on the
    // dashboard just hidden once its exit motion ended; motion is not reduced here).
    assert.equal(await page.eval("matchMedia('(prefers-reduced-motion: reduce)').matches"), false);
    await page.eval(
      'document.querySelector(\'#alerts-delivery-lines a[href="#configure/notifications"]\').focus()'
    );
    await pressKey(page, 'Enter');
    await page.waitFor(
      `document.querySelector('#notifications-page') && !${isOpen('alerts-dialog')}`
    );
    await delay(300);
    assert.equal(await page.eval('document.activeElement.id'), 'configuration-section-title');
    await page.eval("location.hash = ''");
    await page.waitFor("!document.querySelector('#dashboard-page').hidden");
    // Paused and refusing webhooks.
    useStatus(
      notificationStatus({
        channels: [
          channelBody('email', { lastAttempt: now }),
          channelBody('env-webhook', {
            state: 'paused',
            pausedReason: 'The webhook answered 401 (sign-in required).',
            counts: { paused: 1 },
          }),
        ],
      })
    );
    await page.poll();
    assert.deepEqual(await dialogLines(), [
      'Webhook is paused: The webhook answered 401 (sign-in required). Alerts wait until it is resumed. These in-app alerts remain available.',
    ]);
    await pressKey(page, 'Escape');
    await page.waitFor(`!${isOpen('alerts-dialog')}`);
    useStatus(
      notificationStatus({
        channels: [
          channelBody('email', { lastAttempt: now }),
          channelBody('env-webhook', {
            state: 'refusing',
            lastError: { time: now, message: 'The webhook answered 422.' },
          }),
        ],
      })
    );
    await page.poll();
    assert.deepEqual(await dialogLines(), [
      'Webhook is refusing notifications: The webhook answered 422. These in-app alerts remain available.',
    ]);
    await pressKey(page, 'Escape');
    await page.waitFor(`!${isOpen('alerts-dialog')}`);
    // Nothing needs attention: no lines, and the status is not read for them.
    useStatus(
      notificationStatus({
        channels: [channelBody('email', { lastAttempt: now }), channelBody('env-webhook')],
      })
    );
    await page.poll();
    const reads = statusRequests().length;
    assert.deepEqual(await dialogLines(), []);
    assert.equal(statusRequests().length, reads);
    assert.deepEqual(await cspViolations(page), []);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'the Email page counts only the messages waiting to retry, and says apart those waiting for their first message',
  { skip },
  async () => {
    const now = Date.now();
    mock.dashboard.config.email = {
      ...mock.dashboard.config.email,
      enabled: true,
      from: 'orbit@example.test',
      to: 'dana@example.test',
      passwordConfigured: true,
    };
    // One message waits to retry in 10 minutes; two newer alerts wait for their own digest.
    const email = channelBody('email', {
      state: 'retrying',
      lastAttempt: now,
      lastFailure: now,
      nextAttemptAt: now + 600000,
      counts: { waiting: 2, retrying: 1 },
    });
    useStatus(notificationStatus({ channels: [email, channelBody('env-webhook')] }));
    const page = await open('#configure/email');
    const status = await text(page, '#email-status');
    assert.match(
      status,
      /^1 message waiting to retry \(next attempt .+\), and 2 waiting to be sent\.$/
    );
    // The same count as the Notifications page's summary.
    await page.eval("location.hash = '#configure/notifications'");
    await page.waitFor(
      "document.querySelector('#notifications-summary') && !document.querySelector('#notifications-summary').textContent.startsWith('Reading')"
    );
    assert.match(
      await text(page, '#notifications-summary'),
      /^1 notification waiting to retry \(next attempt .+\)\.$/
    );
    // Only retries: nothing else is said.
    useStatus(
      notificationStatus({
        channels: [
          channelBody('email', { ...email, counts: { retrying: 3 } }),
          channelBody('env-webhook'),
        ],
      })
    );
    await page.eval("location.hash = '#configure/email'");
    await page.waitFor("document.querySelector('#email-status')");
    await page.poll();
    assert.match(
      await text(page, '#email-status'),
      /^3 messages waiting to retry \(next attempt .+\)\.$/
    );
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'the Email page, the Alerts page, the alerts dialog and the System page say "Delivery status is unavailable." while it is',
  { skip },
  async () => {
    const now = Date.now();
    // The dashboard keeps the last figures it computed (an email accepted, failures, a paused
    // webhook), which must not be shown as current.
    const stale = notificationStatus({
      channels: [
        channelBody('email', { lastAttempt: now, lastSuccess: now }),
        channelBody('env-webhook', {
          state: 'paused',
          pausedReason: 'The webhook answered 401.',
          counts: { failed: 2, paused: 1 },
        }),
      ],
    });
    useStatus(stale, { available: false });
    mock.status = () => deliveryError('delivery_status_unavailable');
    mock.dashboard.config.email = {
      ...mock.dashboard.config.email,
      enabled: true,
      from: 'orbit@example.test',
      to: 'dana@example.test',
      passwordConfigured: true,
    };
    mock.routes.set('GET /api/system', () => ({
      body: {
        ...deliverySystemBody(),
        notifications: {
          available: false,
          saving: true,
          totals: stale.totals,
          oldestWaitingAt: null,
        },
      },
    }));
    const page = await open('#configure/email');
    assert.equal(await text(page, '#email-status'), 'Delivery status is unavailable.');
    await page.eval("location.hash = '#configure/alerts'");
    await page.waitFor(
      "document.querySelectorAll('#alerts-delivery .delivery-row').length === 2 && !document.querySelector('#alerts-delivery').textContent.includes('Reading')"
    );
    await page.settle();
    assert.deepEqual(await allText(page, '#alerts-delivery .delivery-row p'), [
      'Delivery status is unavailable.',
      'Delivery status is unavailable.',
    ]);
    await page.eval("document.querySelector('[data-view-alerts]').click()");
    await page.waitFor(isOpen('alerts-dialog'));
    await page.settle();
    assert.equal(
      await text(page, '#alerts-delivery-lines p.detail-error'),
      'Delivery status is unavailable. These in-app alerts remain available.'
    );
    assert.equal(await text(page, '#alerts-delivery-lines a'), 'View deliveries');
    await pressKey(page, 'Escape');
    await page.waitFor(`!${isOpen('alerts-dialog')}`);
    await page.eval("location.hash = '#configure/system'");
    await page.waitFor("document.querySelector('#system-details .system-facts')");
    const notifications = await page.eval(
      "[...document.querySelectorAll('#system-details .settings-block')].find(b => b.querySelector('h3').textContent === 'Notifications').textContent"
    );
    assert.match(notifications, /Delivery status is unavailable\./);
    assert.doesNotMatch(notifications, /Failed|Waiting|\d/);
    // The banner says so, on configuration pages too.
    assert.match(await text(page, '#configuration-notice'), /^Delivery status is unavailable: /);
    // Readable again: the figures come back.
    useStatus(stale);
    await page.eval("location.hash = '#configure/email'");
    await page.waitFor("document.querySelector('#email-status')");
    await page.poll();
    assert.match(await text(page, '#email-status'), /^Email alerts are enabled\./);
    assert.deepEqual(page.exceptions, []);
  }
);

/** A GET /api/system answer of this milestone, with `overrides` merged in. */
function deliverySystemBody(overrides = {}) {
  return {
    version: '1.5.0-dev.1',
    build: web.build,
    clients: [],
    uptimeSeconds: 10,
    startedAt: Date.now(),
    authenticationRequired: true,
    authentication: {},
    data: {
      databaseBytes: 2048,
      controlBytes: 4096,
      writeFailure: null,
      configBytes: 512,
      samples: 0,
      events: 0,
      activeAlerts: 0,
    },
    collection: {
      inflight: 0,
      pending: 0,
      concurrency: 4,
      timeoutSeconds: 90,
      lastCollected: null,
    },
    limits: { sources: 200, mappingsPerSource: 100, rulesPerSource: 30 },
    notifications: {
      available: true,
      saving: true,
      totals: counts0(),
      oldestWaitingAt: null,
      notQueued: 0,
    },
    keys: {
      source: 'file',
      file: '/etc/uptime-goblin/secret.key',
      fingerprint: '0123456789abcdef',
      previous: null,
      needsRewrap: false,
      warnings: [],
    },
    disk: {
      full: false,
      since: null,
      freeBytes: 5 * 2 ** 30,
      reserveHeld: true,
      reserveReleased: false,
      freed: null,
      measurable: true,
      nextRecreateAt: null,
      reserveBytes: 8 * 2 ** 20,
    },
    ...overrides,
  };
}

test(
  'alerts the backlog cap refused are said in the summary, a banner, the channel card and the System page, for 24 hours',
  { skip },
  async () => {
    const now = Date.now();
    // The webhook keeps failing; 10,000 notifications wait, and 10 newer alerts were refused.
    const full = channelBody('env-webhook', {
      state: 'retrying',
      lastAttempt: now - 60000,
      lastFailure: now - 60000,
      nextAttemptAt: now + 600000,
      counts: { waiting: 9995, retrying: 5 },
      notQueued: 10,
      notQueuedAt: now - 30000,
    });
    const status = notificationStatus({
      channels: [channelBody('email', { lastAttempt: now, lastSuccess: now }), full],
      notQueued: 10,
    });
    useStatus(status);
    mock.deliveries = () => ({ body: { deliveries: [], nextCursor: null, unsaved: 0 } });
    const sentence =
      /^10 notifications for Webhook were not queued because its backlog was full \(the last at .+\): they are not sent and not in the delivery history\.$/;
    const page = await openNotifications();
    assert.match(await text(page, '#notifications-summary'), sentence);
    assert.match(
      await text(page, '[data-id="env-webhook"] .channel-facts'),
      /Not queued since Uptime Goblin started \(backlog full\)10/
    );
    // The banner, on the dashboard and on configuration pages.
    assert.equal(mock.dashboard.notifications.attention.notQueued.join(), 'env-webhook');
    await page.poll();
    await page.waitFor("!document.querySelector('#configuration-notice').hidden");
    const banner = (await text(page, '#configuration-notice')).replace(/ Open Notifications$/, '');
    assert.match(banner, sentence);
    // One refused alert, in the singular.
    useStatus(
      notificationStatus({
        channels: [
          channelBody('email', { lastAttempt: now, lastSuccess: now }),
          channelBody('env-webhook', { ...full, notQueued: 1 }),
        ],
        notQueued: 1,
      })
    );
    await refreshPage(page);
    assert.match(
      await text(page, '#notifications-summary'),
      /^1 notification for Webhook was not queued because its backlog was full \(the last at .+\): it is not sent and not in the delivery history\.$/
    );
    // More than 24 hours after the last refusal, the counts speak again; the card keeps the
    // figure since Uptime Goblin started.
    useStatus(
      notificationStatus({
        channels: [
          channelBody('email', { lastAttempt: now, lastSuccess: now }),
          channelBody('env-webhook', { ...full, notQueuedAt: now - 25 * 3600000 }),
        ],
        notQueued: 10,
      })
    );
    await refreshPage(page);
    assert.match(
      await text(page, '#notifications-summary'),
      /^5 notifications waiting to retry \(next attempt .+\)\.$/
    );
    assert.match(
      await text(page, '[data-id="env-webhook"] .channel-facts'),
      /Not queued since Uptime Goblin started \(backlog full\)10/
    );
    await page.poll();
    await page.waitFor("document.querySelector('#configuration-notice').hidden");
    // The System page counts them since Uptime Goblin started.
    mock.routes.set('GET /api/system', () => ({
      body: deliverySystemBody({
        notifications: {
          available: true,
          saving: true,
          totals: { waiting: 9995, retrying: 5, sending: 0, paused: 0, failed: 0 },
          oldestWaitingAt: now - 3600000,
          notQueued: 10,
        },
      }),
    }));
    await page.eval("location.hash = '#configure/system'");
    await page.waitFor("document.querySelector('#system-details .system-facts')");
    assert.ok(
      (await text(page, '#system-details')).includes(
        'Not queued since Uptime Goblin started (backlog full)10'
      )
    );
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'the System page shows the encryption key, the disk and the notifications',
  { skip },
  async () => {
    const now = Date.now();
    let body = deliverySystemBody({
      notifications: {
        available: true,
        saving: false,
        totals: { waiting: 1, retrying: 2, sending: 0, paused: 3, failed: 4 },
        oldestWaitingAt: now - 600000,
      },
      keys: {
        source: 'data-directory',
        file: '/var/lib/uptime-goblin/secret.key',
        fingerprint: 'fedcba9876543210',
        previous: '0011223344556677',
        needsRewrap: true,
        warnings: [
          '/var/lib/uptime-goblin/secret.key is inside the data directory, so every copy of the data directory carries the key.',
        ],
      },
    });
    mock.routes.set('GET /api/system', () => ({ body }));
    const page = await open('#configure/system');
    await page.waitFor("document.querySelector('#system-details .system-facts')");
    const details = (await text(page, '#system-details')).replace(/\s+/g, ' ');
    for (const expected of [
      'Control database4 KiB',
      'Free space5 GiB',
      'StateSpace available',
      'Reserve for sign-in and alert deliveryHeld (8 MiB)',
      'Waiting to be sent1',
      'Waiting to retry2',
      'Held while a channel is paused3',
      'Failed since the last successful one4',
      'SavedNo: kept in memory until Uptime Goblin can write its control database',
      'Source/var/lib/uptime-goblin/secret.key',
      'Fingerprintfedcba9876543210',
      'Previous key0011223344556677',
      'every copy of the data directory carries the key',
      'Some data keys open only with GOBLIN_SECRET_KEY_PREVIOUS; run goblin-admin key rotate with Uptime Goblin stopped.',
    ])
      assert.ok(details.includes(expected), expected);
    // Every source, as the start line names it.
    const sources = [
      [{ source: 'env' }, 'SourceGOBLIN_SECRET_KEY'],
      [
        { source: 'file', file: '/etc/uptime-goblin/secret.key' },
        'SourceGOBLIN_SECRET_KEY_FILE (/etc/uptime-goblin/secret.key)',
      ],
      [
        { source: 'credentials', file: '/run/credentials/uptime-goblin.service/orbit-secret-key' },
        'SourceThe systemd credential (/run/credentials/uptime-goblin.service/orbit-secret-key)',
      ],
      [
        { source: 'secrets', file: '/run/secrets/orbit_secret_key' },
        'SourceThe Compose secret (/run/secrets/orbit_secret_key)',
      ],
      [
        { source: 'generated', file: '/app/data/secret.key' },
        'SourceA new /app/data/secret.key (generated at this start)',
      ],
    ];
    for (const [keys, expected] of sources) {
      body = deliverySystemBody({
        keys: { fingerprint: 'fedcba9876543210', warnings: [], ...keys },
      });
      await page.eval("document.querySelector('#refresh-system').click()");
      await page.waitFor(
        `document.querySelector('#system-details').textContent.includes(${js(expected)})`
      );
    }
    // The server's own warning for data keys that need a rewrap names the whole command line
    // (keyLines in server.mjs): the page adds its short sentence only without it, so the warning
    // shows once (docs audit, keys 20).
    const serverRewrap =
      'Some data keys open only with GOBLIN_SECRET_KEY_PREVIOUS; run, with Uptime Goblin stopped: sudo -u uptime-goblin env GOBLIN_SECRET_KEY_FILE=/etc/uptime-goblin/secret.key GOBLIN_SECRET_KEY_PREVIOUS_FILE=OLD_KEY_FILE node /opt/uptime-goblin/lib/cli/goblin-admin.mjs key rotate --data-dir /var/lib/uptime-goblin (the native install; Docker Compose and other installs: docs/installation.md#goblin-admin).';
    body = deliverySystemBody({
      keys: {
        source: 'file',
        file: '/etc/uptime-goblin/secret.key',
        fingerprint: 'fedcba9876543210',
        previous: '0011223344556677',
        needsRewrap: true,
        warnings: [serverRewrap],
      },
    });
    await page.eval("document.querySelector('#refresh-system').click()");
    await page.waitFor(
      `document.querySelector('#system-details').textContent.includes(${js('key rotate --data-dir /var/lib/uptime-goblin')})`
    );
    assert.deepEqual(
      (
        await page.eval(
          "[...document.querySelectorAll('#system-details .system-warnings li')].map(li => li.textContent)"
        )
      ).filter(line => line.startsWith('Some data keys open only')),
      [serverRewrap]
    );
    // A full disk whose release freed nothing, and a file system that reports no size.
    body = deliverySystemBody({
      disk: {
        full: true,
        since: now - 60000,
        freeBytes: 0,
        reserveHeld: false,
        reserveReleased: true,
        freed: false,
        measurable: true,
        nextRecreateAt: now + 300000,
        reserveBytes: 8 * 2 ** 20,
      },
    });
    await page.eval("document.querySelector('#refresh-system').click()");
    await page.waitFor(
      "document.querySelector('#system-details').textContent.includes('Released, but the file system did not free the space')"
    );
    assert.match(await text(page, '#system-details'), /StateFull since /);
    body = deliverySystemBody({
      disk: { ...deliverySystemBody().disk, measurable: false, freeBytes: null },
    });
    await page.eval("document.querySelector('#refresh-system').click()");
    await page.waitFor(
      "document.querySelector('#system-details').textContent.includes('Unknown: the file system does not report it')"
    );
    assert.deepEqual(page.exceptions, []);
    // On a phone, a key warning that repeats a long path in parentheses wraps within the list
    // instead of widening the page (§7.4). A file name of letters, digits, underscores and a
    // dot offers the browser no place to break a line.
    const longFile = '/srv/orbit/keys/orbit_secret_key_for_the_production_homelab_primary_site.key';
    body = deliverySystemBody({
      keys: {
        source: 'file',
        file: longFile,
        fingerprint: 'fedcba9876543210',
        warnings: [
          `GOBLIN_SECRET_KEY_FILE (${longFile}) can be read by every user of this host; make it 0600 or 0440.`,
        ],
      },
    });
    const phone = await openOnPhone(360, '#configure/system');
    await phone.waitFor("document.querySelector('#system-details .system-warnings li')");
    await phone.settle();
    assert.deepEqual(
      await phone.eval(
        "(li => [document.documentElement.scrollWidth, li.scrollWidth <= li.clientWidth])(document.querySelector('#system-details .system-warnings li'))"
      ),
      [360, true]
    );
    assert.deepEqual(phone.exceptions, []);
    await closeNewest();
  }
);

test('a save refused because the disk is full says so and keeps the draft', { skip }, async () => {
  const full = deliveryError('storage_full');
  mock.routes.set('PATCH /api/settings', () => full);
  const page = await open('#configure/monitoring');
  await setValue(page, '#poll-seconds', '120');
  await page.eval("document.querySelector('#settings-form [type=submit]').click()");
  await page.waitFor("!document.querySelector('#settings-error').hidden");
  assert.equal(await text(page, '#settings-error'), full.body.error);
  assert.equal(await page.eval("document.querySelector('#poll-seconds').value"), '120');
  assert.equal(await text(page, '#dirty-status'), 'You have unsaved changes');
  // The email form too: the answer's text in its result area, the draft kept.
  await page.eval("document.querySelector('[data-discard]').click()");
  await page.eval("location.hash = '#configure/email'");
  await page.waitFor("document.querySelector('#email-form')");
  await setValue(page, '#email-to', 'dana@example.test');
  await page.eval("document.querySelector('#email-form [type=submit]').click()");
  await page.waitFor("document.querySelector('#email-result').classList.contains('failed')");
  await page.settle();
  assert.equal(await text(page, '#email-result'), full.body.error);
  assert.equal(await page.eval("document.querySelector('#email-to').value"), 'dana@example.test');
  assert.deepEqual(page.exceptions, []);
});

test(
  'on a phone the Notifications page and its dialogs are one column, nothing is wider than the screen, and nothing breaks the CSP',
  { skip },
  async () => {
    const now = Date.now();
    useStatus(
      notificationStatus({
        saving: false,
        unsavedSince: now,
        channels: [
          channelBody('email', {
            state: 'refusing',
            lastAttempt: now,
            lastError: {
              time: now,
              message:
                '550 5.4.5 Daily user sending quota exceeded. https://support.example.test/mail/answer/22839-a-very-long-reference',
            },
            counts: { failed: 3 },
          }),
          channelBody('env-webhook', {
            state: 'paused',
            pausedReason: 'The webhook answered 401 (sign-in required).',
            nextAttemptAt: now + 900000,
            host: 'a-very-long-receiver-host-name.internal.homelab.example.test',
            counts: { paused: 4, failed: 2 },
          }),
        ],
      })
    );
    const long = deliveryBody({
      alert: {
        name: 'A source with a rather long name for a phone screen',
        message: 'x'.repeat(200),
      },
      lastError:
        'connect ECONNREFUSED 192.0.2.10:443 — the receiver did not accept the connection at all',
      batch: 'g_abcdefghijklmnopqrstuvwxyz',
      saved: false,
    });
    mock.deliveries = () => ({
      body: { deliveries: [long, deliveryBody()], nextCursor: '42', unsaved: 1 },
    });
    const keys = publicKeyBody({ createdAt: now, previous: true, previousUntil: now + 86400000 });
    mock.routes.set('GET /api/notifications/webhook/public-key', () => ({ body: keys }));
    for (const width of [320, 360]) {
      const page = await openOnPhone(width, '#configure/notifications');
      await page.waitFor(
        "document.querySelectorAll('#history-list .delivery').length === 2 && document.querySelectorAll('#attention-list .delivery').length"
      );
      await page.settle();
      // Boxes, and text that overflows its box, past either edge of the screen. (Not innerWidth:
      // on a phone the layout viewport widens to what overflows it.)
      const layout = await page.eval(`({
        scrollWidth: document.documentElement.scrollWidth,
        wide: [
          ...[...document.querySelectorAll('body *')]
            .filter(e => e.getClientRects().length)
            .filter(e => e.getBoundingClientRect().right > ${width} + 0.5 || e.getBoundingClientRect().left < -0.5)
            .map(e => e.id || e.className || e.localName),
          ...(() => {
            const out = [], walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
            for (let node; (node = walker.nextNode()); ) {
              const range = document.createRange();
              range.selectNodeContents(node);
              for (const r of range.getClientRects())
                if (r.width && (r.right > ${width} + 0.5 || r.left < -0.5))
                  out.push('text: ' + node.textContent.trim().slice(0, 40) + ' in ' + (node.parentElement.id || node.parentElement.className || node.parentElement.localName));
            }
            return out;
          })(),
        ].slice(0, 8),
        columns: getComputedStyle(document.querySelector('#notification-channels')).gridTemplateColumns.split(' ').length,
        tables: document.querySelectorAll('#configuration-content table').length,
      })`);
      assert.deepEqual(layout, { scrollWidth: width, wide: [], columns: 1, tables: 0 }, `${width}`);
      // The dialogs fit too, the PEM wrapped inside its field.
      await page.eval("document.querySelector('[data-public-key]').click()");
      await page.waitFor(isOpen('signing-key-dialog'));
      await settled(page, 'signing-key-dialog');
      const dialog = await page.eval(
        "(r => [r.left, r.right, document.documentElement.scrollWidth])(document.querySelector('#signing-key-dialog').getBoundingClientRect())"
      );
      assert.ok(
        dialog[0] >= 0 && dialog[1] <= width && dialog[2] === width,
        `${width} dialog ${dialog}`
      );
      const pem = await page.eval(
        "(f => [f.getBoundingClientRect().right, f.scrollWidth <= f.clientWidth])(document.querySelector('#signing-key-value'))"
      );
      assert.ok(pem[0] <= width && pem[1], `${width} key field ${pem}`);
      await pressKey(page, 'Escape');
      await page.waitFor(`!${isOpen('signing-key-dialog')}`);
      assert.deepEqual(await cspViolations(page), [], `${width}`);
      assert.deepEqual(page.exceptions, [], `${width}`);
      await closeNewest();
    }
  }
);

// --- Configure → Audit log (audit spec §8, §9.1 U) ----------------------------------------------
//
// The page against a scripted /api/audit. Every answer is an entry of
// test/contract/audit-bodies.json with its placeholders made real (concreteBody(), "now" being
// the test's own time), the bodies lane H's routes send and lane O's service resolves, so the page
// is tested against what Uptime Goblin will send. Each test's name starts with the name §9.4 uses for it.

/** An audit list answer: the contract's entry `name`, with `overrides` merged in. */
const auditList = (name, overrides = {}, firstSeq = 5000) => ({
  body: { ...concreteBody(name, { now: Date.now(), firstSeq }), ...overrides },
});
/** An audit error answer, as error.* of the contract gives it (status, headers, body). */
function auditError(name) {
  const { status, headers, body } = auditBody(`error.${name}`);
  return { status, headers, body };
}
/** An export answer (export.csv or export.ndjson), its body sent as it is, BOM included. */
function auditExport(name, { rows, more } = {}) {
  const entry = concreteBody(name, { now: Date.now() });
  const headers = Object.fromEntries(
    Object.entries(entry.headers).map(([key, value]) => [
      key === 'content-type' ? 'Content-Type' : key,
      value,
    ])
  );
  if (rows !== undefined) headers['x-goblin-export-rows'] = String(rows);
  if (more !== undefined) headers['x-goblin-export-more'] = String(more);
  return { status: entry.status, headers, raw: entry.body, entry };
}
/** GET /api/audit requests (not the verify and export routes), each as its query. */
const auditReads = () =>
  mock.requests
    .filter(r => r.method === 'GET' && r.path === '/api/audit')
    .map(r => r.url.searchParams);
const auditReading =
  "document.querySelector('#audit-list')?.textContent.includes('Reading the audit log')";
async function openAudit(hash = '#configure/audit') {
  const page = await open(hash);
  await page.waitFor(`document.querySelector('#audit-list') && !(${auditReading})`);
  await page.settle();
  return page;
}
/** Waits until the page has sent `count` list reads in all, and drawn the last answer. */
async function auditReadsReach(page, count) {
  const end = Date.now() + 5000;
  while (auditReads().length < count) {
    if (Date.now() > end) throw new Error(`Timed out waiting for audit read ${count}`);
    await delay(10);
  }
  await page.settle();
}
async function refreshAudit(page) {
  const before = auditReads().length;
  await page.eval("document.querySelector('#audit-refresh').click()");
  await auditReadsReach(page, before + 1);
}
const auditHeads = page =>
  page.eval(
    `[...document.querySelectorAll('#audit-list > li.audit-entry')].map(li => [li.querySelector('.audit-summary').textContent, li.querySelector('.audit-outcome').textContent])`
  );
/** The facts of the entry with `seq`, as {label: value}. */
const auditFacts = (page, seq, selector = ':scope > .audit-facts') =>
  page.eval(
    `Object.fromEntries([...document.querySelector('#audit-list > [data-id="${seq}"]').querySelectorAll(${js(`${selector} > div`)})].map(d => [d.querySelector('dt').textContent, d.querySelector('dd').textContent]))`
  );
/** Moves the focus with Tab alone until `selector` has it: proof that it can be reached so. */
async function tabTo(page, selector, limit = 200) {
  for (let i = 0; i < limit; i++) {
    if (await page.eval(`!!document.activeElement?.matches(${js(selector)})`)) return;
    await pressKey(page, 'Tab');
  }
  throw new Error(`Tab never reached ${selector}`);
}
const minuteMs = 60000;

test(
  '"states": Configure → Audit log reads, says when it is empty or matches nothing, lists every kind of entry, notes entries not written, and says when the log is unavailable',
  { skip },
  async () => {
    let reply = () => ({ ...auditList('list.empty'), delay: 400 });
    mock.audit = () => reply();
    const page = await open('#configure/overview');
    await page.eval("location.hash = '#configure/audit'");
    // Its place: after Account; Email and Notifications keep theirs.
    assert.deepEqual((await allText(page, '#configuration-nav a')).slice(5, 9), [
      'Email',
      'Notifications',
      'Account',
      'Audit log',
    ]);
    assert.equal(await text(page, '#configuration-section-title'), 'Who changed what, and when.');
    await page.waitFor("document.querySelector('#audit-list')");
    assert.equal(await text(page, '#audit-list'), 'Reading the audit log…');
    await page.waitFor(`!(${auditReading})`);
    await page.settle();
    assert.equal(await text(page, '#audit-list'), 'No entries yet.');
    // "retention": the line with no entry.
    assert.equal(
      await text(page, '#audit-retention'),
      'Entries are kept for 90 days, at most 250,000. There are no entries yet.'
    );
    assert.equal(await page.eval("document.querySelector('#audit-more').hidden"), true);
    assert.equal(await page.eval("document.querySelector('#audit-unwritten').hidden"), true);

    // Entries exist, none in the period chosen.
    reply = () => auditList('list.empty', { retention: concreteBody('list.entries').retention });
    await refreshAudit(page);
    assert.equal(await text(page, '#audit-list'), 'No entry matches these filters.');
    assert.match(
      await text(page, '#audit-retention'),
      /^Entries are kept for 90 days, at most 250,000\. The oldest kept entry is from [^—]+\.$/
    );

    // One entry of each outcome, an operation, a summary and its immediate row, a diff with a
    // secret and a truncation, and an action this release does not know.
    const listed = concreteBody('list.entries', { now: Date.now() });
    reply = () => ({ body: listed });
    await refreshAudit(page);
    assert.deepEqual(await auditHeads(page), [
      ['Recorded: users.created', 'Succeeded'],
      [
        'Uptime Goblin 1.5.0-dev.2 started; security settings from the environment changed: legacyBasic',
        'Recorded',
      ],
      ['Tested the connection to Plex: connected', 'Succeeded'],
      [
        '7 more refused sign-ins: wrong name or password (6), too many failed attempts (1)',
        'Failed',
      ],
      ['Sign-in refused: wrong name or password', 'Failed'],
      ['Showing the webhook signing secret: in progress', 'In progress'],
      ['Change of workspace settings: outcome unknown', 'Outcome unknown'],
      ['Change of source Blog: refused, changed elsewhere first', 'Changed elsewhere'],
      ['Retry of a notification: refused (Uptime Goblin error delivery_not_retryable)', 'Refused'],
      ['Changed workspace settings', 'Succeeded'],
      ['Signed in', 'Succeeded'],
    ]);
    // Each heading starts with the entry's time, and names the entry for a screen reader.
    assert.equal(
      await page.eval(`[...document.querySelectorAll('#audit-list > li.audit-entry')].every(li =>
        li.tabIndex === -1 && document.getElementById(li.getAttribute('aria-labelledby'))?.querySelector('time.audit-time'))`),
      true
    );
    const summary = await auditFacts(page, 4997);
    assert.equal(summary.Who, 'Not signed in');
    assert.equal(summary.Outcome, 'Failed');
    assert.match(summary.Count, /^7 times between [^—]+ and [^—]+, from 3 different clients$/);
    assert.equal(summary.From, undefined, 'a summary names no client of its own');
    const refusal = await auditFacts(page, 4996);
    assert.deepEqual(
      { who: refusal.Who, from: refusal.From, target: refusal.Target },
      { who: 'Not signed in', from: '192.0.2.20, curl/8.5.0', target: 'account admin' }
    );
    const retry = await auditFacts(page, 4991);
    assert.equal(retry.Who, 'admin (script with a password)');
    assert.equal(retry.From, '192.0.2.10, python-requests/2.32.3');
    assert.equal(retry.Outcome, 'Refused (HTTP 409)');
    assert.equal(retry.Request, listed.entries.find(e => e.seq === 4991).requestId);
    const signedIn = await auditFacts(page, 4987);
    assert.equal(signedIn.Who, 'admin (signed in)');
    assert.equal(signedIn.From, '192.0.2.10, Firefox on Linux');
    assert.equal((await auditFacts(page, 4999)).Who, 'Uptime Goblin');
    assert.equal((await auditFacts(page, 4998)).Target, 'source Plex (plex-1)');
    assert.equal(await page.eval("document.querySelector('#audit-unwritten').hidden"), true);

    // A summary from more than 1,000 clients; an earlier 1.5 build's local preview and
    // goblin-admin run with sudo as Who; a source whose name looks like markup, which reads as text and never becomes HTML
    // (spec §8.2: every value goes through esc()).
    const like = seq => structuredClone(listed.entries.find(e => e.seq === seq));
    const many = like(4997),
      markup = like(4998),
      local = like(4998),
      sudo = like(4998);
    Object.assign(many, { seq: 6004 });
    Object.assign(many.detail, { clients: 1000, more: true });
    Object.assign(markup, {
      seq: 6003,
      target: { type: 'source', id: 'plex-1', name: '<b>Plex</b>' },
    });
    Object.assign(local, { seq: 6002 });
    Object.assign(local.actor, { id: null, name: 'local', via: 'local', sessionId: null });
    Object.assign(sudo, {
      seq: 6001,
      action: 'key.rotate',
      status: null,
      requestId: null,
      target: { type: 'keyring', id: null, name: null },
      detail: { purposes: ['audit'], retired: 1, active: 'k2' },
      actor: {
        type: 'cli',
        id: null,
        name: 'cli:dana (sudo as orbit)',
        via: 'cli',
        sessionId: null,
        client: null,
        userAgent: null,
      },
    });
    reply = () => ({ body: { ...listed, entries: [many, markup, local, sudo] } });
    await refreshAudit(page);
    assert.deepEqual(await auditHeads(page), [
      [
        '7 more refused sign-ins: wrong name or password (6), too many failed attempts (1)',
        'Failed',
      ],
      ['Tested the connection to <b>Plex</b>: connected', 'Succeeded'],
      ['Tested the connection to Plex: connected', 'Succeeded'],
      ['goblin-admin rotated the data keys', 'Succeeded'],
    ]);
    assert.match(
      (await auditFacts(page, 6004)).Count,
      /^7 times between [^—]+ and [^—]+, from more than 1,000 different clients$/
    );
    assert.equal((await auditFacts(page, 6003)).Target, 'source <b>Plex</b> (plex-1)');
    assert.equal(await page.eval("document.querySelectorAll('#audit-list b').length"), 0);
    assert.equal((await auditFacts(page, 6002)).Who, 'Local preview');
    assert.equal((await auditFacts(page, 6001)).Who, 'goblin-admin as dana (sudo as orbit)');

    // Entries Uptime Goblin could not write since it started.
    reply = () => auditList('list.unwritten');
    await refreshAudit(page);
    assert.match(
      await text(page, '#audit-unwritten'),
      /^Uptime Goblin could not write 1 audit entry since [^—]+\. Uptime Goblin's log holds them, in lines that start with \{"orbit":"audit\.unwritten"\}; a change among them shows "Outcome unknown"\.$/
    );
    assert.equal(await page.eval("document.querySelector('#audit-unwritten').hidden"), false);

    // Unavailable: Uptime Goblin's own words for its 503, and a request without an answer.
    reply = () => auditError('audit_read_unavailable');
    await refreshAudit(page);
    assert.equal(
      await text(page, '#audit-list'),
      'Uptime Goblin could not read its audit log. Try again in a moment.'
    );
    assert.equal(await page.eval("document.querySelector('#audit-retention').hidden"), true);
    assert.equal(await page.eval("document.querySelector('#audit-unwritten').hidden"), true);
    reply = () => ({ drop: true });
    await refreshAudit(page);
    assert.equal(
      await text(page, '#audit-list'),
      'The audit log is unavailable: Uptime Goblin is not answering.'
    );
    assert.deepEqual(await cspViolations(page), []);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  '"filters": the period, kind, outcome and who filters build the list’s query, which stays out of the address',
  { skip },
  async () => {
    mock.audit = () => auditList('list.entries');
    const page = await openAudit();
    const near = (from, span) => Math.abs(Number(from) - (Date.now() - span)) < minuteMs;
    let query = auditReads().at(-1);
    // Last 7 days, and nothing else, by default.
    assert.ok(near(query.get('from'), 7 * 86400000), query.get('from'));
    assert.deepEqual([...query.keys()], ['from']);
    assert.deepEqual(
      await page.eval(
        "['#audit-period', '#audit-kind', '#audit-outcome', '#audit-actor'].map(s => document.querySelector(s).value)"
      ),
      ['7d', '', '', '']
    );
    // Each filter has a visible label.
    assert.deepEqual(
      await page.eval(
        "['audit-period', 'audit-kind', 'audit-outcome', 'audit-actor'].map(id => document.querySelector(`label[for=${id}]`)?.textContent)"
      ),
      ['Period', 'Kind', 'Outcome', 'Who']
    );
    assert.deepEqual(await allText(page, '#audit-period option'), [
      'Last 24 hours',
      'Last 7 days',
      'Last 30 days',
      'Last 90 days',
      'All kept entries',
    ]);
    assert.deepEqual(await allText(page, '#audit-outcome option'), [
      'Any',
      'Succeeded',
      'Refused',
      'Failed',
      'Changed elsewhere',
      'Recorded',
      'Outcome unknown',
    ]);
    assert.deepEqual(await allText(page, '#audit-actor option'), [
      'Anyone',
      'The admin',
      'Not signed in',
      'Uptime Goblin',
      'goblin-admin',
    ]);
    const choose = async (selector, value) => {
      const before = auditReads().length;
      await setValue(page, selector, value);
      await auditReadsReach(page, before + 1);
      return auditReads().at(-1);
    };
    query = await choose('#audit-period', '24h');
    assert.ok(near(query.get('from'), 86400000));
    query = await choose('#audit-kind', 'account.,identity.');
    assert.equal(query.get('action'), 'account.,identity.');
    assert.ok(near(query.get('from'), 86400000));
    query = await choose('#audit-outcome', 'unknown');
    assert.equal(query.get('outcome'), 'unknown');
    query = await choose('#audit-actor', 'cli');
    assert.equal(query.get('actor'), 'cli');
    for (const [period, days] of [
      ['30d', 30],
      ['90d', 90],
    ]) {
      query = await choose('#audit-period', period);
      assert.ok(near(query.get('from'), days * 86400000), period);
    }
    query = await choose('#audit-period', 'all');
    assert.deepEqual(Object.fromEntries(query), {
      action: 'account.,identity.',
      outcome: 'unknown',
      actor: 'cli',
    });
    assert.equal(await page.eval('location.hash'), '#configure/audit');
    assert.deepEqual(await cspViolations(page), []);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  '"kinds": the Kind options, taken together, reach every action Uptime Goblin records',
  { skip },
  async () => {
    const page = await openAudit();
    const options = await page.eval(
      "[...document.querySelectorAll('#audit-kind option')].map(o => [o.value, o.textContent])"
    );
    assert.deepEqual(
      options.map(([, label]) => label),
      [
        'All',
        'Sign-in and sessions',
        'Account and password',
        'Scripts with a password',
        'Refused requests',
        'Workspace settings',
        'Sources',
        'Changed outside Uptime Goblin',
        'Email test',
        'Notifications',
        'Webhook signing key',
        'Exports',
        'Uptime Goblin itself',
        'goblin-admin',
        'Audit log',
      ]
    );
    assert.equal(options[0][0], '');
    const items = [];
    for (const [value, label] of options.slice(1)) {
      const list = value.split(',');
      // As GET /api/audit takes them (spec §6.2).
      assert.ok(list.length >= 1 && list.length <= 8, label);
      for (const item of list) assert.match(item, /^[a-z][a-z0-9.-]{0,63}$/, label);
      items.push(...list);
    }
    for (const action of Object.keys(ACTIONS))
      assert.ok(
        items.some(item => (item.endsWith('.') ? action.startsWith(item) : action === item)),
        `no Kind lists ${action}`
      );
    assert.deepEqual(page.exceptions, []);
  }
);

// One sample of each kind of row an action has, with the details Uptime Goblin gives it (spec §5): every
// outcome of every action is among them, and none reads "Recorded: …". `expect` is the sentence
// §8.2's table gives a row whose words depend on more than its outcome (a cause, a summary, a
// code, the release that opened the data): a string for each of its outcomes, or one per outcome.
function textSamples(now) {
  const aggregate = (codes, count, expect) => [
    {
      codes,
      clients: 2,
      more: false,
      sample: ['192.0.2.20', '192.0.2.21'],
      from: now - 1000,
      to: now,
    },
    { count, expect },
  ];
  const attempt = ['attempt', 'unknown', 'ok', 'conflict', 'failed', 'denied'];
  const delivery = ['attempt', 'unknown', 'ok', 'denied', 'failed'];
  const source = { target: { type: 'source', id: 'plex-1', name: 'Plex' } };
  const channel = { target: { type: 'channel', id: 'env-webhook', name: null } };
  const display = { target: { type: 'display', id: 'd_AbCdEfGhIjKlMnOp', name: 'Lobby TV' } };
  const admin = { target: { type: 'account', id: 'u_admin', name: null } };
  return [
    ['session.login', ['ok'], { persistent: true, transport: 'https', ended: 1 }],
    [
      'session.login',
      ['failed', 'denied'],
      { code: 'invalid_credentials', login: 'admin' },
      { expect: 'Sign-in refused: wrong name or password' },
    ],
    [
      'session.login',
      ['failed', 'denied'],
      ...aggregate(
        { invalid_credentials: 3, locked: 1 },
        4,
        '4 more refused sign-ins: wrong name or password (3), too many failed attempts (1)'
      ),
    ],
    ['session.logout', ['ok'], { cause: 'signout' }, { expect: 'Signed out' }],
    [
      'session.logout',
      ['ok'],
      { cause: 'presented' },
      { expect: 'Signed out a session this browser presented' },
    ],
    [
      'session.logout',
      ['ok'],
      { cause: 'ended' },
      { expect: 'Signed out a session that had already ended elsewhere' },
    ],
    [
      'session.logout',
      ['failed'],
      { code: 'storage_full' },
      { expect: 'Sign-out could not be saved: the disk is full' },
    ],
    ['session.revoked', ['ok'], { cause: 'by_user' }, { expect: 'Signed out another device' }],
    [
      'session.revoked',
      ['ok'],
      { cause: 'insecure_cookie' },
      { expect: "Signed out this browser's plain-HTTP session" },
    ],
    [
      'session.revoked',
      ['info'],
      { cause: 'insecure_http_off', count: 2 },
      { expect: 'Signed out 2 plain-HTTP sessions: plain-HTTP sign-in was switched off' },
    ],
    [
      'session.revoked',
      ['info'],
      { cause: 'retried', count: 3 },
      { expect: 'Removed 3 signed-out sessions that could not be removed before' },
    ],
    [
      'session.revoked',
      ['info'],
      { cause: 'ended_part_way', count: 2 },
      { expect: 'Removed 2 sessions signed out by a session that ended before it could save that' },
    ],
    ['session.revoked-others', ['ok'], { count: 2, kept: 1 }],
    [
      'session.revoked-restore',
      ['info'],
      { cause: 'credentials_anchor', displayCodes: 2 },
      { expect: 'Removed 2 display credentials: the credential restore boundary changed' },
    ],
    [
      'session.revoked-restore',
      ['info'],
      { cause: 'snapshot', snapshot: 'manual-1' },
      { expect: 'Signed everyone out: the data was restored from snapshot manual-1' },
    ],
    [
      'session.revoked-restore',
      ['info'],
      { cause: 'control_file', snapshot: null },
      { expect: 'Signed everyone out: control.sqlite was restored from a backup, copied or moved' },
    ],
    ['account.password.changed', ['ok'], { revokedOtherSessions: 1, newSessionId: 's_new' }],
    [
      'account.password.changed',
      ['failed', 'denied'],
      { code: 'password_mismatch' },
      { expect: 'Password change refused: the new password and its confirmation differ' },
    ],
    [
      'account.password.changed',
      ['failed', 'denied'],
      ...aggregate(
        { locked: 2 },
        2,
        '2 more refused password changes: too many failed attempts (2)'
      ),
    ],
    [
      'account.password.changed-outside',
      ['info'],
      { source: 'auth.json' },
      { expect: 'The admin password was changed outside Uptime Goblin (auth.json)' },
    ],
    [
      'account.password.changed-outside',
      ['info'],
      { source: 'env' },
      { expect: 'The admin password was changed outside Uptime Goblin (GOBLIN_PASSWORD)' },
    ],
    [
      'account.password.changed-outside',
      ['info'],
      { source: 'control.sqlite' },
      { expect: 'The admin password was changed by an earlier Uptime Goblin 1.5 build' },
    ],
    [
      'account.bootstrap',
      ['info'],
      { source: 'auth.json' },
      { expect: 'Set up the admin account with the password from auth.json' },
    ],
    [
      'account.bootstrap',
      ['info'],
      { source: 'env' },
      { expect: 'Set up the admin account with GOBLIN_PASSWORD' },
    ],
    [
      'account.bootstrap',
      ['info'],
      { source: 'none' },
      { expect: 'Set up the admin account without a password (local preview)' },
    ],
    ['account.claimed', ['info'], {}],
    ['identity.mirror.failed', ['failed'], { code: 'storage_full' }],
    [
      'auth.basic.failed',
      ['failed', 'denied'],
      { code: 'retired_password', login: 'other' },
      { expect: 'Script sign-in refused: an old password was used' },
    ],
    [
      'auth.basic.failed',
      ['failed', 'denied'],
      ...aggregate(
        { basic_disabled: 5 },
        5,
        '5 more refused script sign-ins: script sign-in is turned off (5)'
      ),
    ],
    [
      'auth.step-up',
      ['denied'],
      { code: 'step_up_failed' },
      { expect: 'Request refused by step-up or lockdown: the password entered again was wrong' },
    ],
    [
      'auth.step-up',
      ['denied'],
      ...aggregate(
        { admin_ui_locked: 3 },
        3,
        '3 more requests refused by step-up or lockdown: the action is turned off in the web app (GOBLIN_ADMIN_UI_LOCK) (3)'
      ),
    ],
    [
      'auth.forbidden',
      ['denied'],
      { code: 'forbidden' },
      { expect: 'Request refused by authorization: the account may not do this' },
    ],
    [
      'auth.forbidden',
      ['denied'],
      ...aggregate(
        { forbidden: 4 },
        4,
        '4 more requests refused by authorization: the account may not do this (4)'
      ),
    ],
    ['auth.basic.used', ['ok'], {}, { expect: 'A script signed in with the password' }],
    [
      'auth.basic.used',
      ['ok'],
      ...aggregate({}, 9, 'Scripts signed in with the password 9 more times'),
    ],
    [
      'settings.update',
      attempt,
      { ifMatch: true, code: 'storage_full' },
      {
        expect: {
          attempt: 'Change of workspace settings: in progress',
          unknown: 'Change of workspace settings: outcome unknown',
          ok: 'Changed workspace settings',
          conflict: 'Change of workspace settings: refused, changed elsewhere first',
          failed: 'Change of workspace settings: failed (the disk is full)',
          denied: 'Change of workspace settings: refused (the disk is full)',
        },
      },
    ],
    [
      'settings.update',
      ['ok', 'failed'],
      { ifMatch: false },
      {
        expect: {
          ok: 'Changed workspace settings',
          failed: 'Change of workspace settings: failed',
        },
      },
    ],
    [
      'source.create',
      attempt,
      { ifMatch: false, code: 'revision_conflict' },
      {
        ...source,
        expect: {
          ok: 'Added source Plex',
          failed: 'Adding source Plex: failed (Uptime Goblin error revision_conflict)',
        },
      },
    ],
    [
      'source.update',
      attempt,
      { ifMatch: true, credentialsCleared: true, code: 'x' },
      {
        ...source,
        expect: {
          ok: 'Changed source Plex',
          failed: 'Change of source Plex: failed (Uptime Goblin error x)',
        },
      },
    ],
    [
      'source.delete',
      attempt,
      { ifMatch: true, historyDeleted: true, code: 'y' },
      {
        ...source,
        expect: {
          ok: 'Deleted source Plex',
          failed: 'Deleting source Plex: failed (Uptime Goblin error y)',
        },
      },
    ],
    [
      'source.test',
      ['ok'],
      { type: 'plex', savedCredentials: true, result: 'connected' },
      { ...source, expect: 'Tested the connection to Plex: connected' },
    ],
    [
      'source.test',
      ['failed'],
      { result: 'failed' },
      { ...source, expect: 'Tested the connection to Plex: it failed' },
    ],
    [
      'source.test',
      ['failed'],
      { result: 'timeout' },
      { ...source, expect: 'Tested the connection to Plex: it timed out' },
    ],
    [
      'source.test',
      ['denied'],
      { code: 'cross_origin' },
      {
        ...source,
        expect: "Connection test of Plex refused (the page address did not match Uptime Goblin's)",
      },
    ],
    ['email.test', ['ok'], { accepted: true }],
    ['email.test', ['failed'], { accepted: false }],
    ['email.test', ['denied'], { code: 'email_busy' }],
    ['email.test', ['conflict'], {}],
    ['sources.refresh', ['ok'], {}],
    ['sources.refresh', ['denied', 'failed'], { code: 'client_closed' }],
    [
      'sources.import',
      attempt,
      { ifMatch: true, added: 4, changed: 1, skipped: 2, code: 'z' },
      {
        target: { type: 'sources', id: 'uptime-kuma', name: null },
        expect: {
          ok: 'Imported from Uptime Kuma: 4 added, 1 changed, 2 skipped',
          failed: 'Import from Uptime Kuma: failed (Uptime Goblin error z)',
        },
      },
    ],
    [
      'delivery.retry',
      delivery,
      { retried: 2, code: 'delivery_not_retryable' },
      {
        expect: {
          ok: 'Retried a notification (2 queued again)',
          failed: 'Retry of a notification: failed (Uptime Goblin error delivery_not_retryable)',
        },
      },
    ],
    [
      'channel.resume',
      delivery,
      { released: 3, code: 'channel_paused' },
      {
        ...channel,
        expect: {
          ok: 'Resumed the env-webhook channel (3 released)',
          failed: 'Resuming the env-webhook channel: failed (Uptime Goblin error channel_paused)',
        },
      },
    ],
    [
      'channel.settings',
      ['ok'],
      { diff: [{ path: 'token', change: 'set' }] },
      {
        target: { type: 'channel', id: 'ntfy', name: null },
        expect: 'Changed the ntfy channel settings',
      },
    ],
    [
      'channel.test',
      ['ok', 'failed', 'denied', 'conflict'],
      { accepted: true, code: 'channel_not_set_up' },
      {
        target: { type: 'channel', id: 'gotify', name: null },
        expect: {
          ok: 'Sent a test notification on gotify: it was accepted',
          failed: 'Sent a test notification on gotify: it was not accepted',
          denied: 'Test notification on gotify refused (Uptime Goblin error channel_not_set_up)',
          conflict: 'Test notification on gotify not sent (Uptime Goblin error channel_not_set_up)',
        },
      },
    ],
    [
      'signing.reveal',
      delivery,
      { shown: true, code: 'reveal_rate_limited' },
      {
        expect: {
          ok: 'Showed the webhook signing secret',
          failed:
            'Showing the webhook signing secret: failed (Uptime Goblin error reveal_rate_limited)',
        },
      },
    ],
    // As rotate() writes it since review F1 (test/audit/noop.test.mjs pins the same paths).
    [
      'signing.rotate',
      ['ok'],
      {
        diff: [
          { path: 'signingKey', change: 'changed' },
          { path: 'previousSigningKey', change: 'set' },
        ],
      },
    ],
    [
      'signing.created',
      ['info'],
      { replaced: false },
      { expect: 'Created the webhook signing key' },
    ],
    [
      'signing.created',
      ['info'],
      { replaced: true },
      { expect: 'Created a new webhook signing key: the old one could not be read' },
    ],
    ['channel.paused', ['info'], { reason: 'HTTP 401', transient: false }, channel],
    ['channel.working', ['info'], {}, channel],
    ['notifications.unsaved', ['info'], {}],
    ['notifications.saved', ['info'], {}],
    ['config.export', ['ok'], { sources: 3, bytes: 2048 }],
    ['audit.export', ['ok'], { format: 'csv', rows: 12, more: false, filters: {} }],
    [
      'config.changed-outside',
      ['info'],
      { from: 4, to: 5, diff: [], repaired: false },
      { expect: 'Settings were changed outside Uptime Goblin (config.json)' },
    ],
    [
      'config.changed-outside',
      ['info'],
      { from: 4, to: 5, diff: [], repaired: true },
      { expect: 'Settings were changed outside Uptime Goblin or repaired at start (config.json)' },
    ],
    [
      'system.start',
      ['info'],
      { version: '1.5.0-dev.2', first: true, cleanStop: false },
      { expect: 'Uptime Goblin 1.5.0-dev.2 started for the first time' },
    ],
    [
      'system.start',
      ['info'],
      { version: '1.5.0-dev.2', first: false, cleanStop: false },
      {
        expect:
          'Uptime Goblin 1.5.0-dev.2 started; its previous stop was not recorded (a crash, or a stop while the disk was full)',
      },
    ],
    [
      'system.start',
      ['info'],
      { version: '1.5.0-dev.2', first: false, cleanStop: true, securityChanged: ['legacyBasic'] },
      {
        expect:
          'Uptime Goblin 1.5.0-dev.2 started; security settings from the environment changed: legacyBasic',
      },
    ],
    ['system.stop', ['info'], { uptimeMs: 1000 }],
    [
      'system.upgrade',
      ['info'],
      { release: '1.5.0-dev.2', entries: [{ from: null, to: '1.5.0-dev.2', at: now }] },
      { expect: 'Uptime Goblin 1.5.0-dev.2 opened this data' },
    ],
    [
      'system.upgrade',
      ['info'],
      {
        release: '1.5.0-dev.2',
        entries: [
          { from: '1.5.0-dev.1', to: '1.4.3', at: now },
          { from: '1.4.3', to: '1.5.0-dev.2', at: now },
        ],
        markerLost: true,
      },
      {
        expect:
          'Uptime Goblin 1.5.0-dev.2 found that 2 releases opened this data: 1.4.3, 1.5.0-dev.2 (some may be missing)',
      },
    ],
    [
      'system.restore',
      ['info'],
      { cause: 'snapshot', snapshot: 'manual-1', at: now, restoredHead: null },
      { expect: "Uptime Goblin's data was restored from snapshot manual-1" },
    ],
    [
      'system.restore',
      ['info'],
      { cause: 'control_file', restoredHead: { seq: 3, hash: 'h' } },
      { expect: 'control.sqlite was replaced: a restore from a backup, a copy or a move' },
    ],
    [
      'data.snapshot',
      ['info'],
      { reason: 'manual', createdAt: now, more: 2 },
      {
        target: { type: 'snapshot', id: 'manual-1', name: null },
        expect: 'Snapshot manual-1 was taken (manual) and 2 older ones',
      },
    ],
    [
      'display.code.created',
      ['ok'],
      { expiresAt: now + 600e3 },
      { ...display, expect: 'Created a display code for wall display Lobby TV' },
    ],
    [
      'display.code.cancelled',
      ['ok', 'info'],
      { cause: 'cancelled' },
      { ...display, expect: 'Cancelled display code Lobby TV' },
    ],
    [
      'display.code.cancelled',
      ['info'],
      { cause: 'cancelled', late: true },
      {
        ...display,
        expect: 'Cancelled display code Lobby TV (recorded when Uptime Goblin next ran)',
      },
    ],
    [
      'display.code.cancelled',
      ['info'],
      { cause: 'plain_http' },
      { ...display, expect: 'Cancelled display code Lobby TV: it was sent over plain HTTP' },
    ],
    [
      'display.code.cancelled',
      ['ok'],
      { cause: 'cancelled', count: 3 },
      { ...admin, expect: 'Cancelled 3 waiting display codes' },
    ],
    [
      'display.code.cancelled',
      ['ok'],
      { cause: 'password_change', count: 2 },
      { ...admin, expect: 'Cancelled 2 waiting display codes: the admin password changed' },
    ],
    [
      'audit.gap',
      ['info'],
      { reason: 'head-mismatch', head: null, lastSeq: 2 },
      { expect: 'Uptime Goblin found its audit log cut or changed at the end' },
    ],
    [
      'audit.gap',
      ['info'],
      { reason: 'inbox-discarded', count: 2 },
      { expect: 'Uptime Goblin discarded 2 entries left in the audit inbox by an earlier start' },
    ],
    [
      'audit.pruned',
      ['info'],
      { through: 100, deleted: 100, reason: 'age' },
      { expect: 'Removed 100 audit entries older than the retention period' },
    ],
    [
      'audit.pruned',
      ['info'],
      { through: 100, deleted: 100, reason: 'cap' },
      { expect: 'Removed 100 audit entries to stay within 250,000' },
    ],
    [
      'audit.pruned',
      ['info'],
      { through: 100, deleted: 100, reason: 'both' },
      {
        expect:
          'Removed 100 audit entries older than the retention period and to stay within 250,000',
      },
    ],
    [
      'key.rewrap',
      ['ok'],
      { rewrapped: 2 },
      { expect: 'goblin-admin re-wrapped the data keys under the current encryption key' },
    ],
    // A rewrap with nothing to do says so (docs audit, audit 23).
    [
      'key.rewrap',
      ['ok'],
      { rewrapped: 0 },
      {
        expect:
          'goblin-admin key rewrap found every data key already wrapped under the current encryption key; nothing changed',
      },
    ],
    [
      'key.rewrap',
      ['failed'],
      { code: 'key_mismatch' },
      { expect: 'goblin-admin key rewrap failed (Uptime Goblin error key_mismatch)' },
    ],
    ['key.rotate', ['ok'], { purposes: ['audit'], retired: 1, active: 'k2' }],
    ['key.rotate', ['failed'], { code: 'failed' }],
    ['key.reset', ['ok'], { lostKeyIds: ['k1'], head: null }],
    // --unused deletes an older key, not a copy (docs audit, keys 21).
    [
      'key.remove-data-copy',
      ['ok'],
      { unused: true },
      {
        expect:
          'goblin-admin deleted an older encryption key, which Uptime Goblin no longer used, from the data directory',
      },
    ],
    [
      'key.remove-data-copy',
      ['ok'],
      { unused: false },
      { expect: 'goblin-admin deleted the copy of the encryption key in the data directory' },
    ],
    ['key.remove-data-copy', ['failed'], { code: 'unlink_failed' }],
  ].map(([action, outcomes, detail, extra = {}]) => ({ action, outcomes, detail, ...extra }));
}

test(
  '"texts": the page’s texts are the server’s, every action and outcome has its sentence, and every refusal code has words',
  { skip },
  async () => {
    const page = await openAudit();
    const module = `import(${js(`/assets/${web.build}/modules/configure/audit.js`)})`;
    // The copy in public/modules/configure/audit.js is lib/audit/actions.mjs's, exactly.
    const plain = value => JSON.parse(JSON.stringify(value));
    assert.deepEqual(
      JSON.parse(
        await page.eval(
          `${module}.then(m => JSON.stringify({ AUDIT_TEXTS: m.AUDIT_TEXTS, CODE_WORDS: m.CODE_WORDS, PROBLEM_TEXTS: m.PROBLEM_TEXTS, UNVERIFIABLE_TEXTS: m.UNVERIFIABLE_TEXTS, ANCHOR_TEXTS: m.ANCHOR_TEXTS }))`
        )
      ),
      plain({ AUDIT_TEXTS, CODE_WORDS, PROBLEM_TEXTS, UNVERIFIABLE_TEXTS, ANCHOR_TEXTS })
    );
    const now = Date.now();
    const samples = textSamples(now);
    const rows = samples.flatMap(({ action, outcomes, detail, target = null, count = 1 }) =>
      outcomes.map(outcome => ({ seq: 1, time: now, action, outcome, detail, target, count }))
    );
    const expected = samples.flatMap(({ outcomes, expect }) =>
      outcomes.map(outcome => (typeof expect === 'string' ? expect : expect?.[outcome]))
    );
    const sentences = await page.eval(
      `${module}.then(m => ${js(rows)}.map(row => m.entrySentence(row)))`
    );
    rows.forEach((row, i) => {
      const where = `${row.action} ${row.outcome} ${JSON.stringify(row.detail)}: ${sentences[i]}`;
      assert.doesNotMatch(sentences[i], /^Recorded: /, where);
      assert.doesNotMatch(sentences[i], /—|undefined|null|NaN|\[object|[{}]/, where);
      // The rule that picks the sentence picks §8.2's.
      if (expected[i] !== undefined) assert.equal(sentences[i], expected[i], where);
    });
    // Every action whose sentence depends on more than its outcome (a cause, a summary, a code,
    // the releases that opened the data) has its sentences checked above.
    const outcomeOnly = when =>
      when === '*' ||
      when
        .split('|')
        .every(term =>
          ['ok', 'denied', 'failed', 'conflict', 'info', 'attempt', 'unknown'].includes(term)
        );
    for (const [action, { texts, suffixes }] of Object.entries(AUDIT_TEXTS))
      if ([...texts, ...suffixes].some(([when]) => !outcomeOnly(when)))
        assert.ok(
          rows.some((row, i) => row.action === action && expected[i] !== undefined),
          `no expected sentence for ${action}`
        );
    // Every outcome of every action, and "unknown" for the attempts, has a sample above.
    for (const [action, { outcomes }] of Object.entries(ACTIONS))
      for (const outcome of [...outcomes, ...(outcomes.includes('attempt') ? ['unknown'] : [])])
        assert.ok(
          rows.some(row => row.action === action && row.outcome === outcome),
          `${action} ${outcome}`
        );
    // A refused sign-in, password change, script sign-in and request (authorization, step-up or
    // lockdown) name the reason in words (§5.2).
    const codes = {
      'session.login': [
        'invalid_credentials',
        'locked',
        'busy',
        'https_required',
        'proxy_proto_missing',
        'proxy_proto_mismatch',
        'cross_origin',
        'signin_unavailable',
        'invalid_request',
        'storage_full',
      ],
      'account.password.changed': [
        'current_password_incorrect',
        'password_invalid',
        'password_mismatch',
        'change_in_progress',
        'signin_required',
        'session_expired',
        'session_newer',
        'invalid_request',
        'cross_origin',
        'storage_full',
      ],
      'auth.basic.failed': [
        'invalid_credentials',
        'retired_password',
        'locked',
        'busy',
        'basic_disabled',
        'multiple_credentials',
      ],
      'auth.step-up': [
        'step_up_required',
        'step_up_failed',
        'step_up_unavailable',
        'admin_ui_locked',
      ],
      'auth.forbidden': ['forbidden'],
    };
    const refusals = Object.entries(codes).flatMap(([action, list]) =>
      [...list, 'client_closed', 'delivery_not_found'].map(code => ({
        seq: 1,
        time: now,
        action,
        outcome: 'denied',
        detail: { code },
        target: null,
        count: 1,
      }))
    );
    const refused = await page.eval(
      `${module}.then(m => ${js(refusals)}.map(row => m.entrySentence(row)))`
    );
    const words = JSON.parse(await page.eval(`${module}.then(m => JSON.stringify(m.CODE_WORDS))`));
    refusals.forEach(({ action, detail: { code } }, i) => {
      if (code === 'delivery_not_found')
        return assert.match(refused[i], / Uptime Goblin error delivery_not_found$/);
      assert.ok(Object.hasOwn(words, code), `${code} has words`);
      assert.ok(refused[i].endsWith(`: ${words[code]}`), `${action} ${code}: ${refused[i]}`);
    });
    assert.deepEqual(page.exceptions, []);
  }
);

test('"refresh": Refresh reads the first page again and keeps the focus', { skip }, async () => {
  let reply = () => auditList('list.more');
  mock.audit = () => reply();
  const page = await openAudit();
  assert.equal(await page.eval("document.querySelector('#audit-more').hidden"), false);
  await page.eval("document.querySelector('#audit-refresh').focus()");
  reply = () => auditList('list.entries', {}, 6000);
  const before = auditReads().length;
  await pressKey(page, 'Enter');
  await auditReadsReach(page, before + 1);
  assert.equal(auditReads().at(-1).get('cursor'), null);
  assert.equal(
    await page.eval("document.querySelectorAll('#audit-list > li.audit-entry').length"),
    11
  );
  assert.equal(await page.eval("document.querySelector('#audit-more').hidden"), true);
  assert.equal(await focused(page), '#audit-refresh');
  assert.deepEqual(page.exceptions, []);
});

test(
  '"load more": Load more appends the next page, keeps rows and cursor when it fails and says so, and moves the focus as the delivery history does',
  { skip },
  async () => {
    let reply = () => auditList('list.more');
    mock.audit = () => reply();
    const page = await openAudit();
    const rows = () =>
      page.eval(
        "[...document.querySelectorAll('#audit-list > li.audit-entry')].map(li => li.dataset.id)"
      );
    assert.deepEqual(await rows(), ['5000', '4999']);
    const first = auditReads().at(-1);
    await page.eval("document.querySelector('#audit-more').focus()");
    const press = async () => {
      const before = auditReads().length;
      await pressKey(page, 'Enter');
      await auditReadsReach(page, before + 1);
      await page.waitFor("document.querySelector('#audit-more').disabled === false");
      await page.settle();
      return auditReads().at(-1);
    };
    // A dropped connection, then Uptime Goblin's 503: the rows and the cursor stay, and a line says so.
    reply = () => ({ drop: true });
    let query = await press();
    assert.equal(query.get('cursor'), '4998');
    assert.equal(query.get('from'), first.get('from'), 'the same entries, read on');
    assert.deepEqual(await rows(), ['5000', '4999']);
    assert.equal(
      await text(page, '#audit-more-result'),
      'The audit log is unavailable: Uptime Goblin is not answering. Older entries were not read: press Load more to try again.'
    );
    assert.equal(
      await page.eval("document.querySelector('#audit-more-result').getAttribute('role')"),
      'status'
    );
    assert.equal(await focused(page), '#audit-more');
    reply = () => auditError('audit_read_unavailable');
    query = await press();
    assert.equal(query.get('cursor'), '4998');
    assert.equal(
      await text(page, '#audit-more-result'),
      'Uptime Goblin could not read its audit log. Try again in a moment. Older entries were not read: press Load more to try again.'
    );
    assert.equal(await focused(page), '#audit-more');
    // The last page, which repeats an entry already listed (written between the two reads).
    reply = () => {
      const last = auditList('list.entries', {}, 4998);
      last.body.entries.unshift(concreteBody('list.more', { now: Date.now() }).entries[1]);
      return last;
    };
    query = await press();
    assert.equal(query.get('cursor'), '4998');
    const shown = await rows();
    assert.equal(shown.length, 13);
    assert.equal(new Set(shown).size, 13, 'each entry once');
    assert.equal(await page.eval("document.querySelector('#audit-more').hidden"), true);
    assert.equal(await page.eval("document.querySelector('#audit-more-result').hidden"), true);
    // Load more went with the last page: the focus is on the first entry it added.
    assert.equal(await focused(page), '4998');

    // A last page that adds nothing (older entries were pruned meanwhile): the last entry.
    reply = () => auditList('list.more');
    await refreshAudit(page);
    await page.eval("document.querySelector('#audit-more').focus()");
    reply = () => auditList('list.empty');
    await press();
    assert.equal(await page.eval("document.querySelector('#audit-more').hidden"), true);
    assert.equal(await focused(page), '4999');
    assert.deepEqual(await cspViolations(page), []);
    assert.deepEqual(page.exceptions, []);
  }
);

test('"stale": an answer to an older read never replaces a newer one', { skip }, async () => {
  let reply = () => auditList('list.empty');
  mock.audit = () => reply();
  const page = await openAudit();
  reply = () => ({ ...auditList('list.entries'), delay: 600 });
  await page.eval("document.querySelector('#audit-refresh').click()");
  // The slow read is on its way (not settled: it must still be unanswered when the filter
  // changes).
  while (auditReads().length < 2) await delay(10);
  reply = () => auditList('list.more');
  await setValue(page, '#audit-kind', 'session.,display.');
  while (auditReads().length < 3) await delay(10);
  await page.waitFor("document.querySelectorAll('#audit-list > li.audit-entry').length === 2");
  assert.equal(mock.inflight, 1, 'the first read is still unanswered');
  // The slow first answer arrives last, and is dropped.
  await page.settle();
  await delay(100);
  assert.deepEqual(
    await page.eval(
      "[...document.querySelectorAll('#audit-list > li.audit-entry')].map(li => li.dataset.id)"
    ),
    ['5000', '4999']
  );
  assert.equal(await page.eval("document.querySelector('#audit-more').hidden"), false);
  assert.deepEqual(page.exceptions, []);
});

test(
  '"401": a list read refused after Cancel stops reading, and signing in again reads it',
  { skip },
  async () => {
    mock.routes.set('GET /api/audit', () => auditList('list.entries'));
    onlySignedIn();
    const page = await open('#configure/overview');
    mock.signedIn = false;
    await page.eval("location.hash = '#configure/audit'");
    await page.waitFor(isOpen('signin-dialog'));
    await settled(page, 'signin-dialog');
    await page.click('#reauth-cancel');
    await page.waitFor(`!${isOpen('signin-dialog')}`);
    await page.settle();
    await delay(300);
    assert.equal(auditReads().length, 1, 'no second read');
    assert.equal(await text(page, '#audit-list'), sessionEnded);
    assert.equal(await page.eval("document.querySelector('#audit-more').hidden"), true);
    // Signed in again: the page reads its entries.
    await page.waitFor("document.querySelector('#configuration-notice').hidden === false");
    await page.eval("document.querySelector('#configuration-sign-in').click()");
    await page.waitFor(isOpen('signin-dialog'));
    await settled(page, 'signin-dialog');
    await submitSignIn(page, 'reauth');
    await page.waitFor("document.querySelectorAll('#audit-list > li.audit-entry').length === 11");
    assert.equal(auditReads().length, 2);
    assert.deepEqual(await cspViolations(page), []);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  '"details": Show details opens by keyboard with what changed, a secret only as changed, and the truncation; the clients of a summary',
  { skip },
  async () => {
    mock.audit = () => auditList('list.entries');
    const page = await openAudit();
    const toggle = '#audit-4989-toggle';
    await page.eval("document.querySelector('#audit-refresh').focus()");
    await tabTo(page, toggle);
    assert.deepEqual(
      await page.eval(
        `(b => [b.textContent, b.getAttribute('aria-expanded'), b.getAttribute('aria-controls'), document.getElementById(b.getAttribute('aria-controls')).hidden])(document.querySelector('${toggle}'))`
      ),
      ['Show details', 'false', 'audit-4989-details', true]
    );
    await pressKey(page, 'Enter');
    await page.settle();
    assert.equal(
      await page.eval(`document.querySelector('${toggle}').getAttribute('aria-expanded')`),
      'true'
    );
    assert.equal(await page.eval("document.querySelector('#audit-4989-details').hidden"), false);
    assert.equal(await text(page, toggle), 'Hide details');
    assert.equal(await focused(page), toggle);
    assert.deepEqual(await allText(page, '#audit-4989-details .audit-diff li'), [
      'email.host: smtp.example.com → mail.example.com',
      'email.password: changed',
    ]);
    assert.equal(
      await text(page, '#audit-4989-details .audit-diff-note'),
      'Only the first 2 of 41 changes are shown.'
    );
    const facts = await auditFacts(page, 4989, '.audit-details > .audit-facts');
    assert.equal(facts.Entry, '#4,989');
    assert.equal(facts.Attempt, 'entry #4,988');
    assert.equal(facts['Configuration revision'], '41');
    assert.equal(facts['Based on the version shown (If-Match)'], 'Yes');
    assert.equal(
      facts.Browser,
      'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0'
    );
    // Refresh keeps it open.
    await refreshAudit(page);
    assert.equal(await page.eval("document.querySelector('#audit-4989-details').hidden"), false);
    // Space closes it.
    await page.eval(`document.querySelector('${toggle}').focus()`);
    await pressKey(page, ' ');
    await page.settle();
    assert.equal(await page.eval("document.querySelector('#audit-4989-details').hidden"), true);
    assert.equal(
      await page.eval(`document.querySelector('${toggle}').getAttribute('aria-expanded')`),
      'false'
    );
    assert.equal(await focused(page), toggle);
    // A summary's sampled clients; an immediate refusal's reason and login class.
    await page.eval("document.querySelector('#audit-4997-toggle').click()");
    assert.deepEqual(await allText(page, '#audit-4997-details .audit-sample li'), [
      '192.0.2.20',
      '192.0.2.21',
      '198.51.100.7',
    ]);
    await page.eval("document.querySelector('#audit-4996-toggle').click()");
    const refusal = await auditFacts(page, 4996, '.audit-details > .audit-facts');
    assert.equal(refusal.Reason, 'wrong name or password (invalid_credentials)');
    assert.equal(refusal['Login name'], 'admin');
    // A stop's uptime reads "Uptime" with the unit its value carries, never "Uptime ms: 2.5 h";
    // a start whose security settings did not change stores `securityChanged: []` (every start
    // after the first audited one), which shows no empty "Security changed" fact (review round 1).
    const listed = concreteBody('list.entries', { now: Date.now() });
    const started = listed.entries.find(entry => entry.action === 'system.start');
    mock.audit = () => ({
      body: {
        ...listed,
        nextCursor: null,
        entries: [
          { ...started, seq: 6002, detail: { ...started.detail, securityChanged: [] } },
          {
            ...started,
            seq: 6001,
            action: 'system.stop',
            configRevision: null,
            detail: { uptimeMs: 9000000 },
          },
        ],
      },
    });
    await refreshAudit(page);
    await page.eval("document.querySelector('#audit-6001-toggle').click()");
    await page.eval("document.querySelector('#audit-6002-toggle').click()");
    const stop = await auditFacts(page, 6001, '.audit-details > .audit-facts');
    assert.equal(stop.Uptime, '2.5 h', JSON.stringify(stop));
    assert.ok(!Object.hasOwn(stop, 'Uptime ms'), JSON.stringify(stop));
    const restart = await auditFacts(page, 6002, '.audit-details > .audit-facts');
    assert.ok(!Object.hasOwn(restart, 'Security changed'), JSON.stringify(restart));
    assert.ok(
      Object.values(restart).every(value => value !== ''),
      `no fact without a value: ${JSON.stringify(restart)}`
    );
    assert.equal(restart.Version, '1.5.0-dev.2');
    assert.deepEqual(await auditHeads(page), [
      ['Uptime Goblin 1.5.0-dev.2 started', 'Recorded'],
      ['Uptime Goblin stopped', 'Recorded'],
    ]);
    assert.deepEqual(await cspViolations(page), []);
    assert.deepEqual(page.exceptions, []);
  }
);

// A verification text as the page should show it: the catalogue's template with the result's
// values, entry numbers grouped, any time as whatever the page shows (it uses its time zone).
function verifyPattern(template, values, whenNull = {}) {
  const parts = template.split(/(#?\{[A-Za-z. ]+\})/);
  return parts
    .map((part, index) => {
      if (index % 2 === 0) return part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const hash = part.startsWith('#') ? '#' : '',
        name = part.slice(hash.length + 1, -1);
      const value = name.split('.').reduce((v, key) => v?.[key], values);
      if (value === null && name in whenNull) return whenNull[name];
      if (['time', 'at', 'lineTime'].includes(name)) return '[^—#]+';
      const shown = typeof value === 'number' ? value.toLocaleString('en-US') : String(value);
      return `${hash}${shown}`.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    })
    .join('');
}
const anchorPatterns = anchor => {
  switch (anchor.action) {
    case 'system.restore':
      return [
        verifyPattern(
          ANCHOR_TEXTS[`system.restore.${anchor.cause}${anchor.restoredHead ? '' : '.empty'}`],
          anchor
        ),
      ];
    case 'audit.gap':
      return [verifyPattern(ANCHOR_TEXTS[`audit.gap.${anchor.reason}`], anchor)];
    case 'key.reset':
      return [verifyPattern(ANCHOR_TEXTS[anchor.head ? 'key.reset' : 'key.reset.empty'], anchor)];
    default:
      return [
        ...(anchor.markerLost
          ? [verifyPattern(ANCHOR_TEXTS['system.upgrade.markerLost'], anchor)]
          : []),
        ...anchor.entries.map(entry =>
          verifyPattern(
            ANCHOR_TEXTS[entry.to === anchor.release ? 'system.upgrade' : 'system.upgrade.other'],
            entry
          )
        ),
      ];
  }
};

test(
  '"integrity": Check integrity says what Uptime Goblin found, in the catalogue’s words, lists every anchor, joins a check on its way and keeps the focus',
  { skip },
  async () => {
    let reply = () => ({ body: concreteBody('verify.empty', { now: Date.now() }) });
    mock.auditVerify = () => reply();
    const page = await openAudit();
    assert.equal(
      await page.eval("document.querySelector('#audit-verify-result').getAttribute('role')"),
      'status'
    );
    const verifyReads = () => requests('GET', '/api/audit/verify').length;
    const check = async () => {
      const before = verifyReads();
      await page.eval("document.querySelector('#audit-verify').focus()");
      await pressKey(page, 'Enter');
      while (verifyReads() === before) await delay(10);
      await page.waitFor(
        "!document.querySelector('#audit-verify-result').textContent.startsWith('Checking')"
      );
      await page.settle();
      assert.equal(await focused(page), '#audit-verify');
      return allText(page, '#audit-verify-result p, #audit-verify-result li');
    };
    const expect = (lines, patterns, what) => {
      assert.equal(lines.length, patterns.length, `${what}: ${JSON.stringify(lines)}`);
      lines.forEach((line, i) =>
        assert.match(line, new RegExp(`^${patterns[i]}$`), `${what} line ${i + 1}`)
      );
    };
    assert.deepEqual(await check(), ['The audit log is empty: there is nothing to check yet.']);

    // While it runs it says so; a second press joins it.
    reply = () => ({ body: concreteBody('verify.intact', { now: Date.now() }), delay: 500 });
    await page.eval("document.querySelector('#audit-verify').focus()");
    await pressKey(page, 'Enter');
    await page.waitFor(
      "document.querySelector('#audit-verify-result').textContent === 'Checking the audit log… A large log can take a minute.'"
    );
    await pressKey(page, 'Enter');
    assert.equal(await page.eval("document.querySelector('#audit-verify').disabled"), false);
    await page.waitFor(
      "document.querySelector('#audit-verify-result').textContent.startsWith('The audit log is intact')"
    );
    await page.settle();
    assert.equal(verifyReads(), 2, 'one request for both presses');
    const intact = concreteBody('verify.intact', { now: Date.now() });
    expect(
      await allText(page, '#audit-verify-result p, #audit-verify-result li'),
      [
        `The audit log is intact: 12 entries checked, from #${intact.rows.first.seq.toLocaleString('en-US')} \\([^—]+\\) to #${intact.rows.last.seq.toLocaleString('en-US')} \\([^—]+\\)\\.`,
      ],
      'intact'
    );
    assert.equal(await focused(page), '#audit-verify');

    // Every anchor of an intact log.
    const anchors = concreteBody('verify.anchors', { now: Date.now() });
    reply = () => ({ body: anchors });
    expect(
      await check(),
      [
        'The audit log is intact: 40 entries checked, from #[0-9,]+ \\([^—]+\\) to #[0-9,]+ \\([^—]+\\)\\.',
        ...anchors.anchors.flatMap(anchorPatterns),
      ],
      'anchors'
    );
    // Each reason that leaves it not fully checked.
    for (const reason of ['key_reset', 'newer_format', 'restore_unchecked']) {
      const result = concreteBody(`verify.incomplete.${reason}`, { now: Date.now() });
      reply = () => ({ body: result });
      expect(
        await check(),
        [
          'Nothing was found changed, but not everything could be checked:',
          ...result.unverifiable.map(item =>
            verifyPattern(UNVERIFIABLE_TEXTS[item.reason], {
              ...item,
              'restore words': item.cause
                ? UNVERIFIABLE_TEXTS[`restore.${item.cause}`].replace('{snapshot}', item.snapshot)
                : undefined,
            })
          ),
          ...result.anchors.flatMap(anchorPatterns),
        ],
        reason
      );
    }
    // Each problem that makes it changed, with its message and consequence.
    const changed = (problem, whenNull) =>
      `The audit log was changed\\. ${verifyPattern(PROBLEM_TEXTS[problem.code].message, problem, whenNull)} ${verifyPattern(PROBLEM_TEXTS[problem.code].consequence, problem, whenNull)} Compare it with Uptime Goblin's log using goblin-admin verify-audit --checkpoints\\.`;
    const codes = Object.keys(auditBody('verify.broken'));
    assert.equal(codes.length, 12);
    for (const code of codes) {
      const result = concreteBody(`verify.broken.${code}`, { now: Date.now() });
      reply = () => ({ body: result });
      expect(
        await check(),
        [changed(result.problem, {}), ...result.anchors.flatMap(anchorPatterns)],
        code
      );
    }
    // log_truncated when the head was missing and the log empty.
    const truncated = concreteBody('verify.broken.log_truncated', { now: Date.now() });
    Object.assign(truncated.problem, { head: null, lastSeq: null });
    reply = () => ({ body: truncated });
    const [line] = await check();
    assert.match(line, /it had last written an unknown entry, and the log ended at no entry\./);
    assert.match(line, /Entries Uptime Goblin wrote after no entry are missing/);
    // head_mismatch when the log holds rows but Uptime Goblin's head is gone: the head reads as
    // log_truncated's does, as goblin-admin verify-audit words it.
    const headless = concreteBody('verify.broken.head_mismatch', { now: Date.now() });
    headless.problem.head = null;
    reply = () => ({ body: headless });
    const [lost] = await check();
    assert.match(
      lost,
      new RegExp(
        `^The audit log was changed\\. The log ends at entry #${headless.problem.seq.toLocaleString('en-US')}, but Uptime Goblin last wrote an unknown entry: entries were removed from the end\\. `
      )
    );
    // A check that outlasts the page's time limit (150 s, cut to 100 ms here; every other timer
    // as it is) says so, long before Uptime Goblin answers, and the focus stays on the button.
    await page.eval(`(() => {
      const realSetTimeout = window.setTimeout;
      window.__realSetTimeout = realSetTimeout;
      window.setTimeout = (fn, ms, ...rest) => realSetTimeout(fn, ms === 150000 ? 100 : ms, ...rest);
    })()`);
    reply = () => ({ body: concreteBody('verify.intact', { now: Date.now() }), delay: 5000 });
    const started = Date.now();
    assert.deepEqual(await check(), [
      'Uptime Goblin did not finish the check in time. Try again; a check of a very large log can take longer than the page waits.',
    ]);
    assert.ok(Date.now() - started < 2000, `ended after ${Date.now() - started} ms`);
    await page.eval('window.setTimeout = window.__realSetTimeout');
    // Unavailable: Uptime Goblin's own words; the focus stays on the button.
    reply = () => auditError('audit_read_unavailable');
    assert.deepEqual(await check(), [
      'Uptime Goblin could not read its audit log. Try again in a moment.',
    ]);
    reply = () => ({ drop: true });
    assert.deepEqual(await check(), [
      'The audit log is unavailable: Uptime Goblin is not answering.',
    ]);
    assert.deepEqual(await cspViolations(page), []);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  '"exports": Export CSV and NDJSON download Uptime Goblin’s bytes with its file name and the filters, say how many, and download nothing for none',
  { skip },
  async () => {
    // The last answer sent, whose bytes the download must be.
    let sent = null;
    let reply = () => auditExport('export.csv');
    mock.auditExport = () => (sent = reply());
    mock.audit = () => auditList('list.entries');
    const page = await openAudit();
    await recordToasts(page);
    await setValue(page, '#audit-kind', 'session.,display.');
    await auditReadsReach(page, 2);
    const exports = () => mock.requests.filter(r => r.path === '/api/audit/export');
    const press = async (button, count) => {
      const before = exports().length;
      await page.eval(`document.querySelector('${button}').focus()`);
      await pressKey(page, 'Enter');
      while (exports().length === before) await delay(10);
      await page.waitFor(`document.querySelector('${button}').disabled === false`);
      await page.waitFor(`window.__toasts.length === ${count}`);
      await page.settle();
      assert.equal(await focused(page), button);
      return exports().at(-1);
    };
    let request = await press('#audit-export-csv', 1);
    assert.equal(request.url.searchParams.get('format'), 'csv');
    assert.equal(request.url.searchParams.get('action'), 'session.,display.');
    assert.ok(
      Math.abs(Number(request.url.searchParams.get('from')) - (Date.now() - 7 * 86400000)) <
        minuteMs
    );
    assert.equal(request.headers['x-goblin-request'], '1');
    await page.waitFor(
      'window.__downloads.length === 1 && window.__downloads[0].text !== null && window.__blobBytes[0]?.hex'
    );
    const download = await page.eval('window.__downloads[0]');
    assert.match(download.name, /^uptime-goblin-audit-\d{8}-\d{6}Z\.csv$/);
    assert.equal(download.type, 'text/csv; charset=utf-8');
    // The bytes as Uptime Goblin sent them: the byte order mark first.
    const hex = await page.eval('window.__blobBytes[0].hex');
    assert.ok(hex.startsWith('efbbbf'), hex.slice(0, 12));
    assert.equal(hex, Buffer.from(sent.entry.body, 'utf8').toString('hex'));
    assert.equal(await page.eval('window.__toasts.at(-1)'), 'Exported 2 entries.');

    reply = () => auditExport('export.ndjson');
    request = await press('#audit-export-ndjson', 2);
    assert.equal(request.url.searchParams.get('format'), 'ndjson');
    await page.waitFor('window.__downloads.length === 2 && window.__downloads[1].text !== null');
    const ndjson = await page.eval('window.__downloads[1]');
    assert.match(ndjson.name, /^uptime-goblin-audit-\d{8}-\d{6}Z\.ndjson$/);
    assert.equal(ndjson.type, 'application/x-ndjson; charset=utf-8');
    assert.equal(ndjson.text, sent.entry.body);
    assert.equal(await page.eval('window.__toasts.at(-1)'), 'Exported 2 entries.');

    // Older entries left out. Every Period counts back from now, so the toast never sends the admin
    // to a shorter one (which exports fewer of the same newest entries, review round 1): it
    // names what reaches further back.
    reply = () => auditExport('export.csv', { more: true });
    request = await press('#audit-export-csv', 3);
    assert.equal(
      await page.eval('window.__toasts.at(-1)'),
      'Exported the newest 2 entries; older ones were left out. Narrow Kind, Outcome or Who to reach further back, or export them from a script with to= (docs/architecture.md).'
    );
    assert.equal(request.url.searchParams.get('to'), null, 'no Period sets an upper bound');
    assert.equal(await page.eval('window.__downloads.length'), 3);
    // None: nothing is downloaded.
    reply = () => {
      const none = auditExport('export.csv', { rows: 0 });
      none.raw = none.raw.split('\r\n')[0] + '\r\n';
      return none;
    };
    await press('#audit-export-csv', 4);
    assert.equal(
      await page.eval('window.__toasts.at(-1)'),
      'There are no entries to export for these filters.'
    );
    await delay(100);
    assert.equal(await page.eval('window.__downloads.length'), 3);
    // Refused: Uptime Goblin's words, nothing downloaded.
    reply = () => auditError('audit_unavailable');
    await press('#audit-export-csv', 5);
    assert.equal(
      await page.eval('window.__toasts.at(-1)'),
      auditBody('error.audit_unavailable').body.error
    );
    assert.equal(await page.eval('window.__downloads.length'), 3);
    assert.deepEqual(await cspViolations(page), []);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  '"system line": while legacy Basic is allowed, the System page links to the Audit log’s "Scripts with a password"',
  { skip },
  async () => {
    mock.routes.set('GET /api/system', () => ({ body: systemBody() }));
    mock.sessionBody = () => identity.session('session', { legacyBasic: false });
    const page = await open('#configure/system');
    await page.waitFor("document.querySelector('#system-details .system-facts')");
    assert.equal(await page.eval("!!document.querySelector('#system-legacy-basic')"), false);
    await closeNewest();

    mock.sessionBody = () => identity.session('session', { legacyBasic: true });
    const basic = await open('#configure/system');
    await basic.waitFor("document.querySelector('#system-legacy-basic')");
    assert.equal(
      await text(basic, '#system-legacy-basic'),
      'Scripts with a password (legacy Basic): allowed. See which scripts use it under Configure → Audit log, Kind: Scripts with a password.'
    );
    await basic.eval("document.querySelector('#system-legacy-basic a').focus()");
    await pressKey(basic, 'Enter');
    await basic.waitFor(`document.querySelector('#audit-list') && !(${auditReading})`);
    await basic.settle();
    assert.equal(await basic.eval('location.hash'), '#configure/audit');
    assert.equal(await basic.eval("document.querySelector('#audit-kind').value"), 'auth.basic.');
    assert.equal(auditReads().at(-1).get('action'), 'auth.basic.');
    // Opened from the navigation, the Audit log starts with every kind again.
    await basic.eval(
      'document.querySelector(\'#configuration-nav a[href="#configure/account"]\').click()'
    );
    await basic.waitFor("location.hash === '#configure/account'");
    await basic.eval(
      'document.querySelector(\'#configuration-nav a[href="#configure/audit"]\').click()'
    );
    await basic.waitFor(`document.querySelector('#audit-kind') && !(${auditReading})`);
    assert.equal(await basic.eval("document.querySelector('#audit-kind').value"), '');
    assert.deepEqual(await cspViolations(basic), []);
    assert.deepEqual(basic.exceptions, []);
  }
);

test(
  '"360 px": the Audit log fits a phone, long values wrapping, and is used by keyboard there',
  { skip },
  async () => {
    const list = concreteBody('list.entries', { now: Date.now() });
    const long = list.entries.find(e => e.action === 'source.test');
    long.target.name = `Source${'x'.repeat(150)}`;
    long.actor.userAgent = `curl/${'8'.repeat(190)}`;
    const diff = list.entries.find(e => e.action === 'settings.update' && e.outcome === 'ok');
    diff.detail.diff.push({
      path: `services.${'y'.repeat(100)}.url`,
      from: 'https://a.example.com/' + 'z'.repeat(150),
      to: 'f'.repeat(64),
    });
    mock.audit = () => ({ body: list });
    const anchors = concreteBody('verify.anchors', { now: Date.now() });
    anchors.anchors[3].snapshot = `manual-${'s'.repeat(150)}`;
    mock.auditVerify = () => ({ body: anchors });
    const width = 360;
    const page = await openOnPhone(width, '#configure/audit');
    await page.waitFor("document.querySelectorAll('#audit-list > li.audit-entry').length === 11");
    await page.eval(`document.querySelector('#audit-${diff.seq}-toggle').focus()`);
    await pressKey(page, 'Enter');
    await page.eval(`document.querySelector('#audit-${long.seq}-toggle').click()`);
    await page.eval("document.querySelector('#audit-verify').focus()");
    await pressKey(page, 'Enter');
    await page.waitFor(
      "document.querySelector('#audit-verify-result').textContent.startsWith('The audit log is intact')"
    );
    await page.settle();
    const layout = await page.eval(`({
      scrollWidth: document.documentElement.scrollWidth,
      wide: [
        ...[...document.querySelectorAll('body *')]
          .filter(e => e.getClientRects().length)
          .filter(e => e.getBoundingClientRect().right > ${width} + 0.5 || e.getBoundingClientRect().left < -0.5)
          .map(e => e.id || e.className || e.localName),
        ...(() => {
          const out = [], walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
          for (let node; (node = walker.nextNode()); ) {
            const range = document.createRange();
            range.selectNodeContents(node);
            for (const r of range.getClientRects())
              if (r.width && (r.right > ${width} + 0.5 || r.left < -0.5))
                out.push('text: ' + node.textContent.trim().slice(0, 40) + ' in ' + (node.parentElement.id || node.parentElement.className || node.parentElement.localName));
          }
          return out;
        })(),
      ].slice(0, 8),
      tables: document.querySelectorAll('#configuration-content table').length,
    })`);
    assert.deepEqual(layout, { scrollWidth: width, wide: [], tables: 0 });
    assert.equal(await focused(page), '#audit-verify');
    assert.deepEqual(await cspViolations(page), []);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'K3 regression: caller headers cannot override activity in a real browser',
  { skip },
  async () => {
    mock.routes.set('GET /api/version', () => ({ body: { version: '1.5.0', build: web.build } }));
    mock.routes.set('POST /api/refresh', () => ({ body: { ok: true } }));
    for (const mode of ['', '?kiosk=1']) {
      const page = await open(mode);
      await page.eval(`import(${js(`/assets/${web.build}/modules/core/api.js`)}).then(async ({ api }) => {
      for (const headers of [{ 'x-Orbit-Activity': 'background', 'If-Match': '7' }, new Headers({ 'X-Goblin-Activity': 'background', 'If-Match': '7' }), [['X-Goblin-Activity','background'],['x-goblin-activity','foreground'],['If-Match','7']]]) {
        await api('/api/version', { headers });
        await api('/api/refresh', { method: 'POST', background: true, headers });
      }
    })`);
      for (const request of requests('GET', '/api/version').slice(-3)) {
        assert.equal(request.headers['x-goblin-activity'], mode ? 'background' : undefined);
        assert.equal(request.headers['if-match'], '7');
      }
      for (const request of requests('POST', '/api/refresh').slice(-3)) {
        assert.equal(request.headers['x-goblin-activity'], undefined);
        assert.equal(request.headers['if-match'], '7');
        assert.ok(request.headers['idempotency-key']);
      }
      assert.deepEqual(page.exceptions, []);
    }
  }
);

test(
  'B6 regression: expired old admin kiosk returns to code form, not password dialog',
  { skip },
  async () => {
    const page = await open('?kiosk=1');
    mock.signedIn = false;
    await page.eval('window.__poll()');
    await page.waitFor("document.querySelector('#display-form')?.hidden === false", 8000);
    assert.equal(await page.eval("document.querySelector('#signin-dialog').open"), false);
    assert.equal(await page.eval('location.search'), '?kiosk=1');
    assert.deepEqual(page.exceptions, []);
  }
);
