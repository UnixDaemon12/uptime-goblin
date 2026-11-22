import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { createApp, startupExitCode } from '../../server.mjs';
import { createRouter, RouteError } from '../../lib/http/router.mjs';
import {
  routeTable,
  reservedPaths,
  supportedAuth,
  supportedFeatures,
} from '../../lib/http/routes.mjs';
import { readinessRoute } from '../../lib/http/routes/health.mjs';
import { createPipeline } from '../../lib/http/pipeline.mjs';
import { adminFetch, adminPassword } from '../helpers/admin.mjs';

// Route factories only keep references, so a table can be built without a running Uptime Goblin.
const table = () =>
  routeTable({
    nonce: 'n',
    site: { build: '000000000000', publicFiles: new Map(), indexPage: Buffer.from('') },
  });
// As server.mjs builds it.
const router = () =>
  createRouter(table(), {
    reserved: reservedPaths,
    auth: supportedAuth,
    supports: supportedFeatures,
  });

test('every route declares how it is reached and what it needs (golden table)', () => {
  const routes = router().routes.map(r =>
    [
      r.method + (r.head ? '+HEAD' : ''),
      r.path,
      r.auth,
      String(r.permission),
      r.csrf ? 'csrf' : '-',
      r.idempotent ? 'replayable' : '-',
      `ifMatch:${r.ifMatch}`,
      `audit:${r.audit}`,
      r.bodyLimit,
    ].join(' ')
  );
  assert.deepEqual(routes, [
    'GET+HEAD /health public null - - ifMatch:none audit:none 0',
    'POST /api/auth/login public null csrf - ifMatch:none audit:identity 4096',
    'POST /api/auth/logout session session:self csrf - ifMatch:none audit:identity 64',
    'GET /api/session session session:self - - ifMatch:none audit:none 0',
    'POST /api/account/password session account:self csrf - ifMatch:none audit:identity 4096',
    'POST /api/auth/password session account:self csrf - ifMatch:none audit:identity 4096',
    'GET /api/account/sessions session account:self - - ifMatch:none audit:none 0',
    'DELETE /api/account/sessions session account:self csrf - ifMatch:none audit:identity 64',
    'DELETE /api/account/sessions/:id session account:self csrf - ifMatch:none audit:identity 64',
    'GET /api/dashboard session dashboard:read - - ifMatch:none audit:none 0',
    'GET /api/version session dashboard:read - - ifMatch:none audit:none 0',
    'GET /api/system session system:read - - ifMatch:none audit:none 0',
    'GET /api/config/export session config:export - - ifMatch:none audit:export 0',
    'GET /api/docs session dashboard:read - - ifMatch:none audit:none 0',
    'GET /api/history/:id session dashboard:read - - ifMatch:none audit:none 0',
    'PATCH /api/settings session settings:write csrf replayable ifMatch:optional audit:config 150000',
    'POST /api/email/test session settings:write csrf replayable ifMatch:none audit:operation 150000',
    'POST /api/test-service session sources:test csrf replayable ifMatch:none audit:operation 150000',
    'POST /api/services session sources:write csrf replayable ifMatch:optional audit:config 150000',
    'PATCH /api/services/:id session sources:write csrf replayable ifMatch:optional audit:config 150000',
    'DELETE /api/services/:id session sources:write csrf replayable ifMatch:optional audit:config 64',
    'POST /api/refresh session sources:operate csrf replayable ifMatch:none audit:operation 64',
    // The Uptime Kuma import: a preview that is neither replayed nor recorded, and the apply, one
    // configuration change that needs the previewed revision.
    'POST /api/import/uptime-kuma/preview session config:import csrf - ifMatch:none audit:none 150000',
    'POST /api/import/uptime-kuma session config:import csrf replayable ifMatch:required audit:config 150000',
    // Delivery (delivery spec §6.4). The webhook's public key is public material, read with the
    // narrowest read of notification settings and not recorded; no route reveals a secret.
    'GET /api/notifications session notifications:read - - ifMatch:none audit:none 0',
    'GET /api/notifications/deliveries session notifications:read - - ifMatch:none audit:none 0',
    'POST /api/notifications/deliveries/:uid/retry session notifications:operate csrf replayable ifMatch:none audit:delivery 1024',
    'POST /api/notifications/channels/:id/resume session notifications:operate csrf replayable ifMatch:none audit:channel 1024',
    'GET /api/notifications/webhook/public-key session notifications:read - - ifMatch:none audit:none 0',
    // ntfy and Gotify: their settings are read with the read of configuration (tokens and
    // passwords only as set or not), changed in the settings store's unit with their audit row,
    // and tested with the saved settings.
    'GET /api/notifications/channels/:id/settings session config:read - - ifMatch:none audit:none 0',
    'PATCH /api/notifications/channels/:id/settings session channels:write csrf replayable ifMatch:none audit:secret 16384',
    'POST /api/notifications/channels/:id/test session channels:write csrf replayable ifMatch:none audit:operation 1024',
    'POST /api/notifications/webhook/signing-secret session channels:write csrf replayable ifMatch:none audit:secret 1024',
    // The audit log (audit spec §6.1): read and checked unrecorded; an export is recorded.
    'GET /api/audit session audit:read - - ifMatch:none audit:none 0',
    'GET /api/audit/export session audit:read - - ifMatch:none audit:export 0',
    'GET /api/audit/verify session audit:read - - ifMatch:none audit:none 0',
    'GET+HEAD / public null - - ifMatch:none audit:none 0',
    'GET+HEAD /index.html public null - - ifMatch:none audit:none 0',
    'GET+HEAD /assets/:build/* public null - - ifMatch:none audit:none 0',
    'GET+HEAD /* public null - - ifMatch:none audit:none 0',
  ]);
  const summaries = Object.fromEntries(
    router()
      .routes.filter(
        r =>
          r.audit === 'identity' ||
          r.permission === 'account:self' ||
          r.permission === 'session:self'
      )
      .map(r => [`${r.method} ${r.path}`, r.summary])
  );
  assert.deepEqual(summaries, {
    'POST /api/auth/login': 'Sign in as the built-in admin; sets the session cookie',
    'POST /api/auth/logout': 'Sign out this session',
    'GET /api/session': 'Who is signed in, how, and until when',
    'POST /api/account/password':
      'Change your password (needs the current one); signs out your other sessions',
    'POST /api/auth/password': 'Deprecated alias of POST /api/account/password',
    'GET /api/account/sessions': 'Your sessions',
    'DELETE /api/account/sessions': 'Sign out your other sessions',
    'DELETE /api/account/sessions/:id': 'Sign out one session',
  });
  for (const route of router().routes) {
    assert.ok(route.summary.length > 5, route.path);
    // Only the 1.4.x password address is deprecated (its answers say so), and no route asks
    // for a protection that is not enforced.
    assert.deepEqual(
      route.headers,
      route.path === '/api/auth/password' ? { Deprecation: '@1790812800' } : {},
      route.path
    );
    assert.equal(route.stepUp, false, route.path);
    assert.equal(route.schema, undefined, route.path);
    assert.equal(route.bodyPermissions, undefined, route.path);
  }
  assert.deepEqual(supportedFeatures, []);
});

test('generated 405s name exactly the methods the 1.4.3 hand-written list named', () => {
  // server.mjs 1.4.3, the list the table replaces, and the 1.5 sign-in and account routes.
  const known = [
    [/^\/api\/auth\/(password|login|logout)$/, 'POST'],
    [/^\/api\/account\/password$/, 'POST'],
    [/^\/api\/session$/, 'GET'],
    [/^\/api\/account\/sessions$/, 'GET, DELETE'],
    [/^\/api\/account\/sessions\/[\w-]+$/, 'DELETE'],
    [/^\/api\/(dashboard|system|config\/export|docs|version)$/, 'GET'],
    [/^\/api\/(test-service|email\/test|services|refresh)$/, 'POST'],
    [/^\/api\/settings$/, 'PATCH'],
    [/^\/api\/services\/[\w-]+$/, 'PATCH, DELETE'],
    [/^\/api\/history\/[\w-]+$/, 'GET'],
    // 1.5 delivery (delivery spec §6.4).
    [/^\/api\/notifications(\/deliveries)?$/, 'GET'],
    [/^\/api\/notifications\/deliveries\/[\w-]+\/retry$/, 'POST'],
    [/^\/api\/notifications\/channels\/[\w-]+\/resume$/, 'POST'],
    [/^\/api\/notifications\/channels\/[\w-]+\/settings$/, 'GET, PATCH'],
    [/^\/api\/notifications\/channels\/[\w-]+\/test$/, 'POST'],
    [/^\/api\/notifications\/webhook\/signing-secret$/, 'POST'],
    [/^\/api\/notifications\/webhook\/public-key$/, 'GET'],
    // 1.5 audit (audit spec §6.1).
    [/^\/api\/audit(\/export|\/verify)?$/, 'GET'],
    // The Uptime Kuma import.
    [/^\/api\/import\/uptime-kuma(\/preview)?$/, 'POST'],
  ];
  const { match } = router();
  const paths = [
    '/api/auth/password',
    '/api/auth/login',
    '/api/auth/logout',
    '/api/account/password',
    '/api/session',
    '/api/account/sessions',
    '/api/account/sessions/s_AbCdEfGhIjKlMnOp',
    '/api/dashboard',
    '/api/system',
    '/api/config/export',
    '/api/docs',
    '/api/version',
    '/api/test-service',
    '/api/email/test',
    '/api/services',
    '/api/refresh',
    '/api/settings',
    '/api/services/linux',
    '/api/services/a_b-2',
    '/api/history/linux',
    '/api/notifications',
    '/api/notifications/deliveries',
    '/api/notifications/deliveries/d_abcdefghijklmnopqrstuvwxyz/retry',
    '/api/notifications/channels/email/resume',
    '/api/notifications/channels/env-webhook/resume',
    '/api/notifications/channels/ntfy/resume',
    '/api/notifications/channels/ntfy/settings',
    '/api/notifications/channels/gotify/settings',
    '/api/notifications/channels/ntfy/test',
    '/api/notifications/channels/gotify/test',
    '/api/notifications/webhook/signing-secret',
    '/api/notifications/webhook/public-key',
    '/api/audit',
    '/api/audit/export',
    '/api/audit/verify',
    '/api/import/uptime-kuma',
    '/api/import/uptime-kuma/preview',
  ];
  for (const pathname of paths) {
    const allow = known.find(([pattern]) => pattern.test(pathname))[1];
    for (const method of ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']) {
      const found = match(method, pathname);
      if (allow.split(', ').includes(method)) assert.ok(found.route, `${method} ${pathname}`);
      else assert.equal(found.allow, allow, `${method} ${pathname}`);
    }
  }
  // No API route exists beyond that list, and unknown API paths stay 404s.
  for (const route of router().routes.filter(r => r.path.startsWith('/api/')))
    assert.ok(
      known.some(([pattern]) => pattern.test(route.path.replace(/:\w+/g, 'x'))),
      route.path
    );
  for (const pathname of [
    '/api/nothing',
    '/api/',
    '/api/services/a/b',
    '/api/history/',
    '/api/auth',
    '/api/account/sessions/a/b',
    '/api/notifications/deliveries/d_abcdefghijklmnopqrstuvwxyz',
    '/api/notifications/channels/email',
    '/api/notifications/webhook',
    '/api/audit/',
    '/api/audit/list',
    '/api/audit/export/csv',
  ])
    assert.equal(match('GET', pathname), null, pathname);
  // The signing secret's reveal is gone: its path is unknown to every method, as any other
  // unknown path is (a 404 from the pipeline, never a 405 that would say it exists).
  for (const method of ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'])
    for (const pathname of [
      '/api/notifications/webhook/signing-secret/reveal',
      '/api/notifications/webhook/public-key/private',
    ])
      assert.equal(match(method, pathname), null, `${method} ${pathname}`);
});

test('a route table that cannot be served refuses the start with exit status 78', () => {
  const broken = [...table(), { method: 'GET', path: '/api/extra', auth: 'session' }];
  let error;
  try {
    createRouter(broken, { reserved: reservedPaths, auth: supportedAuth });
  } catch (e) {
    error = e;
  }
  assert.ok(error instanceof RouteError);
  assert.equal(startupExitCode(error), 78);
});

test('/health/ready is ready to be added: 200 while ready, 503 otherwise', async t => {
  let ready = true;
  const handle = createPipeline({
    router: createRouter([readinessRoute({ ready: () => ready })], { auth: supportedAuth }),
    identity: {},
    loginThrottle: null,
    release: { build: 'x', version: 'y' },
    allowedHost: () => true,
  });
  const server = http.createServer(handle);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const url = `http://127.0.0.1:${server.address().port}/health/ready`;
  assert.deepEqual(await (await fetch(url)).json(), { status: 'ok' });
  ready = false;
  const draining = await fetch(url);
  assert.equal(draining.status, 503);
  assert.deepEqual(await draining.json(), { status: 'unavailable' });
});

test('/api/system reports the same last collection as the dashboard without building it', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-routes-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const app = await createApp({
    directory,
    port: 0,
    password: adminPassword,
    allowedHosts: '',
    webhook: '',
    trustProxy: '',
    startScheduler: false,
  });
  const { port } = await app.listen();
  t.after(() => app.close());
  const system = async () =>
    (await (await adminFetch(`http://127.0.0.1:${port}/api/system`)).json()).collection
      .lastCollected;
  assert.equal(await system(), null);
  assert.equal(app.dashboard().lastCollected, null);
  const now = Date.now();
  app.store.record('linux', [{ key: 'cpu', label: 'CPU', value: 1, unit: '%' }], null, now - 5000);
  app.store.record('docker', [], 'unreachable', now - 1000);
  app.store.record(
    'proxmox',
    [{ key: 'cpu', label: 'CPU', value: 2, unit: '%' }],
    null,
    now - 3000
  );
  assert.equal(await system(), app.dashboard().lastCollected);
  assert.equal(await system(), now - 3000);
});

// GOBLIN_ALLOW_UNLIMITED lets a supervised Uptime Goblin start without a resource limit, a security
// control, so it is read only from Uptime Goblin's environment at its start (lib/resource-limits.mjs, in
// server.mjs's main block) and only shown: GET /api/system gives what that start found, rebuilt
// from its known fields, and nothing sets it. (The router answers a method /api/system does not
// take with 405 and Allow; it is not changed for this.)
test('the resource limits a supervised start found are shown by GET /api/system alone; no route sets them', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-routes-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const app = await createApp({
    directory,
    port: 0,
    password: adminPassword,
    allowedHosts: '',
    webhook: '',
    trustProxy: '',
    startScheduler: false,
    resourceLimits: {
      supervised: true,
      allowUnlimited: ['cpu', 'all'],
      limits: {
        memory: { state: 'enforced', detail: 'memory.max 1073741824', allowed: true },
        cpu: { state: 'missing', detail: 'cpu.max is max', allowed: true, more: 'dropped' },
        pids: { state: 'enforced', detail: 'pids.max 256' },
      },
      extra: 'dropped',
    },
  });
  const { port } = await app.listen();
  t.after(() => app.close());
  const shown = {
    supervised: true,
    allowUnlimited: ['cpu'],
    limits: {
      memory: { state: 'enforced', detail: 'memory.max 1073741824', allowed: false },
      cpu: { state: 'missing', detail: 'cpu.max is max', allowed: true },
      pids: { state: 'enforced', detail: 'pids.max 256', allowed: false },
    },
  };
  const base = `http://127.0.0.1:${port}`;
  const system = async () => (await (await adminFetch(`${base}/api/system`)).json()).resourceLimits;
  assert.deepEqual(await system(), shown);
  const write = (method, route, body) =>
    adminFetch(`${base}${route}`, {
      method,
      headers: { 'Content-Type': 'application/json', 'X-Goblin-Request': '1' },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  for (const method of ['PUT', 'POST', 'PATCH', 'DELETE']) {
    const answer = await write(method, '/api/system', method === 'DELETE' ? undefined : shown);
    assert.ok([404, 405].includes(answer.status), `${method} /api/system: ${answer.status}`);
  }
  // The settings take no such field: a save that gives one is refused, and nothing changes.
  for (const field of ['resourceLimits', 'allowUnlimited', 'GOBLIN_ALLOW_UNLIMITED']) {
    const answer = await write('PATCH', '/api/settings', { [field]: 'memory,cpu,pids' });
    assert.equal(answer.status, 400, `${field}: ${answer.status}`);
  }
  assert.deepEqual(await system(), shown);
  // Only GET /api/system shows them: no other route's path or summary names them.
  for (const route of router().routes)
    assert.doesNotMatch(
      `${route.method} ${route.path} ${route.summary}`,
      /limit|unlimited/i,
      `${route.method} ${route.path}`
    );
  // Only lib/resource-limits.mjs reads GOBLIN_ALLOW_UNLIMITED from an environment, and of the
  // HTTP code only the dashboard routes name resourceLimits (the answer's field, and the app's
  // frozen status it shows). Comments are left out of the comparison.
  const root = path.join(import.meta.dirname, '../..');
  const files = [
    'server.mjs',
    ...fs
      .readdirSync(path.join(root, 'lib'), { recursive: true })
      .filter(name => name.endsWith('.mjs'))
      .map(name => path.join('lib', name)),
  ];
  for (const file of files) {
    const code = fs
      .readFileSync(path.join(root, file), 'utf8')
      .replace(/\/\*[^]*?\*\/|\/\/.*$/gm, '');
    if (file !== path.join('lib', 'resource-limits.mjs'))
      assert.doesNotMatch(code, /\benv\b[^;\n]*GOBLIN_ALLOW_UNLIMITED/, file);
    if (file.startsWith(path.join('lib', 'http')))
      assert.equal(
        [...code.matchAll(/resourceLimits/g)].length,
        file === path.join('lib', 'http', 'routes', 'dashboard.mjs') ? 2 : 0,
        file
      );
  }
});
