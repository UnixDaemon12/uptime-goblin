// Uptime Goblin always requires an admin password (the maintainer's decision, 2026-11-12). 1.4.x and earlier 1.5 builds
// started without one as a "local preview" that served every request from this computer with
// full access; now a start without auth.json or GOBLIN_PASSWORD is refused, and no request but
// those of the routes the table declares 'public' is served without a credential.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { createApp, startupExitCode } from '../server.mjs';
import { passwordRequiredMessage } from '../lib/identity/index.mjs';
import { createRouter } from '../lib/http/router.mjs';
import {
  routeTable,
  reservedPaths,
  supportedAuth,
  supportedFeatures,
} from '../lib/http/routes.mjs';
import { adminPassword, basicAuth } from './helpers/admin.mjs';

function temporary(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-password-required-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}
// Every file below `directory` with its bytes (directories as such).
function fingerprint(directory) {
  const out = {};
  for (const name of fs.readdirSync(directory, { recursive: true }).sort()) {
    const file = path.join(directory, name);
    out[name] = fs.statSync(file).isDirectory() ? 'dir' : fs.readFileSync(file).toString('hex');
  }
  return out;
}
const options = { port: 0, allowedHosts: '', webhook: '', trustProxy: '', startScheduler: false };

/** Sends exactly `headers` (and Host, Connection) from 127.0.0.1; resolves {status, body}. */
function request(port, method, target, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        method,
        path: target,
        headers: { Host: `127.0.0.1:${port}`, Connection: 'close', ...headers },
        agent: false,
      },
      res => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', chunk => (body += chunk));
        res.on('end', () => resolve({ status: res.statusCode, body }));
      }
    );
    req.on('error', reject);
    req.end();
  });
}

test('a start without a password is refused (exit status 78) before anything is written', async t => {
  // A new install: the data directory is not even created.
  const fresh = path.join(temporary(t), 'data');
  for (const host of ['127.0.0.1', '::1', 'localhost', '0.0.0.0'])
    await assert.rejects(
      createApp({ ...options, directory: fresh, host, password: '' }),
      error => startupExitCode(error) === 78 && error.message === passwordRequiredMessage,
      host
    );
  assert.equal(fs.existsSync(fresh), false, 'no data directory');
  // 1.4.x data that ran as the local preview (no auth.json): left byte for byte, unlocked.
  const legacy = temporary(t);
  fs.writeFileSync(path.join(legacy, 'config.json'), '{"services":[]}\n', { mode: 0o600 });
  const before = fingerprint(legacy);
  await assert.rejects(
    createApp({ ...options, directory: legacy, password: '' }),
    error => startupExitCode(error) === 78 && error.message === passwordRequiredMessage
  );
  assert.deepEqual(fingerprint(legacy), before, 'no byte changed, no goblin.lock');
  // The message says how to set one; Uptime Goblin never makes one up.
  assert.match(passwordRequiredMessage, /Set GOBLIN_PASSWORD \(12 to 1024 characters\)/);
  assert.match(passwordRequiredMessage, /\/etc\/uptime-goblin\.env for a native install/);
  assert.match(passwordRequiredMessage, /\.env for npm start and Docker Compose/);
  assert.match(passwordRequiredMessage, /restore auth\.json from a backup/);
  // With a password the same data starts.
  const app = await createApp({ ...options, directory: legacy, password: adminPassword });
  await app.close();
});

test('without a credential only the public routes answer; every other route is 401, also header-less from this computer', async t => {
  const app = await createApp({ ...options, directory: temporary(t), password: adminPassword });
  const { port } = await app.listen();
  t.after(() => app.close());
  // The table server.mjs serves (the same routes; the factories only keep references).
  const { routes } = createRouter(
    routeTable({
      nonce: 'n',
      site: { build: '000000000000', publicFiles: new Map(), indexPage: Buffer.from('') },
    }),
    { reserved: reservedPaths, auth: supportedAuth, supports: supportedFeatures }
  );
  const target = route =>
    route.path.replace(/:[a-z]+/g, 'linux').replace(/\*$/, 'x') +
    (route.path === '/api/history/:id' ? '?range=24h' : '');
  const signedIn = routes.filter(route => route.auth !== 'public');
  assert.ok(signedIn.length >= 25, `${signedIn.length} signed-in routes`);
  assert.deepEqual(
    routes.filter(route => route.auth === 'public').map(route => `${route.method} ${route.path}`),
    [
      'GET /health',
      'POST /api/auth/login',
      'GET /',
      'GET /index.html',
      'GET /assets/:build/*',
      'GET /*',
    ]
  );
  // Header-less (only Host), a page's same-origin request, a write with the request header, and
  // a proxied one: none is served, each is told to sign in.
  const shapes = [
    {},
    { 'Sec-Fetch-Site': 'same-origin', 'X-Goblin-Client': 'web/test' },
    {
      'X-Goblin-Request': '1',
      'Content-Type': 'application/json',
      Origin: `http://127.0.0.1:${port}`,
    },
    { 'X-Forwarded-For': '203.0.113.9', 'X-Forwarded-Proto': 'https' },
  ];
  for (const route of signedIn)
    for (const headers of shapes) {
      const answer = await request(port, route.method, target(route), headers);
      const label = `${route.method} ${target(route)} ${JSON.stringify(headers)}`;
      assert.equal(answer.status, 401, label);
      assert.equal(JSON.parse(answer.body).code, 'signin_required', label);
    }
  // HEAD of a signed-in read is not served either.
  assert.equal((await request(port, 'HEAD', '/api/dashboard')).status, 401);
  // The public routes answer without one: readiness, the web app (its sign-in page) and its files.
  assert.equal((await request(port, 'GET', '/health')).status, 200);
  assert.equal((await request(port, 'GET', '/')).status, 200);
  assert.equal((await request(port, 'GET', '/index.html')).status, 200);
  // The admin password signs a script in to the same routes.
  const dashboard = await request(port, 'GET', '/api/dashboard', {
    Authorization: basicAuth(),
  });
  assert.equal(dashboard.status, 200);
});
