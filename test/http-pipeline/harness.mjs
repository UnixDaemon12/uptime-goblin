// A pipeline with the real sign-in and account routes over the in-memory identity
// (test/helpers/fake-identity.mjs), for the HTTP tests that need no database: requests are sent
// with exact, possibly repeated header lines, from 127.0.0.1, with any Host.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { LoginThrottle, trustedProxies } from '../../lib/throttle.mjs';
import { createRouter } from '../../lib/http/router.mjs';
import { createPipeline } from '../../lib/http/pipeline.mjs';
import { authRoutes } from '../../lib/http/routes/auth.mjs';
import { accountRoutes } from '../../lib/http/routes/account.mjs';
import { json } from '../../lib/http/body.mjs';
import { fakeIdentity } from '../helpers/fake-identity.mjs';

export const password = 'fixture-http-lane-password';
export const build = 'c0ffee000000';
export const version = '1.5.0-test';
export const basic = (value = password) =>
  'Basic ' + Buffer.from('admin:' + value).toString('base64');

/**
 * Sends one request whose headers are given as lines (`Name: value`, in order, repeatable);
 * resolves to {status, headers, body, json}. The Host is `127.0.0.1:<port>` unless a line sets
 * it.
 */
export function raw(port, lines, body = '') {
  const [method, target] = lines[0].split(' ');
  const hostLine = lines.slice(1).some(line => /^host:/i.test(line));
  const headers = [...(hostLine ? [] : ['Host', `127.0.0.1:${port}`]), 'Connection', 'close'];
  for (const line of lines.slice(1)) {
    const at = line.indexOf(':');
    headers.push(line.slice(0, at), line.slice(at + 1).trim());
  }
  if (body) headers.push('Content-Length', String(Buffer.byteLength(body)));
  return new Promise((resolve, reject) => {
    const request = http.request(
      { host: '127.0.0.1', port, method, path: target, headers, agent: false },
      response => {
        let text = '';
        response.setEncoding('utf8');
        response.on('data', chunk => (text += chunk));
        response.on('end', () => {
          let value;
          try {
            value = JSON.parse(text);
          } catch {}
          resolve({
            status: response.statusCode,
            headers: response.headers,
            body: text,
            json: value,
          });
        });
      }
    );
    request.on('error', reject);
    request.end(body || undefined);
  });
}

/** A signed-in read and write for exercising sessions. */
export const thingRoutes = () => [
  {
    method: 'GET',
    path: '/api/thing',
    auth: 'session',
    permission: 'dashboard:read',
    summary: 'read',
    handler: ({ res, access }) => json(res, 200, { ok: true, via: access.via }),
  },
  {
    method: 'POST',
    path: '/api/thing',
    auth: 'session',
    permission: 'sources:write',
    summary: 'write',
    handler: async ({ res, body }) => json(res, 200, { received: await body() }),
  },
];

/**
 * Serves the sign-in and account routes (plus thingRoutes() and `routes`) through the real
 * pipeline. Options: identity (default: the fake with `password` and the same
 * insecureHttpSessions), legacyBasic (true),
 * insecureHttpSessions, trustProxy (a GOBLIN_TRUST_PROXY value), configuredHosts (a list),
 * allowedHost, loginThrottle, idempotency, permitted (the pipeline's permission check), guard
 * (the storage guard fail() reports a full disk to) and audit (the audit service: the
 * pipeline's default, noopAudit(), unless given; the default identity records into it too).
 * Resolves to {port, identity, loginThrottle, logged}: `logged` collects the operator
 * diagnostics and errors.
 */
export async function serveAuth(
  t,
  {
    insecureHttpSessions = false,
    audit,
    identity = fakeIdentity({ password, insecureHttpSessions, ...(audit ? { audit } : {}) }),
    legacyBasic = true,
    trustProxy = '',
    configuredHosts = [],
    allowedHost,
    loginThrottle = new LoginThrottle(),
    routes = [],
    idempotency = null,
    permitted,
    guard = null,
    supports = [],
    adminUiLock,
    adminDeployment,
  } = {}
) {
  const logged = [];
  const log = {
    warn: (...args) => logged.push(args.join(' ')),
    error: (...args) => logged.push(args.join(' ')),
  };
  const trusted = trustedProxies(trustProxy);
  const hosts = new Set(configuredHosts.map(host => host.toLowerCase()));
  const app = {
    identity,
    loginThrottle,
    legacyBasic,
    insecureHttpSessions,
    trusted,
    release: { build, version },
    log,
    ...(audit ? { audit } : {}),
  };
  let port;
  const handle = createPipeline({
    router: createRouter([...authRoutes(app), ...accountRoutes(app), ...thingRoutes(), ...routes], {
      reserved: ['/api/*'],
      auth: ['public', 'session'],
      supports,
    }),
    identity,
    loginThrottle,
    release: app.release,
    allowedHost:
      allowedHost ??
      (host =>
        hosts.has(String(host).toLowerCase()) ||
        [`127.0.0.1:${port}`, `localhost:${port}`].includes(String(host).toLowerCase())),
    configuredHosts: hosts,
    trusted,
    legacyBasic,
    insecureHttpSessions,
    idempotency,
    ...(permitted ? { permitted } : {}),
    guard,
    adminUiLock,
    adminDeployment,
    ...(audit ? { audit } : {}),
    log,
  });
  const server = http.createServer(handle);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  port = server.address().port;
  t.after(() => new Promise(resolve => server.close(resolve)));
  return { port, identity, loginThrottle, logged };
}

/** The header lines of a same-origin browser write from `origin` (e.g. http://127.0.0.1:1). */
export const browserWrite = origin => [
  'X-Goblin-Request: 1',
  'Content-Type: application/json',
  `Origin: ${origin}`,
  'Sec-Fetch-Site: same-origin',
  'X-Goblin-Client: web/test',
];

/** The session cookie pair a login answer set, or null. */
export function cookieFrom(answer) {
  const lines = [].concat(answer.headers['set-cookie'] ?? []);
  for (const line of lines) {
    const pair = line.split(';')[0];
    if (/^(__Host-)?goblin_session=./.test(pair)) return pair;
  }
  return null;
}

/** Signs in on loopback through the login route; resolves to {cookie, answer}. */
export async function login(port, { password: value = password, remember, lines = [] } = {}) {
  const answer = await raw(
    port,
    ['POST /api/auth/login HTTP/1.1', ...browserWrite(`http://127.0.0.1:${port}`), ...lines],
    JSON.stringify({ login: 'admin', password: value, ...(remember ? { remember: true } : {}) })
  );
  return { cookie: cookieFrom(answer), answer };
}

/**
 * A real Uptime Goblin (createApp) on 127.0.0.1 with a temporary data directory, the scheduler off and
 * Basic on for scripts; `options` go to createApp. `fastKdf` (default true) replaces scrypt by
 * a deterministic hash of the same length, so tests that sign in many times stay fast (real
 * scrypt parity is identity's to test). Resolves to {app, port, directory, base}.
 */
export async function startReal(t, { fastKdf = true, identityOptions = {}, ...options } = {}) {
  // Loaded here: the pipeline-only tests using this file need no server.mjs.
  const { createApp } = await import('../../server.mjs');
  const directory = options.directory ?? fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-http-lane-'));
  if (!options.directory) t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const derive = async (secret, salt) => createHash('sha512').update(salt).update(secret).digest();
  const app = await createApp({
    port: 0,
    password,
    allowedHosts: '',
    webhook: '',
    trustProxy: '',
    startScheduler: false,
    legacyBasic: true,
    ...options,
    directory,
    identityOptions: { ...(fastKdf ? { derive } : {}), ...identityOptions },
  });
  const { port } = await app.listen();
  t.after(() => app.close());
  return { app, port, directory, base: `http://127.0.0.1:${port}` };
}
