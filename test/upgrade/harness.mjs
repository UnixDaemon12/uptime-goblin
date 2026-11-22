// Runs real Orbit releases as separate processes, as an installation does, on 127.0.0.1 only.
import { spawn } from 'node:child_process';
import { randomInt } from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { DatabaseSync } from 'node:sqlite';
import { root } from './fixtures.mjs';

// A test value for these throwaway installations only.
export const password = 'upgrade-simulation-only';
export const workingTree = root;

// Real paths: releases before 1.4.2 do not start from a symlinked path (macOS's /var is one).
export function temporary(t, prefix = 'orbit-upgrade-') {
  const directory = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), prefix)));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}
// A loopback port that nothing listens on (until someone binds it). It is picked below the range
// the OS hands out for listen(0) and for outgoing connections (32768-60999 on Linux, 49152-65535
// on macOS by default): a port from that range could be taken by another test file's connection
// between this check and the server's listen(), and that start failed with EADDRINUSE.
const pickedLow = 20000,
  pickedHigh = 32000;
export async function freePort() {
  for (let tries = 0; tries < 100; tries++) {
    const port = pickedLow + randomInt(pickedHigh - pickedLow);
    const server = net.createServer();
    const free = await new Promise(resolve => {
      server.once('error', () => resolve(false));
      server.listen({ port, host: '127.0.0.1', exclusive: true }, () => resolve(true));
    });
    if (free) {
      await new Promise(resolve => server.close(resolve));
      return port;
    }
  }
  throw new Error(`No free loopback port from ${pickedLow} to ${pickedHigh - 1}`);
}
// A fixture HTTP endpoint; `respond(pathname)` returns [status, body] or a body for 200.
export async function endpoint(t, respond = () => 'ok') {
  const server = http.createServer((req, res) => {
    const answer = respond(new URL(req.url, 'http://localhost').pathname),
      [status, body] = Array.isArray(answer) ? answer : [200, answer];
    res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8' }).end(body);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => {
    server.closeAllConnections();
    return new Promise(resolve => server.close(resolve));
  });
  return `http://127.0.0.1:${server.address().port}`;
}
// Headers set to undefined are left out (a session request drops Authorization that way).
const dropUndefined = headers =>
  Object.fromEntries(Object.entries(headers).filter(([, value]) => value !== undefined));
// One API call with the Basic credential and the headers every release requires of writes.
export function request(port, method, pathname, { body, headers = {}, secret = password } = {}) {
  const payload = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        method,
        path: pathname,
        timeout: 15000,
        headers: dropUndefined({
          Authorization: 'Basic ' + Buffer.from('admin:' + secret).toString('base64'),
          ...(method === 'GET'
            ? {}
            : {
                'X-Orbit-Request': '1',
                Origin: `http://127.0.0.1:${port}`,
                'Content-Type': 'application/json',
              }),
          ...(payload ? { 'Content-Length': payload.length } : {}),
          ...headers,
        }),
      },
      res => {
        const chunks = [];
        res.on('data', chunk => chunks.push(chunk));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let json;
          try {
            json = JSON.parse(text);
          } catch {}
          resolve({ status: res.statusCode, headers: res.headers, text, json });
        });
        res.on('error', reject);
      }
    );
    req.on('timeout', () => req.destroy(new Error(`${method} ${pathname} timed out`)));
    req.on('error', reject);
    req.end(payload);
  });
}
export async function waitFor(check, what, timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  let last;
  for (;;) {
    try {
      const value = await check();
      if (value) return value;
    } catch (error) {
      if (error.fatal) throw error;
      last = error;
    }
    if (Date.now() > deadline)
      throw new Error(`Timed out waiting for ${what}${last ? ': ' + last.message : ''}`);
    await delay(100);
  }
}
/**
 * Starts `app`/server.mjs on `data` with a clean environment (nothing inherited but PATH), and
 * waits until the dashboard answers (through Basic, as a script). `port` reuses a port (a
 * server replaced in place, as the installer does); by default a free one is picked. The base
 * environment turns legacy Basic on (ORBIT_LEGACY_BASIC=1): new 1.5 data directories have it off
 * (G2) and these suites sign in as scripts; releases before 1.5 ignore it. `env` overrides it,
 * and a value of undefined removes a variable. The process is killed when the test ends.
 * `ready()` replaces the readiness check, for a start whose password the test does not know yet.
 */
export async function start(t, { app, data, env = {}, secret = password, port, ready = null }) {
  port ??= await freePort();
  const child = spawn(process.execPath, [path.join(app, 'server.mjs')], {
    cwd: app,
    env: dropUndefined({
      PATH: process.env.PATH,
      HOST: '127.0.0.1',
      PORT: String(port),
      ORBIT_DATA_DIR: data,
      ORBIT_PASSWORD: password,
      ORBIT_ALLOW_LOOPBACK: '1',
      ORBIT_LEGACY_BASIC: '1',
      ...env,
    }),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let output = '',
    journal = '';
  for (const stream of [child.stdout, child.stderr])
    stream.on('data', chunk => (output = (output + chunk).slice(-65536)));
  // The whole standard output, as journald keeps it: the audit's checkpoint lines (audit spec
  // §4.6) for orbit-admin verify-audit --checkpoints.
  child.stdout.on('data', chunk => (journal += chunk));
  const exited = new Promise(resolve =>
    child.once('exit', (code, signal) => resolve({ code, signal }))
  );
  t.after(() => {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  });
  const running = {
    port,
    pid: child.pid,
    // The password this server accepts; a test that changes it updates this.
    secret,
    output: () => output,
    journal: () => journal,
    request: (method, pathname, options) =>
      request(port, method, pathname, { secret: running.secret, ...options }),
    dashboard: async () => {
      const response = await running.request('GET', '/api/dashboard');
      if (response.status !== 200) throw new Error(`dashboard answered ${response.status}`);
      return response.json;
    },
    // Ends the process as a power loss or an installer's kill would: no clean stop.
    async kill() {
      child.kill('SIGKILL');
      return exited;
    },
    async stop() {
      child.kill('SIGTERM');
      const result = await Promise.race([exited, delay(20000, null, { ref: false })]);
      if (result) return result;
      child.kill('SIGKILL');
      throw new Error(`${app} did not stop within 20 s:\n${output}`);
    },
  };
  await waitFor(async () => {
    if (child.exitCode !== null || child.signalCode !== null)
      throw Object.assign(new Error(`exited (${child.exitCode ?? child.signalCode})`), {
        fatal: true,
      });
    if (ready) return ready();
    return (await running.request('GET', '/api/dashboard')).status === 200;
  }, `${app} to serve on ${port}`).catch(error => {
    throw new Error(`${error.message}\n--- output ---\n${output}`);
  });
  return running;
}
// Everything the history database holds, read after the server stopped.
export function readHistory(data) {
  const db = new DatabaseSync(path.join(data, 'history.sqlite'), { readOnly: true });
  try {
    const rows = sql => db.prepare(sql).all();
    return {
      tables: rows("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").map(
        r => r.name
      ),
      readings: rows('SELECT * FROM readings ORDER BY service,time'),
      latest: rows('SELECT * FROM latest ORDER BY service'),
      alerts: rows('SELECT * FROM alerts ORDER BY service,rule'),
      events: rows('SELECT * FROM events ORDER BY id'),
    };
  } finally {
    db.close();
  }
}
export const readConfig = data => fs.readFileSync(path.join(data, 'config.json'));

// The headers a 1.5 web app sends: a browser context (Sec-Fetch-Site, X-Orbit-Client), whose
// Authorization is ignored, and the session CSRF gate's Origin and X-Orbit-Request.
export const browserHeaders = port => ({
  Origin: `http://127.0.0.1:${port}`,
  'Sec-Fetch-Site': 'same-origin',
  'X-Orbit-Request': '1',
  'X-Orbit-Client': 'web/upgrade-test',
});

/**
 * One API call as the 1.5 web app makes it: browser headers and the session `cookie` (the
 * `name=value` pair), no Authorization. Resolves like request().
 */
export function sessionRequest(port, method, pathname, { cookie, body, headers = {} } = {}) {
  return request(port, method, pathname, {
    body,
    headers: {
      Authorization: undefined,
      ...browserHeaders(port),
      'Content-Type': 'application/json',
      ...(cookie ? { Cookie: cookie } : {}),
      ...headers,
    },
  });
}

/**
 * Signs in to a 1.5 Orbit on 127.0.0.1 (the loopback transport) as the web app does, and
 * resolves to the session cookie as `name=value`. A refused sign-in throws with the answer.
 */
export async function login(port, secret = password, { remember = false } = {}) {
  const response = await sessionRequest(port, 'POST', '/api/auth/login', {
    body: { login: 'admin', password: secret, ...(remember ? { remember: true } : {}) },
  });
  const cookie = (response.headers['set-cookie'] ?? [])
    .map(value => value.split(';')[0])
    // goblin_session from 1.5 on (the rename to Uptime Goblin), orbit_session before.
    .find(pair => /^(?:__Host-)?(?:goblin|orbit)_session=v1\./.test(pair));
  if (response.status !== 200 || !cookie)
    throw Object.assign(new Error(`sign-in answered ${response.status}: ${response.text}`), {
      response,
    });
  return cookie;
}
