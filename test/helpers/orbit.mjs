// A real Uptime Goblin for browser and restart tests: createApp() on loopback with a data directory
// the test owns, restartable on the same port, optionally serving a changed copy of public/.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createApp } from '../../server.mjs';
import { adminHeaders, adminPassword } from './admin.mjs';
import { signIn } from './session.mjs';

export const root = fileURLToPath(new URL('../../', import.meta.url));

/** A temporary directory removed after the test (or suite) `t`. */
export function temporaryDirectory(t, prefix = 'orbit-real-') {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

/** A copy of public/ that a test may change to make the next start a new release. */
export function copyPublic(t) {
  const directory = temporaryDirectory(t, 'orbit-public-');
  fs.cpSync(path.join(root, 'public'), directory, { recursive: true });
  return directory;
}

/**
 * Starts Uptime Goblin on 127.0.0.1 with the tests' admin password (helpers/admin.mjs: Uptime Goblin always
 * requires one) unless `password` gives another, with the scheduler off. `port` 0 picks a free
 * port; pass the previous one to restart in place. Resolves to `{ app, port, url, password,
 * close }`. A page needs signInBrowser() before it loads; call() signs in as a script.
 */
export async function startOrbit({ directory, port = 0, password = adminPassword, ...options }) {
  const app = await createApp({
    directory,
    host: '127.0.0.1',
    port,
    password,
    allowedHosts: '',
    webhook: '',
    trustProxy: '',
    startScheduler: false,
    ...options,
  });
  const address = await app.listen();
  return {
    app,
    port: address.port,
    url: `http://127.0.0.1:${address.port}`,
    password,
    close: () => app.close(),
  };
}

/**
 * Signs the browser behind `cdp` (its browser-level DevTools connection) in to `orbit` (from
 * startOrbit), as the sign-in page would: a sign-in on loopback, and its session cookie set for
 * 127.0.0.1 in place of any other Uptime Goblin's (cookies are per host, not per port). Call it before
 * the page loads. Resolves to the cookie's `name=value`.
 */
export async function signInBrowser(
  cdp,
  orbit,
  { password = orbit.password ?? adminPassword } = {}
) {
  const { cookie } = await signIn(orbit.url, password);
  const at = cookie.indexOf('=');
  await cdp.send('Storage.setCookies', {
    cookies: [
      {
        name: cookie.slice(0, at),
        value: cookie.slice(at + 1),
        domain: '127.0.0.1',
        path: '/',
        httpOnly: true,
        sameSite: 'Strict',
      },
    ],
  });
  return cookie;
}

/**
 * Calls Uptime Goblin's API as a script signed in as the admin (same-origin JSON, legacy Basic, which
 * test/setup.mjs turns on), returning status and body. `headers` may replace Authorization.
 */
export async function call(url, route, method = 'GET', body, headers = {}) {
  const response = await fetch(url + route, {
    method,
    headers: {
      'Content-Type': 'application/json',
      'X-Goblin-Request': '1',
      ...adminHeaders(),
      ...headers,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  let value = text;
  try {
    value = JSON.parse(text);
  } catch {}
  return { status: response.status, headers: response.headers, body: value };
}

/** Records `count` readings of CPU and memory for a source, ending now. */
export function seedReadings(app, id, { count = 60, stepMs = 60000 } = {}) {
  const now = Date.now();
  for (let i = count - 1; i >= 0; i--)
    app.store.record(
      id,
      [
        { key: 'cpu', label: 'CPU', value: 20 + (i % 7), unit: '%' },
        { key: 'memory', label: 'Memory', value: 50 + (i % 5), unit: '%' },
      ],
      null,
      now - i * stepMs
    );
}

/**
 * Runs before the web app in every document a tab loads. Uptime Goblin's request time limits
 * (30 s and longer) run `scale` times faster; the 15 s dashboard poll and the 5-minute
 * version probe run only when a test calls window.__poll() or window.__probe(). `hidden`
 * makes the page report itself hidden, as a background tab does.
 */
export function appPrelude({ scale = 10, hidden = false } = {}) {
  return `(() => {
    const realSetTimeout = window.setTimeout.bind(window),
      realSetInterval = window.setInterval.bind(window);
    window.setTimeout = (fn, ms, ...rest) =>
      realSetTimeout(fn, ms >= 20000 ? ms / ${Number(scale)} : ms, ...rest);
    window.setInterval = (fn, ms, ...rest) =>
      ms === 15000
        ? ((window.__poll = fn), 0)
        : ms === 300000
          ? ((window.__probe = fn), 0)
          : realSetInterval(fn, ms, ...rest);
    if (${hidden ? 'true' : 'false'}) {
      Object.defineProperty(Document.prototype, 'hidden', { configurable: true, get: () => true });
      Object.defineProperty(Document.prototype, 'visibilityState', {
        configurable: true,
        get: () => 'hidden',
      });
    }
  })();`;
}
