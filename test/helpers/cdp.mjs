// Headless Chrome over the DevTools protocol, with no npm packages. Browser tests use it for
// the web app, against a scripted mock (ui.test.mjs) or a real Uptime Goblin (update, stall).
// CHROME_PATH chooses the browser. Without one, tests are skipped, unless TEST_REQUIRE lists
// 'browser' (as CI does): then a missing or broken browser fails instead.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';

export const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
export const js = value => JSON.stringify(value);
export const chromePath = [
  process.env.CHROME_PATH,
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  '/Applications/Chromium.app/Contents/MacOS/Chromium',
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
].find(candidate => candidate && fs.existsSync(candidate));
/** Whether TEST_REQUIRE (comma-separated) lists `name`. */
export const required = name =>
  (process.env.TEST_REQUIRE || '')
    .split(',')
    .map(entry => entry.trim())
    .includes(name);

export class Cdp {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    this.listeners = new Set();
    ws.onmessage = event => {
      const message = JSON.parse(event.data);
      if (message.id) {
        const call = this.pending.get(message.id);
        this.pending.delete(message.id);
        if (message.error) call.reject(new Error(message.error.message));
        else call.resolve(message.result);
      } else for (const listener of this.listeners) listener(message);
    };
  }
  send(method, params = {}, sessionId) {
    const id = ++this.id;
    this.ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
    return new Promise((resolve, reject) => this.pending.set(id, { resolve, reject }));
  }
}

export class Page {
  constructor(cdp, sessionId, targetId) {
    Object.assign(this, { cdp, sessionId, targetId, exceptions: [] });
    this.listener = message => {
      if (message.sessionId === sessionId && message.method === 'Runtime.exceptionThrown')
        this.exceptions.push(message.params.exceptionDetails);
    };
    cdp.listeners.add(this.listener);
  }
  send(method, params) {
    return this.cdp.send(method, params, this.sessionId);
  }
  async eval(expression) {
    const result = await this.send('Runtime.evaluate', {
      expression,
      awaitPromise: true,
      returnByValue: true,
    });
    if (result.exceptionDetails)
      throw new Error(
        result.exceptionDetails.exception?.description || result.exceptionDetails.text
      );
    return result.result.value;
  }
  async waitFor(expression, timeout = 5000) {
    const end = Date.now() + timeout;
    for (;;) {
      const value = await this.eval(expression).catch(() => undefined);
      if (value) return value;
      if (Date.now() > end) throw new Error('Timed out waiting for: ' + expression);
      await delay(20);
    }
  }
  /** Waits until the page has painted twice. */
  async settle() {
    await delay(60);
    await this.eval('new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))');
    await delay(30);
  }
  async press(key) {
    const codes = { Enter: [13, '\r'], Escape: [27, undefined] }[key];
    await this.send('Input.dispatchKeyEvent', {
      type: codes[1] ? 'keyDown' : 'rawKeyDown',
      key,
      code: key,
      windowsVirtualKeyCode: codes[0],
      ...(codes[1] ? { text: codes[1] } : {}),
    });
    await this.send('Input.dispatchKeyEvent', {
      type: 'keyUp',
      key,
      code: key,
      windowsVirtualKeyCode: codes[0],
    });
  }
  async center(selector) {
    return this.eval(`(() => {
      const r = document.querySelector(${js(selector)}).getBoundingClientRect();
      return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
    })()`);
  }
  /** A trusted click, which also counts as user activation. */
  async click(selector) {
    const { x, y } = await this.center(selector);
    for (const type of ['mousePressed', 'mouseReleased'])
      await this.send('Input.dispatchMouseEvent', { type, x, y, button: 'left', clickCount: 1 });
  }
  /** Sets a field's value as typing would, with input and change events. */
  async setValue(selector, value) {
    await this.eval(`(() => {
      const field = document.querySelector(${js(selector)});
      field.value = ${js(value)};
      field.dispatchEvent(new Event('input', { bubbles: true }));
      field.dispatchEvent(new Event('change', { bubbles: true }));
    })()`);
  }
  text(selector) {
    return this.eval(`document.querySelector(${js(selector)})?.textContent ?? null`);
  }
  async close() {
    this.cdp.listeners.delete(this.listener);
    await this.cdp.send('Target.closeTarget', { targetId: this.targetId }).catch(() => {});
  }
}

// Runs first in every page: a click on a link with a download attribute (the web app's exports,
// public/modules/configure/exports.js) is cancelled and recorded in window.__downloads as
// {name, type, text}, with `text` (exactly as written) once the Blob behind the link is read. Chrome never starts
// the download: Browser.setDownloadBehavior names only where a finished one goes, and Chrome
// writes the file in progress in the user's own Downloads folder and moves it from there, so
// every export a test clicked touched ~/Downloads, and a run killed mid-download could leave a
// file. The Blob is kept from URL.createObjectURL and read directly: the page's CSP lets it
// fetch nothing from a blob: URL. Wrapped in a function, so it declares no global names.
const downloadGuard = `(() => {
  window.__downloads = [];
  const blobs = new Map();
  const create = URL.createObjectURL;
  const revoke = URL.revokeObjectURL;
  const bytes = Blob.prototype.arrayBuffer;
  URL.createObjectURL = object => {
    const url = create.call(URL, object);
    if (object instanceof Blob) blobs.set(url, object);
    return url;
  };
  URL.revokeObjectURL = url => (blobs.delete(url), revoke.call(URL, url));
  addEventListener('click', event => {
    const link = event.target instanceof Element ? event.target.closest('a[download]') : null;
    if (!link) return;
    event.preventDefault();
    const blob = blobs.get(link.href);
    const entry = { name: link.download, type: blob?.type ?? null, text: null };
    window.__downloads.push(entry);
    // ignoreBOM keeps a byte order mark (the CSV export starts with one) in the text.
    if (blob)
      bytes.call(blob).then(
        data => (entry.text = new TextDecoder('utf-8', { ignoreBOM: true }).decode(data)),
        () => (entry.text = '')
      );
    else entry.text = '';
  }, true);
})();`;

/**
 * Opens a tab at `url`. `prelude` runs before any page script, in every document the tab
 * loads (reloads included), after downloadGuard. Resolves once `ready` (an expression) is true.
 */
export async function openPage(
  cdp,
  url,
  { prelude = '', width = 1280, height = 900, ready, PageClass = Page, timeout = 5000 } = {}
) {
  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });
  const page = new PageClass(cdp, sessionId, targetId);
  await page.send('Page.enable');
  await page.send('Runtime.enable');
  await page.send('Emulation.setDeviceMetricsOverride', {
    width,
    height,
    deviceScaleFactor: 1,
    mobile: false,
  });
  await page.send('Emulation.setFocusEmulationEnabled', { enabled: true });
  await page.send('Page.addScriptToEvaluateOnNewDocument', { source: downloadGuard });
  if (prelude) await page.send('Page.addScriptToEvaluateOnNewDocument', { source: prelude });
  await page.send('Page.navigate', { url });
  if (ready) await page.waitFor(ready, timeout);
  return page;
}

/**
 * How Chrome is started so that every file it writes stays in the throwaway `profile`, which
 * close() removes. --user-data-dir alone is not enough: on macOS Chrome keeps its crash database
 * (~/Library/Application Support/Google/Chrome/Crashpad) and its RLZ store
 * (~/Library/Application Support/Google/RLZ) in the account's home folder whatever the profile
 * is, and finds that folder through CFFIXED_USER_HOME when it is set (measured with Chrome 154:
 * HOME alone does not move them); on Linux it takes its folders from HOME and XDG_*. So all of
 * these name a folder in the profile. Crash reporting is switched off as far as Chrome allows
 * (--disable-crash-reporter, --disable-breakpad, dumps into the profile): Chrome 154 still
 * starts its crash handler, but its database is then in the profile, with uploads off. Chrome
 * also uses no keychain or secret store of the account (--use-mock-keychain,
 * --password-store=basic).
 */
export function chromeLaunch(profile, extra = [], environment = process.env) {
  const home = path.join(profile, 'home');
  return {
    home,
    args: [
      '--headless',
      '--remote-debugging-port=0',
      `--user-data-dir=${profile}`,
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-gpu',
      '--disable-extensions',
      '--disable-sync',
      '--disable-background-networking',
      '--disable-component-update',
      '--disable-default-apps',
      '--disable-domain-reliability',
      '--no-pings',
      '--disable-crash-reporter',
      '--disable-breakpad',
      // Cookies and saved passwords are encrypted with a key Chrome keeps in the login keychain
      // (macOS) or the desktop's secret store (Linux). With the home folder in the profile there
      // is no keychain to find, and the first sign-in waited minutes for one; and the user's own
      // keychain is not the test's to touch. A mock keychain and the basic store keep that key
      // in the profile too.
      '--use-mock-keychain',
      '--password-store=basic',
      `--crash-dumps-dir=${path.join(profile, 'crash-dumps')}`,
      // Anything that is not loopback goes to a closed port, so the tests stay offline.
      '--proxy-server=127.0.0.1:9',
      ...extra,
      'about:blank',
    ],
    env: {
      ...environment,
      HOME: home,
      CFFIXED_USER_HOME: home,
      XDG_CONFIG_HOME: path.join(home, '.config'),
      XDG_CACHE_HOME: path.join(home, '.cache'),
      XDG_DATA_HOME: path.join(home, '.local', 'share'),
    },
  };
}

/**
 * The process ids of Chrome crash handlers whose database is in `profile`. The handler is not a
 * child of the browser and can outlive it (it was once left running after a test run); its
 * command line names its database. [] where `ps` cannot be run.
 */
export function crashHandlers(profile) {
  const listed = spawnSync('ps', ['-ww', '-axo', 'pid=,command='], { encoding: 'utf8' });
  if (listed.status !== 0) return [];
  // macOS may name /private/tmp and /private/var by their short forms, /tmp and /var.
  const names = [profile, profile.replace(/^\/private(?=\/(?:tmp|var)\/)/, '')];
  return listed.stdout
    .split('\n')
    .filter(
      line =>
        /crashpad_handler/.test(line) && names.some(name => line.includes(`--database=${name}`))
    )
    .map(line => Number(line.trim().split(/\s+/)[0]))
    .filter(pid => Number.isSafeInteger(pid) && pid > 0);
}

function endCrashHandlers(profile) {
  for (const pid of crashHandlers(profile))
    try {
      process.kill(pid, 'SIGKILL');
    } catch {}
}

async function launchChrome(extra = []) {
  const profile = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-ui-')));
  const downloads = path.join(profile, 'downloads');
  const launch = chromeLaunch(profile, extra);
  fs.mkdirSync(launch.home, { mode: 0o700 });
  const child = spawn(chromePath, launch.args, {
    env: launch.env,
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  try {
    const endpoint = await new Promise((resolve, reject) => {
      let output = '';
      child.stderr.on('data', chunk => {
        output += chunk;
        const match = output.match(/DevTools listening on (ws:\/\/\S+)/);
        if (match) resolve(match[1]);
      });
      child.on('error', reject);
      child.on('exit', code => reject(new Error(`exited (${code}): ${output.slice(-500)}`)));
      setTimeout(() => reject(new Error('did not start within 20 s')), 20000).unref();
    });
    const ws = new WebSocket(endpoint);
    await new Promise((resolve, reject) => {
      ws.onopen = resolve;
      ws.onerror = () => reject(new Error('DevTools connection failed'));
    });
    const cdp = new Cdp(ws);
    // A download that still reaches Chrome (pages cancel the ones they start, downloadGuard)
    // ends in the throwaway profile, removed on close, rather than in the user's Downloads.
    await cdp.send('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: downloads });
    return { child, profile, downloads, cdp };
  } catch (error) {
    child.kill('SIGKILL');
    endCrashHandlers(profile);
    fs.rmSync(profile, { recursive: true, force: true });
    throw error;
  }
}

/**
 * Starts Chrome. Resolves to `{ browser }`, or to `{ skip: reason }` when no browser can run
 * and TEST_REQUIRE does not list 'browser' (then it rejects instead). `browser.close()` ends
 * it; it is also killed when the test process exits.
 */
export async function startBrowser() {
  let reason = chromePath ? null : 'no Chrome or Chromium found (set CHROME_PATH)',
    browser = null;
  if (!reason)
    try {
      browser = await launchChrome(process.getuid?.() === 0 ? ['--no-sandbox'] : []);
    } catch (error) {
      // Some Linux CI images block Chrome's sandbox. These pages are this repository's own,
      // served from loopback with every other host unreachable, so retry without it there.
      if (process.platform === 'linux')
        browser = await launchChrome(['--no-sandbox']).catch(() => null);
      if (!browser) reason = `Chrome could not start: ${error.message}`;
    }
  if (!browser) {
    if (required('browser')) throw new Error(`TEST_REQUIRE lists browser, but ${reason}`);
    return { skip: reason };
  }
  process.on('exit', () => {
    browser.child.kill('SIGKILL');
    endCrashHandlers(browser.profile);
  });
  browser.close = async () => {
    browser.cdp.ws.close();
    // SIGKILL: on SIGTERM Chrome would wait on a page's beforeunload prompt for unsaved edits.
    browser.child.kill('SIGKILL');
    // Chrome's crash reporter or updater can inherit stderr and outlive the browser.
    // Their copy must not keep this test runner waiting for the output pipe to close.
    browser.child.stderr.destroy();
    await delay(200);
    // Its crash handler, whose database is in the profile, ends with it.
    endCrashHandlers(browser.profile);
    // A helper Chrome left behind can still be writing into the profile for a moment after the
    // kill (seen under load as ENOTEMPTY): retry the removal briefly rather than fail the suite.
    fs.rmSync(browser.profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  };
  return { browser, skip: false };
}
