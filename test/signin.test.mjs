// Signing in with a real browser against a real Uptime Goblin (1.5 sessions spec §8.1, S1–S9, and the
// the reference deployment behind nginx, S10–S11): the
// sign-in view under Uptime Goblin's Content-Security-Policy, the session cookie as the browser keeps
// it, signing out, the lockout countdown, the sign-in dialog that keeps a draft, the Account
// page, tabs of 1.4.2 and 1.4.3 across an upgrade (and a 1.5 tab across a rollback), cached
// HTTP Basic credentials, and a page on the Uptime Goblin computer itself, which signs in like any other
// (there is no passwordless local preview). ui.test.mjs covers the same web app against a
// scripted mock; this file proves it against the server it ships with.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import path from 'node:path';
import { delay, js, openPage, startBrowser } from './helpers/cdp.mjs';
import { appPrelude, seedReadings, startOrbit, temporaryDirectory } from './helpers/orbit.mjs';
import { sessionCall, signIn } from './helpers/session.mjs';
import {
  installRelease,
  installTag,
  skipWithoutFixtures,
  skipWithoutTag,
} from './upgrade/fixtures.mjs';
import {
  freePort,
  login,
  password as upgradePassword,
  start,
  temporary,
  workingTree,
} from './upgrade/harness.mjs';
import { selfSignedCertificate } from './helpers/tls.mjs';
import { supervisedEnv } from './helpers/supervised.mjs';
import { LoginThrottle } from '../lib/throttle.mjs';
import { sql } from '../lib/db/sql.mjs';

const { browser, skip } = await startBrowser();
after(() => browser?.close());

// A test value for these throwaway installations only.
const password = 'correct horse battery staple';
// Uptime Goblin's request time limits run 10 times faster, polls run when a test calls window.__poll(),
// and every Content-Security-Policy violation is recorded.
const prelude = `${appPrelude({ scale: 10 })}
  window.__cspViolations = [];
  document.addEventListener('securitypolicyviolation', e =>
    window.__cspViolations.push(e.violatedDirective + ' ' + e.blockedURI)
  );`;
const signInView = "document.querySelector('#signin-page')?.hidden === false";
const cards = "document.querySelector('#services article')";
const dialogOpen = "document.querySelector('#signin-dialog')?.open === true";

/** Uptime Goblin with an admin password, on loopback, stopped when the test ends. */
async function orbitWithPassword(t, options = {}) {
  const orbit = await startOrbit({ directory: temporaryDirectory(t), password, ...options });
  t.after(() => orbit.close());
  return orbit;
}
/**
 * A tab at `url`. Cookies are per host, not per port, so every test starts without the cookies
 * earlier tests' Orbits set. `before(page)` runs before the page loads (request headers).
 */
async function openTab(t, url, { ready = null, before = null, timeout = 10000 } = {}) {
  await browser.cdp.send('Storage.clearCookies');
  const page = await openPage(browser.cdp, 'about:blank', { prelude });
  t.after(() => page.close());
  await page.send('Network.enable');
  if (before) await before(page);
  await page.send('Page.navigate', { url });
  if (ready) await page.waitFor(ready, timeout);
  return page;
}
/** Fills in one of the two sign-in forms (`signin` or `reauth`) and submits it. */
async function submitSignIn(page, form, secret, { remember = false } = {}) {
  await page.setValue(`#${form}-login`, 'admin');
  await page.setValue(`#${form}-password`, secret);
  await page.eval(`document.querySelector('#${form}-remember').checked = ${remember}`);
  await page.eval(`document.querySelector('#${form}-submit').click()`);
}
async function signInThroughView(page, secret = password, options) {
  await page.waitFor(signInView);
  await submitSignIn(page, 'signin', secret, options);
  await page.waitFor(cards, 10000);
}
/** The session cookies the browser holds for `url`. */
async function sessionCookies(page, url) {
  const { cookies } = await page.send('Network.getCookies', { urls: [url] });
  return cookies.filter(c => c.name === 'goblin_session' || c.name === '__Host-goblin_session');
}
/**
 * Records the answers this tab receives from Uptime Goblin's API, `{id, path, status, headers}`, and
 * the API paths it asks for, into `into` (`{responses, requested}`).
 */
function recordResponses(t, page, into = { responses: [], requested: [] }) {
  const { responses, requested } = into;
  const listener = message => {
    if (message.sessionId === page.sessionId && message.method === 'Network.requestWillBeSent')
      requested.push(new URL(message.params.request.url).pathname);
    if (message.sessionId !== page.sessionId || message.method !== 'Network.responseReceived')
      return;
    const { response, requestId } = message.params;
    if (new URL(response.url).pathname.startsWith('/api/'))
      responses.push({
        id: requestId,
        path: new URL(response.url).pathname,
        status: response.status,
        headers: Object.fromEntries(
          Object.entries(response.headers).map(([k, v]) => [k.toLowerCase(), v])
        ),
      });
  };
  page.cdp.listeners.add(listener);
  t.after(() => page.cdp.listeners.delete(listener));
  return into;
}
/** Opens the drawer of source `id`, as its Edit button does. */
async function openDrawer(page, id) {
  await page.eval(`(() => {
    const button = document.createElement('button');
    button.dataset.configure = ${js(id)};
    document.body.append(button);
    button.click();
    button.remove();
  })()`);
  await page.waitFor("document.querySelector('#settings-dialog').open");
}
/** The header a browser sends once someone typed `secret` into its HTTP Basic prompt. */
const basicHeader = secret => ({
  Authorization: 'Basic ' + Buffer.from(`admin:${secret}`).toString('base64'),
});
async function noViolations(page) {
  assert.deepEqual(await page.eval('window.__cspViolations'), []);
  assert.deepEqual(page.exceptions, []);
}

test(
  'S1 the sign-in view loads under Uptime Goblin’s CSP, with labels and focus, and asks for nothing else',
  { skip },
  async t => {
    const orbit = await orbitWithPassword(t);
    const page = await openTab(t, orbit.url + '/', { ready: signInView });
    const { responses } = recordResponses(t, page);
    await page.settle();
    assert.equal(await page.eval('document.activeElement.id'), 'signin-title');
    for (const id of ['signin-login', 'signin-password', 'signin-remember'])
      assert.ok(
        await page.eval(`document.querySelector('label[for=${id}]')?.textContent.trim()`),
        `${id} has a visible label`
      );
    // Nothing but the session check was asked: no readings, no configuration.
    const apiCalls = await page.eval(
      "performance.getEntriesByType('resource').map(e => new URL(e.name).pathname).filter(p => p.startsWith('/api/'))"
    );
    assert.deepEqual(apiCalls, ['/api/session']);
    assert.equal(responses.length, 0, 'no further request once the view shows');
    // The page came with Uptime Goblin's policy.
    const index = await fetch(orbit.url + '/');
    assert.match(index.headers.get('content-security-policy'), /script-src 'self'/);
    await noViolations(page);
  }
);

test(
  'S2 the session cookie is HttpOnly; Keep me signed in makes it last, otherwise it ends with the browser',
  { skip },
  async t => {
    const orbit = await orbitWithPassword(t);
    const page = await openTab(t, orbit.url + '/', { ready: signInView });
    await signInThroughView(page);
    assert.equal(await page.eval('document.cookie'), '', 'scripts cannot read it');
    let [cookie] = await sessionCookies(page, orbit.url);
    assert.equal(cookie.name, 'goblin_session', 'loopback: the plain-HTTP name');
    assert.equal(cookie.httpOnly, true);
    assert.equal(cookie.sameSite, 'Strict');
    assert.equal(cookie.path, '/');
    assert.equal(cookie.session, true, 'without Keep me signed in: a browser-session cookie');
    // Sign out, then in again with Keep me signed in.
    await page.eval("document.querySelector('#user-chip').click()");
    await page.eval("document.querySelector('#sign-out').click()");
    await page.waitFor(signInView, 10000);
    await signInThroughView(page, password, { remember: true });
    [cookie] = await sessionCookies(page, orbit.url);
    assert.equal(cookie.session, false);
    const days = (cookie.expires * 1000 - Date.now()) / 86400000;
    assert.ok(days > 29.9 && days <= 30, `expires in ${days} days`);
    await noViolations(page);
  }
);

test(
  'S3 Sign out returns to the sign-in view, removes the cookie, and Back shows no readings',
  { skip },
  async t => {
    const orbit = await orbitWithPassword(t);
    const names = orbit.app.config.value.services.map(s => s.name);
    const page = await openTab(t, orbit.url + '/', { ready: signInView });
    await signInThroughView(page);
    assert.ok(await page.eval(`document.body.textContent.includes(${js(names[0])})`));
    // A history entry to go back to.
    await page.eval("document.querySelector('#user-chip').click()");
    await page.eval("document.querySelector('#user-account').click()");
    await page.waitFor(
      "location.hash === '#configure/account' && document.querySelector('#account-details')"
    );
    await page.eval("document.querySelector('#user-chip').click()");
    await page.eval("document.querySelector('#sign-out').click()");
    await page.waitFor(`${signInView} && location.hash === ''`, 10000);
    assert.deepEqual(await sessionCookies(page, orbit.url), [], 'Uptime Goblin expired the cookie');
    // Back to the entry of the signed-in page. Whether Chrome keeps this document, loads the
    // page again or restores it from its back/forward cache (which the page then reloads, its
    // session being gone), what shows must be the sign-in view.
    const { currentIndex } = await page.send('Page.getNavigationHistory');
    await page.eval('history.back()');
    for (let end = Date.now() + 5000; Date.now() < end; await delay(20))
      if ((await page.send('Page.getNavigationHistory')).currentIndex < currentIndex) break;
    await delay(300);
    await page.waitFor(signInView, 10000);
    await page.settle();
    for (const name of names)
      assert.equal(
        await page.eval(`document.body.textContent.includes(${js(name)})`),
        false,
        `${name} is not in the page`
      );
    assert.equal(await page.eval("document.querySelector('#services').children.length"), 0);
    await noViolations(page);
  }
);

test(
  'S3b Sign out while another app on this host sets a cookie of Uptime Goblin’s name ends the session and says to remove that cookie',
  { skip },
  async t => {
    // §19 G1. Cookies are not isolated by port: a page on another port of 127.0.0.1 sets
    // goblin_session at Path=/api, and the browser sends both. Before, Sign out got 401
    // multiple_credentials, ended nothing and expired nothing, the page started again as if
    // signed out, and once the other cookie went the browser was the admin again.
    const orbit = await orbitWithPassword(t);
    const sibling = http.createServer((req, res) => {
      const age = req.url.includes('clear') ? 0 : 3600;
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(
        `<script>document.cookie = 'goblin_session=v1.${'A'.repeat(43)}; path=/api; max-age=${age}'; document.title = 'set ${age}'</script>`
      );
    });
    await new Promise(resolve => sibling.listen(0, '127.0.0.1', resolve));
    // Chrome opens a second connection to this page that it never sends a request on. close()
    // ends such a connection on Node 26 but waits for it on Node 24, where this hook then waited
    // until the test timed out (B49), so every connection is closed first, as the nginx stand-in
    // and the header-less proxy below do.
    t.after(() => {
      sibling.closeAllConnections();
      return new Promise(resolve => sibling.close(resolve));
    });
    const siblingUrl = `http://127.0.0.1:${sibling.address().port}/`;
    const page = await openTab(t, orbit.url + '/', { ready: signInView });
    await signInThroughView(page);
    const rows = () => orbit.app.control.db.read(tx => tx.all(sql`SELECT id FROM sessions`));
    assert.equal((await rows()).length, 1);
    const other = await openPage(browser.cdp, siblingUrl, {
      ready: "document.title === 'set 3600'",
    });
    t.after(() => other.close());
    const jar = async () =>
      (await page.send('Network.getCookies', { urls: [orbit.url + '/api/session'] })).cookies
        .filter(c => c.name === 'goblin_session')
        .map(c => `${c.path}${c.httpOnly ? ' HttpOnly' : ''}`)
        .sort();
    assert.deepEqual(await jar(), ['/ HttpOnly', '/api']);
    await page.eval("document.querySelector('#user-chip').click()");
    await page.eval("document.querySelector('#sign-out').click()");
    await page.waitFor(
      `${signInView} && document.querySelector('#signin-notice').hidden === false`,
      10000
    );
    await page.settle();
    assert.equal(
      await page.text('#signin-notice'),
      'You are signed out, but this browser still has an Uptime Goblin sign-in cookie that another site set. Remove this site’s cookies in the browser before you sign in again.'
    );
    assert.deepEqual(await rows(), [], 'the session ended');
    assert.deepEqual(
      await jar(),
      ['/api'],
      'Uptime Goblin’s own cookie expired; the other app’s stays'
    );
    // Later the other app's cookie goes: the browser is signed out, not the admin again.
    await other.send('Page.navigate', { url: siblingUrl + 'clear' });
    await other.waitFor("document.title === 'set 0'");
    assert.deepEqual(await jar(), []);
    await page.eval('location.reload()');
    await delay(300);
    await page.waitFor(signInView, 10000);
    await page.settle();
    assert.equal(await page.eval(`!!${cards}`), false);
    assert.equal(await page.eval("document.querySelector('#user-chip').hidden"), true);
    await noViolations(page);
  }
);

test(
  'S3c a cookie of Uptime Goblin’s name that another app sets while a page is open: the page says to remove it and stops polling until it goes',
  { skip },
  async t => {
    // §20 H5. Every request is then refused with 401 multiple_credentials, which asks nobody.
    // The page said "Signed out. Sign in to see current readings." with a Sign in whose
    // attempt failed the same way, and went on polling, drawing the notice again each time.
    const orbit = await orbitWithPassword(t);
    const page = await openTab(t, orbit.url + '/', { ready: signInView });
    await signInThroughView(page);
    const { requested } = recordResponses(t, page);
    // What a page on another port of 127.0.0.1 can do (S3b): goblin_session at Path=/api.
    const other = { name: 'goblin_session', url: orbit.url + '/api/', path: '/api' };
    const paths = async () =>
      (await sessionCookies(page, orbit.url + '/api/session')).map(c => c.path).sort();
    const twoCookies =
      'Your browser sent two Uptime Goblin sign-in cookies. Remove this site’s cookies, then sign in.';
    const refused = async () => {
      await page.send('Network.setCookie', { ...other, value: 'v1.' + 'B'.repeat(43) });
      assert.deepEqual(await paths(), ['/', '/api']);
      await page.eval('window.__poll()');
      await page.waitFor(`document.querySelector('#notice').textContent === ${js(twoCookies)}`);
      await page.settle();
      assert.equal(await page.eval("document.querySelector('#notice button')"), null);
      assert.equal(await page.text('#connection'), 'Signed out');
      assert.equal(await page.eval(dialogOpen), false);
      // Polls stop: each would only be refused again.
      requested.length = 0;
      await page.eval('window.__poll()');
      await delay(300);
      assert.deepEqual(requested, []);
    };
    const focusTab = () => page.eval("window.dispatchEvent(new Event('focus'))");

    // The other app removed its cookie: the next look at the tab carries on.
    await refused();
    await page.send('Network.deleteCookies', other);
    assert.deepEqual(await paths(), ['/']);
    await focusTab();
    await page.waitFor(
      "document.querySelector('#notice').hidden && document.querySelector('#connection').textContent !== 'Signed out'",
      10000
    );
    // This site's cookies removed, as the notice says: the next look at the tab offers Sign
    // in, which signs in again.
    await refused();
    await browser.cdp.send('Storage.clearCookies');
    await focusTab();
    await page.waitFor("document.querySelector('#notice-sign-in')", 10000);
    assert.equal(
      await page.text('#notice'),
      'Signed out. Sign in to see current readings. Sign in'
    );
    await page.eval("document.querySelector('#notice-sign-in').click()");
    await page.waitFor(dialogOpen, 10000);
    await submitSignIn(page, 'reauth', password);
    await page.waitFor(`!(${dialogOpen}) && document.querySelector('#notice').hidden`, 10000);
    requested.length = 0;
    await page.eval('window.__poll()');
    const end = Date.now() + 5000;
    while (!requested.includes('/api/dashboard') && Date.now() < end) await delay(20);
    assert.ok(requested.includes('/api/dashboard'), 'polls resume');
    await page.settle();
    assert.notEqual(await page.text('#connection'), 'Signed out');
    await noViolations(page);
  }
);

test(
  'S4 a wrong password is said so; a lockout counts down and then signs in',
  { skip },
  async t => {
    // After one free attempt each failure locks this client out, for 2 s at first.
    const orbit = await orbitWithPassword(t, {
      loginThrottle: new LoginThrottle({ freeAttempts: 1, baseMs: 2000 }),
    });
    const page = await openTab(t, orbit.url + '/', { ready: signInView });
    await submitSignIn(page, 'signin', 'not the password, sorry');
    await page.waitFor("document.querySelector('#signin-error').hidden === false");
    assert.equal(await page.text('#signin-error'), 'The login name or password is incorrect.');
    await submitSignIn(page, 'signin', 'still not the password');
    await page.waitFor(
      "document.querySelector('#signin-error').textContent === 'The login name or password is incorrect.' && !document.querySelector('#signin-submit').disabled"
    );
    // Locked now: the next attempt is refused with Retry-After, and the view counts down.
    await submitSignIn(page, 'signin', password);
    await page.waitFor("document.querySelector('#signin-countdown').hidden === false");
    assert.match(
      await page.text('#signin-error'),
      /^Too many attempts\. You can try again in \d+ s\.$/
    );
    assert.equal(await page.eval("document.querySelector('#signin-submit').disabled"), true);
    await page.waitFor("!document.querySelector('#signin-submit').disabled", 10000);
    assert.equal(await page.text('#signin-error'), 'You can try again now.');
    assert.equal(await page.eval('document.activeElement.id'), 'signin-password');
    await signInThroughView(page);
    await noViolations(page);
  }
);

test(
  'S5 a session revoked while a drawer has a draft: Save asks to sign in, then saves once',
  { skip },
  async t => {
    const orbit = await orbitWithPassword(t);
    const page = await openTab(t, orbit.url + '/', { ready: signInView });
    await signInThroughView(page);
    await openDrawer(page, 'linux');
    await page.setValue('#source-name', 'Renamed across a sign-in');
    const revision = orbit.app.config.value.revision;
    // Signed out from another device: Sign out other devices there.
    const other = await signIn(orbit.url, password);
    assert.equal(
      (await sessionCall(orbit.url, other.cookie)('/api/account/sessions', 'DELETE')).status,
      200
    );
    await page.eval("document.querySelector('#connection-form [type=submit]').click()");
    await page.waitFor(dialogOpen, 10000);
    assert.equal(await page.eval("document.querySelector('#settings-dialog').open"), true);
    assert.equal(
      await page.eval("document.querySelector('#source-name').value"),
      'Renamed across a sign-in'
    );
    assert.equal(orbit.app.config.value.revision, revision, 'nothing saved yet');
    await submitSignIn(page, 'reauth', password);
    await page.waitFor(
      `!(${dialogOpen}) && !document.querySelector('#settings-dialog').open`,
      10000
    );
    const saved = orbit.app.config.value;
    assert.equal(saved.services.find(s => s.id === 'linux').name, 'Renamed across a sign-in');
    assert.equal(saved.revision, revision + 1, 'saved once');
    await noViolations(page);
  }
);

test(
  'S6 Account: sessions are listed and signed out; a password change signs out the other devices only',
  { skip },
  async t => {
    const orbit = await orbitWithPassword(t);
    // The other devices sign in first: a session ends only those that signed in no later.
    const second = await signIn(orbit.url, password),
      third = await signIn(orbit.url, password);
    const page = await openTab(t, orbit.url + '/', { ready: signInView });
    await signInThroughView(page);
    await page.eval("location.hash = '#configure/account'");
    await page.waitFor(
      "document.querySelectorAll('#sessions-list tbody [data-session]').length === 3"
    );
    assert.equal(
      await page.eval(
        "document.querySelector('#sessions-list tbody tr').textContent.includes('This device')"
      ),
      true,
      'this session first'
    );
    // Sign out one device.
    await page.eval(
      `document.querySelector('[data-revoke-session=${js(second.body.session.id)}]').click()`
    );
    await page.waitFor(
      "document.querySelectorAll('#sessions-list tbody [data-session]').length === 2"
    );
    assert.equal((await sessionCall(orbit.url, second.cookie)('/api/session')).status, 401);
    assert.equal((await sessionCall(orbit.url, third.cookie)('/api/session')).status, 200);
    // Sign out the others.
    await page.eval("document.querySelector('#sign-out-others').click()");
    await page.waitFor(
      "document.querySelectorAll('#sessions-list tbody [data-session]').length === 1"
    );
    assert.equal((await sessionCall(orbit.url, third.cookie)('/api/session')).status, 401);
    assert.equal(await page.eval("document.querySelector('#sign-out-others').disabled"), true);
    // A password change keeps this browser signed in and signs out every other device.
    const fourth = await signIn(orbit.url, password);
    const changed = 'a brand new passphrase for orbit';
    await page.setValue('#current-password', password);
    await page.setValue('#new-password', changed);
    await page.setValue('#confirm-new-password', changed);
    await page.eval("document.querySelector('#password-form [type=submit]').click()");
    await page.waitFor("document.querySelector('#password-result').hidden === false", 10000);
    assert.equal(
      await page.text('#password-result'),
      'Password changed. Other devices were signed out.'
    );
    assert.equal((await sessionCall(orbit.url, fourth.cookie)('/api/session')).status, 401);
    assert.equal(
      await page.eval(
        "fetch('/api/session', { headers: { 'X-Goblin-Request': '1', 'X-Goblin-Client': 'web/test' } }).then(r => r.status)"
      ),
      200,
      'this browser is still signed in'
    );
    await page.eval('window.__poll()');
    await delay(300);
    assert.equal(await page.eval(dialogOpen), false);
    await signIn(orbit.url, changed);
    await noViolations(page);
  }
);

test(
  'S8 a browser that still sends 1.4.x Basic credentials sees the sign-in view and signs in',
  { skip },
  async t => {
    const orbit = await orbitWithPassword(t, { legacyBasic: true });
    let responses;
    const page = await openTab(t, orbit.url + '/', {
      before: async page => {
        ({ responses } = recordResponses(t, page));
        await page.send('Network.setExtraHTTPHeaders', { headers: basicHeader(password) });
      },
    });
    await page.waitFor(signInView, 10000);
    // Uptime Goblin ignored the credential: a browser's Basic header signs nobody in any more, and its
    // 401 carries no challenge, so the browser shows no prompt of its own.
    const first = responses.find(r => r.path === '/api/session');
    assert.equal(first.status, 401);
    assert.equal(first.headers['www-authenticate'], undefined);
    const { body } = await page.send('Network.getResponseBody', { requestId: first.id });
    assert.equal(JSON.parse(body).code, 'signin_required');
    await signInThroughView(page);
    await page.settle();
    const refused = responses.filter(r => r.status === 401 && r !== first);
    assert.deepEqual(refused, [], 'the cookie and the Basic header together are not refused');
    await noViolations(page);
  }
);

/** Signs every session out from another device ("Sign out other devices" there). */
async function signOutEverywhere(orbit) {
  const other = await signIn(orbit.url, password);
  assert.equal(
    (await sessionCall(orbit.url, other.cookie)('/api/account/sessions', 'DELETE')).status,
    200
  );
}
const signedOutText = 'Signed out. Sign in to see current readings. Sign in';
// What a 1.5 page says once Orbit 1.4.x answers in its place (S7 B1), with no Sign in.
const olderReleaseText =
  'Uptime Goblin now runs an older release, which this page cannot sign in to, so what it shows is no longer updated. Reload the page to use that release.';
const dialogClosed = "document.querySelector('#signin-dialog')?.open === false";
// Which page heading has the focus ('dashboard', 'configuration'), else what has it.
const focusedHeading = `(() => {
  const focused = document.activeElement;
  if (focused && focused === document.querySelector('#dashboard-title')?.closest('h1'))
    return 'dashboard';
  if (focused?.id === 'configuration-section-title') return 'configuration';
  return focused ? focused.id || focused.tagName : null;
})()`;
/** A trusted click (it moves the focus, as a person's does) on `selector`, scrolled into view. */
async function clickVisible(page, selector) {
  await page.eval(`document.querySelector(${js(selector)}).scrollIntoView({ block: 'center' })`);
  await page.settle();
  await page.click(selector);
}
/**
 * Focuses `selector` and presses Enter on it, as a keyboard user does, once a dialog that just
 * closed has given the focus back (its 'close' event).
 */
async function pressOn(page, selector) {
  await page.settle();
  await page.eval(`document.querySelector(${js(selector)}).focus()`);
  await page.waitFor(`document.activeElement === document.querySelector(${js(selector)})`);
  await page.press('Enter');
}
/** The id (or tag) of the element that has the focus. */
const focusedElement = 'document.activeElement?.id || document.activeElement?.tagName || null';

test(
  'S12 cancelling a sign-in that a person’s action asked for says the page is signed out',
  { skip },
  async t => {
    // A poll that finds the session gone leads, on Cancel, to a "Signed out" notice. A card's
    // pause, a save or a configuration page asks too, and polls stop on Cancel all the same:
    // without the notice the dashboard would go on saying "Collection active" while its
    // readings never change again.
    const orbit = await orbitWithPassword(t);
    orbit.app.config.update('linux', { apiUrl: 'http://127.0.0.1:9/' });
    seedReadings(orbit.app, 'linux', { count: 5, stepMs: 1000 });
    const page = await openTab(t, orbit.url + '/', { ready: signInView });
    const { requested } = recordResponses(t, page);
    await signInThroughView(page);
    await page.waitFor(
      "document.querySelector('#connection').textContent === 'Collection active' && document.querySelector('#connection').classList.contains('live')"
    );
    await signOutEverywhere(orbit);
    await page.eval(`document.querySelector('[data-toggle="linux"]').click()`);
    await page.waitFor(dialogOpen, 10000);
    await page.eval("document.querySelector('#reauth-cancel').click()");
    await page.waitFor(dialogClosed, 5000);
    await page.waitFor("document.querySelector('#notice').hidden === false");
    assert.equal(await page.text('#connection'), 'Signed out');
    assert.equal(
      await page.eval("document.querySelector('#connection').classList.contains('live')"),
      false
    );
    assert.equal(await page.text('#notice'), signedOutText);
    assert.ok(await page.eval("!!document.querySelector('#notice #notice-sign-in')"));
    assert.equal(orbit.app.config.value.services.find(s => s.id === 'linux').enabled, true);
    // Polls send nothing while signed out.
    requested.length = 0;
    for (let i = 0; i < 3; i++) await page.eval('window.__poll()');
    await delay(300);
    assert.deepEqual(requested, []);
    // The notice's Sign in brings the readings back. Used from the keyboard, so the focus is
    // the button's: the load hides that button, and the focus goes to the page's heading
    // rather than being lost on <body> (§16 C8).
    await page.waitFor(dialogClosed, 5000);
    await pressOn(page, '#notice-sign-in');
    await page.waitFor(dialogOpen, 10000);
    await page.waitFor("document.activeElement?.id === 'reauth-password'");
    await page.setValue('#reauth-password', password);
    await page.press('Enter');
    await page.waitFor(
      `${dialogClosed} && document.querySelector('#notice').hidden && document.querySelector('#connection').classList.contains('live')`,
      10000
    );
    await page.settle();
    await delay(300);
    assert.equal(await page.eval(focusedHeading), 'dashboard', 'the focus is on the heading');

    // On a configuration page the dashboard's notice is hidden: the page has its own.
    await page.eval("location.hash = '#configure/overview'");
    await page.waitFor("document.querySelector('#configuration-page').hidden === false");
    assert.equal(await page.eval("document.querySelector('#configuration-notice').hidden"), true);
    await signOutEverywhere(orbit);
    await page.eval("location.hash = '#configure/account'");
    await page.waitFor(dialogOpen, 10000);
    await page.eval("document.querySelector('#reauth-cancel').click()");
    await page.waitFor("document.querySelector('#configuration-notice').hidden === false", 5000);
    assert.equal(await page.text('#configuration-notice'), signedOutText);
    assert.equal(await page.text('#connection'), 'Signed out');
    assert.ok(
      await page.eval(
        "!!document.querySelector('#configuration-notice #configuration-sign-in').getClientRects().length"
      ),
      'its Sign in button is visible'
    );
    await page.waitFor(dialogClosed, 5000);
    await pressOn(page, '#configuration-sign-in');
    await page.waitFor(dialogOpen, 10000);
    await page.waitFor("document.activeElement?.id === 'reauth-password'");
    await page.setValue('#reauth-password', password);
    await page.press('Enter');
    await page.waitFor(
      `${dialogClosed} && document.querySelector('#configuration-notice').hidden`,
      10000
    );
    await page.settle();
    await delay(300);
    assert.equal(await page.eval(focusedHeading), 'configuration');
    await noViolations(page);
  }
);

test(
  'S13 while Uptime Goblin is not answering at start the app’s controls wait; a sign-in asked meanwhile is the sign-in view',
  { skip },
  async t => {
    // Uptime Goblin answers the page but not yet the session check (it is restarting). The page must
    // offer nothing that needs a signed-in Uptime Goblin, and a request that still finds nobody signed
    // in (a Refresh) must lead to the sign-in view, after which the page starts and polls:
    // never the dialog, which signed in behind the view and left the page without polls.
    const orbit = await orbitWithPassword(t);
    let failing = true;
    const page = await openTab(t, orbit.url + '/', {
      before: async page => {
        const listener = message => {
          if (message.sessionId !== page.sessionId || message.method !== 'Fetch.requestPaused')
            return;
          const { requestId } = message.params;
          page
            .send(
              failing ? 'Fetch.failRequest' : 'Fetch.continueRequest',
              failing ? { requestId, errorReason: 'ConnectionRefused' } : { requestId }
            )
            .catch(() => {});
        };
        page.cdp.listeners.add(listener);
        t.after(() => page.cdp.listeners.delete(listener));
        await page.send('Fetch.enable', { patterns: [{ urlPattern: '*/api/session*' }] });
      },
    });
    await page.waitFor(
      "document.querySelector('#notice')?.textContent === 'Uptime Goblin is not answering. This page connects by itself once it is back.'",
      10000
    );
    for (const selector of ['#refresh', '#settings', '.workspace-actions'])
      assert.equal(
        await page.eval(`document.querySelector(${js(selector)}).getClientRects().length`),
        0,
        `${selector} is not offered yet`
      );
    // Uptime Goblin is back; a Refresh still goes out (a click that slipped through).
    failing = false;
    await page.eval("document.querySelector('#refresh').click()");
    await page.waitFor(signInView, 10000);
    await delay(300);
    assert.equal(await page.eval(dialogOpen), false, 'no dialog over the start');
    assert.equal(await page.eval("document.querySelector('#dashboard-page').hidden"), true);
    await signInThroughView(page);
    await page.waitFor("typeof window.__poll === 'function'", 10000);
    assert.equal(await page.eval(signInView), false);
    assert.equal(await page.eval(dialogOpen), false);
    for (const selector of ['#refresh', '#settings', '.workspace-actions'])
      assert.ok(
        await page.eval(`document.querySelector(${js(selector)}).getClientRects().length`),
        `${selector} is offered once signed in`
      );
    await noViolations(page);
  }
);

/**
 * Makes Chrome fail this tab's requests to URLs matching `pattern` while `failing(request)` says
 * so (no answer at all, as when Uptime Goblin is restarting or the network dropped); others go through.
 * Call before the requests are made (Fetch.enable).
 */
async function failRequests(t, page, pattern, failing) {
  const listener = message => {
    if (message.sessionId !== page.sessionId || message.method !== 'Fetch.requestPaused') return;
    const { requestId, request } = message.params;
    const fail = failing(request);
    page
      .send(
        fail ? 'Fetch.failRequest' : 'Fetch.continueRequest',
        fail ? { requestId, errorReason: 'ConnectionRefused' } : { requestId }
      )
      .catch(() => {});
  };
  page.cdp.listeners.add(listener);
  t.after(() => page.cdp.listeners.delete(listener));
  await page.send('Fetch.enable', { patterns: [{ urlPattern: pattern }] });
}

test(
  'S14 a configuration page that never loaded, signed out and cancelled, still offers Sign in',
  { skip },
  async t => {
    // The first dashboard load of a configuration page failed (Uptime Goblin restarting), then the
    // session ended and the user cancelled signing in again. Polls stop and routes draw
    // nothing without data: the notice's Sign in is the way in, so it must show (§16 C6).
    const orbit = await orbitWithPassword(t);
    let failDashboard = false;
    const page = await openTab(t, orbit.url + '/', {
      ready: signInView,
      before: page => failRequests(t, page, '*/api/dashboard*', () => failDashboard),
    });
    failDashboard = true;
    await page.eval("history.replaceState(history.state, '', '/#configure/account')");
    await submitSignIn(page, 'signin', password);
    await page.waitFor("document.querySelector('#signin-page').hidden === true", 10000);
    await page.waitFor(
      "document.querySelector('#configuration-content').textContent.includes('Configuration is unavailable')",
      10000
    );
    failDashboard = false;
    await signOutEverywhere(orbit);
    await page.eval('window.__poll()');
    await page.waitFor(dialogOpen, 10000);
    await page.eval("document.querySelector('#reauth-cancel').click()");
    await page.waitFor(dialogClosed, 5000);
    await page.waitFor("document.querySelector('#configuration-notice').hidden === false", 5000);
    assert.equal(await page.text('#configuration-notice'), signedOutText);
    assert.ok(
      await page.eval(
        "!!document.querySelector('#configuration-notice #configuration-sign-in')?.getClientRects().length"
      ),
      'a visible Sign in'
    );
    assert.equal(
      await page.text('#configuration-content'),
      'Configuration shows once you sign in.'
    );
    assert.equal(await page.text('#connection'), 'Signed out');
    // It signs in, and the page it was opened at loads.
    await clickVisible(page, '#configuration-sign-in');
    await page.waitFor(dialogOpen, 10000);
    await submitSignIn(page, 'reauth', password);
    await page.waitFor(
      `${dialogClosed} && document.querySelector('#configuration-notice').hidden && document.querySelector('#account-details')`,
      10000
    );
    await page.waitFor(
      "document.querySelectorAll('#sessions-list tbody [data-session]').length > 0",
      10000
    );
    await noViolations(page);
  }
);

test(
  'S15 signing in again after Cancel through a request no load follows clears the signed-out notice',
  { skip },
  async t => {
    // After Cancel, the Account page's own request opens the dialog: signing in there loads
    // the sessions but no dashboard, and the page must not go on saying "Signed out" with a
    // Sign in button beside them (§16 C7).
    const orbit = await orbitWithPassword(t);
    const page = await openTab(t, orbit.url + '/', { ready: signInView });
    await signInThroughView(page);
    await page.eval("location.hash = '#configure/account'");
    await page.waitFor("document.querySelector('#account-details')");
    await signOutEverywhere(orbit);
    await page.eval('window.__poll()');
    await page.waitFor(dialogOpen, 10000);
    await page.eval("document.querySelector('#reauth-cancel').click()");
    await page.waitFor("document.querySelector('#configuration-notice').hidden === false", 5000);
    await page.eval("location.hash = '#configure/overview'");
    await page.waitFor("document.querySelector('#configuration-section-title')");
    await page.eval("location.hash = '#configure/account'");
    await page.waitFor(dialogOpen, 10000);
    await submitSignIn(page, 'reauth', password);
    await page.waitFor(
      `${dialogClosed} && document.querySelectorAll('#sessions-list tbody [data-session]').length > 0`,
      10000
    );
    assert.equal(await page.eval("document.querySelector('#configuration-notice').hidden"), true);
    assert.notEqual(await page.text('#connection'), 'Signed out');
    // The load that signing in started brings the dashboard back too.
    await page.waitFor(
      "!['Signed out', 'Connecting…'].includes(document.querySelector('#connection').textContent)",
      10000
    );
    assert.equal(await page.eval("document.querySelector('#notice').hidden"), true);

    // Cancelled on the Account page itself, whose own requests were refused, and signed in from
    // the notice without leaving it: the page shows the list again, not those refusals (§17 E5).
    await signOutEverywhere(orbit);
    await page.eval("location.hash = '#configure/overview'");
    await page.waitFor("document.querySelector('#configuration-section-title')");
    await page.eval("location.hash = '#configure/account'");
    await page.waitFor(dialogOpen, 10000);
    await page.eval("document.querySelector('#reauth-cancel').click()");
    await page.waitFor(
      `${dialogClosed} && document.querySelector('#configuration-notice').hidden === false`,
      5000
    );
    assert.match(await page.text('#account-sign-in'), /Your session has ended\. Sign in again\./);
    // Once the closed dialog's 'close' event has run (as S12 waits), Sign in asks again.
    await page.settle();
    await page.eval("document.querySelector('#configuration-sign-in').click()");
    await page.waitFor(dialogOpen, 10000);
    await submitSignIn(page, 'reauth', password);
    await page.waitFor(
      `${dialogClosed} && document.querySelectorAll('#sessions-list tbody [data-session]').length === 2`,
      10000
    );
    assert.doesNotMatch(await page.text('#configuration-content'), /Your session has ended/);
    assert.match(await page.text('#account-sign-in'), /Login name/);
    assert.equal(await page.eval("document.querySelector('#sign-out-others').disabled"), false);
    await noViolations(page);
  }
);

test(
  'S18 one Cancel closes the sign-in dialog for the Account page’s Sign out buttons and the email form',
  { skip },
  async t => {
    // Each of these read again after a failure. After Cancel that read was refused too and asked
    // again while the dialog was closing, which kept it open: it took a second Cancel (§17 E4).
    const orbit = await orbitWithPassword(t);
    for (const [hash, action, how] of [
      ['#configure/account', '[data-revoke-session]', 'Cancel'],
      ['#configure/account', '#sign-out-others', 'Escape'],
      ['#configure/email', '#test-email', 'Escape'],
      ['#configure/email', '#email-form [type=submit]', 'Cancel'],
    ]) {
      // A second device, so the Account page has a session to sign out: signed in first, since
      // a session ends only those that signed in no later than it.
      await signIn(orbit.url, password);
      const page = await openTab(t, orbit.url + '/', { ready: signInView });
      await signInThroughView(page);
      await page.eval(`location.hash = ${js(hash)}`);
      await page.waitFor(`document.querySelector(${js(action)})?.disabled === false`, 10000);
      await page.eval(`(() => {
        window.__opens = 0;
        const dialog = document.querySelector('#signin-dialog');
        new MutationObserver(() => dialog.open && window.__opens++).observe(dialog, {
          attributes: true,
          attributeFilter: ['open'],
        });
      })()`);
      await signOutEverywhere(orbit);
      await page.eval(`document.querySelector(${js(action)}).click()`);
      await page.waitFor(dialogOpen, 10000);
      // Its entry motion over, so the click lands on Cancel.
      await page.waitFor(
        "document.querySelector('#signin-dialog').getAnimations({ subtree: true }).every(a => a.playState !== 'running')"
      );
      if (how === 'Escape') await page.press('Escape');
      else await page.click('#reauth-cancel');
      await page.waitFor(dialogClosed, 3000);
      await delay(500);
      assert.equal(await page.eval(dialogOpen), false, `${action}: closed by one ${how}`);
      assert.equal(await page.eval('window.__opens'), 1, `${action}: asked once`);
      assert.equal(await page.text('#configuration-notice'), signedOutText);
      assert.equal(await page.text('#connection'), 'Signed out');
      await noViolations(page);
    }
  }
);

test(
  'S19 Notifications: one Cancel ends a Refresh, and the reads after a Retry, that found the session ended; a Retry signed in again keeps its key and sends once',
  { skip, timeout: 60000 },
  async t => {
    // Refresh read the delivery status and then both lists. After Cancel the status read was
    // refused, and the history's read was refused too and asked again while the dialog was
    // closing, which kept it open: it took a second Cancel (delivery spec A64, sessions spec E4).
    // The reads after a Retry or Resume did the same, and load() with them.
    const receiver = { status: 500, requests: [] };
    const server = http.createServer(async (req, res) => {
      let body = '';
      for await (const chunk of req) body += chunk;
      receiver.requests.push(JSON.parse(body));
      res.writeHead(receiver.status, { 'Content-Type': 'application/json' });
      res.end('{}');
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    // A failed send waits a minute: only Retry sends it again within this test.
    const orbit = await orbitWithPassword(t, {
      webhook: `http://127.0.0.1:${server.address().port}/hook`,
      delivery: { pollMs: 100, policy: { baseMs: 60000, capMs: 60000 } },
    });
    for (const n of [1, 2])
      await orbit.app.alerting.enqueueDirect(
        {
          service: 'linux',
          name: `Alert ${n}`,
          kind: 'firing',
          category: 'threshold',
          rule: `s19-${n}`,
          message: 'CPU is above 80%',
          time: Date.now(),
        },
        `test:s19-${n}`
      );
    const admin = sessionCall(orbit.url, (await signIn(orbit.url, password)).cookie);
    for (let end = Date.now() + 15000; ; await delay(50)) {
      const { body } = await admin('/api/notifications');
      if (body.channels?.find(c => c.id === 'env-webhook')?.counts?.retrying === 2) break;
      assert.ok(Date.now() < end, 'two notifications waiting to retry');
    }
    const page = await openTab(t, orbit.url + '/', { ready: signInView });
    await signInThroughView(page);
    await page.eval("location.hash = '#configure/notifications'");
    const retries = "document.querySelectorAll('#attention-list [data-retry-delivery]').length";
    await page.waitFor(`${retries} === 2`, 10000);
    // Every API request the page sends, with its Idempotency-Key, but the session checks
    // (GET /api/session, signIn: false), which never ask anyone to sign in.
    const sent = [];
    const record = message => {
      if (message.sessionId !== page.sessionId || message.method !== 'Network.requestWillBeSent')
        return;
      const { url, method, headers } = message.params.request,
        path = new URL(url).pathname,
        key = Object.entries(headers).find(([name]) => /^idempotency-key$/i.test(name));
      if (path.startsWith('/api/') && path !== '/api/session')
        sent.push({ method, path, key: key?.[1] ?? null });
    };
    page.cdp.listeners.add(record);
    t.after(() => page.cdp.listeners.delete(record));
    await page.eval(`(() => {
      window.__opens = 0;
      const dialog = document.querySelector('#signin-dialog');
      new MutationObserver(() => dialog.open && window.__opens++).observe(dialog, {
        attributes: true,
        attributeFilter: ['open'],
      });
    })()`);
    const cancelOnce = async what => {
      await page.waitFor(dialogOpen, 10000);
      // Its entry motion over, so the click lands on Cancel.
      await page.waitFor(
        "document.querySelector('#signin-dialog').getAnimations({ subtree: true }).every(a => a.playState !== 'running')"
      );
      await page.click('#reauth-cancel');
      await page.waitFor(dialogClosed, 3000).catch(() => {});
      await delay(500);
      assert.equal(await page.eval(dialogOpen), false, `${what}: closed by one Cancel`);
      assert.equal(await page.eval('window.__opens'), 1, `${what}: asked once`);
    };
    const refused = 'Delivery status is unavailable: Your session has ended. Sign in again.';

    // Refresh with the session ended: one Cancel, and nothing is read after the status.
    await signOutEverywhere(orbit);
    sent.length = 0;
    await page.eval("document.querySelector('#notifications-refresh').click()");
    await cancelOnce('Refresh');
    assert.deepEqual(
      sent.map(r => r.path),
      ['/api/notifications'],
      'Refresh reads nothing after the refused status'
    );
    assert.equal(await page.text('#notifications-summary'), refused);
    // Each list says why, with Try again, rather than showing what it read before as current.
    for (const list of ['#attention-list', '#history-list'])
      assert.equal(await page.text(list), `${refused} Try again`, list);
    assert.equal(await page.text('#configuration-notice'), signedOutText);
    // Signed in again from the notice, the page reads its lists again (reloadSection()).
    await page.settle();
    await page.eval("document.querySelector('#configuration-sign-in').click()");
    await page.waitFor(dialogOpen, 10000);
    await submitSignIn(page, 'reauth', password);
    await page.waitFor(`${dialogClosed} && ${retries} === 2`, 10000);

    // The companion: Retry with the session ended asks to sign in, then sends the same request
    // with the same Idempotency-Key, and Uptime Goblin sends the notification once.
    receiver.status = 200;
    const [first, second] = await page.eval(
      "[...document.querySelectorAll('#attention-list [data-retry-delivery]')].map(b => b.dataset.retryDelivery)"
    );
    await signOutEverywhere(orbit);
    sent.length = 0;
    const before = receiver.requests.length;
    await page.eval(
      `document.querySelector('#attention-list [data-retry-delivery=${js(first)}]').click()`
    );
    await page.waitFor(dialogOpen, 10000);
    await submitSignIn(page, 'reauth', password);
    await page.waitFor(
      "document.querySelector('#notifications-result').textContent === 'Uptime Goblin sends this notification again now.'",
      10000
    );
    await page.waitFor(`${dialogClosed} && ${retries} === 1`, 10000);
    const posts = sent.filter(r => r.method === 'POST' && r.path.endsWith('/retry'));
    assert.equal(posts.length, 2, 'refused, then sent again once signed in');
    assert.match(posts[0].key, /^[0-9a-f-]{36}$/);
    assert.equal(posts[1].key, posts[0].key, 'the same Idempotency-Key');
    for (let end = Date.now() + 10000; receiver.requests.length === before; await delay(50))
      assert.ok(Date.now() < end, 'the retried notification is sent');
    await delay(300);
    assert.equal(receiver.requests.length, before + 1, 'sent once');

    // The session ends as Uptime Goblin answers a Retry: the reads after it are refused, one Cancel
    // closes the dialog, and neither the lists nor the dashboard are read after the status.
    const paused = message => {
      if (message.sessionId !== page.sessionId || message.method !== 'Fetch.requestPaused') return;
      signOutEverywhere(orbit)
        .finally(() => page.send('Fetch.continueRequest', { requestId: message.params.requestId }))
        .catch(() => {});
    };
    page.cdp.listeners.add(paused);
    t.after(() => page.cdp.listeners.delete(paused));
    await page.send('Fetch.enable', {
      patterns: [{ urlPattern: '*/retry', requestStage: 'Response' }],
    });
    await page.settle();
    await page.eval('window.__opens = 0');
    sent.length = 0;
    await page.eval(
      `document.querySelector('#attention-list [data-retry-delivery=${js(second)}]').click()`
    );
    await cancelOnce('after Retry');
    await page.send('Fetch.disable');
    assert.equal(
      await page.text('#notifications-result'),
      'Uptime Goblin sends this notification again now.'
    );
    assert.deepEqual(
      sent.map(r => r.path),
      [`/api/notifications/deliveries/${second}/retry`, '/api/notifications'],
      'nothing is read after the refused status'
    );
    for (const list of ['#attention-list', '#history-list'])
      assert.equal(await page.text(list), `${refused} Try again`, list);
    assert.equal(await page.text('#configuration-notice'), signedOutText);
    await noViolations(page);
  }
);

test(
  'S16 a sign-out that does not reach Uptime Goblin keeps the page, says so, and the session stays listed',
  { skip },
  async t => {
    // Uptime Goblin restarting, a dropped link or the time limit: the cookie and the session are both
    // still valid, so a fresh page would sign itself back in without a word (§16 C5).
    const orbit = await orbitWithPassword(t);
    let failLogout = true;
    const page = await openTab(t, orbit.url + '/', {
      ready: signInView,
      before: page => failRequests(t, page, '*/api/auth/logout*', () => failLogout),
    });
    const { responses } = recordResponses(t, page);
    await signInThroughView(page);
    responses.length = 0;
    await page.eval("document.querySelector('#user-chip').click()");
    await page.eval("document.querySelector('#sign-out').click()");
    await page.waitFor("document.querySelector('#sign-out-error').hidden === false", 10000);
    assert.equal(
      await page.text('#sign-out-error'),
      'Uptime Goblin did not confirm the sign-out, so this browser may still be signed in. Try again.'
    );
    assert.equal(
      await page.eval("document.querySelector('#sign-out-error').getAttribute('role')"),
      'alert'
    );
    assert.equal(await page.eval("document.querySelector('#sign-out').disabled"), false);
    assert.equal(await page.eval(signInView), false, 'the page did not start again');
    assert.ok(await page.eval(cards));
    assert.equal(responses.filter(r => r.path === '/api/session').length, 0, 'no new start');
    const listed = await page.eval(
      "fetch('/api/account/sessions', { headers: { 'X-Goblin-Request': '1', 'X-Goblin-Client': 'web/test' } }).then(r => r.json()).then(b => b.sessions.length)"
    );
    assert.equal(listed, 1, 'the session is still listed: Uptime Goblin never saw the sign-out');
    // Pressed again once Uptime Goblin answers: signed out.
    failLogout = false;
    await page.eval("document.querySelector('#sign-out').click()");
    await page.waitFor(signInView, 10000);
    assert.deepEqual(await sessionCookies(page, orbit.url), []);
    await noViolations(page);
  }
);

test(
  'S16b a sign-out Uptime Goblin could not record keeps the page and the cookie; pressing Sign out again removes the session',
  { skip },
  async t => {
    // §20 H1. On a full disk the delete fails: Uptime Goblin refuses the session, but only in this
    // process, and a crash before its hourly cleanup would let it back in. Before, the failed
    // answer expired the cookie, so the press the page asked for came without a session, got a
    // 401, and started the page again at the sign-in view as if signed out, while the row
    // stayed. Now the browser keeps its cookie until Uptime Goblin has recorded the sign-out.
    const orbit = await orbitWithPassword(t);
    const page = await openTab(t, orbit.url + '/', { ready: signInView });
    await signInThroughView(page);
    const db = orbit.app.control.db,
      write = db.write.bind(db);
    let failing = 0;
    db.write = (...args) =>
      failing-- > 0
        ? Promise.reject(
            Object.assign(new Error('database or disk is full'), {
              code: 'SQLITE_FULL',
              class: 'full',
            })
          )
        : write(...args);
    const rows = () => db.read(tx => tx.all(sql`SELECT id FROM sessions`));
    assert.equal((await rows()).length, 1);
    failing = 1;
    await page.eval("document.querySelector('#user-chip').click()");
    await page.eval("document.querySelector('#sign-out').click()");
    await page.waitFor("document.querySelector('#sign-out-error').hidden === false", 10000);
    assert.match(
      await page.text('#sign-out-error'),
      /^Uptime Goblin's disk is full, so it could not record this sign-out\. .* then try again\.$/
    );
    assert.equal(await page.eval("document.querySelector('#sign-out').disabled"), false);
    assert.equal(await page.eval(signInView), false, 'the page did not start again');
    assert.equal((await sessionCookies(page, orbit.url)).length, 1, 'the cookie is kept');
    assert.equal((await rows()).length, 1, 'not recorded');
    // Pressed again, the disk having space: Uptime Goblin deletes the session, and only then does the
    // page start again at the sign-in view, without the cookie.
    await page.eval("document.querySelector('#sign-out').click()");
    await page.waitFor(signInView, 10000);
    assert.deepEqual(await sessionCookies(page, orbit.url), []);
    assert.deepEqual(await rows(), []);
    await noViolations(page);
  }
);

test(
  'S17 a password change keeps the focus in its form, across a sign-in again too',
  { skip },
  async t => {
    // lockForm() disables the field Enter was pressed in, which drops the focus to <body>: a
    // keyboard user would start again from the top of the page (§16 C9).
    const orbit = await orbitWithPassword(t);
    const page = await openTab(t, orbit.url + '/', { ready: signInView });
    await signInThroughView(page);
    await page.eval("location.hash = '#configure/account'");
    await page.waitFor("document.querySelector('#password-form')");
    const changed = 'a brand new passphrase for orbit';
    const fill = async current => {
      await page.setValue('#current-password', current);
      await page.setValue('#new-password', changed);
      await page.setValue('#confirm-new-password', changed);
      await page.eval("document.querySelector('#confirm-new-password').focus()");
      await page.press('Enter');
    };
    await fill('not the current password at all');
    await page.waitFor("document.querySelector('#password-error').hidden === false", 10000);
    assert.equal(await page.text('#password-error'), 'The current password is incorrect.');
    await page.settle();
    assert.equal(await page.eval(focusedElement), 'confirm-new-password');
    // The session ends meanwhile: the save asks to sign in again, then finishes, and the
    // focus comes back to the form.
    await signOutEverywhere(orbit);
    await fill(password);
    await page.waitFor(dialogOpen, 10000);
    await page.waitFor("document.activeElement?.id === 'reauth-password'");
    await page.setValue('#reauth-password', password);
    await page.press('Enter');
    await page.waitFor("document.querySelector('#password-result').hidden === false", 10000);
    assert.equal(
      await page.text('#password-result'),
      'Password changed. Other devices were signed out.'
    );
    await page.waitFor(dialogClosed, 5000);
    await page.settle();
    await delay(300);
    assert.equal(await page.eval(focusedElement), 'confirm-new-password');
    await signIn(orbit.url, changed);
    await noViolations(page);
  }
);

test(
  'S9 a page on the Uptime Goblin computer itself gets the sign-in view: there is no passwordless local preview',
  { skip },
  async t => {
    // 1.4.x and earlier 1.5 builds showed the dashboard here without a password ("Local
    // preview"); Uptime Goblin now always has one, and loopback is signed out like any other address.
    const orbit = await orbitWithPassword(t);
    const page = await openTab(t, orbit.url + '/', { ready: signInView });
    assert.equal(await page.eval(cards), null);
    assert.equal(await page.eval("document.querySelector('#user-chip').hidden"), true);
    assert.equal(await page.eval("document.body.textContent.includes('Local preview')"), false);
    await noViolations(page);
  }
);

// S7: tabs open across an upgrade from 1.4.x, and a 1.5 tab across a rollback (§9.1 T1, T2, B1).
// Releases run as their own processes on one port and one data directory, as an installation
// replaces them; they skip like the upgrade suite without the release fixtures (and git for
// v1.4.3), unless TEST_REQUIRE lists fixtures.

test(
  'S7 T1 a 1.4.2 tab signed in with Basic gets a JSON 401 and its notice after the upgrade, counts nothing, and signs in after a reload',
  { skip },
  async t => {
    if (skipWithoutFixtures(t)) return;
    const app = installRelease('1.4.2', path.join(temporary(t, 'orbit-app-'), '1.4.2')),
      data = temporary(t, 'orbit-data-');
    let server = await start(t, { app, data });
    const url = `http://127.0.0.1:${server.port}/`;
    const page = await openTab(t, url, {
      ready: cards,
      before: page =>
        page.send('Network.setExtraHTTPHeaders', { headers: basicHeader(upgradePassword) }),
    });
    const { responses } = recordResponses(t, page);
    await server.stop();
    server = await start(t, { app: workingTree, data, port: server.port });
    await page.eval('window.__poll()');
    await page.waitFor(
      "document.querySelector('#notice')?.textContent.includes('Reload the page to sign in again')",
      10000
    );
    const refusal = responses.find(r => r.path === '/api/dashboard' && r.status === 401);
    assert.match(refusal.headers['content-type'], /application\/json/);
    assert.equal(refusal.headers['www-authenticate'], undefined, 'no browser prompt');
    // Seven more polls, each refused: none of them counts as a failed sign-in.
    for (let i = 0; i < 7; i++) {
      const before = responses.length;
      await page.eval('window.__poll()');
      const end = Date.now() + 5000;
      while (responses.length === before && Date.now() < end) await delay(20);
    }
    assert.ok(responses.filter(r => r.status === 401).length >= 8);
    assert.ok(await login(server.port), 'the same client signs in');
    await page.eval('location.reload()');
    await page.waitFor(signInView, 10000);
    await signInThroughView(page, upgradePassword);
    await noViolations(page);
  }
);

test(
  'S7 T2 1.4.3 tabs after the upgrade: a clean one reloads into the sign-in view, one with a draft offers the reload',
  { skip },
  async t => {
    if (skipWithoutTag(t, 'v1.4.3')) return;
    const app = installTag('v1.4.3', path.join(temporary(t, 'orbit-app-'), 'v1.4.3')),
      data = temporary(t, 'orbit-data-');
    let server = await start(t, { app, data });
    const url = `http://127.0.0.1:${server.port}/`;
    const withBasic = page =>
      page.send('Network.setExtraHTTPHeaders', { headers: basicHeader(upgradePassword) });
    const clean = await openTab(t, url, { ready: cards, before: withBasic });
    const dirty = await openTab(t, url, { ready: cards, before: withBasic });
    const oldBuild = await clean.eval("document.querySelector('meta[name=orbit-build]').content");
    await openDrawer(dirty, 'linux');
    await dirty.setValue('#source-name', 'A 1.4.3 draft');
    await server.stop();
    server = await start(t, { app: workingTree, data, port: server.port });
    await clean.eval('window.__poll()');
    await clean.waitFor(
      `document.querySelector('meta[name=orbit-build]')?.content !== ${js(oldBuild)} && ${signInView}`,
      15000
    );
    // An open drawer stops 1.4.3's polls, so the draft's tab learns of the upgrade when it saves.
    await dirty.eval("document.querySelector('#connection-form [type=submit]').click()");
    await dirty.waitFor("document.querySelector('#update-banner')?.hidden === false", 10000);
    assert.equal(await dirty.eval("document.querySelector('#settings-dialog').open"), true);
    assert.equal(await dirty.eval("document.querySelector('#source-name').value"), 'A 1.4.3 draft');
    assert.equal(
      await dirty.eval("document.querySelector('meta[name=orbit-build]').content"),
      oldBuild
    );
    assert.ok(await login(server.port), 'nothing was counted against this client');
    await signInThroughView(clean, upgradePassword);
    await noViolations(clean);
  }
);

test(
  'S7 B1 a 1.5 tab after a rollback to 1.4.3 asks nobody to sign in, reloads, and 1.4.3’s own prompt signs it in',
  { skip },
  async t => {
    if (skipWithoutTag(t, 'v1.4.3')) return;
    const old = installTag('v1.4.3', path.join(temporary(t, 'orbit-app-'), 'v1.4.3')),
      data = temporary(t, 'orbit-data-');
    let server = await start(t, { app: workingTree, data });
    const url = `http://127.0.0.1:${server.port}/`;
    const page = await openTab(t, url, { ready: signInView });
    await signInThroughView(page, upgradePassword);
    const newBuild = await page.eval("document.querySelector('meta[name=orbit-build]').content");
    // Chrome's Basic prompt: a page load is answered with the password, as a person would;
    // the web app's own requests are cancelled, as a person dismissing it for a fetch would.
    const asked = [];
    const listener = message => {
      if (message.sessionId !== page.sessionId) return;
      if (message.method === 'Fetch.requestPaused')
        page.send('Fetch.continueRequest', { requestId: message.params.requestId }).catch(() => {});
      if (message.method === 'Fetch.authRequired') {
        const document = message.params.resourceType === 'Document';
        asked.push(message.params.resourceType);
        page
          .send('Fetch.continueWithAuth', {
            requestId: message.params.requestId,
            authChallengeResponse: document
              ? { response: 'ProvideCredentials', username: 'admin', password: upgradePassword }
              : { response: 'CancelAuth' },
          })
          .catch(() => {});
      }
    };
    page.cdp.listeners.add(listener);
    t.after(() => page.cdp.listeners.delete(listener));
    await page.send('Fetch.enable', { handleAuthRequests: true, patterns: [{ urlPattern: '*' }] });
    const { requested } = recordResponses(t, page);
    await server.stop();
    server = await start(t, { app: old, data, port: server.port });
    await page.eval('window.__poll()');
    // Reloaded into 1.4.3 (its page names no /boot.js), signed in by the prompt.
    await page.waitFor(
      `document.querySelector('meta[name=orbit-build]')?.content !== ${js(newBuild)} && document.querySelector('script[src^="/app.js"]') && ${cards}`,
      20000
    );
    assert.ok(asked.includes('Document'), 'the page load asked for the password');
    assert.equal(
      requested.filter(p => p === '/api/session').length,
      0,
      'the 1.5 page never asked to sign in again'
    );
  }
);

test(
  'S7 B1 a 1.5 tab with a configuration draft after a rollback to 1.4.3 says to reload, offers no Sign in, and its Reload reaches 1.4.3',
  { skip },
  async t => {
    // It said "Signed out. Sign in to see current readings." with a Sign in that could never
    // work: the dialog's check and each attempt (1.4.3 has neither /api/session nor
    // /api/auth/login) brought up Chrome's Basic prompt, and the right password failed with
    // 1.4.3's "Sign in to Uptime Goblin" (sessions spec §18 F7).
    if (skipWithoutTag(t, 'v1.4.3')) return;
    const old = installTag('v1.4.3', path.join(temporary(t, 'orbit-app-'), 'v1.4.3')),
      data = temporary(t, 'orbit-data-');
    let server = await start(t, { app: workingTree, data });
    const url = `http://127.0.0.1:${server.port}/`;
    const page = await openTab(t, url, { ready: signInView });
    await signInThroughView(page, upgradePassword);
    const newBuild = await page.eval("document.querySelector('meta[name=orbit-build]').content");
    await page.eval("location.hash = '#configure/appearance'");
    await page.waitFor("document.querySelector('#workspace-title')", 10000);
    await page.setValue('#workspace-title', 'A draft across the rollback');
    // Chrome's Basic prompt, as in B1: the page load is answered with the password, the web
    // app's own requests are dismissed. A leave-page prompt for the draft would be accepted, as
    // the banner says the draft is lost.
    const prompted = [];
    const listener = message => {
      if (message.sessionId !== page.sessionId) return;
      if (message.method === 'Page.javascriptDialogOpening')
        page.send('Page.handleJavaScriptDialog', { accept: true }).catch(() => {});
      if (message.method === 'Fetch.requestPaused')
        page.send('Fetch.continueRequest', { requestId: message.params.requestId }).catch(() => {});
      if (message.method === 'Fetch.authRequired') {
        const document = message.params.resourceType === 'Document';
        prompted.push(document ? 'Document' : new URL(message.params.request.url).pathname);
        page
          .send('Fetch.continueWithAuth', {
            requestId: message.params.requestId,
            authChallengeResponse: document
              ? { response: 'ProvideCredentials', username: 'admin', password: upgradePassword }
              : { response: 'CancelAuth' },
          })
          .catch(() => {});
      }
    };
    page.cdp.listeners.add(listener);
    t.after(() => page.cdp.listeners.delete(listener));
    await page.send('Fetch.enable', { handleAuthRequests: true, patterns: [{ urlPattern: '*' }] });
    const { requested } = recordResponses(t, page);
    await server.stop();
    server = await start(t, { app: old, data, port: server.port });
    await page.eval('window.__poll()');
    await page.waitFor("document.querySelector('#update-banner')?.hidden === false", 10000);
    await page.waitFor(
      `document.querySelector('#configuration-notice')?.textContent === ${js(olderReleaseText)}`,
      10000
    );
    await delay(500);
    assert.equal(
      await page.eval("!!document.querySelector('#configuration-sign-in, #notice-sign-in')"),
      false,
      'no Sign in'
    );
    assert.equal(await page.eval(dialogOpen), false);
    assert.equal(await page.text('#connection'), 'Reload needed');
    assert.deepEqual(
      requested.filter(p => p === '/api/session' || p === '/api/auth/login'),
      [],
      'nothing asked to sign in'
    );
    assert.deepEqual([...new Set(prompted)], ['/api/dashboard'], 'only the poll met the prompt');
    assert.equal(
      await page.eval("document.querySelector('#workspace-title').value"),
      'A draft across the rollback'
    );
    // The banner's Reload is the way in: 1.4.3's page, signed in by its own prompt, on the
    // same configuration page.
    await page.eval("document.querySelector('#update-reload').click()");
    await page.waitFor(
      `document.querySelector('meta[name=orbit-build]')?.content !== ${js(newBuild)} && document.querySelector('script[src^="/app.js"]') && document.querySelector('#workspace-title')`,
      20000
    );
    assert.ok(prompted.includes('Document'), 'the page load asked for the password');
  }
);

// S10–S11: the reference deployment (sessions spec §9.2, §9.3) end to end. Real processes, as the
// native installer runs them: 1.4.3, then the working tree on the same port and data, with the
// installer's /etc/uptime-goblin.env (HOST=127.0.0.1, GOBLIN_TRUST_PROXY=loopback, the proxy's hostname
// in GOBLIN_ALLOWED_HOSTS), behind a reverse proxy on the same host that ends TLS as nginx does.
// The browser opens the proxy's https:// address. They skip like S7 without the v1.4.3 tag.

/**
 * nginx in front of Uptime Goblin on the same host: it ends TLS with a throwaway certificate, forwards
 * the Host the browser asked for (`proxy_set_header Host $http_host;`), appends the client to
 * X-Forwarded-For, and sends `X-Forwarded-Proto $scheme` only when `scheme` is true (the line a
 * 1.4.x recipe may lack). Resolves `{url, port}` of its https:// address.
 */
async function nginx(t, upstreamPort, { scheme }) {
  const hopByHop = new Set([
    'connection',
    'keep-alive',
    'proxy-connection',
    'transfer-encoding',
    'te',
    'trailer',
    'upgrade',
  ]);
  const server = https.createServer(selfSignedCertificate(), (req, res) => {
    const headers = {};
    for (const [name, value] of Object.entries(req.headers))
      if (!hopByHop.has(name) && name !== 'x-forwarded-proto') headers[name] = value;
    headers['x-forwarded-for'] = [req.headers['x-forwarded-for'], req.socket.remoteAddress]
      .filter(Boolean)
      .join(', ');
    if (scheme) headers['x-forwarded-proto'] = 'https';
    const upstream = http.request(
      { host: '127.0.0.1', port: upstreamPort, method: req.method, path: req.url, headers },
      answer => {
        const raw = [];
        for (let i = 0; i < answer.rawHeaders.length; i += 2)
          if (!hopByHop.has(answer.rawHeaders[i].toLowerCase()))
            raw.push(answer.rawHeaders[i], answer.rawHeaders[i + 1]);
        res.writeHead(answer.statusCode, raw);
        answer.pipe(res);
      }
    );
    upstream.on('error', () => {
      if (!res.headersSent) res.writeHead(502);
      res.end();
    });
    req.pipe(upstream);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => {
    server.closeAllConnections();
    return new Promise(resolve => server.close(resolve));
  });
  const { port } = server.address();
  return { url: `https://localhost:${port}`, port };
}

/** A script's GET through `proxy` with the harness password (Basic): resolves the status. */
function scriptThrough(proxy, pathname) {
  return new Promise((resolve, reject) =>
    https
      .get(
        `${proxy.url}${pathname}`,
        {
          rejectUnauthorized: false,
          headers: {
            Authorization: 'Basic ' + Buffer.from(`admin:${upgradePassword}`).toString('base64'),
          },
        },
        res => resolve(res.resume().statusCode)
      )
      .on('error', reject)
  );
}

/**
 * A sign-in POST through `proxy` from its own https page with the given password, as the sign-in
 * view sends it: resolves [status, code].
 */
function signInThrough(proxy, password) {
  const body = JSON.stringify({ login: 'admin', password });
  return new Promise((resolve, reject) =>
    https
      .request(
        `${proxy.url}/api/auth/login`,
        {
          method: 'POST',
          rejectUnauthorized: false,
          headers: {
            Origin: proxy.url,
            'Sec-Fetch-Site': 'same-origin',
            'X-Goblin-Request': '1',
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(body),
          },
        },
        res => {
          let text = '';
          res.setEncoding('utf8');
          res.on('data', chunk => (text += chunk));
          res.on('end', () => {
            let code = null;
            try {
              code = JSON.parse(text).code ?? null;
            } catch {}
            resolve([res.statusCode, code]);
          });
        }
      )
      .on('error', reject)
      .end(body)
  );
}

/**
 * A script's GET straight to Uptime Goblin on `port` (from 127.0.0.1, as a proxy on the Uptime Goblin host
 * connects) with the harness password (Basic) and `headers`: resolves the status.
 */
function scriptAt(port, pathname, headers = {}) {
  return new Promise((resolve, reject) =>
    http
      .get(
        {
          host: '127.0.0.1',
          port,
          path: pathname,
          headers: {
            Authorization: 'Basic ' + Buffer.from(`admin:${upgradePassword}`).toString('base64'),
            ...headers,
          },
        },
        res => resolve(res.resume().statusCode)
      )
      .on('error', reject)
  );
}

/**
 * 1.4.3 installed and browsed once through `proxy` (what its run/status.json then records is
 * what the 1.5 installer's preflight reads), then replaced by the working tree on the same port
 * and data directory.
 */
async function ownerUpgrade(t, { scheme }) {
  const old = installTag('v1.4.3', path.join(temporary(t, 'orbit-app-'), 'v1.4.3')),
    data = temporary(t, 'orbit-data-'),
    port = await freePort(),
    proxy = await nginx(t, port, { scheme });
  const ownerEnv = {
    // The names 1.4.3 reads, which the working tree takes too (lib/legacy-names.mjs), as an
    // /etc/orbit.env kept from before the rename gives them.
    ORBIT_TRUST_PROXY: 'loopback',
    ORBIT_ALLOWED_HOSTS: `localhost:${proxy.port}`,
    // The working tree, started supervised, refuses where this machine does not hold Uptime Goblin's
    // limits, unless GOBLIN_ALLOW_UNLIMITED names them (helpers/supervised.mjs); the 1.4.3 start
    // gets the same environment.
    ...supervisedEnv(),
  };
  let server = await start(t, { app: old, data, port, env: ownerEnv });
  const viaProxy = await scriptThrough(proxy, '/api/dashboard');
  assert.equal(viaProxy, 200, '1.4.3 answers through the proxy');
  const observed = JSON.parse(fs.readFileSync(path.join(data, 'run', 'status.json'), 'utf8'))
    .observed.forwardedProto;
  await server.stop();
  server = await start(t, { app: workingTree, data, port, env: ownerEnv });
  return { server, proxy, data, port, observed, ownerEnv };
}

// Chrome does not trust the throwaway certificate; these tests tell it to accept it.
async function acceptTestCertificates(t) {
  await browser.cdp.send('Security.setIgnoreCertificateErrors', { ignore: true });
  t.after(() => browser.cdp.send('Security.setIgnoreCertificateErrors', { ignore: false }));
}

const sessionBanner = "document.querySelector('#session-banner')";

test(
  'S10 behind nginx with X-Forwarded-Proto $scheme, the admin signs in over HTTPS after the upgrade, with the __Host- cookie',
  { skip },
  async t => {
    if (skipWithoutTag(t, 'v1.4.3')) return;
    await acceptTestCertificates(t);
    const { server, proxy, observed } = await ownerUpgrade(t, { scheme: true });
    assert.equal(observed, 'https', 'the installer preflight would let this upgrade through');
    const page = await openTab(t, `${proxy.url}/`, { ready: signInView });
    assert.equal(await page.text('#signin-notice'), '', 'no transport notice');
    await signInThroughView(page, upgradePassword, { remember: true });
    const cookies = await sessionCookies(page, proxy.url);
    assert.deepEqual(
      cookies.map(c => [c.name, c.secure, c.httpOnly, c.sameSite, c.path, c.expires > 0]),
      [['__Host-goblin_session', true, true, 'Strict', '/', true]]
    );
    const session = await page.eval(
      "fetch('/api/session', { headers: { 'X-Goblin-Client': 'web/test' } }).then(r => r.json())"
    );
    assert.equal(session.via, 'session');
    assert.deepEqual(session.transport, {
      kind: 'https',
      https: true,
      insecure: false,
      insecureAllowed: false,
    });
    assert.equal(await page.eval(`${sessionBanner}.hidden`), true, 'no plain-HTTP banner');
    // The cookie carries the next page load: still signed in, no sign-in view.
    await page.eval('location.reload()');
    await page.waitFor(cards, 10000);
    assert.equal(await page.eval("document.querySelector('#signin-page').hidden"), true);
    assert.match(server.output(), /plain-HTTP sessions: refused/);
    await noViolations(page);
  }
);

test(
  'S11 behind nginx without X-Forwarded-Proto, sign-in is refused with the fix; GOBLIN_INSECURE_HTTP_SESSIONS=1 signs in with a banner',
  { skip },
  async t => {
    if (skipWithoutTag(t, 'v1.4.3')) return;
    await acceptTestCertificates(t);
    const owner = await ownerUpgrade(t, { scheme: false });
    assert.equal(owner.observed, 'http', 'the installer preflight would refuse this upgrade');
    const page = await openTab(t, `${owner.proxy.url}/`, { ready: signInView });
    // Before any attempt the view already says what the proxy lacks.
    await page.waitFor(
      "document.querySelector('#signin-notice').textContent.includes('does not tell Uptime Goblin so')"
    );
    await submitSignIn(page, 'signin', upgradePassword);
    await page.waitFor(
      "document.querySelector('#signin-error').textContent.includes('proxy_set_header X-Forwarded-Proto $scheme;')"
    );
    assert.deepEqual(await sessionCookies(page, owner.proxy.url), [], 'no cookie was issued');
    // The journal names the fix too.
    assert.match(
      owner.server.output(),
      /Sign-in refused: the browser used HTTPS \(Origin https:\/\/localhost:\d+\) but the request from 127\.0\.0\.1 carries no X-Forwarded-Proto: https\. Make the proxy send X-Forwarded-Proto: https \(nginx: proxy_set_header X-Forwarded-Proto \$scheme;\)/
    );
    // A script's Basic through the same proxy is plain HTTP to Uptime Goblin too, so it is refused
    // like the sign-in, before its password is checked (https_required); once plain HTTP is
    // allowed (below), it gets in.
    assert.equal(await scriptThrough(owner.proxy, '/api/dashboard'), 403);
    // A refused sign-in is not counted. Ten more through the proxy, five more than the free
    // attempts and with a wrong password, are refused before any check; then a script with
    // the same lockout key (127.0.0.1, the address the proxy names in X-Forwarded-For) that
    // says it used HTTPS still gets in, before the restart that would clear the lockout. Were
    // they counted, a later one would meet the lockout (429), or the key would be locked for
    // 16 seconds after the tenth, so even a slow host's script request would land inside it.
    for (let i = 0; i < 10; i++)
      assert.deepEqual(await signInThrough(owner.proxy, `not the password ${i}`), [
        403,
        'proxy_proto_missing',
      ]);
    assert.equal(
      await scriptAt(owner.port, '/api/dashboard', {
        'X-Forwarded-For': '127.0.0.1',
        'X-Forwarded-Proto': 'https',
      }),
      200
    );
    await noViolations(page);

    // The escape hatch (§9.3 item 2): GOBLIN_INSECURE_HTTP_SESSIONS=1 and a restart.
    await owner.server.stop();
    const insecure = await start(t, {
      app: workingTree,
      data: owner.data,
      port: owner.port,
      env: { ...owner.ownerEnv, GOBLIN_INSECURE_HTTP_SESSIONS: '1' },
    });
    assert.match(insecure.output(), /plain-HTTP sessions: allowed/);
    assert.equal(await scriptThrough(owner.proxy, '/api/dashboard'), 200);
    await page.eval('location.reload()');
    await signInThroughView(page, upgradePassword);
    const cookies = await sessionCookies(page, owner.proxy.url);
    assert.deepEqual(
      cookies.map(c => [c.name, c.secure, c.httpOnly]),
      [['goblin_session', false, true]]
    );
    await page.waitFor(`${sessionBanner}.hidden === false`);
    // The page is already https:, so "Serve Uptime Goblin over HTTPS" would change nothing: the banner
    // names what is missing, the proxy's header (§17 E9).
    assert.equal(
      await page.text('#session-banner'),
      'Your browser uses HTTPS, but the reverse proxy in front of Uptime Goblin does not tell Uptime Goblin so, and with GOBLIN_INSECURE_HTTP_SESSIONS this session signed in as plain HTTP: its sign-in cookie is not marked Secure, so this browser would also send it to a plain http:// address of this host, where the network can see it. In nginx add proxy_set_header X-Forwarded-Proto $scheme; to Uptime Goblin’s location and reload nginx (GOBLIN_TRUST_PROXY must name the proxy), then set GOBLIN_INSECURE_HTTP_SESSIONS=0, restart Uptime Goblin (Docker: in .env, then docker compose up -d) and sign in again.'
    );
    assert.equal(
      await page.text('#session-banner code'),
      'proxy_set_header X-Forwarded-Proto $scheme;'
    );
    await noViolations(page);
  }
);

// B11 and B12 (1.5 release blockers): a browser that reaches Uptime Goblin over plain HTTP from the
// network. The tab sends an X-Forwarded-For that no GOBLIN_TRUST_PROXY names, so Uptime Goblin treats it
// as the `http` transport, as a browser elsewhere on the LAN. Uptime Goblin refuses a sign-in over it
// only once it has the password, which has then crossed the network unencrypted: the web app
// must not ask for it while it knows that refusal will come.
const viaNetwork = page =>
  page.send('Network.setExtraHTTPHeaders', { headers: { 'X-Forwarded-For': '192.0.2.10' } });
// What the sign-in view says where Uptime Goblin allows plain HTTP from the network (B12).
const plainHttpText =
  'This page uses plain HTTP, so your password crosses the network unencrypted when you sign in (GOBLIN_INSECURE_HTTP_SESSIONS allows it). Sign in only on a network you trust, and serve Uptime Goblin over HTTPS.';

test(
  'S20 over plain HTTP from the network the sign-in view offers no form while Uptime Goblin refuses the sign-in; plain-HTTP sessions turned off under an open page ask for no password',
  { skip },
  async t => {
    // GOBLIN_INSECURE_HTTP_SESSIONS off: the view says why, with no form.
    const refusing = await orbitWithPassword(t);
    const view = await openTab(t, refusing.url + '/', { ready: signInView, before: viaNetwork });
    await view.waitFor("document.querySelector('#signin-notice').hidden === false");
    assert.match(
      await view.text('#signin-notice'),
      /^Sign-in needs HTTPS, or a browser on the Uptime Goblin computer itself\. Open Uptime Goblin at its https:\/\/ address\./
    );
    assert.equal(await view.eval("document.querySelector('#signin-form').hidden"), true);
    // That refusal is certain: Uptime Goblin refuses any password there (here a wrong one), with
    // https_required rather than invalid_credentials.
    assert.deepEqual(
      await view.eval(
        `fetch('/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Goblin-Request': '1', 'X-Goblin-Client': 'web/test' }, body: JSON.stringify({ login: 'admin', password: 'not the password at all' }) }).then(async r => [r.status, (await r.json()).code])`
      ),
      [403, 'https_required']
    );
    await noViolations(view);

    // Allowed (GOBLIN_INSECURE_HTTP_SESSIONS=1): the form signs in, and the banner says that
    // the password crosses the network too, and how to turn it off in every install mode.
    const directory = temporaryDirectory(t);
    let orbit = await startOrbit({ directory, password, insecureHttpSessions: true });
    t.after(() => orbit.close());
    const page = await openTab(t, orbit.url + '/', { ready: signInView, before: viaNetwork });
    // The page is at a loopback name (127.0.0.1), so it cannot tell this from a browser on
    // the Uptime Goblin computer, and warns of nothing: S21 shows the warning at another name.
    assert.equal(await page.eval("document.querySelector('#signin-notice').hidden"), true);
    assert.equal(await page.eval("document.querySelector('#signin-form').hidden"), false);
    await signInThroughView(page);
    await page.waitFor(`${sessionBanner}.hidden === false`);
    assert.equal(
      await page.text('#session-banner'),
      'This session uses plain HTTP, so anyone who can watch the traffic between your browser and Uptime Goblin can see its sign-in cookie, and your password each time you sign in or change it. Serve Uptime Goblin over HTTPS, then set GOBLIN_INSECURE_HTTP_SESSIONS=0 and restart Uptime Goblin (Docker: in .env, then docker compose up -d).'
    );

    // Turned off while the page is open: the restart signs that session out, and the page's
    // next poll is refused. Nobody is asked for the password: the notices say why, with no
    // Sign in, and nothing is sent to /api/auth/login.
    const port = orbit.port;
    await orbit.close();
    const logged = [];
    const log = {
      info: (...args) => logged.push(args.join(' ')),
      log: (...args) => logged.push(args.join(' ')),
      warn: (...args) => logged.push(args.join(' ')),
      error: (...args) => logged.push(args.join(' ')),
    };
    orbit = await startOrbit({
      directory,
      password,
      port,
      insecureHttpSessions: false,
      identityOptions: { log },
    });
    assert.ok(
      logged.includes(
        'Signed out 1 session that signed in over plain HTTP: GOBLIN_INSECURE_HTTP_SESSIONS is off.'
      ),
      logged.join('\n')
    );
    const { requested } = recordResponses(t, page);
    await page.eval('window.__poll()');
    await page.waitFor(
      "document.querySelector('#notice').textContent.startsWith('Sign-in needs HTTPS')",
      10000
    );
    await delay(500);
    assert.equal(await page.eval(dialogOpen), false, 'no sign-in dialog');
    assert.equal(
      await page.eval("!!document.querySelector('#notice-sign-in, #configuration-sign-in')"),
      false,
      'no Sign in'
    );
    assert.equal(await page.text('#connection'), 'Signed out');
    assert.ok(requested.includes('/api/session'), requested.join(' '));
    assert.ok(!requested.includes('/api/auth/login'), requested.join(' '));
    await noViolations(page);
  }
);

// B11 and B12 through a reverse proxy on the Uptime Goblin host that sends no forwarding headers and
// keeps a loopback Host (nginx's default Host with a bare proxy_pass). Uptime Goblin answers such a
// request `loopback`, but the page has another name, so the browser is anywhere, and Uptime Goblin
// signs it in only as plain HTTP (sessionTransport() in lib/http/routes/auth.mjs). The page
// showed a form, sent the password, and only then got 403 https_required. Chrome takes
// *.localhost to this computer, so the page's own name is not a loopback one.
async function headerlessProxy(t) {
  let upstream = null;
  const dropped = new Set([
    'x-forwarded-for',
    'x-forwarded-proto',
    'x-forwarded-host',
    'forwarded',
    'x-real-ip',
    'connection',
    'keep-alive',
  ]);
  const server = http.createServer((req, res) => {
    const headers = { host: `127.0.0.1:${upstream}` };
    for (const [name, value] of Object.entries(req.headers))
      if (name !== 'host' && !dropped.has(name)) headers[name] = value;
    const forward = http.request(
      { host: '127.0.0.1', port: upstream, method: req.method, path: req.url, headers },
      answer => {
        res.writeHead(answer.statusCode, answer.headers);
        answer.pipe(res);
      }
    );
    forward.on('error', () => {
      if (!res.headersSent) res.writeHead(502);
      res.end();
    });
    req.pipe(forward);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => {
    server.closeAllConnections();
    return new Promise(resolve => server.close(resolve));
  });
  const { port } = server.address();
  return {
    host: `orbit.localhost:${port}`,
    url: `http://orbit.localhost:${port}`,
    to: orbitPort => (upstream = orbitPort),
  };
}

test(
  'S21 through a proxy on the Uptime Goblin host that sends no forwarding headers, the sign-in view offers no form while Uptime Goblin refuses plain HTTP, and warns when it allows it',
  { skip },
  async t => {
    const proxy = await headerlessProxy(t);
    const refusing = await orbitWithPassword(t, { allowedHosts: proxy.host });
    proxy.to(refusing.port);
    const view = await openTab(t, proxy.url + '/', { ready: signInView });
    await view.waitFor("document.querySelector('#signin-notice').hidden === false");
    assert.match(
      await view.text('#signin-notice'),
      /^Sign-in needs HTTPS, or a browser on the Uptime Goblin computer itself\./
    );
    assert.equal(await view.eval("document.querySelector('#signin-form').hidden"), true);
    // Uptime Goblin answered `loopback`: only the page's own name tells the proxy apart.
    assert.deepEqual(
      await view.eval(
        `fetch('/api/session', { headers: { 'X-Goblin-Request': '1', 'X-Goblin-Client': 'web/test' } }).then(async r => [r.status, (await r.json()).transport])`
      ),
      [401, { kind: 'loopback', insecureAllowed: false }]
    );
    // The refusal is certain: any password (here a wrong one) gets https_required.
    assert.deepEqual(
      await view.eval(
        `fetch('/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Goblin-Request': '1', 'X-Goblin-Client': 'web/test' }, body: JSON.stringify({ login: 'admin', password: 'not the password at all' }) }).then(async r => [r.status, (await r.json()).code])`
      ),
      [403, 'https_required']
    );
    await noViolations(view);

    // Plain-HTTP sessions allowed: the form signs in, as plain HTTP, after the warning.
    const allowing = await orbitWithPassword(t, {
      allowedHosts: proxy.host,
      insecureHttpSessions: true,
    });
    proxy.to(allowing.port);
    const page = await openTab(t, proxy.url + '/', { ready: signInView });
    assert.equal(await page.text('#signin-notice'), plainHttpText);
    assert.equal(await page.eval("document.querySelector('#signin-form').hidden"), false);
    await signInThroughView(page);
    await page.waitFor(`${sessionBanner}.hidden === false`);
    assert.match(await page.text('#session-banner'), /^This session uses plain HTTP/);
    await noViolations(page);
  }
);

test(
  'S22 a sign-in view that offers no form looks again when the tab comes back: once plain-HTTP sessions are allowed and Uptime Goblin restarted it offers the form, or gives way to the dashboard another tab signed in',
  { skip },
  async t => {
    // The independent checkpoint-2 review (CLIENT-1). The view says to set GOBLIN_INSECURE_HTTP_SESSIONS=1
    // and restart Uptime Goblin, and offers no form until then. The admin did, and came back to the tab: it
    // asked Uptime Goblin nothing, so the form never came, and nothing said that only a reload would
    // bring it. The page here is at orbit.localhost, through the proxy of S21, so Uptime Goblin is
    // restarted on the same port without the page's address changing.
    const proxy = await headerlessProxy(t);
    const directory = temporaryDirectory(t);
    let orbit = await startOrbit({ directory, password, allowedHosts: proxy.host });
    t.after(() => orbit.close());
    proxy.to(orbit.port);
    const formHidden = "document.querySelector('#signin-form').hidden";
    const focusTab = page => page.eval("window.dispatchEvent(new Event('focus'))");
    const refusedView = async () => {
      const page = await openTab(t, proxy.url + '/', { ready: signInView });
      await page.waitFor("document.querySelector('#signin-notice').hidden === false");
      assert.match(
        await page.text('#signin-notice'),
        /^Sign-in needs HTTPS, or a browser on the Uptime Goblin computer itself\./
      );
      assert.equal(await page.eval(formHidden), true);
      // Gone if the page reloads: everything below happens in the page that was refused.
      await page.eval('window.__samePage = true');
      return page;
    };
    const view = await refusedView();
    const other = await refusedView();
    const { requested } = recordResponses(t, view);

    // Still refused: the look asks Uptime Goblin, and the same refusal is not drawn again (the notice is
    // a status region, which would read it out at every look). The focus stays where the admin left
    // it, here nowhere (<body>), rather than jump to the view's heading at every look.
    await view.eval("window.__refusal = document.querySelector('#signin-notice').firstChild");
    await view.eval('document.activeElement.blur()');
    await focusTab(view);
    const end = Date.now() + 5000;
    while (!requested.includes('/api/session') && Date.now() < end) await delay(20);
    assert.deepEqual(requested, ['/api/session'], 'the look at the tab asks Uptime Goblin again');
    await view.settle();
    assert.equal(await view.eval(formHidden), true);
    assert.equal(
      await view.eval("document.querySelector('#signin-notice').firstChild === window.__refusal"),
      true,
      'the unchanged refusal is not drawn again'
    );
    assert.equal(await view.eval('document.activeElement === document.body'), true);

    // The admin sets GOBLIN_INSECURE_HTTP_SESSIONS=1 and restarts Uptime Goblin, and is back before it
    // answers: the view says it is waiting (the dashboard's notice is hidden behind it), and
    // offers the form once Uptime Goblin is back, with the plain-HTTP warning in place of the refusal,
    // without another look and without a reload.
    const port = orbit.port;
    await orbit.close();
    await focusTab(view);
    await view.waitFor(
      "document.querySelector('#signin-notice').textContent === 'Uptime Goblin is not answering. This page connects by itself once it is back.'",
      10000
    );
    assert.equal(await view.eval(formHidden), true);
    assert.equal(await view.text('#connection'), 'Reconnecting…');
    orbit = await startOrbit({
      directory,
      password,
      port,
      allowedHosts: proxy.host,
      insecureHttpSessions: true,
    });
    await view.waitFor(`${formHidden} === false`, 10000);
    assert.equal(await view.text('#signin-notice'), plainHttpText);
    assert.equal(await view.eval("document.querySelector('#notice').hidden"), true);
    assert.equal(await view.eval('window.__samePage'), true, 'no reload');
    await signInThroughView(view);

    // The other refused tab, when it comes into view: the cookie that sign-in left is this
    // browser's, so its view gives way to the dashboard, as after its own sign-in.
    await other.eval("document.dispatchEvent(new Event('visibilitychange'))");
    await other.waitFor(cards, 10000);
    assert.equal(await other.eval(signInView), false);
    assert.equal(await other.eval("document.querySelector('#dashboard-page').hidden"), false);
    assert.equal(await other.eval(dialogOpen), false);
    assert.equal(await other.eval('window.__samePage'), true, 'no reload');
    assert.equal(
      await other.eval(
        "document.activeElement === document.querySelector('#dashboard-title').closest('h1')"
      ),
      true,
      'the focus moves from the sign-in view to the dashboard’s heading'
    );
    await noViolations(view);
    await noViolations(other);
  }
);

/** A waiting display code in `orbit`'s control.sqlite, as goblin-admin display code makes it. */
async function displayCode(orbit, name = 'Lobby TV') {
  const { newDisplayCode } = await import('../lib/identity/secrets.mjs');
  const { identityOps } = await import('../lib/repo/identity.mjs');
  const made = newDisplayCode();
  const now = Date.now();
  await orbit.app.control.db.write(tx =>
    identityOps.insertDisplay(tx, {
      id: made.id,
      name,
      codeHash: made.codeHash,
      codeExpiresAt: now + 10 * 60e3,
      createdAt: now,
      createdBy: 'cli:test',
    })
  );
  return made.code;
}

test(
  'W1 a ?kiosk=1 page asks for a display code, catches a typo itself, and then shows the dashboard read-only',
  { skip },
  async t => {
    const orbit = await orbitWithPassword(t);
    const page = await openTab(t, orbit.url + '/?kiosk=1', { ready: signInView });
    const into = recordResponses(t, page);
    await page.settle();
    assert.equal(await page.eval("document.querySelector('#display-form').hidden"), false);
    assert.equal(await page.eval("document.querySelector('#signin-form').hidden"), true);
    assert.equal(
      await page.eval("document.querySelector('#signin-title').textContent"),
      'Set up this wall display'
    );
    // Only the code form: no password field, no link to one, and a code input no password
    // manager pairs with a login (B6 design §7.7).
    assert.equal(
      await page.eval(
        "[...document.querySelectorAll('#signin-page input, #signin-page button')].some(e => e.checkVisibility() && (e.type === 'password' || /password/i.test(e.textContent)))"
      ),
      false
    );
    assert.equal(
      await page.eval("document.querySelector('#display-code').hasAttribute('name')"),
      false
    );
    assert.match(
      await page.eval("document.querySelector('#display-intro').textContent"),
      /This browser will only show the dashboard\. It cannot change anything\./
    );
    assert.equal(
      await page.eval("document.querySelector('#display-code-hint').textContent"),
      '26 characters; spaces and dashes are optional.'
    );
    // A wrong check symbol is caught before anything is sent.
    const code = await displayCode(orbit);
    const last = code.at(-1);
    await page.setValue('#display-code', code.slice(0, -1) + (last === '0' ? '1' : '0'));
    await page.eval("document.querySelector('#display-submit').click()");
    await page.waitFor("document.querySelector('#display-error').hidden === false");
    assert.match(
      await page.eval("document.querySelector('#display-error').textContent"),
      /has a typo/
    );
    assert.ok(!into.requested.includes('/api/auth/login'), 'a typo is not sent');
    // Typed loosely, the real code signs the display in.
    await page.setValue('#display-code', code.toLowerCase().replaceAll('-', ' '));
    await page.eval("document.querySelector('#display-submit').click()");
    await page.waitFor(cards, 10000);
    await page.settle();
    assert.equal(await page.eval("document.body.classList.contains('display-mode')"), true);
    assert.equal(
      await page.eval("document.querySelector('#user-chip-name').textContent"),
      'Wall display'
    );
    for (const selector of [
      '#settings',
      '#refresh',
      '#add-source',
      '.user-area',
      '#footer-status',
      '.launch-note',
      '.pause-control',
      '[data-configure]',
    ])
      assert.equal(
        await page.eval(
          `[...document.querySelectorAll('${selector}')].some(e => e.checkVisibility())`
        ),
        false,
        selector
      );
    assert.equal(await page.eval("document.querySelector('#display-banner').hidden"), true);
    assert.equal(
      await page.eval("document.querySelector('#display-footer').checkVisibility()"),
      true
    );
    assert.match(
      await page.eval("document.querySelector('#display-footer').textContent"),
      /Wall display · read-only\s+Sign out/
    );
    // A poll reads the dashboard, and never what a display may not read.
    await page.eval('window.__poll()');
    await page.settle();
    assert.ok(into.requested.includes('/api/dashboard'));
    assert.deepEqual(
      into.responses.filter(r => r.status === 403).map(r => r.path),
      [],
      'no request was refused'
    );
    const { cookies } = await page.send('Network.getCookies', { urls: [orbit.url] });
    const session = cookies.find(c => c.name === 'goblin_session');
    assert.ok(session.expires > Date.now() / 1000 + 29 * 86400, 'kept for 30 days');
    await noViolations(page);
  }
);

test(
  'W2 a ?kiosk=1 page signed in with the password offers Set up, which signs it out into the code form',
  { skip },
  async t => {
    const orbit = await orbitWithPassword(t);
    // An old wall display: signed in with the password, as before display codes, at ?kiosk=1.
    const page = await openTab(t, orbit.url + '/', { ready: signInView });
    await submitSignIn(page, 'signin', password, { remember: true });
    await page.waitFor(cards, 10000);
    await page.send('Page.navigate', { url: orbit.url + '/?kiosk=1' });
    await page.waitFor(cards, 10000);
    await page.waitFor("document.querySelector('#display-banner').hidden === false");
    assert.match(
      await page.eval("document.querySelector('#display-banner-text').textContent"),
      /^This wall display is signed in as the admin, with every right\. From Uptime Goblin 1\.5 it signs out after 12 hours without use\..*Then delete Uptime Goblin's saved password from this browser\.$/
    );
    assert.equal(
      await page.eval("document.querySelector('#display-banner-setup').textContent"),
      'Set up'
    );
    assert.equal(await page.eval("document.body.classList.contains('display-mode')"), false);
    await page.eval("document.querySelector('#display-banner-setup').click()");
    await page.waitFor(
      "document.querySelector('#signin-page')?.hidden === false && document.querySelector('#display-form')?.hidden === false",
      10000
    );
    assert.equal(await page.eval("document.querySelector('#signin-form').hidden"), true);
    assert.deepEqual(await sessionCookies(page, orbit.url), []);
    await noViolations(page);
  }
);
