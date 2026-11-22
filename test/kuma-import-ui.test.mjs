// Configure → Sources → Import from Uptime Kuma against a real Uptime Goblin: the admin chooses a backup,
// sees what would be added, changed and skipped, and nothing is saved until it is confirmed; then
// the sources are there, in one configuration revision. What the page sent holds none of the
// backup's credentials (the browser reduces it first), and the page broke nothing in Uptime Goblin's
// Content-Security-Policy. Chrome is needed as for the other browser suites (TEST_REQUIRE=browser
// makes a missing one fail); the backup is synthetic (test/helpers/kuma.mjs).
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { delay, js, openPage, startBrowser } from './helpers/cdp.mjs';
import {
  appPrelude,
  call,
  signInBrowser,
  startOrbit,
  temporaryDirectory,
} from './helpers/orbit.mjs';
import { kumaSecrets, mixedBackup } from './helpers/kuma.mjs';

const { browser, skip } = await startBrowser();
after(() => browser?.close());

/** Waits until `check()` (sync or async) is truthy. */
async function until(check, what, timeout = 15000) {
  const end = Date.now() + timeout;
  for (;;) {
    const value = await check();
    if (value) return value;
    if (Date.now() > end) throw new Error(`Timed out waiting for ${what}`);
    await delay(50);
  }
}

test(
  'the admin previews an Uptime Kuma backup, nothing is saved before confirming, and no credential leaves the browser',
  { skip, timeout: 120000 },
  async t => {
    const orbit = await startOrbit({ directory: temporaryDirectory(t) });
    t.after(() => orbit.close());
    const saved = await call(orbit.url, '/api/services', 'POST', {
      type: 'http',
      name: 'Plex web',
      url: 'https://old.example.com/',
    });
    assert.equal(saved.status, 201);
    await browser.cdp.send('Storage.clearCookies');
    await signInBrowser(browser.cdp, orbit);
    const page = await openPage(browser.cdp, orbit.url + '/#configure/sources', {
      prelude:
        appPrelude() +
        // Every request body the page sends, and any policy violation.
        `window.__sent = [];
        window.__cspViolations = [];
        const realFetch = window.fetch.bind(window);
        window.fetch = (url, init = {}) => {
          window.__sent.push(String(url) + ' ' + (typeof init.body === 'string' ? init.body : ''));
          return realFetch(url, init);
        };
        document.addEventListener('securitypolicyviolation', e =>
          window.__cspViolations.push(e.violatedDirective + ' ' + e.blockedURI));`,
      ready: "document.querySelector('[data-kuma-import]')",
      timeout: 15000,
    });
    t.after(() => page.close());
    const revision = () => orbit.app.config.value.revision;
    const before = revision();

    // Import from Uptime Kuma opens the panel, its file field focused.
    await page.eval("document.querySelector('[data-kuma-import]').click()");
    await page.waitFor("document.activeElement?.id === 'kuma-file'");
    // The backup file, as a person choosing it would hand it over.
    const backup = JSON.stringify(mixedBackup());
    await page.eval(`(() => {
      const input = document.querySelector('#kuma-file'), files = new DataTransfer();
      files.items.add(new File([${js(backup)}], 'backup.json', { type: 'application/json' }));
      input.files = files.files;
      input.dispatchEvent(new Event('change', { bubbles: true }));
    })()`);
    await page.waitFor("document.querySelector('#kuma-preview-title')", 10000);
    const shown = await page.eval(`({
      title: document.querySelector('#kuma-preview-title').textContent,
      focused: document.activeElement?.id,
      added: document.querySelectorAll('tr[data-kuma="add"]').length,
      changed: document.querySelectorAll('tr[data-kuma="change"]').length,
      skipped: document.querySelectorAll('tr[data-kuma="skip"]').length,
      flagged: document.querySelectorAll('tr[data-kuma="add"] .kuma-flag').length,
      button: document.querySelector('#kuma-apply').textContent,
      text: document.querySelector('#kuma-import').textContent,
    })`);
    assert.equal(shown.title, '6 to add, 1 to change, 13 skipped');
    assert.equal(shown.focused, 'kuma-preview-title');
    assert.deepEqual([shown.added, shown.changed, shown.skipped], [6, 1, 13]);
    assert.equal(shown.flagged, 3, 'three monitors had credentials');
    assert.equal(shown.button, 'Import 7 monitors');
    assert.match(shown.text, /Ping monitors are not supported/);
    assert.match(shown.text, /Keyword not checked/);
    // Previewed, not saved.
    assert.equal(revision(), before);

    await page.eval("document.querySelector('#kuma-apply').click()");
    await until(() => revision() === before + 1, 'the import saved');
    await page.waitFor("document.querySelector('#kuma-import').hidden === true", 10000);
    await until(
      () =>
        page.eval(
          `document.querySelectorAll('#configured-sources .configured-source').length === ${orbit.app.config.value.services.length}`
        ),
      'the source list updated'
    );
    const names = orbit.app.config.value.services.map(s => s.name);
    for (const name of ['Plex web', 'Site 3', 'Site 4', 'Site 5', 'Site 6', 'Site 7', 'Site 8'])
      assert.ok(names.includes(name), name);
    assert.equal(
      orbit.app.config.value.services.find(s => s.name === 'Plex web').url,
      'https://site2.example.com/'
    );
    // What the page sent: the reduced backup, twice (preview and apply), never a credential.
    const sent = await page.eval('window.__sent');
    const imports = sent.filter(line => line.includes('/api/import/uptime-kuma'));
    assert.equal(imports.length, 2);
    for (const line of imports) {
      for (const secret of kumaSecrets) assert.ok(!line.includes(secret), secret);
      assert.ok(!line.includes('notificationList'));
    }
    assert.deepEqual(await page.eval('window.__cspViolations'), []);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'a file that is not an Uptime Kuma 1.x backup is refused in the page, and Cancel closes the panel',
  { skip, timeout: 60000 },
  async t => {
    const orbit = await startOrbit({ directory: temporaryDirectory(t) });
    t.after(() => orbit.close());
    await browser.cdp.send('Storage.clearCookies');
    await signInBrowser(browser.cdp, orbit);
    const page = await openPage(browser.cdp, orbit.url + '/#configure/sources', {
      prelude: appPrelude(),
      ready: "document.querySelector('[data-kuma-import]')",
      timeout: 15000,
    });
    t.after(() => page.close());
    await page.eval("document.querySelector('[data-kuma-import]').click()");
    const choose = text =>
      page.eval(`(() => {
        const input = document.querySelector('#kuma-file'), files = new DataTransfer();
        files.items.add(new File([${js(text)}], 'backup.json'));
        input.files = files.files;
        input.dispatchEvent(new Event('change', { bubbles: true }));
      })()`);
    const error = () =>
      page.waitFor(
        "!document.querySelector('#kuma-error').hidden && document.querySelector('#kuma-error').textContent"
      );
    await choose('not json');
    assert.match(await error(), /not valid JSON/);
    await choose(JSON.stringify({ version: '2.0.0', monitorList: [] }));
    assert.match(await error(), /Only Uptime Kuma 1\.x backups can be imported/);
    assert.equal(await page.eval("document.querySelector('#kuma-apply').hidden"), true);
    await page.eval("document.querySelector('[data-kuma-cancel]').click()");
    assert.equal(await page.eval("document.querySelector('#kuma-import').hidden"), true);
    assert.equal(await page.eval("document.activeElement?.matches('[data-kuma-import]')"), true);
    assert.deepEqual(page.exceptions, []);
  }
);
