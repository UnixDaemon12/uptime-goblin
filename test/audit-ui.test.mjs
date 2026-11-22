// Configure → Audit log against a real Uptime Goblin (audit spec §9.1 U): signed in with the admin
// password, the admin changes the email sender and the SMTP password twice, opens the Audit log, finds
// the change and its details (what changed, the password only as "set" and "changed"), checks the
// log's integrity and exports it as CSV, every step with the keyboard alone (Tab, Enter, typing).
// Then neither the page nor the export holds any of the secrets the test planted (the audit
// canary's DOM part, test/helpers/audit-sentinels.mjs), and the page broke nothing in Uptime Goblin's
// Content-Security-Policy. ui.test.mjs covers the same page against a scripted API.
//
// It needs the audit service and its routes (lanes O and H of the audit milestone): until they
// are in the tree it is skipped, saying so. Chrome is needed as for the other browser suites
// (TEST_REQUIRE=browser makes a missing one fail). Downloads never reach the user's Downloads
// folder: test/helpers/cdp.mjs cancels them and keeps their bytes in the page.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { delay, js, openPage, startBrowser } from './helpers/cdp.mjs';
import { auditSentinels, findSentinels } from './helpers/audit-sentinels.mjs';
import { appPrelude, root, startOrbit, temporaryDirectory } from './helpers/orbit.mjs';

const integrated = ['lib/audit/index.mjs', 'lib/http/routes/audit.mjs'].every(file =>
  fs.existsSync(path.join(root, file))
);
const { browser, skip: noBrowser } = integrated
  ? await startBrowser()
  : { browser: null, skip: false };
const skip = integrated
  ? noBrowser
  : 'needs the audit service and its routes (lib/audit/index.mjs, lib/http/routes/audit.mjs)';
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
/** Presses a key on the focused element, as a keyboard would. */
async function pressKey(page, key) {
  const keys = {
    Tab: { code: 'Tab', keyCode: 9 },
    Enter: { code: 'Enter', keyCode: 13, text: '\r' },
  };
  const { code, keyCode, text } = keys[key];
  const common = { key, code, windowsVirtualKeyCode: keyCode };
  await page.send('Input.dispatchKeyEvent', {
    type: text ? 'keyDown' : 'rawKeyDown',
    ...common,
    ...(text ? { text } : {}),
  });
  await page.send('Input.dispatchKeyEvent', { type: 'keyUp', ...common });
}
/** Moves the focus with Tab alone until it is on `selector`: proof it can be reached so. */
async function tabTo(page, selector, limit = 400) {
  for (let i = 0; i < limit; i++) {
    if (await page.eval(`!!document.activeElement?.matches(${js(selector)})`)) return;
    await pressKey(page, 'Tab');
  }
  throw new Error(`Tab never reached ${selector}`);
}
/** Tabs to a field, selects what it holds (as Ctrl+A would) and types `value` over it. */
async function typeInto(page, selector, value) {
  await tabTo(page, selector);
  const a = { key: 'a', code: 'KeyA', windowsVirtualKeyCode: 65 };
  await page.send('Input.dispatchKeyEvent', { type: 'rawKeyDown', ...a, commands: ['selectAll'] });
  await page.send('Input.dispatchKeyEvent', { type: 'keyUp', ...a });
  await page.send('Input.insertText', { text: value });
}
/**
 * Saves the email form by keyboard and waits until the page has finished with it: the form stays
 * locked, and leaving the page is refused ("Finishing your request…"), until the dashboard it
 * reads after the save has arrived, a moment after "Email settings saved." shows.
 */
async function saveEmail(page) {
  await page.eval("document.querySelector('#email-result').textContent = ''");
  await tabTo(page, '#email-form [type=submit]');
  await pressKey(page, 'Enter');
  await until(
    () =>
      page.eval(
        "document.querySelector('#email-result').textContent === 'Email settings saved.' && !document.querySelector('#email-form [type=submit]').disabled && !document.querySelector('#configuration-page').classList.contains('has-unsaved')"
      ),
    'the email settings saved'
  );
}

test(
  'The admin finds a settings change with its details, checks the log and exports it, by keyboard alone, and no secret reaches the page',
  { skip, timeout: 180000 },
  async t => {
    const sentinels = auditSentinels();
    const orbit = await startOrbit({
      directory: temporaryDirectory(t),
      password: sentinels.adminPassword,
    });
    t.after(() => orbit.close());
    await browser.cdp.send('Storage.clearCookies');
    const page = await openPage(browser.cdp, orbit.url + '/', {
      prelude:
        appPrelude() +
        `window.__cspViolations = [];
        document.addEventListener('securitypolicyviolation', e =>
          window.__cspViolations.push(e.violatedDirective + ' ' + e.blockedURI));`,
      ready: "document.querySelector('#signin-page')?.hidden === false",
      timeout: 10000,
    });
    t.after(() => page.close());

    // Signs in with the admin password.
    await typeInto(page, '#signin-login', 'admin');
    await typeInto(page, '#signin-password', sentinels.adminPassword);
    await pressKey(page, 'Enter');
    await page.waitFor("document.querySelector('#services > *')", 10000);

    // The email sender and an SMTP password, then the password again, changed.
    await page.eval("location.hash = '#configure/email'");
    await page.waitFor("document.querySelector('#email-form')");
    await typeInto(page, '#email-from', 'orbit@example.com');
    await typeInto(page, '#email-password', sentinels.smtpPassword);
    await saveEmail(page);
    await typeInto(page, '#email-password', sentinels.smtpPasswordChanged);
    await saveEmail(page);

    // Configure → Audit log, from the navigation.
    await tabTo(page, '#configuration-nav a[href="#configure/audit"]');
    await pressKey(page, 'Enter');
    await page.waitFor(
      "document.querySelectorAll('#audit-list > li.audit-entry').length > 0",
      10000
    );
    const changes = await page.eval(`[...document.querySelectorAll('#audit-list > li.audit-entry')]
      .filter(li => li.querySelector('.audit-summary').textContent === 'Changed workspace settings')
      .map(li => li.dataset.id)`);
    assert.equal(changes.length, 2, 'both saves are listed, each once');
    const [latest, first] = changes;
    const openDetails = async seq => {
      await tabTo(page, `#audit-${seq}-toggle`);
      await pressKey(page, 'Enter');
      await page.waitFor(`document.querySelector('#audit-${seq}-details').hidden === false`);
      return page.eval(
        `[...document.querySelectorAll('#audit-${seq}-details .audit-diff li')].map(li => li.textContent)`
      );
    };
    assert.deepEqual(await openDetails(latest), ['email.password: changed']);
    const firstDiff = await openDetails(first);
    assert.ok(firstDiff.includes('email.from: (empty) → orbit@example.com'), firstDiff.join(' | '));
    assert.ok(firstDiff.includes('email.password: set'), firstDiff.join(' | '));
    assert.equal(
      await page.eval(
        `document.querySelector('#audit-list > [data-id="${latest}"] .audit-outcome').textContent`
      ),
      'Succeeded'
    );

    // Check integrity.
    await tabTo(page, '#audit-verify');
    await pressKey(page, 'Enter');
    await until(
      () =>
        page.eval(
          "document.querySelector('#audit-verify-result').textContent.startsWith('The audit log is intact: ')"
        ),
      'the log intact'
    );
    assert.equal(await page.eval('document.activeElement?.id'), 'audit-verify');

    // Export CSV: Uptime Goblin's bytes, its byte order mark first.
    await tabTo(page, '#audit-export-csv');
    await pressKey(page, 'Enter');
    const download = await until(
      () =>
        page.eval(
          'window.__downloads.length === 1 && window.__downloads[0].text !== null && window.__downloads[0]'
        ),
      'the CSV download'
    );
    assert.match(download.name, /^uptime-goblin-audit-\d{8}-\d{6}Z\.csv$/);
    assert.ok(download.text.startsWith('﻿seq,time,actor_type,'), download.text.slice(0, 40));
    assert.match(download.text, /settings\.update/);

    // No planted secret in the page or in the export.
    const html = await page.eval('document.documentElement.outerHTML');
    assert.deepEqual(findSentinels(html, sentinels), []);
    assert.deepEqual(findSentinels(download.text, sentinels), []);
    assert.deepEqual(await page.eval('window.__cspViolations'), []);
    assert.deepEqual(page.exceptions, []);
  }
);
