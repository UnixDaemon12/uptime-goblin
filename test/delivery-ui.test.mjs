// Configure → Notifications against a real Uptime Goblin (1.5 delivery spec §8.1 U): an alert to a
// webhook that fails is shown waiting to retry, Retry delivers it once the receiver is fixed; a
// webhook that answers 401 pauses, the banner says so, and Resume delivers what it held. Every
// step in the page is taken with the keyboard alone (Tab, Enter), and the page breaks nothing in
// Uptime Goblin's Content-Security-Policy. ui.test.mjs covers the same page against a scripted API.
//
// It needs the delivery service and its routes (lanes D and H of the delivery milestone): until
// they are in the tree it is skipped, saying so. Chrome is needed as for the other browser
// suites (TEST_REQUIRE=browser makes a missing one fail).
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { delay, js, openPage, startBrowser } from './helpers/cdp.mjs';
import {
  appPrelude,
  call,
  root,
  signInBrowser,
  startOrbit,
  temporaryDirectory,
} from './helpers/orbit.mjs';

const integrated = ['lib/alerting/service.mjs', 'lib/http/routes/notifications.mjs'].every(file =>
  fs.existsSync(path.join(root, file))
);
const { browser, skip: noBrowser } = integrated
  ? await startBrowser()
  : { browser: null, skip: false };
const skip = integrated
  ? noBrowser
  : 'needs the delivery service and its routes (lib/alerting/service.mjs, lib/http/routes/notifications.mjs)';
after(() => browser?.close());

/** A webhook receiver on loopback that answers `status` and records every request. */
async function webhookFixture(t) {
  const fixture = { status: 200, requests: [] };
  const server = http.createServer(async (req, res) => {
    let body = '';
    for await (const chunk of req) body += chunk;
    fixture.requests.push({ headers: req.headers, body: JSON.parse(body) });
    res.writeHead(fixture.status, { 'Content-Type': 'application/json' });
    res.end('{}');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  fixture.url = `http://127.0.0.1:${server.address().port}/hook`;
  return fixture;
}
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
async function pressKey(page, key, { shift = false } = {}) {
  const keys = {
    Tab: { code: 'Tab', keyCode: 9 },
    Enter: { code: 'Enter', keyCode: 13, text: '\r' },
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
/** Moves the focus with Tab alone until it is on `selector`: proof it can be reached so. */
async function tabTo(page, selector, limit = 400) {
  for (let i = 0; i < limit; i++) {
    if (await page.eval(`!!document.activeElement?.matches(${js(selector)})`)) return;
    await pressKey(page, 'Tab');
  }
  throw new Error(`Tab never reached ${selector}`);
}
/** Presses Refresh by keyboard, then gives the page a moment to read the status and lists. */
async function refresh(page) {
  await tabTo(page, '#notifications-refresh');
  await pressKey(page, 'Enter');
  await delay(200);
}

test(
  'a failing webhook, Retry, a paused webhook and Resume, by keyboard alone, against a real Uptime Goblin',
  { skip, timeout: 180000 },
  async t => {
    const receiver = await webhookFixture(t);
    receiver.status = 500;
    let value = 95;
    const orbit = await startOrbit({
      directory: temporaryDirectory(t),
      webhook: receiver.url,
      collector: async () => [{ key: 'cpu', label: 'CPU', value, unit: '%' }],
      // A failed send waits a minute: only Retry sends it again within this test.
      delivery: { pollMs: 100, policy: { baseMs: 60000, capMs: 60000 } },
    });
    t.after(() => orbit.close());
    const { app } = orbit;
    app.config.updateGlobal({
      monitoring: { ...app.config.value.monitoring, recoverySuccesses: 1, recoverySeconds: 0 },
    });
    app.config.update('linux', {
      apiUrl: 'http://fixture.invalid',
      rules: [{ key: 'cpu', operator: 'gt', threshold: 80, forSeconds: 0 }],
    });
    const name = app.config.get('linux').name;
    const webhookStatus = async () =>
      (await call(orbit.url, '/api/notifications')).body.channels?.find(
        c => c.id === 'env-webhook'
      );

    await signInBrowser(browser.cdp, orbit);
    const page = await openPage(browser.cdp, orbit.url + '/#configure/notifications', {
      prelude:
        appPrelude() +
        `window.__cspViolations = [];
        document.addEventListener('securitypolicyviolation', e =>
          window.__cspViolations.push(e.violatedDirective + ' ' + e.blockedURI));`,
      ready:
        "document.querySelector('#notifications-summary') && !document.querySelector('#notifications-summary').textContent.startsWith('Reading')",
    });
    t.after(() => page.close());
    const summary = () => page.eval("document.querySelector('#notifications-summary').textContent");
    const history = () =>
      page.eval(
        "[...document.querySelectorAll('#history-list .delivery')].map(r => [r.querySelector('.delivery-kind').textContent, r.querySelector('.delivery-status').textContent])"
      );
    assert.equal(await summary(), 'Nothing has been sent yet.');

    // An alert; the receiver answers 500: the page says it waits to retry.
    await app.poll(app.config.get('linux'));
    await app.poll(app.config.get('linux'));
    await until(() => receiver.requests.length === 1, 'the first request');
    await until(async () => (await webhookStatus())?.counts?.retrying === 1, 'a retrying row');
    await refresh(page);
    await until(
      async () => /^1 notification waiting to retry/.test(await summary()),
      'the retrying summary'
    );
    assert.match(
      await page.eval(
        'document.querySelector(\'[data-id="env-webhook"] .channel-state\').textContent'
      ),
      /^Retrying \(next attempt .+\)$/
    );

    // The receiver is fixed; Retry, by keyboard, delivers it.
    receiver.status = 200;
    await tabTo(page, '#attention-list [data-retry-delivery]');
    assert.equal(
      await page.eval("document.activeElement.getAttribute('aria-label')"),
      `Retry the ${name} alert on Webhook`
    );
    await pressKey(page, 'Enter');
    await until(
      () =>
        page.eval(
          "document.querySelector('#notifications-result').textContent === 'Uptime Goblin sends this notification again now.'"
        ),
      'the retry result'
    );
    await until(() => receiver.requests.length === 2, 'the retried request');
    await until(async () => {
      await refresh(page);
      return (await history()).some(([kind, status]) => kind === 'Alert' && status === 'Delivered');
    }, 'the alert delivered in the history');
    const [failed, delivered] = receiver.requests;
    assert.equal(delivered.body.kind, 'firing');
    assert.match(failed.headers['x-goblin-delivery'], /^d_[a-z2-7]{26}$/);
    assert.equal(delivered.headers['x-goblin-delivery'], failed.headers['x-goblin-delivery']);

    // The receiver answers 401: the webhook pauses and holds the recovery; the banner says so.
    receiver.status = 401;
    value = 10;
    await app.poll(app.config.get('linux'));
    await until(() => receiver.requests.length === 3, 'the recovery refused');
    await until(async () => (await webhookStatus())?.state === 'paused', 'the paused webhook');
    await page.eval('window.__poll()');
    await until(
      () =>
        page.eval(
          "!document.querySelector('#configuration-notice').hidden && document.querySelector('#configuration-notice').textContent.startsWith('Webhook notifications are paused: ')"
        ),
      'the paused banner'
    );
    await until(async () => (await summary()).startsWith('Webhook is paused: '), 'the summary');

    // Fixed again; Resume, by keyboard, sends what it held.
    receiver.status = 200;
    await tabTo(page, '[data-resume-channel="env-webhook"]');
    await pressKey(page, 'Enter');
    await until(
      () =>
        page.eval(
          "/^Webhook notifications resumed/.test(document.querySelector('#notifications-result').textContent)"
        ),
      'the resume result'
    );
    // Resume went; the focus moved on within the Webhook card, not to the top of the page. The
    // result is announced before the page reads the status and lists again (resumeChannel() in
    // configure/notifications.js), and the focus moves once they are drawn: wait for that.
    await until(
      () =>
        page.eval(
          "!document.querySelector('[data-resume-channel]') && !!document.activeElement.closest('[data-id=\"env-webhook\"]')"
        ),
      'the focus moved on within the Webhook card'
    );
    // The recovery the 401 refused, sent again: the same delivery id.
    const recoveries = await until(() => {
      const sent = receiver.requests.filter(r => r.body.kind === 'resolved');
      return sent.length === 2 && sent;
    }, 'the held recovery sent again');
    assert.equal(
      recoveries[1].headers['x-goblin-delivery'],
      recoveries[0].headers['x-goblin-delivery']
    );
    await until(async () => {
      await refresh(page);
      return (await history()).some(
        ([kind, status]) => kind === 'Recovered' && status === 'Delivered'
      );
    }, 'the recovery delivered in the history');
    await until(
      () => page.eval("document.querySelector('#configuration-notice').hidden"),
      'the banner gone'
    );
    assert.deepEqual(await page.eval('window.__cspViolations'), []);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'Needs attention and Problems list what retries behind 145 newer notifications waiting at an open circuit, and Load more ends with the last full page',
  { skip, timeout: 180000 },
  async t => {
    const receiver = await webhookFixture(t);
    receiver.status = 500;
    // A failed send waits a minute, and 5 failures open the circuit for a minute: the first 5
    // notifications retry, and the 145 queued after them wait for their first attempt.
    const orbit = await startOrbit({
      directory: temporaryDirectory(t),
      webhook: receiver.url,
      delivery: { pollMs: 100, policy: { baseMs: 60000, capMs: 60000 } },
    });
    t.after(() => orbit.close());
    for (let n = 1; n <= 150; n++)
      await orbit.app.alerting.enqueueDirect(
        {
          service: 'linux',
          name: `Flood ${n}`,
          kind: 'firing',
          category: 'threshold',
          rule: `flood-${n}`,
          message: 'CPU is above 80%',
          time: Date.now(),
        },
        `test:flood-${n}`
      );
    await until(async () => {
      const totals = (await call(orbit.url, '/api/notifications')).body.totals;
      return totals?.retrying === 5 && totals?.waiting === 145;
    }, '5 notifications retrying and 145 waiting');

    await signInBrowser(browser.cdp, orbit);
    const page = await openPage(browser.cdp, orbit.url + '/#configure/notifications', {
      prelude: appPrelude(),
      ready: `(() => {
        const summary = document.querySelector('#notifications-summary');
        return summary && !summary.textContent.startsWith('Reading') &&
          [...document.querySelectorAll('#attention-list, #history-list')].every(l => !l.textContent.includes('Reading notifications'));
      })()`,
    });
    t.after(() => page.close());
    const statuses = list =>
      page.eval(
        `[...document.querySelectorAll('#${list} .delivery-status')].map(e => e.textContent)`
      );
    assert.match(
      await page.eval("document.querySelector('#notifications-summary').textContent"),
      /^5 notifications waiting to retry/
    );
    // Needs attention: the 5 that retry, each with Retry; never "Nothing needs attention."
    assert.deepEqual(await statuses('attention-list'), Array(5).fill('Waiting to retry'));
    assert.equal(
      await page.eval("document.querySelectorAll('#attention-list [data-retry-delivery]').length"),
      5
    );
    // Delivery history, Problems: the same 5, and nothing more to load.
    const listHtml = () => page.eval("document.querySelector('#history-list').innerHTML");
    const choose = async value => {
      const before = await listHtml();
      await page.eval(`(f => {
        f.value = ${js(value)};
        f.dispatchEvent(new Event('change', { bubbles: true }));
      })(document.querySelector('#history-filter'))`);
      await until(async () => (await listHtml()) !== before, `the ${value} history`);
      await delay(300);
    };
    await choose('problems');
    assert.deepEqual(await statuses('history-list'), Array(5).fill('Waiting to retry'));
    assert.equal(await page.eval("document.querySelector('#history-more').hidden"), true);

    // All 150, by keyboard: three pages of 50. The third is the last, so Load more goes with
    // it and the focus moves to its first row; there is no fourth, empty page.
    await choose('all');
    const rows = () => page.eval("document.querySelectorAll('#history-list .delivery').length");
    assert.equal(await rows(), 50);
    await tabTo(page, '#history-more');
    for (const expected of [100, 150]) {
      await pressKey(page, 'Enter');
      await until(async () => (await rows()) === expected, `${expected} rows`);
      await delay(200);
    }
    assert.equal(await page.eval("document.querySelector('#history-more').hidden"), true);
    assert.equal(
      await page.eval(
        "document.activeElement === document.querySelectorAll('#history-list .delivery')[100]"
      ),
      true,
      'the focus is on the first row of the last page'
    );
    assert.deepEqual(page.exceptions, []);
  }
);
