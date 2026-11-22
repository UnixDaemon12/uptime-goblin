// A tab must never freeze on a request that gets no answer, and a change sent again after a
// lost answer must never be applied twice, even when Uptime Goblin restarted in between. Real Uptime Goblin,
// real browser; the network faults come from test/helpers/net.mjs.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { delay, openPage, startBrowser } from './helpers/cdp.mjs';
import {
  appPrelude,
  call,
  signInBrowser,
  startOrbit,
  temporaryDirectory,
} from './helpers/orbit.mjs';
import { httpProxy, silentServer } from './helpers/net.mjs';

const { browser, skip } = await startBrowser();
after(() => browser?.close());

// Uptime Goblin's request time limits run 10 times faster: 3 s for a read, 6 s for a write.
const prelude = appPrelude({ scale: 10 });
const ready = "document.querySelector('#services article')";
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const named = (app, name) => app.config.value.services.filter(s => s.name === name).length;
const sourcePosts = proxy =>
  proxy.requests.filter(r => r.method === 'POST' && r.path === '/api/services');

/** Adds a bookmark source through the source drawer. */
async function addSource(page, name) {
  await page.eval(`document.querySelector('#add-source').click()`);
  await page.waitFor("document.querySelector('#settings-dialog').open");
  await page.setValue('#source-type', 'link');
  await page.setValue('#source-name', name);
  await page.eval(`document.querySelector('#connection-form [type=submit]').click()`);
}
/** Uptime Goblin behind a proxy that decides what happens to each request. */
async function proxied(t, decide) {
  const directory = temporaryDirectory(t);
  const handle = { orbit: null };
  const proxy = await httpProxy({ target: () => handle.orbit.port, decide });
  t.after(() => proxy.close());
  const options = { directory, allowedHosts: `127.0.0.1:${proxy.port}` };
  handle.orbit = await startOrbit(options);
  t.after(() => handle.orbit.close());
  handle.restart = async () => {
    await handle.orbit.close();
    handle.orbit = await startOrbit({ ...options, port: handle.orbit.port });
  };
  // The session cookie is the host's (127.0.0.1), so it reaches Uptime Goblin through the proxy too.
  await signInBrowser(browser.cdp, handle.orbit);
  const page = await openPage(browser.cdp, proxy.url + '/', { prelude, ready });
  t.after(() => page.close());
  return { handle, proxy, page };
}

test(
  'a tab whose dashboard request never gets an answer reconnects once Uptime Goblin is back',
  { skip },
  async t => {
    const directory = temporaryDirectory(t);
    let orbit = await startOrbit({ directory });
    const { port } = orbit;
    t.after(() => orbit.close());
    await signInBrowser(browser.cdp, orbit);
    const page = await openPage(browser.cdp, orbit.url + '/', { prelude, ready });
    t.after(() => page.close());
    // Uptime Goblin goes away and something that accepts connections but never answers takes its
    // port, like a host that hangs during a restart.
    await orbit.close();
    const silent = await silentServer(port);
    t.after(() => silent.close());
    await page.eval('window.__poll()');
    await page.waitFor(
      "document.querySelector('#connection').textContent === 'Reconnecting…'",
      8000
    );
    assert.ok(silent.accepted >= 1, 'the dashboard request went to the silent server');
    // Uptime Goblin is back on its port; the silent connection stays open and never answers.
    await silent.stopListening();
    orbit = await startOrbit({ directory, port });
    orbit.app.config.updateGlobal({ title: 'Back again' });
    await page.eval('window.__poll()');
    await page.waitFor(
      "document.querySelector('#dashboard-title').textContent === 'Back again'",
      8000
    );
    assert.notEqual(await page.text('#connection'), 'Reconnecting…');
    assert.equal(await page.eval("document.querySelector('#notice').hidden"), true);
  }
);

test(
  'a new source whose request never reached Uptime Goblin is sent once more and added once',
  { skip },
  async t => {
    let held = 0;
    const { handle, proxy, page } = await proxied(t, request =>
      request.method === 'POST' && request.path === '/api/services' && held++ === 0
        ? 'hold'
        : 'forward'
    );
    await addSource(page, 'Held host');
    // No answer: after the time limit the tab reloads the settings, sees nothing changed,
    // and sends the same request again, which Uptime Goblin applies.
    await page.waitFor("!document.querySelector('#settings-dialog').open", 15000);
    const [first, retry] = sourcePosts(proxy);
    assert.equal(sourcePosts(proxy).length, 2);
    assert.match(first.headers['idempotency-key'], uuid);
    assert.equal(retry.headers['idempotency-key'], first.headers['idempotency-key']);
    assert.equal(retry.headers['if-match'], first.headers['if-match']);
    assert.equal(retry.body, first.body);
    assert.equal(named(handle.orbit.app, 'Held host'), 1);
  }
);

test(
  'a source saved just before Uptime Goblin restarted, whose answer was lost, is not added twice',
  { skip },
  async t => {
    let swallowed = 0;
    const { handle, proxy, page } = await proxied(t, request =>
      request.method === 'POST' && request.path === '/api/services' && swallowed++ === 0
        ? 'swallow'
        : 'forward'
    );
    await addSource(page, 'Lost answer host');
    let post;
    while (!(post = sourcePosts(proxy)[0])) await delay(20);
    // Uptime Goblin saved the source, but its answer never reaches the tab; then Uptime Goblin restarts, as
    // it does during an upgrade, and forgets the request's Idempotency-Key.
    assert.equal((await post.answered).status, 201);
    await handle.restart();
    // After the time limit the tab reloads the settings, sees they changed (perhaps by its
    // own save), and says so instead of sending the source again.
    await page.waitFor(
      "/may have been saved/.test(document.querySelector('#form-error')?.textContent ?? '')",
      15000
    );
    await delay(500);
    assert.equal(sourcePosts(proxy).length, 1, 'not sent again');
    assert.equal(named(handle.orbit.app, 'Lost answer host'), 1);
    assert.equal(await page.eval("document.querySelector('#settings-dialog').open"), true);
    assert.equal(
      await page.eval("document.querySelector('#source-name').value"),
      'Lost answer host'
    );
    assert.ok(
      await page.eval(
        "[...document.querySelectorAll('#services h3')].some(h => h.textContent.includes('Lost answer host'))"
      ),
      'the dashboard shows the saved source'
    );
    // The same request sent again (same key, same revision) to the restarted Uptime Goblin is refused.
    const again = await call(handle.orbit.url, '/api/services', 'POST', JSON.parse(post.body), {
      'Idempotency-Key': post.headers['idempotency-key'],
      'If-Match': post.headers['if-match'],
    });
    assert.equal(again.status, 409);
    assert.equal(named(handle.orbit.app, 'Lost answer host'), 1);
  }
);
