// "Uptime Goblin was updated": a real Uptime Goblin is restarted on the same port as a new release (a changed
// copy of public/), and an open tab must move to it by itself when nothing would be lost, or
// offer a reload when something would. This is the regression test for the owner's report
// that Uptime Goblin did not seem to start after an upgrade: the open tab kept the old version.
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { delay, js, openPage, startBrowser } from './helpers/cdp.mjs';
import {
  appPrelude,
  copyPublic,
  root,
  seedReadings,
  signInBrowser,
  startOrbit,
  temporaryDirectory,
} from './helpers/orbit.mjs';
import { httpProxy } from './helpers/net.mjs';
import {
  declareGit,
  expectNested,
  gitMissing,
  gitProbe,
  gitStubs,
  runNested,
} from './helpers/git.mjs';
import { history, historyRequired, historySchema } from './upgrade/history.mjs';
import { buildInfo, renderIndex } from '../server.mjs';

const { browser, skip } = await startBrowser();
after(() => browser?.close());

const cards = "document.querySelector('#services article')";
const pageBuild = page =>
  page.eval(`document.querySelector('meta[name="orbit-build"]')?.content ?? ''`);
const onBuild = build =>
  `document.querySelector('meta[name="orbit-build"]')?.content === ${js(build)}`;

/**
 * Uptime Goblin (startOrbit) with the browser signed in to it: Uptime Goblin always requires a password, and the
 * session cookie, kept in control.sqlite, stays good across the restarts below.
 */
async function startSignedIn(options) {
  const orbit = await startOrbit(options);
  await signInBrowser(browser.cdp, orbit);
  return orbit;
}

/**
 * A release under test: Uptime Goblin with its own data and copy of public/, the browser signed in.
 * next() stops it and starts the next release (public/ changed) on the same port with the same
 * data.
 */
async function releases(t, options = {}) {
  const directory = temporaryDirectory(t),
    publicDirectory = copyPublic(t);
  let orbit = await startSignedIn({ directory, publicDirectory, ...options });
  t.after(() => orbit.close());
  return {
    get orbit() {
      return orbit;
    },
    async next() {
      await orbit.close();
      fs.appendFileSync(
        path.join(publicDirectory, 'style.css'),
        `\n/* ${crypto.randomUUID()} */\n`
      );
      orbit = await startOrbit({ directory, publicDirectory, port: orbit.port, ...options });
      return orbit;
    },
  };
}
async function open(t, url, options = {}) {
  const page = await openPage(browser.cdp, url, {
    prelude: appPrelude(options.prelude),
    ready: options.ready ?? cards,
    height: options.height ?? 900,
  });
  t.after(() => page.close());
  return page;
}

test(
  'after an update reload, a chart without readings ends the scroll restore, so polls leave the page alone',
  { skip },
  async t => {
    const release = await releases(t);
    // One old reading: the card has measurements, but the 1-hour chart has no readings.
    release.orbit.app.store.record(
      'linux',
      [{ key: 'cpu', label: 'CPU', value: 20, unit: '%' }],
      null,
      Date.now() - 2 * 86400000
    );
    const page = await open(t, release.orbit.url + '/', { height: 600 });
    await page.eval(`document.querySelector('[data-expand="linux"]').click()`);
    await page.eval(`document.querySelector('[data-range="1h"]').click()`);
    const empty = "document.querySelector('#graph-linux .empty-history')";
    await page.waitFor(empty);
    const scrollY = await page.eval(
      "(window.scrollTo({ top: 300, behavior: 'instant' }), window.scrollY)"
    );
    assert.ok(scrollY > 0, 'the page scrolls');
    const next = await release.next();
    await page.eval('window.__poll()');
    await page.waitFor(onBuild(next.app.build), 10000);
    await page.waitFor(empty);
    await page.waitFor(`Math.abs(window.scrollY - ${scrollY}) <= 2`);
    // The user moves on; the next poll must not pull the page back.
    await page.eval("window.scrollTo({ top: 0, behavior: 'instant' })");
    await page.eval('window.__poll()');
    await delay(500);
    assert.equal(await page.eval('window.scrollY'), 0);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'a tab open across a restart into a new release reloads itself and returns to the same view',
  { skip },
  async t => {
    const release = await releases(t);
    seedReadings(release.orbit.app, 'linux');
    const first = release.orbit.app.build;
    const page = await open(t, release.orbit.url + '/', { height: 600 });
    assert.equal(await pageBuild(page), first);
    await page.eval(`document.querySelector('[data-expand="linux"]').click()`);
    await page.waitFor("document.querySelector('#graph-linux svg.chart')");
    await page.eval(`document.querySelector('[data-range="7d"]').click()`);
    await page.waitFor(
      `document.querySelector('[data-range="7d"]')?.getAttribute('aria-pressed') === 'true'`
    );
    // The active button changes immediately; the new period's history arrives later.
    await page.waitFor(
      "document.querySelector('#graph-linux svg.chart') && document.querySelector('#metric-select')"
    );
    await page.setValue('#metric-select', 'memory');
    const chart = `document.querySelector('#graph-linux svg.chart')?.getAttribute('aria-label') ?? ''`;
    await page.waitFor(`/^Memory history/.test(${chart})`);
    const scrollY = await page.eval(
      "(window.scrollTo({ top: 400, behavior: 'instant' }), window.scrollY)"
    );
    assert.ok(scrollY > 0, 'the page scrolls');
    await page.eval('window.__oldPage = true');

    const next = await release.next();
    assert.notEqual(next.app.build, first, 'a changed public/ is a new build');
    await page.eval('window.__poll()');
    await page.waitFor(onBuild(next.app.build), 10000);
    assert.equal(await page.eval('window.__oldPage'), undefined, 'the page was reloaded');
    // The same card, period, measurement and scroll position as before.
    await page.waitFor(`/^Memory history/.test(${chart})`);
    assert.equal(
      await page.eval(`document.querySelector('.service.expanded')?.dataset.id`),
      'linux'
    );
    assert.equal(
      await page.eval(`document.querySelector('[data-range="7d"]').getAttribute('aria-pressed')`),
      'true'
    );
    await page.waitFor(`Math.abs(window.scrollY - ${scrollY}) <= 2`);
    assert.deepEqual(page.exceptions, []);
  }
);

test(
  'unsaved changes keep the page and show a reload banner; saving them lets it reload',
  { skip },
  async t => {
    const release = await releases(t);
    const first = release.orbit.app.build;
    const page = await open(t, release.orbit.url + '/#configure/appearance', {
      ready: "document.querySelector('#workspace-title')",
    });
    await page.setValue('#workspace-title', 'Edited during the upgrade');
    await page.eval('window.__oldPage = true');
    const next = await release.next();
    await page.eval('window.__poll()');
    await page.waitFor("!document.querySelector('#update-banner').hidden");
    assert.match(await page.text('#update-text'), /Uptime Goblin was updated/);
    await delay(1500);
    assert.equal(await pageBuild(page), first, 'unsaved changes are not reloaded away');
    assert.equal(
      await page.eval('document.querySelector("#workspace-title").value'),
      'Edited during the upgrade'
    );

    await page.eval(`document.querySelector('#settings-form [type=submit]').click()`);
    await page.waitFor(onBuild(next.app.build), 10000);
    assert.equal(await page.eval('window.__oldPage'), undefined);
    assert.equal(next.app.config.value.title, 'Edited during the upgrade');
    await page.waitFor(
      `location.hash === '#configure/appearance' && document.querySelector('#workspace-title')?.value === 'Edited during the upgrade'`
    );
  }
);

test('a hidden tab finds the new release by asking for the version', { skip }, async t => {
  const release = await releases(t);
  const first = release.orbit.app.build;
  const page = await open(t, release.orbit.url + '/', { prelude: { hidden: true } });
  const next = await release.next();
  // Hidden tabs do not poll the dashboard.
  await page.eval('window.__poll()');
  await delay(500);
  assert.equal(await pageBuild(page), first);
  // The 5-minute version check finds the new release and reloads at once.
  await page.eval('window.__probe()');
  await page.waitFor(onBuild(next.app.build), 10000);
});

test(
  'a wall display (?kiosk=1) reloads even with a dialog open; a normal tab asks',
  { skip },
  async t => {
    const release = await releases(t);
    const first = release.orbit.app.build;
    const normal = await open(t, release.orbit.url + '/');
    const kiosk = await open(t, release.orbit.url + '/?kiosk=1');
    for (const page of [normal, kiosk]) {
      await page.eval(`document.querySelector('#alerts-button').click()`);
      await page.waitFor("document.querySelector('#alerts-dialog').open");
    }
    const next = await release.next();
    await normal.eval('window.__poll()');
    await kiosk.eval('window.__poll()');
    await kiosk.waitFor(onBuild(next.app.build), 10000);
    await normal.waitFor("!document.querySelector('#update-banner').hidden");
    assert.equal(await pageBuild(normal), first);
    // The banner's button reloads into the new release.
    await normal.eval(`document.querySelector('#update-reload').click()`);
    await normal.waitFor(onBuild(next.app.build), 10000);
  }
);

test(
  'a proxy that keeps serving the old page cannot make the tab reload more than twice',
  { skip },
  async t => {
    let orbitPort,
      stalePage = null;
    const proxy = await httpProxy({
      target: () => orbitPort,
      // Like a cache that kept the first release's page.
      decide: request =>
        request.method === 'GET' && request.path.split('?')[0] === '/' && stalePage
          ? { headers: { 'Content-Type': 'text/html; charset=utf-8' }, body: stalePage }
          : 'forward',
    });
    t.after(() => proxy.close());
    const release = await releases(t, { allowedHosts: `127.0.0.1:${proxy.port}` });
    orbitPort = release.orbit.port;
    stalePage = await (await fetch(release.orbit.url + '/')).text();
    const page = await open(t, proxy.url + '/');
    const pageLoads = () => proxy.requests.filter(r => r.path.split('?')[0] === '/').length;
    assert.equal(pageLoads(), 1);
    const next = await release.next();
    orbitPort = next.port;
    await page.eval('window.__poll()');
    await page.waitFor(
      "!document.querySelector('#update-banner').hidden && /still the older version/.test(document.querySelector('#update-text').textContent)",
      15000
    );
    assert.equal(pageLoads(), 3, 'the first load and two automatic reloads');
    await delay(1500);
    assert.equal(pageLoads(), 3, 'no further automatic reload');
  }
);

test(
  'a page that loads while Uptime Goblin restarts into a new release waits for it, then opens the new release',
  { skip },
  async t => {
    let orbitPort,
      down = false;
    const proxy = await httpProxy({
      target: () => orbitPort,
      // Like nginx while Uptime Goblin restarts: 502 Bad Gateway for the page's files.
      decide: request =>
        down && request.path.startsWith('/assets/')
          ? { status: 502, headers: { 'Content-Type': 'text/plain' }, body: 'Bad Gateway' }
          : 'forward',
    });
    t.after(() => proxy.close());
    const release = await releases(t, { allowedHosts: `127.0.0.1:${proxy.port}` });
    orbitPort = release.orbit.port;
    const first = release.orbit.app.build;
    const pageLoads = () =>
      proxy.requests.filter(r => r.method === 'GET' && r.path.split('?')[0] === '/').length;
    // Uptime Goblin sends the page, then stops before the browser has its web app.
    down = true;
    const page = await open(t, proxy.url + '/', {
      ready: "document.querySelector('#update-banner')?.hidden === false",
    });
    assert.match(await page.text('#update-text'), /not answering/);
    const next = await release.next();
    orbitPort = next.port;
    await delay(500);
    assert.equal(pageLoads(), 1, 'no reload into an error page while Uptime Goblin is away');
    down = false;
    await page.waitFor(`${onBuild(next.app.build)} && ${cards}`, 20000);
    assert.equal(pageLoads(), 2, 'one reload, once Uptime Goblin answered');
    // It asked Uptime Goblin about its own build, which the new release no longer has.
    assert.ok(
      proxy.requests.some(
        r =>
          r.method === 'HEAD' &&
          r.path === `/assets/${first}/modules/main.js` &&
          r.response?.status === 404
      )
    );
    assert.equal(await page.eval("document.querySelector('#update-banner').hidden"), true);
    assert.deepEqual(page.exceptions, []);
  }
);

/**
 * public/ of an earlier release from its git tag in the private history repository
 * (test/upgrade/history.mjs): `files` (a Map of path to bytes); or `skip` when there is no
 * history input, or a working Git says that repository has no such tag or is no repository, all
 * of which TEST_REQUIRE=history turns into `broken`; or `broken` when Git did not answer or the
 * history input is wrong, which fails the test.
 */
function publicAt(tag) {
  const missing = reason =>
    historyRequired() ? { broken: `${reason} (TEST_REQUIRE=history)` } : { skip: reason };
  let input;
  try {
    input = history();
  } catch (error) {
    return { broken: `the private history input is wrong: ${error.message}` };
  }
  if (input.unavailable) return missing(`needs the ${tag} tag, and ${input.unavailable}`);
  const git = (args, options) => gitProbe(['-C', input.repository, ...args], options);
  const commit = git(['rev-parse', '--verify', '--quiet', `${tag}^{commit}`], {
    statuses: [0, 1],
  });
  if (commit.outside)
    return missing(`needs the ${tag} tag, and the private history repository is not a checkout`);
  if (commit.broken) return { broken: commit.broken };
  // --quiet makes a missing tag exit 1 with no output; anything else with 1 is not that answer.
  if (commit.status === 1) {
    const probe = `git rev-parse --verify --quiet ${tag}^{commit} exited with status 1`;
    const said = `${commit.stdout}${commit.stderr}`.trim().slice(0, 500);
    if (said) return { broken: `${probe}: ${said}` };
    // A missing tag is an answer about a repository, so Git must find one: a git that exits 1 to
    // everything but --version must not read as a repository without the tag.
    const repository = git(['rev-parse', '--git-dir']);
    const lost =
      repository.broken ||
      (repository.outside && 'git rev-parse --git-dir says this source is in no repository') ||
      (!repository.stdout.trim() && 'git rev-parse --git-dir printed nothing');
    return lost
      ? { broken: `${probe}, which says the repository has no ${tag}, but ${lost}` }
      : missing(`needs the ${tag} tag, which the private history repository does not have`);
  }
  const list = git(['ls-tree', '-r', '--name-only', `${tag}^{commit}`, '--', 'public']);
  if (list.broken) return { broken: list.broken };
  const names = list.stdout.split('\n').filter(Boolean);
  if (!names.length) return { broken: `${tag} has no public/ directory` };
  const files = new Map();
  for (const name of names) {
    const show = git(['show', `${tag}:${name}`], { encoding: 'buffer' });
    if (show.broken) return { broken: show.broken };
    files.set(name.slice('public/'.length), show.stdout);
  }
  return { files };
}
const public143 = publicAt('v1.4.3');
// Without Git there is no tag to read: that is the git requirement (test/helpers/git.mjs), which
// TEST_REQUIRE=git turns into a failure, not the history repository's missing tag. A Git that cannot
// read the tag fails the test instead of passing for either.
const gitSkip = declareGit();

test(
  'a tab running the 1.4.3 web app moves to this release’s by itself and returns to the same view',
  { skip: skip || (gitMissing ? gitSkip : public143.skip) },
  async t => {
    if (public143.broken) assert.fail(public143.broken);
    const directory = temporaryDirectory(t),
      old = temporaryDirectory(t, 'orbit-public-1.4.3-');
    for (const [file, bytes] of public143.files) {
      fs.mkdirSync(path.dirname(path.join(old, file)), { recursive: true });
      fs.writeFileSync(path.join(old, file), bytes);
    }
    let orbit = await startSignedIn({ directory, publicDirectory: old });
    t.after(() => orbit.close());
    seedReadings(orbit.app, 'linux');
    const script = `document.querySelector('script[type="module"]')?.getAttribute('src')`;
    const page = await open(t, orbit.url + '/', { height: 600 });
    assert.equal(await page.eval(script), `/app.js?v=${orbit.app.build}`, 'the 1.4.3 web app');
    await page.eval(`document.querySelector('[data-expand="linux"]').click()`);
    await page.waitFor("document.querySelector('#graph-linux svg.chart')");
    await page.eval(`document.querySelector('[data-range="7d"]').click()`);
    await page.waitFor(
      `document.querySelector('[data-range="7d"]')?.getAttribute('aria-pressed') === 'true'`
    );
    await page.eval('window.__oldPage = true');

    // The update: the same data, this release's web app.
    await orbit.close();
    orbit = await startOrbit({ directory, publicDirectory: copyPublic(t), port: orbit.port });
    await page.eval('window.__poll()');
    await page.waitFor(onBuild(orbit.app.build), 10000);
    assert.equal(await page.eval('window.__oldPage'), undefined, 'the page was reloaded');
    assert.equal(await page.eval(script), '/boot.js');
    await page.waitFor("document.querySelector('#graph-linux svg.chart')");
    assert.equal(
      await page.eval(`document.querySelector('.service.expanded')?.dataset.id`),
      'linux'
    );
    assert.equal(
      await page.eval(`document.querySelector('[data-range="7d"]').getAttribute('aria-pressed')`),
      'true'
    );
    const scripts = await page.eval(
      "performance.getEntriesByType('resource').map(e => new URL(e.name).pathname).filter(p => p.endsWith('.js'))"
    );
    assert.ok(scripts.includes(`/assets/${orbit.app.build}/modules/main.js`));
    assert.ok(!scripts.some(p => p.startsWith('/app.js')), 'the new page does not use the shim');
    assert.deepEqual(page.exceptions, []);
  }
);

// The test above as its own runner reports it (the update side of the maintainer's
// TOOLING-GIT-REQUIRED-P3): a copy of the shipped files and of this file runs it in a nested
// runner (with TEST_REQUIRE=browser, so that it cannot skip for want of Chrome), without and with
// git in TEST_REQUIRE, with no git, a git that exits 23, one that answers --version but exits 23
// to the tag probe, one that exits 1 silently (as Git does for a missing tag) to everything or to
// everything but --version, one that cannot be executed (EACCES), and the real Git, first in no
// repository (a source archive) and then in a checkout without the tag, where it also runs with a
// `git --version` that fails. The copy is the repository of a synthetic private history input
// (TEST_HISTORY). Only a missing optional Git, a source archive and a missing tag may skip it; a
// broken Git fails it.
test(
  'the old web app test skips only for a missing optional Git, a source archive or a missing tag, never for a broken Git',
  { skip, timeout: 180000 },
  t => {
    if (gitSkip) return t.skip(gitSkip);
    const base = fs.realpathSync(temporaryDirectory(t, 'orbit-git-probe-'));
    const source = path.join(base, 'source');
    const manifest = fs
      .readFileSync(path.join(root, 'deploy/manifest.txt'), 'utf8')
      .split('\n')
      .filter(line => line && !line.startsWith('#'));
    for (const file of [...manifest, 'test/update.test.mjs', 'test/setup.mjs'])
      fs.cpSync(path.join(root, file), path.join(source, file));
    fs.cpSync(path.join(root, 'test/helpers'), path.join(source, 'test/helpers'), {
      recursive: true,
    });
    fs.symlinkSync(
      fs.realpathSync(path.join(root, 'node_modules')),
      path.join(source, 'node_modules')
    );
    fs.cpSync(
      path.join(root, 'test/upgrade/history.mjs'),
      path.join(source, 'test/upgrade/history.mjs')
    );
    const historyInput = path.join(base, 'history.json');
    fs.writeFileSync(
      historyInput,
      JSON.stringify({
        schema: historySchema,
        repository: 'source',
        milestones: { '1.5.0-dev.0': '0'.repeat(40), '1.5.0-dev.1': '1'.repeat(40) },
        fixtures: {},
        rewrites: [],
      })
    );
    const stubs = gitStubs(base);
    const run = (directory, required) =>
      runNested({
        cwd: source,
        history: historyInput,
        file: 'test/update.test.mjs',
        pattern: '^(git is installed|a tab running the 1\\.4\\.3 web app)',
        // Chrome's launcher may run other commands; only Git is replaced.
        PATH: [directory, stubs.commands].filter(Boolean).join(path.delimiter),
        required: required ? 'browser,git' : 'browser',
        ceiling: base,
      });
    const probe = 'rev-parse --verify --quiet v1\\.4\\.3\\^\\{commit\\}';
    for (const required of [false, true]) {
      const name = what => `${what}, TEST_REQUIRE ${required ? '=browser,git' : '=browser'}`;
      expectNested(
        name('no git'),
        run(stubs.missing, required),
        required
          ? {
              status: 1,
              tests: 2,
              fail: 2,
              says: [
                /TEST_REQUIRE lists git, but git is not installed/,
                new RegExp(`${probe} could not run: spawnSync git ENOENT`),
              ],
            }
          : {
              status: 0,
              tests: 1,
              skipped: 1,
              says: /# SKIP git is not installed \(TEST_REQUIRE=git makes this fail\)/,
            }
      );
      // The test and the file's `git is installed and runs` fail, whatever TEST_REQUIRE says.
      expectNested(name('a git that exits 23'), run(stubs.exits23, required), {
        status: 1,
        tests: 2,
        fail: 2,
        says: [
          new RegExp(`${probe} exited with status 23`),
          /git is broken: git --version exited with status 23/,
        ],
      });
      expectNested(name('a git that cannot be executed'), run(stubs.unrunnable, required), {
        status: 1,
        tests: 2,
        fail: 2,
        says: [
          new RegExp(`${probe} could not run: spawnSync git EACCES`),
          /git is broken: git --version could not run: spawnSync git EACCES/,
        ],
      });
      // `git --version` works, so only the probe's own status can tell it from a missing tag.
      expectNested(name('a git whose probe exits 23'), run(stubs.probeExits23, required), {
        status: 1,
        tests: 1,
        fail: 1,
        says: new RegExp(`${probe} exited with status 23`),
      });
      // Its silent exit 1 is what Git says of a missing tag, but its `git --version` fails.
      expectNested(name('a git that exits 1'), run(stubs.exits1, required), {
        status: 1,
        tests: 2,
        fail: 2,
        says: [
          new RegExp(
            `${probe} exited with status 1, but git is broken: git --version exited with status 1`
          ),
          /git is broken: git --version exited with status 1/,
        ],
      });
      // `git --version` works, so only Git failing to find the repository tells it from a
      // shallow clone.
      expectNested(name('a git whose other commands exit 1'), run(stubs.probeExits1, required), {
        status: 1,
        tests: 1,
        fail: 1,
        says: new RegExp(
          `${probe} exited with status 1, which says the repository has no v1\\.4\\.3, but git -C \\S+ rev-parse --git-dir exited with status 1`
        ),
      });
      expectNested(name('a source archive'), run(process.env.PATH, required), {
        status: 0,
        tests: 1,
        skipped: 1,
        says: /# SKIP needs the v1\.4\.3 tag, and the private history repository is not a checkout/,
      });
    }
    // A GIT_DIR of this run's own (a hook's, say) must not be the repository it initialises.
    const init = spawnSync('git', ['init', '--quiet'], {
      cwd: source,
      encoding: 'utf8',
      env: Object.fromEntries(Object.entries(process.env).filter(([n]) => !n.startsWith('GIT_'))),
    });
    assert.equal(init.status, 0, init.error?.message ?? init.stderr);
    for (const required of [false, true]) {
      const name = what => `${what}, TEST_REQUIRE ${required ? '=browser,git' : '=browser'}`;
      expectNested(name('a checkout without the tag'), run(process.env.PATH, required), {
        status: 0,
        tests: 1,
        skipped: 1,
        says: /# SKIP needs the v1\.4\.3 tag, which the private history repository does not have/,
      });
      // Git's own answer for a missing tag, from a Git whose `git --version` fails.
      expectNested(
        name('a checkout without the tag and a git whose --version fails'),
        run(stubs.versionFails, required),
        {
          status: 1,
          tests: 2,
          fail: 2,
          says: [
            new RegExp(
              `${probe} exited with status 1, but git is broken: git --version exited with status 1`
            ),
            /git is broken: git --version exited with status 1/,
          ],
        }
      );
    }
  }
);

test(
  'a kiosk update with unsaved settings does not stop at a leave-page prompt',
  { skip },
  async t => {
    const release = await releases(t);
    const page = await open(t, release.orbit.url + '/?kiosk=1#configure/appearance', {
      ready: "document.querySelector('#workspace-title')",
    });
    // A real interaction is required: browsers suppress beforeunload prompts in tabs that
    // never had user activation, which would make this regression invisible.
    await page.click('#workspace-title');
    await page.setValue('#workspace-title', 'Unsaved kiosk title');
    const prompts = [];
    const listener = message => {
      if (
        message.sessionId === page.sessionId &&
        message.method === 'Page.javascriptDialogOpening'
      ) {
        prompts.push(message.params.type);
        void page.send('Page.handleJavaScriptDialog', { accept: false });
      }
    };
    page.cdp.listeners.add(listener);
    t.after(() => page.cdp.listeners.delete(listener));
    // Kiosk mode still protects edits during an ordinary manual reload.
    await page.send('Page.reload');
    const promptDeadline = Date.now() + 5000;
    while (!prompts.length && Date.now() < promptDeadline) await delay(20);
    assert.deepEqual(prompts, ['beforeunload']);
    assert.equal(
      await page.eval("document.querySelector('#workspace-title').value"),
      'Unsaved kiosk title'
    );
    prompts.length = 0;
    const next = await release.next();
    await page.eval('window.__poll()');
    await delay(1500);
    assert.deepEqual(prompts, [], 'an unattended kiosk must not need confirmation');
    await page.waitFor(onBuild(next.app.build), 10000);
    await page.waitFor("document.querySelector('#workspace-title')");
    assert.notEqual(
      await page.eval("document.querySelector('#workspace-title').value"),
      'Unsaved kiosk title'
    );
    assert.deepEqual(page.exceptions, []);
  }
);

// A page kept by a cache, from before 1.5 or of a build Uptime Goblin no longer has. 1.4.x ran its whole
// web app from /app.js in any page, so a page from before 1.5 kept working there. From 1.5 the web
// app never runs in a page whose markup it was not written for: /app.js, now the shim, hands the
// page to /boot.js, which reloads it twice at most, says why, and then checks in the background
// (first after 30 s, then twice as long each time, up to every 10 minutes) until the cache
// answers with a current page. Each test runs the page's clock faster through its prelude.
const template = () => fs.readFileSync(path.join(root, 'public/index.html'), 'utf8');
const olderPages = {
  // Unversioned asset URLs (the web app was /app.js), no build meta tag, no update banner.
  'a 1.4.2 page': () =>
    template()
      .replace('src="/boot.js"', 'src="/app.js"')
      .replace(/\s*<div id="update-banner"[\s\S]*?<\/div>/, ''),
  // As the 1.4.3 server rendered it: its build in the meta tag and in /app.js?v=<build>.
  'a 1.4.3 page': () =>
    renderIndex(template().replace('src="/boot.js"', 'src="/app.js"'), '0123456789ab'),
  // A page from 1.5 on whose build's files Uptime Goblin no longer has.
  'a page of a build Uptime Goblin no longer has': () => renderIndex(template(), 'dead00000000'),
};
const stuckNotice =
  "document.querySelector('#update-banner')?.hidden === false && /still the older version after reloading/.test(document.querySelector('#update-text').textContent)";
const checkNotice = `${stuckNotice} && /checks again by itself/.test(document.querySelector('#update-text').textContent)`;
/**
 * Uptime Goblin behind a cache that answers GET / with `oldPage` whenever `old(load)` says so, holds it
 * without an answer when it says 'hold', and otherwise forwards it. `loads` lists every GET / in
 * order: `kind` is 'navigate' for a page load and 'check' for the page's own background check (a
 * fetch); `old` is whether it did not get Uptime Goblin's page, and `held` whether it got no answer.
 */
async function behindCache(t, oldPage, old) {
  let orbitPort;
  const loads = [];
  const proxy = await httpProxy({
    target: () => orbitPort,
    decide: request => {
      if (request.method !== 'GET' || request.path.split('?')[0] !== '/') return 'forward';
      const load = {
        kind: request.headers['sec-fetch-mode'] === 'navigate' ? 'navigate' : 'check',
        headers: request.headers,
      };
      const answer = old(load, loads);
      Object.assign(load, { old: Boolean(answer), held: answer === 'hold' });
      loads.push(load);
      if (load.held) return 'hold';
      return load.old
        ? { headers: { 'Content-Type': 'text/html; charset=utf-8' }, body: oldPage }
        : 'forward';
    },
  });
  t.after(() => proxy.close());
  const release = await releases(t, { allowedHosts: `127.0.0.1:${proxy.port}` });
  orbitPort = release.orbit.port;
  return { proxy, release, loads };
}
const kinds = loads =>
  loads.map(load => (load.held ? 'held ' : load.old ? 'old ' : 'new ') + load.kind);
/** Waits until `condition()` (a check of the test's own records) holds. */
async function until(condition, timeout, message) {
  const end = Date.now() + timeout;
  while (!condition()) {
    if (Date.now() > end) assert.fail(`Timed out waiting for ${message}`);
    await delay(20);
  }
}
/** The checks bypass the browser's cache and ask proxies to revalidate: fetch cache 'reload'. */
function assertBypassesCaches(loads) {
  for (const load of loads.filter(load => load.kind === 'check')) {
    assert.equal(load.headers['cache-control'], 'no-cache');
    assert.equal(load.headers.pragma, 'no-cache');
  }
}

for (const name of ['a 1.4.2 page', 'a 1.4.3 page'])
  test(
    `${name} kept by a cache is not run: it says why, then opens the current release by itself once the cache lets go`,
    { skip },
    async t => {
      const oldPage = olderPages[name]();
      assert.match(oldPage, /<script type="module" src="\/app\.js(\?v=0123456789ab)?"><\/script>/);
      // The cache answers the page load, both automatic reloads and the first background check
      // with the old page, then serves Uptime Goblin's.
      const { proxy, release, loads } = await behindCache(
        t,
        oldPage,
        (load, earlier) => earlier.length < 4
      );
      const page = await open(t, proxy.url + '/', {
        prelude: { scale: 50 },
        ready: "document.readyState === 'complete'",
      });
      // Checks after 30 s and 60 s: 0.6 s and 1.2 s here.
      await page.waitFor(checkNotice, 10000);
      assert.deepEqual(kinds(loads.slice(0, 3)), Array(3).fill('old navigate'));
      assert.equal(await page.eval("document.querySelector('#services').children.length"), 0);
      assert.equal(await page.text('#update-reload'), 'Reload', 'the Reload button stays');
      // Nobody presses Reload: the dashboard opens by itself once the check gets a current page.
      await page.waitFor(`${onBuild(release.orbit.app.build)} && ${cards}`, 15000);
      assert.deepEqual(kinds(loads), [
        ...Array(3).fill('old navigate'),
        'old check',
        'new check',
        'new navigate',
      ]);
      assertBypassesCaches(loads);
      assert.equal(
        await page.eval(`document.querySelector('script[type="module"]').getAttribute('src')`),
        '/boot.js'
      );
      assert.equal(await page.eval("document.querySelector('#update-banner').hidden"), true);
      // Its checks are over: a later stale page in this tab starts again from the beginning.
      assert.equal(await page.eval("sessionStorage.getItem('orbit-stale-checks')"), null);
      assert.ok(
        proxy.requests.some(r => r.path.split('?')[0] === '/app.js'),
        'the old page loads /app.js'
      );
      assert.deepEqual(page.exceptions, []);
    }
  );

/**
 * A page clock `scale` times faster than real time: Date.now() and every timer, counted from the
 * same `epoch` in each page the tab loads, so the times a page keeps in sessionStorage stay true
 * across reloads. A timer waits at least its length on this clock: its real delay is rounded up
 * (a fraction of a millisecond would be cut, and the timer would fire early on the page's clock).
 * Kept in sessionStorage, across the tab's reloads, by the page's clock: 'test-timers', each
 * timer's requested length; 'test-pages', when each page began; 'test-checks', each background
 * check (a fetch with cache 'reload'): `page`, the index of the page that made it in
 * 'test-pages'; `made`, when the timer that made it fired, if a timer's callback made it (the
 * time of the fetch otherwise); `timer`, that timer, or null when the fetch was not made inside
 * a timer's callback (it came after an await); `fetched`, the time of the fetch; `record`, the
 * page's own record of its checks (sessionStorage 'orbit-stale-checks') as the check left it;
 * 'test-notices', when each page first said it checks again by itself: {page, at}, read by a
 * MutationObserver, so in the same task as the text changed, once that task's script has run.
 * A timer is {id, set, ms, parent, fired, write}: its number in its page, when it was set (read
 * before anything else the timer does), the length asked for, the id of the timer whose callback
 * set it (null when no timer's callback was running), how many of the callbacks the page
 * scheduled had run by then (its timers', intervals', animation frames' and idle callbacks', and
 * its handlers of a message to the window or to a MessageChannel's port), and the page's latest
 * write of its record of the checks if the run of script that made it had not yet ended (no task
 * could run between them, nor any microtask queued after the write), or null: {n, at}, its
 * number among that page's writes of the record, and when it was made.
 */
const fastClock = (scale, epoch = Date.now()) => `(() => {
  const realNow = Date.now.bind(Date),
    realSetTimeout = window.setTimeout.bind(window),
    realFetch = window.fetch.bind(window),
    realSetItem = Storage.prototype.setItem;
  const read = key => JSON.parse(sessionStorage.getItem(key) || '[]');
  const log = (key, value) =>
    realSetItem.call(sessionStorage, key, JSON.stringify([...read(key), value]));
  Date.now = () => ${epoch} + (realNow() - ${epoch}) * ${scale};
  log('test-pages', Date.now());
  const page = read('test-pages').length - 1;
  let timers = 0,
    fired = 0,
    firing = null,
    writes = 0,
    writing = null;
  // The page's latest write of its record of the checks, until the run of script that made it
  // ends: the microtask its first write queues runs before any task, and before any microtask
  // queued after it.
  Storage.prototype.setItem = function (key, value) {
    realSetItem.call(this, key, value);
    if (this === sessionStorage && key === 'orbit-stale-checks') {
      if (!writing) queueMicrotask(() => (writing = null));
      writing = { n: writes++, at: Date.now() };
    }
  };
  // A callback the page scheduled in another way counts as a timer that fired: it could stand
  // in for one.
  const counted = fn =>
    typeof fn === 'function'
      ? function (...args) {
          fired += 1;
          return fn.apply(this, args);
        }
      : fn;
  for (const name of ['setInterval', 'requestAnimationFrame', 'requestIdleCallback']) {
    const real = window[name].bind(window);
    window[name] = (fn, ...rest) => real(counted(fn), ...rest);
  }
  window.MessageChannel = class extends MessageChannel {
    constructor() {
      super();
      for (const port of [this.port1, this.port2])
        port.addEventListener('message', () => (fired += 1));
    }
  };
  addEventListener('message', () => (fired += 1), true);
  const said = new MutationObserver(() => {
    if (/checks again by itself/.test(document.getElementById('update-text')?.textContent ?? '')) {
      said.disconnect();
      log('test-notices', { page, at: Date.now() });
    }
  });
  said.observe(document, { childList: true, characterData: true, subtree: true });
  window.setTimeout = (fn, ms = 0, ...rest) => {
    const timer = {
      id: timers++,
      set: Date.now(),
      ms,
      parent: firing?.timer.id ?? null,
      fired,
      write: writing,
    };
    log('test-timers', ms);
    return realSetTimeout(
      (...args) => {
        fired += 1;
        firing = { made: Date.now(), timer };
        try {
          return fn(...args);
        } finally {
          firing = null;
        }
      },
      Math.ceil(ms / ${scale}),
      ...rest
    );
  };
  window.fetch = (resource, init) => {
    if (init?.cache === 'reload')
      log('test-checks', {
        page,
        made: firing?.made ?? Date.now(),
        timer: firing?.timer ?? null,
        fetched: Date.now(),
        record: JSON.parse(sessionStorage.getItem('orbit-stale-checks')),
      });
    return realFetch(resource, init);
  };
})();`;
for (const name of ['a 1.4.2 page', 'a page of a build Uptime Goblin no longer has'])
  test(
    `${name} behind a cache that never lets go keeps checking without a reload loop: one reload per check at most`,
    { skip },
    async t => {
      // Page loads always get the old page. The checks are first held without an answer (a proxy
      // waiting for an Uptime Goblin that does not answer), then answered with the old page, then with
      // Uptime Goblin's current page (a proxy that revalidates a no-cache request but not a reload).
      let checkAnswer = 'hold';
      const { proxy, loads } = await behindCache(t, olderPages[name](), load =>
        load.kind === 'navigate' ? true : { hold: 'hold', old: true, current: false }[checkAnswer]
      );
      // A wall display whose clock runs 1000 times faster: 30 s is 30 ms, 10 minutes 0.6 s.
      const scale = 1000;
      const page = await openPage(browser.cdp, proxy.url + '/?kiosk=1', {
        prelude: fastClock(scale),
        ready: checkNotice,
        timeout: 10000,
      });
      t.after(() => page.close());
      const count = (kind, old) =>
        loads.filter(load => load.kind === kind && (old === undefined || load.old === old)).length;
      // Unanswered checks neither stop the next one nor pile up: each is dropped when the next is
      // due, so the seventh still gets through, past the browser's six connections per server.
      await until(() => count('check') >= 7, 10000, 'seven checks without an answer');
      assert.equal(count('navigate'), 3);
      checkAnswer = 'old';
      const answered = () => loads.filter(load => load.kind === 'check' && !load.held).length;
      await until(() => answered() >= 2, 10000, 'two checks answered with the old page');
      assert.equal(count('navigate'), 3, 'no reload for an answer that is still the old page');

      // The checks have gone on for most of an hour, so the allowance's two reloads are more than
      // 10 minutes old and it would allow two more: still, only a check may reload the page.
      checkAnswer = 'current';
      await until(() => count('navigate') >= 7, 20000, 'four reloads by the checks');
      checkAnswer = 'old';
      const settled = loads.length;
      await until(
        () => loads.slice(settled).some(load => load.kind === 'check'),
        10000,
        'a check after the last reload'
      );
      // Page loads: the first, the allowance's two reloads, then one for each check that got the
      // current page, right after it. Never a reload without a check of its own before it.
      assert.deepEqual(kinds(loads.slice(0, 3)), Array(3).fill('old navigate'));
      for (const [i, load] of loads.entries()) {
        if (i >= 3 && load.kind === 'navigate')
          assert.equal(kinds([loads[i - 1]])[0], 'new check', `load ${i}: ${kinds(loads)}`);
        if (load.kind === 'check' && !load.old)
          assert.equal(loads[i + 1]?.kind, 'navigate', `load ${i}: ${kinds(loads)}`);
      }
      assert.equal(count('navigate'), 3 + count('check', false));
      assertBypassesCaches(loads);
      // The interval does not start over after a reload: the first check came 30 s after the
      // page gave up reloading, and each one after that twice as long after the one before, up to
      // 10 minutes, whichever page made it. The times are the page's own (fastClock), and a check
      // made by a timer is judged by when that timer was due (when it was set, plus the length
      // asked for), not by when it fired: a timer fires late by however long the machine keeps it
      // waiting, which at 1000 times real time hides a check some seconds early, and when a
      // request reached the proxy is no measure at all (166 ms on a busy machine read as 166 s).
      // Every time compared is a reading of the page's Date.now(), so no allowance is made.
      // Every check the proxy has seen was recorded (before its request was sent) by then.
      const seen = count('check');
      const [checks, pages, notices] = await page.eval(
        "['test-checks', 'test-pages', 'test-notices'].map(key => JSON.parse(sessionStorage.getItem(key) || '[]'))"
      );
      assert.ok(
        checks.length >= seen,
        `the page recorded ${checks.length} checks, the proxy saw ${seen}`
      );
      const interval = i => Math.min(30000 * 2 ** i, 600000);
      const all = JSON.stringify(checks);
      for (const [i, check] of checks.entries()) {
        const before = checks[i - 1],
          { timer } = check;
        // Each check is made by a timer's callback, and records itself while it is made, before
        // it asks.
        assert.ok(timer, `check ${i} was not made by a timer's callback: ${all}`);
        assert.ok(
          check.made <= check.record.at && check.record.at <= check.fetched,
          `check ${i} did not record itself as it was made: ${all}`
        );
        // Never early: due at least its interval after the check before was made (the first,
        // after the page that gave up began).
        const after = timer.set + timer.ms - (before ? before.made : pages[2]);
        assert.ok(
          after >= interval(i),
          `check ${i} was due ${after} ms after the one before: ${all}`
        );
        // Never late, judged by what the page asked for, so how late the machine fires a timer
        // does not matter, and by when it asked: a timer set by another timer's callback, after
        // an await, or from any other task or microtask could add any wait to the interval. A
        // check is made by a timer set by the callback of the check before on the same page,
        // asking for no more than the interval. The first check of a page (after a reload, or the
        // first of all) is made by a timer set in the same run of script as the page's first
        // write of its record of the checks, a write made no later than the page said it checks
        // by itself, asking for at most what was then left of the interval since the check before
        // (as that check recorded it), or nothing: never a whole interval again. So once a page
        // says it checks by itself, its checks keep to their schedule. Not seen: a synchronous
        // stall between that write and the timer, which the page's clock cannot tell from the
        // machine pausing the page, and how long a page takes, from when it began, to begin its
        // checks. Of that, only this is judged: it begins them before any callback it scheduled
        // (a timer, an interval, an animation frame, an idle callback or a message handler) has
        // run, and not in a timer's callback. Nothing bounds the rest: the page first loads its
        // scripts and, from 1.5 on, asks Uptime Goblin about its build, through the proxy in this process,
        // which a busy machine stretches to page-minutes at this scale, so code that waited for a
        // request of its own, or for any other event, before it began would not be seen.
        if (before && check.page === before.page) {
          assert.equal(
            timer.parent,
            before.timer.id,
            `check ${i}: not set by the one before: ${all}`
          );
          assert.ok(timer.ms <= interval(i), `check ${i} waited ${timer.ms} ms: ${all}`);
        } else {
          const { write } = timer,
            said = notices.find(notice => notice.page === check.page);
          assert.ok(
            write?.n === 0,
            `check ${i}: not set as its page first wrote its record of the checks: ${all}`
          );
          assert.ok(
            said && write.at <= said.at,
            `check ${i}: its page said it checks by itself before it began to: ${JSON.stringify(notices)} ${all}`
          );
          assert.ok(
            timer.parent === null && timer.fired === 0,
            `check ${i}: its page began its checks in a timer's callback, or after a callback it scheduled ran: ${all}`
          );
          const left = before ? before.record.at + interval(i) - write.at : interval(i);
          assert.ok(
            timer.ms <= Math.max(0, left),
            `check ${i}, the first of its page, waited ${timer.ms} ms: ${all}`
          );
        }
      }
      const timers = JSON.parse(await page.eval("sessionStorage.getItem('test-timers')"));
      assert.ok(Math.max(...timers) <= 600000, `at most 10 minutes: ${timers}`);
      assert.equal(await page.eval("document.querySelector('#services').children.length"), 0);
      assert.deepEqual(page.exceptions, []);
    }
  );

test('a kiosk checks for updates while a connection drawer is open', { skip }, async t => {
  const release = await releases(t);
  const page = await open(t, release.orbit.url + '/?kiosk=1');
  await page.eval("document.querySelector('#add-source').click()");
  await page.waitFor("document.querySelector('#settings-dialog').open");
  await page.setValue('#source-name', 'Unattended connection draft');
  const next = await release.next();
  await page.eval('window.__poll()');
  await page.waitFor(onBuild(next.app.build), 5000);
  assert.deepEqual(page.exceptions, []);
});

test('three genuine releases are not mistaken for a cached-page reload loop', { skip }, async t => {
  const release = await releases(t);
  const page = await open(t, release.orbit.url + '/');
  for (let i = 0; i < 3; i++) {
    const next = await release.next();
    await page.eval('window.__poll()');
    await page.waitFor(onBuild(next.app.build), 5000);
    await page.waitFor(cards);
    assert.equal(await page.eval("document.querySelector('#update-banner').hidden"), true);
  }
  assert.deepEqual(page.exceptions, []);
});

test(
  'an update offer is withdrawn when Uptime Goblin returns to this page’s build',
  { skip },
  async t => {
    let orbitPort, reportedBuild;
    const proxy = await httpProxy({
      target: () => orbitPort,
      decide: request =>
        request.path === '/api/version' && reportedBuild
          ? {
              headers: { 'Content-Type': 'application/json', 'X-Goblin-Build': reportedBuild },
              body: JSON.stringify({ build: reportedBuild }),
            }
          : 'forward',
    });
    t.after(() => proxy.close());
    const release = await releases(t, { allowedHosts: `127.0.0.1:${proxy.port}` });
    orbitPort = release.orbit.port;
    const page = await open(t, proxy.url + '/#configure/appearance', {
      prelude: { hidden: true },
      ready: "document.querySelector('#workspace-title')",
    });
    await page.setValue('#workspace-title', 'Keep this draft');
    reportedBuild = '000000000000';
    await page.eval('window.__probe()');
    await page.waitFor("!document.querySelector('#update-banner').hidden");
    reportedBuild = release.orbit.app.build;
    await page.eval('window.__probe()');
    await page.waitFor("document.querySelector('#update-banner').hidden");
    assert.equal(
      await page.eval("document.querySelector('#workspace-title').value"),
      'Keep this draft'
    );
    assert.deepEqual(page.exceptions, []);
  }
);

// Not a browser test: what the server sends a page and its files (contract C-O, 1.5). The page
// names its build and loads the stable /boot.js, which loads that build's modules from
// /assets/<build>/; those URLs change with every release, so they are cached for a year, and a
// build Uptime Goblin no longer has is a 404 that is never cached, so /boot.js reloads the page.
test('the page names its build and loads it from /assets/<build>/ through /boot.js; another build’s files are 404', async t => {
  const directory = temporaryDirectory(t),
    publicDirectory = copyPublic(t);
  const orbit = await startOrbit({ directory, publicDirectory });
  t.after(() => orbit.close());
  const { build, version } = orbit.app;
  assert.match(build, /^[0-9a-f]{12}$/);
  assert.equal(version, JSON.parse(fs.readFileSync(path.join(root, 'package.json'))).version);
  // The documented algorithm, which the installer reproduces for the release it installs.
  const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
  // Every file under public/ and every *.mjs file under lib/ (1.5 keeps server code in lib/http/
  // and other subdirectories), both walked recursively, dot names skipped, then server.mjs.
  const files = [];
  function walk(directory, relative, keep) {
    for (const name of fs.readdirSync(directory)) {
      if (name.startsWith('.')) continue;
      const full = path.join(directory, name);
      if (fs.statSync(full).isDirectory()) walk(full, `${relative}/${name}`, keep);
      else if (keep(name)) files.push([`${relative}/${name}`, full]);
    }
  }
  walk(publicDirectory, 'public', () => true);
  walk(path.join(root, 'lib'), 'lib', name => name.endsWith('.mjs'));
  files.push(['server.mjs', path.join(root, 'server.mjs')]);
  files.sort(([a], [b]) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  const listing = [
    version,
    ...files.flatMap(([name, full]) => [name, sha256(fs.readFileSync(full))]),
  ];
  assert.equal(sha256(listing.join('\n') + '\n').slice(0, 12), build);
  assert.deepEqual(buildInfo(root, publicDirectory), { version, build });

  const index = await fetch(orbit.url + '/');
  assert.equal(index.headers.get('x-goblin-build'), build);
  // From 1.5 the page is public, since the sign-in view must load before anyone signs in; only
  // answers to a signed-in request name the version (sessions spec D9, D10).
  assert.equal(index.headers.get('x-goblin-version'), null);
  assert.equal(index.headers.get('cache-control'), 'no-store');
  const html = await index.text();
  assert.equal(html.match(/<meta name="orbit-build"/g).length, 1);
  assert.ok(html.includes(`<meta name="orbit-build" content="${build}" />`));
  assert.deepEqual(
    [...html.matchAll(/<script\b[^>]*>/g)].map(match => match[0]),
    ['<script type="module" src="/boot.js">']
  );
  assert.ok(html.includes(`<link rel="stylesheet" href="/assets/${build}/style.css" />`));
  assert.doesNotMatch(html, /\/app\.js|\?v=/);
  // Still no inline script, so the strict Content-Security-Policy holds.
  assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/);
  assert.match(index.headers.get('content-security-policy'), /script-src 'self';/);
  assert.equal(await (await fetch(orbit.url + '/index.html')).text(), html);
  assert.equal(renderIndex(html, build), html, 'injecting twice changes nothing');

  // The loader: one stable URL, checked with Uptime Goblin on every load.
  const boot = await fetch(orbit.url + '/boot.js');
  assert.equal(boot.status, 200);
  assert.equal(boot.headers.get('cache-control'), 'no-cache');
  assert.equal(boot.headers.get('content-type'), 'text/javascript; charset=utf-8');
  assert.equal(await boot.text(), fs.readFileSync(path.join(publicDirectory, 'boot.js'), 'utf8'));

  // This build's files, for a year: their URL changes whenever they do.
  for (const [file, type] of [
    ['modules/main.js', 'text/javascript; charset=utf-8'],
    ['modules/core/api.js', 'text/javascript; charset=utf-8'],
    ['shared/timezone.js', 'text/javascript; charset=utf-8'],
    ['style.css', 'text/css; charset=utf-8'],
    ['favicon.svg', 'image/svg+xml'],
  ]) {
    const response = await fetch(`${orbit.url}/assets/${build}/${file}`);
    assert.equal(response.status, 200, file);
    assert.match(response.headers.get('cache-control'), /max-age=31536000/, file);
    assert.match(response.headers.get('cache-control'), /immutable/, file);
    assert.equal(response.headers.get('content-type'), type, file);
    assert.equal(await response.text(), fs.readFileSync(path.join(publicDirectory, file), 'utf8'));
  }
  const probe = await fetch(`${orbit.url}/assets/${build}/modules/main.js`, { method: 'HEAD' });
  assert.equal(probe.status, 200);
  assert.equal(await probe.text(), '');
  // Another build's files (here, one Uptime Goblin never had) and missing files: 404, never cached,
  // also for /boot.js's HEAD probe, so the page reloads instead of keeping the miss.
  for (const [method, url] of [
    ['GET', '/assets/000000000000/modules/main.js'],
    ['HEAD', '/assets/000000000000/modules/main.js'],
    ['GET', `/assets/${build}/modules/missing.js`],
    ['GET', `/assets/${build}/index.html`],
  ]) {
    const response = await fetch(orbit.url + url, { method });
    assert.equal(response.status, 404, `${method} ${url}`);
    assert.equal(response.headers.get('cache-control'), 'no-store', `${method} ${url}`);
  }

  // A page from before 1.5 still gets its /app.js, now the shim that hands it to /boot.js,
  // and its stylesheet; neither is kept by the browser.
  for (const asset of ['app.js', 'style.css']) {
    const other = await fetch(`${orbit.url}/${asset}?v=000000000000`);
    assert.equal(other.status, 200, asset);
    assert.equal(other.headers.get('cache-control'), 'no-store', asset);
    assert.equal(other.headers.get('x-goblin-build'), build, asset);
    assert.equal(await other.text(), fs.readFileSync(path.join(publicDirectory, asset), 'utf8'));
  }
  const legacy = await fetch(orbit.url + '/app.js');
  assert.equal(legacy.status, 200);
  assert.match(await legacy.text(), /^import '\.\/boot\.js';$/m);
  for (const missing of ['/missing.js', '/shared/', '/../server.mjs', '/%2e%2e/server.mjs']) {
    const response = await fetch(orbit.url + missing);
    assert.equal(response.status, 404, missing);
    assert.equal(response.headers.get('x-goblin-build'), build, missing);
  }
  const head = await fetch(orbit.url + '/', { method: 'HEAD' });
  assert.equal(head.status, 200);
  assert.equal(await head.text(), '');

  // Any change to the web app is a new build.
  fs.appendFileSync(path.join(publicDirectory, 'favicon.svg'), '\n');
  assert.notEqual(buildInfo(root, publicDirectory).build, build);
});
