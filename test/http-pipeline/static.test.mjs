import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createApp } from '../../server.mjs';
import {
  renderIndex,
  findReleasesDirectory,
  immutableCache,
  readRelease,
} from '../../lib/http/static.mjs';

const root = path.resolve(import.meta.dirname, '../..');
const password = 'fixture-static-password';
const signedIn = { Authorization: 'Basic ' + Buffer.from('admin:' + password).toString('base64') };

function temporary(t, prefix = 'orbit-static-') {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}
function write(file, text) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
}

// The 1.5 layout lane O builds (contract C-O): index.html loads only /boot.js and the
// stylesheet; boot.js imports /assets/<build>/modules/main.js; /app.js stays as a shim.
function bootLayout(t) {
  const publicDirectory = temporary(t, 'orbit-public-');
  fs.cpSync(path.join(root, 'public'), publicDirectory, { recursive: true });
  write(
    path.join(publicDirectory, 'index.html'),
    [
      '<!doctype html>',
      '<html lang="en">',
      '  <head>',
      '    <meta charset="UTF-8" />',
      '    <link rel="stylesheet" href="/style.css" />',
      '    <script type="module" src="/boot.js"></script>',
      '  </head>',
      '  <body></body>',
      '</html>',
      '',
    ].join('\n')
  );
  write(path.join(publicDirectory, 'boot.js'), '// boot\n');
  write(path.join(publicDirectory, 'modules/main.js'), 'export const main = 1;\n');
  write(path.join(publicDirectory, 'app.js'), "import '/boot.js';\n");
  return publicDirectory;
}

async function start(t, options) {
  const app = await createApp({
    directory: temporary(t),
    port: 0,
    password,
    allowedHosts: '',
    webhook: '',
    trustProxy: '',
    startScheduler: false,
    ...options,
  });
  const { port } = await app.listen();
  t.after(() => app.close());
  const get = (route, { headers = signedIn, method = 'GET' } = {}) =>
    fetch(`http://127.0.0.1:${port}${route}`, { headers, method });
  return { app, get };
}

test('a boot.js page gets a build-stamped stylesheet; rendering is idempotent', () => {
  const template = [
    '<head>',
    '<meta charset="UTF-8" />',
    '<link rel="stylesheet" href="/style.css" />',
    '<link rel="modulepreload" href="/assets/BUILD/modules/main.js" />',
    '<script type="module" src="/boot.js"></script>',
    '<link rel="icon" href="/favicon.svg" />',
    '</head>',
  ].join('\n');
  const html = renderIndex(template, 'a1b2c3d4e5f6');
  assert.ok(html.includes('<meta name="orbit-build" content="a1b2c3d4e5f6" />'));
  assert.ok(html.includes('href="/assets/a1b2c3d4e5f6/style.css"'));
  assert.ok(html.includes('href="/assets/a1b2c3d4e5f6/modules/main.js"'));
  assert.ok(html.includes('src="/boot.js"'), '/boot.js is never stamped');
  assert.ok(html.includes('href="/favicon.svg"'));
  assert.doesNotMatch(html, /\?v=/);
  assert.equal(renderIndex(html, 'a1b2c3d4e5f6'), html);
  // Rendered again for another build, nothing of the first remains.
  assert.doesNotMatch(renderIndex(html, '0f0f0f0f0f0f'), /a1b2c3d4e5f6/);
  // A 1.4.3 page (no boot.js) is rendered exactly as before.
  const legacy = renderIndex(
    '<head><meta charset="UTF-8" /><link rel="stylesheet" href="/style.css" /><script type="module" src="/app.js"></script></head>',
    'a1b2c3d4e5f6'
  );
  assert.ok(legacy.includes('href="/style.css?v=a1b2c3d4e5f6"'));
  assert.ok(legacy.includes('src="/app.js?v=a1b2c3d4e5f6"'));
  assert.doesNotMatch(legacy, /\/assets\//);
});

test('the shipped shell shows the new brand without replacing compatibility identifiers', async t => {
  const { get } = await start(t);
  const index = await get('/');
  assert.equal(index.status, 200);
  const html = await index.text();
  assert.match(html, /<title>Uptime Goblin · Homelab<\/title>/);
  assert.match(html, /id="signin-title"[^>]*>Sign in to Uptime Goblin<\/h1>/);
  assert.match(html, /class="brand"[^>]*>[\s\S]*?Uptime Goblin/);
  assert.match(html, /href="\/favicon\.svg"/);
  // The penguin mark, not a text glyph, beside the name and on the sign-in card.
  assert.match(html, /<img class="brandmark" src="\/favicon\.svg" alt=""/);
  assert.match(html, /<img class="signin-mark" src="\/favicon\.svg" alt=""/);
  assert.doesNotMatch(html, /◉/);
  assert.match(html, /name="orbit-build"/);
  assert.match(html, /goblin-admin display code/);
  const boot = await get('/boot.js');
  assert.equal(boot.status, 200);
  assert.match(await boot.text(), /Uptime Goblin is not answering/);
});

test('/boot.js, /assets/<build>/ and the legacy /app.js are served as contract C-O says', async t => {
  const publicDirectory = bootLayout(t);
  const { app, get } = await start(t, { publicDirectory });
  const { build } = app;
  const index = await get('/');
  assert.equal(index.headers.get('cache-control'), 'no-store');
  const html = await index.text();
  assert.ok(html.includes(`href="/assets/${build}/style.css"`));
  assert.ok(html.includes('<script type="module" src="/boot.js"></script>'));
  assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/, 'no inline script (CSP)');

  const boot = await get('/boot.js');
  assert.equal(boot.status, 200);
  assert.equal(boot.headers.get('cache-control'), 'no-cache');
  assert.equal(boot.headers.get('content-type'), 'text/javascript; charset=utf-8');

  for (const [file, type] of [
    ['style.css', 'text/css; charset=utf-8'],
    ['modules/main.js', 'text/javascript; charset=utf-8'],
    ['boot.js', 'text/javascript; charset=utf-8'],
  ]) {
    const asset = await get(`/assets/${build}/${file}`);
    assert.equal(asset.status, 200, file);
    assert.equal(asset.headers.get('cache-control'), immutableCache, file);
    assert.equal(asset.headers.get('content-type'), type, file);
    assert.equal(asset.headers.get('x-goblin-build'), build, file);
    assert.equal(await asset.text(), fs.readFileSync(path.join(publicDirectory, file), 'utf8'));
  }
  const head = await get(`/assets/${build}/style.css`, { method: 'HEAD' });
  assert.equal(head.status, 200);
  assert.equal(
    Number(head.headers.get('content-length')),
    fs.statSync(path.join(publicDirectory, 'style.css')).size
  );
  assert.equal(await head.text(), '');
  // Misses are never cached, so the page's boot.js can reload once and recover.
  for (const miss of [
    `/assets/${build}/missing.js`,
    `/assets/${build}/index.html`,
    `/assets/${build}/`,
    '/assets/000000000000/style.css',
    '/assets/not-a-build/style.css',
  ]) {
    const answer = await get(miss);
    assert.equal(answer.status, 404, miss);
    assert.equal(answer.headers.get('cache-control'), 'no-store', miss);
  }
  // A page from before 1.5 still loads /app.js (now a shim that loads /boot.js).
  const shim = await get(`/app.js?v=${build}`);
  assert.equal(shim.status, 200);
  assert.equal(shim.headers.get('cache-control'), 'no-cache');
  const old = await get('/app.js?v=0123456789ab');
  assert.equal(old.status, 200);
  assert.equal(old.headers.get('cache-control'), 'no-store');
  // The loader and the assets need no sign-in (D9, was 401 in 1.4.3): the sign-in view is part
  // of the web app. They name the build, as the page does, but never the version.
  for (const route of ['/', '/index.html', '/boot.js', `/assets/${build}/style.css`, '/app.js']) {
    const open = await get(route, { headers: {} });
    assert.equal(open.status, 200, route);
    assert.equal(open.headers.get('x-goblin-build'), build, route);
    assert.equal(open.headers.get('x-goblin-version'), null, route);
    assert.equal(open.headers.get('www-authenticate'), null, route);
  }
  // A credential sent anyway is not checked on a public route: a wrong one changes nothing.
  const wrong = { Authorization: 'Basic ' + Buffer.from('admin:wrong').toString('base64') };
  assert.equal((await get('/boot.js', { headers: wrong })).status, 200);
  // Writing to an asset is a 405 from the table.
  const post = await fetch(
    `http://127.0.0.1:${new URL(index.url).port}/assets/${build}/style.css`,
    {
      method: 'POST',
      headers: { ...signedIn, 'X-Goblin-Request': '1', 'Content-Type': 'application/json' },
      body: '{}',
    }
  );
  assert.equal(post.status, 405);
  assert.equal(post.headers.get('allow'), 'GET, HEAD');
});

// A file at its own path (the stable /boot.js, the /app.js shim and stylesheet a page from
// before 1.5 names with ?v=, the favicon, /shared/timezone.js) is revalidated on every load
// with the build as its ETag: a browser holding this build's copy gets an empty 304, and one
// holding an earlier build's copy gets the new bytes, so an upgrade reaches every tab. 1.4.3
// checked this for /app.js in test/update.test.mjs; these are the same checks on 1.5's routes.
test('files at their own paths carry the build as ETag; another build’s answer carries none', async t => {
  const publicDirectory = bootLayout(t);
  const { app, get } = await start(t, { publicDirectory });
  const { build } = app;
  const tag = `"${build}"`,
    js = 'text/javascript; charset=utf-8',
    css = 'text/css; charset=utf-8',
    svg = 'image/svg+xml';
  const bytes = file => fs.readFileSync(path.join(publicDirectory, file), 'utf8');
  const offering = etag => ({ ...signedIn, 'If-None-Match': etag });
  for (const [route, file, type] of [
    ['/boot.js', 'boot.js', js],
    ['/app.js', 'app.js', js],
    [`/app.js?v=${build}`, 'app.js', js],
    ['/style.css', 'style.css', css],
    [`/style.css?v=${build}`, 'style.css', css],
    ['/favicon.svg', 'favicon.svg', svg],
    // 1.4.3's app.js imports ./shared/timezone.js: a module script needs a JavaScript type.
    ['/shared/timezone.js', 'shared/timezone.js', js],
  ]) {
    const current = await get(route);
    assert.equal(current.status, 200, route);
    assert.equal(current.headers.get('etag'), tag, route);
    assert.equal(current.headers.get('cache-control'), 'no-cache', route);
    assert.equal(current.headers.get('content-type'), type, route);
    assert.equal(await current.text(), bytes(file), route);
    for (const method of ['GET', 'HEAD']) {
      const unchanged = await get(route, { method, headers: offering(tag) });
      assert.equal(unchanged.status, 304, `${method} ${route}`);
      assert.equal(unchanged.headers.get('etag'), tag, `${method} ${route}`);
      assert.equal(unchanged.headers.get('cache-control'), 'no-cache', `${method} ${route}`);
      assert.equal(await unchanged.text(), '', `${method} ${route}`);
    }
    // A copy kept from another build is replaced, never confirmed.
    const replaced = await get(route, { headers: offering('"000000000000"') });
    assert.equal(replaced.status, 200, route);
    assert.equal(replaced.headers.get('etag'), tag, route);
    assert.equal(await replaced.text(), bytes(file), route);
  }
  // A page from another build still gets its script and stylesheet (never a blank page), but
  // without this build's ETag and never cached, even when it offers this build's tag: those
  // bytes are not what that page named, and the page reloads itself onto this build.
  for (const [route, file] of [
    ['/app.js?v=000000000000', 'app.js'],
    ['/style.css?v=000000000000', 'style.css'],
  ])
    for (const headers of [signedIn, offering(tag)]) {
      const other = await get(route, { headers });
      assert.equal(other.status, 200, route);
      assert.equal(other.headers.get('etag'), null, route);
      assert.equal(other.headers.get('cache-control'), 'no-store', route);
      assert.equal(other.headers.get('x-goblin-build'), build, route);
      assert.equal(await other.text(), bytes(file), route);
    }
  // A build-stamped URL names its build itself, so it is cached for a year with no validator
  // to revalidate. The page's modules import ../../shared/timezone.js, which lands here.
  for (const [file, type] of [
    ['shared/timezone.js', js],
    ['modules/main.js', js],
    ['style.css', css],
    ['favicon.svg', svg],
  ]) {
    const asset = await get(`/assets/${build}/${file}`);
    assert.equal(asset.status, 200, file);
    assert.equal(asset.headers.get('content-type'), type, file);
    assert.equal(asset.headers.get('cache-control'), immutableCache, file);
    assert.equal(asset.headers.get('etag'), null, file);
    assert.equal(await asset.text(), bytes(file), file);
  }
});

test('files of an earlier release kept beside this one are served while they exist', async t => {
  const releases = path.join(temporary(t, 'orbit-releases-'), 'releases');
  const previous = path.join(releases, '1.4.9-aaaaaaaaaaaa');
  write(path.join(previous, 'public/style.css'), 'body { color: old }\n');
  write(path.join(previous, 'public/modules/main.js'), 'export const old = 1;\n');
  write(path.join(previous, 'public/.hidden.js'), 'secret\n');
  write(path.join(releases, 'outside.txt'), 'not public\n');
  fs.symlinkSync(path.join(releases, 'outside.txt'), path.join(previous, 'public/link.txt'));
  write(path.join(releases, '1.4.2-legacy/public/style.css'), 'legacy\n');
  const { get } = await start(t, { publicDirectory: bootLayout(t), releasesDirectory: releases });
  const style = await get('/assets/aaaaaaaaaaaa/style.css');
  assert.equal(style.status, 200);
  assert.equal(style.headers.get('cache-control'), immutableCache);
  assert.equal(style.headers.get('content-type'), 'text/css; charset=utf-8');
  // Only this build's bytes may carry this build's ETag.
  assert.equal(style.headers.get('etag'), null);
  assert.equal(await style.text(), 'body { color: old }\n');
  const module = await get('/assets/aaaaaaaaaaaa/modules/main.js');
  assert.equal(await module.text(), 'export const old = 1;\n');
  for (const refused of [
    '/assets/aaaaaaaaaaaa/.hidden.js',
    '/assets/aaaaaaaaaaaa/link.txt',
    '/assets/aaaaaaaaaaaa/..%2foutside.txt',
    '/assets/aaaaaaaaaaaa/modules',
    '/assets/aaaaaaaaaaaa/index.html',
    '/assets/legacy/style.css',
    '/assets/bbbbbbbbbbbb/style.css',
  ]) {
    const answer = await get(refused);
    assert.equal(answer.status, 404, refused);
    assert.equal(answer.headers.get('cache-control'), 'no-store', refused);
  }
  // Once the earlier release is removed, its URLs are misses that are not cached.
  fs.rmSync(previous, { recursive: true });
  const gone = await get('/assets/aaaaaaaaaaaa/style.css');
  assert.equal(gone.status, 404);
  assert.equal(gone.headers.get('cache-control'), 'no-store');
});

test('only a staged install (…/releases/<version>-<build>/) has earlier releases', t => {
  const base = temporary(t, 'orbit-layout-');
  const current = path.join(base, 'releases', '1.5.0-cccccccccccc');
  fs.mkdirSync(current, { recursive: true });
  fs.symlinkSync(current, path.join(base, 'current'));
  assert.equal(
    findReleasesDirectory(path.join(base, 'current')),
    fs.realpathSync(path.join(base, 'releases'))
  );
  assert.equal(findReleasesDirectory(current), fs.realpathSync(path.join(base, 'releases')));
  assert.equal(findReleasesDirectory(base), null);
  assert.equal(findReleasesDirectory(path.join(base, 'missing')), null);
  assert.equal(findReleasesDirectory(root), null, 'a checkout keeps no releases');
});

test('the build covers the version, server.mjs, lib/**/*.mjs and every public file', t => {
  const { version, build, publicFiles } = readRelease(root);
  assert.match(build, /^[0-9a-f]{12}$/);
  assert.equal(version, JSON.parse(fs.readFileSync(path.join(root, 'package.json'))).version);
  assert.ok(publicFiles.has('/index.html') && publicFiles.has('/app.js'));
  // lib/ is hashed but never served: only public/ files are web app files.
  const tree = temporary(t, 'orbit-release-');
  write(path.join(tree, 'package.json'), JSON.stringify({ version: '1.5.0' }));
  write(path.join(tree, 'server.mjs'), 'server');
  write(path.join(tree, 'lib/http/static.mjs'), 'static');
  write(path.join(tree, 'public/app.js'), 'app');
  write(path.join(tree, 'public/shared/timezone.js'), 'tz');
  write(path.join(tree, 'public/.hidden.js'), 'hidden');
  const release = readRelease(tree);
  assert.deepEqual([...release.publicFiles.keys()].sort(), ['/app.js', '/shared/timezone.js']);
  // A server module in a lib/ subdirectory is part of the build (1.5 keeps code there).
  write(path.join(tree, 'lib/http/static.mjs'), 'static, fixed');
  assert.notEqual(readRelease(tree).build, release.build);
});
