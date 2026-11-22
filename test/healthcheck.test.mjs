import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createApp } from '../server.mjs';
import { isReady, probe, computeBuild, readStatus, verifyInstance } from '../lib/healthcheck.mjs';
import { readRunStatusFile, UnusableFileError } from '../lib/saved-data.mjs';
import { readRelease } from '../lib/http/static.mjs';
import { buildAsIn143 } from './helpers/build-reference.mjs';
import { adminFetch, adminPassword } from './helpers/admin.mjs';
import { platformTest } from './helpers/platform.mjs';
import { releaseFiles, skipWithoutFixtures, versions } from './upgrade/fixtures.mjs';

const repository = fileURLToPath(new URL('..', import.meta.url));
const healthcheck = fileURLToPath(new URL('../lib/healthcheck.mjs', import.meta.url));

async function fakeServer(t, handler) {
  const server = http.createServer(handler);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(
    () =>
      new Promise(resolve => {
        server.closeAllConnections();
        server.close(resolve);
      })
  );
  return server.address().port;
}

function temporary(t, prefix) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function writeStatus(dataDir, status) {
  fs.mkdirSync(path.join(dataDir, 'run'), { recursive: true });
  fs.writeFileSync(path.join(dataDir, 'run', 'status.json'), JSON.stringify(status));
}

test('installation and container readiness need no sign-in and survive password rotation', async t => {
  const directory = temporary(t, 'orbit-readiness-');
  const password = 'fixture-bootstrap-password',
    next = 'fixture-replacement-password';
  const app = await createApp({
    directory,
    host: '127.0.0.1',
    port: 0,
    password,
    allowedHosts: '',
    webhook: '',
    startScheduler: false,
  });
  const { port } = await app.listen();
  t.after(() => app.close());
  assert.equal(await isReady({ host: '127.0.0.1', port }), true);
  const authorization = 'Basic ' + Buffer.from('admin:' + password).toString('base64');
  const changed = await fetch(`http://127.0.0.1:${port}/api/auth/password`, {
    method: 'POST',
    headers: {
      Authorization: authorization,
      'Content-Type': 'application/json',
      'X-Goblin-Request': '1',
    },
    body: JSON.stringify({ currentPassword: password, password: next, confirmPassword: next }),
  });
  assert.equal(changed.status, 200);
  // /health is public: stale credentials neither help nor hurt, and it reveals no version.
  for (const headers of [{}, { Authorization: authorization }]) {
    const response = await fetch(`http://127.0.0.1:${port}/health`, { headers });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { status: 'ok' });
  }
  assert.equal(await isReady({ host: '127.0.0.1', port }), true);
});

test('/health?instance matches only the running process nonce and never echoes it', async t => {
  const directory = temporary(t, 'orbit-instance-');
  const app = await createApp({
    directory,
    host: '127.0.0.1',
    port: 0,
    password: adminPassword,
    allowedHosts: '',
    webhook: '',
    startScheduler: false,
  });
  const { port } = await app.listen();
  t.after(() => app.close());
  const status = readStatus(directory);
  assert.ok(status, 'the server writes run/status.json once it listens');
  assert.equal(status.pid, process.pid);
  assert.equal(await isReady({ host: '127.0.0.1', port, instance: status.nonce }), true);
  const wrong = status.nonce.replace(/^./, c => (c === '0' ? '1' : '0'));
  assert.equal(await isReady({ host: '127.0.0.1', port, instance: wrong }), false);
  for (const nonce of [status.nonce, wrong]) {
    const response = await fetch(`http://127.0.0.1:${port}/health?instance=${nonce}`, {
      headers: { Host: `localhost:${port}` },
    });
    const text = await response.text();
    assert.equal(response.status, 200);
    assert.ok(!text.includes(nonce) && !text.includes(status.nonce), 'the nonce is never echoed');
    assert.deepEqual(JSON.parse(text), {
      status: 'ok',
      instance: nonce === status.nonce ? 'match' : 'mismatch',
    });
  }
});

test('the build the installer expects is the one the server reports', async t => {
  const directory = temporary(t, 'orbit-build-');
  const app = await createApp({
    directory,
    host: '127.0.0.1',
    port: 0,
    password: adminPassword,
    allowedHosts: '',
    webhook: '',
    startScheduler: false,
  });
  const { port } = await app.listen();
  t.after(() => app.close());
  // A signed-in request: the release is named.
  const response = await adminFetch(`http://127.0.0.1:${port}/api/version`);
  assert.equal(response.headers.get('x-goblin-build'), computeBuild(repository));
  assert.equal((await response.json()).build, computeBuild(repository));
  assert.equal(readStatus(directory)?.build, computeBuild(repository));
});

test('the 1.4.2 sign-in challenge no longer counts as ready', async t => {
  const port = await fakeServer(t, (_req, res) => {
    res.writeHead(401, {
      'Content-Type': 'application/json',
      'WWW-Authenticate': 'Basic realm="Orbit", charset="UTF-8"',
    });
    res.end(JSON.stringify({ error: 'Sign in to Uptime Goblin' }));
  });
  assert.equal(await isReady({ host: '127.0.0.1', port }), false);
  assert.match((await probe({ host: '127.0.0.1', port })).reason, /401/);
});

test('readiness rejects unrelated errors, redirects and stalled responses', async t => {
  let mode = 'unrelated';
  const port = await fakeServer(t, (_req, res) => {
    if (mode === 'stall') return;
    if (mode === 'redirect') {
      res.writeHead(302, { Location: '/health' });
      res.end();
      return;
    }
    if (mode === 'unrelated') {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Sign in to Uptime Goblin' }));
      return;
    }
    if (mode === 'wrong-body') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ status: 'starting' }));
      return;
    }
    res.writeHead(503, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok' }));
  });
  const options = { host: '127.0.0.1', port, timeoutMs: 100 };
  for (const value of ['unrelated', 'redirect', 'wrong-body', 'failure', 'stall']) {
    mode = value;
    assert.equal(await isReady(options), false, value);
  }
});

test('readiness has a total deadline even while a response keeps sending bytes', async t => {
  const port = await fakeServer(t, (_req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.write(' ');
    const trickle = setInterval(() => res.write(' '), 20);
    const end = setTimeout(() => res.end('{"status":"ok"}'), 500);
    res.on('close', () => {
      clearInterval(trickle);
      clearTimeout(end);
    });
  });
  const result = await probe({ host: '127.0.0.1', port, timeoutMs: 100 });
  assert.equal(result.ready, false, 'bytes arriving regularly must not renew the deadline');
  assert.match(result.reason, /did not answer in time/);
});

test('the readiness probe sends an allowlisted Host header whatever address it connects to', async t => {
  let host;
  const port = await fakeServer(t, (req, res) => {
    host = req.headers.host;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end('{"status":"ok"}');
  });
  assert.equal(await isReady({ host: '127.0.0.1', port }), true);
  assert.equal(await isReady({ host: '0.0.0.0', port }), true);
  // Uptime Goblin always accepts localhost:<port>, unlike the configured listen address.
  assert.equal(host, `localhost:${port}`);
});

test('an instance check needs an explicit match for the nonce it sent', async t => {
  let answer = 'match',
    requested;
  const port = await fakeServer(t, (req, res) => {
    requested = req.url;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(
      JSON.stringify(answer === undefined ? { status: 'ok' } : { status: 'ok', instance: answer })
    );
  });
  const options = { host: '127.0.0.1', port, instance: '0123456789abcdef0123456789abcdef' };
  assert.equal(await isReady(options), true);
  assert.equal(requested, '/health?instance=0123456789abcdef0123456789abcdef');
  answer = 'mismatch';
  assert.deepEqual(await probe(options), {
    ready: false,
    reason: 'a different Uptime Goblin process is answering on this port',
  });
  answer = undefined;
  assert.equal(await isReady(options), false, 'an older /health that ignores ?instance');
  assert.equal(await isReady({ host: '127.0.0.1', port, instance: 'a&b=c' }), false);
  assert.equal(requested, '/health?instance=a%26b%3Dc');
});

async function verificationFixture(t) {
  const nonce = 'fedcba9876543210fedcba9876543210';
  let answer = 'match';
  const port = await fakeServer(t, (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(
      JSON.stringify({
        status: 'ok',
        instance: url.searchParams.get('instance') === nonce ? answer : 'mismatch',
      })
    );
  });
  const dataDir = temporary(t, 'orbit-verify-');
  const record = (overrides = {}) =>
    writeStatus(dataDir, {
      version: '9.8.7',
      build: 'abcdefabcdef',
      pid: 4242,
      nonce,
      startedAt: new Date().toISOString(),
      listen: { host: '127.0.0.1', port },
      observed: { forwardedProto: null },
      ...overrides,
    });
  const base = {
    host: '127.0.0.1',
    port,
    dataDir,
    expectVersion: '9.8.7',
    expectBuild: 'abcdefabcdef',
    unit: 'uptime-goblin.service',
    intervalMs: 20,
    timeoutMs: 400,
  };
  return { nonce, dataDir, record, base, setAnswer: value => (answer = value) };
}

test('verification passes only for the service process running the expected release', async t => {
  const { nonce, record, base } = await verificationFixture(t);
  let mainPid = 4242;
  const state = async () => ({ mainPid, activeState: 'active', result: 'success' });
  record();
  const passed = await verifyInstance({ ...base, state });
  assert.equal(passed.ok, true);
  assert.equal(passed.status.pid, 4242);

  // A status file left by an earlier process is waited out, never trusted.
  mainPid = 5151;
  const stale = await verifyInstance({ ...base, state });
  assert.equal(stale.ok, false);
  assert.match(stale.reason, /belongs to process 4242, not the service's process 5151/);
  setTimeout(() => record({ pid: 5151 }), 100);
  const waited = await verifyInstance({ ...base, state, timeoutMs: 5000 });
  assert.equal(waited.ok, true);

  for (const result of [passed, stale, waited])
    assert.ok(!JSON.stringify(result.reason ?? '').includes(nonce));
});

test('verification fails at once for a wrong version or build, or a failed unit', async t => {
  const { record, base } = await verificationFixture(t);
  const state = async () => ({ mainPid: 4242, activeState: 'active', result: 'success' });
  const quick = async options => {
    const started = Date.now();
    const result = await verifyInstance({ ...base, timeoutMs: 10000, ...options });
    assert.ok(Date.now() - started < 2000, 'no waiting for a definite answer');
    return result;
  };
  record({ version: '9.8.6' });
  assert.deepEqual(await quick({ state }), {
    ok: false,
    reason: 'the service runs Uptime Goblin 9.8.6, expected 9.8.7',
  });
  record({ build: '000000000000' });
  assert.deepEqual(await quick({ state }), {
    ok: false,
    reason: 'the service runs build 000000000000, expected abcdefabcdef',
  });
  record();
  const failed = await quick({
    state: async () => ({ mainPid: 0, activeState: 'failed', result: 'exit-code' }),
  });
  assert.deepEqual(failed, {
    ok: false,
    reason: 'uptime-goblin.service failed (exit-code) and systemd will not restart it',
  });
});

test('verification times out without a status file, a process or an instance match', async t => {
  const { dataDir, record, base, setAnswer } = await verificationFixture(t);
  const state = async () => ({ mainPid: 4242, activeState: 'active', result: 'success' });
  let result = await verifyInstance({ ...base, state });
  assert.deepEqual(result, {
    ok: false,
    reason: 'Uptime Goblin has not written run/status.json yet',
  });
  fs.mkdirSync(path.join(dataDir, 'run'));
  fs.writeFileSync(path.join(dataDir, 'run', 'status.json'), '{"version":');
  result = await verifyInstance({ ...base, state });
  assert.equal(result.reason, 'Uptime Goblin has not written run/status.json yet');
  record();
  result = await verifyInstance({
    ...base,
    state: async () => ({ mainPid: 0, activeState: 'activating', result: 'exit-code' }),
  });
  assert.deepEqual(result, { ok: false, reason: 'uptime-goblin.service has no running process' });
  setAnswer('mismatch');
  result = await verifyInstance({ ...base, state });
  assert.deepEqual(result, {
    ok: false,
    reason: 'a different Uptime Goblin process is answering on this port',
  });
  // A plain --pid check works the same without systemd.
  setAnswer('match');
  assert.equal((await verifyInstance({ ...base, unit: undefined, pid: 4242 })).ok, true);
  assert.equal((await verifyInstance({ ...base, unit: undefined, pid: 1 })).ok, false);
});

function writer(root) {
  return (file, text) => {
    fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    fs.writeFileSync(path.join(root, file), text);
  };
}

// The installer (computeBuild) and the server (readRelease) must name every tree alike.
function buildOf(root) {
  const build = computeBuild(root);
  assert.equal(readRelease(root).build, build, 'readRelease() agrees with computeBuild()');
  return build;
}

test('the build covers the version, server.mjs, lib/**/*.mjs and public/ only', t => {
  const root = temporary(t, 'orbit-build-tree-');
  const write = writer(root);
  write('package.json', JSON.stringify({ version: '1.5.0' }));
  write('server.mjs', 'server');
  write('lib/a.mjs', 'a');
  // 1.5 keeps server code in lib/ subdirectories: lib/http/, lib/db/dialect/ and so on.
  write('lib/http/router.mjs', 'router');
  write('lib/db/dialect/sqlite.mjs', 'dialect');
  write('public/app.js', 'app');
  write('public/shared/timezone.js', 'tz');
  write('docs/guide.md', 'docs');
  write('README.md', 'readme');
  write('test/http.test.mjs', 'test');
  const first = buildOf(root);
  assert.match(first, /^[0-9a-f]{12}$/);
  assert.equal(buildOf(root), first, 'deterministic');
  for (const file of [
    'docs/guide.md',
    'docs/api/routes.md',
    'README.md',
    'test/http.test.mjs',
    'test/http-pipeline/static.test.mjs',
    'lib/notes.txt',
    'lib/http/notes.txt',
    'lib/.cache/http.mjs',
    'lib/db/.draft.mjs',
    'deploy/manifest.txt',
  ]) {
    write(file, 'changed');
    assert.equal(buildOf(root), first, `${file} does not change the build`);
  }
  const seen = new Set([first]);
  const changes = (label, change) => {
    change();
    const build = buildOf(root);
    assert.ok(!seen.has(build), `${label} changes the build`);
    seen.add(build);
  };
  for (const [file, text] of [
    ['public/shared/timezone.js', 'tz2'],
    ['public/new.css', 'css'],
    ['lib/a.mjs', 'a2'],
    ['lib/b.mjs', 'b'],
    ['lib/http/router.mjs', 'router2'],
    ['lib/http/routes/settings.mjs', 'settings'],
    ['lib/db/dialect/sqlite.mjs', 'dialect2'],
    ['lib/db/dialect/postgres.mjs', 'postgres'],
    ['server.mjs', 'server2'],
    ['package.json', JSON.stringify({ version: '1.5.1' })],
  ])
    changes(file, () => write(file, text));
  // The path is hashed too: moving a module to another lib/ directory is a new build.
  changes('moving lib/db/dialect/postgres.mjs', () =>
    fs.renameSync(
      path.join(root, 'lib/db/dialect/postgres.mjs'),
      path.join(root, 'lib/db/postgres.mjs')
    )
  );
  // So is removing a nested module, as a revert does.
  changes('removing lib/http/routes/settings.mjs', () =>
    fs.rmSync(path.join(root, 'lib/http/routes/settings.mjs'))
  );
});

test('a tree without lib/ subdirectories (1.4.x) keeps the build 1.4.3 gave it', t => {
  const root = temporary(t, 'orbit-build-143-');
  const write = writer(root);
  write('package.json', JSON.stringify({ version: '1.4.3' }));
  write('server.mjs', 'server');
  write('lib/healthcheck.mjs', 'healthcheck');
  write('lib/store.mjs', 'store');
  write('lib/notes.txt', 'not a module');
  write('lib/.editor.mjs', 'dot file');
  write('public/index.html', 'page');
  write('public/app.js', 'app');
  write('public/shared/timezone.js', 'tz');
  write('public/.DS_Store', 'finder');
  write('docs/guide.md', 'docs');
  const expected = buildAsIn143(root);
  assert.equal(buildOf(root), expected);
  // A lib/ subdirectory without modules hashes nothing, as it did in 1.4.3.
  write('lib/fixtures/sample.json', '{}');
  assert.equal(buildOf(root), expected);
  // The one difference: a module in a lib/ subdirectory now counts, which 1.4.3 ignored.
  write('lib/http/router.mjs', 'router');
  assert.equal(buildAsIn143(root), expected);
  assert.notEqual(buildOf(root), expected);
});

test('every published release up to 1.4.2 keeps its build (release fixtures)', t => {
  if (skipWithoutFixtures(t)) return;
  for (const version of versions) {
    const root = temporary(t, `orbit-build-${version}-`);
    const write = writer(root);
    for (const [file, data] of releaseFiles(version).files) write(file, data);
    assert.equal(buildOf(root), buildAsIn143(root), version);
  }
});

test('the command line prints the build, rejects unknown options and explains failures', t => {
  const printed = spawnSync(process.execPath, [healthcheck, '--print-build', repository], {
    encoding: 'utf8',
  });
  assert.equal(printed.status, 0, printed.stderr);
  assert.equal(printed.stdout.trim(), computeBuild(repository));
  const unknown = spawnSync(process.execPath, [healthcheck, '--version-check'], {
    encoding: 'utf8',
  });
  assert.equal(unknown.status, 2);
  assert.match(unknown.stderr, /Unknown or incomplete option: --version-check/);
  const incomplete = spawnSync(process.execPath, [healthcheck, '--expect-version', '1.4.3'], {
    encoding: 'utf8',
  });
  assert.equal(incomplete.status, 2);
  assert.match(incomplete.stderr, /need --data-dir/);
  const dataDir = temporary(t, 'orbit-cli-');
  const missing = spawnSync(
    process.execPath,
    [healthcheck, '--wait', '--timeout', '1', '--data-dir', dataDir, '--pid', '1'],
    { encoding: 'utf8', env: { ...process.env, HOST: '127.0.0.1', PORT: '9' } }
  );
  assert.equal(missing.status, 1);
  assert.match(
    missing.stderr,
    /Uptime Goblin is not verified: Uptime Goblin has not written run\/status.json yet/
  );
});

test('readStatus refuses a symlink to an otherwise valid status record', t => {
  const dataDir = temporary(t, 'orbit-status-symlink-');
  const status = {
    version: '1.4.3',
    build: 'abcdefabcdef',
    pid: 4242,
    nonce: 'fedcba9876543210fedcba9876543210',
  };
  writeStatus(dataDir, status);
  assert.deepEqual(readStatus(dataDir), status, 'the target is a valid status record');
  const file = path.join(dataDir, 'run', 'status.json');
  const target = path.join(dataDir, 'target.json');
  fs.renameSync(file, target);
  fs.symlinkSync(target, file);
  assert.equal(readStatus(dataDir), null, 'a final symlink must never supply readiness identity');
  // Nor a run/ that is a link: the uptime-goblin account owns run/, and its status.json could then be
  // any file named so in any directory the reader (root, in the installer) can read.
  const elsewhere = path.join(dataDir, 'elsewhere');
  fs.mkdirSync(elsewhere);
  fs.writeFileSync(path.join(elsewhere, 'status.json'), JSON.stringify(status));
  fs.rmSync(path.join(dataDir, 'run'), { recursive: true });
  fs.symlinkSync(elsewhere, path.join(dataDir, 'run'));
  assert.equal(readStatus(dataDir), null, 'a linked run/ must never supply readiness identity');
});

test('readRunStatusFile opens run/ itself without following a link, and the file through it', t => {
  const dataDir = temporary(t, 'orbit-status-run-');
  const elsewhere = path.join(dataDir, 'elsewhere');
  fs.mkdirSync(elsewhere);
  fs.writeFileSync(path.join(elsewhere, 'status.json'), '{"synthetic":true}');
  // No run/ yet: no record.
  assert.equal(readRunStatusFile(dataDir, 1024), undefined);
  // A linked run/ is refused as a link when it is opened, before anything in it is.
  fs.symlinkSync(elsewhere, path.join(dataDir, 'run'));
  assert.throws(
    () => readRunStatusFile(dataDir, 1024),
    error => error instanceof UnusableFileError && error.reason === 'symlink'
  );
  // The directory itself: its file, as it is.
  fs.rmSync(path.join(dataDir, 'run'));
  fs.renameSync(elsewhere, path.join(dataDir, 'run'));
  assert.equal(readRunStatusFile(dataDir, 1024).toString(), '{"synthetic":true}');
});

// The uptime-goblin account owns run/, and root reads it (the healthcheck in the installer, goblin-admin
// status, the installer's proxy preflight): between the open of run/, which refuses a link, and
// the open of status.json, run/ could be swapped for a link to another directory, whose
// status.json root would then read. On Linux the file is opened through run/'s own descriptor
// (/proc/self/fd/<n>), so the swap changes nothing. Here it happens exactly in that window: the
// first open of run/ as a directory renames it and puts a link to elsewhere/ in its place.
const swapRunAfterOpen = `const fs = require('node:fs'), path = require('node:path');
const run = path.join(process.argv[1], 'run'), open = fs.openSync;
let swaps = 0;
fs.openSync = function (file, flags, ...rest) {
  const descriptor = open.call(this, file, flags, ...rest);
  if (file === run && typeof flags === 'number' && flags & fs.constants.O_DIRECTORY && !swaps++) {
    fs.renameSync(run, run + '.real');
    fs.symlinkSync(path.join(process.argv[1], 'elsewhere'), run);
  }
  return descriptor;
};`;
// The two tests below are Linux's alone (/proc/self/fd; elsewhere the file is opened by its run/
// path, and the root readers run on Linux): registered there only (test/platform-manifest.json).

function swappableRun(t) {
  const dataDir = temporary(t, 'orbit-status-swap-');
  for (const [directory, text] of [
    ['run', '{"real":true}'],
    ['elsewhere', '{"elsewhere":true}'],
  ]) {
    fs.mkdirSync(path.join(dataDir, directory));
    fs.writeFileSync(path.join(dataDir, directory, 'status.json'), text);
  }
  return dataDir;
}

platformTest(
  import.meta.url,
  'healthcheck.run-status-swap',
  'readRunStatusFile reads the run/ it opened, though run/ is swapped for a link right after that open',
  {},
  t => {
    const dataDir = swappableRun(t);
    const child = spawnSync(
      process.execPath,
      [
        '--input-type=module',
        '-e',
        `import { createRequire } from 'node:module';
       const require = createRequire(import.meta.url);
       ${swapRunAfterOpen}
       const { readRunStatusFile } = await import(${JSON.stringify(new URL('../lib/saved-data.mjs', import.meta.url).href)});
       process.stdout.write(String(readRunStatusFile(process.argv[1], 1024)) + ' ' + swaps);`,
        dataDir,
      ],
      { encoding: 'utf8', timeout: 30000 }
    );
    assert.equal(child.status, 0, child.stderr);
    assert.equal(child.stdout, '{"real":true} 1');
    assert.equal(fs.readlinkSync(path.join(dataDir, 'run')), path.join(dataDir, 'elsewhere'));
  }
);

platformTest(
  import.meta.url,
  'healthcheck.preflight-swap',
  "the installer's proxy preflight reads the run/ it opened, though run/ is swapped for a link right after that open",
  {},
  t => {
    // Its own copy of the reader, in deploy/install.sh, run as the installer runs it.
    const line = fs
      .readFileSync(path.join(repository, 'deploy/install.sh'), 'utf8')
      .split('\n')
      .find(text => text.startsWith('const readStatus='));
    assert.ok(line, 'install.sh reads run/status.json with readStatus');
    const dataDir = swappableRun(t);
    const child = spawnSync(
      process.execPath,
      [
        '-e',
        `${swapRunAfterOpen}\n${line}\nprocess.stdout.write(readStatus(path.join(run, 'status.json')) + ' ' + swaps);`,
        dataDir,
      ],
      { encoding: 'utf8', timeout: 30000 }
    );
    assert.equal(child.status, 0, child.stderr);
    assert.equal(child.stdout, '{"real":true} 1');
  }
);

for (const symlink of [false, true])
  test(`verification cannot hang on ${symlink ? 'a symlink to a FIFO' : 'a FIFO'} in place of status.json`, t => {
    const dataDir = temporary(t, 'orbit-status-fifo-');
    fs.mkdirSync(path.join(dataDir, 'run'));
    const file = path.join(dataDir, 'run', 'status.json');
    const fifo = symlink ? path.join(dataDir, 'target.fifo') : file;
    const made = spawnSync('mkfifo', [fifo], {
      encoding: 'utf8',
    });
    assert.equal(made.status, 0, made.stderr);
    if (symlink) fs.symlinkSync(fifo, file);
    const result = spawnSync(
      process.execPath,
      [healthcheck, '--wait', '--timeout', '1', '--data-dir', dataDir, '--pid', '1'],
      { encoding: 'utf8', timeout: 3000 }
    );
    assert.equal(
      result.status,
      1,
      `verification must finish itself: ${result.error ?? result.stderr}`
    );
    assert.match(result.stderr, /has not written run\/status\.json yet/);
  });
