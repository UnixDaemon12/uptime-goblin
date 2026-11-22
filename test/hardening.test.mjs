import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import http from 'node:http';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { createApp, launchKind, startupExitCode } from '../server.mjs';
import { ConfigStore, InputError } from '../lib/config.mjs';
import { readAuthRecord, tightenAuthRecord } from '../lib/identity/password.mjs';
import { passwordRequiredMessage } from '../lib/identity/index.mjs';
import { signIn, sessionCall } from './helpers/session.mjs';
import { LoginThrottle, clientAddress, trustedProxies } from '../lib/throttle.mjs';
import { configureDestinations, destinationProblem } from '../lib/destinations.mjs';
import { freePortSync } from './helpers/net.mjs';
import { supervisedEnv } from './helpers/supervised.mjs';

// Fixture hostnames resolve instantly to a documentation address, never via real DNS.
const lookup = async host =>
  host === 'unspecified.example.test' ? [{ address: '::' }] : [{ address: '192.0.2.1' }];
configureDestinations({ lookup });

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const password = 'fixture-hardening-password';
const basic = (value, user = 'admin') =>
  'Basic ' + Buffer.from(user + ':' + value).toString('base64');
const measurement = value => [{ key: 'cpu', label: 'CPU', value, unit: '%' }];
function temporary(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-hardening-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}
async function fixture(t, options = {}) {
  const directory = options.directory ?? temporary(t);
  const app = await createApp({
    directory,
    port: 0,
    password,
    allowedHosts: '',
    webhook: '',
    startScheduler: false,
    trustProxy: '',
    ...options,
  });
  const { port } = await app.listen();
  let closed = false;
  const close = async () => {
    if (closed) return;
    closed = true;
    await app.close();
  };
  t.after(close);
  const call = async (route, method = 'GET', body, headers = {}) => {
    const response = await fetch(`http://127.0.0.1:${port}${route}`, {
      method,
      headers: {
        Authorization: basic(password),
        'Content-Type': 'application/json',
        'X-Goblin-Request': '1',
        ...headers,
      },
      body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
    });
    const text = await response.text();
    let value = text;
    try {
      value = JSON.parse(text);
    } catch {}
    return { status: response.status, headers: response.headers, body: value };
  };
  return { app, call, port, directory, close };
}
// Collects alert webhooks so tests can see which notifications were sent.
async function webhookSink(t) {
  const received = [];
  const server = http.createServer(async (req, res) => {
    let text = '';
    for await (const chunk of req) text += chunk;
    received.push(JSON.parse(text));
    res.end('ok');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  return { url: `http://127.0.0.1:${server.address().port}/hook`, received };
}

test('failures spread over many addresses pause sign-in for everyone but trusted clients', () => {
  let now = 0;
  const throttle = new LoginThrottle({
    globalFailures: 3,
    globalWindowMs: 1000,
    trustMs: 5000,
    now: () => now,
  });
  throttle.success('owner');
  for (const key of ['a', 'b']) throttle.failure(key);
  assert.equal(throttle.globalLocked(), false);
  throttle.failure('c');
  assert.equal(throttle.globalLocked(), true);
  assert.equal(throttle.trusted('owner'), true);
  assert.equal(throttle.trusted('stranger'), false);
  // Failures age out of the window.
  now = 1001;
  assert.equal(throttle.globalLocked(), false);
  // Trust expires.
  now = 5001;
  assert.equal(throttle.trusted('owner'), false);
});

test('a full throttle table evicts idle clients before locked ones', () => {
  const now = 0;
  const throttle = new LoginThrottle({ freeAttempts: 1, maxClients: 2, now: () => now });
  throttle.failure('locked');
  throttle.failure('locked');
  assert.ok(throttle.retryAfter('locked') > 0);
  throttle.failure('idle');
  // A third address must not push the locked client out: that would reset its lockout.
  throttle.failure('attacker');
  assert.equal(throttle.size, 2);
  assert.ok(throttle.retryAfter('locked') > 0);
});

test('behind a trusted proxy the last forwarded address is the client, and oversized values are ignored', () => {
  const proxy = trustedProxies('loopback');
  const forwarded = value =>
    clientAddress(
      { headers: { 'x-forwarded-for': value }, socket: { remoteAddress: '127.0.0.1' } },
      proxy
    );
  // A client can prepend anything; only the entry the proxy appended counts.
  assert.equal(forwarded('198.51.100.1, 203.0.113.9'), '203.0.113.9');
  assert.equal(forwarded('x'.repeat(5000) + ', 203.0.113.9'), '203.0.113.9');
  assert.equal(forwarded('203.0.113.9, ' + '1'.repeat(100)), '127.0.0.1');
});

test('during a many-address guessing attack only recently signed-in clients may try', async t => {
  const { call } = await fixture(t, {
    trustProxy: 'loopback',
    loginThrottle: new LoginThrottle({ globalFailures: 3 }),
  });
  // Scripts through the trusted proxy over HTTPS (Basic on plain HTTP needs
  // GOBLIN_INSECURE_HTTP_SESSIONS=1).
  const from = (address, value = password) =>
    call('/api/dashboard', 'GET', undefined, {
      Authorization: basic(value),
      'X-Forwarded-For': address,
      'X-Forwarded-Proto': 'https',
    });
  assert.equal((await from('198.51.100.1')).status, 200);
  for (const address of ['203.0.113.1', '203.0.113.2', '203.0.113.3'])
    assert.equal((await from(address, 'wrong-password-guess')).status, 401);
  // The correct password from a new address is refused like any other attempt (no oracle).
  const refused = await from('203.0.113.4');
  assert.equal(refused.status, 429);
  assert.equal(refused.headers.get('retry-after'), '60');
  assert.equal((await from('198.51.100.1')).status, 200);
});

test('writes with an outdated If-Match revision are refused with 409 and change nothing', async t => {
  const { app, call } = await fixture(t);
  const start = (await call('/api/dashboard')).body.config.revision;
  assert.ok(Number.isInteger(start));
  const saved = await call(
    '/api/settings',
    'PATCH',
    { appearance: { timezone: 'UTC' } },
    { 'If-Match': `"${start}"` }
  );
  assert.equal(saved.status, 200);
  assert.equal(saved.body.revision, start + 1);
  const stale = await call(
    '/api/settings',
    'PATCH',
    { appearance: { timezone: 'Europe/London' } },
    { 'If-Match': String(start) }
  );
  assert.equal(stale.status, 409);
  assert.equal(stale.body.revision, start + 1);
  assert.equal(app.config.value.appearance.timezone, 'UTC');

  const added = await call('/api/services', 'POST', {
    type: 'linux',
    name: 'Node',
    apiUrl: 'http://node.example.test:9100',
  });
  assert.equal(added.status, 201);
  const id = added.body.service.id,
    current = added.body.revision;
  const edit = await call(
    `/api/services/${id}`,
    'PATCH',
    { name: 'Renamed' },
    { 'If-Match': String(current - 1) }
  );
  assert.equal(edit.status, 409);
  assert.equal(app.config.get(id).name, 'Node');
  const removal = await call(`/api/services/${id}`, 'DELETE', undefined, { 'If-Match': '0' });
  assert.equal(removal.status, 409);
  assert.ok(app.config.get(id));
  // The weak form of the current revision is accepted, and writes without If-Match still work.
  const renamed = await call(
    `/api/services/${id}`,
    'PATCH',
    { name: 'Renamed' },
    { 'If-Match': `W/"${current}"` }
  );
  assert.equal(renamed.status, 200);
  assert.equal((await call(`/api/services/${id}`, 'DELETE')).status, 200);
  // Only a revision, as a number or an entity tag: other spellings of the current one (hex,
  // binary, exponent, sign, decimals), '*', lists and blanks get 400 and change nothing, before
  // the write takes its turn.
  const revision = app.config.value.revision;
  for (const tag of [
    `0x${revision.toString(16)}`,
    `0b${revision.toString(2)}`,
    `${revision}e0`,
    `+${revision}`,
    `${revision}.0`,
    `"${revision}`,
    `W/${revision}x`,
    `W/${revision}`,
    `w/"${revision}"`,
    `"${revision}", "${revision}"`,
    '*',
    '',
    '  ',
  ]) {
    const odd = await call(
      '/api/settings',
      'PATCH',
      { appearance: { timezone: 'Europe/Paris' } },
      { 'If-Match': tag }
    );
    assert.equal(odd.status, 400, `If-Match ${JSON.stringify(tag)}`);
    assert.equal(odd.body.code, 'if_match_invalid');
    assert.equal(app.config.value.revision, revision, `If-Match ${JSON.stringify(tag)}`);
  }
  assert.equal(app.config.value.appearance.timezone, 'UTC');
  // The forms a browser or script sends still work.
  for (const tag of [`${revision}`, ` "${revision + 1}" `, `W/"${revision + 2}"`])
    assert.equal(
      (await call('/api/settings', 'PATCH', { title: 'Uptime Goblin' }, { 'If-Match': tag }))
        .status,
      200,
      tag
    );
});

test('source IDs are never reused, even after a restart', async t => {
  const directory = temporary(t);
  const first = await fixture(t, { directory });
  const add = async call =>
    (await call('/api/services', 'POST', { type: 'prometheus', name: 'Exporter' })).body.service.id;
  const a = await add(first.call);
  assert.equal((await first.call(`/api/services/${a}`, 'DELETE')).status, 200);
  const b = await add(first.call);
  assert.notEqual(a, b);
  assert.equal((await first.call(`/api/services/${b}`, 'DELETE')).status, 200);
  await first.close();
  const second = await fixture(t, { directory });
  const c = await add(second.call);
  assert.ok(![a, b].includes(c), `${c} reused a deleted ID`);
});

test('known API routes with the wrong method return 405 with Allow', async t => {
  const { call } = await fixture(t);
  for (const [route, method, allow] of [
    ['/api/settings', 'GET', 'PATCH'],
    ['/api/services', 'GET', 'POST'],
    ['/api/services/linux', 'PUT', 'PATCH, DELETE'],
    ['/api/dashboard', 'POST', 'GET'],
    ['/api/history/linux', 'DELETE', 'GET'],
  ]) {
    const response = await call(route, method, method === 'GET' ? undefined : {});
    assert.equal(response.status, 405, `${method} ${route}`);
    assert.equal(response.headers.get('allow'), allow);
  }
  assert.equal((await call('/api/nothing-here')).status, 404);
});

test('request guards: JSON content type in any case, body size, username and document allowlist', async t => {
  const { call } = await fixture(t);
  const patch = headers => call('/api/settings', 'PATCH', { title: 'Uptime Goblin' }, headers);
  assert.equal((await patch({ 'Content-Type': 'Application/JSON; Charset=UTF-8' })).status, 200);
  assert.equal((await patch({ 'Content-Type': ' application/json ;charset=utf-8' })).status, 200);
  assert.equal((await patch({ 'Content-Type': 'text/plain' })).status, 415);
  assert.equal((await patch({ 'Content-Type': 'application/jsonx' })).status, 415);
  const large = await call('/api/settings', 'PATCH', JSON.stringify({ title: 'x'.repeat(150001) }));
  assert.equal(large.status, 413);
  assert.match(large.body.error, /too large/);
  assert.equal(
    (await call('/api/dashboard', 'GET', undefined, { Authorization: basic(password, 'root') }))
      .status,
    401
  );
  for (const doc of ['../README', 'constructor', '__proto__', 'toString'])
    assert.equal((await call(`/api/docs?doc=${encodeURIComponent(doc)}`)).status, 404, doc);
  assert.equal((await call('/api/docs?doc=security')).status, 200);
});

test('with GOBLIN_ALLOWED_HOSTS set only the listed hosts are accepted', async t => {
  const { port } = await fixture(t, {
    allowedHosts: 'goblin.example.test, goblin.example.test:8443',
  });
  const status = host =>
    new Promise((resolve, reject) => {
      const request = http.request(
        {
          host: '127.0.0.1',
          port,
          path: '/health',
          headers: {
            Authorization: basic(password),
            ...(host === undefined ? {} : { Host: host }),
          },
          setHost: host !== undefined,
        },
        response => {
          response.resume();
          resolve(response.statusCode);
        }
      );
      request.on('error', reject);
      request.end();
    });
  assert.equal(await status('goblin.example.test'), 200);
  assert.equal(await status('GOBLIN.Example.TEST:8443'), 200);
  assert.equal(await status(`127.0.0.1:${port}`), 200);
  for (const host of [
    'attacker.example',
    'goblin.example.test:1',
    'goblin.example.test.attacker.example',
  ])
    assert.equal(await status(host), 403, host);
  // Node itself refuses an HTTP/1.1 request without Host (400) before Uptime Goblin sees it.
  assert.ok([400, 403].includes(await status(undefined)));
});

test('requests arriving on open connections while Uptime Goblin stops get 503', async t => {
  const { close, port } = await fixture(t);
  const socket = net.connect(port, '127.0.0.1');
  t.after(() => socket.destroy());
  await new Promise(resolve => socket.once('connect', resolve));
  let received = '';
  socket.on('data', chunk => (received += chunk));
  const head = `Host: 127.0.0.1:${port}\r\nAuthorization: ${basic(password)}\r\n`;
  // The first request's body is held back, so the connection is busy when close() starts.
  socket.write(
    `PATCH /api/settings HTTP/1.1\r\n${head}X-Goblin-Request: 1\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n`
  );
  await new Promise(resolve => setTimeout(resolve, 100));
  const closing = close();
  socket.write(`{}GET /api/dashboard HTTP/1.1\r\n${head}\r\n`);
  await new Promise(resolve => socket.once('end', resolve));
  await closing;
  const statuses = received.match(/^HTTP\/1\.1 \d+/gm);
  assert.deepEqual(statuses, ['HTTP/1.1 200', 'HTTP/1.1 503']);
  assert.match(received, /Uptime Goblin is stopping/);
});

// gate-prep verify-1, note 3: a browser opens a connection before it has a request to send. On
// Node 24.21.0, server.close() waits for such a connection and closeIdleConnections() does not end
// it, so Uptime Goblin's stop waited its whole 10 s for open requests. On Node 26.5.1 server.close() does
// not wait for it, and the stop's closeAllConnections() ends it within milliseconds, so this test
// passes there on the code before the fix too: the defect is Node 24's. The stop now ends a
// connection that never sent a byte at once, and one that did still gets its answer (the test
// above).
test('a stop ends a connection that never sent a request at once, on every runtime', async t => {
  const { close, port } = await fixture(t);
  const socket = net.connect(port, '127.0.0.1');
  t.after(() => socket.destroy());
  await new Promise(resolve => socket.once('connect', resolve));
  socket.on('error', () => {});
  const ended = new Promise(resolve => socket.once('close', () => resolve(true)));
  // Uptime Goblin has accepted it before the stop begins.
  await new Promise(resolve => setTimeout(resolve, 100));
  const started = performance.now();
  await close();
  const took = performance.now() - started;
  assert.ok(took < 5000, `the stop took ${Math.round(took)} ms, waiting for the unused connection`);
  assert.equal(
    await Promise.race([ended, new Promise(resolve => setTimeout(resolve, 2000, false))]),
    true,
    'the stop ended the connection'
  );
});

test('server and readiness probe start when launched through a symlink', async t => {
  const directory = temporary(t);
  const link = path.join(directory, 'server-link.mjs'),
    probe = path.join(directory, 'healthcheck-link.mjs');
  fs.symlinkSync(path.join(root, 'server.mjs'), link);
  fs.symlinkSync(path.join(root, 'lib', 'healthcheck.mjs'), probe);
  const env = {
    PATH: process.env.PATH,
    HOST: '127.0.0.1',
    PORT: freePortSync(),
    GOBLIN_DATA_DIR: path.join(directory, 'data'),
    GOBLIN_PASSWORD: password,
  };
  const child = spawn(process.execPath, [link], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  t.after(() => child.kill('SIGKILL'));
  let output = '';
  const ready = await new Promise(resolve => {
    const timer = setTimeout(() => resolve(false), 10000);
    child.stdout.on('data', chunk => {
      output += chunk;
      if (/Uptime Goblin is ready/.test(output)) {
        clearTimeout(timer);
        resolve(true);
      }
    });
    child.on('exit', () => resolve(false));
  });
  assert.ok(ready, 'a symlinked server.mjs must start, not exit silently');
  const exited = new Promise(resolve => child.once('exit', code => resolve(code)));
  child.kill('SIGTERM');
  assert.equal(await exited, 0);
  // The probe run as a program must report failure for a port with nothing listening.
  const closedPort = await new Promise(resolve => {
    const server = net.createServer().listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
  const result = await new Promise(resolve => {
    const run = spawn(process.execPath, [probe], {
      env: { ...env, PORT: String(closedPort) },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let errors = '';
    run.stderr.on('data', chunk => (errors += chunk));
    run.on('exit', code => resolve({ code, errors }));
  });
  assert.equal(result.code, 1);
  assert.match(result.errors, /did not become ready/);
});

test('time zones: local, UTC and region-based IANA names only', async t => {
  const { call } = await fixture(t);
  const zone = timezone => call('/api/settings', 'PATCH', { appearance: { timezone } });
  for (const accepted of [
    'local',
    'UTC',
    'Europe/London',
    'America/Argentina/Buenos_Aires',
    'Etc/GMT+5',
  ])
    assert.equal((await zone(accepted)).status, 200, accepted);
  for (const refused of [
    'US/Eastern',
    'EST5EDT',
    'Mars/Olympus_Mons',
    '../etc/passwd',
    'europe/london',
    '',
  ])
    assert.equal((await zone(refused)).status, 400, refused);
});

test('collection addresses, metric paths and launch links cannot carry credentials or change origin', async t => {
  const { app, call } = await fixture(t);
  const add = fields =>
    call('/api/services', 'POST', { type: 'prometheus', name: 'Exporter', ...fields });
  for (const apiUrl of [
    'https://admin:secret@nas.example.test:5001',
    'http://nas.example.test:9100/?token=secret',
    'http://nas.example.test:9100/?',
    'http://nas.example.test:9100/#fragment',
    'file:///etc/passwd',
    'ftp://nas.example.test/',
  ])
    assert.equal((await add({ apiUrl })).status, 400, apiUrl);
  for (const metricPath of [
    '.evil.example.test/x',
    ':8080/x',
    '@evil.example.test/x',
    'metrics',
    '/metrics?x=1',
    '/a\\b',
  ])
    assert.equal(
      (await add({ apiUrl: 'http://nas.example.test', metricPath })).status,
      400,
      metricPath
    );
  for (const url of [
    'https://nas.example.test/?token=abc',
    'https://nas.example.test/#access_token=abc',
    'https://git.example.test/?private_token=abc',
    'https://nas.example.test/?apiToken=abc',
    'https://nas.example.test/?X-Api-Key=abc',
    'https://nas.example.test/?access_key=abc',
    'https://nas.example.test/?PHPSESSID=abc',
    'https://nas.example.test/?apitoken=abc',
    'https://nas.example.test/?APIToken=abc',
    'https://prtg.example.test/?username=admin&passhash=123',
    'https://nas.example.test/?apikey2=abc',
    'https://nas.example.test/#id_token=abc&token_type=Bearer',
    'https://tracker.example.test/rss.php?uid=1&passkey=0123456789abcdef',
    'https://nas.example.test/?sessionkey=abc',
    'https://nas.example.test/?authorization=Basic%20abc',
    'https://nas.example.test/?user=admin&adminpass=abc',
    'https://nas.example.test/#access_token=abc&state=/home?tab=1',
    // Codex review A2: an empty or valueless neighbour no longer hides the pair.
    'https://nas.example.test/#access_token=abc&',
    'https://nas.example.test/#access_token=abc&state',
    'https://nas.example.test/#&access_token=abc',
    'https://nas.example.test/#state&id_token=abc',
    'https://nas.example.test/#:~:access_token=abc',
    // Verification round: nor does one before it, nor a route character in its name, nor %3D.
    'https://nas.example.test/#/home&access_token=abc',
    'https://nas.example.test/#/&access_token=abc',
    'https://nas.example.test/#!&access_token=abc',
    'https://nas.example.test/#?&access_token=abc',
    'https://nas.example.test/#home/&access_token=abc&state',
    'https://nas.example.test/#/access_token=abc&expires_in=3600',
    'https://nas.example.test/#a=1&api/key=abc',
    'https://nas.example.test/#access_token%3Dabc&state=1',
  ])
    assert.equal((await add({ url })).status, 400, url);
  const ok = await add({
    apiUrl: 'http://nas.example.test:9100',
    metricPath: '/metrics',
    url: 'https://nas.example.test/?page=2',
    apiKey: 'fixture-exporter-key',
  });
  assert.equal(ok.status, 201);
  const id = ok.body.service.id;
  // An edit of the path alone cannot point the saved key at another host.
  assert.equal(
    (await call(`/api/services/${id}`, 'PATCH', { metricPath: '.evil.example.test/metrics' }))
      .status,
    400
  );
  const exported = JSON.stringify((await call('/api/config/export')).body);
  assert.ok(!exported.includes('fixture-exporter-key'));
  assert.equal(app.config.get(id).metricPath, '/metrics');
});

test('changing the SMTP server, port, security or sender requires the app password again', async t => {
  const { app, call } = await fixture(t);
  const email = fields => call('/api/settings', 'PATCH', { email: fields });
  assert.equal(
    (
      await email({
        enabled: true,
        from: 'orbit@example.test',
        to: 'owner@example.test',
        password: 'fixture-app-password',
      })
    ).status,
    200
  );
  for (const change of [
    { host: 'smtp.example.test' },
    { port: 587, secure: false },
    { from: 'other@example.test' },
  ]) {
    const refused = await email(change);
    assert.equal(refused.status, 400, JSON.stringify(change));
    assert.match(refused.body.error, /Re-enter the app password/);
  }
  assert.equal(app.config.value.email.password, 'fixture-app-password');
  // The recipient is not part of the SMTP account, so it can change freely.
  assert.equal((await email({ to: 'someone@example.test' })).status, 200);
  assert.equal(app.config.value.email.password, 'fixture-app-password');
  assert.equal(
    (await email({ host: 'smtp.example.test', password: 'fixture-other-password' })).status,
    200
  );
  assert.equal(app.config.value.email.password, 'fixture-other-password');
  assert.equal(
    (await email({ enabled: false, from: 'next@example.test', clearPassword: true })).status,
    200
  );
  assert.equal(app.config.value.email.password, '');
});

test('settings saved by older releases that newer validation refuses are repaired on start', async t => {
  const directory = temporary(t);
  fs.writeFileSync(
    path.join(directory, 'config.json'),
    JSON.stringify({
      appearance: { timezone: 'US/Eastern' },
      services: [
        {
          id: 'linux-3',
          type: 'linux',
          apiUrl: 'http://node.example.test:9100/?',
          metrics: [
            { key: 'cpu', path: 'node_load5' },
            { key: 'load5', path: 'node_load5' },
          ],
        },
        // URL parsing drops the trailing tab, so older releases accepted this address.
        { id: 'linux-5', type: 'linux', apiUrl: 'http://node.example.test:9100/?\t' },
        // A Linux card on the JSON method reports only its mappings, whatever their keys.
        {
          id: 'linux-6',
          type: 'linux',
          collector: 'json',
          apiUrl: 'http://node.example.test:8080',
          metricPath: '/data.json',
          metrics: [{ key: 'cpu', path: 'cpu' }],
        },
        { id: 'link-1', type: 'link', url: 'https://nas.example.test/#access_token=abc' },
        { id: 'link-2', type: 'link', url: 'https://nas.example.test/?page=2&apitoken=abc' },
        {
          id: 'link-4',
          type: 'link',
          url: 'https://nas.example.test/#access_token=abc&state=/home?tab=1',
        },
        // SPA routes are not credentials and must survive the upgrade.
        { id: 'link-3', type: 'link', url: 'https://portainer.example.test:9443/#!/auth' },
      ],
    })
  );
  const warnings = [];
  const warn = console.warn;
  console.warn = message => warnings.push(message);
  let started;
  try {
    started = await fixture(t, { directory });
  } finally {
    console.warn = warn;
  }
  const { app } = started;
  assert.equal(app.config.value.appearance.timezone, 'local');
  for (const id of ['linux-3', 'linux-5'])
    assert.match(app.config.get(id).apiUrl, /^http:\/\/node\.example\.test:9100\/?$/);
  // Only the credential parameters are removed; the link itself is kept.
  assert.equal(app.config.get('link-1').url, 'https://nas.example.test/');
  assert.equal(app.config.get('link-2').url, 'https://nas.example.test/?page=2');
  assert.equal(app.config.get('link-3').url, 'https://portainer.example.test:9443/#!/auth');
  assert.equal(app.config.get('link-4').url, 'https://nas.example.test/#state=/home?tab=1');
  // Saved mappings are never deleted, even where new ones may no longer use the key.
  assert.deepEqual(
    app.config.get('linux-3').metrics.map(m => m.key),
    ['cpu', 'load5']
  );
  assert.deepEqual(
    app.config.get('linux-6').metrics.map(m => m.key),
    ['cpu']
  );
  // ...and stay editable.
  assert.equal(
    (
      await started.call('/api/services/linux-3', 'PATCH', {
        metrics: [{ key: 'cpu', label: 'CPU', path: 'node_load5' }],
      })
    ).status,
    200
  );
  // 1.5: a new data directory also gets a generated key, which is warned about at every start
  // (delivery spec §6.7); the repairs are the other warnings.
  const repairs = () => warnings.filter(message => !/secret\.key/.test(message));
  assert.equal(repairs().length, 6);
  assert.ok(!/access_token|apitoken/.test(warnings.join('\n')), 'repairs must not log secrets');
  // The saved counter keeps new IDs above the existing ones.
  const added = await started.call('/api/services', 'POST', { type: 'linux', name: 'Next' });
  assert.equal(added.body.service.id, 'linux-7');
  // Repairs are saved, so the next start neither repeats nor logs them.
  await started.close();
  console.warn = message => warnings.push(message);
  try {
    const again = await fixture(t, { directory });
    assert.equal(again.app.config.value.appearance.timezone, 'local');
  } finally {
    console.warn = warn;
  }
  assert.equal(repairs().length, 6);
});

// Codex review A4: the six synthetic cases of maintenance 27f81dd, as they are there.
test('legacy collection address repairs never log URL contents', async t => {
  const canary = 'fixture-repair-secret';
  const address = `https://node.example.test/${canary}`;
  const cases = [
    { name: 'query', apiUrl: `${address}?apitoken=${canary}`, repaired: '' },
    { name: 'fragment', apiUrl: `${address}#access_token=${canary}`, repaired: '' },
    { name: 'bare query', apiUrl: `${address}?`, repaired: address },
    { name: 'bare fragment', apiUrl: `${address}#\t`, repaired: address },
    { name: 'malformed address', apiUrl: `not-a-url?token=${canary}`, repaired: '' },
    {
      name: 'rejected userinfo',
      apiUrl: `https://fixture:${canary}@node.example.test/?`,
      refused: true,
    },
  ];
  for (const entry of cases)
    await t.test(entry.name, t => {
      const directory = temporary(t);
      const file = path.join(directory, 'config.json');
      const original = JSON.stringify({
        services: [{ id: 'linux-1', type: 'linux', apiUrl: entry.apiUrl }],
      });
      fs.writeFileSync(file, original);
      const warnings = [];
      const warn = console.warn;
      console.warn = message => warnings.push(message);
      try {
        if (entry.refused) {
          assert.throws(() => new ConfigStore(directory), /API address.*without credentials/);
          assert.equal(fs.readFileSync(file, 'utf8'), original);
        } else {
          const store = new ConfigStore(directory);
          assert.equal(store.get('linux-1').apiUrl, entry.repaired);
          assert.equal(
            JSON.parse(fs.readFileSync(file, 'utf8')).services[0].apiUrl,
            entry.repaired
          );
          // A successfully saved repair is silent on the next load.
          assert.equal(new ConfigStore(directory).get('linux-1').apiUrl, entry.repaired);
        }
      } finally {
        console.warn = warn;
      }
      assert.equal(warnings.length, 1);
      assert.match(warnings[0], /collection address of linux-1/);
      assert.equal(warnings[0].includes(canary), false, 'repair warnings must not reveal secrets');
      assert.equal(
        warnings[0].includes('node.example.test'),
        false,
        'repair warnings must not reveal either URL'
      );
    });
});

test('storage recovery waits until every failing source writes again and five quiet minutes pass', async t => {
  const hook = await webhookSink(t);
  let clock = 0;
  const { app } = await fixture(t, {
    webhook: hook.url,
    monotonic: () => clock,
    collector: async () => measurement(10),
  });
  for (const id of ['linux', 'docker'])
    app.config.update(id, { apiUrl: 'http://node.example.test:9100' });
  const record = app.store.record.bind(app.store);
  let failing = new Set(['linux']);
  app.store.record = (id, ...rest) => {
    if (failing.has(id)) throw Object.assign(new Error('disk full'), { code: 'SQLITE_FULL' });
    return record(id, ...rest);
  };
  const storage = () => hook.received.filter(e => e.rule === '__storage').map(e => e.kind);
  const errors = console.error;
  console.error = () => {};
  t.after(() => (console.error = errors));
  await app.poll(app.config.get('linux'));
  await app.flushNotifications();
  assert.deepEqual(storage(), ['firing']);
  // Other sources writing fine do not end the incident while linux still cannot write.
  clock += 10 * 60 * 1000;
  for (let i = 0; i < 4; i++) await app.poll(app.config.get('docker'));
  await app.flushNotifications();
  assert.deepEqual(storage(), ['firing']);
  failing = new Set();
  await app.poll(app.config.get('linux'));
  await app.flushNotifications();
  assert.deepEqual(storage(), ['firing', 'resolved']);
});

test('retention is enforced by the scheduler and when lowered in settings', async t => {
  const { app, call, directory } = await fixture(t);
  const day = 24 * 60 * 60 * 1000,
    now = Date.now();
  const count = () => {
    const db = new DatabaseSync(path.join(directory, 'history.sqlite'), { readOnly: true });
    try {
      return db.prepare("SELECT count(*) AS n FROM readings WHERE service='linux'").get().n;
    } finally {
      db.close();
    }
  };
  app.store.record('linux', measurement(1), null, now - 40 * day);
  app.store.record('linux', measurement(1), null, now - 10 * day);
  app.store.record('linux', measurement(1), null, now - 60 * 1000);
  assert.equal(count(), 3);
  await app.tick();
  assert.equal(count(), 2, 'the first scheduler tick prunes history past retention');
  assert.equal((await call('/api/settings', 'PATCH', { retentionDays: 7 })).status, 200);
  assert.equal(count(), 1);
});

test('recovery notifications follow their switch and pausing a source clears its alert', async t => {
  const hook = await webhookSink(t);
  let value = 95;
  const { app, call } = await fixture(t, {
    webhook: hook.url,
    collector: async () => measurement(value),
  });
  app.config.update('linux', {
    apiUrl: 'http://node.example.test:9100',
    rules: [{ key: 'cpu', threshold: 90, forSeconds: 0, operator: 'gt', recoveryThreshold: 85 }],
  });
  await call('/api/settings', 'PATCH', {
    monitoring: { recoverySuccesses: 1, recoverySeconds: 0 },
    alerts: { notifyOnRecovery: false },
  });
  // A measurement rule fires on its second matching sample.
  await app.poll(app.config.get('linux'));
  await app.poll(app.config.get('linux'));
  assert.equal(app.store.alerts().length, 1);
  value = 10;
  await app.poll(app.config.get('linux'));
  await app.flushNotifications();
  assert.deepEqual(
    hook.received.map(e => e.kind),
    ['firing'],
    'no recovery notification while the switch is off'
  );
  assert.equal(app.store.alerts().length, 0);
  value = 95;
  await app.poll(app.config.get('linux'));
  await app.poll(app.config.get('linux'));
  assert.equal(app.store.alerts().length, 1);
  assert.equal((await call('/api/services/linux', 'PATCH', { enabled: false })).status, 200);
  assert.equal(app.store.alerts().length, 0, 'pausing clears the source alert');
});

test('saving new credentials makes the next collection sign in again', async t => {
  const logins = [];
  const server = http.createServer(async (req, res) => {
    let text = '';
    for await (const chunk of req) text += chunk;
    res.setHeader('Content-Type', 'application/json');
    if (req.url === '/api/tokens') {
      const { secret } = JSON.parse(text);
      logins.push(secret);
      if (secret !== 'right-password') {
        res.writeHead(401);
        res.end(JSON.stringify({ error: { message: 'Invalid password' } }));
        return;
      }
      res.end(JSON.stringify({ token: 'session-' + logins.length }));
      return;
    }
    if (req.url === '/api/nginx/proxy-hosts') {
      res.end(
        JSON.stringify(
          req.headers.authorization?.startsWith('Bearer session-') ? [{ enabled: true }] : []
        )
      );
      return;
    }
    res.writeHead(404);
    res.end('{}');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const { app, call } = await fixture(t, { allowLoopback: true });
  const errors = console.error;
  console.error = () => {};
  t.after(() => (console.error = errors));
  app.config.update('npm', {
    apiUrl: `http://127.0.0.1:${server.address().port}`,
    username: 'admin@example.test',
    password: 'right-password',
  });
  await app.poll(app.config.get('npm'));
  await app.poll(app.config.get('npm'));
  assert.equal(logins.length, 1, 'the session is reused between polls');
  assert.equal(app.store.latest('npm').error ?? null, null);
  assert.equal(
    (await call('/api/services/npm', 'PATCH', { password: 'mistyped-password' })).status,
    200
  );
  await app.poll(app.config.get('npm'));
  assert.deepEqual(logins, ['right-password', 'mistyped-password']);
  assert.ok(app.store.latest('npm').error, 'the mistyped password is reported at once');
});

test('unspecified and multicast IPv6 destinations are refused', async () => {
  for (const url of [
    'http://[::]/',
    'http://[::0]:9100/',
    'http://unspecified.example.test/',
    'http://[ff02::1]/',
    'http://[::ffff:0.0.0.0]/',
  ])
    assert.match(String(await destinationProblem(url)), /link-local, multicast or reserved/, url);
  assert.equal(await destinationProblem('http://nas.example.test/'), null);
});

test('Linux and Windows mappings cannot reuse keys of built-in readings', async t => {
  const { call } = await fixture(t);
  const mapping = (id, key) =>
    call(`/api/services/${id}`, 'PATCH', {
      metrics: [{ key, label: 'Mapped', path: 'node_load5' }],
    });
  for (const [id, key] of [
    ['linux', 'cpu'],
    ['linux', 'transmit'],
    ['windows', 'memory_free'],
    ['windows', 'received'],
  ]) {
    const refused = await mapping(id, key);
    assert.equal(refused.status, 400, `${id} ${key}`);
    assert.match(refused.body.error, /built-in/);
  }
  assert.equal((await mapping('linux', 'load5')).status, 200);
});

test('native Linux mappings cannot take built-in keys; JSON-method cards and disk keys can', async t => {
  const { call } = await fixture(t);
  const mapping = (id, key, extra = {}) =>
    call(`/api/services/${id}`, 'PATCH', {
      ...extra,
      metrics: [{ key, label: 'Mapped', path: 'value' }],
    });
  assert.equal((await mapping('linux', 'disk_free_/dev/shm')).status, 200);
  assert.equal(
    (
      await mapping('linux', 'cpu', {
        collector: 'json',
        apiUrl: 'http://node.example.test',
        metricPath: '/data.json',
      })
    ).status,
    200
  );
  assert.equal(
    (
      await mapping('windows', 'sent', {
        collector: 'json',
        apiUrl: 'http://win.example.test',
        metricPath: '/data.json',
      })
    ).status,
    200
  );
});

test('a guessing attack ends when it stops, and every signed-in browser stays trusted', async t => {
  let now = 0;
  const { call } = await fixture(t, {
    trustProxy: 'loopback',
    loginThrottle: new LoginThrottle({ globalFailures: 5, now: () => now }),
  });
  // Scripts through the trusted proxy over HTTPS (Basic on plain HTTP needs
  // GOBLIN_INSECURE_HTTP_SESSIONS=1).
  const from = (address, value = password) =>
    call('/api/dashboard', 'GET', undefined, {
      Authorization: basic(value),
      'X-Forwarded-For': address,
      'X-Forwarded-Proto': 'https',
    });
  // The first sign-in is fully checked; the second browser is answered from the cache.
  assert.equal((await from('198.51.100.1')).status, 200);
  assert.equal((await from('198.51.100.2')).status, 200);
  for (let i = 1; i <= 5; i++)
    assert.equal((await from('203.0.113.' + i, 'wrong-password-guess')).status, 401);
  assert.equal((await from('203.0.113.9')).status, 429);
  // Both signed-in browsers keep working during the attack.
  for (let poll = 0; poll < 60; poll++) {
    now += 15000;
    assert.equal((await from('198.51.100.1')).status, 200);
    assert.equal((await from('198.51.100.2')).status, 200);
    // A refused, unchecked attempt does not keep the lock going.
    await from('203.0.113.9');
  }
  // 15 minutes later the attack has aged out and new addresses may sign in again.
  assert.equal((await from('203.0.113.9')).status, 200);
});

test('deleting a source neither polls nor alerts on it while its history is cleared', async t => {
  const hook = await webhookSink(t);
  let collected = 0;
  const { app, call } = await fixture(t, {
    webhook: hook.url,
    collector: async () => {
      collected++;
      throw new Error('Connection refused');
    },
  });
  app.config.update('linux', { apiUrl: 'http://node.example.test:9100' });
  await call('/api/settings', 'PATCH', {
    monitoring: { availabilityFailures: 2, availabilitySeconds: 0, retryCount: 0 },
  });
  await app.poll(app.config.get('linux'));
  const errors = console.error;
  console.error = () => {};
  t.after(() => (console.error = errors));
  // A slow deletion, as for a large history, with the scheduler running meanwhile.
  const forget = app.store.forget.bind(app.store);
  app.store.forget = async id => {
    for (let i = 0; i < 5; i++) {
      await app.tick(true);
      await new Promise(resolve => setTimeout(resolve, 20));
    }
    return forget(id);
  };
  assert.equal((await call('/api/services/linux', 'DELETE')).status, 200);
  await app.tick(true);
  await app.flushNotifications();
  assert.equal(collected, 1);
  assert.deepEqual(hook.received, []);
  assert.equal(app.config.get('linux'), undefined);
});

test('two saves based on the same revision cannot both succeed, even while history is pruned', async t => {
  const { app, call } = await fixture(t);
  const revision = (await call('/api/dashboard')).body.config.revision;
  const prune = app.store.prune.bind(app.store);
  app.store.prune = async (...args) => {
    await new Promise(resolve => setTimeout(resolve, 200));
    return prune(...args);
  };
  const first = call(
    '/api/settings',
    'PATCH',
    { retentionDays: 7 },
    { 'If-Match': String(revision) }
  );
  await new Promise(resolve => setTimeout(resolve, 50));
  const second = call(
    '/api/settings',
    'PATCH',
    { retentionDays: 60 },
    { 'If-Match': String(revision) }
  );
  const [a, b] = await Promise.all([first, second]);
  assert.equal(a.status, 200);
  assert.equal(b.status, 409);
  assert.equal(app.config.value.retentionDays, 7);
});

test('the storage all-clear does not wait for a source that was removed or paused', async t => {
  const hook = await webhookSink(t);
  let clock = 0;
  const { app, call } = await fixture(t, {
    webhook: hook.url,
    monotonic: () => clock,
    collector: async () => measurement(10),
  });
  for (const id of ['linux', 'docker', 'windows'])
    app.config.update(id, { apiUrl: 'http://node.example.test:9100' });
  const record = app.store.record.bind(app.store);
  let failing = true;
  app.store.record = (...args) => {
    if (failing) throw Object.assign(new Error('disk full'), { code: 'SQLITE_FULL' });
    return record(...args);
  };
  const errors = console.error;
  console.error = () => {};
  t.after(() => (console.error = errors));
  for (const id of ['linux', 'docker', 'windows']) await app.poll(app.config.get(id));
  failing = false;
  assert.equal((await call('/api/services/linux', 'DELETE')).status, 200);
  assert.equal((await call('/api/services/windows', 'PATCH', { enabled: false })).status, 200);
  clock += 10 * 60 * 1000;
  for (let i = 0; i < 3; i++) await app.poll(app.config.get('docker'));
  await app.flushNotifications();
  assert.deepEqual(
    hook.received.filter(e => e.rule === '__storage').map(e => e.kind),
    ['firing', 'resolved']
  );
});

test('launch links keep SPA routes, anchors and harmless parameters', async t => {
  const { call } = await fixture(t);
  for (const url of [
    'https://portainer.example.test:9443/#!/auth',
    'https://awx.example.test/#/credentials',
    'https://app.example.test/#/auth/login',
    'https://docs.example.test/page#api-key',
    'https://app.plex.tv/desktop/#!/server/abc/details?key=%2Flibrary%2Fmetadata%2F1',
    'https://mail.example.test/?authuser=1&author=me&keyword=x&hotkey=k',
    'https://app.plex.tv/desktop/#!/server/abc/list?key=%2Flibrary%2Fsections%2F1%2Fall%3Fgenre%3D57&context=content.library',
    'https://app.plex.tv/desktop/#!/server/abc/details?key=%2Fplaylists',
    'https://adguard.example.test/#logs?search=example.com',
    'https://app.example.test/#tokens?page=2',
    'https://docs.example.test/page#authentication:~:text=Basic%20auth',
    'https://app.example.test/#page=2&view=list',
    // Codex review A2: empty or valueless members beside routes, anchors and harmless pairs.
    'https://app.example.test/#page=2&view=list&',
    'https://app.example.test/#state&page=2',
    'https://app.example.test/#/callback?x=1&',
    'https://docs.example.test/page#api-key&',
    // Verification round: a route with a harmless pair after it, a root route's parameters.
    'https://app.example.test/#/home&page=2',
    'https://app.example.test/#/?page=2',
  ])
    assert.equal(
      (await call('/api/services', 'POST', { type: 'link', name: 'Link', url })).status,
      201,
      url
    );
});

// Codex review A2: settings saved by a release whose check missed a fragment token beside an
// empty, valueless or route-like member are repaired on start like an ordinary
// #access_token=…: only the pair goes, the warning and the saved file keep nothing of it, and a
// route stays as it was.
test('saved destinations with a fragment token beside an empty or valueless member are repaired on start', t => {
  const directory = temporary(t),
    file = path.join(directory, 'config.json'),
    canary = 'fixture-fragment-secret';
  const links = {
    'link-1': [`https://nas.example.test/#access_token=${canary}&`, 'https://nas.example.test/'],
    'link-2': [
      `https://nas.example.test/#access_token=${canary}&state`,
      'https://nas.example.test/#state',
    ],
    'link-3': [`https://nas.example.test/#&access_token=${canary}`, 'https://nas.example.test/'],
    'link-4': [
      'https://app.example.test/#/callback?x=1&',
      'https://app.example.test/#/callback?x=1&',
    ],
    // Verification round: the neighbour before the pair (a route-like one) hid it too.
    'link-5': [
      `https://nas.example.test/#/home&access_token=${canary}`,
      'https://nas.example.test/#/home',
    ],
    'link-6': [
      `https://nas.example.test/#!&access_token=${canary}&state`,
      'https://nas.example.test/#!&state',
    ],
    'link-7': ['https://app.example.test/#/home&page=2', 'https://app.example.test/#/home&page=2'],
  };
  fs.writeFileSync(
    file,
    JSON.stringify({
      services: Object.entries(links).map(([id, [url]]) => ({ id, type: 'link', url })),
    })
  );
  const warnings = [];
  t.mock.method(console, 'warn', (...args) => warnings.push(args.join(' ')));
  const config = new ConfigStore(directory);
  for (const [id, [, repaired]] of Object.entries(links))
    assert.equal(config.get(id).url, repaired, id);
  assert.deepEqual(
    warnings.map(warning => /destination of (link-\d)/.exec(warning)?.[1]),
    ['link-1', 'link-2', 'link-3', 'link-5', 'link-6']
  );
  assert.equal(warnings.join('\n').includes(canary), false, 'repairs must not log secrets');
  assert.equal(fs.readFileSync(file, 'utf8').includes(canary), false, 'the repair is saved');
});

test('a write queued behind history work is refused if the password changed meanwhile', async t => {
  const { app, call } = await fixture(t);
  const prune = app.store.prune.bind(app.store);
  let release;
  app.store.prune = async (...args) => {
    await new Promise(resolve => (release = resolve));
    return prune(...args);
  };
  const slow = call('/api/settings', 'PATCH', { retentionDays: 7 });
  while (!release) await new Promise(resolve => setTimeout(resolve, 10));
  const queued = call('/api/settings', 'PATCH', { title: 'Changed with the old password' });
  await new Promise(resolve => setTimeout(resolve, 50));
  const next = 'fixture-hardening-rotated';
  const changed = await call('/api/auth/password', 'POST', {
    currentPassword: password,
    password: next,
    confirmPassword: next,
  });
  assert.equal(changed.status, 200);
  release();
  await slow;
  assert.equal((await queued).status, 401);
  assert.notEqual(app.config.value.title, 'Changed with the old password');
});

test('testing a new source with a reserved mapping key explains the problem', async t => {
  const { call } = await fixture(t);
  const response = await call('/api/test-service', 'POST', {
    serviceId: null,
    settings: {
      type: 'linux',
      name: 'New host',
      apiUrl: 'http://node.example.test:9100',
      metrics: [{ key: 'cpu', label: 'CPU', path: 'node_load5' }],
    },
  });
  assert.equal(response.status, 400);
  assert.match(response.body.error, /built-in/);
});

test('IDs of deleted default sources are not reused on a fresh install', async t => {
  const { call } = await fixture(t);
  assert.equal((await call('/api/services/cosmos-3', 'DELETE')).status, 200);
  const added = await call('/api/services', 'POST', { type: 'cosmos', name: 'Cosmos' });
  assert.equal(added.status, 201);
  assert.equal(added.body.service.id, 'cosmos-4');
});

const raw = async (port, route, options = {}) => {
  const response = await fetch(`http://127.0.0.1:${port}${route}`, options);
  return { status: response.status, headers: response.headers, text: await response.text() };
};

test(
  '/health answers without sign-in or version, and says whether this process started',
  { timeout: 30000 },
  async t => {
    const { port, directory, close } = await fixture(t);
    const plain = await raw(port, '/health');
    assert.equal(plain.status, 200);
    assert.deepEqual(JSON.parse(plain.text), { status: 'ok' });
    // A wrong password is not a failed sign-in here: nothing is checked.
    const guessed = await raw(port, '/health', { headers: { Authorization: basic('wrong') } });
    assert.equal(guessed.status, 200);
    const { nonce } = JSON.parse(
      fs.readFileSync(path.join(directory, 'run', 'status.json'), 'utf8')
    );
    const matched = await raw(port, `/health?instance=${nonce}`);
    assert.deepEqual(JSON.parse(matched.text), { status: 'ok', instance: 'match' });
    for (const other of ['', '0'.repeat(32), nonce.slice(1), nonce + '0', nonce.toUpperCase()]) {
      const response = await raw(port, `/health?instance=${encodeURIComponent(other)}`);
      assert.deepEqual(JSON.parse(response.text), { status: 'ok', instance: 'mismatch' }, other);
    }
    for (const response of [plain, matched]) {
      assert.ok(!response.text.includes(nonce));
      assert.doesNotMatch(response.text, /version|build|started/i);
    }
    // While stopping, a request on an open connection hears that Uptime Goblin is going away.
    const socket = net.connect(port, '127.0.0.1');
    t.after(() => socket.destroy());
    await new Promise(resolve => socket.once('connect', resolve));
    let received = '';
    socket.on('data', chunk => (received += chunk));
    const head = `Host: 127.0.0.1:${port}\r\nAuthorization: ${basic(password)}\r\n`;
    socket.write(
      `PATCH /api/settings HTTP/1.1\r\n${head}X-Goblin-Request: 1\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n`
    );
    await new Promise(resolve => setTimeout(resolve, 100));
    const closing = close();
    socket.write(`{}GET /health HTTP/1.1\r\nHost: 127.0.0.1:${port}\r\n\r\n`);
    await new Promise(resolve => socket.once('end', resolve));
    await closing;
    assert.match(received, /HTTP\/1\.1 503[^]*\{"status":"stopping"\}/);
  }
);

test(
  'every answer names the build, refusals included, except /health; only signed-in ones name the version',
  { timeout: 30000 },
  async t => {
    const { app, call, port } = await fixture(t);
    assert.match(app.build, /^[0-9a-f]{12}$/);
    const answers = [
      await raw(port, '/api/dashboard'),
      await raw(port, '/api/dashboard', { headers: { Authorization: basic('wrong') } }),
      await raw(port, '/health'),
      await raw(port, '/'),
      await raw(port, '/', { headers: { Authorization: basic(password) } }),
      await raw(port, '/missing', { headers: { Authorization: basic(password) } }),
      await raw(port, '/api/missing', { headers: { Authorization: basic(password) } }),
      await raw(port, '/api/dashboard', {
        method: 'DELETE',
        headers: { Authorization: basic(password) },
      }),
    ];
    // The page and its files are public in 1.5 (the sign-in view must load): a credential
    // sent to them is not even read.
    assert.deepEqual(
      answers.map(a => a.status),
      [401, 401, 200, 200, 200, 404, 404, 403]
    );
    // Refusals say why, in a form the sign-in page and scripts can act on.
    assert.equal(JSON.parse(answers[0].text).code, 'signin_required');
    assert.equal(JSON.parse(answers[1].text).code, 'invalid_credentials');
    assert.equal(JSON.parse(answers[7].text).code, 'cross_origin');
    const refusedHost = await new Promise((resolve, reject) => {
      const request = http.request(
        { host: '127.0.0.1', port, path: '/health', headers: { Host: 'attacker.example' } },
        response => {
          response.resume();
          resolve(response);
        }
      );
      request.on('error', reject);
      request.end();
    });
    assert.equal(refusedHost.statusCode, 403);
    // Every answer after the Host allowlist names the build, 401 and 403 included (D10): a
    // 1.4.3 tab reloads itself into the sign-in view when a 401 names another build. /health
    // stays version-free. Only signed-in answers (the last two) name the version.
    const signedIn = [6, 7];
    answers.forEach((answer, i) => {
      assert.equal(answer.headers.get('x-goblin-build'), i === 2 ? null : app.build, `answer ${i}`);
      assert.equal(
        answer.headers.get('x-goblin-version'),
        signedIn.includes(i) ? app.version : null,
        `answer ${i}`
      );
    });
    assert.equal(new Headers(refusedHost.headers).get('x-goblin-build'), null);
    assert.equal(new Headers(refusedHost.headers).get('x-goblin-version'), null);
    const version = await call('/api/version');
    assert.equal(version.status, 200);
    assert.deepEqual(version.body, { version: app.version, build: app.build });
    assert.equal((await raw(port, '/api/version')).status, 401);
    assert.equal((await call('/api/version', 'POST', {})).status, 405);
  }
);

test(
  'run/status.json names the process serving and is removed when it stops',
  { timeout: 30000 },
  async t => {
    const { app, call, port, directory, close } = await fixture(t, { trustProxy: 'loopback' });
    const run = path.join(directory, 'run'),
      file = path.join(run, 'status.json'),
      read = () => JSON.parse(fs.readFileSync(file, 'utf8'));
    const status = read();
    assert.deepEqual(status, {
      version: app.version,
      build: app.build,
      pid: process.pid,
      nonce: status.nonce,
      startedAt: status.startedAt,
      listen: { host: '127.0.0.1', port },
      observed: { forwardedProto: null },
    });
    assert.match(status.nonce, /^[0-9a-f]{32}$/);
    assert.ok(status.startedAt <= Date.now() && status.startedAt > Date.now() - 60000);
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    assert.equal(fs.statSync(run).mode & 0o777, 0o700);
    // 1.5: run/ also holds the storage guard's reserve (delivery spec D14); no temporary file.
    assert.deepEqual(fs.readdirSync(run).sort(), ['space-reserve', 'status.json']);
    // Only a request through the trusted proxy records what protocol the proxy reports.
    await call('/api/dashboard');
    assert.equal(read().observed.forwardedProto, null);
    const proxied = proto => ({ 'X-Forwarded-For': '203.0.113.9', 'X-Forwarded-Proto': proto });
    await call('/api/dashboard', 'GET', undefined, proxied('https'));
    assert.equal(read().observed.forwardedProto, 'https');
    await call('/api/dashboard', 'GET', undefined, proxied('http'));
    assert.equal(read().observed.forwardedProto, 'http');
    await call('/api/dashboard', 'GET', undefined, proxied('gopher'));
    assert.equal(read().observed.forwardedProto, 'http');
    await call('/api/dashboard', 'GET', undefined, { 'X-Forwarded-For': '203.0.113.9' });
    assert.equal(read().observed.forwardedProto, 'http', 'a proxy that names no protocol');
    await call('/api/dashboard', 'GET', undefined, { Forwarded: 'for=203.0.113.9;proto=https' });
    assert.equal(read().observed.forwardedProto, 'https');
    assert.equal(read().nonce, status.nonce);
    assert.deepEqual(fs.readdirSync(run).sort(), ['space-reserve', 'status.json']);
    await close();
    assert.equal(fs.existsSync(file), false);
    // Another process's file (a newer start) is left alone.
    const second = await fixture(t);
    const replaced = {
      ...JSON.parse(fs.readFileSync(path.join(second.directory, 'run', 'status.json'))),
      nonce: 'f'.repeat(32),
    };
    fs.writeFileSync(path.join(second.directory, 'run', 'status.json'), JSON.stringify(replaced));
    await second.close();
    assert.ok(fs.existsSync(path.join(second.directory, 'run', 'status.json')));
  }
);

test(
  'the System page lists the web app builds seen in the last 10 minutes',
  { timeout: 30000 },
  async t => {
    const { app, call, port } = await fixture(t);
    // A request carrying X-Goblin-Client is a browser's, whose Basic header is ignored: the
    // tabs sign in with a session. The "legacy" tab (before 1.4.3) sends no X-Goblin-Client,
    // so it is a script-style Basic request.
    const base = `http://127.0.0.1:${port}`;
    const { cookie } = await signIn(base, password);
    const tab = sessionCall(base, cookie);
    const as = client => tab('/api/dashboard', 'GET', undefined, { 'X-Goblin-Client': client });
    assert.equal((await as(`web/${app.build}`)).status, 200);
    assert.equal((await as('web/0123456789ab')).status, 200);
    assert.equal((await call('/api/dashboard')).status, 200); // a tab from before 1.4.3
    assert.equal((await as('curl/8.0')).status, 200);
    const { clients } = (await call('/api/system')).body;
    assert.deepEqual(
      clients.map(c => [c.build, c.current]),
      [
        [null, false],
        ['0123456789ab', false],
        [app.build, true],
      ]
    );
    for (const c of clients) assert.ok(Math.abs(Date.now() - c.lastSeen) < 60000);
  }
);

/** Runs server.mjs as a program; resolves to its exit code, signal and output. */
function launch(t, { env = {}, args = [], script = path.join(root, 'server.mjs'), stop } = {}) {
  const directory = temporary(t);
  const child = spawn(process.execPath, [...args, script], {
    env: {
      PATH: process.env.PATH,
      HOST: '127.0.0.1',
      PORT: freePortSync(),
      GOBLIN_DATA_DIR: path.join(directory, 'data'),
      GOBLIN_PASSWORD: password,
      ...env,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  t.after(() => child.kill('SIGKILL'));
  let stdout = '',
    stderr = '',
    stopping = false;
  child.stdout.on('data', chunk => {
    stdout += chunk;
    // Once: what Uptime Goblin prints while it stops must not call `stop` again, after Uptime Goblin may have
    // removed the run/status.json that `stop` reads.
    if (stop && !stopping && /Uptime Goblin is ready/.test(stdout)) {
      stopping = true;
      stop(child, path.join(directory, 'data'));
    }
  });
  child.stderr.on('data', chunk => (stderr += chunk));
  return new Promise(resolve =>
    child.on('exit', (code, signal) => resolve({ code, signal, stdout, stderr, directory }))
  );
}

// Uptime Goblin prints more once it is told to stop (the audit checkpoint of its stop entry, for one),
// and a `stop` called again for that output found run/status.json already removed (in 2 to 5 of
// 10 runs in a container). A stand-in that prints twice while it stops makes that certain.
test('launch() calls stop once, whatever the program prints after it is ready', async t => {
  const script = path.join(temporary(t), 'stand-in.mjs');
  fs.writeFileSync(
    script,
    [
      'let stopping = false;',
      "process.on('SIGTERM', () => {",
      '  if (stopping) return;',
      '  stopping = true;',
      "  console.log('Stand-in stopping');",
      "  setTimeout(() => (console.log('Stand-in stopped'), process.exit(0)), 200);",
      '});',
      "console.log('Uptime Goblin is ready at http://127.0.0.1:0');",
      'setTimeout(() => {}, 20000);',
      '',
    ].join('\n')
  );
  let calls = 0;
  const stopped = await launch(t, {
    script,
    stop: child => {
      calls++;
      child.kill('SIGTERM');
    },
  });
  assert.equal(stopped.code, 0, stopped.stderr);
  assert.match(stopped.stdout, /Stand-in stopping\n(?:.|\n)*Stand-in stopped/);
  assert.equal(calls, 1);
});

test(
  'a stop signal during the readiness announcement shuts down cleanly',
  { timeout: 30000 },
  async t => {
    for (const signal of ['SIGTERM', 'SIGINT']) {
      // Send the signal before console.log returns, so a handler installed after the
      // announcement is too late. Hold JS briefly so the OS delivers it at that point.
      const preload = `
      const log = console.log;
      console.log = (...args) => {
        log(...args);
        if (String(args[0]).startsWith('Uptime Goblin is ready at ')) {
          process.kill(process.pid, ${JSON.stringify(signal)});
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);
        }
      };
    `;
      const stopped = await launch(t, {
        env: supervisedEnv(),
        args: ['--import', `data:text/javascript,${encodeURIComponent(preload)}`],
      });
      assert.match(stopped.stdout, /Uptime Goblin is ready at /);
      assert.equal(stopped.signal, null, `${signal} must reach Uptime Goblin's shutdown handler`);
      assert.equal(stopped.code, 0, stopped.stderr);
      assert.equal(
        fs.existsSync(path.join(stopped.directory, 'data', 'run', 'status.json')),
        false
      );
    }
  }
);

test(
  'under a service manager Uptime Goblin exits 0 only when stopped by a signal',
  { timeout: 30000 },
  async t => {
    const supervised = supervisedEnv();
    // Stopped with SIGTERM: 0, and its run/status.json is gone. A line printed as the process
    // exits, after run/status.json is gone, holds launch() to calling `stop` once: a call at that
    // line would read the file that is no longer there.
    let running = null;
    const late = `import fs from 'node:fs'; process.on('exit', () => fs.writeSync(1, 'a line after run/status.json is gone\\n'));`;
    const stopped = await launch(t, {
      env: supervised,
      args: ['--import', `data:text/javascript,${encodeURIComponent(late)}`],
      stop: (child, data) => {
        running = JSON.parse(fs.readFileSync(path.join(data, 'run', 'status.json'), 'utf8'));
        assert.equal(running.pid, child.pid);
        child.kill('SIGTERM');
      },
    });
    assert.equal(stopped.code, 0);
    assert.match(stopped.stdout, /a line after run\/status\.json is gone\n/);
    assert.ok(running, 'status.json was written once Uptime Goblin was ready');
    assert.equal(fs.existsSync(path.join(stopped.directory, 'data', 'run', 'status.json')), false);
    // Anything else that ends the process with 0 is reported as a failure, so it is restarted.
    const exitZero = [
      '--import',
      `data:text/javascript,${encodeURIComponent('setTimeout(() => process.exit(0), 1500)')}`,
    ];
    const unexpected = await launch(t, { env: supervised, args: exitZero });
    assert.equal(unexpected.code, 1);
    assert.match(unexpected.stderr, /no stop signal/);
    const unsupervised = await launch(t, { args: exitZero });
    assert.equal(unsupervised.code, 0);
    assert.match(unsupervised.stderr, /no stop signal/, 'never silent, even when not supervised');
  }
);

test(
  'a stop signal that arrives while Uptime Goblin binds its port is a clean stop',
  { timeout: 30000 },
  async t => {
    // The signal is raised inside listen(), before Uptime Goblin could announce itself: a service
    // manager stopping a starting unit, or a test stopping it as soon as it is ready. Without
    // a handler in place, SIGTERM's default action would end the process (no exit status) and
    // leave run/status.json behind.
    const stopDuringListen = [
      '--import',
      `data:text/javascript,${encodeURIComponent(
        [
          "import http from 'node:http';",
          'const listen = http.Server.prototype.listen;',
          'http.Server.prototype.listen = function (...args) {',
          "  process.kill(process.pid, 'SIGTERM');",
          '  return listen.apply(this, args);',
          '};',
        ].join('\n')
      )}`,
    ];
    const stopped = await launch(t, { env: supervisedEnv(), args: stopDuringListen });
    assert.equal(stopped.signal, null, stopped.stderr);
    assert.equal(stopped.code, 0, stopped.stderr);
    assert.doesNotMatch(stopped.stderr, /no stop signal/);
    assert.equal(fs.existsSync(path.join(stopped.directory, 'data', 'run', 'status.json')), false);
  }
);

test(
  'a refused start exits 78, and a start that may succeed later exits 1',
  { timeout: 30000 },
  async t => {
    const supervised = supervisedEnv();
    // No admin password (GOBLIN_PASSWORD empty, no auth.json): refused on any address, with
    // passwordRequiredMessage as the line before the refusal line.
    const noPassword = await launch(t, {
      env: { ...supervised, HOST: '0.0.0.0', GOBLIN_PASSWORD: '' },
    });
    assert.equal(noPassword.code, 78);
    const lines = noPassword.stderr.trimEnd().split('\n');
    const refusal = lines.indexOf(
      'Uptime Goblin refused to start (exit status 78). Correct the problem above, then start Uptime Goblin again.'
    );
    assert.ok(refusal > 0, noPassword.stderr);
    assert.equal(lines[refusal - 1], passwordRequiredMessage, noPassword.stderr);
    const proxy = await launch(t, { env: { ...supervised, GOBLIN_TRUST_PROXY: 'not-an-address' } });
    assert.equal(proxy.code, 78);
    // A corrupt configuration file.
    const corrupt = temporary(t);
    fs.writeFileSync(path.join(corrupt, 'config.json'), '{not json', { mode: 0o600 });
    const broken = await launch(t, { env: { ...supervised, GOBLIN_DATA_DIR: corrupt } });
    assert.equal(broken.code, 78);
    // The port is taken (say, by the process being replaced): starting again may work.
    const blocker = net.createServer();
    await new Promise(resolve => blocker.listen(0, '127.0.0.1', resolve));
    t.after(() => blocker.close());
    const busy = await launch(t, { env: { ...supervised, PORT: String(blocker.address().port) } });
    assert.equal(busy.code, 1);
    assert.match(busy.stderr, /EADDRINUSE/);
    // Started through another file named server.mjs: refused, never a silent exit 0.
    const wrapper = path.join(temporary(t), 'server.mjs');
    fs.writeFileSync(wrapper, `import ${JSON.stringify(path.join(root, 'server.mjs'))};\n`);
    const wrapped = await launch(t, { script: wrapper });
    assert.equal(wrapped.code, 78);
    assert.match(wrapped.stderr, /does not resolve to this file/);
  }
);

test('Uptime Goblin tells being started from being imported, through any symlink', t => {
  const self = path.join(root, 'server.mjs'),
    directory = temporary(t),
    link = path.join(directory, 'orbit.mjs'),
    other = path.join(directory, 'server.mjs');
  fs.symlinkSync(self, link);
  fs.writeFileSync(other, '');
  assert.equal(launchKind({ argv1: self, self }), 'main');
  assert.equal(launchKind({ argv1: link, self }), 'main');
  assert.equal(launchKind({ argv1: undefined, self }), 'library');
  assert.equal(launchKind({ argv1: fileURLToPath(import.meta.url), self }), 'library');
  assert.equal(launchKind({ argv1: path.join(directory, 'missing.mjs'), self }), 'library');
  // Cannot tell: refuse (exit 78) rather than exit silently.
  assert.equal(launchKind({ argv1: other, self }), 'unknown');
  assert.equal(launchKind({ argv1: path.join(directory, 'gone', 'server.mjs'), self }), 'unknown');
  const vanished = () => {
    throw Object.assign(new Error('no such file'), { code: 'ENOENT' });
  };
  assert.equal(launchKind({ argv1: self, self, realpath: vanished }), 'unknown');
  // Only refusals Uptime Goblin checked itself exit 78; everything else is retried.
  const refusal = Object.assign(new Error('Set GOBLIN_PASSWORD before listening'), {
    refusal: true,
  });
  assert.equal(startupExitCode(refusal), 78);
  assert.equal(startupExitCode(new InputError('Choose a source type')), 78);
  assert.equal(startupExitCode(new SyntaxError('Unexpected token')), 78);
  for (const failure of [
    Object.assign(new Error('x'), { code: 'ENOSPC' }),
    Object.assign(new Error('x'), { code: 'EDQUOT' }),
    Object.assign(new Error('x'), { code: 'EROFS' }),
    Object.assign(new Error('database or disk is full'), { errcode: 13 }),
    Object.assign(new Error('disk I/O error'), { errcode: 10 | (4 << 8) }),
    Object.assign(new Error('out of memory'), { errcode: 7 }),
    new Error('something unexpected'),
  ])
    assert.equal(startupExitCode(failure), 1, failure.message);
});

// One request on its own connection, written byte for byte (repeated or missing headers, any
// request target); resolves to {status, text}.
function rawRequest(port, text) {
  return new Promise((resolve, reject) => {
    const socket = net.connect(port, '127.0.0.1', () => socket.write(text));
    let answer = '';
    socket.on('data', chunk => (answer += chunk));
    socket.on('end', () => resolve({ status: Number(answer.split(' ')[1]), text: answer }));
    socket.on('error', reject);
  });
}

test('malformed request addresses get 400 before sign-in and are not logged as failures', async t => {
  const { port } = await fixture(t);
  const errors = [];
  t.mock.method(console, 'error', (...args) => errors.push(args.join(' ')));
  const host = `Host: 127.0.0.1:${port}`;
  for (const target of ['//[', 'http://[', '//a:b@[x/']) {
    const { status } = await rawRequest(
      port,
      `GET ${target} HTTP/1.1\r\n${host}\r\nConnection: close\r\n\r\n`
    );
    assert.equal(status, 400, target);
  }
  // Targets the URL parser reads as another authority ('//x', '/\\x') or as an absolute URL:
  // Uptime Goblin would serve their path while a proxy rule written for that path (a sign-in rate
  // limit) never matched them. Refused with valid credentials too, and nothing signs in.
  const credentials = `Authorization: ${basic(password)}`;
  for (const target of [
    '//x/api/session',
    '/\\x/api/session',
    'http://evil.example/api/session',
    '//x/api/audit/export?format=csv',
    '//x/health',
    '//127.0.0.1/api/version',
  ]) {
    const answer = await rawRequest(
      port,
      `GET ${target} HTTP/1.1\r\n${host}\r\n${credentials}\r\nConnection: close\r\n\r\n`
    );
    assert.equal(answer.status, 400, target);
    assert.match(answer.text, /Malformed request address/, target);
  }
  const body = JSON.stringify({ login: 'admin', password });
  for (const target of ['//x/api/auth/login', '/\\x/api/auth/login', 'http://x/api/auth/login']) {
    const signIn = await rawRequest(
      port,
      [
        `POST ${target} HTTP/1.1`,
        host,
        `Origin: http://127.0.0.1:${port}`,
        'X-Goblin-Request: 1',
        'Content-Type: application/json',
        `Content-Length: ${body.length}`,
        'Connection: close',
        '',
        body,
      ].join('\r\n')
    );
    assert.equal(signIn.status, 400, target);
    assert.doesNotMatch(signIn.text, /set-cookie/i, target);
  }
  // A backslash in the query is data, not part of the address.
  const query = await rawRequest(
    port,
    `GET /api/version?x=a\\b HTTP/1.1\r\n${host}\r\n${credentials}\r\nConnection: close\r\n\r\n`
  );
  assert.equal(query.status, 200);
  assert.deepEqual(errors, []);
});

test('a request with no Host or several Host lines is refused 400', async t => {
  const { port } = await fixture(t);
  const host = `Host: 127.0.0.1:${port}`,
    credentials = `Authorization: ${basic(password)}`;
  const status = async (...lines) =>
    (await rawRequest(port, [...lines, credentials, 'Connection: close', '', ''].join('\r\n')))
      .status;
  assert.equal(await status('GET /api/version HTTP/1.1', host), 200);
  // Node keeps the first Host line: a front end that honours the last would decide otherwise.
  assert.equal(await status('GET /api/version HTTP/1.1', host, 'Host: evil.example'), 400);
  assert.equal(await status('GET /api/version HTTP/1.1', 'Host: evil.example', host), 400);
  assert.equal(await status('GET /api/version HTTP/1.1', host, host), 400);
  // HTTP/1.0 may leave Host out (Node refuses that for HTTP/1.1 itself); Uptime Goblin refuses both.
  assert.equal(await status('GET /api/version HTTP/1.0'), 400);
  assert.equal(await status('GET /health HTTP/1.0'), 400);
});

test('only problems with the files themselves refuse a start; disk trouble is retried', t => {
  // A valid saved auth.json on a disk that is now read-only: the record still loads (identity
  // reads it, then tightens its mode as housekeeping).
  const saved = temporary(t);
  fs.writeFileSync(
    path.join(saved, 'auth.json'),
    JSON.stringify({
      version: 1,
      algorithm: 'scrypt',
      parameters: { N: 32768, r: 8, p: 3, keyLength: 64 },
      salt: '07'.repeat(32),
      hash: '0a'.repeat(64),
      passwordChangedAt: 123456,
    }),
    { mode: 0o600 }
  );
  const warnings = [];
  const readOnly = t.mock.method(fs, 'fchmodSync', () => {
    throw Object.assign(new Error('read-only file system'), { code: 'EROFS' });
  });
  assert.equal(readAuthRecord(saved).record.passwordChangedAt, 123456);
  tightenAuthRecord(saved, { warn: (...args) => warnings.push(args.join(' ')) });
  readOnly.mock.restore();
  assert.match(warnings.join('\n'), /could not be tightened: EROFS/);
  // Reading auth.json fails on the disk itself: retried, not a refusal.
  const failing = t.mock.method(fs, 'openSync', () => {
    throw Object.assign(new Error('input/output error'), { code: 'EIO' });
  });
  assert.throws(
    () => readAuthRecord(saved),
    e => e.code === 'EIO' && startupExitCode(e) === 1
  );
  failing.mock.restore();
  // Contents Uptime Goblin cannot use are refusals that say what is wrong.
  for (const [name, content] of [
    ['null', 'null'],
    ['null source', JSON.stringify({ services: [null] })],
    ['numeric ID', JSON.stringify({ services: [{ id: 7, type: 'linux' }] })],
    ['unknown type', JSON.stringify({ services: [{ id: 'future-1', type: 'future-type' }] })],
    ['missing type', JSON.stringify({ services: [{ id: 'linux-9' }] })],
    ['not JSON', '{not json'],
  ]) {
    const dir = temporary(t);
    fs.writeFileSync(path.join(dir, 'config.json'), content, { mode: 0o600 });
    assert.throws(
      () => new ConfigStore(dir),
      e =>
        e.refusal === true &&
        startupExitCode(e) === 78 &&
        /Invalid configuration file/.test(e.message),
      name
    );
  }
});
