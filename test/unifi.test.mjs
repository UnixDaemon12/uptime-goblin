import test from 'node:test';
import assert from 'node:assert/strict';
import { CollectionError, collect, resetCollector, transport } from '../lib/collectors.mjs';
import { newService, publicConfig } from '../lib/catalog.mjs';
import { configureDestinations } from '../lib/destinations.mjs';
// Fixture hostnames resolve instantly to a documentation address, never via real DNS.
configureDestinations({ lookup: async () => [{ address: '192.0.2.1' }] });

// Field shapes match the sanitized live UniFi OS / Network responses inspected
// on 2026-09-25. Identities and values here are test fixtures, not live readings.
const local = (id = 'unifi-test') => ({
  ...newService('unifi', id),
  apiUrl: 'https://console.example',
  username: 'test-viewer',
  password: 'test-password',
});
const payload = data => ({ meta: { rc: 'ok' }, data });
const health = () =>
  payload([
    {
      subsystem: 'wan',
      'rx_bytes-r': 1338653,
      'tx_bytes-r': 80383,
      'gw_system-stats': { cpu: '40.0', mem: '89.4', uptime: '224688' },
    },
    { subsystem: 'www', latency: 10 },
  ]);
const devices = () =>
  payload([
    {
      _id: 'ap1',
      name: 'Access point',
      state: 1,
      uptime: 224774,
      'system-stats': { cpu: '8.4', mem: '32.8' },
      uplink: { 'rx_bytes-r': 70590.5, 'tx_bytes-r': 71581.2 },
      x_authkey: 'must-never-leak',
    },
    { _id: 'switch2', name: 'Offline switch', state: 0, 'system-stats': { cpu: '60', mem: '40' } },
  ]);
const clients = () =>
  payload([{ is_wired: true, hostname: 'private-client' }, { is_wired: false }]);
function response(body, status = 200, cookies = []) {
  const headers = new Headers({ 'Content-Type': 'application/json' });
  for (const cookie of cookies) headers.append('Set-Cookie', cookie);
  return new Response(JSON.stringify(body), { status, headers });
}
function mockConsole(t, { id = 'unifi-test', login, read } = {}) {
  const calls = [];
  resetCollector(id);
  t.after(() => resetCollector(id));
  t.mock.method(transport, 'fetch', async (url, options) => {
    calls.push({ url, options });
    assert.equal(options.redirect, 'error');
    assert.ok(options.signal instanceof AbortSignal);
    if (new URL(url).pathname === '/api/auth/login')
      return login
        ? login(options)
        : response({ username: 'test-viewer' }, 200, [
            'TOKEN=test-session; Path=/; Secure; HttpOnly',
            'csrf_token=test-csrf; Expires=Wed, 01 Jan 2031 00:00:00 GMT; Path=/; Secure',
          ]);
    assert.equal(options.method, undefined);
    assert.equal(options.body, undefined);
    assert.equal(options.headers.Cookie, 'TOKEN=test-session; csrf_token=test-csrf');
    if (read) return read(url, options);
    const name = new URL(url).pathname.split('/').pop();
    return response({ health, device: devices, sta: clients }[name]());
  });
  return calls;
}

test('UniFi local login handles multiple cookies and normalizes observed metrics without source payloads', async t => {
  const calls = mockConsole(t),
    service = local();
  const metrics = await collect(service),
    values = Object.fromEntries(metrics.map(m => [m.key, m.value]));
  assert.deepEqual(JSON.parse(calls[0].options.body), {
    username: 'test-viewer',
    password: 'test-password',
  });
  assert.equal(values.devices, 2);
  assert.equal(values.devices_online, 1);
  assert.equal(values.devices_offline, 1);
  assert.equal(values.clients, 2);
  assert.equal(values.clients_wired, 1);
  assert.equal(values.cpu, 40);
  assert.equal(values.wan_receive, 1338653);
  assert.equal(values.wan_latency, 10);
  assert.equal(values.device_ap1_rx, 70590.5);
  assert.ok(!metrics.some(m => m.key.startsWith('device_switch2')));
  for (const secret of [
    'test-password',
    'test-session',
    'test-csrf',
    'must-never-leak',
    'private-client',
  ])
    assert.ok(!JSON.stringify(metrics).includes(secret));
  assert.ok(
    calls
      .slice(1)
      .every(call =>
        call.url.startsWith('https://console.example/proxy/network/api/s/default/stat/')
      )
  );
  await collect(service);
  assert.equal(calls.filter(call => call.url.endsWith('/api/auth/login')).length, 1);
  const publicSource = publicConfig({ services: [service] }).services[0];
  assert.equal(publicSource.passwordConfigured, true);
  assert.equal(publicSource.password, undefined);
});

test('UniFi local missing or invalid readings remain absent and transitional devices are not counted offline', async t => {
  mockConsole(t, {
    read: url =>
      response(
        payload(
          url.endsWith('/health')
            ? [
                {
                  subsystem: 'wan',
                  'rx_bytes-r': -1,
                  'gw_system-stats': { cpu: '101', mem: '', uptime: null },
                },
              ]
            : url.endsWith('/device')
              ? [{ _id: 'x', state: 5, 'system-stats': { cpu: 44 } }]
              : [{}]
        )
      ),
  });
  const values = Object.fromEntries((await collect(local())).map(m => [m.key, m.value]));
  assert.equal(values.devices_offline, 0);
  assert.equal(values.devices_online, 0);
  assert.equal(values.clients, 1);
  for (const key of [
    'cpu',
    'memory',
    'uptime',
    'wan_receive',
    'wan_latency',
    'clients_wired',
    'device_x_cpu',
  ])
    assert.equal(values[key], undefined);
});

test('UniFi local authentication failures never echo provider content or cache a login', async t => {
  let tries = 0;
  mockConsole(t, {
    login: () => {
      tries++;
      return response({ error: 'test-password test-session' }, 401);
    },
  });
  for (let n = 0; n < 2; n++)
    await assert.rejects(
      collect(local()),
      error =>
        /Authentication failed/.test(error.message) &&
        !error.message.includes('test-password') &&
        !error.message.includes('test-session')
    );
  assert.equal(tries, 2);
});

test('UniFi local rejected read keeps the session and uses the configured site name', async t => {
  const calls = mockConsole(t, {
    read: url => {
      assert.ok(url.includes('/s/secondary-site/'));
      return response({ meta: { rc: 'error', msg: 'test-password' }, data: [] });
    },
  });
  const source = { ...local(), siteId: 'secondary-site' };
  await assert.rejects(collect(source), /UniFi rejected the read request/);
  await assert.rejects(collect(source), /UniFi rejected the read request/);
  // A rejected read (wrong site, missing permission) is not a session problem: no new sign-in.
  assert.equal(calls.filter(call => call.url.endsWith('/api/auth/login')).length, 1);
});

test('UniFi local LoginRequired drops the session and signs in once more', async t => {
  let expired = false;
  const calls = mockConsole(t, {
    read: url => {
      const name = new URL(url).pathname.split('/').pop();
      if (expired) {
        expired = false;
        return response({ meta: { rc: 'error', msg: 'api.err.LoginRequired' }, data: [] });
      }
      return response({ health, device: devices, sta: clients }[name]());
    },
  });
  await collect(local()); // signs in and caches the session
  const count = calls.filter(call => call.url.endsWith('/api/auth/login')).length;
  expired = true;
  assert.ok((await collect(local())).length > 0);
  assert.equal(calls.filter(call => call.url.endsWith('/api/auth/login')).length, count + 1);
});

test('UniFi local sign-ins answered with HTTP 429 pause further sign-ins', async t => {
  let logins = 0;
  const calls = mockConsole(t, {
    login: () => {
      logins++;
      return new Response('{}', { status: 429, headers: { 'Retry-After': '120' } });
    },
  });
  await assert.rejects(collect(local()), /limiting sign-ins/);
  for (let i = 0; i < 3; i++) await assert.rejects(collect(local()), /limiting sign-ins/);
  assert.equal(logins, 1);
  assert.equal(calls.length, 1);
});

test('UniFi local timeouts keep the session, so retries do not sign in again', async t => {
  let slow = false;
  const calls = mockConsole(t, {
    read: (url, options) => {
      if (slow)
        return new Promise((_, reject) =>
          options.signal.addEventListener('abort', () =>
            reject(new DOMException('x', 'AbortError'))
          )
        );
      const name = new URL(url).pathname.split('/').pop();
      return response({ health, device: devices, sta: clients }[name]());
    },
  });
  await collect(local());
  slow = true;
  for (let i = 0; i < 3; i++)
    await assert.rejects(collect({ ...local(), requestTimeoutMs: 1000 }), /timed out/);
  slow = false;
  await collect(local());
  assert.equal(calls.filter(call => call.url.endsWith('/api/auth/login')).length, 1);
});

test('UniFi local login requires verified HTTPS console roots and safe local site names', async t => {
  const fetch = t.mock.method(transport, 'fetch', () => {
    throw new Error('Should not request');
  });
  for (const overrides of [
    { apiUrl: 'http://console.example' },
    { apiUrl: 'https://console.example/proxy/network' },
    { siteId: '../other' },
    { password: '' },
  ])
    await assert.rejects(
      collect({ ...local(), ...overrides }),
      /HTTPS console root|site name|local account/
    );
  assert.equal(fetch.mock.callCount(), 0);
});

test('UniFi local abort cancels active reads and keeps the session for the next poll', async t => {
  const controller = new AbortController();
  let entered;
  const ready = new Promise(resolve => (entered = resolve));
  const calls = mockConsole(t, {
    read: (_, options) =>
      new Promise((_, reject) => {
        entered();
        options.signal.addEventListener(
          'abort',
          () => reject(new DOMException('Aborted', 'AbortError')),
          { once: true }
        );
      }),
  });
  const pending = collect({ ...local(), signal: controller.signal });
  await ready;
  controller.abort();
  await assert.rejects(pending, { name: 'AbortError' });
  const count = calls.length;
  await assert.rejects(collect({ ...local(), signal: controller.signal }), { name: 'AbortError' });
  assert.equal(calls.length, count);
  const next = new AbortController();
  const again = collect({ ...local(), signal: next.signal });
  await new Promise(resolve => setImmediate(resolve));
  next.abort();
  await assert.rejects(again);
  // Cancelling a poll says nothing about the session, so it is reused rather than replaced.
  assert.equal(calls.filter(call => call.url.endsWith('/api/auth/login')).length, 1);
});

test('UniFi local rejects missing, malformed and excessive session cookies', async t => {
  for (const cookies of [
    [],
    ['TOKEN=has a space; Path=/'],
    ['TOKEN=' + 'x'.repeat(17000) + '; Path=/'],
  ]) {
    mockConsole(t, { login: () => response({}, 200, cookies) });
    await assert.rejects(collect(local()), /login failed|invalid session cookie|cookies exceed/);
    t.mock.restoreAll();
  }
});

test('UniFi local retains the bounded response body limit', async t => {
  mockConsole(t, { read: () => new Response('x'.repeat(16 * 1024 * 1024 + 1)) });
  await assert.rejects(collect(local()), /16 MB collection limit/);
});

test('UniFi Integration API key keeps priority and existing pagination', async t => {
  const calls = [];
  t.mock.method(transport, 'fetch', async (url, options) => {
    calls.push(url);
    assert.equal(options.headers['X-API-KEY'], 'test-api-key');
    assert.equal(options.headers.Cookie, undefined);
    assert.equal(options.body, undefined);
    const u = new URL(url),
      offset = Number(u.searchParams.get('offset'));
    if (u.pathname.endsWith('/v1/sites'))
      return response({ data: [{ id: offset ? 'site2' : 'site1' }], totalCount: 2 });
    if (u.pathname.endsWith('/devices'))
      return response({ data: [{ id: 'one', state: 'OFFLINE' }], totalCount: 1 });
    return response({ data: [{}, {}], totalCount: 2 });
  });
  const values = Object.fromEntries(
    (await collect({ ...local(), apiKey: 'test-api-key' })).map(m => [m.key, m.value])
  );
  assert.equal(values.sites, 2);
  assert.equal(values.devices, 2);
  assert.equal(values.clients, 4);
  assert.ok(calls.some(url => url.includes('offset=1')));
  assert.ok(!calls.some(url => url.includes('/api/auth/login')));
});

test('an expiring UniFi session is still used when renewing it fails', async t => {
  let now = Date.UTC(2031, 0, 1);
  t.mock.method(Date, 'now', () => now);
  const jwt = exp =>
    'h.' +
    Buffer.from(JSON.stringify({ exp: Math.floor(exp / 1000) })).toString('base64url') +
    '.s';
  let logins = 0,
    failLogin = false;
  resetCollector('unifi-test');
  t.after(() => resetCollector('unifi-test'));
  t.mock.method(transport, 'fetch', async url => {
    if (new URL(url).pathname === '/api/auth/login') {
      logins++;
      return failLogin
        ? response({}, 503)
        : response({}, 200, [`TOKEN=${jwt(now + 60 * 60 * 1000)}; Path=/; Secure`]);
    }
    const name = new URL(url).pathname.split('/').pop();
    return response({ health, device: devices, sta: clients }[name]());
  });
  await collect(local());
  // 57 minutes later the session is due for renewal (5 min before expiry) but still valid.
  now += 57 * 60 * 1000;
  failLogin = true;
  assert.ok((await collect(local())).length > 0);
  assert.equal(logins, 2);
  // After the token's real expiry a failed renewal is an error again.
  now += 5 * 60 * 1000;
  await assert.rejects(collect(local()), /HTTP 503/);
});

test('a sign-in rate limit without Retry-After pauses sign-ins for one minute', async t => {
  let now = Date.UTC(2031, 0, 1),
    limited = true;
  t.mock.method(Date, 'now', () => now);
  let logins = 0;
  mockConsole(t, {
    login: () => {
      logins++;
      return limited
        ? response({}, 429)
        : response({}, 200, ['TOKEN=test-session; Path=/; Secure', 'csrf_token=test-csrf; Path=/']);
    },
  });
  await assert.rejects(collect(local()), /limiting sign-ins/);
  now += 30 * 1000;
  await assert.rejects(collect(local()), /limiting sign-ins/);
  assert.equal(logins, 1);
  now += 31 * 1000;
  limited = false;
  assert.ok((await collect(local())).length > 0);
  assert.equal(logins, 2);
});

test('UniFi key mode finds the Integration API from the address path, not the host name', async t => {
  const calls = [];
  t.mock.method(transport, 'fetch', async url => {
    calls.push(url);
    return new URL(url).pathname.endsWith('/v1/sites')
      ? response({ data: [{ id: 'site1' }], totalCount: 1 })
      : response({ data: [], totalCount: 0 });
  });
  for (const [apiUrl, sites] of [
    [
      'https://integration.example.com',
      'https://integration.example.com/proxy/network/integration/v1/sites?',
    ],
    [
      'https://console.example/proxy/network/integration',
      'https://console.example/proxy/network/integration/v1/sites?',
    ],
  ]) {
    calls.length = 0;
    await collect({ ...local(), apiUrl, apiKey: 'test-api-key' });
    assert.ok(calls[0].startsWith(sites), calls[0]);
  }
});

// Key-mode inventory with ten online devices; `statistics` answers each device's detail read.
function keyModeConsole(t, statistics) {
  t.mock.method(transport, 'fetch', async (url, options) => {
    const path = new URL(url).pathname;
    if (path.endsWith('/v1/sites')) return response({ data: [{ id: 'site1' }], totalCount: 1 });
    if (path.endsWith('/devices'))
      return response({
        data: Array.from({ length: 10 }, (_, i) => ({ id: 'd' + i, state: 'ONLINE' })),
        totalCount: 10,
      });
    if (path.endsWith('/clients')) return response({ data: [{}, {}], totalCount: 2 });
    return statistics(path.split('/').at(-3), options.signal);
  });
}
const counts = values => [values.sites, values.devices, values.devices_online, values.clients];

test('UniFi key mode skips a device whose statistics are not an object', async t => {
  keyModeConsole(t, id =>
    response(id === 'd1' ? null : id === 'd2' ? [1] : { cpuUtilizationPct: 12, uptimeSec: 5 })
  );
  const values = Object.fromEntries(
    (await collect({ ...local(), apiKey: 'test-api-key' })).map(m => [m.key, m.value])
  );
  assert.deepEqual(counts(values), [1, 10, 10, 2]);
  assert.equal(values.device_d0_cpu, 12);
  assert.equal(values.device_d1_cpu, undefined);
  assert.equal(values.device_d2_cpu, undefined);
  assert.equal(values.device_d3_uptime, 5);
});

test('UniFi key-mode device detail has a bounded share of the collection time', async t => {
  // One device answers; the others hang until their read is cancelled.
  keyModeConsole(t, (id, signal) =>
    id === 'd0'
      ? response({ cpuUtilizationPct: 12 })
      : new Promise((_, reject) =>
          signal.addEventListener('abort', () => reject(new DOMException('x', 'AbortError')), {
            once: true,
          })
        )
  );
  const started = performance.now();
  // A 1.2 s request limit (the server passes a quarter of the deadline) and a 4 s deadline:
  // nine hung reads of up to 1.2 s each would use up the deadline and lose the counts.
  const metrics = await collect({
    ...local(),
    apiKey: 'test-api-key',
    requestTimeoutMs: 1200,
    signal: AbortSignal.timeout(4000),
  });
  const values = Object.fromEntries(metrics.map(m => [m.key, m.value]));
  assert.deepEqual(counts(values), [1, 10, 10, 2]);
  assert.equal(values.device_d0_cpu, 12);
  assert.ok(performance.now() - started < 3000);
});

test('UniFi key-mode pagination is bounded by pages, sites and requests whatever totalCount says', async t => {
  // A broken or hostile controller: one entry per page and a total of a billion, on every list.
  let requests = 0;
  t.mock.method(transport, 'fetch', async url => {
    requests++;
    return response({ data: [{ id: 's' + requests }], totalCount: 1e9 });
  });
  const started = performance.now();
  await assert.rejects(
    collect({ ...local(), apiKey: 'test-api-key' }),
    error =>
      error instanceof CollectionError &&
      error.message ===
        'UniFi lists took more than 1,000 requests in one collection. Enter one site ID, or check the controller.' &&
      error.retryable === false
  );
  await new Promise(resolve => setImmediate(resolve));
  assert.ok(requests <= 1000, `${requests} requests`);
  assert.ok(performance.now() - started < 10000);
  t.mock.restoreAll();

  // One site, listed again on every page (the controller ignores the offset), is read once;
  // its sites, devices and clients lists stop at 100 pages each, and say so.
  requests = 0;
  t.mock.method(transport, 'fetch', async url => {
    requests++;
    const path = new URL(url).pathname;
    return response({ data: [{ id: path.endsWith('/v1/sites') ? 's1' : 'x' }], totalCount: 1e9 });
  });
  const readings = await collect({ ...local(), apiKey: 'test-api-key', siteId: 's1' });
  const values = Object.fromEntries(readings.map(m => [m.key, m.value]));
  assert.deepEqual([values.sites, values.devices, values.clients], [1, 100, 100]);
  assert.equal(requests, 300);
  assert.deepEqual(
    readings.notes.map(n => n.code),
    ['unifi_lists_capped']
  );
  // The note names the page limit that stopped these lists at 100 entries, not only the
  // 20,000-entry one, which blamed a cap the lists never reached.
  assert.equal(
    readings.notes[0].message,
    'UniFi lists are read up to 20,000 entries or 100 pages each, so devices, clients or sites beyond that are left out of the counts.'
  );
  t.mock.restoreAll();

  // Devices and clients are read for the first 50 sites.
  const paths = [];
  t.mock.method(transport, 'fetch', async url => {
    const path = new URL(url).pathname;
    paths.push(path);
    if (path.endsWith('/v1/sites'))
      return response({
        data: Array.from({ length: 60 }, (_, i) => ({ id: 'site' + i })),
        totalCount: 60,
      });
    return response({ data: [], totalCount: 0 });
  });
  const many = await collect({ ...local(), apiKey: 'test-api-key' });
  assert.equal(paths.length, 1 + 50 * 2);
  assert.ok(!paths.some(path => path.includes('/site50/')));
  assert.equal(Object.fromEntries(many.map(m => [m.key, m.value])).sites, 60);
  assert.deepEqual(many.notes, [
    {
      code: 'unifi_sites_capped',
      message: 'Device and client readings cover the first 50 UniFi sites; 10 more are left out.',
      omitted: 10,
    },
  ]);
  t.mock.restoreAll();

  // A total that is not a whole number of entries is no UniFi answer.
  for (const totalCount of ['many', -1, 1.5, 1e300, { n: 1 }]) {
    t.mock.method(transport, 'fetch', async () => response({ data: [{ id: 's1' }], totalCount }));
    await assert.rejects(
      collect({ ...local(), apiKey: 'test-api-key' }),
      /Source returned an unexpected response/,
      JSON.stringify(totalCount)
    );
    t.mock.restoreAll();
  }
});

test('a UniFi page longer than the requested limit is capped and noted without a RangeError', async t => {
  // 160,000 sites in one page: spreading it into push() overflowed the call stack, and the
  // RangeError's own text was shown. 25,000 clients in one page were counted in full.
  t.mock.method(transport, 'fetch', async url => {
    const path = new URL(url).pathname;
    if (path.endsWith('/v1/sites'))
      return response({ data: Array.from({ length: 160000 }, (_, i) => ({ id: 's' + i })) });
    if (path.endsWith('/clients'))
      return response({ data: Array.from({ length: 25000 }, () => ({})), totalCount: 25000 });
    return response({ data: [], totalCount: 0 });
  });
  const readings = await collect({ ...local(), apiKey: 'test-api-key', siteId: 's7' });
  const values = Object.fromEntries(readings.map(m => [m.key, m.value]));
  assert.equal(values.clients, 20000);
  assert.equal(values.sites, 1);
  assert.deepEqual(
    readings.notes.map(n => n.code),
    ['unifi_lists_capped']
  );
  // Without a site ID: the first 20,000 sites are listed, devices and clients read for 50.
  t.mock.restoreAll();
  t.mock.method(transport, 'fetch', async url =>
    new URL(url).pathname.endsWith('/v1/sites')
      ? response({ data: Array.from({ length: 160000 }, (_, i) => ({ id: 's' + i })) })
      : response({ data: [], totalCount: 0 })
  );
  const all = await collect({ ...local(), apiKey: 'test-api-key' });
  assert.equal(Object.fromEntries(all.map(m => [m.key, m.value])).sites, 20000);
  assert.deepEqual(
    all.notes.map(n => [n.code, n.omitted]),
    [
      ['unifi_lists_capped', undefined],
      ['unifi_sites_capped', 19950],
    ]
  );
});
