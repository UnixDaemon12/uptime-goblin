import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createApp } from '../server.mjs';
import { configureDestinations } from '../lib/destinations.mjs';
import { resetCollector, transport } from '../lib/collectors.mjs';

// Fixture hostnames resolve instantly to a documentation address, never via real DNS.
configureDestinations({ lookup: async () => [{ address: '192.0.2.1' }] });

const password = 'fixture-api-password';
const measurement = value => [{ key: 'cpu', label: 'CPU', value, unit: '%' }];
async function fixture(t, options = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-api-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
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
  t.after(() => app.close());
  const call = async (route, method = 'GET', body, headers = {}, signal) => {
    const response = await fetch(`http://127.0.0.1:${port}${route}`, {
      method,
      headers: {
        Authorization: 'Basic ' + Buffer.from('admin:' + password).toString('base64'),
        'Content-Type': 'application/json',
        'X-Goblin-Request': '1',
        ...headers,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal,
    });
    return { status: response.status, headers: response.headers, body: await response.json() };
  };
  return { app, call, port, directory };
}

// The payload public/app.js connectionInput() builds for the source editor.
const editorPayload = {
  type: 'linux',
  name: 'Linux systems',
  group: 'Infrastructure',
  color: 'cyan',
  url: '',
  apiUrl: 'http://node.example.test:9100',
  enabled: true,
  showOnDashboard: true,
  pollSeconds: 0,
  collector: 'native',
  metricPath: '',
  siteId: '',
  nodeName: '',
  httpMethod: 'GET',
  httpExpectedStatus: '200-399',
  monitoring: {
    retryCount: null,
    retryDelaySeconds: null,
    timeoutSeconds: null,
    availabilityFailures: null,
    availabilitySeconds: null,
    recoverySuccesses: null,
    recoverySeconds: null,
  },
  alerts: { notifyAvailability: null, notifyMeasurements: null },
  rules: [{ key: 'cpu', threshold: 90, forSeconds: 120, operator: 'gt', recoveryThreshold: 85 }],
  username: '',
  apiKey: 'fixture-key',
  metrics: [],
};

test('unknown fields are rejected by settings, sources, the connection test, sign-in and the password change; refresh, sign-out and the deletes take no body', async t => {
  const { app, call, port } = await fixture(t);
  const before = JSON.stringify(app.config.value);
  const rejected = [
    ['/api/settings', 'PATCH', { extra: 1 }],
    ['/api/settings', 'PATCH', { monitoring: { concurrency: 2, bogus: 1 } }],
    ['/api/settings', 'PATCH', { email: { passwordConfigured: true } }],
    ['/api/settings', 'PATCH', { appearance: { theme: 'dark' } }],
    ['/api/settings', 'PATCH', { alerts: { enabled: true, loud: true } }],
    ['/api/settings', 'PATCH', { services: [] }],
    ['/api/services/linux', 'PATCH', { apiUrl: 'http://node.example.test', icon: 'x' }],
    ['/api/services/linux', 'PATCH', { monitoring: { concurrency: 2 } }],
    [
      '/api/services/linux',
      'PATCH',
      { rules: [{ key: 'cpu', operator: 'gt', threshold: 1, x: 1 }] },
    ],
    ['/api/services/linux', 'PATCH', { metrics: [{ key: 'a', path: 'a', label: 'A', extra: 1 }] }],
    ['/api/services', 'POST', { type: 'json', name: 'X', id: 'chosen-id' }],
    ['/api/test-service', 'POST', { settings: {}, extra: true }],
    ['/api/test-service', 'POST', { settings: { type: 'json', apiUrl: 'http://a.test', x: 1 } }],
  ];
  for (const [route, method, body] of rejected) {
    const result = await call(route, method, body);
    assert.equal(result.status, 400, `${method} ${route} ${JSON.stringify(body)}`);
    assert.match(result.body.error, /Unknown .* field/);
  }
  assert.equal(JSON.stringify(app.config.value), before);

  // Sign-in and the password change take exactly their fields: another one is refused as a
  // malformed request (never echoed), and nothing signs in or changes.
  const page = { Authorization: '', Origin: `http://127.0.0.1:${port}` };
  const signIn = await call(
    '/api/auth/login',
    'POST',
    { login: 'admin', password, remmeber: true },
    page
  );
  assert.equal(signIn.status, 400);
  assert.equal(signIn.body.code, 'invalid_request');
  assert.equal(signIn.headers.get('set-cookie'), null);
  assert.doesNotMatch(JSON.stringify(signIn.body), /remmeber/);
  const replacement = 'fixture-api-password-replaced';
  for (const extra of [{ otp: '123456' }, { currentPassword2: password }]) {
    const change = await call('/api/account/password', 'POST', {
      currentPassword: password,
      password: replacement,
      confirmPassword: replacement,
      ...extra,
    });
    assert.equal(change.status, 400, JSON.stringify(extra));
    assert.equal(change.body.code, 'invalid_request');
  }
  assert.equal((await call('/api/version')).status, 200, 'the password is unchanged');

  // Writes that take no body: anything but nothing or {} is refused before they act.
  const send = (route, method, body) =>
    fetch(`http://127.0.0.1:${port}${route}`, {
      method,
      headers: {
        Authorization: 'Basic ' + Buffer.from('admin:' + password).toString('base64'),
        'Content-Type': 'application/json',
        'X-Goblin-Request': '1',
      },
      body,
    });
  const bodiless = [
    ['/api/refresh', 'POST'],
    ['/api/services/linux', 'DELETE'],
    ['/api/account/sessions', 'DELETE'],
    ['/api/account/sessions/s_unknown', 'DELETE'],
    ['/api/auth/logout', 'POST'],
  ];
  for (const [route, method] of bodiless)
    for (const body of ['{{{not json', '{"force":true}', '[]', 'null', '"x"', ' '.repeat(100)]) {
      const answer = await send(route, method, body);
      assert.ok(
        [400, 413].includes(answer.status),
        `${method} ${route} ${JSON.stringify(body)} -> ${answer.status}`
      );
    }
  assert.ok(app.config.get('linux'), 'the source was not deleted');
  assert.equal((await call('/api/version')).status, 200, 'still signed in');
  // No body, or {}, still does what the route does.
  assert.equal((await send('/api/refresh', 'POST', '{}')).status, 202);
  assert.equal((await send('/api/refresh', 'POST')).status, 202);
  assert.equal((await send('/api/services/linux', 'DELETE', '{ }')).status, 200);
  assert.equal((await send('/api/account/sessions', 'DELETE')).status, 200);
});

test('a saved source keeps its type through the API', async t => {
  const collected = [];
  const { app, call } = await fixture(t, {
    collector: async service => {
      collected.push(service.type);
      return measurement(1);
    },
  });
  const before = JSON.stringify(app.config.value);
  // The editor locks the type; a script cannot change it either, which would keep credentials
  // entered for the old type and mappings checked against its readings.
  const proxmox = await call('/api/services/proxmox', 'PATCH', { type: 'json' });
  assert.equal(proxmox.status, 400);
  assert.match(proxmox.body.error, /keeps its service type/);
  assert.equal(JSON.stringify(app.config.value), before);
  // Nor can a connection test of the saved source: another type's collector would be handed
  // the saved credentials (a Proxmox token sent as SABnzbd's ?apikey= query parameter).
  const apiUrl = 'https://pve.example.test:8006';
  const token = { apiUrl, apiKey: 'root@pam!orbit=synthetic-token-not-real-0001' };
  assert.equal((await call('/api/services/proxmox', 'PATCH', token)).status, 200);
  const saved = app.config.get('proxmox');
  const retest = await call('/api/test-service', 'POST', {
    serviceId: 'proxmox',
    settings: { type: 'sabnzbd', name: saved.name, group: saved.group, apiUrl },
  });
  assert.equal(retest.status, 400);
  assert.match(retest.body.error, /keeps its service type/);
  assert.deepEqual(collected, [], 'no collector ran');
  // Its own type is tested as before.
  const own = await call('/api/test-service', 'POST', {
    serviceId: 'proxmox',
    settings: { type: 'proxmox', name: saved.name, group: saved.group, apiUrl },
  });
  assert.equal(own.status, 200, JSON.stringify(own.body));
  assert.deepEqual(collected, ['proxmox']);
  // A JSON source mapping 'cpu' (allowed: JSON-method cards report only their mappings) cannot
  // become a Linux source, whose built-in reading is 'cpu'.
  const added = await call('/api/services', 'POST', {
    type: 'json',
    name: 'J',
    group: 'G',
    metrics: [{ key: 'cpu', path: 'a' }],
  });
  assert.equal(added.status, 201);
  const id = added.body.service.id;
  const retyped = await call(`/api/services/${id}`, 'PATCH', { type: 'linux' });
  assert.equal(retyped.status, 400);
  assert.equal(app.config.get(id).type, 'json');
  // The editor sends the type it shows, the saved one: still accepted.
  const same = await call(`/api/services/${id}`, 'PATCH', { type: 'json', name: 'Renamed' });
  assert.equal(same.status, 200);
  assert.equal(app.config.get(id).name, 'Renamed');
});

test('single-line texts refuse control and bidi characters', async t => {
  const { app, call } = await fixture(t);
  const before = JSON.stringify(app.config.value);
  const bad = [
    'A\nB',
    'A\rB',
    'A\tB',
    'A\u0007B',
    'A\u007fB',
    'A\u0085B',
    'A\u2028B',
    'A\u202eB',
    'A\u2066B',
  ];
  const mapping = value => ({ metrics: [{ key: 'm', path: 'p', ...value }] });
  const writes = value => [
    ['/api/settings', 'PATCH', { title: value }],
    ['/api/settings', 'PATCH', { subtitle: value }],
    ['/api/services/linux', 'PATCH', { name: value }],
    ['/api/services/linux', 'PATCH', { group: value }],
    ['/api/services/linux', 'PATCH', { username: value }],
    ['/api/services/unifi', 'PATCH', { siteId: value }],
    ['/api/services/linux', 'PATCH', mapping({ label: value })],
    ['/api/services/linux', 'PATCH', mapping({ unit: value })],
    ['/api/services', 'POST', { type: 'link', name: value, group: 'G' }],
    ['/api/services', 'POST', { type: 'link', name: 'N', group: value }],
  ];
  for (const value of bad)
    for (const [route, method, body] of writes(value)) {
      const answer = await call(route, method, body);
      assert.equal(answer.status, 400, `${method} ${route} ${JSON.stringify(body)}`);
      assert.match(answer.body.error, /control or text-direction characters/);
    }
  assert.equal(JSON.stringify(app.config.value), before);
  // Letters of any script, emoji and the direction marks a right-to-left name may need stay
  // (a UniFi site has its own syntax).
  for (const [route, method, body] of writes('Ünïcødé שלום 🛰 \u200f').filter(
    ([, , body]) => body.siteId === undefined
  ))
    assert.ok(
      [200, 201].includes((await call(route, method, body)).status),
      `${method} ${route} ${JSON.stringify(body)}`
    );
});

test('a Prometheus label filter keeps the exporter’s exact value, line breaks and direction controls included', async t => {
  // Label values as an exporter sends them: an escaped line break, direction controls, a line
  // separator. A filter matches only when it holds the same text.
  const exposition =
    'example_note{note="line1\\nline2"} 7\n' +
    'example_dir{name="‫vol‬"} 9\n' +
    'example_separator{name="a b"} 4\n' +
    'example_plain{name="plain"} 3\n';
  t.mock.method(transport, 'fetch', async () => new Response(exposition));
  const { app, call } = await fixture(t);
  const metrics = [
    { key: 'note', label: 'Note', path: 'example_note', labels: { note: 'line1\nline2' } },
    { key: 'dir', label: 'Dir', path: 'example_dir', labels: { name: '‫vol‬' } },
    { key: 'separator', label: 'Sep', path: 'example_separator', labels: { name: 'a b' } },
    { key: 'plain', label: 'Plain', path: 'example_plain', labels: { name: 'plain' } },
  ];
  const apiUrl = 'http://exporter.example.test:9100';
  const source = { type: 'prometheus', name: 'Exporter', group: 'G', apiUrl, metricPath: '/m' };
  const readings = body => Object.fromEntries(body.metrics.map(m => [m.key, m.value]));
  // A connection test before saving, then the saved source's own.
  const fresh = await call('/api/test-service', 'POST', {
    serviceId: null,
    settings: { ...source, metrics },
  });
  assert.equal(fresh.status, 200, JSON.stringify(fresh.body));
  assert.deepEqual(readings(fresh.body), { note: 7, dir: 9, separator: 4, plain: 3 });
  const added = await call('/api/services', 'POST', { ...source, metrics });
  assert.equal(added.status, 201, JSON.stringify(added.body));
  const id = added.body.service.id;
  t.after(() => resetCollector(id));
  assert.deepEqual(
    app.config.get(id).metrics.map(m => m.labels),
    metrics.map(m => m.labels)
  );
  const saved = await call('/api/test-service', 'POST', { serviceId: id, settings: source });
  assert.equal(saved.status, 200, JSON.stringify(saved.body));
  assert.deepEqual(readings(saved.body), { note: 7, dir: 9, separator: 4, plain: 3 });
  // NUL, and more than 200 characters, are still refused; 200 are fine.
  const filter = value => ({ metrics: [{ key: 'm', path: 'p', labels: { job: value } }] });
  for (const value of ['a\u0000b', 'a'.repeat(201)]) {
    const answer = await call(`/api/services/${id}`, 'PATCH', filter(value));
    assert.equal(answer.status, 400, JSON.stringify(value));
    assert.match(answer.body.error, /^Invalid label value$/);
  }
  assert.equal(app.config.get(id).metrics.length, metrics.length);
  assert.equal((await call(`/api/services/${id}`, 'PATCH', filter('a'.repeat(200)))).status, 200);
});

test('the web app’s own saves work after an upgrade from a configuration holding half a surrogate pair', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-api-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  // Written as 1.4.3 writes it: JSON.stringify keeps half a pair as a \u escape, which 1.4.3
  // accepted in a request body and in a measurement key that a rule then copied.
  const saved = {
    title: 'Home \ud83d',
    services: [
      {
        id: 'linux-1',
        type: 'linux',
        name: 'Server',
        group: 'G',
        apiUrl: 'https://192.0.2.10:9100',
        rules: [{ key: 'disk_\ud83d', operator: 'gt', threshold: 90 }],
      },
    ],
  };
  fs.writeFileSync(path.join(directory, 'config.json'), JSON.stringify(saved), { mode: 0o600 });
  const { app, call } = await fixture(t, { directory });
  // What the web app loads, and sends back unchanged: the dashboard name with every Appearance
  // save, and the source's rules (page.draftRules) with every source save.
  const { config } = (await call('/api/dashboard')).body;
  const linux = config.services.find(s => s.id === 'linux-1');
  const appearance = await call('/api/settings', 'PATCH', {
    title: config.title,
    subtitle: 'Changed subtitle',
  });
  assert.equal(appearance.status, 200, JSON.stringify(appearance.body));
  const drawer = await call('/api/services/linux-1', 'PATCH', {
    type: linux.type,
    name: 'Renamed',
    group: linux.group,
    rules: linux.rules,
  });
  assert.equal(drawer.status, 200, JSON.stringify(drawer.body));
  assert.equal(app.config.value.subtitle, 'Changed subtitle');
  assert.equal(app.config.get('linux-1').name, 'Renamed');
  // The halves were made whole (U+FFFD) when the configuration was loaded.
  assert.equal(config.title, 'Home �');
  assert.equal(linux.rules[0].key, 'disk_�');
  assert.equal(app.config.get('linux-1').rules[0].key, 'disk_�');
  // A request that sends half a pair itself is still refused.
  const half = await call('/api/settings', 'PATCH', { title: 'Home \udc00' });
  assert.equal(half.status, 400);
  assert.equal(app.config.value.title, 'Home �');
});

test('repeated history, docs and health parameters are refused', async t => {
  const { call } = await fixture(t);
  for (const route of [
    '/api/history/linux?range=1h&range=bogus',
    '/api/history/linux?range=1h&range=1h',
    '/api/docs?doc=security&doc=bogus',
    '/health?instance=a&instance=b',
  ]) {
    const answer = await call(route);
    assert.equal(answer.status, 400, route);
    assert.match(answer.body.error, /may be given only once/, route);
  }
  // A metric key longer than a collector reports, or with control characters, names nothing.
  for (const metric of ['a'.repeat(201), 'cpu\n', 'cpu\u0000'])
    assert.equal(
      (await call(`/api/history/linux?metric=${encodeURIComponent(metric)}`)).status,
      400,
      JSON.stringify(metric)
    );
  for (const route of [
    '/api/history/linux?range=1h',
    `/api/history/linux?metric=${'a'.repeat(200)}&metric=disk_free_%2Fdev%2Fshm`,
    '/api/docs?doc=security',
    '/health?instance=a',
  ])
    assert.equal((await call(route)).status, 200, route);
});

test('the connection test takes a saved source ID or null, and a UniFi site is checked when saved', async t => {
  const { app, call, directory } = await fixture(t);
  const settings = { type: 'link', name: 'n', group: 'g' };
  for (const serviceId of [0, '', false, true, { a: 1 }, ['x'], 'bad id!', 'a'.repeat(81)]) {
    const answer = await call('/api/test-service', 'POST', { serviceId, settings });
    assert.equal(answer.status, 400, JSON.stringify(serviceId));
    assert.match(answer.body.error, /serviceId must be the ID of a saved source/);
  }
  // null (the editor's new source) and no serviceId: the settings are tested unsaved.
  for (const body of [{ serviceId: null, settings }, { settings }])
    assert.match((await call('/api/test-service', 'POST', body)).body.error, /bookmark/);
  assert.match(
    (await call('/api/test-service', 'POST', { serviceId: 'missing-1', settings })).body.error,
    /Source not found/
  );
  // A UniFi site: a UUID, a local site name, or empty.
  const before = JSON.stringify(app.config.value);
  for (const siteId of ['../../../x?y#z', 'my site', 'a'.repeat(101), 'site/1'])
    assert.equal(
      (await call('/api/services/unifi', 'PATCH', { siteId })).status,
      400,
      JSON.stringify(siteId)
    );
  assert.equal(JSON.stringify(app.config.value), before);
  for (const siteId of ['default', '88f7af54-98f8-306a-a1c7-c9349722b1f6', ''])
    assert.equal((await call('/api/services/unifi', 'PATCH', { siteId })).status, 200, siteId);
  // A site an older release saved keeps loading, and saving it unchanged (as the editor does)
  // still works; only a new value is checked.
  await app.close();
  const file = path.join(directory, 'config.json');
  const saved = JSON.parse(fs.readFileSync(file, 'utf8'));
  saved.services.find(service => service.id === 'unifi').siteId = 'Old site';
  fs.writeFileSync(file, JSON.stringify(saved));
  const again = await fixture(t, { directory });
  assert.equal(again.app.config.get('unifi').siteId, 'Old site');
  assert.equal(
    (await again.call('/api/services/unifi', 'PATCH', { siteId: 'Old site', name: 'U' })).status,
    200
  );
});

test('internal RangeErrors and other built-in errors are shown as fixed text', async t => {
  // A collector that fails inside JavaScript itself (a call stack overflow on a huge upstream
  // list, a malformed escape) must not show that error's text: it can quote upstream content.
  const canary = 'SYNTHETIC-BUILTIN-CANARY';
  let failure;
  const { call } = await fixture(t, {
    collector: async () => {
      throw failure;
    },
  });
  for (const make of [RangeError, SyntaxError, ReferenceError, URIError, EvalError]) {
    failure = new make(`Maximum call stack size exceeded near "${canary}"`);
    const result = await call('/api/test-service', 'POST', {
      serviceId: 'linux',
      settings: editorPayload,
    });
    assert.equal(result.status, 422, make.name);
    assert.equal(
      result.body.error,
      'Collection failed. Check the endpoint, credentials, and source compatibility.',
      make.name
    );
  }
  // A collector's own error keeps its message, as before.
  failure = new Error('No numeric Prometheus measurements found');
  const own = await call('/api/test-service', 'POST', {
    serviceId: 'linux',
    settings: editorPayload,
  });
  assert.equal(own.body.error, 'No numeric Prometheus measurements found');
});

test('payloads the editor and settings pages send are accepted', async t => {
  const { call } = await fixture(t, { collector: async () => measurement(20) });
  assert.equal((await call('/api/services/linux', 'PATCH', editorPayload)).status, 200);
  // In website-check mode the editor leaves out the sections it hides.
  const { apiKey, username, metrics, siteId, nodeName, metricPath, ...websitePayload } =
    editorPayload;
  assert.equal(
    (
      await call('/api/services/linux', 'PATCH', {
        ...websitePayload,
        collector: 'http',
        apiUrl: 'http://node.example.test:9100/health',
      })
    ).status,
    200
  );
  assert.equal(
    (await call('/api/test-service', 'POST', { serviceId: 'linux', settings: editorPayload }))
      .status,
    200
  );
  for (const body of [
    {
      title: 'Uptime Goblin',
      subtitle: '',
      appearance: {
        accent: 'cyan',
        density: 'compact',
        columns: 'auto',
        defaultRange: '24h',
        sortBy: 'manual',
        showSummary: true,
        showPaused: true,
        showUnconfigured: true,
        openInNewTab: true,
        reduceMotion: false,
        timezone: 'local',
        timeFormat: 'auto',
      },
    },
    {
      pollSeconds: 60,
      monitoring: {
        concurrency: 4,
        timeoutSeconds: 90,
        availabilityFailures: 2,
        availabilitySeconds: 60,
        retryCount: 2,
        retryDelaySeconds: 2,
        recoverySuccesses: 2,
        recoverySeconds: 60,
      },
    },
    {
      alerts: {
        enabled: true,
        notifyOnAlert: true,
        notifyOnRecovery: true,
        notifyAvailability: true,
        notifyMeasurements: true,
      },
    },
    { retentionDays: 30 },
    { pollSeconds: 60, retentionDays: 30 },
    {
      email: {
        enabled: false,
        host: 'smtp.example.test',
        port: 465,
        secure: true,
        from: 'a@example.test',
        to: 'b@example.test',
      },
    },
  ])
    assert.equal((await call('/api/settings', 'PATCH', body)).status, 200, JSON.stringify(body));
  const examples = path.join(import.meta.dirname, '..', 'examples');
  const global = JSON.parse(fs.readFileSync(path.join(examples, 'global-settings.json'), 'utf8'));
  assert.equal((await call('/api/settings', 'PATCH', global)).status, 200);
  const linux = JSON.parse(fs.readFileSync(path.join(examples, 'linux-source.json'), 'utf8'));
  assert.equal((await call('/api/services', 'POST', linux)).status, 201);
});

test('the credential origin guard covers password-based and mixed sources on every path', async t => {
  let calls = 0;
  const { app, call } = await fixture(t, {
    collector: async () => {
      calls++;
      return measurement(1);
    },
  });
  app.config.update('unifi', {
    apiUrl: 'https://console.example.test',
    username: 'viewer',
    password: 'saved-unifi-password',
  });
  const elsewhere = { apiUrl: 'https://attacker.example.test' };
  assert.equal((await call('/api/services/unifi', 'PATCH', elsewhere)).status, 400);
  assert.equal(
    (await call('/api/test-service', 'POST', { serviceId: 'unifi', settings: elsewhere })).status,
    400
  );
  assert.equal(calls, 0);
  assert.equal(app.config.get('unifi').apiUrl, 'https://console.example.test');
  // Mixed: re-entering only one of two saved secrets is not enough.
  app.config.update('amp', {
    apiUrl: 'https://amp.example.test',
    apiKey: 'saved-token',
    password: 'saved-amp-password',
  });
  assert.equal(
    (await call('/api/services/amp', 'PATCH', { ...elsewhere, apiKey: 'new-token' })).status,
    400
  );
  const both = await call('/api/services/amp', 'PATCH', {
    ...elsewhere,
    apiKey: 'new-token',
    password: 'new-password',
  });
  assert.equal(both.status, 200);
  const cleared = await call('/api/services/unifi', 'PATCH', { ...elsewhere, password: '' });
  assert.equal(cleared.status, 200);
  assert.equal(app.config.get('unifi').password, '');
});

test('website checks and bookmarks drop saved credentials when their address moves', async t => {
  const { app, call } = await fixture(t, { collector: async () => measurement(1) });
  app.config.update('sonarr', { apiUrl: 'https://sonarr.example.test', apiKey: 'saved-key' });
  const result = await call('/api/services/sonarr', 'PATCH', {
    collector: 'http',
    apiUrl: 'https://www.example.test',
  });
  assert.equal(result.status, 200);
  assert.equal(result.body.credentialsCleared, true);
  assert.equal(result.body.service.apiKeyConfigured, false);
  assert.equal(app.config.get('sonarr').apiKey, '');
  // A connection test reports the same without saving anything.
  app.config.update('radarr', { apiUrl: 'https://radarr.example.test', apiKey: 'saved-key' });
  const test = await call('/api/test-service', 'POST', {
    serviceId: 'radarr',
    settings: { collector: 'http', apiUrl: 'https://www.example.test' },
  });
  assert.equal(test.status, 200);
  assert.equal(test.body.credentialsCleared, true);
  assert.equal(app.config.get('radarr').apiKey, 'saved-key');
});

test('security headers, system fields and refresh coalescing', async t => {
  const { call, port, directory } = await fixture(t);
  const system = await call('/api/system');
  const page = await fetch(`http://127.0.0.1:${port}/`, {
    headers: { Authorization: 'Basic ' + Buffer.from('admin:' + password).toString('base64') },
  });
  assert.equal(page.status, 200);
  for (const headers of [system.headers, page.headers]) {
    assert.match(headers.get('content-security-policy'), /default-src 'self'/);
    assert.match(headers.get('content-security-policy'), /script-src 'self';/);
    assert.match(headers.get('content-security-policy'), /frame-ancestors 'none'/);
    assert.equal(headers.get('x-frame-options'), 'DENY');
    assert.equal(headers.get('x-content-type-options'), 'nosniff');
    assert.equal(headers.get('referrer-policy'), 'no-referrer');
    assert.equal(headers.get('cross-origin-opener-policy'), 'same-origin');
    assert.equal(headers.get('cross-origin-resource-policy'), 'same-origin');
    assert.match(headers.get('permissions-policy'), /camera=\(\)/);
  }
  assert.deepEqual(Object.keys(system.body).sort(), [
    'authentication',
    'authenticationRequired',
    'build',
    'clients',
    'collection',
    'data',
    // 1.5 (delivery spec §6.3): the storage guard and where the encryption key came from.
    'disk',
    'keys',
    'limits',
    'notifications',
    // What a supervised start found of its resource limits (not checked here: this Uptime Goblin was
    // started by createApp, not under a service manager).
    'resourceLimits',
    'startedAt',
    'uptimeSeconds',
    'version',
  ]);
  assert.deepEqual(system.body.resourceLimits, { supervised: false });
  // The additive delivery, key and disk fields (delivery spec §6.3); never the key itself.
  const { notifications, keys, disk, data } = system.body;
  assert.equal(typeof notifications.webhookConfigured, 'boolean');
  assert.equal(typeof notifications.email.state, 'string');
  assert.equal(notifications.available, true);
  assert.equal(notifications.saving, true);
  assert.deepEqual(Object.keys(notifications.totals).sort(), [
    'failed',
    'paused',
    'retrying',
    'sending',
    'waiting',
  ]);
  assert.equal(notifications.oldestWaitingAt, null);
  // A46: alerts the backlog cap refused since this start.
  assert.equal(notifications.notQueued, 0);
  assert.equal(keys.source, 'generated');
  assert.match(keys.fingerprint, /^[0-9a-f]{16}$/);
  assert.equal(keys.needsRewrap, false);
  assert.ok(Array.isArray(keys.warnings));
  assert.equal(disk.full, false);
  assert.equal(disk.reserveBytes, 8 * 2 ** 20);
  assert.equal(typeof disk.reserveHeld, 'boolean');
  assert.ok(data.controlBytes > 0);
  // The generated key itself never leaves the data directory.
  const key = fs.readFileSync(path.join(directory, 'secret.key'), 'utf8').trim();
  assert.match(key, /^[0-9a-f]{64}$/);
  assert.equal(JSON.stringify(system.body).includes(key), false);
  assert.equal((await call('/api/refresh', 'POST', {})).body.coalesced, undefined);
  const second = await call('/api/refresh', 'POST', {});
  assert.equal(second.status, 202);
  assert.equal(second.body.coalesced, true);
  assert.equal((await call('/api/history/linux?range=constructor')).status, 400);
  assert.equal((await call('/api/history/linux?range=__proto__')).status, 400);
});

test('cosmetic edits during a poll neither abort collection nor discard its result', async t => {
  let release,
    calls = 0;
  const { app, call } = await fixture(t, {
    collector: async () => {
      calls++;
      return new Promise(resolve => (release = () => resolve(measurement(42))));
    },
  });
  app.config.update('linux', { apiUrl: 'http://node.example.test:9100' });
  const pending = app.poll(app.config.get('linux'));
  await new Promise(resolve => setImmediate(resolve));
  for (const body of [
    { name: 'Renamed' },
    { showOnDashboard: false },
    { color: 'pink' },
    { group: 'Elsewhere' },
    { alerts: { notifyAvailability: false } },
  ])
    assert.equal((await call('/api/services/linux', 'PATCH', body)).status, 200);
  release();
  await pending;
  assert.equal(calls, 1);
  assert.equal(app.store.latest('linux').metrics[0].value, 42);
  // A collection change still restarts collection.
  const restarted = app.poll(app.config.get('linux'));
  await new Promise(resolve => setImmediate(resolve));
  assert.equal((await call('/api/services/linux', 'PATCH', { metricPath: '/other' })).status, 200);
  release();
  await restarted;
  assert.equal(app.store.latest('linux').metrics[0].value, 42);
  assert.equal(app.store.stats().samples, 1);
});

test('a history write failure does not stop alerts and is reported once', async t => {
  const sent = [];
  const { app } = await fixture(t, {
    collector: async () => {
      throw new Error('Connection refused. Check the port.');
    },
    mailTransportFactory: () => ({
      sendMail: async message => {
        sent.push(message.text);
        return { accepted: ['to@example.test'] };
      },
      close() {},
    }),
  });
  app.config.updateGlobal({
    monitoring: { availabilityFailures: 1, availabilitySeconds: 0, retryCount: 0 },
    email: { enabled: true, from: 'from@example.test', to: 'to@example.test', password: 'x' },
  });
  app.config.update('linux', { apiUrl: 'http://node.example.test:9100' });
  const record = app.store.record;
  app.store.record = () => {
    throw Object.assign(new Error('database or disk is full'), { errcode: 13 });
  };
  t.after(() => (app.store.record = record));
  await app.poll(app.config.get('linux'));
  await app.poll(app.config.get('linux'));
  await app.flushNotifications();
  // Both alerts arrive together, so they are batched into one email listing each.
  const text = sent.join('\n');
  assert.match(text, /Alert — Uptime Goblin: Uptime Goblin cannot write its history database/);
  assert.equal(text.match(/Alert — Linux systems: Source is unavailable/g).length, 1);
  assert.deepEqual(Object.keys(app.dashboard().storage).sort(), ['code', 'since']);
});

test('deleting a source clears its history before the configuration, and new sources start clean', async t => {
  const { app, call } = await fixture(t);
  app.store.record('json-1', measurement(5), null, Date.now());
  assert.equal((await call('/api/services', 'POST', { type: 'json', name: 'API' })).status, 201);
  assert.equal(app.store.latest('json-1').lastSuccess, null);
  app.store.record('json-1', measurement(5), null, Date.now());
  const forget = app.store.forget;
  app.store.forget = async () => {
    throw new Error('disk I/O error');
  };
  assert.equal((await call('/api/services/json-1', 'DELETE', {})).status, 500);
  assert.ok(app.config.get('json-1'), 'the source stays so the delete can be retried');
  app.store.forget = forget;
  assert.equal((await call('/api/services/json-1', 'DELETE', {})).status, 200);
  assert.equal(app.store.latest('json-1').lastSuccess, null);
});

// Holds every later configuration write back: the next source deletion waits in forget()
// until the returned function is called.
function holdWrites(app) {
  let release;
  const held = new Promise(resolve => (release = resolve)),
    forget = app.store.forget.bind(app.store);
  app.store.forget = async id => {
    await held;
    return forget(id);
  };
  return release;
}
const settle = () => new Promise(resolve => setTimeout(resolve, 50));

test(
  'a write sent again with its Idempotency-Key is answered from the first and applied once',
  { timeout: 30000 },
  async t => {
    let clock = 0;
    const { app, call } = await fixture(t, { monotonic: () => clock });
    const key = { 'Idempotency-Key': 'b1f2a3c4-0000-4000-8000-000000000001' },
      source = { type: 'link', name: 'Once' };
    const first = await call('/api/services', 'POST', source, key);
    assert.equal(first.status, 201);
    assert.equal(first.headers.get('idempotent-replayed'), null);
    const again = await call('/api/services', 'POST', source, key);
    assert.equal(again.status, 201);
    assert.equal(again.headers.get('idempotent-replayed'), 'true');
    assert.deepEqual(again.body, first.body);
    const count = () => app.config.value.services.filter(s => s.name === 'Once').length;
    assert.equal(count(), 1);
    // The key belongs to that request: another body is refused, another route is its own.
    const other = await call('/api/services', 'POST', { ...source, name: 'Other' }, key);
    assert.equal(other.status, 422);
    assert.equal(app.config.value.services.filter(s => s.name === 'Other').length, 0);
    const settings = await call('/api/settings', 'PATCH', { title: 'Keyed' }, key);
    assert.equal(settings.status, 200);
    assert.equal(app.config.value.title, 'Keyed');
    for (const bad of ['short', 'has space in it', 'x'.repeat(129)])
      assert.equal(
        (await call('/api/services', 'POST', source, { 'Idempotency-Key': bad })).status,
        400,
        bad
      );
    // Answers are kept for 10 minutes; after that the key is forgotten.
    clock += 10 * 60 * 1000 + 1;
    const later = await call('/api/services', 'POST', source, key);
    assert.equal(later.status, 201);
    assert.equal(later.headers.get('idempotent-replayed'), null);
    assert.equal(count(), 2);
    // Requests without a key (older tabs, scripts) behave as before.
    assert.equal((await call('/api/services', 'POST', source)).status, 201);
    assert.equal(count(), 3);
  }
);

test(
  'a retry that arrives while the first attempt still runs waits for its answer',
  { timeout: 30000 },
  async t => {
    let release,
      calls = 0;
    const { call } = await fixture(t, {
      collector: async () => {
        calls++;
        await new Promise(resolve => (release = resolve));
        return measurement(7);
      },
    });
    const body = {
        settings: { type: 'linux', name: 'Probe', apiUrl: 'http://node.example.test:9100' },
      },
      key = { 'Idempotency-Key': 'retry-while-running-0001' };
    const first = call('/api/test-service', 'POST', body, key);
    while (!calls) await settle();
    const second = call('/api/test-service', 'POST', body, key);
    await settle();
    release();
    const [a, b] = await Promise.all([first, second]);
    assert.equal(calls, 1);
    assert.equal(a.status, 200);
    assert.deepEqual(b.body, a.body);
    assert.equal(b.headers.get('idempotent-replayed'), 'true');
  }
);

test(
  'a new source honours If-Match, so a retry based on an old revision cannot duplicate it',
  { timeout: 30000 },
  async t => {
    const { app, call } = await fixture(t);
    const revision = app.config.value.revision;
    const added = await call(
      '/api/services',
      'POST',
      { type: 'link', name: 'Guarded' },
      { 'If-Match': String(revision) }
    );
    assert.equal(added.status, 201);
    assert.equal(added.body.revision, revision + 1);
    // The same request again, as a tab would send it after losing the answer (another key,
    // as after a restart that forgot the first): refused, nothing added.
    const retry = await call(
      '/api/services',
      'POST',
      { type: 'link', name: 'Guarded' },
      { 'If-Match': String(revision), 'Idempotency-Key': 'after-a-restart-0001' }
    );
    assert.equal(retry.status, 409);
    assert.equal(retry.body.revision, revision + 1);
    assert.equal(app.config.value.services.filter(s => s.name === 'Guarded').length, 1);
  }
);

test(
  'configuration writes wait in a bounded queue and never apply after giving up',
  { timeout: 30000 },
  async t => {
    const { app, call } = await fixture(t, { writeQueueLimit: 2, writeStartMs: 300 });
    const title = app.config.value.title;
    let release = holdWrites(app);
    const deleting = call('/api/services/linux', 'DELETE', {});
    await settle();
    // Waiting longer than writeStartMs: 503 busy, and the change is never applied later.
    const late = await call('/api/settings', 'PATCH', { title: 'Too late' });
    assert.equal(late.status, 503);
    assert.equal(late.body.code, 'busy');
    assert.equal(late.headers.get('retry-after'), '5');
    release();
    assert.equal((await deleting).status, 200);
    await settle();
    assert.equal(app.config.value.title, title);
    // A busy answer applied nothing, so it is not kept for its Idempotency-Key.
    release = holdWrites(app);
    const again = call('/api/services/windows', 'DELETE', {});
    await settle();
    const key = { 'Idempotency-Key': 'busy-then-retried-0001' };
    assert.equal((await call('/api/settings', 'PATCH', { title: 'Retried' }, key)).status, 503);
    release();
    await again;
    assert.equal((await call('/api/settings', 'PATCH', { title: 'Retried' }, key)).status, 200);
    assert.equal(app.config.value.title, 'Retried');
  }
);

test(
  'at most writeQueueLimit writes wait; a write whose browser left is skipped',
  { timeout: 30000 },
  async t => {
    const { app, call } = await fixture(t, { writeQueueLimit: 2, writeStartMs: 60000 });
    const release = holdWrites(app);
    const deleting = call('/api/services/linux', 'DELETE', {});
    await settle();
    const leaving = new AbortController();
    const left = call('/api/settings', 'PATCH', { title: 'Abandoned' }, {}, leaving.signal).catch(
      () => 'aborted'
    );
    const waiting = call('/api/settings', 'PATCH', { subtitle: 'Queued' });
    await settle();
    const full = await call('/api/settings', 'PATCH', { title: 'No room' });
    assert.equal(full.status, 503);
    assert.equal(full.body.code, 'busy');
    leaving.abort();
    assert.equal(await left, 'aborted');
    await settle();
    release();
    assert.equal((await deleting).status, 200);
    assert.equal((await waiting).status, 200);
    assert.equal(app.config.value.subtitle, 'Queued');
    assert.notEqual(app.config.value.title, 'Abandoned', 'the browser left before its turn');
    assert.notEqual(app.config.value.title, 'No room');
  }
);

test(
  'lowering retention saves the settings while a long prune continues',
  { timeout: 30000 },
  async t => {
    const { app, call } = await fixture(t, { settingsPruneMs: 100 });
    let pruned = null,
      finish;
    app.store.prune = days => {
      pruned = days;
      return new Promise(resolve => (finish = resolve));
    };
    const started = Date.now();
    const saved = await call('/api/settings', 'PATCH', { retentionDays: 7 });
    assert.equal(saved.status, 200);
    assert.ok(Date.now() - started < 5000);
    assert.equal(pruned, 7);
    assert.equal(app.config.value.retentionDays, 7);
    finish();
    // The next change is not held back by the prune either.
    assert.equal((await call('/api/settings', 'PATCH', { title: 'Next' })).status, 200);
  }
);

test('history can be limited to the measurements a chart draws', { timeout: 30000 }, async t => {
  const { app, call } = await fixture(t);
  const readings = value => [
    { key: 'cpu', label: 'CPU', value, unit: '%' },
    { key: 'memory', label: 'Memory', value: value + 1, unit: '%' },
    { key: 'disk', label: 'Disk', value: value + 2, unit: '%' },
  ];
  for (let i = 0; i < 5; i++) app.store.record('linux', readings(i), null, Date.now() - i * 60000);
  const keys = history => [
    ...new Set(history.points.filter(p => p.ok).flatMap(p => p.metrics.map(m => m.key))),
  ];
  const all = await call('/api/history/linux?range=1h');
  assert.equal(all.status, 200);
  assert.deepEqual(keys(all.body).sort(), ['cpu', 'disk', 'memory']);
  const one = await call('/api/history/linux?range=1h&metric=memory');
  assert.deepEqual(keys(one.body), ['memory']);
  assert.deepEqual(Object.keys(one.body).sort(), Object.keys(all.body).sort());
  assert.equal(one.body.points.length, all.body.points.length);
  const two = await call('/api/history/linux?range=1h&metric=cpu&metric=disk&metric=unknown');
  assert.deepEqual(keys(two.body).sort(), ['cpu', 'disk']);
  const unknown = await call('/api/history/linux?range=1h&metric=unknown');
  assert.equal(unknown.status, 200);
  assert.deepEqual(keys(unknown.body), []);
  const many = Array.from({ length: 21 }, (_, i) => `metric=m${i}`).join('&');
  assert.equal((await call(`/api/history/linux?range=1h&${many}`)).status, 400);
  const twenty = Array.from({ length: 20 }, (_, i) => `metric=m${i}`).join('&');
  assert.equal((await call(`/api/history/linux?range=1h&${twenty}`)).status, 200);
});

test('collector notes reach the dashboard and connection tests', { timeout: 30000 }, async t => {
  const notes = [
    { code: 'measurements_capped', message: 'Only the first 512 measurements are kept.' },
  ];
  const { app, call } = await fixture(t, {
    collector: async () =>
      Object.defineProperty(measurement(3), 'notes', { value: notes, enumerable: false }),
  });
  app.config.update('linux', { apiUrl: 'http://node.example.test:9100' });
  await app.poll(app.config.get('linux'));
  const dashboard = await call('/api/dashboard');
  const services = dashboard.body.services;
  assert.deepEqual(services.find(s => s.id === 'linux').notes, notes);
  assert.deepEqual(services.find(s => s.id === 'windows').notes, []);
  const tested = await call('/api/test-service', 'POST', {
    settings: { type: 'linux', name: 'Probe', apiUrl: 'http://node.example.test:9100' },
  });
  assert.equal(tested.status, 200);
  assert.deepEqual(tested.body.notes, notes);
});

test('a password change is never answered from a stored reply', { timeout: 30000 }, async t => {
  const { call } = await fixture(t);
  const key = { 'Idempotency-Key': 'password-change-0001' },
    wrong = {
      currentPassword: 'not-the-password',
      password: 'another-long-password',
      confirmPassword: 'another-long-password',
    };
  const first = await call('/api/auth/password', 'POST', wrong, key);
  const second = await call('/api/auth/password', 'POST', wrong, key);
  assert.equal(first.status, 403);
  assert.equal(second.status, 403);
  assert.equal(second.headers.get('idempotent-replayed'), null);
});
