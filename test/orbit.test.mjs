import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { createApp } from '../server.mjs';
import { defaults, newService, publicConfig } from '../lib/catalog.mjs';
import { ConfigStore, validateService } from '../lib/config.mjs';
import { Store } from '../lib/store.mjs';
import { historyWindow } from '../lib/series/shape.mjs';
import { collect, parsePrometheus, request, transport } from '../lib/collectors.mjs';
import { configureDestinations } from '../lib/destinations.mjs';
import { adminHeaders, adminPassword } from './helpers/admin.mjs';
// Fixture hostnames resolve instantly to a documentation address, never via real DNS.
configureDestinations({ lookup: async () => [{ address: '192.0.2.1' }] });
const measurement = value => [{ key: 'cpu', label: 'CPU', value, unit: '%' }];
function temp(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}
// Local fixture servers listen on loopback, which collectors refuse by default.
function allowLoopback(t) {
  configureDestinations({ allowLoopback: true });
  t.after(() => configureDestinations({ allowLoopback: false }));
}
async function appFor(t, options = {}) {
  const dir = temp(t),
    app = await createApp({
      directory: dir,
      host: '127.0.0.1',
      password: adminPassword,
      allowedHosts: '',
      webhook: '',
      port: 0,
      startScheduler: false,
      ...options,
    });
  const address = await app.listen();
  t.after(() => app.close());
  const base = `http://127.0.0.1:${address.port}`;
  const call = async (route, method = 'GET', value, headers = {}) => {
    const res = await fetch(base + route, {
      method,
      headers: {
        'Content-Type': 'application/json',
        'X-Goblin-Request': '1',
        ...adminHeaders(),
        ...headers,
      },
      body: value === undefined ? undefined : JSON.stringify(value),
    });
    return { status: res.status, body: await res.json() };
  };
  return { app, dir, base, call };
}
async function fixture(t, respond) {
  allowLoopback(t);
  const server = http.createServer(async (req, res) => {
    let raw = '';
    for await (const part of req) raw += part;
    try {
      const result = await respond(req, raw ? JSON.parse(raw) : null);
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(result));
    } catch (e) {
      res.writeHead(500);
      res.end(JSON.stringify({ error: e.message }));
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  return `http://127.0.0.1:${server.address().port}`;
}

test('defaults include three independently addressable Cosmos servers and AMP', () => {
  const services = defaults().services;
  assert.equal(services.filter(s => s.type === 'cosmos').length, 3);
  assert.equal(services.filter(s => s.type === 'amp').length, 1);
  assert.equal(new Set(services.map(s => s.id)).size, services.length);
});

test('API stores credentials privately, keeps them on partial edits, and supports duplicates', async t => {
  const { call, dir } = await appFor(t);
  const first = await call('/api/services', 'POST', {
    type: 'cosmos',
    name: 'Media host',
    apiKey: 'test-only-secret',
    password: 'test-only-password',
    enabled: false,
  });
  assert.equal(first.status, 201);
  assert.equal(first.body.service.apiKeyConfigured, true);
  assert.ok(!JSON.stringify(first.body).includes('test-only-secret'));
  const second = await call('/api/services', 'POST', {
    type: 'cosmos',
    name: 'Games host',
    enabled: false,
  });
  assert.notEqual(first.body.service.id, second.body.service.id);
  await call('/api/services/' + first.body.service.id, 'PATCH', { name: 'Renamed host' });
  const saved = new ConfigStore(dir).get(first.body.service.id);
  assert.equal(saved.apiKey, 'test-only-secret');
  assert.equal(saved.password, 'test-only-password');
  assert.equal(fs.statSync(path.join(dir, 'config.json')).mode & 0o777, 0o600);
  const response = await call('/api/dashboard');
  assert.ok(!JSON.stringify(response.body).includes('test-only-secret'));
  assert.ok(!JSON.stringify(response.body).includes('test-only-password'));
});

test('unsafe destinations, cross-origin changes, and secret-file requests are rejected', async t => {
  const { call, base } = await appFor(t);
  for (const url of [
    'javascript:alert(1)',
    'https://user:pass@example.com',
    'https://example.com/?api_key=secret',
  ])
    assert.equal((await call('/api/services', 'POST', { type: 'link', url })).status, 400);
  assert.equal(
    (await call('/api/services', 'POST', { type: 'link' }, { Origin: 'https://untrusted.example' }))
      .status,
    403
  );
  assert.equal(
    (await call('/api/services', 'POST', { type: 'link' }, { 'X-Goblin-Request': '' })).status,
    403
  );
  assert.equal((await fetch(base + '/data/config.json')).status, 404);
  assert.equal(
    await new Promise(resolve =>
      http.get(base + '/api/dashboard', { headers: { Host: 'attacker.example' } }, res => {
        res.resume();
        resolve(res.statusCode);
      })
    ),
    403
  );
  // Pinned so an exported GOBLIN_PASSWORD cannot turn this into a running app that never exits.
  await assert.rejects(
    createApp({ host: '0.0.0.0', directory: temp(t), password: '', startScheduler: false }),
    /GOBLIN_PASSWORD/
  );
});

test('disabled sources stop collection while preserving separate per-instance history', async t => {
  const calls = [];
  const { app, call } = await appFor(t, {
    collector: async s => {
      calls.push(s.id);
      return measurement(s.id === 'cosmos-1' ? 12 : 48);
    },
  });
  for (const id of ['cosmos-1', 'cosmos-2'])
    await call('/api/services/' + id, 'PATCH', { apiUrl: 'http://configured.invalid' });
  await app.tick(true);
  assert.equal(app.store.latest('cosmos-1').metrics[0].value, 12);
  assert.equal(app.store.latest('cosmos-2').metrics[0].value, 48);
  await call('/api/services/cosmos-1', 'PATCH', { enabled: false });
  calls.length = 0;
  await app.tick(true);
  assert.deepEqual(calls, ['cosmos-2']);
  assert.equal(app.store.latest('cosmos-1').metrics[0].value, 12);
  assert.equal(app.dashboard().services.find(s => s.id === 'cosmos-1').status, 'disabled');
  await call('/api/services/cosmos-1', 'PATCH', { enabled: true });
  await app.tick(true);
  assert.ok(calls.includes('cosmos-1'));
});

test('pausing an in-flight poll cancels its result and does not alert', async t => {
  let release, entered;
  const enteredPromise = new Promise(r => (entered = r));
  const { app, call } = await appFor(t, {
    collector: async () => {
      entered();
      return new Promise(r => (release = r));
    },
  });
  await call('/api/services/cosmos-1', 'PATCH', { apiUrl: 'http://configured.invalid' });
  const pending = app.poll(app.config.get('cosmos-1'));
  await enteredPromise;
  await call('/api/services/cosmos-1', 'PATCH', { enabled: false });
  release(measurement(99));
  await pending;
  assert.equal(app.store.latest('cosmos-1').lastSuccess, null);
  assert.deepEqual(app.dashboard().alerts, []);
});

test('history persists real zeros, last-good data, failure gaps, and retention', async t => {
  const dir = temp(t);
  let store = new Store(dir);
  const now = Date.now();
  store.record('a', measurement(0), null, now - 180000);
  store.record('a', measurement(10), null, now - 120000);
  store.record('a', [], 'Timed out', now - 60000);
  store.record('a', measurement(5), null, now);
  const history = store.history('a', '1h', now);
  assert.equal(history.totalSamples, 3);
  assert.ok(history.points.some(p => !p.ok));
  assert.equal(history.points[0].metrics[0].value, 0);
  store.close();
  store = new Store(dir);
  assert.equal(store.latest('a').metrics[0].value, 5);
  store.record('a', [], 'Failed', now + 1);
  assert.equal(store.latest('a').metrics[0].value, 5);
  await store.prune(1, now + 172800000);
  assert.equal(store.history('a', '30d', now + 172800000).points.length, 0);
  store.close();
});

test('history downsampling is bounded and preserves collection failure buckets', t => {
  const store = new Store(temp(t));
  t.after(() => store.close());
  const now = Date.now();
  for (let n = 0; n < 1800; n++)
    store.record('a', measurement(n), n === 700 ? 'Gap' : null, now - 1800000 + n * 1000);
  const h = store.history('a', '1h', now);
  assert.ok(h.points.length <= 601);
  assert.ok(h.points.some(p => !p.ok));
});

test('alerts debounce, persist, resolve, and do not resolve on missing data', t => {
  const store = new Store(temp(t));
  t.after(() => store.close());
  const s = {
    ...newService('linux'),
    recoverySuccesses: 1,
    recoverySeconds: 0,
    rules: [{ key: 'cpu', operator: 'gt', threshold: 80, forSeconds: 60 }],
  };
  const now = Date.now();
  assert.deepEqual(store.evaluate(s, measurement(95), null, now), []);
  assert.equal(store.evaluate(s, measurement(96), null, now + 60000)[0].kind, 'firing');
  assert.equal(store.alerts().length, 1);
  store.evaluate(s, [], 'Network failed', now + 120000);
  assert.equal(store.alerts().length, 1);
  assert.equal(
    store.evaluate(s, measurement(20), null, now + 180000).filter(e => e.kind === 'resolved')
      .length,
    1
  );
  assert.equal(store.alerts().length, 0);
});

test('metric mapping and rule validation reject invalid input', () => {
  const s = newService('json');
  assert.throws(
    () =>
      validateService(
        {
          metrics: [
            { key: 'a', label: 'A', path: 'x' },
            { key: 'a', path: 'y' },
          ],
        },
        s
      ),
    /unique/
  );
  assert.throws(
    () => validateService({ rules: [{ key: 'x', operator: 'gt', threshold: 'not-number' }] }, s),
    /Invalid/
  );
  assert.throws(() => validateService({ metricPath: '/metrics?token=secret' }, s), /Metric path/);
});

test('Cosmos connector normalizes actual API values and per-bucket network rates', async t => {
  const now = new Date().toISOString();
  const apiUrl = await fixture(t, req => {
    assert.equal(req.headers.authorization, 'Bearer cosmos_test');
    if (req.url.includes('servapps'))
      return { status: 'OK', data: [{ State: 'running' }, { State: 'exited' }] };
    return {
      status: 'OK',
      data: [
        { Key: 'cosmos.system.cpu.0', Scale: 1, Values: [{ Date: now, Value: 24 }] },
        { Key: 'cosmos.system.ram', Max: 1000, Values: [{ Date: now, Value: 250 }] },
        { Key: 'cosmos.system.netRx', TimeScale: 1, Values: [{ Date: now, Value: 3000 }] },
      ],
    };
  });
  const metrics = await collect({ ...newService('cosmos'), apiUrl, apiKey: 'cosmos_test' });
  assert.equal(metrics.find(m => m.key === 'cpu').value, 24);
  assert.equal(metrics.find(m => m.key === 'memory').value, 25);
  assert.equal(metrics.find(m => m.key === 'receive').value, 100);
  assert.equal(metrics.find(m => m.key === 'containers').value, 2);
});

test('AMP uses per-instance session authentication and unwraps API result', async t => {
  const apiUrl = await fixture(t, (req, body) => {
    assert.equal(req.headers.accept, 'application/vnd.cubecoders-ampapi');
    if (req.url.endsWith('/Login'))
      return { result: { success: true, sessionID: 'fixture-session' } };
    assert.equal(body.SESSIONID, 'fixture-session');
    return {
      result: {
        Metrics: {
          'CPU Usage': { Percent: 12 },
          'Memory Usage': { RawValue: 1024, Units: 'MB', Percent: 25 },
          'Active Users': { RawValue: 3, MaxValue: 10 },
        },
      },
    };
  });
  const metrics = await collect({
    ...newService('amp'),
    apiUrl,
    username: 'fixture',
    password: 'fixture',
  });
  assert.equal(metrics.find(m => m.key === 'players').value, 3);
  assert.equal(metrics.find(m => m.key === 'cpu').value, 12);
});

test('CrowdSec uses watcher JWT for alerts and bouncer key for decisions', async t => {
  const apiUrl = await fixture(t, req => {
    if (req.url.endsWith('/login')) return { token: 'watcher-fixture' };
    if (req.url.startsWith('/v1/alerts')) {
      assert.equal(req.headers.authorization, 'Bearer watcher-fixture');
      return [{ id: 1 }];
    }
    assert.equal(req.headers['x-api-key'], 'bouncer-fixture');
    assert.equal(req.headers.authorization, undefined);
    return [{ type: 'ban' }];
  });
  const metrics = await collect({
    ...newService('crowdsec'),
    apiUrl,
    username: 'fixture',
    password: 'fixture',
    apiKey: 'bouncer-fixture',
  });
  assert.equal(metrics.find(m => m.key === 'bans').value, 1);
});

test('NZBGet high/low counters and app-level failures are handled', async t => {
  const apiUrl = await fixture(t, () => ({
    result: {
      DownloadRateHi: 1,
      DownloadRateLo: 2,
      RemainingSizeHi: 0,
      RemainingSizeLo: 900,
      PostJobCount: 0,
      DownloadPaused: false,
    },
  }));
  const values = await collect({ ...newService('nzbget'), apiUrl });
  assert.equal(values.find(m => m.key === 'speed').value, 4294967298);
  assert.equal(values.find(m => m.key === 'remaining').value, 900);
  const badUrl = await fixture(t, () => ({ error: { message: 'private internal detail' } }));
  await assert.rejects(
    collect({ ...newService('nzbget', 'nzbget-bad'), apiUrl: badUrl }),
    /rejected/
  );
});

test('Prometheus parser preserves labels and ignores non-finite values', () => {
  const samples = parsePrometheus(
    '# HELP test\nnode_cpu_seconds_total{cpu="0",mode="idle"} 12.5\nbad NaN\nmissing +Inf\nzero 0\n'
  );
  assert.equal(samples.length, 2);
  assert.equal(samples[0].labels.mode, 'idle');
  assert.equal(samples[1].value, 0);
});

test('HTTP redirects do not forward source credentials', async t => {
  // The redirect target is a live server that records requests, so a followed redirect is seen.
  const received = [];
  const target = http.createServer((req, res) => {
    received.push(req.headers);
    res.end('{}');
  });
  const server = http.createServer((req, res) => {
    res.writeHead(302, { Location: `http://127.0.0.1:${target.address().port}/secret` });
    res.end();
  });
  allowLoopback(t);
  for (const s of [target, server]) {
    await new Promise(r => s.listen(0, '127.0.0.1', r));
    t.after(() => new Promise(r => s.close(r)));
  }
  await assert.rejects(
    collect({
      ...newService('json'),
      apiUrl: `http://127.0.0.1:${server.address().port}`,
      apiKey: 'fixture-secret',
      metrics: [{ key: 'value', label: 'Value', path: 'value' }],
    }),
    error => /redirected/.test(error.message) && !error.message.includes('fixture-secret')
  );
  assert.deepEqual(received, []);
});

test('failed configuration persistence leaves all running settings unchanged', t => {
  const config = new ConfigStore(temp(t)),
    before = JSON.stringify(config.value);
  t.mock.method(fs, 'renameSync', () => {
    throw Object.assign(new Error('Fixture persistence failure'), { code: 'EIO' });
  });
  for (const mutate of [
    () => config.update('cosmos-1', { enabled: false }),
    () => config.add({ type: 'amp' }),
    () => config.remove('cosmos-1'),
    () => config.updateGlobal({ pollSeconds: 120 }),
  ]) {
    assert.throws(mutate);
    assert.equal(JSON.stringify(config.value), before);
  }
  assert.equal(
    fs.readFileSync(config.file, 'utf8').trim(),
    JSON.stringify(JSON.parse(before), null, 2)
  );
  assert.deepEqual(fs.readdirSync(path.dirname(config.file)), ['config.json']);
});

test('saving configuration never follows a pre-existing temporary-file symlink', t => {
  const directory = temp(t),
    config = new ConfigStore(path.join(directory, 'data')),
    unrelated = path.join(directory, 'unrelated.txt'),
    stale = config.file + '.tmp';
  fs.writeFileSync(unrelated, 'Keep these unrelated bytes', { mode: 0o644 });
  fs.symlinkSync(unrelated, stale);
  config.updateGlobal({ title: 'A safely saved dashboard' });
  assert.ok(fs.readFileSync(unrelated, 'utf8') === 'Keep these unrelated bytes');
  assert.ok(fs.lstatSync(stale).isSymbolicLink());
  assert.ok(fs.lstatSync(config.file).isFile());
  assert.equal(fs.statSync(config.file).mode & 0o777, 0o600);
  assert.equal(new ConfigStore(path.dirname(config.file)).value.title, 'A safely saved dashboard');
});

test('outages and absent measurements restart pending alert durations', t => {
  const store = new Store(temp(t));
  t.after(() => store.close());
  const s = {
    ...newService('linux'),
    rules: [{ key: 'cpu', operator: 'gt', threshold: 80, forSeconds: 120 }],
  };
  const now = Date.now();
  store.evaluate(s, measurement(95), null, now);
  store.evaluate(s, [], 'Failed', now + 60000);
  assert.deepEqual(store.evaluate(s, measurement(96), null, now + 120000), []);
  assert.deepEqual(store.evaluate(s, measurement(96), null, now + 180000), []);
  assert.equal(store.evaluate(s, measurement(96), null, now + 240000)[0].kind, 'firing');
  store.clearAlerts(s.id);
  store.evaluate(s, measurement(95), null, now);
  assert.deepEqual(store.evaluate(s, measurement(95), null, now + 3600000), []);
  store.clearAlerts(s.id);
  store.evaluate(s, measurement(95), null, now);
  store.evaluate(s, [], null, now + 60000);
  assert.deepEqual(store.evaluate(s, measurement(95), null, now + 120000), []);
});

test('long-range history marks collection outages before downsampling', t => {
  const store = new Store(temp(t));
  t.after(() => store.close());
  const now = Date.now();
  store.record('a', measurement(10), null, now - 6 * 3600000);
  store.record('a', measurement(20), null, now - 3600000);
  store.record('a', measurement(30), null, now);
  const history = store.history('a', '30d', now, 60);
  assert.ok(history.points.some(p => p.gapBefore));
});

test('custom readings ignore empty values and retain signed numeric measurements', async t => {
  const apiUrl = await fixture(t, () => ({
    empty: [],
    blank: ' ',
    absent: null,
    flag: false,
    valid: '-12.5',
    zero: 0,
  }));
  const metrics = await collect({
    ...newService('json'),
    apiUrl,
    metrics: ['empty', 'blank', 'absent', 'flag', 'valid', 'zero'].map(key => ({
      key,
      label: key,
      path: key,
      scale: 1,
      unit: '',
    })),
  });
  assert.deepEqual(
    metrics.map(m => [m.key, m.value]),
    [
      ['valid', -12.5],
      ['zero', 0],
    ]
  );
});

test('null Cosmos readings are unavailable rather than measured zero', async t => {
  const now = new Date().toISOString();
  const apiUrl = await fixture(t, req =>
    req.url.includes('servapps')
      ? { status: 'OK', data: [] }
      : {
          status: 'OK',
          data: [
            { Key: 'cosmos.system.cpu.0', Values: [{ Date: now, Value: null }] },
            { Key: 'cosmos.system.netRx', Values: [{ Date: now, Value: null }] },
          ],
        }
  );
  const metrics = await collect({ ...newService('cosmos'), apiUrl });
  assert.ok(!metrics.some(m => ['cpu', 'receive'].includes(m.key)));
});

test('collection errors do not expose long credentials and multiline secrets are rejected', async t => {
  const secret = 'private-fixture-'.repeat(60);
  const { app, call } = await appFor(t, {
    collector: async () => {
      throw new Error('Unexpected ' + secret);
    },
  });
  await call('/api/services/cosmos-1', 'PATCH', {
    apiUrl: 'http://configured.invalid',
    apiKey: secret,
  });
  await app.tick(true);
  const result = await call('/api/dashboard');
  assert.ok(!JSON.stringify(result.body).includes('private-fixture'));
  assert.match(app.store.latest('cosmos-1').error, /redacted/);
  assert.equal(
    (await call('/api/services/cosmos-1', 'PATCH', { apiKey: 'invalid\nkey' })).status,
    400
  );
});

test('a quick pause and resume still discards the earlier in-flight result', async t => {
  let release, entered;
  const started = new Promise(r => (entered = r));
  const { app, call } = await appFor(t, {
    collector: async () => {
      entered();
      return new Promise(r => (release = r));
    },
  });
  await call('/api/services/cosmos-1', 'PATCH', { apiUrl: 'http://configured.invalid' });
  const pending = app.poll(app.config.get('cosmos-1'));
  await started;
  await call('/api/services/cosmos-1', 'PATCH', { enabled: false });
  await call('/api/services/cosmos-1', 'PATCH', { enabled: true });
  release(measurement(99));
  await pending;
  assert.equal(app.store.latest('cosmos-1').lastSuccess, null);
});

test('HTTP checks accept successful responses with no body', async t => {
  const server = http.createServer((req, res) => {
    res.writeHead(204);
    res.end();
  });
  allowLoopback(t);
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(() => new Promise(r => server.close(r)));
  const metrics = await collect({
    ...newService('http'),
    apiUrl: `http://127.0.0.1:${server.address().port}`,
  });
  assert.equal(metrics.find(m => m.key === 'available').value, 1);
});

test('a collection deadline records a failure and follows the normal retry interval', async t => {
  let calls = 0;
  const { app, call } = await appFor(t, {
    collectionTimeoutMs: 10,
    collector: async s => {
      calls++;
      return new Promise((resolve, reject) =>
        s.signal.addEventListener('abort', () => reject(s.signal.reason), { once: true })
      );
    },
  });
  await call('/api/services/cosmos-1', 'PATCH', { apiUrl: 'http://configured.invalid' });
  await app.tick(true);
  assert.match(app.store.latest('cosmos-1').error, /exceeded its time limit/);
  assert.ok(app.store.history('cosmos-1').points.some(p => !p.ok));
  await app.tick();
  assert.equal(calls, 1);
});

test('connection tests use draft settings without saving, recording, or alerting', async t => {
  const calls = [];
  const { app, call } = await appFor(t, {
    collector: async s => {
      calls.push(s);
      return measurement(95);
    },
  });
  await call('/api/services/cosmos-1', 'PATCH', {
    apiKey: 'saved-fixture',
    apiUrl: 'http://saved.invalid',
    enabled: false,
  });
  const before = JSON.stringify(app.config.value);
  // A saved credential is never sent to a different server without being re-entered.
  const elsewhere = await call('/api/test-service', 'POST', {
    serviceId: 'cosmos-1',
    settings: { apiUrl: 'http://draft.invalid' },
  });
  assert.equal(elsewhere.status, 400);
  assert.match(elsewhere.body.error, /Re-enter or clear the saved credentials/);
  assert.equal(calls.length, 0);
  const preview = await call('/api/test-service', 'POST', {
    serviceId: 'cosmos-1',
    settings: { apiUrl: 'http://saved.invalid/draft' },
  });
  assert.equal(preview.status, 200);
  assert.equal(preview.body.metrics[0].value, 95);
  assert.equal(calls[0].apiKey, 'saved-fixture');
  assert.equal(calls[0].apiUrl, 'http://saved.invalid/draft');
  assert.match(calls[0].id, /^test-/);
  assert.equal(JSON.stringify(app.config.value), before);
  assert.equal(app.store.latest('cosmos-1').lastSuccess, null);
  assert.deepEqual(app.store.alerts(), []);
  assert.ok(!JSON.stringify(preview.body).includes('saved-fixture'));
  const added = await call('/api/test-service', 'POST', {
    settings: { type: 'amp', apiUrl: 'http://new.invalid', password: 'draft-only' },
  });
  assert.equal(added.status, 200);
  assert.equal(JSON.stringify(app.config.value), before);
});

test('connection test failures are sanitized and require a valid source and same-origin request', async t => {
  const { call } = await appFor(t, {
    collector: async s => {
      throw new Error('Authentication failed. Check ' + s.apiKey);
    },
  });
  assert.equal(
    (await call('/api/test-service', 'POST', { settings: { type: 'cosmos' } })).status,
    400
  );
  assert.equal(
    (
      await call('/api/test-service', 'POST', {
        serviceId: 'missing',
        settings: { type: 'cosmos' },
      })
    ).status,
    400
  );
  assert.equal(
    (
      await call('/api/test-service', 'POST', {
        settings: { type: 'link', url: 'https://example.com' },
      })
    ).status,
    400
  );
  const failed = await call('/api/test-service', 'POST', {
    settings: { type: 'cosmos', apiUrl: 'http://fixture.invalid', apiKey: 'private-fixture' },
  });
  assert.equal(failed.status, 422);
  assert.ok(!JSON.stringify(failed.body).includes('private-fixture'));
  assert.equal(
    (
      await call(
        '/api/test-service',
        'POST',
        { settings: { type: 'cosmos' } },
        { Origin: 'https://untrusted.example' }
      )
    ).status,
    403
  );
});

test('connection tests respect their time limit', async t => {
  const { app, call } = await appFor(t, {
    collectionTimeoutMs: 10,
    collector: async s =>
      new Promise((resolve, reject) =>
        s.signal.addEventListener('abort', () => reject(s.signal.reason), { once: true })
      ),
  });
  const res = await call('/api/test-service', 'POST', {
    settings: { type: 'cosmos', apiUrl: 'http://fixture.invalid' },
  });
  assert.equal(res.status, 422);
  assert.match(res.body.error, /time limit/);
  assert.deepEqual(app.dashboard().alerts, []);
});

test('Sonarr and Radarr queue health includes unknown failed downloads', async t => {
  const apiUrl = await fixture(t, req =>
    req.url.endsWith('/queue/status')
      ? {
          totalCount: 1,
          errors: false,
          warnings: false,
          unknownErrors: true,
          unknownWarnings: true,
        }
      : []
  );
  for (const type of ['sonarr', 'radarr']) {
    const metrics = await collect({ ...newService(type), apiUrl });
    assert.equal(metrics.find(m => m.key === 'queue').value, 1);
    assert.equal(metrics.find(m => m.key === 'queue_errors').value, 1);
    assert.equal(metrics.find(m => m.key === 'queue_warnings').value, 1);
  }
});

test('Prowlarr totals include RSS queries and authentication failures', async t => {
  const apiUrl = await fixture(t, req =>
    req.url.startsWith('/api/v1/indexerstats')
      ? {
          indexers: [
            {
              numberOfQueries: 4,
              numberOfRssQueries: 12,
              numberOfFailedQueries: 2,
              numberOfFailedGrabs: 3,
              numberOfFailedRssQueries: 9,
              numberOfFailedAuthQueries: 2,
            },
          ],
        }
      : []
  );
  const metrics = await collect({ ...newService('prowlarr'), apiUrl });
  assert.equal(metrics.find(m => m.key === 'queries_24h').value, 16);
  assert.equal(metrics.find(m => m.key === 'failures_24h').value, 16);
});

test('numeric source values reject oversized strings without blocking collection', async t => {
  const values = {
    valid: ' -1.25e+2 ',
    integer: '42',
    decimal: '.5',
    trailing: '1.',
    malformed: '7'.repeat(50000) + '!',
    oversized: '0'.repeat(50000) + '1',
  };
  const base = await fixture(t, () => values);
  const service = {
    ...newService('json'),
    apiUrl: base,
    metrics: Object.keys(values).map(key => ({ key, label: key, path: key })),
  };
  const readings = await collect(service);
  assert.deepEqual(
    readings.map(m => [m.key, m.value]),
    [
      ['valid', -125],
      ['integer', 42],
      ['decimal', 0.5],
      ['trailing', 1],
    ]
  );
});

test('Prometheus label parsing rejects malformed input and bounds line size', () => {
  assert.deepEqual(parsePrometheus('sample{' + 'a'.repeat(8000) + '} 1\n'), []);
  assert.throws(() => parsePrometheus('sample{' + 'a'.repeat(50000) + '} 1\n'), /8 KB/);
  assert.deepEqual(parsePrometheus('sample{a="one",a="two"} 1\n'), []);
  const [sample] = parsePrometheus('sample{path="a\\\\b",line="hello\\nworld"} -1.5e2\n');
  assert.equal(sample.value, -150);
  assert.equal(sample.labels.path, 'a\\b');
  assert.equal(sample.labels.line, 'hello\nworld');
});

test('reserved metric rules cannot override connection alerts', () => {
  assert.throws(
    () =>
      validateService(
        { rules: [{ key: '__availability', operator: 'lt', threshold: 0 }] },
        newService('linux')
      ),
    /reserved/
  );
});

test('manual refresh survives history storage failures and reports them', async t => {
  const { app, call } = await appFor(t, { collector: async () => measurement(10) });
  app.config.update('linux', { apiUrl: 'http://fixture.invalid' });
  app.store.record = () => {
    throw new Error('SQLITE_FULL');
  };
  const original = console.error;
  const errors = [];
  console.error = (...args) => errors.push(args.join(' '));
  t.after(() => {
    console.error = original;
  });
  assert.equal((await call('/api/refresh', 'POST', {})).status, 202);
  await new Promise(resolve => setTimeout(resolve, 20));
  // The write failure is caught inside the poll, logged with its code and surfaced.
  assert.ok(errors.some(line => line.startsWith('History database write failed')));
  assert.ok(!errors.includes('Collector refresh failed'));
  assert.equal(app.dashboard().storage.code, 'Error');
});

test('Linux keeps missing network counters unavailable and bounds filesystem work', async t => {
  const server = http.createServer((req, res) =>
    res.end(
      'node_memory_MemTotal_bytes 1000\nnode_memory_MemAvailable_bytes 500\n' +
        Array.from(
          { length: 10000 },
          (_, i) =>
            `node_filesystem_size_bytes{mountpoint="/${i}",fstype="ext4"} 1000\nnode_filesystem_avail_bytes{mountpoint="/${i}",fstype="ext4"} 500\n`
        ).join('')
    )
  );
  allowLoopback(t);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const service = { ...newService('linux'), apiUrl: `http://127.0.0.1:${server.address().port}` };
  await collect(service);
  const metrics = await collect(service);
  assert.ok(!metrics.some(m => ['receive', 'transmit'].includes(m.key)));
  assert.equal(metrics.filter(m => m.key.startsWith('disk_free_')).length, 200);
  assert.ok(metrics.length <= 512);
});

test('oversized upstream labels are shortened before history persistence', async t => {
  const base = await fixture(t, () => ({
    data: [
      {
        id: 'node/test',
        name: 'x'.repeat(262144),
        type: 'node',
        node: 'test',
        status: 'online',
        cpu: 0.1,
        maxcpu: 1,
        mem: 1,
        maxmem: 2,
      },
    ],
  }));
  // One long name no longer fails the whole source (the 1.5 boundary review): the label is
  // shortened to the label limit, and nothing longer is stored.
  const metrics = await collect({ ...newService('proxmox'), apiUrl: base, apiKey: 'test-only' });
  const cpu = metrics.find(m => m.key === 'node/test.cpu');
  assert.equal(cpu.label, 'x'.repeat(199) + '… · CPU');
  assert.ok(metrics.every(m => m.label.length <= 240 && m.key.length <= 150));
});

test('long-range buckets retain successful readings alongside failure markers', t => {
  const store = new Store(temp(t));
  t.after(() => store.close());
  const now = Date.now();
  store.record('source', measurement(11), null, now - 60000);
  store.record('source', [], 'Unavailable', now - 30000);
  store.record('source', measurement(22), null, now - 10000);
  const history = store.history('source', '30d', now);
  assert.equal(history.totalSamples, 2);
  assert.ok(history.points.some(p => p.ok && p.metrics[0].value === 22));
  assert.ok(history.points.some(p => !p.ok));
  assert.equal(history.points.find(p => p.ok).gapBefore, true);
  store.record('source', [], 'Unavailable', now);
  const trailing = store.history('source', '30d', now);
  assert.ok(trailing.points.some(p => p.ok));
  assert.equal(trailing.points.at(-1).ok, false);
});

test('AdGuard zero query strings retain a zero blocking percentage', async t => {
  const base = await fixture(t, () => ({
    num_dns_queries: '0',
    num_blocked_filtering: '0',
    avg_processing_time: '0',
  }));
  const values = await collect({ ...newService('adguard'), apiUrl: base });
  assert.equal(values.find(m => m.key === 'blocked_percent').value, 0);
});

test('multiple failures within one history bucket cannot bridge an earlier outage', t => {
  const store = new Store(temp(t));
  t.after(() => store.close());
  // The start of a bucket near the end (145 min wide: whole 5-minute summary slots).
  const now = Date.now(),
    { from, width } = historyWindow('30d', now),
    boundary = from + width * 297;
  store.record('source', measurement(10), null, boundary - 60000);
  store.record('source', [], 'First outage', boundary + 10000);
  store.record('source', measurement(20), null, boundary + 60000);
  store.record('source', [], 'Second outage', boundary + 100000);
  const h = store.history('source', '30d', now);
  assert.equal(h.points.find(p => p.ok && p.metrics[0].value === 20).gapBefore, true);
  assert.equal(h.points.at(-1).ok, false);
});

test('*arr health issues count warnings and errors; notices are reported separately', async t => {
  const health = [
    { type: 'notice', message: 'Update available' },
    { type: 'warning', message: 'Indexer unavailable' },
    { type: 'error', message: 'Download client unavailable' },
  ];
  const apiUrl = await fixture(t, req =>
    req.url.endsWith('/health')
      ? health
      : req.url.endsWith('/queue/status')
        ? { totalCount: 0 }
        : req.url.startsWith('/api/v1/indexerstats')
          ? { indexers: [] }
          : []
  );
  for (const type of ['sonarr', 'radarr', 'prowlarr']) {
    const metrics = await collect({ ...newService(type), apiUrl });
    assert.equal(metrics.find(m => m.key === 'health_issues').value, 2, type);
    assert.equal(metrics.find(m => m.key === 'health_notices').value, 1, type);
  }
});

test('the per-request time limit follows the requested value, with 12 s by default', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  t.mock.method(
    transport,
    'fetch',
    (_, options) =>
      new Promise((_, reject) =>
        options.signal.addEventListener('abort', () => reject(new DOMException('x', 'AbortError')))
      )
  );
  const source = { ...newService('json'), apiUrl: 'https://slow.example.test' };
  const settle = () => new Promise(resolve => setImmediate(resolve));
  const pending = request({ ...source, requestTimeoutMs: 20000 });
  await settle();
  t.mock.timers.tick(12000);
  await settle();
  t.mock.timers.tick(8000);
  await assert.rejects(pending, /timed out after 20 seconds/);
  const fallback = request(source);
  await settle();
  t.mock.timers.tick(12000);
  await assert.rejects(fallback, /timed out after 12 seconds/);
});
