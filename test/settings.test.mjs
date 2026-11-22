import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { createApp } from '../server.mjs';
import { ConfigStore, cycleSeconds } from '../lib/config.mjs';
import { newService, configured, noCollector } from '../lib/catalog.mjs';
import { Store } from '../lib/store.mjs';
import { configureDestinations } from '../lib/destinations.mjs';
// Fixture hostnames resolve instantly to a documentation address, never via real DNS.
configureDestinations({ lookup: async () => [{ address: '192.0.2.1' }] });
const measurements = value => [{ key: 'cpu', label: 'CPU', value, unit: '%' }];
function temporary(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-settings-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}
async function fixture(t, options = {}) {
  const directory = temporary(t),
    app = await createApp({
      directory,
      port: 0,
      password: 'fixture-password',
      allowedHosts: '',
      webhook: '',
      startScheduler: false,
      ...options,
    });
  const address = await app.listen();
  t.after(() => app.close());
  const base = `http://127.0.0.1:${address.port}`;
  const call = async (route, method = 'GET', body, authenticated = true) => {
    const r = await fetch(base + route, {
      method,
      headers: {
        'Content-Type': 'application/json',
        'X-Goblin-Request': '1',
        ...(authenticated
          ? { Authorization: 'Basic ' + Buffer.from('admin:fixture-password').toString('base64') }
          : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: r.status, body: await r.json() };
  };
  return { app, directory, call };
}
test('old configuration gains complete defaults without losing source or email credentials', t => {
  const dir = temporary(t),
    c = new ConfigStore(dir);
  c.update('linux', { apiKey: 'fixture-private' });
  c.updateGlobal({
    email: {
      from: 'sender@example.com',
      to: 'recipient@example.com',
      password: 'fixture-email-private',
      enabled: true,
    },
  });
  const saved = JSON.parse(fs.readFileSync(c.file));
  for (const key of ['appearance', 'monitoring', 'alerts', 'subtitle']) delete saved[key];
  for (const s of saved.services) {
    delete s.pollSeconds;
    delete s.showOnDashboard;
  }
  fs.writeFileSync(c.file, JSON.stringify(saved));
  const migrated = new ConfigStore(dir);
  assert.equal(migrated.get('linux').apiKey, 'fixture-private');
  assert.equal(migrated.value.email.password, 'fixture-email-private');
  assert.equal(migrated.value.appearance.showPaused, true);
  assert.equal(migrated.value.monitoring.concurrency, 4);
  assert.equal(migrated.get('linux').pollSeconds, 0);
  assert.equal(migrated.get('linux').showOnDashboard, true);
});
test('nested preference edits persist atomically and reject malformed or out-of-range values', async t => {
  const { app, call, directory } = await fixture(t);
  assert.equal(
    (
      await call('/api/settings', 'PATCH', {
        title: 'My lab',
        subtitle: 'One quiet page',
        appearance: { accent: 'violet', timezone: 'America/Chicago', columns: '2' },
        monitoring: { concurrency: 2 },
        alerts: { notifyOnRecovery: false },
      })
    ).status,
    200
  );
  await call('/api/settings', 'PATCH', { appearance: { density: 'compact' } });
  const c = new ConfigStore(directory);
  assert.equal(c.value.appearance.accent, 'violet');
  assert.equal(c.value.appearance.density, 'compact');
  assert.equal(c.value.monitoring.concurrency, 2);
  assert.equal(c.value.alerts.notifyOnAlert, true);
  const before = JSON.stringify(app.config.value);
  for (const body of [
    { title: '' },
    { appearance: { timezone: 'Missing/Invalid' } },
    { appearance: { showPaused: 'false' } },
    { appearance: { columns: '8' } },
    { monitoring: { concurrency: 0 } },
    { monitoring: { timeoutSeconds: 121 } },
    { alerts: { enabled: 1 } },
    { appearance: null },
    { pollSeconds: null },
    { retentionDays: 366 },
  ]) {
    assert.equal((await call('/api/settings', 'PATCH', body)).status, 400);
    assert.equal(JSON.stringify(app.config.value), before);
  }
});
test('redacted export and system diagnostics are authenticated and exclude secrets and server paths', async t => {
  const { app, call, directory } = await fixture(t);
  app.config.update('linux', {
    apiKey: 'fixture-source-key',
    password: 'fixture-source-password',
    apiUrl: 'https://metrics.example.com',
  });
  app.config.updateGlobal({
    email: {
      from: 'sender@example.com',
      to: 'recipient@example.com',
      password: 'fixture-mail-secret',
    },
  });
  for (const route of ['/api/system', '/api/config/export', '/api/docs?doc=configuration'])
    assert.equal((await call(route, 'GET', undefined, false)).status, 401);
  const exp = await call('/api/config/export');
  assert.equal(exp.status, 200);
  assert.equal(exp.body.containsSecrets, false);
  assert.equal(exp.body.config.services.find(s => s.id === 'linux').apiKeyConfigured, true);
  assert.equal(exp.body.config.email.passwordConfigured, true);
  const sys = await call('/api/system');
  assert.equal(sys.status, 200);
  assert.equal(sys.body.authenticationRequired, true);
  assert.equal(sys.body.collection.concurrency, 4);
  assert.equal(sys.body.data.samples, 0);
  assert.ok(sys.body.data.configBytes > 0);
  const serialized = JSON.stringify([exp.body, sys.body]);
  for (const secret of [
    'fixture-source-key',
    'fixture-source-password',
    'fixture-mail-secret',
    directory,
  ])
    assert.ok(!serialized.includes(secret));
  assert.equal((await call('/api/docs?doc=../../data/config')).status, 404);
  assert.equal((await call('/api/docs?doc=__proto__')).status, 404);
});
test('hidden sources still collect and source intervals control due times and graph gap thresholds', async t => {
  const calls = [];
  // Scheduling uses a monotonic clock, so a wall-clock change cannot skip or repeat polls.
  let now = 1000;
  const { app, call } = await fixture(t, {
    monotonic: () => now,
    collector: async s => {
      calls.push(s.id);
      return measurements(25);
    },
  });
  await call('/api/services/linux', 'PATCH', {
    apiUrl: 'https://fixture.invalid',
    showOnDashboard: false,
    pollSeconds: 3600,
  });
  await app.tick();
  now += 61000;
  await app.tick();
  assert.deepEqual(calls, ['linux']);
  assert.equal(app.dashboard().services.find(s => s.id === 'linux').status, 'live');
  assert.equal((await call('/api/history/linux?range=24h')).body.pollSeconds, 3600);
  now += 3600000;
  await app.tick();
  assert.deepEqual(calls, ['linux', 'linux']);
  for (const value of [-1, 1, 14, 3601, '60'])
    assert.equal((await call('/api/services/linux', 'PATCH', { pollSeconds: value })).status, 400);
});
test('configured collector concurrency bounds work and appearance changes do not repoll sources', async t => {
  let active = 0,
    peak = 0,
    calls = 0;
  const { app, call } = await fixture(t, {
    collector: async () => {
      calls++;
      active++;
      peak = Math.max(active, peak);
      await new Promise(r => setTimeout(r, 5));
      active--;
      return measurements(5);
    },
  });
  for (const id of ['linux', 'windows', 'cosmos-1', 'cosmos-2'])
    app.config.update(id, { apiUrl: 'https://fixture.invalid' });
  await call('/api/settings', 'PATCH', { monitoring: { concurrency: 2 } });
  await app.tick();
  assert.equal(peak, 2);
  assert.equal(calls, 4);
  await call('/api/settings', 'PATCH', { appearance: { accent: 'pink' } });
  await app.tick();
  assert.equal(calls, 4);
});
test('availability sensitivity requires both the chosen failure count and elapsed time', t => {
  const store = new Store(temporary(t));
  t.after(() => store.close());
  const service = {
    ...newService('linux'),
    availabilityFailures: 3,
    availabilitySeconds: 120,
    recoverySuccesses: 1,
    recoverySeconds: 0,
  };
  const now = Date.now();
  assert.deepEqual(store.evaluate(service, [], 'Offline', now), []);
  assert.deepEqual(store.evaluate(service, [], 'Offline', now + 60000), []);
  assert.equal(store.evaluate(service, [], 'Offline', now + 120000)[0].kind, 'firing');
  assert.equal(store.evaluate(service, [], null, now + 180000)[0].kind, 'resolved');
  service.availabilityFailures = 1;
  service.availabilitySeconds = 0;
  assert.equal(store.evaluate(service, [], 'Offline', now + 240000)[0].kind, 'firing');
});
test('master alert switch keeps collection and history but silently resets alert evaluation', async t => {
  const { app, call } = await fixture(t, {
    collector: async () => {
      throw new Error('Offline');
    },
  });
  app.config.update('linux', { apiUrl: 'https://fixture.invalid' });
  await call('/api/settings', 'PATCH', {
    monitoring: { availabilityFailures: 1, availabilitySeconds: 0 },
  });
  await app.poll(app.config.get('linux'));
  assert.equal(app.store.alerts().length, 1);
  const events = app.store.events().length;
  await call('/api/settings', 'PATCH', { alerts: { enabled: false } });
  assert.equal(app.store.alerts().length, 0);
  await app.poll(app.config.get('linux'));
  assert.equal(app.store.alerts().length, 0);
  assert.equal(app.store.events().length, events);
  assert.ok(app.store.latest('linux').lastAttempt);
  await call('/api/settings', 'PATCH', { alerts: { enabled: true } });
  await app.poll(app.config.get('linux'));
  assert.equal(app.store.alerts().length, 1);
});
test('notification switches filter future transitions without suppressing in-app alert events', async t => {
  const sent = [];
  let failing = true;
  const { app, call } = await fixture(t, {
    collector: async () => {
      if (failing) throw new Error('Offline');
      return measurements(20);
    },
    mailTransportFactory: () => ({
      sendMail: async message => {
        sent.push(message);
        return { accepted: ['recipient@example.com'] };
      },
      close() {},
    }),
  });
  app.config.update('linux', { apiUrl: 'https://fixture.invalid' });
  await call('/api/settings', 'PATCH', {
    monitoring: {
      availabilityFailures: 1,
      availabilitySeconds: 0,
      recoverySuccesses: 1,
      recoverySeconds: 0,
    },
    alerts: { notifyOnAlert: false },
    email: {
      enabled: true,
      from: 'sender@example.com',
      to: 'recipient@example.com',
      password: 'fixture-secret',
    },
  });
  await app.poll(app.config.get('linux'));
  await app.flushNotifications();
  assert.equal(sent.length, 0);
  assert.equal(app.store.alerts().length, 1);
  failing = false;
  await app.poll(app.config.get('linux'));
  await app.flushNotifications();
  assert.equal(sent.length, 1);
  assert.match(sent[0].subject, /recovered|resolved|restored/i);
  assert.equal(app.store.events().length, 2);
});
test('fast source intervals can use a free slot while another source is still collecting', async t => {
  let release, slowStarted;
  const started = new Promise(r => (slowStarted = r));
  const calls = [];
  let now = 1000;
  const { app } = await fixture(t, {
    monotonic: () => now,
    collector: async s => {
      calls.push(s.id);
      if (s.id === 'windows') {
        slowStarted();
        await new Promise(r => (release = r));
      }
      return measurements(5);
    },
  });
  app.config.updateGlobal({ monitoring: { concurrency: 2 } });
  app.config.update('linux', { apiUrl: 'https://fixture.invalid', pollSeconds: 15 });
  app.config.update('windows', { apiUrl: 'https://fixture.invalid', pollSeconds: 60 });
  const first = app.tick();
  await started;
  await new Promise(r => setImmediate(r));
  now += 20000;
  await app.tick();
  assert.equal(calls.filter(x => x === 'linux').length, 2);
  assert.equal(calls.filter(x => x === 'windows').length, 1);
  release();
  await first;
});
test('consecutive slow timeout failures can mature into availability alerts', t => {
  const store = new Store(temporary(t));
  t.after(() => store.close());
  const s = {
    ...newService('linux'),
    pollSeconds: 15,
    collectionTimeoutSeconds: 90,
    availabilityFailures: 2,
    availabilitySeconds: 60,
  };
  const now = Date.now();
  assert.deepEqual(store.evaluate(s, [], 'Timed out', now), []);
  const events = store.evaluate(s, [], 'Timed out', now + 105000);
  assert.equal(events.length, 1);
  assert.equal(events[0].kind, 'firing');
});
test('bundled guides are available through the allowlisted reader', async t => {
  const { call } = await fixture(t);
  for (const doc of [
    'installation',
    'configuration',
    'integrations',
    'architecture',
    'security',
    // 1.5: signing in, sessions, HTTPS and the escape hatches (docs/authentication.md).
    'authentication',
    'troubleshooting',
    // 1.5: durable alert delivery, its history, signing and the full disk.
    'notifications',
  ]) {
    const r = await call('/api/docs?doc=' + doc);
    assert.equal(r.status, 200, doc);
    assert.equal(typeof r.body.title, 'string');
    if (doc === 'authentication') assert.equal(r.body.title, 'Signing in');
    if (doc === 'notifications') assert.equal(r.body.title, 'Alerts and notifications');
    assert.match(r.body.markdown, /^# /);
    assert.ok(r.body.markdown.length > 200);
  }
});

// 1.5 #7 hot paths: sources by ID and the collection cycle cost O(1) per call.
test('sources are found by ID through an index that follows every saved change', t => {
  const config = new ConfigStore(temporary(t)),
    find = id => config.value.services.find(s => s.id === id);
  const added = config.add({ type: 'linux', name: 'Added' });
  config.update('proxmox', { name: 'Renamed' });
  config.remove('docker');
  config.updateGlobal({ title: 'Indexed' });
  for (const id of [...config.value.services.map(s => s.id), 'docker', 'missing', '', undefined])
    assert.equal(config.get(id), find(id), String(id));
  assert.equal(config.get(added.id).name, 'Added');
  assert.equal(config.get('proxmox').name, 'Renamed');
  assert.equal(config.get('docker'), undefined);
  for (const name of ['__proto__', 'constructor', 'toString', 'hasOwnProperty'])
    assert.equal(config.get(name), undefined, name);
  // O(1): once indexed, a lookup no longer walks the list of sources.
  let walked = 0;
  const services = config.value.services;
  config.value = {
    ...config.value,
    services: new Proxy(services, {
      get(target, key, receiver) {
        if (key === Symbol.iterator || key === 'find') walked++;
        return Reflect.get(target, key, receiver);
      },
    }),
  };
  config.get('proxmox');
  const indexing = walked;
  for (let n = 0; n < 50; n++) config.get('proxmox');
  assert.equal(walked, indexing, 'later lookups use the index');
  // A replaced configuration value (a save) is indexed again.
  config.update('proxmox', { name: 'Again' });
  assert.equal(config.get('proxmox').name, 'Again');
});

test('collection cycles match 1.4.3 and are computed once per saved configuration', t => {
  const config = new ConfigStore(temporary(t)),
    interval = s => s.pollSeconds || config.value.pollSeconds;
  // server.mjs's figures in 1.4.3, word for word, as the reference.
  const reference = (s, timeoutMs) => {
    const active = config.value.services.filter(x => x.enabled && configured(x)),
      slowest = Math.max(timeoutMs(s), ...active.map(timeoutMs)) / 1000;
    return (
      interval(s) +
      Math.ceil(Math.max(1, active.length) / config.value.monitoring.concurrency) * slowest
    );
  };
  const timeouts = override => s =>
    override ?? { ...config.value.monitoring, ...s?.monitoring }.timeoutSeconds * 1000;
  let seed = 11;
  const random = () => (seed = (seed * 1103515245 + 12345) % 2 ** 31) / 2 ** 31,
    pick = list => list[Math.floor(random() * list.length)];
  const compare = timeoutMs => {
    for (const s of config.value.services)
      assert.equal(cycleSeconds(config, s, { interval, timeoutMs }), reference(s, timeoutMs), s.id);
  };
  const plain = timeouts(),
    fixed = timeouts(20000);
  compare(plain);
  compare(fixed);
  for (let step = 0; step < 40; step++) {
    const id = pick(config.value.services).id,
      roll = random();
    if (roll < 0.3)
      config.update(id, {
        apiUrl: random() < 0.7 ? `http://192.0.2.${step + 1}` : '',
        enabled: random() < 0.8,
      });
    else if (roll < 0.5)
      config.update(id, { monitoring: { timeoutSeconds: pick([5, 30, 90, 120, null]) } });
    else if (roll < 0.6) config.update(id, { pollSeconds: pick([0, 15, 300]) });
    else if (roll < 0.7)
      config.updateGlobal({ monitoring: { concurrency: pick([1, 2, 4, 8]), timeoutSeconds: 45 } });
    else if (roll < 0.8)
      config.add({ type: 'http', name: `Site ${step}`, url: `https://site${step}.example.test` });
    else if (roll < 0.9 && config.value.services.length > 3) config.remove(id);
    else config.updateGlobal({ pollSeconds: pick([15, 60, 600]) });
    compare(plain);
    compare(fixed);
  }
  // Nothing collected: the source's own limit, one round.
  for (const s of config.value.services) config.update(s.id, { enabled: false });
  assert.deepEqual(config.cycleStatistics(plain), { active: 0, slowestMs: -Infinity });
  compare(plain);
  // Cached: one pass over the sources per saved configuration and timeout function.
  config.update('linux', { enabled: true, apiUrl: 'http://192.0.2.1' });
  let calls = 0;
  const counted = s => (calls++, plain(s));
  const first = config.cycleStatistics(counted);
  assert.equal(calls, 1, 'one collected source');
  for (const s of config.value.services) cycleSeconds(config, s, { interval, timeoutMs: counted });
  assert.equal(calls, 1 + config.value.services.length, "only each source's own limit");
  assert.equal(config.cycleStatistics(counted), first);
  assert.equal(Object.isFrozen(first), true);
  config.update('linux', { monitoring: { timeoutSeconds: 7 } });
  assert.notEqual(config.cycleStatistics(counted), first, 'a save computes them again');
  assert.equal(config.cycleStatistics(counted).slowestMs, 7000);
});

test('the catalog says which sources are collected, as the scheduler does', () => {
  const source = (type, fields = {}) => ({ ...newService(type), ...fields });
  assert.equal(noCollector(source('link')), true);
  assert.equal(noCollector(source('netbox')), true);
  assert.equal(noCollector(source('netbox', { collector: 'json' })), false);
  assert.equal(noCollector(source('linux', { collector: 'none' })), true);
  assert.equal(configured(source('linux')), false);
  assert.equal(configured(source('linux', { apiUrl: 'http://192.0.2.1' })), true);
  assert.equal(configured(source('link', { apiUrl: 'http://192.0.2.1' })), false);
  assert.equal(configured(source('http', { url: 'https://example.test' })), true);
  assert.equal(configured(source('linux', { collector: 'http', url: 'https://x.test' })), true);
  assert.equal(configured(source('linux', { url: 'https://example.test' })), false);
});

test('a guide that is not a regular file or is too large is not served and never blocks', async t => {
  const docs = temporary(t),
    data = temporary(t);
  fs.copyFileSync(
    new URL('../docs/configuration.md', import.meta.url),
    path.join(docs, 'configuration.md')
  );
  // A FIFO with no writer, a 2 MiB file, a symlink to a real guide and a directory.
  assert.equal(spawnSync('mkfifo', [path.join(docs, 'security.md')]).status, 0);
  fs.writeFileSync(path.join(docs, 'troubleshooting.md'), 'x'.repeat(2 * 1024 * 1024));
  fs.symlinkSync(path.join(docs, 'configuration.md'), path.join(docs, 'authentication.md'));
  fs.mkdirSync(path.join(docs, 'installation.md'));
  // Uptime Goblin runs in a child: a read that blocks would stop its event loop, and this test with it.
  const password = 'fixture-docs-password-0001';
  const child = spawn(
    process.execPath,
    [
      '--input-type=module',
      '-e',
      `import { createHash } from 'node:crypto';
       import { createApp } from ${JSON.stringify(new URL('../server.mjs', import.meta.url).href)};
       const [directory, docsDirectory, password] = process.argv.slice(1);
       const derive = async (secret, salt) => createHash('sha512').update(salt).update(secret).digest();
       const app = await createApp({ directory, docsDirectory, password, port: 0, allowedHosts: '', webhook: '', trustProxy: '', startScheduler: false, legacyBasic: true, identityOptions: { derive } });
       const { port } = await app.listen();
       console.log('PORT ' + port);`,
      data,
      docs,
      password,
    ],
    { stdio: ['ignore', 'pipe', 'pipe'] }
  );
  t.after(() => child.kill('SIGKILL'));
  // A start that blocks (the hang this test guards against) fails here within 30 seconds and
  // is killed, rather than holding the run, and the child with it, for ever.
  let errors = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', chunk => (errors = (errors + chunk).slice(-4000)));
  const port = await new Promise((resolve, reject) => {
    let output = '';
    const deadline = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error(`Uptime Goblin did not listen within 30 seconds: ${errors}`));
    }, 30000);
    child.stdout.on('data', chunk => {
      output += chunk;
      const match = /PORT (\d+)/.exec(output);
      if (match) {
        clearTimeout(deadline);
        resolve(Number(match[1]));
      }
    });
    child.once('exit', code => {
      clearTimeout(deadline);
      reject(new Error(`Uptime Goblin exited (${code}) before listening: ${errors}`));
    });
  });
  const get = async route => {
    const response = await fetch(`http://127.0.0.1:${port}${route}`, {
      headers: { Authorization: 'Basic ' + Buffer.from(`admin:${password}`).toString('base64') },
      signal: AbortSignal.timeout(1000),
    });
    return { status: response.status, body: await response.json() };
  };
  const guide = await get('/api/docs?doc=configuration');
  assert.equal(guide.status, 200);
  assert.match(guide.body.markdown, /^# Configuration/);
  for (const doc of ['security', 'troubleshooting', 'authentication', 'installation']) {
    const refused = await get(`/api/docs?doc=${doc}`);
    assert.equal(refused.status, 404, doc);
    assert.equal(refused.body.error, 'Documentation is not installed', doc);
    // Uptime Goblin still answers everything else at once.
    assert.equal((await get('/health')).status, 200, `after ${doc}`);
  }
  assert.ok(fs.statSync(path.join(docs, 'security.md')).isFIFO(), 'the FIFO is left as it was');
});
