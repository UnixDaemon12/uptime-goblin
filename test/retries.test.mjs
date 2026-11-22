import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { inspect } from 'node:util';
import { DatabaseSync } from 'node:sqlite';
import { createApp } from '../server.mjs';
import { newService, publicConfig } from '../lib/catalog.mjs';
import { ConfigStore, validateService } from '../lib/config.mjs';
import { Store } from '../lib/store.mjs';
import {
  CollectionError,
  collect,
  request,
  resetCollector,
  transport,
} from '../lib/collectors.mjs';
import { configureDestinations } from '../lib/destinations.mjs';
// Fixture hostnames resolve instantly to a documentation address, never via real DNS.
configureDestinations({ lookup: async () => [{ address: '192.0.2.1' }] });
const measurements = value => [{ key: 'cpu', label: 'CPU', value, unit: '%' }];
const transient = () => new CollectionError('Connection was interrupted.', { retryable: true });
// Waits for a condition instead of a fixed sleep, which a stalled test machine can outlast.
const until = async condition => {
  for (let i = 0; i < 200 && !condition(); i++) await new Promise(r => setImmediate(r));
  assert.ok(condition(), 'condition was not reached');
};
function temporary(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-retry-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
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
  let closed = false;
  const close = async () => {
    if (!closed) {
      closed = true;
      await app.close();
    }
  };
  t.after(close);
  app.config.update('linux', {
    apiUrl: 'http://fixture.invalid',
    monitoring: { retryDelaySeconds: 1 },
  });
  const call = async (route, method = 'GET', body) => {
    const r = await fetch(`http://127.0.0.1:${address.port}` + route, {
      method,
      headers: {
        'Content-Type': 'application/json',
        'X-Goblin-Request': '1',
        Authorization: 'Basic ' + Buffer.from('admin:fixture-password').toString('base64'),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { status: r.status, body: await r.json() };
  };
  // Verify the password once up front (slow scrypt), so later timed requests use the
  // cached credential like a signed-in browser does.
  await call('/api/dashboard');
  return { app, directory, call, close, source: () => app.config.get('linux') };
}
test('retry defaults migrate and source options inherit, persist, redact and accept null resets', t => {
  const directory = temporary(t),
    config = new ConfigStore(directory);
  assert.equal(config.value.monitoring.retryCount, 2);
  assert.equal(config.value.monitoring.retryDelaySeconds, 2);
  assert.equal(config.value.monitoring.recoverySuccesses, 2);
  assert.equal(config.value.monitoring.recoverySeconds, 60);
  config.update('linux', {
    apiKey: 'fixture-private',
    monitoring: { retryCount: 0, recoverySeconds: 120, timeoutSeconds: 10 },
    alerts: { notifyAvailability: false, notifyMeasurements: true },
  });
  config.update('linux', {
    monitoring: { retryCount: null },
    alerts: { notifyMeasurements: null },
  });
  const saved = new ConfigStore(directory);
  assert.deepEqual(saved.get('linux').monitoring, { recoverySeconds: 120, timeoutSeconds: 10 });
  assert.deepEqual(saved.get('linux').alerts, { notifyAvailability: false });
  assert.equal(saved.get('linux').apiKey, 'fixture-private');
  assert.ok(!JSON.stringify(publicConfig(saved.value)).includes('fixture-private'));
  const raw = JSON.parse(fs.readFileSync(config.file));
  for (const key of ['retryCount', 'retryDelaySeconds', 'recoverySuccesses', 'recoverySeconds'])
    delete raw.monitoring[key];
  delete raw.alerts.notifyAvailability;
  delete raw.alerts.notifyMeasurements;
  delete raw.services[0].monitoring;
  delete raw.services[0].alerts;
  fs.writeFileSync(config.file, JSON.stringify(raw));
  const migrated = new ConfigStore(directory);
  assert.equal(migrated.value.monitoring.retryCount, 2);
  assert.equal(migrated.value.alerts.notifyAvailability, true);
  assert.deepEqual(migrated.value.services[0].monitoring, {});
  for (const monitoring of [
    { retryCount: -1 },
    { retryCount: 4 },
    { retryCount: 1.5 },
    { retryDelaySeconds: 0 },
    { retryDelaySeconds: 31 },
    { recoverySuccesses: 0 },
    { recoverySuccesses: 11 },
    { recoverySeconds: -1 },
    { recoverySeconds: 3601 },
    { timeoutSeconds: 121 },
  ]) {
    assert.throws(() => config.updateGlobal({ monitoring }));
    assert.throws(() => config.update('linux', { monitoring }));
  }
  assert.throws(() => config.update('linux', { alerts: { notifyAvailability: 'false' } }));
  assert.throws(() => config.updateGlobal({ alerts: { notifyMeasurements: null } }));
});
test('recovery boundary validation accepts the healthy side of either trigger only', () => {
  for (const [operator, threshold, recoveryThreshold] of [
    ['gt', 90, 88],
    ['lt', 10, 12],
    ['gt', 90, 90],
    ['lt', 10, 10],
    ['gt', 90, null],
  ])
    assert.equal(
      validateService(
        { rules: [{ key: 'cpu', operator, threshold, recoveryThreshold }] },
        newService('linux')
      ).rules[0].recoveryThreshold,
      recoveryThreshold
    );
  for (const [operator, threshold, recoveryThreshold] of [
    ['gt', 90, 92],
    ['lt', 10, 8],
    ['gt', 90, '88'],
    ['gt', 90, Infinity],
  ])
    assert.throws(() =>
      validateService(
        { rules: [{ key: 'cpu', operator, threshold, recoveryThreshold }] },
        newService('linux')
      )
    );
});
test('measurement hysteresis and recovery confirmation survive restart without replaying firing events', t => {
  const directory = temporary(t);
  let store = new Store(directory);
  t.after(() => store.close());
  const service = {
      ...newService('linux'),
      rules: [{ key: 'cpu', operator: 'gt', threshold: 90, recoveryThreshold: 88, forSeconds: 0 }],
    },
    now = Date.now();
  store.evaluate(service, measurements(95), null, now);
  assert.equal(
    store.evaluate(service, measurements(96), null, now + 1000)[0].category,
    'measurement'
  );
  assert.equal(store.alerts().length, 1);
  for (const [offset, value] of [
    [2000, 89],
    [3000, 90],
    [4000, 88],
  ])
    assert.deepEqual(store.evaluate(service, measurements(value), null, now + offset), []);
  store.close();
  store = new Store(directory);
  assert.equal(store.events().length, 1);
  assert.equal(store.evaluate(service, measurements(87), null, now + 63000).length, 0);
  const events = store.evaluate(service, measurements(88), null, now + 64000);
  assert.equal(events[0].kind, 'resolved');
  assert.equal(events[0].rule, 'cpu');
  assert.equal(store.alerts().length, 0);
  assert.equal(store.events()[0].category, 'measurement');
  assert.equal(store.events()[0].rule, 'cpu');
});
test('failed, missing, deadband and long-gap samples reset recovery; both count and duration are required', t => {
  const store = new Store(temporary(t));
  t.after(() => store.close());
  const s = {
      ...newService('linux'),
      pollSeconds: 15,
      collectionTimeoutSeconds: 5,
      recoverySuccesses: 2,
      recoverySeconds: 30,
      rules: [{ key: 'cpu', operator: 'lt', threshold: 10, recoveryThreshold: 12, forSeconds: 0 }],
    },
    now = Date.now();
  store.evaluate(s, measurements(5), null, now);
  store.evaluate(s, measurements(6), null, now + 1000);
  for (const [offset, value, error] of [
    [2000, 13, null],
    [32000, undefined, null],
    [33000, 13, null],
    [63000, 13, 'Failed'],
    [64000, 13, null],
    [94000, 11, null],
    [95000, 13, null],
    [160000, 13, null],
    [170000, 13, null],
  ]) {
    assert.deepEqual(
      store
        .evaluate(s, value === undefined ? [] : measurements(value), error, now + offset)
        .filter(e => e.rule === 'cpu'),
      []
    );
    assert.ok(store.alerts().some(a => a.rule === 'cpu'));
  }
  assert.equal(
    store.evaluate(s, measurements(13), null, now + 190000).find(e => e.rule === 'cpu').kind,
    'resolved'
  );
});
test('availability failures and recovery confirmations count logical polls and reset interrupted recovery', t => {
  const store = new Store(temporary(t));
  t.after(() => store.close());
  const s = {
      ...newService('linux'),
      availabilityFailures: 3,
      availabilitySeconds: 180,
      recoverySuccesses: 2,
      recoverySeconds: 60,
    },
    now = Date.now();
  assert.deepEqual(store.evaluate(s, [], 'Failed', now), []);
  assert.deepEqual(store.evaluate(s, [], 'Failed', now + 90000), []);
  assert.equal(store.evaluate(s, [], 'Failed', now + 180000)[0].category, 'availability');
  assert.deepEqual(store.evaluate(s, [], null, now + 240000), []);
  assert.deepEqual(store.evaluate(s, [], 'Failed', now + 300000), []);
  assert.deepEqual(store.evaluate(s, [], null, now + 360000), []);
  assert.deepEqual(store.evaluate(s, [], null, now + 390000), []);
  assert.equal(store.evaluate(s, [], null, now + 420000)[0].kind, 'resolved');
});
test('database migration retains old firing alerts and event rows without synthetic notifications', t => {
  const directory = temporary(t),
    db = new DatabaseSync(path.join(directory, 'history.sqlite')),
    now = Date.now();
  db.exec(
    'CREATE TABLE alerts(service TEXT,rule TEXT,state TEXT,since INTEGER,count INTEGER,message TEXT,updated INTEGER,PRIMARY KEY(service,rule));CREATE TABLE events(id INTEGER PRIMARY KEY,service TEXT,time INTEGER,kind TEXT,message TEXT)'
  );
  db.prepare('INSERT INTO alerts VALUES(?,?,?,?,?,?,?)').run(
    'linux',
    '__availability',
    'firing',
    now - 120000,
    3,
    'Source is unavailable',
    now
  );
  db.prepare('INSERT INTO events VALUES(?,?,?,?,?)').run(
    1,
    'linux',
    now,
    'firing',
    'Source is unavailable'
  );
  db.close();
  const store = new Store(directory);
  t.after(() => store.close());
  assert.equal(store.alerts().length, 1);
  assert.equal(store.events().length, 1);
  assert.deepEqual(store.evaluate(newService('linux'), [], 'Still unavailable', now + 60000), []);
  assert.equal(store.events()[0].category, null);
  assert.deepEqual(store.evaluate(newService('linux'), [], null, now + 120000), []);
  assert.equal(store.evaluate(newService('linux'), [], null, now + 180000)[0].kind, 'resolved');
});
test('a transient retry succeeding records one successful poll and no failure alert', async t => {
  let calls = 0;
  const { app, source } = await fixture(t, {
    collector: async () => {
      if (++calls === 1) throw transient();
      return measurements(20);
    },
  });
  app.config.updateGlobal({ monitoring: { availabilityFailures: 1, availabilitySeconds: 0 } });
  await app.poll(source());
  assert.equal(calls, 2);
  assert.equal(app.store.stats().samples, 1);
  assert.equal(app.store.latest('linux').error, null);
  assert.equal(app.store.events().length, 0);
});
test('exhausted retries create one failed sample and one availability transition', async t => {
  let calls = 0;
  const { app, source } = await fixture(t, {
    collector: async () => {
      calls++;
      throw transient();
    },
  });
  app.config.updateGlobal({ monitoring: { availabilityFailures: 1, availabilitySeconds: 0 } });
  await app.poll(source());
  assert.equal(calls, 3);
  assert.equal(app.store.stats().samples, 1);
  assert.equal(app.store.events().length, 1);
  assert.equal(app.store.events()[0].category, 'availability');
});
test('HTTP and network retry classification is structured, bounded and never reveals raw network details', async t => {
  const service = { ...newService('json'), apiUrl: 'https://fixture.invalid' };
  let status = 401,
    body = '{}',
    failure;
  const mock = t.mock.method(transport, 'fetch', async () => {
    if (failure) throw failure;
    return new Response(body, { status });
  });
  for (const code of [400, 401, 403, 404, 408, 429, 500, 502, 503]) {
    status = code;
    await assert.rejects(
      request(service),
      error => error.status === code && error.retryable === [408, 429, 500, 502, 503].includes(code)
    );
  }
  status = 200;
  body = 'not-json';
  await assert.rejects(
    request(service),
    error => error.retryable !== true && /valid JSON/.test(error.message)
  );
  for (const [code, pattern, retryable] of [
    ['ENOTFOUND', /DNS lookup/, true],
    ['ETIMEDOUT', /timed out/, true],
    ['ECONNREFUSED', /refused/, true],
    ['ECONNRESET', /interrupted/, true],
    ['ENETUNREACH', /unreachable/, true],
    ['CERT_HAS_EXPIRED', /TLS certificate/, false],
    ['ERR_TLS_CERT_ALTNAME_INVALID', /TLS certificate/, false],
    ['ERR_SSL_UNSUPPORTED_PROTOCOL', /TLS handshake failed/, false],
    ['ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE', /TLS handshake failed/, false],
  ]) {
    failure = new TypeError('fetch failed', {
      cause: Object.assign(new Error('secret-provider-value https://private.invalid'), { code }),
    });
    await assert.rejects(
      request(service),
      error =>
        pattern.test(error.message) &&
        error.retryable === retryable &&
        !/secret-provider|private.invalid/.test(error.message)
    );
  }
  failure = new TypeError('fetch failed', { cause: new Error('bad port') });
  await assert.rejects(
    request(service),
    error => error.retryable === false && /configuration/.test(error.message)
  );
  assert.ok(mock.mock.callCount() > 0);
});
test('known authentication rejection, malformed JSON and configuration errors are never retried', async t => {
  let calls = 0,
    error = new CollectionError('Authentication failed.', { status: 401 });
  const { app, source } = await fixture(t, {
    collector: async () => {
      calls++;
      throw error;
    },
  });
  for (const failure of [
    error,
    new CollectionError('Permission denied.', { status: 403 }),
    new Error('Source did not return valid JSON.'),
    new Error('Add metric mappings.'),
  ]) {
    error = failure;
    const before = calls;
    await app.poll(source());
    assert.equal(calls - before, 1);
  }
});
test('healthy collection with persistent measurement warnings is not retried or hidden', async t => {
  let calls = 0;
  const { app, source } = await fixture(t, {
    collector: async () => {
      calls++;
      return measurements(95);
    },
  });
  app.config.update('linux', {
    rules: [{ key: 'cpu', operator: 'gt', threshold: 90, forSeconds: 0 }],
  });
  await app.poll(source());
  await app.poll(source());
  assert.equal(calls, 2);
  assert.equal(app.store.alerts()[0].rule, 'cpu');
  assert.equal(app.store.events()[0].category, 'measurement');
});
test('total deadline includes retry waits and stops collectors that ignore cancellation', async t => {
  let calls = 0;
  const { app, source } = await fixture(t, {
    collectionTimeoutMs: 25,
    collector: async () => {
      calls++;
      throw transient();
    },
  });
  // A 30 s retry wait that the 25 ms deadline must cut short. Timing only the wait keeps
  // slow disk commits from failing the check; a deadline that ignored it would take 30 s.
  app.config.update('linux', { monitoring: { retryDelaySeconds: 30 } });
  const began = Date.now();
  await app.poll(source());
  assert.ok(Date.now() - began < 10000);
  assert.equal(calls, 1);
  assert.match(app.store.latest('linux').error, /time limit/);
  assert.equal(app.store.stats().samples, 1);
  const hung = await fixture(t, {
    collectionTimeoutMs: 25,
    collector: async () => new Promise(() => {}),
  });
  await hung.app.poll(hung.source());
  assert.match(hung.app.store.latest('linux').error, /time limit/);
  assert.equal(hung.app.store.stats().samples, 1);
});
test('pausing, editing and shutdown abort retry waits without samples, alerts or further attempts', async t => {
  for (const action of ['pause', 'edit', 'shutdown']) {
    let calls = 0,
      signal;
    const { app, source, call, close } = await fixture(t, {
      collector: async service => {
        calls++;
        signal = service.signal;
        throw transient();
      },
    });
    const pending = app.poll(source());
    // The first attempt has ended and the poll is in its 1 s retry wait.
    await until(() => signal?.aborted);
    assert.equal(calls, 1);
    if (action === 'shutdown') await close();
    else {
      assert.equal(
        (
          await call(
            '/api/services/linux',
            'PATCH',
            // Only collection settings restart a poll; a rename does not.
            action === 'pause' ? { enabled: false } : { pollSeconds: 30 }
          )
        ).status,
        200
      );
    }
    await pending;
    assert.equal(calls, 1);
    if (action !== 'shutdown') {
      assert.equal(app.store.stats().samples, action === 'pause' ? 1 : 0);
      assert.equal(app.store.latest('linux').lastAttempt, null);
      assert.equal(app.store.events().length, 0);
    }
  }
});
test('test connection uses source retry overrides and isolated state without recording samples', async t => {
  let calls = 0;
  const ids = [];
  const { app, call } = await fixture(t, {
    collector: async service => {
      ids.push(service.id);
      if (++calls === 1) throw transient();
      return measurements(20);
    },
  });
  const result = await call('/api/test-service', 'POST', {
    serviceId: 'linux',
    settings: { monitoring: { retryCount: 1, retryDelaySeconds: 1 } },
  });
  assert.equal(result.status, 200);
  assert.equal(calls, 2);
  assert.equal(ids[0], ids[1]);
  assert.match(ids[0], /^test-/);
  assert.equal(app.store.stats().samples, 0);
  assert.equal(app.store.events().length, 0);
});
test('notification categories and source overrides filter delivery while keeping active alerts and history', async t => {
  const sent = [];
  let failing = true;
  const { app, source } = await fixture(t, {
    collector: async () => {
      if (failing) throw new Error('Failed');
      return measurements(95);
    },
    mailTransportFactory: () => ({
      sendMail: async m => {
        sent.push(m);
        return { accepted: ['recipient@example.com'] };
      },
      close() {},
    }),
  });
  app.config.updateGlobal({
    monitoring: {
      availabilityFailures: 1,
      availabilitySeconds: 0,
      recoverySuccesses: 1,
      recoverySeconds: 0,
    },
    alerts: { notifyAvailability: false, notifyMeasurements: false },
    email: {
      enabled: true,
      from: 'sender@example.com',
      to: 'recipient@example.com',
      password: 'fixture-secret',
    },
  });
  app.config.update('linux', {
    alerts: { notifyAvailability: true },
    rules: [{ key: 'cpu', operator: 'gt', threshold: 90, forSeconds: 0 }],
  });
  await app.poll(source());
  await app.flushNotifications();
  assert.equal(sent.length, 1);
  assert.equal(app.store.alerts()[0].rule, '__availability');
  failing = false;
  await app.poll(source());
  await app.poll(source());
  await app.flushNotifications();
  assert.equal(sent.length, 2);
  assert.equal(app.store.alerts()[0].rule, 'cpu');
  assert.equal(app.store.events().filter(e => e.category === 'measurement').length, 1);
  app.config.update('linux', { alerts: { notifyAvailability: null } });
  failing = true;
  await app.poll(source());
  await app.flushNotifications();
  assert.equal(sent.length, 2);
  assert.ok(app.store.alerts().some(a => a.rule === '__availability'));
});
test('editing only a recovery boundary preserves a firing alert and resets recovery confirmation', async t => {
  const { app, source, call } = await fixture(t);
  app.config.update('linux', {
    rules: [{ key: 'cpu', operator: 'gt', threshold: 90, forSeconds: 0 }],
  });
  const now = Date.now();
  app.store.evaluate(source(), measurements(95), null, now);
  app.store.evaluate(source(), measurements(96), null, now + 1000);
  app.store.evaluate(source(), measurements(89), null, now + 2000);
  assert.equal(
    (
      await call('/api/services/linux', 'PATCH', {
        rules: [
          { key: 'cpu', operator: 'gt', threshold: 90, recoveryThreshold: 88, forSeconds: 0 },
        ],
      })
    ).status,
    200
  );
  assert.equal(app.store.alerts().length, 1);
  assert.equal(app.store.events().length, 1);
  assert.deepEqual(app.store.evaluate(source(), measurements(88), null, now + 62000), []);
  assert.equal(
    app.store.evaluate(source(), measurements(88), null, now + 122000)[0].kind,
    'resolved'
  );
  app.store.evaluate(source(), measurements(95), null, now + 180000);
  app.store.evaluate(source(), measurements(95), null, now + 181000);
  await call('/api/services/linux', 'PATCH', {
    rules: [{ key: 'cpu', operator: 'gt', threshold: 97, recoveryThreshold: 88, forSeconds: 0 }],
  });
  assert.equal(app.store.alerts().length, 0);
});
test('failed exporter attempts do not advance the rate baseline', async t => {
  let now = 100000,
    idle = 10,
    busy = 10;
  const clock = t.mock.method(Date, 'now', () => now);
  t.mock.method(
    transport,
    'fetch',
    async () =>
      new Response(
        `node_cpu_seconds_total{mode="idle"} ${idle}\nnode_cpu_seconds_total{mode="user"} ${busy}\nnode_memory_MemTotal_bytes 100\nnode_memory_MemAvailable_bytes 50\n`
      )
  );
  const service = { ...newService('linux', 'rate-fixture'), apiUrl: 'http://fixture.invalid' };
  t.after(() => resetCollector(service.id));
  await collect(service);
  now += 1000;
  idle = 19;
  busy = 11;
  // Mappings are read after the rates, so this attempt fails late, after the rate step.
  await assert.rejects(
    collect({
      ...service,
      metrics: [{ key: 'bad', label: 'x'.repeat(241), path: 'node_memory_MemTotal_bytes' }],
    }),
    /names or units/
  );
  now += 1000;
  idle = 20;
  busy = 20;
  const result = await collect(service);
  assert.equal(result.find(m => m.key === 'cpu').value, 50);
  assert.ok(clock.mock.callCount() > 0);
});

function sessionFixture(t, type, id = 'session-' + type) {
  const service = {
    ...newService(type, id),
    apiUrl: 'https://fixture.invalid',
    username: 'fixture-user',
    password: 'fixture-password',
  };
  resetCollector(id);
  t.after(() => resetCollector(id));
  let logins = 0,
    reads = 0,
    rejectCached = false,
    rejectLogin = false,
    rejectFresh = false,
    loginWait = false,
    aborted = 0;
  let entered;
  const enteredLogin = new Promise(resolve => (entered = resolve));
  t.mock.method(transport, 'fetch', async (url, options) => {
    const route = new URL(url).pathname,
      login = route.endsWith('/login') || route.endsWith('/Login') || route.endsWith('/tokens');
    if (login) {
      logins++;
      if (loginWait) {
        entered();
        return new Promise((_, reject) =>
          options.signal.addEventListener(
            'abort',
            () => {
              aborted++;
              reject(new DOMException('Aborted', 'AbortError'));
            },
            { once: true }
          )
        );
      }
      if (rejectLogin) return new Response('{}', { status: 401 });
      const data =
        type === 'amp'
          ? { success: true, sessionID: 'token-' + logins }
          : type === 'unifi'
            ? {}
            : { token: 'token-' + logins };
      return new Response(JSON.stringify(data), {
        headers:
          type === 'unifi' ? { 'Set-Cookie': 'TOKEN=token-' + logins + '; Path=/; Secure' } : {},
      });
    }
    reads++;
    const rejected = rejectCached && (logins === 1 || rejectFresh);
    if (rejected) return new Response('{}', { status: 403 });
    let data =
      type === 'amp'
        ? { Metrics: { 'CPU Usage': { Percent: 20, RawValue: 20, Units: '%' } } }
        : type === 'unifi'
          ? { meta: { rc: 'ok' }, data: [] }
          : [];
    return new Response(JSON.stringify(data));
  });
  return {
    service,
    enteredLogin,
    get logins() {
      return logins;
    },
    get reads() {
      return reads;
    },
    get aborted() {
      return aborted;
    },
    expire({ loginFails = false, freshFails = false, wait = false } = {}) {
      rejectCached = true;
      rejectLogin = loginFails;
      rejectFresh = freshFails;
      loginWait = wait;
    },
  };
}
test('each session collector refreshes one rejected cached session within the same collection', async t => {
  for (const type of ['npm', 'amp', 'crowdsec', 'unifi']) {
    const f = sessionFixture(t, type);
    await collect(f.service);
    assert.equal(f.logins, 1);
    f.expire();
    const result = await collect(f.service);
    assert.ok(result.length > 0);
    assert.equal(f.logins, 2);
    await collect(f.service);
    assert.equal(f.logins, 2);
    t.mock.restoreAll();
  }
});
test('a rejected fresh login or fresh session stops refresh without a credential retry loop', async t => {
  for (const freshFails of [false, true]) {
    const f = sessionFixture(t, 'npm', 'session-rejected-' + freshFails);
    await collect(f.service);
    f.expire({ loginFails: !freshFails, freshFails });
    await assert.rejects(
      collect(f.service),
      error => [401, 403].includes(error.status) && error.retryable === false
    );
    assert.equal(f.logins, 2);
    assert.equal(f.reads, freshFails ? 3 : 2);
    t.mock.restoreAll();
  }
});
test('NPM, CrowdSec and AMP sign-in answers with a non-string, oversized or control-character token are refused without caching a session or echoing the token; the next poll signs in again', async t => {
  const canary = 'SYNTHETIC-UPSTREAM-TOKEN';
  const products = { npm: 'Nginx Proxy Manager', crowdsec: 'CrowdSec', amp: 'AMP' };
  for (const [type, product] of Object.entries(products))
    for (const bad of [
      { nested: canary },
      [canary],
      42,
      `${canary}\r\nX-Injected: 1`,
      `${canary} with spaces`,
      `${canary}\u0000`,
      canary + 'A'.repeat(8192),
    ]) {
      const id = 'unusable-token-' + type;
      resetCollector(id);
      t.after(() => resetCollector(id));
      let logins = 0;
      const sent = [];
      t.mock.method(transport, 'fetch', async (url, options) => {
        if (/\/(?:login|Login|tokens)$/.test(new URL(url).pathname)) {
          logins++;
          // The source recovers: from the second sign-in on, it answers with a usable token.
          const token = logins === 1 ? bad : 'good.token-' + logins;
          return Response.json(type === 'amp' ? { success: true, sessionID: token } : { token });
        }
        sent.push(options.headers.Authorization ?? options.body);
        return Response.json(
          type === 'amp' ? { Metrics: { 'CPU Usage': { Percent: 20, RawValue: 20 } } } : []
        );
      });
      const service = {
        ...newService(type, id),
        apiUrl: 'https://fixture.invalid',
        username: 'fixture-user',
        password: 'fixture-password',
      };
      const what = `${type} ${JSON.stringify(bad).slice(0, 40)}`;
      const error = await collect(service).catch(e => e);
      assert.ok(error instanceof CollectionError, what);
      assert.equal(error.message, `${product} sign-in returned an unusable session token.`, what);
      assert.equal(error.retryable, false, what);
      assert.doesNotMatch(inspect(error, { depth: 10 }), new RegExp(canary), what);
      assert.deepEqual(sent, [], `${what}: nothing was sent with it`);
      // Nothing was cached: the next poll signs in again and uses the new token.
      const metrics = await collect(service);
      assert.ok(metrics.length > 0, what);
      assert.equal(logins, 2, what);
      assert.ok(sent.length > 0 && sent.every(value => value.includes('good.token-2')), what);
      t.mock.restoreAll();
    }
});
test('session refresh obeys cancellation and the same logical deadline without publishing late results', async t => {
  const f = sessionFixture(t, 'npm', 'session-cancelled');
  await collect(f.service);
  f.expire({ wait: true });
  const controller = new AbortController(),
    pending = collect({ ...f.service, signal: controller.signal });
  await f.enteredLogin;
  controller.abort();
  await assert.rejects(pending, { name: 'AbortError' });
  assert.equal(f.logins, 2);
  assert.equal(f.aborted, 1);
  t.mock.restoreAll();
  const other = sessionFixture(t, 'npm', 'linux');
  const { app, source } = await fixture(t, { collectionTimeoutMs: 25 });
  // A saved source keeps its type through update(), so the fixture's source becomes an NPM one
  // in the saved configuration itself.
  app.config.save({
    ...app.config.value,
    services: app.config.value.services.map(service =>
      service.id === 'linux'
        ? { ...service, type: 'npm', username: 'fixture-user', password: 'fixture-password' }
        : service
    ),
  });
  await app.poll(source());
  other.expire({ wait: true });
  await app.poll(source());
  assert.match(app.store.latest('linux').error, /time limit/);
  assert.equal(other.logins, 2);
  assert.equal(other.aborted, 1);
  assert.equal(app.store.stats().samples, 2);
});
test('a forced session refresh can only consume its shared logical-poll budget once', async t => {
  const f = sessionFixture(t, 'npm');
  await collect(f.service);
  f.expire();
  const budget = { remaining: 1 };
  await collect({ ...f.service, sessionRefreshBudget: budget });
  assert.equal(budget.remaining, 0);
  assert.equal(f.logins, 2);
  // A new cached-session rejection under the same budget must not submit a third login.
  f.expire({ freshFails: true });
  await assert.rejects(
    collect({ ...f.service, sessionRefreshBudget: budget }),
    error => error.status === 403
  );
  assert.equal(f.logins, 2);
});

test('cached UniFi session refresh cancels failed-attempt sibling reads before logging in again', async t => {
  const service = {
    ...newService('unifi', 'unifi-refresh-siblings'),
    apiUrl: 'https://fixture.invalid',
    username: 'fixture',
    password: 'fixture',
  };
  resetCollector(service.id);
  t.after(() => resetCollector(service.id));
  let logins = 0,
    expired = false,
    cancelled = 0;
  t.mock.method(transport, 'fetch', async (url, options) => {
    if (url.endsWith('/api/auth/login')) {
      if (logins === 1) assert.equal(cancelled, 2);
      logins++;
      return new Response('{}', {
        headers: { 'Set-Cookie': 'TOKEN=fixture-' + logins + '; Path=/; Secure' },
      });
    }
    if (expired && logins === 1) {
      if (url.endsWith('/health')) return new Response('{}', { status: 401 });
      return new Promise((_, reject) =>
        options.signal.addEventListener(
          'abort',
          () => {
            cancelled++;
            reject(new DOMException('Aborted', 'AbortError'));
          },
          { once: true }
        )
      );
    }
    return new Response(JSON.stringify({ meta: { rc: 'ok' }, data: [] }));
  });
  await collect(service);
  expired = true;
  const metrics = await collect(service);
  assert.equal(logins, 2);
  assert.equal(cancelled, 2);
  assert.equal(metrics.find(m => m.key === 'clients').value, 0);
});

test('pausing a source records exactly one collection gap marker', async t => {
  const { app, call } = await fixture(t);
  const before = app.store.stats().samples;
  // Freeze the clock so duplicate markers could not collapse onto one primary key.
  let now = Date.now();
  t.mock.method(Date, 'now', () => now++);
  assert.equal((await call('/api/services/linux', 'PATCH', { enabled: false })).status, 200);
  assert.equal(app.store.stats().samples - before, 1);
});
