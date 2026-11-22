import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { createApp } from '../server.mjs';
import { ConfigStore } from '../lib/config.mjs';
import { configureDestinations } from '../lib/destinations.mjs';
// Fixture hostnames resolve instantly to a documentation address, never via real DNS.
configureDestinations({ lookup: async () => [{ address: '192.0.2.1' }] });

test('website override preserves source identity and supports history, alerts, recovery and pausing', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-website-lifecycle-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  let status = 302;
  const requests = [],
    mail = [];
  const target = http.createServer((req, res) => {
    requests.push({ method: req.method, headers: req.headers });
    res.writeHead(status, { Location: 'https://destination.invalid/sign-in' });
    res.end();
  });
  await new Promise(resolve => target.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => target.close(resolve)));
  const app = await createApp({
    directory,
    port: 0,
    password: 'fixture-password',
    allowLoopback: true,
    allowedHosts: '',
    webhook: '',
    startScheduler: false,
    mailTransportFactory: () => ({
      sendMail: async message => {
        mail.push(message);
        return { accepted: ['recipient@example.com'] };
      },
      close() {},
    }),
  });
  await app.listen();
  t.after(() => app.close());
  app.config.updateGlobal({
    monitoring: {
      availabilityFailures: 1,
      availabilitySeconds: 0,
      retryCount: 0,
      recoverySuccesses: 1,
      recoverySeconds: 0,
    },
    email: {
      enabled: true,
      from: 'sender@example.com',
      to: 'recipient@example.com',
      password: 'fixture-email-secret',
    },
  });
  app.config.update('cosmos-1', {
    collector: 'http',
    apiUrl: `http://127.0.0.1:${target.address().port}/health`,
    url: 'https://launch.example.com',
    apiKey: 'fixture-source-key',
    password: 'fixture-source-password',
    httpExpectedStatus: '200-399',
    httpMethod: 'HEAD',
  });
  const source = () => app.config.get('cosmos-1');
  await app.poll(source());
  let snapshot = app.dashboard(),
    state = snapshot.services.find(s => s.id === source().id);
  assert.equal(state.status, 'live');
  assert.equal(state.collector, 'http');
  assert.equal(state.metrics.find(m => m.key === 'http_status').value, 302);
  assert.equal(source().type, 'cosmos');
  assert.equal(source().url, 'https://launch.example.com');
  assert.equal(requests.length, 1);
  assert.equal(requests[0].method, 'HEAD');
  for (const key of ['authorization', 'cookie', 'x-api-key'])
    assert.equal(requests[0].headers[key], undefined);
  const persisted = new ConfigStore(directory).get(source().id);
  assert.equal(persisted.httpMethod, 'HEAD');
  assert.equal(persisted.httpExpectedStatus, '200-399');
  await new Promise(resolve => setTimeout(resolve, 5));
  status = 503;
  await app.poll(source());
  await app.flushNotifications();
  state = app.dashboard().services.find(s => s.id === source().id);
  assert.equal(state.status, 'stale');
  assert.match(state.error, /503/);
  assert.equal(app.store.alerts().length, 1);
  assert.equal(mail.length, 1);
  assert.ok(app.store.history(source().id).points.some(point => !point.ok));
  await new Promise(resolve => setTimeout(resolve, 5));
  status = 204;
  await app.poll(source());
  await app.flushNotifications();
  assert.equal(app.dashboard().services.find(s => s.id === source().id).status, 'live');
  assert.equal(app.store.alerts().length, 0);
  assert.equal(mail.length, 2);
  assert.deepEqual(
    app.store
      .events()
      .map(event => event.kind)
      .sort(),
    ['firing', 'resolved']
  );
  app.config.update(source().id, { enabled: false });
  const count = requests.length;
  await app.poll(source());
  assert.equal(requests.length, count);
  assert.equal(app.dashboard().services.find(s => s.id === source().id).status, 'disabled');
});

test('changing monitoring method clears alerts for measurements from the previous method', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-method-change-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const app = await createApp({
    directory,
    port: 0,
    password: 'fixture-password',
    allowedHosts: '',
    webhook: '',
    startScheduler: false,
  });
  const address = await app.listen();
  t.after(() => app.close());
  app.config.update('cosmos-1', {
    apiUrl: 'https://fixture.invalid',
    rules: [{ key: 'cpu', operator: 'gt', threshold: 80, forSeconds: 0 }],
  });
  const source = app.config.get('cosmos-1'),
    now = Date.now();
  for (const time of [now - 1000, now])
    app.store.evaluate(source, [{ key: 'cpu', label: 'CPU', value: 95, unit: '%' }], null, time);
  assert.equal(app.store.alerts().length, 1);
  const response = await fetch(`http://127.0.0.1:${address.port}/api/services/cosmos-1`, {
    method: 'PATCH',
    headers: {
      'Content-Type': 'application/json',
      'X-Goblin-Request': '1',
      Authorization: 'Basic ' + Buffer.from('admin:fixture-password').toString('base64'),
    },
    body: JSON.stringify({ collector: 'http' }),
  });
  assert.equal(response.status, 200);
  assert.equal(app.store.alerts().length, 0);
  assert.ok(app.store.history(source.id).points.some(point => !point.ok));
  assert.equal(app.store.events().length, 1);
});
