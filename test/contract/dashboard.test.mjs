// GET /api/dashboard is read by dashboard widgets outside Uptime Goblin (Homepage's customapi, Glance's
// custom-api, scripts), which address fields by name and often by array index. This test pins
// what they rely on: field names, types, value sets, epoch-millisecond times, source order,
// secret redaction and plain Basic reads. New fields are allowed; removing or renaming a field,
// changing its type or producing a value outside a pinned set fails here. Change this file only
// together with a CHANGELOG entry that names the break.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createApp } from '../../server.mjs';
import { configureDestinations } from '../../lib/destinations.mjs';

// Fixture hostnames resolve instantly to a documentation address, never via real DNS.
configureDestinations({ lookup: async () => [{ address: '192.0.2.1' }] });

const password = 'fixture-contract-password';
const sourceSecret = 'fixture-contract-api-key';
const mailSecret = 'fixture-contract-mail-password';

// A small shape language: 'string', 'integer', 'number', 'boolean', 'null' and 'time' (epoch
// milliseconds), joined with '|'; oneOf(...values); listOf(shape); nullable(shape);
// optional(shape); and plain objects, whose listed keys are required (others are allowed).
const oneOf = (...values) => ({ oneOf: values });
const listOf = item => ({ listOf: item });
const nullable = shape => ({ nullable: shape });
const optional = shape => ({ optional: shape });
const kinds = {
  string: value => typeof value === 'string',
  integer: value => Number.isSafeInteger(value),
  number: value => typeof value === 'number' && Number.isFinite(value),
  boolean: value => typeof value === 'boolean',
  null: value => value === null,
  // Milliseconds, not seconds or ISO strings: 2001-09-09 to 5138-11-16.
  time: value => Number.isSafeInteger(value) && value >= 1e12 && value < 1e14,
};
function problems(value, shape, where = 'dashboard', found = []) {
  if (typeof shape === 'string') {
    if (!shape.split('|').some(kind => kinds[kind](value)))
      found.push(`${where}: expected ${shape}, got ${JSON.stringify(value)}`);
  } else if (shape.oneOf) {
    if (!shape.oneOf.includes(value))
      found.push(
        `${where}: expected one of ${shape.oneOf.map(v => JSON.stringify(v)).join(', ')}, got ${JSON.stringify(value)}`
      );
  } else if (shape.listOf) {
    if (!Array.isArray(value)) found.push(`${where}: expected a list`);
    else value.forEach((item, index) => problems(item, shape.listOf, `${where}[${index}]`, found));
  } else if (shape.nullable) {
    if (value !== null) problems(value, shape.nullable, where, found);
  } else if (shape.optional) {
    if (value !== undefined) problems(value, shape.optional, where, found);
  } else if (!value || typeof value !== 'object' || Array.isArray(value))
    found.push(`${where}: expected an object`);
  else
    for (const [key, inner] of Object.entries(shape)) {
      if (!(key in value) && !inner.optional) found.push(`${where}.${key}: missing`);
      else problems(value[key], inner, `${where}.${key}`, found);
    }
  return found;
}

const status = oneOf('live', 'stale', 'error', 'unconfigured', 'disabled', 'link', 'collecting');
const nullableTime = 'time|null';
// The built-in channels: 1.4.2's two, then ntfy and Gotify (listed whether set up or not).
const channelId = oneOf('email', 'env-webhook', 'ntfy', 'gotify');
const channelState = oneOf(
  'not-configured',
  'off',
  'paused',
  'circuit-open',
  'retrying',
  'refusing',
  'ok'
);
// `freed` is null when there was no reserve to release (a start on a disk already full).
const diskBanner = {
  full: oneOf(true),
  since: 'time',
  freeBytes: 'integer|null',
  reserveReleased: 'boolean',
  freed: 'boolean|null',
};
const contract = {
  config: {
    title: 'string',
    subtitle: 'string',
    pollSeconds: 'integer',
    retentionDays: 'integer',
    revision: 'integer',
    appearance: {
      timezone: 'string',
      timeFormat: oneOf('auto', '12h', '24h'),
      defaultRange: oneOf('1h', '6h', '24h', '7d', '30d'),
      accent: 'string',
    },
    alerts: { enabled: 'boolean' },
    email: { enabled: 'boolean', passwordConfigured: 'boolean' },
    services: listOf({
      id: 'string',
      type: 'string',
      name: 'string',
      group: 'string',
      color: 'string',
      icon: 'string',
      url: 'string',
      enabled: 'boolean',
      showOnDashboard: 'boolean',
      pollSeconds: 'integer',
      apiKeyConfigured: 'boolean',
      passwordConfigured: 'boolean',
      rules: listOf({ key: 'string', operator: oneOf('gt', 'lt'), threshold: 'number' }),
    }),
  },
  catalog: listOf({
    type: 'string',
    name: 'string',
    group: 'string',
    color: 'string',
    icon: 'string',
    labels: listOf('string'),
  }),
  services: listOf({
    id: 'string',
    status,
    lastAttempt: nullableTime,
    lastSuccess: nullableTime,
    error: 'string|null',
    metrics: listOf({ key: 'string', label: 'string', value: 'number', unit: 'string' }),
    collecting: 'boolean',
    configured: 'boolean',
    collector: 'string',
    // 1.4.3: why the last collection left readings out (a cap). May be absent or null.
    notes: optional(nullable(listOf({ code: 'string', message: 'string' }))),
  }),
  alerts: listOf({
    service: 'string',
    rule: 'string',
    name: 'string',
    message: 'string',
    since: 'time',
    updated: 'time',
  }),
  events: listOf({
    id: 'integer',
    service: 'string',
    name: 'string',
    time: 'time',
    kind: oneOf('firing', 'resolved'),
    message: 'string',
    // Events saved by older releases may have neither.
    category: oneOf('availability', 'measurement', null),
    rule: 'string|null',
  }),
  lastCollected: nullableTime,
  // Set while history cannot be written (a full disk).
  storage: nullable({ since: 'time', code: 'string' }),
  notifications: {
    configured: 'boolean',
    lastError: nullableTime,
    webhook: { configured: 'boolean', lastError: nullableTime },
    email: {
      enabled: 'boolean',
      configured: 'boolean',
      state: oneOf('disabled', 'unconfigured', 'error', 'accepted', 'ready'),
      pending: 'integer',
      failedCount: 'integer',
      lastAttempt: nullableTime,
      lastAccepted: nullableTime,
      // 1.5 additions (delivery spec §6.5): the email channel's persisted delivery status.
      channelState: nullable(channelState),
      pausedReason: 'string|null',
      nextAttemptAt: nullableTime,
      waiting: 'integer',
      // A44: the email rows waiting to retry (`waiting` also counts first tries and held rows).
      retrying: 'integer',
      failed: 'integer',
    },
    // 1.5 additions: whether the figures are current, whether delivery is being saved, and what
    // needs attention. While `available` is false every figure is the last one computed.
    available: 'boolean',
    updatedAt: nullableTime,
    saving: 'boolean',
    unsavedSince: nullableTime,
    attention: {
      waiting: 'integer',
      retrying: 'integer',
      failed: 'integer',
      paused: listOf(channelId),
      refusing: listOf(channelId),
    },
    channels: listOf({
      id: channelId,
      state: channelState,
      pausedReason: 'string|null',
      nextAttemptAt: nullableTime,
      lastAttempt: nullableTime,
    }),
  },
  // 1.5 addition: set while the disk of the data directory is full (the storage guard), else null.
  disk: nullable(diskBanner),
};

async function fixture(t, options = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-contract-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  // A source reports, fails or reports then fails, as the test sets.
  const behaviour = new Map();
  const app = await createApp({
    directory,
    port: 0,
    password,
    allowedHosts: '',
    webhook: '',
    startScheduler: false,
    trustProxy: '',
    collector: async service => {
      const outcome = behaviour.get(service.id);
      if (outcome instanceof Error) throw outcome;
      return outcome ?? [];
    },
    ...options,
  });
  const { port } = await app.listen();
  t.after(() => app.close());
  const get = (route, headers = {}) =>
    fetch(`http://127.0.0.1:${port}${route}`, {
      headers: {
        Authorization: 'Basic ' + Buffer.from('admin:' + password).toString('base64'),
        Accept: 'application/json',
        ...headers,
      },
    });
  return { app, behaviour, get };
}

test('GET /api/dashboard keeps the shape dashboard widgets read', async t => {
  const { app, behaviour, get } = await fixture(t);
  const address = 'http://node.example.test:9100';
  const fastFailure = { availabilityFailures: 1, availabilitySeconds: 0, retryCount: 0 };
  app.config.update('linux', {
    apiUrl: address,
    rules: [{ key: 'cpu', operator: 'gt', threshold: 90, forSeconds: 0 }],
  });
  app.config.update('docker', { apiUrl: address, monitoring: fastFailure });
  app.config.update('sonarr', { apiUrl: address, apiKey: sourceSecret, monitoring: fastFailure });
  app.config.update('radarr', { apiUrl: address, apiKey: sourceSecret });
  app.config.update('plex', { apiUrl: address, enabled: false });
  app.config.updateGlobal({ email: { password: mailSecret } });
  behaviour.set('linux', [
    { key: 'cpu', label: 'CPU', value: 95, unit: '%' },
    { key: 'uptime', label: 'Uptime', value: 86400, unit: 'seconds' },
  ]);
  behaviour.set('docker', new Error('Connection refused by the Docker API'));
  behaviour.set('sonarr', [{ key: 'series', label: 'Series', value: 12, unit: '' }]);
  // A measurement rule fires on its second matching reading.
  await app.poll(app.config.get('linux'));
  await app.poll(app.config.get('linux'));
  await app.poll(app.config.get('docker'));
  await app.poll(app.config.get('sonarr'));
  behaviour.set('sonarr', new Error('Sonarr answered HTTP 503'));
  await app.poll(app.config.get('sonarr'));

  const response = await get('/api/dashboard');
  assert.equal(response.status, 200);
  assert.match(response.headers.get('content-type'), /^application\/json\b/);
  assert.equal(response.headers.get('cache-control'), 'no-store');
  const text = await response.text();
  const dashboard = JSON.parse(text);
  assert.deepEqual(problems(dashboard, contract), []);

  // Widgets address sources by index: the list follows the configured order, one per source.
  assert.deepEqual(
    dashboard.services.map(s => s.id),
    dashboard.config.services.map(s => s.id)
  );
  const byId = Object.fromEntries(dashboard.services.map(s => [s.id, s]));
  assert.deepEqual(
    ['linux', 'docker', 'sonarr', 'radarr', 'plex', 'netbox', 'proxmox'].map(id => byId[id].status),
    ['live', 'error', 'stale', 'collecting', 'disabled', 'link', 'unconfigured']
  );
  assert.deepEqual(byId.linux.metrics[0], { key: 'cpu', label: 'CPU', value: 95, unit: '%' });
  assert.equal(byId.linux.error, null);
  assert.match(byId.docker.error, /Connection refused/);
  assert.equal(byId.docker.lastSuccess, null);
  assert.match(byId.sonarr.error, /HTTP 503/);
  assert.equal(typeof byId.sonarr.lastSuccess, 'number');
  assert.deepEqual(byId.sonarr.metrics, [{ key: 'series', label: 'Series', value: 12, unit: '' }]);
  assert.equal(
    dashboard.lastCollected,
    Math.max(...dashboard.services.map(s => s.lastSuccess || 0))
  );
  assert.deepEqual(dashboard.alerts.map(a => [a.service, a.rule, a.name]).sort(), [
    ['docker', '__availability', 'Docker'],
    ['linux', 'cpu', 'Linux systems'],
    ['sonarr', '__availability', 'Sonarr'],
  ]);
  assert.deepEqual(dashboard.events.map(e => [e.service, e.kind, e.category, e.rule]).sort(), [
    ['docker', 'firing', 'availability', '__availability'],
    ['linux', 'firing', 'measurement', 'cpu'],
    ['sonarr', 'firing', 'availability', '__availability'],
  ]);
  assert.equal(dashboard.catalog.length > 0, true);

  // Secrets never leave the server; widgets see only whether one is set.
  assert.doesNotMatch(text, new RegExp(`${sourceSecret}|${mailSecret}|${password}`));
  const radarr = dashboard.config.services.find(s => s.id === 'radarr');
  assert.equal(radarr.apiKeyConfigured, true);
  for (const service of dashboard.config.services) {
    assert.equal('apiKey' in service, false, service.id);
    assert.equal('password' in service, false, service.id);
  }
  assert.equal('password' in dashboard.config.email, false);
  assert.equal(dashboard.config.email.passwordConfigured, true);
});

test('GET /api/dashboard needs only the Basic credential, whatever the query string', async t => {
  const { get } = await fixture(t);
  // No X-Goblin-Request, Origin or Content-Type: widgets send none of them on reads.
  for (const route of ['/api/dashboard', '/api/dashboard?_=1759149296000'])
    assert.equal((await get(route)).status, 200, route);
  const anonymous = await get('/api/dashboard', { Authorization: '' });
  assert.equal(anonymous.status, 401);
  assert.match(anonymous.headers.get('www-authenticate'), /^Basic\b/);
});

test('GET /api/dashboard: the 1.5 delivery and disk fields keep their shape, also while the disk is full', async t => {
  // A disk that statfs reports as full: the storage guard is full from the start.
  const statfs = () => ({ type: 0, bsize: 1, blocks: 2 ** 40, bfree: 2 ** 20, bavail: 2 ** 20 });
  t.mock.method(console, 'warn', () => {});
  const { get } = await fixture(t, {
    webhook: 'http://127.0.0.1:9/hook',
    storageGuard: { statfs },
  });
  const dashboard = await (await get('/api/dashboard')).json();
  assert.deepEqual(problems(dashboard, contract), []);
  assert.equal(dashboard.disk.full, true);
  assert.equal(dashboard.notifications.configured, true);
  assert.deepEqual(
    dashboard.notifications.channels.map(channel => channel.id),
    ['email', 'env-webhook', 'ntfy', 'gotify']
  );
  // Email is not set up (1.4.x's default): its channel says so, and nothing waits on it.
  assert.equal(dashboard.notifications.email.state, 'disabled');
  assert.equal(dashboard.notifications.email.channelState, 'not-configured');
  assert.equal(dashboard.notifications.email.waiting, 0);
});
