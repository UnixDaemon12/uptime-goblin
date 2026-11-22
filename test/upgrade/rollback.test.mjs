import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { installRelease, skipWithoutFixtures } from './fixtures.mjs';
import {
  endpoint,
  freePort,
  readConfig,
  readHistory,
  start,
  temporary,
  waitFor,
  workingTree,
} from './harness.mjs';

// Rollback simulation: the working tree writes data (including collector notes and a changed
// password), 1.4.2 runs on the result, and the working tree runs on it again. 1.4.2 is the
// rollback floor for 1.4.3 (code only): it must start, keep every reading, alert and setting,
// and leave config.json and auth.json byte-identical.
const exporter = () =>
  'node_load1 0.5\n' +
  Array.from(
    { length: 210 },
    (_, i) =>
      `node_filesystem_size_bytes{mountpoint="/srv/${i}",device="d${i}",fstype="ext4"} 100\n` +
      `node_filesystem_avail_bytes{mountpoint="/srv/${i}",device="d${i}",fstype="ext4"} 40\n`
  ).join('');
const changedPassword = 'rollback-simulation-only';
const service = (dashboard, id) => dashboard.services.find(s => s.id === id);
const readingKeys = history => history.readings.map(r => `${r.service}@${r.time}:${r.ok}`);

test('rolling back to 1.4.2 and forward again keeps readings, alerts, settings and sign-in', async t => {
  if (skipWithoutFixtures(t)) return;
  const directory = temporary(t),
    data = path.join(directory, 'data'),
    floor = installRelease('1.4.2', path.join(directory, 'orbit-1.4.2')),
    website = await endpoint(t),
    metrics = await endpoint(t, pathname => (pathname === '/metrics' ? exporter() : [404, ''])),
    outage = `http://127.0.0.1:${await freePort()}/`;

  // Forward: the working tree, used as its owner would.
  let current = await start(t, { app: workingTree, data });
  const settings = await current.request('PATCH', '/api/settings', {
    body: {
      title: 'Rollback drill',
      monitoring: { availabilityFailures: 1, availabilitySeconds: 0, retryCount: 0 },
    },
  });
  assert.equal(settings.status, 200, settings.text);
  const add = async body => {
    const response = await current.request('POST', '/api/services', {
      body: { group: 'Rollback', ...body },
    });
    assert.equal(response.status, 201, response.text);
    return response.json.service.id;
  };
  const ids = {
    website: await add({ type: 'http', name: 'Website', apiUrl: website }),
    outage: await add({ type: 'http', name: 'Outage', apiUrl: outage }),
    host: await add({ type: 'linux', name: 'Host', apiUrl: metrics }),
  };
  const noted = async running =>
    service(await running.dashboard(), ids.host)?.notes?.some(n => n.code === 'filesystems_capped');
  await waitFor(async () => {
    const dashboard = await current.dashboard();
    return (
      service(dashboard, ids.website)?.lastSuccess &&
      dashboard.alerts.some(a => a.service === ids.outage) &&
      (await noted(current))
    );
  }, 'the working tree to collect, note the filesystem cap and raise an alert');
  const change = await current.request('POST', '/api/auth/password', {
    body: {
      currentPassword: current.secret,
      password: changedPassword,
      confirmPassword: changedPassword,
    },
  });
  assert.equal(change.status, 200, change.text);
  current.secret = changedPassword;
  assert.equal((await current.request('GET', '/api/dashboard')).status, 200);
  assert.equal((await current.stop()).code, 0, current.output());
  const forward = {
    config: readConfig(data),
    auth: fs.readFileSync(path.join(data, 'auth.json')),
    history: readHistory(data),
  };
  assert.ok(forward.history.tables.includes('latest_notes'));
  const alert = forward.history.alerts.find(a => a.service === ids.outage);
  assert.equal(alert.state, 'firing');
  const hostSuccess = forward.history.latest.find(l => l.service === ids.host).success;

  // Back: 1.4.2 on the same data directory.
  const old = await start(t, { app: floor, data, secret: changedPassword });
  assert.ok(readConfig(data).equals(forward.config), 'config.json is not rewritten');
  let dashboard = await old.dashboard();
  assert.equal(dashboard.config.title, 'Rollback drill');
  assert.deepEqual(
    dashboard.services.map(s => s.id),
    JSON.parse(forward.config).services.map(s => s.id)
  );
  assert.equal(dashboard.alerts.find(a => a.service === ids.outage)?.since, alert.since);
  assert.equal(service(dashboard, ids.host).notes, undefined, '1.4.2 knows nothing of notes');
  // 1.4.2 records readings of its own, which the notes do not describe.
  await waitFor(
    async () => service(await old.dashboard(), ids.host).lastSuccess > hostSuccess,
    '1.4.2 to collect'
  );
  const history = await old.request('GET', `/api/history/${ids.website}?range=1h`);
  assert.equal(history.status, 200);
  assert.ok(history.json.points.some(p => p.ok));
  assert.equal((await old.stop()).code, 0, old.output());
  const back = { config: readConfig(data), history: readHistory(data) };
  assert.ok(back.config.equals(forward.config), 'config.json is byte-identical');
  assert.ok(fs.readFileSync(path.join(data, 'auth.json')).equals(forward.auth), 'auth.json too');
  const kept = new Set(readingKeys(back.history));
  assert.ok(readingKeys(forward.history).every(key => kept.has(key)));

  // Forward again: everything from both runs is there, and notes return with new readings.
  current = await start(t, { app: workingTree, data, secret: changedPassword });
  dashboard = await current.dashboard();
  assert.equal(dashboard.config.title, 'Rollback drill');
  assert.equal(dashboard.alerts.find(a => a.service === ids.outage)?.since, alert.since);
  await waitFor(() => noted(current), 'notes to return after the next collection');
  assert.equal((await current.stop()).code, 0, current.output());
  const again = readHistory(data),
    all = new Set(readingKeys(again));
  assert.ok(
    readingKeys(back.history).every(key => all.has(key)),
    'no reading was lost'
  );
  assert.ok(back.history.events.every(e => again.events.some(x => x.id === e.id)));
  assert.ok(fs.readFileSync(path.join(data, 'auth.json')).equals(forward.auth));
});

test('a UTC offset time zone reverts to local on 1.4.2 and stays local after upgrading again', async t => {
  if (skipWithoutFixtures(t)) return;
  const directory = temporary(t),
    data = path.join(directory, 'data'),
    floor = installRelease('1.4.2', path.join(directory, 'orbit-1.4.2'));
  let current = await start(t, { app: workingTree, data });
  const set = await current.request('PATCH', '/api/settings', {
    body: { appearance: { timezone: 'UTC+05:30' } },
  });
  assert.equal(set.status, 200, set.text);
  assert.equal((await current.dashboard()).config.appearance.timezone, 'UTC+05:30');
  assert.equal((await current.stop()).code, 0, current.output());

  const old = await start(t, { app: floor, data });
  assert.equal((await old.dashboard()).config.appearance.timezone, 'local');
  assert.equal((await old.stop()).code, 0);
  assert.match(old.output(), /unsupported time zone "UTC\+05:30" was replaced by "local"/);
  assert.equal(JSON.parse(readConfig(data)).appearance.timezone, 'local');

  current = await start(t, { app: workingTree, data });
  assert.equal((await current.dashboard()).config.appearance.timezone, 'local');
  assert.equal((await current.stop()).code, 0, current.output());
});
