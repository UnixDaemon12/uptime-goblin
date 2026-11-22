import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { installRelease, releaseFiles, skipWithoutFixtures, versions } from './fixtures.mjs';
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

// Upgrade simulation: each published release starts on an empty data directory and is used
// through its own API (settings, two sources, a real poll of each, an availability alert),
// then stops; the working tree starts on the same directory and must keep all of it.
async function useRelease(running, { version, website, outage }) {
  const supports = key => releaseFiles(version).files.get('lib/config.mjs').includes(key);
  const settings = await running.request('PATCH', '/api/settings', {
    body: {
      title: `Upgraded from ${version}`,
      monitoring: {
        availabilityFailures: 1,
        availabilitySeconds: 0,
        timeoutSeconds: 5,
        ...(supports("'retryCount'") ? { retryCount: 0 } : {}),
      },
    },
  });
  assert.equal(settings.status, 200, settings.text);
  const add = async body => {
    const response = await running.request('POST', '/api/services', { body });
    assert.equal(response.status, 201, response.text);
    return response.json.service.id;
  };
  const ids = {
    website: await add({
      type: 'http',
      name: 'Upgrade website',
      group: 'Upgrade',
      apiUrl: website,
      rules: [{ key: 'response', operator: 'gt', threshold: 60000, forSeconds: 0 }],
    }),
    outage: await add({ type: 'http', name: 'Upgrade outage', group: 'Upgrade', apiUrl: outage }),
  };
  await waitFor(async () => {
    const dashboard = await running.dashboard(),
      site = dashboard.services.find(s => s.id === ids.website);
    return site?.lastSuccess && dashboard.alerts.some(a => a.service === ids.outage);
  }, `${version} to record a reading and raise an alert`);
  return ids;
}

describe('upgrading from each published release keeps its data', { concurrency: 3 }, () => {
  for (const version of versions)
    it(`from ${version}`, async t => {
      if (skipWithoutFixtures(t)) return;
      const directory = temporary(t),
        data = path.join(directory, 'data'),
        app = installRelease(version, path.join(directory, 'app')),
        website = await endpoint(t),
        outage = `http://127.0.0.1:${await freePort()}/`;
      // 1. The old release, used as its owner would.
      const old = await start(t, { app, data });
      const ids = await useRelease(old, { version, website, outage });
      const stopped = await old.stop();
      assert.equal(stopped.code, 0, old.output());
      const before = { config: JSON.parse(readConfig(data)), history: readHistory(data) };
      const alert = before.history.alerts.find(a => a.service === ids.outage);
      assert.equal(alert?.state, 'firing');
      const successes = before.history.readings.filter(r => r.service === ids.website && r.ok);
      assert.ok(successes.length >= 1);

      // 2. The working tree on the same data directory.
      const current = await start(t, { app: workingTree, data });
      const dashboard = await current.dashboard();
      assert.equal(dashboard.config.title, `Upgraded from ${version}`);
      for (const [name, id] of Object.entries(ids))
        assert.ok(
          dashboard.services.some(s => s.id === id),
          `${name} source is listed`
        );
      assert.ok(
        dashboard.services.find(s => s.id === ids.website).lastSuccess >= successes.at(-1).time
      );
      // The alert raised by the old release is still firing, since the same moment.
      const firing = dashboard.alerts.find(a => a.service === ids.outage);
      assert.equal(firing?.rule, '__availability');
      assert.equal(firing.since, alert.since);
      const event = before.history.events.find(e => e.service === ids.outage);
      assert.ok(
        dashboard.events.some(
          e => e.id === event.id && e.time === event.time && e.kind === 'firing'
        ),
        'the firing event is kept'
      );
      const history = await current.request('GET', `/api/history/${ids.website}?range=1h`);
      assert.equal(history.status, 200, history.text);
      assert.ok(history.json.totalSamples >= successes.length);
      assert.ok(history.json.points.some(p => p.ok && p.metrics.some(m => m.key === 'response')));
      assert.equal((await current.stop()).code, 0, current.output());

      // 3. Nothing the old release wrote was lost or changed.
      const after = { config: JSON.parse(readConfig(data)), history: readHistory(data) };
      assert.equal(after.config.title, before.config.title);
      assert.deepEqual(
        { ...after.config.monitoring, ...before.config.monitoring },
        after.config.monitoring,
        'monitoring settings are kept'
      );
      for (const old of before.config.services) {
        const kept = after.config.services.find(s => s.id === old.id);
        for (const key of ['type', 'name', 'group', 'apiUrl', 'enabled', 'rules'])
          assert.deepEqual(kept?.[key], old[key], `${old.id}.${key}`);
      }
      const rows = new Set(after.history.readings.map(r => `${r.service}@${r.time}:${r.ok}`));
      for (const r of before.history.readings)
        assert.ok(rows.has(`${r.service}@${r.time}:${r.ok}`), 'every reading is kept');
      for (const e of before.history.events)
        assert.ok(after.history.events.some(x => x.id === e.id && x.message === e.message));
      assert.ok(after.history.tables.includes('latest_notes'));
    });
});
