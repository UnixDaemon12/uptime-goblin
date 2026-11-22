// lib/repo/state: the alerts and events repositories over the 1.x tables, and source status.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createAlerts } from '../../lib/repo/state/alerts.mjs';
import { createEvents } from '../../lib/repo/state/events.mjs';
import { sourceState, sourceStatus, createStatus } from '../../lib/repo/state/status.mjs';
import { createUnitRunner } from '../../lib/repo/unit.mjs';
import { createSeriesStoreV1 } from '../../lib/series/v1.mjs';
import { cycleSeconds } from '../../lib/config.mjs';
import { newService } from '../../lib/catalog.mjs';
import { createApp } from '../../server.mjs';
import { configureDestinations } from '../../lib/destinations.mjs';
import {
  temporary,
  openHistory,
  measurements,
  seeded,
  rows,
  eventOf,
  withoutUid,
  legacyEvaluator,
} from './helpers.mjs';

configureDestinations({ lookup: async () => [{ address: '192.0.2.1' }] });
const base = Date.UTC(2026, 8, 1, 12);
const source = (id, rules = []) => ({
  id,
  name: id.toUpperCase(),
  rules,
  pollSeconds: 60,
  collectionTimeoutSeconds: 90,
  availabilityFailures: 2,
  availabilitySeconds: 60,
  recoverySuccesses: 2,
  recoverySeconds: 60,
});
const cpuRule = {
  key: 'cpu',
  operator: 'gt',
  threshold: 80,
  forSeconds: 60,
  recoveryThreshold: 70,
};

function repositories(t) {
  const opened = openHistory(t),
    units = createUnitRunner(opened.stores),
    events = createEvents({ db: opened.history, units }),
    alerts = createAlerts({ db: opened.history, events, units });
  return { ...opened, units, events, alerts };
}

test('transition() applies an evaluation exactly as Store.evaluate() writes it', async t => {
  const { store: legacy } = openHistory(t),
    { alerts, events, store: view } = repositories(t),
    evaluator = legacyEvaluator(t),
    { random, pick, int } = seeded(7),
    sources = [source('a', [cpuRule]), source('b'), source('c', [{ ...cpuRule, forSeconds: 0 }])];
  let now = base;
  for (let step = 0; step < 300; step++) {
    now += int(10, 200) * 1000;
    const service = pick(sources),
      error = random() < 0.3 ? 'Refused' : null,
      metrics = error ? [] : random() < 0.1 ? [] : measurements(int(0, 100));
    // Events are compared without their uid, random per write (each Store draws its own);
    // since and relayed are compared.
    const expected = legacy.evaluate(service, metrics, error, now).map(eventOf);
    const recorded = await alerts.transition(service.id, evaluator(service, metrics, error, now));
    assert.deepEqual(recorded.map(withoutUid), expected.map(withoutUid), `events @${step}`);
    assert.ok(
      recorded.every(event => /^e_[a-z2-7]{26}$/.test(event.uid)),
      'events carry a uid'
    );
    if (step % 10 === 0 || step > 290) {
      assert.deepEqual(
        rows(view.db, 'alerts', 'service,rule'),
        rows(legacy.db, 'alerts', 'service,rule')
      );
      assert.deepEqual(
        rows(view.db, 'events', 'id').map(({ id, uid, ...rest }) => rest),
        rows(legacy.db, 'events', 'id').map(({ id, uid, ...rest }) => rest)
      );
      assert.ok(rows(view.db, 'events', 'id').every(row => row.relayed === 0 && row.uid));
      assert.deepEqual(await alerts.firing(), legacy.alerts());
      assert.deepEqual(await events.recent(), legacy.events());
      assert.equal(await alerts.countFiring(), legacy.stats().activeAlerts);
      assert.equal(await events.count(), legacy.stats().events);
    }
  }
  assert.ok(legacy.stats().events > 10, 'the sequence fired and resolved alerts');
});

test('transition() is one unit: a failing or awaiting evaluator leaves nothing behind', async t => {
  const { alerts, events, units } = repositories(t);
  const row = (rule, state = 'pending') => ({
    service: 'a',
    rule,
    state,
    since: base,
    count: 1,
    message: `${rule} is high`,
    updated: base,
  });
  const firing = {
    service: 'a',
    time: base,
    kind: 'firing',
    message: 'm',
    category: 'availability',
    rule: 'x',
  };
  assert.deepEqual(
    await alerts.transition('a', current => {
      assert.deepEqual(current, []);
      return { alerts: [row('x'), row('y')], events: [firing] };
    }),
    [firing]
  );
  assert.deepEqual(
    (await alerts.forService('a')).map(r => [r.rule, r.recovery_since, r.recovery_count]),
    [
      ['x', null, 0],
      ['y', null, 0],
    ]
  );
  // Rows left out are deleted, changed rows updated, unchanged rows left alone.
  await alerts.transition('a', current => {
    assert.equal(current.length, 2);
    current[0].count = 99; // a copy: changing it changes nothing stored
    return { alerts: [{ ...row('x', 'firing'), count: 2 }], events: [] };
  });
  assert.deepEqual(
    (await alerts.forService('a')).map(r => [r.rule, r.state, r.count]),
    [['x', 'firing', 2]]
  );
  const before = await alerts.forService('a'),
    eventsBefore = await events.count();
  // An evaluator that throws: nothing written, the error passes with its class.
  await assert.rejects(
    alerts.transition('a', () => {
      throw Object.assign(new Error('broken rule'), { class: 'poison' });
    }),
    { name: 'RepoError', class: 'poison', unit: 'state.transition' }
  );
  // Rows it returns are checked before anything is written.
  await assert.rejects(
    alerts.transition('a', () => ({
      alerts: [row('z'), { ...row('x'), service: 'b' }],
      events: [],
    })),
    /another source/
  );
  await assert.rejects(
    alerts.transition('a', () => ({ alerts: [{ ...row('z'), state: 'snoozed' }], events: [] })),
    { class: 'poison' }
  );
  await assert.rejects(
    alerts.transition('a', () => ({ alerts: [{ ...row('z'), since: undefined }], events: [] })),
    { class: 'poison', message: /no since/ }
  );
  await assert.rejects(
    alerts.transition('a', () => ({ alerts: [], events: [{ ...firing, time: 'soon' }] })),
    { class: 'poison' }
  );
  await assert.rejects(
    alerts.transition('a', () => null),
    { class: 'fatal' }
  );
  await assert.rejects(alerts.transition('a'), { class: 'fatal' });
  // The SQLite guard, as the evaluator meets it.
  await assert.rejects(
    alerts.transition('a', async () => ({ alerts: [], events: [] })),
    /cannot be async|promise/
  );
  assert.deepEqual(await alerts.forService('a'), before);
  assert.equal(await events.count(), eventsBefore);
  assert.ok(units.stats()['state.transition'].failures >= 6);
});

test('alert rows are upserted: a column a later release adds survives an update here', async t => {
  const { alerts, store } = repositories(t);
  store.db.exec('ALTER TABLE alerts ADD COLUMN acknowledged_by TEXT');
  const row = {
    service: 'a',
    rule: 'cpu',
    state: 'firing',
    since: base,
    count: 2,
    message: 'CPU is high',
    updated: base,
  };
  await alerts.transition('a', () => ({ alerts: [row], events: [] }));
  store.db.prepare("UPDATE alerts SET acknowledged_by='ops' WHERE service='a'").run();
  await alerts.transition('a', () => ({
    alerts: [{ ...row, count: 3, updated: base + 1 }],
    events: [],
  }));
  const stored = store.db.prepare("SELECT * FROM alerts WHERE service='a'").get();
  assert.equal(stored.count, 3);
  assert.equal(stored.acknowledged_by, 'ops', 'INSERT OR REPLACE would have reset it');
});

test('rule changes, pauses and switching alerts off reset state as the Store does', async t => {
  const { store: legacy } = openHistory(t),
    { alerts, store: view } = repositories(t),
    evaluator = legacyEvaluator(t),
    rules = [cpuRule, { key: 'memory', operator: 'lt', threshold: 5, forSeconds: 0 }],
    services = ['a', 'b'].map(id => source(id, rules));
  // Both databases hold the same firing and recovering alerts.
  let now = base;
  for (let n = 0; n < 6; n++) {
    now += 60000;
    const list = [
      { key: 'cpu', label: 'CPU', value: n < 5 ? 95 : 60, unit: '%' },
      { key: 'memory', label: 'Memory', value: 1, unit: '%' },
    ];
    for (const service of services) {
      legacy.evaluate(service, list, null, now);
      await alerts.transition(service.id, evaluator(service, list, null, now));
    }
  }
  const same = async () => {
    assert.deepEqual(
      rows(view.db, 'alerts', 'service,rule'),
      rows(legacy.db, 'alerts', 'service,rule')
    );
  };
  await same();
  assert.ok(rows(legacy.db, 'alerts', 'service,rule').some(r => r.recovery_count > 0));
  const changed = [
    { ...cpuRule, recoveryThreshold: 60 },
    { ...rules[1], threshold: 10 },
  ];
  legacy.reconcileRules('a', rules, changed);
  await alerts.reconcileRules('a', rules, changed);
  await same();
  legacy.reconcileRules('b', rules, [rules[0]]);
  await alerts.reconcileRules('b', rules, [rules[0]]);
  await same();
  legacy.clearAlerts('a');
  await alerts.clear('a');
  await same();
  legacy.clearAllAlerts();
  await alerts.clearAll();
  await same();
  assert.deepEqual(await alerts.forService('b'), []);
});

test('events: newest first, retention and erasure in chunks, as the Store keeps them', async t => {
  const { store: legacy } = openHistory(t),
    { events, store: view } = repositories(t);
  const insert = store =>
    store.db.prepare(
      'INSERT INTO events(service,time,kind,message,category,rule) VALUES(?,?,?,?,?,?)'
    );
  const legacyInsert = insert(legacy),
    viewInsert = insert(view);
  const { int, pick } = seeded(3);
  const list = [];
  for (let n = 0; n < 2600; n++)
    // Many share a time, so the order of ties matters.
    list.push([
      pick(['a', 'b', 'c']),
      base - int(0, 400) * 60000,
      'firing',
      `e${n}`,
      'availability',
      '__availability',
    ]);
  legacy.db.exec('BEGIN');
  for (const values of list) legacyInsert.run(...values);
  legacy.db.exec('COMMIT');
  await events.append(
    list.map(([service, time, kind, message, category, rule]) => ({
      service,
      time,
      kind,
      message,
      category,
      rule,
    }))
  );
  assert.deepEqual(await events.recent(), legacy.events());
  assert.deepEqual(await events.recent(5), legacy.events().slice(0, 5));
  assert.equal(await events.count(), 2600);
  // Retention: the Store's prune removes events (and readings, none here) older than it.
  await legacy.prune(0.1, base);
  const removed = await events.applyRetention({ retentionDays: 0.1, now: base });
  assert.ok(removed > 1000, String(removed));
  assert.deepEqual(rows(view.db, 'events', 'id'), rows(legacy.db, 'events', 'id'));
  // Erasure: a source's events, whatever their age.
  await legacy.forget('b');
  await events.eraseTarget('b');
  assert.deepEqual(rows(view.db, 'events', 'id'), rows(legacy.db, 'events', 'id'));
  assert.deepEqual(await events.recent(), legacy.events());
  await assert.rejects(events.applyRetention({}), { class: 'fatal' });
  await assert.rejects(events.append([{ service: 'a', kind: 'firing', message: 'm' }]), {
    class: 'poison',
  });
});

test('an event with an over-long message, kind or source ID is poison; a message is made storable', async t => {
  const { history, store } = openHistory(t),
    events = createEvents({ db: history });
  const event = fields => ({ service: 'a', time: base, kind: 'firing', message: 'm', ...fields });
  // The 1.x table has no CHECK: these were stored whole (a 5 MiB message, say).
  for (const fields of [
    { message: 'SYNTHETIC '.repeat(512 * 1024) },
    { message: 'x'.repeat(1001) },
    { message: '' },
    { kind: 'k'.repeat(33) },
    { service: 's'.repeat(81) },
    { service: '' },
  ])
    await assert.rejects(events.append([event(fields)]), { class: 'poison' });
  assert.equal(store.stats().events, 0);
  // A message can quote a source's error text: half a pair becomes U+FFFD (as SQLite stored
  // it), and a NUL goes; at the limit it is kept whole.
  await events.append([
    event({ message: 'Source is unavailable: a\u0000b\ud800' }),
    event({ message: 'x'.repeat(1000), time: base + 1 }),
  ]);
  assert.deepEqual(
    store.db
      .prepare('SELECT message FROM events ORDER BY id')
      .all()
      .map(row => row.message),
    ['Source is unavailable: ab�', 'x'.repeat(1000)]
  );
});

test('remove and resetRecovery need a rule; clearService is the only whole-source delete', async t => {
  const { alerts, history, store } = repositories(t);
  const row = rule => ({
    service: 's',
    rule,
    state: 'pending',
    since: base,
    count: 1,
    message: 'm',
    updated: base,
    recovery_since: base,
    recovery_count: 1,
  });
  await history.write(tx => ['cpu', 'disk', 'mem'].forEach(rule => alerts.tx.put(tx, row(rule))));
  // A missing rule fell back to the source's condition: every rule's row was deleted or reset.
  for (const missing of [undefined, null, 7])
    for (const call of [
      tx => alerts.tx.remove(tx, 's', missing),
      tx => alerts.tx.resetRecovery(tx, 's', missing, base + 1),
    ])
      await assert.rejects(history.write(call), {
        class: 'fatal',
        message: /An alert rule is needed/,
      });
  assert.equal((await alerts.forService('s')).length, 3);
  assert.equal(
    store.db.prepare('SELECT count(*) AS n FROM alerts WHERE recovery_count = 1').get().n,
    3
  );
  assert.equal(await history.write(tx => alerts.tx.remove(tx, 's', 'cpu')), 1);
  assert.equal(await history.write(tx => alerts.tx.resetRecovery(tx, 's', 'disk', base + 1)), 1);
  assert.deepEqual(
    (await alerts.forService('s')).map(r => [r.rule, r.recovery_count]),
    [
      ['disk', 0],
      ['mem', 1],
    ]
  );
  assert.equal(await history.write(tx => alerts.tx.clearService(tx, 's')), 2);
});

test('events recycled on a full disk go in the same transaction, a chunk at a time', async t => {
  const { history, store } = openHistory(t),
    events = createEvents({ db: history });
  await events.append(
    Array.from({ length: 1500 }, (_, n) => ({
      service: 'a',
      time: base + n,
      kind: 'firing',
      message: `e${n}`,
    }))
  );
  const deleted = await history.write(tx => events.tx.deleteBefore(tx, base + 1400));
  assert.equal(deleted, 1000, 'one chunk');
  assert.equal(store.stats().events, 500);
  assert.equal(await history.write(tx => events.tx.deleteBefore(tx, base + 1400, 50)), 50);
});

test('source status is the rule the 1.4.3 dashboard applies', async t => {
  const directory = temporary(t),
    app = await createApp({
      directory,
      port: 0,
      password: 'fixture-password',
      allowedHosts: '',
      webhook: '',
      startScheduler: false,
    });
  t.after(() => app.close());
  const now = Date.now();
  // Sources in every status: live, stale (old success; failure after success), error,
  // collecting, unconfigured, disabled and link.
  app.config.update('linux', { apiUrl: 'http://192.0.2.10' });
  app.config.update('proxmox', { apiUrl: 'http://192.0.2.11' });
  app.config.update('docker', { apiUrl: 'http://192.0.2.12' });
  app.config.update('plex', { apiUrl: 'http://192.0.2.13' });
  app.config.update('sonarr', { apiUrl: 'http://192.0.2.14', enabled: false });
  const site = app.config.add({ type: 'http', name: 'Site', url: 'https://site.example.test' });
  const link = app.config.add({ type: 'link', name: 'Link', url: 'https://link.example.test' });
  app.store.record('linux', measurements(1), null, now - 1000);
  app.store.record('proxmox', measurements(2), null, now - 3 * 3600 * 1000);
  app.store.record('docker', measurements(3), null, now - 60000);
  app.store.record('docker', [], 'Refused', now - 1000);
  app.store.record('plex', [], 'Refused', now - 1000);
  app.store.record(site.id, measurements(4), null, now - 2000);
  const interval = s => s.pollSeconds || app.config.value.pollSeconds,
    timeoutMs = s => ({ ...app.config.value.monitoring, ...s?.monitoring }).timeoutSeconds * 1000,
    cycle = s => cycleSeconds(app.config, s, { interval, timeoutMs });
  const dashboard = app.dashboard().services;
  const derived = app.config.value.services.map(s =>
    sourceState(s, app.store.latest(s.id), { now, cycleSeconds: cycle, collecting: new Set() })
  );
  assert.deepEqual(derived, dashboard);
  const statuses = Object.fromEntries(
    app.config.value.services.map((s, i) => [s.id, dashboard[i].status])
  );
  assert.equal(statuses.linux, 'live');
  assert.equal(statuses.proxmox, 'stale');
  assert.equal(statuses.docker, 'stale');
  assert.equal(statuses.plex, 'error');
  assert.equal(statuses.sonarr, 'disabled');
  assert.equal(statuses[link.id], 'link');
  assert.equal(statuses.unifi, 'unconfigured');
  assert.equal(statuses[site.id], 'live');
  assert.equal(
    sourceStatus(
      { ...newService('linux'), apiUrl: 'http://x' },
      { lastSuccess: null, error: null },
      { cycleSeconds: 60 }
    ),
    'collecting'
  );
  // The same through the series store, which reads every source in one call.
  const { history } = openHistory(t);
  const series = createSeriesStoreV1({ db: history }),
    status = createStatus({ series });
  await series.append({ service: 'linux', time: now - 1000, metrics: measurements(1) });
  const [linux] = await status.states([app.config.get('linux')], {
    now,
    cycleSeconds: cycle,
    collecting: new Set(['linux']),
  });
  assert.equal(linux.status, 'live');
  assert.equal(linux.collecting, true);
  assert.equal(linux.collector, 'linux');
});
