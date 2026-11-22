import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { setImmediate as nextTurn, setTimeout as delay } from 'node:timers/promises';
import { createApp } from '../server.mjs';
import { Store } from '../lib/store.mjs';
import { configureDestinations } from '../lib/destinations.mjs';

function temporary(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-retention-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}
function seed(store, count = 5000) {
  const now = Date.now(),
    insert = store.db.prepare(
      'INSERT INTO readings(service,time,ok,metrics,error) VALUES (?,?,1,?,NULL)'
    );
  store.db.exec('BEGIN');
  for (let i = 0; i < count; i++) insert.run('linux', now - 3 * 86400000 - i, '[]');
  store.db.exec('COMMIT');
  return now;
}

async function fixture(t, options = {}) {
  const app = await createApp({
    directory: temporary(t),
    port: 0,
    password: 'fixture-retention-password',
    allowedHosts: '',
    webhook: '',
    startScheduler: false,
    trustProxy: '',
    ...options,
  });
  const { port } = await app.listen();
  t.after(() => app.close());
  const call = async (route, method, body) => {
    const response = await fetch(`http://127.0.0.1:${port}${route}`, {
      method,
      headers: {
        Authorization:
          'Basic ' + Buffer.from('admin:fixture-retention-password').toString('base64'),
        'Content-Type': 'application/json',
        'X-Goblin-Request': '1',
      },
      body: JSON.stringify(body),
    });
    await response.arrayBuffer();
    return response.status;
  };
  return { app, call, save: settings => call('/api/settings', 'PATCH', settings) };
}

test(
  'combined settings cancel old collection and mail before waiting for retention pruning',
  { timeout: 15000 },
  async t => {
    let collectionSignal, collectionStarted, mailStarted, pruneStarted, releasePrune;
    const collecting = new Promise(resolve => (collectionStarted = resolve)),
      sending = new Promise(resolve => (mailStarted = resolve)),
      pruning = new Promise(resolve => (pruneStarted = resolve)),
      heldPrune = new Promise(resolve => (releasePrune = resolve));
    let closedTransports = 0;
    const { app, call, save } = await fixture(t, {
      collector: service => {
        collectionSignal = service.signal;
        collectionStarted();
        return new Promise(() => {});
      },
      mailTransportFactory: () => ({
        sendMail() {
          mailStarted();
          return new Promise(() => {});
        },
        close() {
          closedTransports++;
        },
      }),
    });
    // Only injected collection and mail run; even SMTP DNS stays inside the fixture.
    configureDestinations({ lookup: async () => [{ address: '192.0.2.1', family: 4 }] });
    app.config.update('linux', { apiUrl: 'http://node.example.test:9100' });
    app.config.updateGlobal({
      email: {
        host: 'smtp.example.test',
        port: 465,
        secure: true,
        from: 'sender@example.test',
        to: 'recipient@example.test',
        password: 'fixture-app-password',
        enabled: true,
      },
    });
    app.store.db
      .prepare(
        'INSERT INTO alerts(service,rule,state,since,count,message,updated) VALUES (?,?,?,?,?,?,?)'
      )
      .run('linux', '__availability', 'firing', Date.now(), 1, 'Fixture alert', Date.now());
    const poll = app.poll(app.config.get('linux')),
      email = call('/api/email/test', 'POST', {});
    await Promise.all([collecting, sending]);
    t.mock.method(app.store, 'prune', () => {
      pruneStarted();
      return heldPrune;
    });
    const saving = save({
      retentionDays: 1,
      monitoring: { retryCount: 0 },
      email: { enabled: false },
      alerts: { enabled: false },
    });
    await pruning;
    try {
      assert.equal(app.config.value.retentionDays, 1, 'settings are already saved');
      assert.deepEqual(
        {
          collectionCanceled: collectionSignal.aborted,
          mailCanceled: closedTransports > 0,
          activeAlerts: app.store.alerts().length,
        },
        { collectionCanceled: true, mailCanceled: true, activeAlerts: 0 },
        'all saved settings must take effect before yielding for history cleanup'
      );
    } finally {
      releasePrune();
      assert.equal(await saving, 200);
      await poll;
      assert.equal(await email, 422, 'the canceled test reports its outcome');
    }
  }
);

test(
  'a changed collection interval applies before the settings response waits for pruning',
  { timeout: 15000 },
  async t => {
    // A controllable monotonic clock, so the test and not timing decides what is due.
    let clock = 1000000,
      pruneStarted,
      releasePrune;
    const polls = [],
      pruning = new Promise(resolve => (pruneStarted = resolve)),
      heldPrune = new Promise(resolve => (releasePrune = resolve));
    const { app, save } = await fixture(t, {
      monotonic: () => clock,
      collector: () => {
        polls.push(clock);
        return [];
      },
    });
    app.config.update('linux', { apiUrl: 'http://node.example.test:9100' });
    assert.ok(app.config.value.pollSeconds > 20, 'the default interval is longer than the new one');
    // The first tick collects the source (and runs the hourly prune on an empty history),
    // which schedules its next collection at the default interval.
    await app.tick();
    assert.equal(polls.length, 1, 'the first tick collects the source');
    // Past the new interval but inside the old one: the old schedule still holds the source.
    clock += 20000;
    await app.tick();
    assert.equal(polls.length, 1, 'the old interval is in force before the save');
    t.mock.method(app.store, 'prune', () => {
      pruneStarted();
      return heldPrune;
    });
    // Only retention and the interval change. A monitoring change would restart collection,
    // which clears the schedule on its own and would hide a reschedule made after the wait.
    const saving = save({ retentionDays: 1, pollSeconds: 15 });
    await pruning;
    try {
      assert.equal(app.config.value.pollSeconds, 15, 'settings are already saved');
      await app.tick();
      assert.equal(
        polls.length,
        2,
        'the saved interval must replace the old schedule before yielding for history cleanup'
      );
      clock += 15000;
      await app.tick();
      assert.equal(polls.length, 3, 'collection continues at the saved interval');
    } finally {
      releasePrune();
      assert.equal(await saving, 200);
    }
  }
);

test(
  'a failed shorter-retention save deletes no history in the default pruning window',
  { timeout: 15000 },
  async t => {
    const { app, save } = await fixture(t);
    seed(app.store, 60000);
    const before = fs.readFileSync(app.config.file, 'utf8');
    t.mock.method(app.config, 'save', () => {
      throw Object.assign(new Error('fixture configuration write failure'), { code: 'ENOSPC' });
    });
    // 1.5 (delivery spec §6.8): a full disk refusing the save is 503 storage_full, not 500.
    assert.equal(await save({ retentionDays: 1 }), 503);
    assert.equal(app.config.value.retentionDays, 30);
    assert.equal(fs.readFileSync(app.config.file, 'utf8'), before);
    assert.equal(app.store.stats().samples, 60000, 'an unsaved policy must never delete readings');
  }
);

test(
  'a saved shorter retention finishes real pruning after its bounded response',
  { timeout: 15000 },
  async t => {
    const { app, save } = await fixture(t, { settingsPruneMs: 1 });
    seed(app.store, 60000);
    assert.equal(await save({ retentionDays: 1 }), 200);
    assert.equal(app.config.value.retentionDays, 1);
    const remaining = app.store.stats().samples;
    assert.ok(
      remaining > 0 && remaining < 60000,
      'real deletion is still running after the response'
    );
    const deadline = Date.now() + 5000;
    while (app.store.stats().samples && Date.now() < deadline) await delay(10);
    assert.equal(app.store.stats().samples, 0, 'the saved policy permits every remaining batch');
  }
);

test(
  'a scheduled prune stops when a longer retention is saved between real batches',
  { timeout: 15000 },
  async t => {
    const { app } = await fixture(t);
    app.config.updateGlobal({ retentionDays: 1 });
    seed(app.store, 60000);
    const pruning = app.tick();
    const deadline = Date.now() + 5000;
    while (app.store.stats().samples === 60000 && Date.now() < deadline) await nextTurn();
    const remaining = app.store.stats().samples;
    assert.ok(remaining > 0 && remaining < 60000, 'the scheduler deleted a batch and yielded');
    app.config.updateGlobal({ retentionDays: 7 });
    await pruning;
    assert.equal(app.store.stats().samples, remaining, 'no batch uses the superseded policy');
  }
);

test(
  'a pruning failure after a settings save reports storage trouble without failing the save',
  { timeout: 15000 },
  async t => {
    const { app, save } = await fixture(t);
    seed(app.store, 10);
    app.store.db.exec(`
    CREATE TRIGGER refuse_prune BEFORE DELETE ON readings BEGIN
      SELECT RAISE(ABORT, 'fixture deletion failure');
    END;
  `);
    assert.equal(await save({ retentionDays: 1 }), 200);
    assert.equal(app.config.value.retentionDays, 1);
    assert.equal(JSON.parse(fs.readFileSync(app.config.file, 'utf8')).retentionDays, 1);
    assert.equal(app.store.stats().samples, 10);
    assert.ok(app.dashboard().storage, 'history failure remains visible');
  }
);

test('a superseded retention policy stops before its next deletion chunk', async t => {
  const store = new Store(temporary(t));
  t.after(() => store.close());
  const now = seed(store);
  let current = true;
  const pruning = store.prune(1, now, { shouldContinue: () => current });
  const afterFirst = store.stats().samples;
  assert.ok(afterFirst > 0 && afterFirst < 5000, 'first chunk ran and yielded');
  current = false;
  await pruning;
  assert.equal(store.stats().samples, afterFirst, 'later chunks must respect the new policy');
});

for (const scenario of ['longer retention saved', 'shorter retention save fails']) {
  test(`background pruning preserves history when ${scenario}`, { timeout: 15000 }, async t => {
    const app = await createApp({
      directory: temporary(t),
      port: 0,
      password: 'fixture-retention-password',
      allowedHosts: '',
      webhook: '',
      startScheduler: false,
      trustProxy: '',
      settingsPruneMs: 1,
    });
    const { port } = await app.listen();
    t.after(() => app.close());
    seed(app.store, 10);
    const call = body =>
      fetch(`http://127.0.0.1:${port}/api/settings`, {
        method: 'PATCH',
        headers: {
          Authorization:
            'Basic ' + Buffer.from('admin:fixture-retention-password').toString('base64'),
          'Content-Type': 'application/json',
          'X-Goblin-Request': '1',
        },
        body: JSON.stringify(body),
      });
    // Stand in for a long deletion that has yielded between chunks. Resume actual store
    // deletion after the new setting has been acknowledged, so timing is deterministic.
    let release, pending;
    const gate = new Promise(resolve => {
      release = resolve;
    });
    const original = app.store.prune.bind(app.store);
    app.store.prune = (...args) => (pending = gate.then(() => original(...args)));
    t.after(() => release());
    if (scenario === 'shorter retention save fails') {
      t.mock.method(app.config, 'save', () => {
        throw new Error('fixture write failure');
      });
      const response = await call({ retentionDays: 1 });
      assert.equal(response.status, 500);
      await response.arrayBuffer();
      assert.equal(app.config.value.retentionDays, 30);
    } else {
      let response = await call({ retentionDays: 1 });
      assert.equal(response.status, 200);
      await response.arrayBuffer();
      response = await call({ retentionDays: 7 });
      assert.equal(response.status, 200);
      await response.arrayBuffer();
      assert.equal(app.config.value.retentionDays, 7);
    }
    release();
    await pending;
    assert.equal(
      app.store.stats().samples,
      10,
      'history within the saved retention window survives'
    );
  });
}
