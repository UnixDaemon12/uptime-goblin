// The relay (lib/alerting/relay.mjs; delivery spec §5.3) over the real history Store and the
// memory outbox: the fast path, the sweep, marking by uid (V1), order per alert (D23, probe P1),
// source deletion, Uptime Goblin's own notices and the degraded path (D15).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Store } from '../../lib/store.mjs';
import { createRelay } from '../../lib/alerting/relay.mjs';
import { legacyEntries } from '../../lib/alerting/policy.mjs';
import { createOutbox, deliveryUid, ACTIVE_STATES } from '../../lib/notify/outbox.mjs';
import { createMemoryOutboxStore, createFailoverStore } from '../../lib/notify/memory-store.mjs';
import { accepted, retry } from '../../lib/notify/channel.mjs';
import { fakeClock, quietLogger, settle } from './fake-clock.mjs';

const ACTIVE = new Set(ACTIVE_STATES);
const alertSettings = {
  enabled: true,
  notifyOnAlert: true,
  notifyOnRecovery: true,
  notifyAvailability: true,
  notifyMeasurements: true,
};
const full = () =>
  Object.assign(new Error('database or disk is full'), { class: 'full', code: 'SQLITE_FULL' });
const busy = () =>
  Object.assign(new Error('database is locked'), { class: 'retry', code: 'SQLITE_BUSY' });

// A source that fires on its first failed check and recovers on its first good one.
const source = id => ({
  id,
  name: id.toUpperCase(),
  pollSeconds: 60,
  availabilityFailures: 1,
  availabilitySeconds: 0,
  recoverySuccesses: 1,
  recoverySeconds: 0,
  rules: [],
});

function history(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-relay-'));
  const store = new Store(directory);
  t.after(() => {
    store.close();
    fs.rmSync(directory, { recursive: true, force: true });
  });
  let time = 1_800_000_000_000;
  return {
    store,
    fire: id => store.evaluate(source(id), [], 'connection refused', (time += 1000)),
    recover: id => store.evaluate(source(id), [], null, (time += 1000)),
    idOf: uid => store.db.prepare('SELECT id FROM events WHERE uid = ?').get(uid)?.id ?? null,
    relayedOf: uid =>
      store.db.prepare('SELECT relayed FROM events WHERE uid = ?').get(uid)?.relayed,
  };
}

// A webhook that records each body's kind and service, answering from `script`, then 200.
function receiver(script = []) {
  const got = [];
  return {
    got,
    script,
    channel: {
      name: 'env-webhook',
      async send(message) {
        const [event] = message.events;
        got.push({ uid: message.uid, kind: event.kind, service: event.service });
        return script.length ? script.shift() : accepted({ status: 200 });
      },
    },
  };
}

/**
 * The relay as the delivery service wires it, over `outboxStore`: legacy routing to the webhook
 * (and email, when an email channel is given), `isFinal` through find(), cancel by source.
 * `faults` lets a test fail the next enqueue or mark.
 */
function relaySetup(
  t,
  {
    hist = history(t),
    outboxStore = createMemoryOutboxStore(),
    channels = [receiver().channel],
    wrapHistory = value => value,
    clock = fakeClock(),
  } = {}
) {
  const logger = quietLogger();
  const outbox = createOutbox({ store: outboxStore, clock, rng: () => 1, logger, channels });
  t.after(() => outbox.stop({ timeoutMs: 0 }));
  const faults = { enqueue: [], mark: [] };
  const emailEnabled = channels.some(channel => channel.name === 'email');
  const enqueue = async (event, eventUid, { exclude = [] } = {}) => {
    if (faults.enqueue.length) throw faults.enqueue.shift()();
    const entries = legacyEntries(event, {
      eventUid,
      settings: alertSettings,
      sourceAlerts: undefined,
      webhookConfigured: true,
      emailEnabled,
    }).filter(entry => !exclude.includes(entry.channelId));
    if (!entries.length) return { inserted: 0, duplicates: 0, dropped: 0, memoryUids: [] };
    return outbox.enqueue(entries);
  };
  const historyApi = wrapHistory({
    unrelayedEvents: options => hist.store.unrelayedEvents(options),
    markRelayed: uids => {
      if (faults.mark.length) throw faults.mark.shift()();
      return hist.store.markRelayed(uids);
    },
  });
  const relay = createRelay({
    history: historyApi,
    enqueue,
    isFinal: async uid => {
      const row = await outboxStore.find(uid);
      return !row || !ACTIVE.has(row.state);
    },
    cancelSource: id => outbox.cancelSource(id, 'Not sent: the source was deleted.'),
    nameOf: id => id.toUpperCase(),
    clock,
    logger,
  });
  const start = async () => {
    const sweep = relay.sweep();
    relay.started();
    return sweep;
  };
  const deliver = async () => {
    for (let i = 0; i < 50; i++) {
      const { started } = await outbox.pump();
      await settle();
      if (!started && !outbox.inFlight) return;
    }
  };
  return { hist, outbox, outboxStore, relay, faults, logger, start, deliver, clock };
}

test('the fast path enqueues each change and marks it relayed by uid', async t => {
  const hook = receiver();
  const { hist, relay, start, deliver } = relaySetup(t, { channels: [hook.channel] });
  await start();
  const events = hist.fire('plex');
  assert.match(events[0].uid, /^e_[a-z2-7]{26}$/);
  assert.deepEqual(await relay.relay(events), { enqueued: 1, marked: 1, deferred: 0 });
  assert.equal(hist.relayedOf(events[0].uid), 1);
  assert.deepEqual(hist.store.unrelayedEvents(), []);
  await deliver();
  assert.deepEqual(hook.got, [
    { uid: deliveryUid(events[0].uid, 'env-webhook'), kind: 'firing', service: 'plex' },
  ]);
  assert.equal(relay.pending, 0);
});

test('before start() and until the start sweep finished, the fast path defers to the sweep', async t => {
  const hook = receiver();
  const { hist, relay, deliver } = relaySetup(t, { channels: [hook.channel] });
  const early = hist.fire('plex');
  assert.deepEqual(await relay.relay(early), { enqueued: 0, marked: 0, deferred: 1 });
  // Queued before the start sweep: still deferred even though started() comes meanwhile.
  const queuedBefore = relay.relay(hist.fire('nas'));
  const sweep = relay.sweep();
  relay.started();
  assert.equal((await queuedBefore).deferred, 1);
  const result = await sweep;
  assert.deepEqual([result.relayed, result.marked], [2, 2]);
  // Now caught up: the fast path relays.
  assert.equal((await relay.relay(hist.recover('plex'))).enqueued, 1);
  await deliver();
  assert.deepEqual(
    hook.got.map(item => `${item.service}:${item.kind}`),
    ['plex:firing', 'nas:firing', 'plex:resolved']
  );
});

test('an enqueue that fails leaves the change to the sweep; a failed mark is retried', async t => {
  const hook = receiver();
  const { hist, relay, faults, start, deliver, logger } = relaySetup(t, {
    channels: [hook.channel],
  });
  await start();
  faults.enqueue.push(full);
  const events = hist.fire('plex');
  assert.deepEqual(await relay.relay(events), { enqueued: 0, marked: 0, deferred: 1 });
  assert.equal(hist.relayedOf(events[0].uid), 0);
  assert.match(logger.lines.error[0], /could not be queued: database or disk is full/);
  // The sweep relays it; its mark fails once (history full) and is tried again later.
  faults.mark.push(full);
  const first = await relay.sweep();
  assert.deepEqual([first.relayed, first.marked, first.pending], [1, 0, 1]);
  assert.equal(hist.relayedOf(events[0].uid), 0);
  const second = await relay.sweep();
  assert.deepEqual([second.relayed, second.marked, second.pending], [0, 1, 0]);
  assert.equal(hist.relayedOf(events[0].uid), 1);
  await deliver();
  assert.equal(hook.got.length, 1);
});

test('a crash between the outbox commit and the mark gives one row, not two', async t => {
  const hist = history(t);
  const outboxStore = createMemoryOutboxStore();
  const before = relaySetup(t, { hist, outboxStore });
  await before.start();
  before.faults.mark.push(busy);
  const events = hist.fire('plex');
  await before.relay.relay(events);
  assert.equal(hist.relayedOf(events[0].uid), 0, 'not marked: the process "crashed"');
  // The next process relays it again from history: the delivery id already exists.
  const hook = receiver();
  const after = relaySetup(t, { hist, outboxStore, channels: [hook.channel] });
  const swept = await after.start();
  assert.deepEqual([swept.relayed, swept.marked], [1, 1]);
  assert.equal((await outboxStore.list({ limit: 10 })).length, 1);
  await after.deliver();
  assert.equal(hook.got.length, 1);
});

test('V1 (a): a reused event id is relayed by the sweep, whose cursor lives one pass only', async t => {
  const hook = receiver();
  const { hist, relay, faults, deliver } = relaySetup(t, { channels: [hook.channel] });
  // x and y fire before the start: the start sweep relays both, its cursor reaching y's id.
  const x = hist.fire('x'),
    y = hist.fire('y');
  const sweep = relay.sweep();
  relay.started();
  await sweep;
  await deliver();
  const yId = hist.idOf(y[0].uid);
  assert.ok(yId > hist.idOf(x[0].uid));
  // y is deleted: its event goes, and SQLite gives the highest id to the next event, z's.
  await hist.store.forget('y');
  await relay.forget('y');
  const z = hist.fire('z');
  assert.equal(hist.idOf(z[0].uid), yId, 'z reuses y’s id');
  // z's fast path fails, so only the sweep can relay it.
  faults.enqueue.push(full);
  assert.equal((await relay.relay(z)).deferred, 1);
  await relay.sweep();
  await deliver();
  assert.deepEqual(
    hook.got.map(item => item.service),
    ['x', 'y', 'z']
  );
  assert.equal(hist.relayedOf(z[0].uid), 1);
});

test('V1 (b): a mark that runs after the id was reused never marks the new event', async t => {
  const hook = receiver();
  let gate = null;
  const { hist, relay, deliver } = relaySetup(t, {
    channels: [hook.channel],
    // Holds the sweep between reading y and marking it.
    wrapHistory: api => ({
      ...api,
      markRelayed: async uids => {
        if (gate) await gate.promise;
        return api.markRelayed(uids);
      },
    }),
  });
  const y = hist.fire('y');
  const yId = hist.idOf(y[0].uid);
  let release;
  gate = { promise: new Promise(resolve => (release = resolve)) };
  const sweep = relay.sweep();
  relay.started();
  await settle();
  // While the mark waits: y is deleted and z reuses its id.
  await hist.store.forget('y');
  const z = hist.fire('z');
  assert.equal(hist.idOf(z[0].uid), yId);
  gate = null;
  release();
  await sweep;
  // The mark named y's uid: z is still waiting to be relayed, and the next sweep does it.
  assert.equal(hist.relayedOf(z[0].uid), 0);
  await relay.sweep();
  assert.equal(hist.relayedOf(z[0].uid), 1);
  await deliver();
  assert.deepEqual(
    hook.got.map(item => item.service),
    ['y', 'z']
  );
});

test('P1: a recovery never overtakes an alert whose enqueue failed', async t => {
  const hook = receiver();
  const { hist, relay, faults, start, deliver } = relaySetup(t, { channels: [hook.channel] });
  await start();
  faults.enqueue.push(busy);
  const firing = hist.fire('plex');
  assert.equal((await relay.relay(firing)).deferred, 1);
  // The next poll: the resolved of the same alert is deferred too (its key is held).
  const resolved = hist.recover('plex');
  assert.deepEqual(await relay.relay(resolved), { enqueued: 0, marked: 0, deferred: 1 });
  // Another alert is not held up.
  assert.equal((await relay.relay(hist.fire('nas'))).enqueued, 1);
  await deliver();
  // The sweep relays in history order: firing, then resolved.
  await relay.sweep();
  await deliver();
  assert.deepEqual(
    hook.got.map(item => `${item.service}:${item.kind}`),
    ['nas:firing', 'plex:firing', 'plex:resolved']
  );
  // With the key released, the fast path relays the key's next change at once.
  assert.equal((await relay.relay(hist.fire('plex'))).enqueued, 1);
});

test('within one sweep, a key whose enqueue failed keeps its later changes for the next one', async t => {
  const hook = receiver();
  const { hist, relay, faults, deliver } = relaySetup(t, { channels: [hook.channel] });
  hist.fire('plex');
  hist.recover('plex');
  hist.fire('nas');
  faults.enqueue.push(full);
  const sweep = relay.sweep();
  relay.started();
  const first = await sweep;
  assert.equal(first.relayed, 1, 'only nas: plex’s firing failed, so its recovery waited');
  await relay.sweep();
  await deliver();
  assert.deepEqual(
    hook.got.map(item => `${item.service}:${item.kind}`),
    ['nas:firing', 'plex:firing', 'plex:resolved']
  );
});

test('forget() runs after the relays queued before it, then cancels the source’s rows', async t => {
  let release;
  const gated = new Promise(resolve => (release = resolve));
  const hook = receiver();
  const { hist, relay, start, outboxStore, deliver } = relaySetup(t, {
    channels: [hook.channel],
    wrapHistory: api => ({
      ...api,
      markRelayed: async uids => {
        await gated;
        return api.markRelayed(uids);
      },
    }),
  });
  const starting = start();
  release();
  await starting;
  const relayed = relay.relay(hist.fire('plex'));
  const forgotten = relay.forget('plex');
  assert.deepEqual(await forgotten, { cancelled: 1 });
  assert.equal((await relayed).enqueued, 1);
  const [row] = await outboxStore.list({ limit: 10 });
  assert.deepEqual([row.state, row.lastError], ['cancelled', 'Not sent: the source was deleted.']);
  await deliver();
  assert.equal(hook.got.length, 0);
});

test('direct() sends Uptime Goblin’s own notices through the routing, minus excluded channels', async t => {
  const hook = receiver();
  const mails = [];
  const email = {
    name: 'email',
    async send(message) {
      mails.push(message.events.map(event => event.message));
      return accepted();
    },
  };
  const { relay, outboxStore } = relaySetup(t, { channels: [hook.channel, email] });
  const notice = {
    service: 'orbit',
    name: 'Uptime Goblin',
    kind: 'firing',
    category: 'system',
    rule: '__channel_env-webhook',
    message: 'Webhook notifications are paused: The webhook answered 401.',
    time: 1_800_000_000_000,
  };
  assert.deepEqual(
    await relay.direct(notice, 'sys:pause:env-webhook:1800000000000:firing', {
      exclude: ['env-webhook'],
    }),
    { enqueued: 1 }
  );
  const rows = await outboxStore.list({ limit: 10 });
  assert.deepEqual(
    rows.map(row => row.channelId),
    ['email']
  );
  // The same notice again (a second call for the same pause) writes nothing.
  assert.deepEqual(
    await relay.direct(notice, 'sys:pause:env-webhook:1800000000000:firing', {
      exclude: ['env-webhook'],
    }),
    { enqueued: 0 }
  );
  assert.deepEqual(await relay.direct(notice, 'sys:disk:1:firing'), { enqueued: 2 });
});

test('rows written by 1.4.x (relayed NULL) are never read, relayed or rewritten', async t => {
  const hook = receiver();
  const { hist, relay, deliver } = relaySetup(t, { channels: [hook.channel] });
  const insert = hist.store.db.prepare(
    'INSERT INTO events(service,time,kind,message,category,rule) VALUES(?,?,?,?,?,?)'
  );
  for (let n = 0; n < 5; n++)
    insert.run(
      'legacy',
      1_700_000_000_000 + n,
      'firing',
      'Source is unavailable',
      'availability',
      '__availability'
    );
  const sweep = relay.sweep();
  relay.started();
  assert.deepEqual(await sweep, { relayed: 0, marked: 0, pending: 0, settled: 0 });
  await deliver();
  assert.equal(hook.got.length, 0);
  assert.equal(
    hist.store.db.prepare('SELECT COUNT(*) AS n FROM events WHERE relayed IS NULL').get().n,
    5
  );
});

test('a change the outbox refuses (TypeError) is logged, marked and never blocks its key', async t => {
  const hook = receiver();
  const { hist, relay, faults, start, deliver, logger } = relaySetup(t, {
    channels: [hook.channel],
  });
  await start();
  faults.enqueue.push(() => new TypeError('An outbox entry needs a kind'));
  const poisoned = hist.fire('plex');
  assert.deepEqual(await relay.relay(poisoned), { enqueued: 0, marked: 1, deferred: 0 });
  assert.equal(hist.relayedOf(poisoned[0].uid), 1);
  assert.match(
    logger.lines.error[0],
    /cannot be queued and is skipped: An outbox entry needs a kind/
  );
  assert.equal((await relay.relay(hist.recover('plex'))).enqueued, 1);
  await deliver();
  assert.deepEqual(
    hook.got.map(item => item.kind),
    ['resolved']
  );
});

// A primary store that fails writes with class `full` while `state.full` is true.
function fillable() {
  const inner = createMemoryOutboxStore();
  const state = { full: false };
  const writes = new Set([
    'insert',
    'claim',
    'complete',
    'hold',
    'release',
    'setChannel',
    'requeue',
    'stale',
    'unclaim',
    'cancel',
    'supersede',
    'expire',
    'prune',
    'shiftExpiry',
    'clampTimes',
  ]);
  const store = {};
  for (const [name, fn] of Object.entries(inner))
    if (typeof fn === 'function')
      store[name] = async (...args) => {
        if (state.full && writes.has(name)) throw full();
        return fn(...args);
      };
  return { store, inner, state };
}

test('D15: an event delivered from memory is marked once its rows are final', async t => {
  const { store: primary, state } = fillable();
  const hook = receiver();
  const { hist, relay, start, deliver } = relaySetup(t, {
    outboxStore: createFailoverStore({ primary, logger: quietLogger() }),
    channels: [hook.channel],
  });
  await start();
  state.full = true;
  const events = hist.fire('plex');
  assert.deepEqual(await relay.relay(events), { enqueued: 1, marked: 0, deferred: 0 });
  assert.equal(relay.pending, 1);
  assert.equal(hist.relayedOf(events[0].uid), 0, 'kept unmarked while its row is in memory');
  // Still waiting: the sweep leaves it alone.
  assert.equal((await relay.sweep()).settled, 0);
  await deliver();
  assert.equal(hook.got.length, 1);
  const swept = await relay.sweep();
  assert.deepEqual([swept.settled, swept.pending], [1, 0]);
  assert.equal(hist.relayedOf(events[0].uid), 1);
});

test('D15: restarting while an alert retries from memory sends it again from history, once', async t => {
  const hist = history(t);
  const { store: primary, inner, state } = fillable();
  const clock = fakeClock();
  // The first process: control.sqlite is full; the alert goes to memory and its first attempt
  // fails, so it is still waiting to retry when Uptime Goblin restarts.
  const first = receiver([retry(null, 'The webhook answered 500.', { status: 500 })]);
  const before = relaySetup(t, {
    hist,
    clock,
    outboxStore: createFailoverStore({ primary, logger: quietLogger() }),
    channels: [first.channel],
  });
  await before.start();
  state.full = true;
  const events = hist.fire('plex');
  await before.relay.relay(events);
  await before.deliver();
  assert.equal(first.got.length, 1);
  assert.equal(hist.relayedOf(events[0].uid), 0);
  // Restart with space again: memory is gone; the start sweep enqueues the alert into the
  // control database and it is delivered once.
  state.full = false;
  const second = receiver();
  const after = relaySetup(t, {
    hist,
    clock,
    outboxStore: createFailoverStore({ primary, logger: quietLogger() }),
    channels: [second.channel],
  });
  const swept = await after.start();
  assert.deepEqual([swept.relayed, swept.marked], [1, 1]);
  await after.deliver();
  assert.deepEqual(
    second.got.map(item => item.uid),
    [deliveryUid(events[0].uid, 'env-webhook')]
  );
  assert.equal((await inner.list({ limit: 10 }))[0].state, 'delivered');
});

test('D15, double failure: both databases full, an alert sent from memory is sent again after a restart', async t => {
  const hist = history(t);
  const { store: primary, state } = fillable();
  const first = receiver();
  const before = relaySetup(t, {
    hist,
    outboxStore: createFailoverStore({ primary, logger: quietLogger() }),
    channels: [first.channel],
  });
  await before.start();
  state.full = true;
  const events = hist.fire('plex');
  await before.relay.relay(events);
  await before.deliver();
  // Delivered from memory; history cannot record the relay either.
  before.faults.mark.push(full);
  assert.equal((await before.relay.sweep()).settled, 0);
  assert.equal(hist.relayedOf(events[0].uid), 0);
  // Restarted before the mark: sent again, with the same delivery id (at-least-once, §5.1).
  state.full = false;
  const second = receiver();
  const after = relaySetup(t, {
    hist,
    outboxStore: createFailoverStore({ primary, logger: quietLogger() }),
    channels: [second.channel],
  });
  await after.start();
  await after.deliver();
  assert.deepEqual(
    [...first.got, ...second.got].map(item => item.uid),
    [deliveryUid(events[0].uid, 'env-webhook'), deliveryUid(events[0].uid, 'env-webhook')]
  );
  assert.equal(hist.relayedOf(events[0].uid), 1);
});

test('idle() waits for everything queued, including what is queued meanwhile', async t => {
  const { hist, relay, start } = relaySetup(t);
  await start();
  const order = [];
  void relay.relay(hist.fire('a')).then(() => order.push('a'));
  const waiting = relay.idle().then(() => order.push('idle'));
  void relay.relay(hist.fire('b')).then(() => order.push('b'));
  await waiting;
  assert.deepEqual(order, ['a', 'b', 'idle']);
  assert.throws(() => createRelay({ history: {}, enqueue: async () => ({}) }), TypeError);
});

// Held (the ntfy and Gotify settings not read): enqueue queues the other channels and answers
// `held`. The event stays unrelayed with the rows it put in memory, is not tried again while
// enqueue still holds, and is relayed, then awaited (D15) with all its rows, once it does not.
function heldRelay(t, { maxPerSweep, pageSize } = {}) {
  const hist = history(t);
  const state = { waiting: true, final: new Set(), calls: [] };
  const relay = createRelay({
    history: hist.store,
    enqueue: async (event, uid) => {
      state.calls.push(`${event.service}:${event.kind}`);
      if (!event.service.startsWith('held-')) return { inserted: 1, memoryUids: [] };
      return state.waiting
        ? { inserted: 0, memoryUids: [`email:${uid}`], held: true }
        : { inserted: 0, memoryUids: [`ntfy:${uid}`] };
    },
    isFinal: async delivery => state.final.has(delivery),
    waiting: () => state.waiting,
    logger: quietLogger(),
    ...(maxPerSweep ? { maxPerSweep } : {}),
    ...(pageSize ? { pageSize } : {}),
  });
  relay.started();
  return { hist, state, relay };
}

test('a held change keeps the rows it put in memory, and is marked once those and its later rows are final', async t => {
  const { hist, state, relay } = heldRelay(t);
  const [firing] = hist.fire('held-plex');
  await relay.sweep();
  assert.equal(hist.relayedOf(firing.uid), 0);
  // Still held: the sweep does not route it again.
  await relay.sweep();
  assert.deepEqual(state.calls, ['held-plex:firing']);
  state.waiting = false;
  await relay.sweep();
  assert.deepEqual(state.calls, ['held-plex:firing', 'held-plex:firing']);
  assert.equal(hist.relayedOf(firing.uid), 0);
  // The ntfy row is final, but the email row the held attempt put in memory is not.
  state.final.add(`ntfy:${firing.uid}`);
  await relay.sweep();
  assert.equal(hist.relayedOf(firing.uid), 0);
  state.final.add(`email:${firing.uid}`);
  await relay.sweep();
  assert.equal(hist.relayedOf(firing.uid), 1);
});

test('held changes do not use up a sweep: newer changes pass more than maxPerSweep of them', async t => {
  const { hist, state, relay } = heldRelay(t, { maxPerSweep: 5, pageSize: 3 });
  const held = [];
  for (let n = 0; n < 12; n++) held.push(hist.fire(`held-${n}`)[0]);
  const [later] = hist.recover('held-0');
  const [newer] = hist.fire('plex');
  for (let pass = 0; pass < 3; pass++) await relay.sweep();
  assert.equal(hist.relayedOf(newer.uid), 1);
  // Each held change was routed once, and the recovery of a held alert waits behind it.
  assert.equal(state.calls.filter(call => call.startsWith('held-')).length, 12);
  assert.equal(state.calls.includes('held-0:resolved'), false);
  assert.ok(held.every(event => hist.relayedOf(event.uid) === 0));
  // The fast path keeps a held key's later change for the sweep too.
  const [fast] = hist.fire('held-0');
  assert.equal((await relay.relay([fast])).deferred, 1);
  state.waiting = false;
  for (const event of [...held, later, fast])
    for (const channel of ['email', 'ntfy']) state.final.add(`${channel}:${event.uid}`);
  for (let pass = 0; pass < 6; pass++) await relay.sweep();
  assert.ok([...held, later, fast].every(event => hist.relayedOf(event.uid) === 1));
  const order = state.calls.filter(call => call.startsWith('held-0:'));
  assert.deepEqual(order, ['held-0:firing', 'held-0:firing', 'held-0:resolved', 'held-0:firing']);
});

// An alert that flaps while its first change is held: its later changes wait behind it, and must
// not use up a sweep's maxPerSweep either, or newer alerts of other keys would never pass.
test('changes waiting behind a held one do not use up a sweep: newer keys pass more than maxPerSweep of them', async t => {
  const { hist, state, relay } = heldRelay(t, { maxPerSweep: 5, pageSize: 3 });
  const [first] = hist.fire('held-0');
  const flaps = [];
  for (let n = 0; n < 6; n++) flaps.push(hist.recover('held-0')[0], hist.fire('held-0')[0]);
  assert.equal(flaps.length, 12);
  const [newer] = hist.fire('plex');
  await relay.sweep();
  assert.equal(hist.relayedOf(newer.uid), 1);
  // Only the first change was routed; the flaps wait behind it.
  assert.deepEqual(
    state.calls.filter(call => call.startsWith('held-')),
    ['held-0:firing']
  );
  assert.ok([first, ...flaps].every(event => hist.relayedOf(event.uid) === 0));
  // The pass read to the end, so the fast path relays a newer key's change at once.
  const [fast] = hist.fire('nas');
  assert.equal((await relay.relay([fast])).deferred ?? 0, 0);
  assert.equal(hist.relayedOf(fast.uid), 1);
  state.waiting = false;
  for (const event of [first, ...flaps])
    for (const channel of ['email', 'ntfy']) state.final.add(`${channel}:${event.uid}`);
  for (let pass = 0; pass < 8; pass++) await relay.sweep();
  assert.ok([first, ...flaps].every(event => hist.relayedOf(event.uid) === 1));
  // In the order the alert changed.
  assert.deepEqual(state.calls.filter(call => call.startsWith('held-0:')).slice(1), [
    'held-0:firing',
    ...flaps.map((_, n) => (n % 2 ? 'held-0:firing' : 'held-0:resolved')),
  ]);
});
