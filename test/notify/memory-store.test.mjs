// The in-memory OutboxStore and the failover store (the degraded path of design §2.7, T8).
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createMemoryOutboxStore,
  createFailoverStore,
  isStorageError,
} from '../../lib/notify/memory-store.mjs';
import { createOutbox, deliveryUid, digestKeyFor } from '../../lib/notify/outbox.mjs';
import { accepted, retry, failed } from '../../lib/notify/channel.mjs';
import {
  outboxStoreContract,
  outboxRow,
  deliveryOrderProperty,
  seededRandom,
} from './store-contract.mjs';
import { fakeClock, quietLogger, settle } from '../alerting/fake-clock.mjs';

outboxStoreContract(test, 'memory', async () => createMemoryOutboxStore());
outboxStoreContract(test, 'failover over a healthy store', async () =>
  createFailoverStore({ primary: createMemoryOutboxStore(), logger: quietLogger() })
);

const full = () =>
  Object.assign(new Error('database or disk is full'), {
    code: 'ERR_SQLITE_ERROR',
    errcode: 13,
    errstr: 'database or disk is full',
  });

// The OutboxStore operations that write (a full disk refuses these; reads keep working).
const WRITES = new Set([
  'insert',
  'claim',
  'complete',
  'expire',
  'hold',
  'release',
  'supersede',
  'setChannel',
  'prune',
  'requeue',
  'stale',
  'unclaim',
  'cancel',
  'shiftExpiry',
  'clampTimes',
]);

// A store whose calls fail with `error()` while `broken` is true: every call, or with
// `state.writesOnly` only writes (as on a full disk). `state.failing[name] = n` fails the next n
// calls of one operation.
function breakable(error = full) {
  const inner = createMemoryOutboxStore();
  const state = { broken: false, writesOnly: false, calls: 0, failing: {} };
  const store = { kind: 'breakable' };
  for (const [name, fn] of Object.entries(inner)) {
    if (typeof fn !== 'function') continue;
    store[name] = async (...args) => {
      state.calls++;
      if (state.failing[name] > 0) {
        state.failing[name]--;
        throw error();
      }
      if (state.broken && (!state.writesOnly || WRITES.has(name))) throw error();
      return fn(...args);
    };
  }
  return { store, inner, state };
}
const busy = () =>
  Object.assign(new Error('database is locked'), { code: 'SQLITE_BUSY', class: 'retry' });

// A webhook-like channel that answers from `script` (then accepted) and records what it got.
function recording(script = []) {
  const sent = [];
  return {
    sent,
    channel: {
      name: 'env-webhook',
      async send(message) {
        sent.push(message.events[0].kind);
        return script.length ? script.shift() : accepted({ status: 200 });
      },
    },
  };
}
function outboxOver(store, channels, clock = fakeClock()) {
  return {
    clock,
    outbox: createOutbox({ store, clock, rng: () => 1, logger: quietLogger(), channels }),
  };
}
async function drain(outbox) {
  for (let i = 0; i < 50; i++) {
    const { started } = await outbox.pump();
    await settle();
    if (!started && !outbox.inFlight) return;
  }
  throw new Error('the outbox did not settle');
}
const key = 'plex\n__availability';
const entry = (eventUid, kind) => ({
  eventUid,
  channelId: 'env-webhook',
  kind,
  orderKey: key,
  event: { service: 'plex', kind, message: kind },
});

test('storage errors are the full or unavailable classes and SQLite I/O failures', () => {
  for (const error of [
    full(),
    { class: 'full' },
    { class: 'unavailable' },
    { errcode: 10 | (3 << 8) }, // SQLITE_IOERR_WRITE: the primary code decides
    { errcode: 8 },
    { code: 'SQLITE_CANTOPEN' },
    { message: 'SQLITE_CORRUPT: database disk image is malformed' },
    { errstr: 'file is not a database', errcode: 26 },
  ])
    assert.equal(isStorageError(error), true, JSON.stringify(error));
  for (const error of [
    new TypeError('bad row'),
    { errcode: 19, message: 'UNIQUE constraint failed' },
    { class: 'unique' },
    null,
    undefined,
  ])
    assert.equal(isStorageError(error), false, JSON.stringify(error));
});

test('a full disk moves new rows to memory; they are still delivered and counted', async () => {
  const { store: primary, inner, state } = breakable();
  const changes = [];
  const logger = quietLogger();
  const store = createFailoverStore({ primary, logger, onChange: value => changes.push(value) });
  const T0 = 1_800_000_000_000;
  await store.insert([outboxRow({ eventUid: 'saved', createdAt: T0 })]);
  assert.equal(store.degraded, false);

  state.broken = true;
  const { inserted } = await store.insert([outboxRow({ eventUid: 'in-memory', createdAt: T0 })]);
  assert.equal(store.degraded, true);
  assert.equal(store.reason, 'ERR_SQLITE_ERROR');
  assert.deepEqual(changes, [true]);
  assert.match(logger.lines.error[0], /Notifications are not being saved/);
  assert.match(String(inserted[0].id), /^m:\d+$/);
  // Reads skip the failing store without failing: the memory rows are still worked.
  const due = await store.candidates({ now: T0, limit: 10 });
  assert.deepEqual(
    due.map(row => row.eventUid),
    ['in-memory']
  );
  const [claimed] = await store.claim(
    due.map(row => row.id),
    { owner: 'o', epoch: 1, now: T0, leaseUntil: T0 + 60000 }
  );
  assert.equal(claimed.id, inserted[0].id);
  assert.equal(
    await store.complete([{ id: claimed.id, patch: { state: 'delivered' } }], {
      owner: 'o',
      epoch: 1,
    }),
    1
  );
  assert.deepEqual((await store.counts()).total, { delivered: 1 });

  // Space is back: the next insert is saved again and the notice clears. The row that was
  // delivered from memory is saved first, as it is, so it is listed before the new one.
  assert.equal(store.unsaved, 1);
  state.broken = false;
  await store.insert([outboxRow({ eventUid: 'saved-again', createdAt: T0 })]);
  assert.equal(store.degraded, false);
  assert.deepEqual(changes, [true, false]);
  assert.equal(store.degradedSince, null);
  assert.deepEqual(
    (await inner.list({ limit: 10 })).map(row => [row.eventUid, row.state]),
    [
      ['saved-again', 'queued'],
      ['in-memory', 'delivered'],
      ['saved', 'queued'],
    ]
  );
  assert.equal(store.unsaved, 0);
  const counts = await store.counts();
  assert.deepEqual(counts.total, { queued: 2, delivered: 1 });
  assert.equal(await store.countActive(), 2);
});

test('an error that is not about storage is never hidden by the failover store', async () => {
  const { store: primary, state } = breakable(() => new TypeError('a bug, not a full disk'));
  const store = createFailoverStore({ primary, logger: quietLogger() });
  state.broken = true;
  await assert.rejects(store.insert([outboxRow()]), TypeError);
  await assert.rejects(store.candidates({ now: 0, limit: 1 }), TypeError);
  assert.equal(store.degraded, false);
});

test('with the control database full, the outbox still delivers and reports it', async () => {
  const clock = fakeClock();
  const { store: primary, state } = breakable();
  const logger = quietLogger();
  const store = createFailoverStore({ primary, logger });
  const sent = [];
  const outbox = createOutbox({
    store,
    clock,
    rng: () => 1,
    logger: quietLogger(),
    channels: [
      {
        name: 'env-webhook',
        async send(message) {
          sent.push(message.events[0].message);
          return accepted({ status: 204 });
        },
      },
    ],
  });
  state.broken = true;
  const result = await outbox.enqueue({
    eventUid: 'ev-full',
    channelId: 'env-webhook',
    kind: 'firing',
    event: { message: 'Uptime Goblin cannot write its history database' },
  });
  assert.equal(result.inserted, 1);
  assert.equal(await outbox.flush(), true);
  assert.deepEqual(sent, ['Uptime Goblin cannot write its history database']);
  const status = await outbox.status();
  assert.equal(status.degraded, true);
  assert.equal(status.counts.delivered, 1);
  assert.equal(status.channels['env-webhook'].deliveredTotal, 1);
  // A row saved before the disk filled: its completion cannot be written now. It is kept for
  // later and counted as recorded, not reported as "another worker owns those rows".
  state.broken = false;
  await outbox.enqueue({
    eventUid: 'ev-saved',
    channelId: 'env-webhook',
    kind: 'firing',
    event: { message: 'saved before the disk filled' },
  });
  state.broken = true;
  state.writesOnly = true;
  state.failing.claim = 0;
  // Claim works on this one call (the disk filled between the claim and the result).
  state.broken = false;
  await outbox.pump();
  state.broken = true;
  await settle();
  assert.equal(sent.length, 2);
  assert.ok(!logger.lines.warn.some(line => /another worker/.test(line)));
  state.broken = false;
  await outbox.pump();
  assert.equal((await primary.find(deliveryUid('ev-saved', 'env-webhook'))).state, 'delivered');
});

test('P2: a recovery kept in memory never overtakes its alert across the two stores', async () => {
  // The primary refuses the firing (full); the firing's first attempt fails, so it is still
  // active in memory when the resolved arrives with the primary writable again.
  {
    const { store: primary, state } = breakable();
    const store = createFailoverStore({ primary, logger: quietLogger() });
    const hook = recording([retry(null, 'The webhook answered 500.', { status: 500 })]);
    const { outbox, clock } = outboxOver(store, [hook.channel]);
    state.broken = true;
    await outbox.enqueue(entry('fire', 'firing'));
    await drain(outbox);
    state.broken = false;
    const result = await outbox.enqueue(entry('ok', 'resolved'));
    // The key has an active memory row: the resolved goes to memory too, behind it.
    assert.deepEqual(result.memoryUids, [deliveryUid('ok', 'env-webhook')]);
    await drain(outbox);
    await clock.advance(60000);
    await drain(outbox);
    assert.deepEqual(hook.sent, ['firing', 'firing', 'resolved']);
  }
  // The reverse: the firing is in the primary and retrying; the primary refuses the resolved,
  // which goes to memory and waits while the primary holds the firing.
  {
    const { store: primary, state } = breakable();
    const store = createFailoverStore({ primary, logger: quietLogger() });
    const hook = recording([retry(null, 'The webhook answered 500.', { status: 500 })]);
    const { outbox, clock } = outboxOver(store, [hook.channel]);
    await outbox.enqueue(entry('fire', 'firing'));
    await drain(outbox);
    state.failing.insert = 1;
    const result = await outbox.enqueue(entry('ok', 'resolved'));
    assert.deepEqual(result.memoryUids, [deliveryUid('ok', 'env-webhook')]);
    await drain(outbox);
    assert.deepEqual(hook.sent, ['firing']);
    await clock.advance(60000);
    await drain(outbox);
    assert.deepEqual(hook.sent, ['firing', 'firing', 'resolved']);
  }
});

test('the delivery order property holds over the failover store while the primary fills and empties', async () => {
  for (const seed of [11, 12, 13, 14]) {
    const { store: primary, state } = breakable();
    state.writesOnly = true;
    const store = createFailoverStore({ primary, logger: quietLogger() });
    // probe() writes a channel status the store already holds.
    await store.setChannel('env-webhook', { state: 'ok', nextSendAt: 0 });
    const { random } = seededRandom(seed * 7);
    const steps = 300;
    const result = await deliveryOrderProperty(store, {
      seed,
      steps,
      between: async n => {
        // A full disk comes and goes; space is back before the final drain.
        if (n === steps - 1) state.broken = false;
        else if (random() < 0.15) state.broken = !state.broken;
      },
    });
    assert.ok(result.inserted > 50);
    // Space is back: a probe (the service runs one every 10 s while degraded) ends the state.
    assert.equal(await store.probe(), true);
    assert.equal(store.degraded, false);
  }
});

test('a completion the primary cannot write is deferred, never resent, and applied later', async () => {
  for (const [label, makeError] of [
    ['a full disk', full],
    ['SQLITE_BUSY past its retries', busy],
  ]) {
    const { store: primary, inner, state } = breakable(makeError);
    const store = createFailoverStore({ primary, logger: quietLogger() });
    const hook = recording();
    const { outbox, clock } = outboxOver(store, [hook.channel]);
    await outbox.enqueue(entry('fire', 'firing'));
    // The send succeeds; writing its result fails, again and again.
    state.failing.complete = 1000;
    await outbox.pump();
    await settle();
    assert.equal(hook.sent.length, 1, label);
    const [row] = await inner.list({ limit: 10 });
    assert.equal(row.state, 'sending', label);
    // Past the lease: a sending row would count as "acceptance unknown" and be resent, but a
    // deferred one is neither recovered nor a candidate.
    await clock.advance(5 * 60 * 1000);
    await drain(outbox);
    assert.equal(await outbox.recover({ foreign: true }), 0, label);
    assert.equal(hook.sent.length, 1, label);
    assert.equal(store.degraded, makeError === full, label);
    // The primary accepts writes again: the next operation applies the kept result.
    state.failing.complete = 0;
    await outbox.pump();
    assert.equal((await inner.list({ limit: 10 }))[0].state, 'delivered', label);
    assert.equal(hook.sent.length, 1, label);
  }
});

test('an unclaim the primary cannot write is deferred like a completion', async () => {
  const { store: primary, inner, state } = breakable();
  const store = createFailoverStore({ primary, logger: quietLogger() });
  const [row] = (await store.insert([outboxRow()])).inserted;
  const lease = { owner: 'o', epoch: 1, now: 1, leaseUntil: 60001 };
  await store.claim([row.id], lease);
  state.failing.unclaim = 1;
  assert.equal(await store.unclaim([row.id], { owner: 'o', epoch: 1, now: 2 }), 1);
  assert.deepEqual(await store.sending(), []);
  // Applied before the next primary operation.
  await store.countActive();
  const [after] = await inner.list({ limit: 10 });
  assert.deepEqual([after.state, after.attempts], ['queued', 0]);
});

test('clock-step adjustments the primary cannot write are kept, in order after kept completions, and written once it can (D25)', async () => {
  const T = 1_800_000_000_000,
    hour = 3600 * 1000,
    max = Number.MAX_SAFE_INTEGER,
    lease = { owner: 'o_a', epoch: 1 };
  // The same calls on a failover store whose primary takes them and on one whose primary refuses
  // every write meanwhile (a full disk): once it takes writes again, its rows must read the same.
  const run = async refusing => {
    const { store: primary, inner, state } = breakable();
    state.writesOnly = true;
    const store = createFailoverStore({ primary, logger: quietLogger(), now: () => T });
    const sending = { state: 'sending', leaseOwner: 'o_a', epoch: 1, attempts: 1 };
    await store.insert([
      outboxRow({ eventUid: 'queued', nextAt: T + 5 * hour, expiresAt: T + 23 * hour }),
      outboxRow({ eventUid: 'held', state: 'held', expiresAt: T + 2 * hour }),
      outboxRow({ eventUid: 'sent', ...sending, leaseUntil: T + 60000, expiresAt: T + 20 * hour }),
      outboxRow({ eventUid: 'sending', ...sending, leaseUntil: T + 10 * hour }),
      outboxRow({ eventUid: 'done', state: 'delivered', expiresAt: T + hour }),
    ]);
    const id = async uid => (await inner.list({ limit: 10 })).find(r => r.eventUid === uid).id;
    state.broken = refusing;
    // A retry answer before a backward step: its time comes from the clock before the step.
    await store.complete(
      [
        {
          id: await id('sent'),
          patch: { state: 'queued', nextAt: T + 10 * hour, leaseOwner: null, leaseUntil: null },
        },
      ],
      lease
    );
    // A forward step of 6 h, a backward one, then a forward one of 2 h (D25's calls).
    await store.shiftExpiry({ by: 6 * hour, now: T + 1 });
    await store.clampTimes({
      now: T + 1,
      nextAtMax: max,
      expiresAtMax: T + 24 * hour,
      leaseUntilMax: max,
    });
    await store.clampTimes({
      now: T + 2,
      nextAtMax: T + 15 * 60000,
      expiresAtMax: T + 24 * hour,
      leaseUntilMax: T + 60000,
    });
    await store.shiftExpiry({ by: 2 * hour, now: T + 3 });
    await store.clampTimes({
      now: T + 3,
      nextAtMax: max,
      expiresAtMax: T + 25 * hour,
      leaseUntilMax: max,
    });
    // Before the adjustment is written, no row of the primary expires by its old expiry (the held
    // row's was T + 2 h); then space is back, and the next primary operation writes it first.
    assert.equal(await store.expire(T + 5 * hour), 0);
    state.broken = false;
    assert.equal(await store.expire(T + 5 * hour), 0);
    const rows = await inner.list({ limit: 10 });
    return Object.fromEntries(
      rows.map(r => [r.eventUid, [r.state, r.nextAt, r.expiresAt, r.leaseUntil]])
    );
  };
  const written = await run(false),
    kept = await run(true);
  assert.deepEqual(kept, written);
  assert.deepEqual(written, {
    queued: ['queued', T + 15 * 60000, T + 25 * hour, null],
    held: ['held', T, T + 10 * hour, null],
    sent: ['queued', T + 15 * 60000, T + 25 * hour, null],
    sending: ['sending', T, T + 25 * hour, T + 60000],
    done: ['delivered', T, T + hour, null],
  });
});

test('a channel status the primary cannot write is served from memory until probe() saves it', async () => {
  const { store: primary, inner, state } = breakable();
  const logger = quietLogger();
  const changes = [];
  const store = createFailoverStore({
    primary,
    logger,
    onChange: (value, error) => changes.push([value, error?.errcode ?? null]),
  });
  await store.setChannel('env-webhook', { state: 'ok', consecutiveFailures: 0 });
  state.broken = true;
  state.writesOnly = true;
  await store.setChannel('env-webhook', { state: 'paused', pausedReason: '401' });
  assert.equal(store.degraded, true);
  assert.deepEqual(changes, [[true, 13]]);
  // Dirty: the memory copy wins over the primary's stale one.
  assert.equal((await inner.channel('env-webhook')).state, 'ok');
  assert.equal((await store.channel('env-webhook')).state, 'paused');
  assert.equal(await store.probe(), false);
  state.broken = false;
  assert.equal(await store.probe(), true);
  assert.equal(store.degraded, false);
  assert.equal((await inner.channel('env-webhook')).state, 'paused');
  assert.deepEqual(changes, [
    [true, 13],
    [false, null],
  ]);
  // Nothing to write (no channel status anywhere): probe() reports the current state.
  const empty = createFailoverStore({ primary: createMemoryOutboxStore(), logger });
  assert.equal(await empty.probe(), true);
});

test('release() is never swallowed: the primary’s error rejects it, after the rows kept in memory are released', async () => {
  // Swallowed (answering 0), a resume or probe went on as if its rows were queued, and they
  // stayed held for good on a channel that looked fine (delivery spec A20).
  const T0 = 1_800_000_000_000;
  const { store: primary, inner, state } = breakable();
  const store = createFailoverStore({ primary, logger: quietLogger() });
  await store.insert([outboxRow({ eventUid: 'saved', state: 'held', createdAt: T0 })]);
  state.broken = true;
  state.writesOnly = true;
  const [kept] = (
    await store.insert([outboxRow({ eventUid: 'kept', state: 'held', createdAt: T0 })])
  ).inserted;
  assert.match(String(kept.id), /^m:/);
  await assert.rejects(store.release('env-webhook', T0), { errstr: 'database or disk is full' });
  assert.equal(store.degraded, true);
  assert.equal((await store.find(kept.uid)).state, 'queued', 'the memory row is released');
  assert.equal((await inner.find(outboxRow({ eventUid: 'saved' }).uid)).state, 'held');
  state.broken = false;
  assert.equal(await store.release('env-webhook', T0), 1);
  assert.equal((await inner.find(outboxRow({ eventUid: 'saved' }).uid)).state, 'queued');
  // An error that is not about storage is passed on as it is, without "not saving".
  const other = breakable(() => new TypeError('a bug, not a full disk'));
  const plain = createFailoverStore({ primary: other.store, logger: quietLogger() });
  other.state.broken = true;
  await assert.rejects(plain.release('env-webhook', T0), TypeError);
  assert.equal(plain.degraded, false);
});

test('a re-enqueue of a row the primary already holds adds nothing to memory', async () => {
  const { store: primary, inner, state } = breakable();
  const store = createFailoverStore({ primary, logger: quietLogger() });
  const row = outboxRow({ eventUid: 'relayed-twice' });
  await store.insert([row]);
  state.broken = true;
  state.writesOnly = true;
  const again = await store.insert([row, outboxRow({ eventUid: 'new-one' })]);
  assert.deepEqual(again.duplicates, [row.uid]);
  assert.deepEqual(
    again.inserted.map(r => r.eventUid),
    ['new-one']
  );
  assert.match(String(again.inserted[0].id), /^m:/);
  assert.equal(store.unsaved, 1);
  // When the primary cannot even be read, every row is kept in memory (better twice than lost).
  state.writesOnly = false;
  const unread = await store.insert([outboxRow({ eventUid: 'relayed-twice' })]);
  assert.equal(unread.inserted.length, 1);
  assert.equal(store.unsaved, 2);
  assert.equal((await inner.list({ limit: 10 })).length, 1);
});

test('summary, list, batch and find report a primary read error instead of answering empty', async () => {
  const { store: primary, state } = breakable();
  const store = createFailoverStore({ primary, logger: quietLogger() });
  const [saved] = (await store.insert([outboxRow({ digestKey: 'g_x' })])).inserted;
  state.broken = true;
  const kept = (await store.insert([outboxRow({ eventUid: 'kept' })])).inserted[0];
  for (const read of [
    () => store.summary({ failedSince: {} }),
    () => store.list({ limit: 10 }),
    () => store.batch('g_x'),
    () => store.find(saved.uid),
  ])
    await assert.rejects(read(), /database or disk is full/);
  // A memory row is found without the primary.
  assert.equal((await store.find(kept.uid)).id, kept.id);
  state.broken = false;
  // Without a cursor: memory rows first (ids m:<n>), then the primary's; with one, primary only.
  const listed = await store.list({ limit: 10 });
  assert.deepEqual(
    listed.map(row => row.eventUid),
    ['kept', saved.eventUid]
  );
  assert.deepEqual(
    (await store.list({ limit: 10, beforeId: saved.id + 1 })).map(row => row.id),
    [saved.id]
  );
  assert.equal((await store.summary({}))['env-webhook'].waiting, 2);
});

test('list() reads one side alone for the history pages: memory rows below an m:<n> id, or the saved rows (A30)', async () => {
  const { store: primary, state } = breakable();
  const store = createFailoverStore({ primary, logger: quietLogger() });
  const saved = (await store.insert([outboxRow({ eventUid: 'saved' })])).inserted[0];
  state.failing.insert = 3;
  const kept = [];
  for (const eventUid of ['m1', 'm2', 'm3'])
    kept.push((await store.insert([outboxRow({ eventUid })])).inserted[0]);
  assert.ok(kept.every(row => /^m:[1-9][0-9]*$/.test(row.id)));
  const uids = rows => rows.map(row => row.eventUid);
  // Memory rows alone, newest first, paged by their own ids; never the primary's.
  assert.deepEqual(uids(await store.list({ part: 'memory', limit: 2 })), ['m3', 'm2']);
  assert.deepEqual(uids(await store.list({ part: 'memory', beforeId: kept[1].id, limit: 2 })), [
    'm1',
  ]);
  assert.deepEqual(uids(await store.list({ part: 'memory', beforeId: kept[0].id })), []);
  // The saved rows alone, from the newest, and below a row id.
  assert.deepEqual(uids(await store.list({ part: 'saved', limit: 10 })), ['saved']);
  assert.deepEqual(uids(await store.list({ part: 'saved', beforeId: saved.id })), []);
  // A memory page names a memory row, never a primary one.
  await assert.rejects(store.list({ part: 'memory', beforeId: saved.id }), TypeError);
  await assert.rejects(store.list({ part: 'memory', afterId: kept[0].id }), TypeError);
  // Without `part`, as before: memory rows first, then the primary's.
  assert.deepEqual(uids(await store.list({ limit: 10 })), ['m3', 'm2', 'm1', 'saved']);
});

test('memory candidates wait for the primary unless it cannot be read; that is logged once a minute', async () => {
  const { store: primary, state } = breakable();
  let now = 1000;
  const logger = quietLogger();
  const store = createFailoverStore({ primary, logger, now: () => now });
  const T0 = 1_800_000_000_000;
  await store.insert([outboxRow({ eventUid: 'p', orderKey: key, nextAt: T0 + 60000 })]);
  state.failing.insert = 1;
  await store.insert([outboxRow({ eventUid: 'm', orderKey: key })]);
  // The primary's row of the key waits to retry: the memory row waits behind it.
  assert.deepEqual(await store.candidates({ now: T0, limit: 10 }), []);
  // The primary cannot be read: delivery goes on, unfiltered, and this is logged once a minute.
  state.broken = true;
  for (let i = 0; i < 3; i++) {
    const due = await store.candidates({ now: T0, limit: 10 });
    assert.deepEqual(
      due.map(row => row.eventUid),
      ['m']
    );
  }
  const lines = () => logger.lines.error.filter(line => /could not be checked/.test(line)).length;
  assert.equal(lines(), 1);
  now += 61000;
  await store.candidates({ now: T0, limit: 10 });
  assert.equal(lines(), 2);
});

// A webhook channel that runs `before(message)` as it sends (to fill the disk mid-send), then
// answers from `script` (then accepted).
function sendingThen(before, script = []) {
  const sent = [];
  return {
    sent,
    channel: {
      name: 'env-webhook',
      async send(message) {
        before(message);
        sent.push(message.events[0].kind);
        return script.length ? script.shift() : accepted({ status: 200 });
      },
    },
  };
}

test('a row sent before the primary stopped taking writes holds its key only while its kept result keeps it active', async () => {
  // Accepted: the firing was delivered and only its write waits. The recovery, kept in memory,
  // is not held back behind it, and the history and summary show the firing as delivered.
  {
    const { store: primary, inner, state } = breakable();
    state.writesOnly = true;
    const store = createFailoverStore({ primary, logger: quietLogger() });
    await store.setChannel('env-webhook', { state: 'ok', nextSendAt: 0 });
    const hook = sendingThen(() => (state.broken = true));
    const { outbox, clock } = outboxOver(store, [hook.channel]);
    await outbox.enqueue(entry('fire', 'firing'));
    await drain(outbox);
    assert.equal((await inner.find(deliveryUid('fire', 'env-webhook'))).state, 'sending');
    const result = await outbox.enqueue(entry('ok', 'resolved'));
    assert.deepEqual(result.memoryUids, [deliveryUid('ok', 'env-webhook')]);
    await drain(outbox);
    assert.deepEqual(hook.sent, ['firing', 'resolved']);
    // Kept for a day with the disk still full: nothing more is sent, nothing expires.
    await clock.advance(25 * 3600 * 1000);
    await drain(outbox);
    assert.deepEqual(hook.sent, ['firing', 'resolved']);
    assert.deepEqual(
      (await store.list({ limit: 10 })).map(row => [row.kind, row.state]),
      [
        ['resolved', 'delivered'],
        ['firing', 'delivered'],
      ]
    );
    // Filtered by state, the row is listed by what the database holds.
    assert.deepEqual(
      (await store.list({ states: ['queued', 'sending', 'held'], limit: 10 })).map(row => [
        row.kind,
        row.state,
      ]),
      [['firing', 'sending']]
    );
    assert.equal((await store.summary({ failedSince: {} }))['env-webhook'], undefined);
    assert.deepEqual(await store.activeKeys([{ channelId: 'env-webhook', orderKey: key }]), []);
    // Space is back: the kept result is written, the recovery saved.
    state.broken = false;
    assert.equal(await store.probe(), true);
    assert.deepEqual(
      (await inner.list({ limit: 10 })).map(row => [row.kind, row.state]),
      [
        ['resolved', 'delivered'],
        ['firing', 'delivered'],
      ]
    );
    assert.equal(store.unsaved, 0);
  }
  // Asked to retry: the firing is still to be sent, so the recovery waits behind it (D23), and
  // goes after it once the result is written and the firing delivered.
  {
    const { store: primary, inner, state } = breakable();
    state.writesOnly = true;
    const store = createFailoverStore({ primary, logger: quietLogger() });
    await store.setChannel('env-webhook', { state: 'ok', nextSendAt: 0 });
    const hook = sendingThen(
      () => (state.broken = true),
      [retry(null, 'The webhook answered 500.', { status: 500 })]
    );
    const { outbox, clock } = outboxOver(store, [hook.channel]);
    await outbox.enqueue(entry('fire', 'firing'));
    await drain(outbox);
    await outbox.enqueue(entry('ok', 'resolved'));
    await clock.advance(5 * 60 * 1000);
    await drain(outbox);
    assert.deepEqual(hook.sent, ['firing']);
    assert.equal((await store.summary({ failedSince: {} }))['env-webhook'].sending, 1);
    hook.channel.send = async message => {
      hook.sent.push(message.events[0].kind);
      return accepted({ status: 200 });
    };
    state.broken = false;
    assert.equal(await store.probe(), true);
    assert.equal((await inner.find(deliveryUid('fire', 'env-webhook'))).state, 'queued');
    await drain(outbox);
    assert.deepEqual(hook.sent, ['firing', 'firing', 'resolved']);
  }
});

test('rows that ended in memory are saved once the primary takes writes again; rows still in progress stay unsaved and listed first', async () => {
  const { store: primary, inner, state } = breakable();
  state.writesOnly = true;
  const store = createFailoverStore({ primary, logger: quietLogger() });
  await store.setChannel('env-webhook', { state: 'ok', nextSendAt: 0 });
  const hook = recording([
    accepted({ status: 200 }),
    retry(null, 'The webhook answered 500.', { status: 500 }),
  ]);
  const { outbox, clock } = outboxOver(store, [hook.channel]);
  const other = { ...entry('nas-fire', 'firing'), orderKey: 'nas\n__availability' };
  state.broken = true;
  // plex's firing is delivered from memory; nas's is asked to retry.
  await outbox.enqueue(entry('fire', 'firing'));
  await outbox.enqueue(other);
  await drain(outbox);
  assert.equal(store.unsaved, 2);
  // Space is back: plex's delivered row is saved as it is; nas's, still retrying, stays.
  state.broken = false;
  assert.equal(await store.probe(), true);
  assert.equal(store.unsaved, 1);
  assert.deepEqual(
    (await inner.list({ limit: 10 })).map(row => [row.eventUid, row.state, row.sentAt !== null]),
    [['fire', 'delivered', true]]
  );
  assert.deepEqual(
    (await store.list({ limit: 10 })).map(row => [row.eventUid, String(row.id).startsWith('m:')]),
    [
      ['nas-fire', true],
      ['fire', false],
    ]
  );
  // A later alert is saved as usual, after the row saved from memory.
  await outbox.enqueue({ ...entry('dns-fire', 'firing'), orderKey: 'dns\n__availability' });
  // nas's retry is delivered; the next pass saves it too, and nothing is unsaved any more.
  await clock.advance(60 * 1000);
  await drain(outbox);
  await store.candidates({ now: clock.wall(), limit: 10 });
  assert.equal(store.unsaved, 0);
  assert.deepEqual(
    (await store.list({ limit: 10 })).map(row => [row.eventUid, row.state]),
    [
      ['nas-fire', 'delivered'],
      ['dns-fire', 'delivered'],
      ['fire', 'delivered'],
    ]
  );
  // Restarted, a store over the same primary has the whole history.
  const again = createFailoverStore({ primary: inner, logger: quietLogger() });
  assert.equal((await again.find(deliveryUid('fire', 'env-webhook'))).state, 'delivered');
});

test('Retry of a failed memory row that is being saved meanwhile answers 0 there, then works on the saved row', async () => {
  // A primary whose inserts fail (`refuse`) or wait for `gate`.
  const inner = createMemoryOutboxStore();
  let gate = null,
    refuse = false;
  const primary = {
    ...inner,
    async insert(rows) {
      if (refuse) throw full();
      if (gate) await gate.promise;
      return inner.insert(rows);
    },
  };
  const store = createFailoverStore({ primary, logger: quietLogger() });
  await store.setChannel('env-webhook', { state: 'ok', nextSendAt: 0 });
  // A row kept in memory (the primary refused it) that then failed.
  refuse = true;
  const [row] = (await store.insert([outboxRow({ eventUid: 'dead-in-memory' })])).inserted;
  refuse = false;
  assert.match(String(row.id), /^m:/);
  await store.claim([row.id], { owner: 'o', epoch: 1, now: 1, leaseUntil: 60001 });
  await store.complete([{ id: row.id, patch: { state: 'dead', deadReason: 'failed' } }], {
    owner: 'o',
    epoch: 1,
  });
  // Saving starts and is slow; Retry comes meanwhile.
  let open;
  gate = { promise: new Promise(resolve => (open = resolve)) };
  const probing = store.probe();
  await settle();
  const retried = store.requeue([row.id], { now: 2, expiresAt: 86400002 });
  await settle();
  open();
  gate = null;
  assert.equal(await probing, true);
  assert.equal(await retried, 0, 'the memory copy is gone: nothing changed there');
  const saved = await store.find(row.uid);
  assert.equal(typeof saved.id, 'number');
  assert.equal(saved.state, 'dead');
  assert.equal(await store.requeue([saved.id], { now: 3, expiresAt: 86400003 }), 1);
  assert.equal((await store.find(row.uid)).state, 'queued');
  assert.equal(store.unsaved, 0);
});

test('a row saved from memory keeps its alert’s order: a newer row of its key waits in memory until it is saved', async () => {
  const { store: primary, inner, state } = breakable();
  state.writesOnly = true;
  const store = createFailoverStore({ primary, logger: quietLogger() });
  await store.setChannel('env-webhook', { state: 'ok', nextSendAt: 0 });
  const hook = recording([failed('The webhook refused the alert (400).', { status: 400 })]);
  const { outbox } = outboxOver(store, [hook.channel]);
  // The disk is full: plex's firing is kept in memory, and refused for good.
  state.broken = true;
  await outbox.enqueue(entry('fire', 'firing'));
  await drain(outbox);
  assert.equal((await store.find(deliveryUid('fire', 'env-webhook'))).state, 'dead');
  // Space comes back, but saving the firing fails once: plex's recovery, which arrives then,
  // waits in memory behind it rather than going to the primary ahead of it.
  state.broken = false;
  state.failing.insert = 1;
  const result = await outbox.enqueue(entry('ok', 'resolved'));
  assert.deepEqual(result.memoryUids, [deliveryUid('ok', 'env-webhook')]);
  await drain(outbox);
  assert.deepEqual(hook.sent, ['firing', 'resolved']);
  // Both are saved, in the alert's order.
  assert.equal(await store.probe(), true);
  assert.equal(store.unsaved, 0);
  assert.deepEqual(
    (await inner.list({ limit: 10 })).map(row => [row.kind, row.state]),
    [
      ['resolved', 'delivered'],
      ['firing', 'dead'],
    ]
  );
  // So Retry on the old firing is refused: it would arrive after the recovery.
  assert.equal((await outbox.retry(deliveryUid('fire', 'env-webhook'))).refused, 'outdated');
  await drain(outbox);
  assert.deepEqual(hook.sent, ['firing', 'resolved']);
});

test('finished memory rows are saved only once no earlier row of their key is in progress', async () => {
  const memory = createMemoryOutboxStore();
  const T0 = 1_800_000_000_000;
  const [first, second, other] = (
    await memory.insert([
      outboxRow({ eventUid: 'k1', orderKey: key, createdAt: T0 }),
      outboxRow({ eventUid: 'k2', orderKey: key, createdAt: T0, state: 'cancelled' }),
      outboxRow({ eventUid: 'o1', orderKey: 'nas\n__availability', state: 'delivered' }),
    ])
  ).inserted;
  assert.deepEqual(
    (await memory.finishedRows()).map(row => row.id),
    [other.id]
  );
  assert.deepEqual(
    await memory.heldKeys([
      { channelId: 'env-webhook', orderKey: key },
      { channelId: 'env-webhook', orderKey: 'dns\n__availability' },
    ]),
    [{ channelId: 'env-webhook', orderKey: key }]
  );
  await memory.claim([first.id], { owner: 'o', epoch: 1, now: T0, leaseUntil: T0 + 60000 });
  await memory.complete([{ id: first.id, patch: { state: 'delivered' } }], {
    owner: 'o',
    epoch: 1,
  });
  assert.deepEqual(
    (await memory.finishedRows()).map(row => row.id),
    [first.id, second.id, other.id]
  );
  assert.equal(await memory.removeFinished([first.id, second.id, other.id]), 3);
  assert.equal(memory.size, 0);
});

test('a digest kept in memory that waits for a row the candidates left out never goes before a saved earlier row of its alert', async () => {
  // plex's firing is saved and waits ten more minutes to retry. A digest kept in memory, tried
  // once and due again, holds nas's alert and plex's recovery (Retry made the firing active again
  // after the digest formed). The failover store leaves the recovery out of the candidates while
  // control.sqlite holds the firing (D23), so the digest is not whole and nothing else can go: a
  // pass then sends a digest whole from the store only when no earlier row of its alerts is
  // active, here read from both sides (memory below the recovery, and the saved rows).
  const clock = fakeClock(),
    now = clock.wall();
  const { store: primary } = breakable();
  const fallback = createMemoryOutboxStore();
  const store = createFailoverStore({ primary, fallback, logger: quietLogger() });
  const mail = (eventUid, service, kind, overrides) =>
    outboxRow({
      eventUid,
      channelId: 'email',
      kind,
      orderKey: `${service}\n__availability`,
      event: { service, kind },
      attempts: 1,
      createdAt: now - 10 * 60000,
      nextAt: now - 1000,
      ...overrides,
    });
  await primary.insert([
    mail('e_plex', 'plex', 'firing', {
      digestKey: digestKeyFor([deliveryUid('e_plex', 'email')]),
      nextAt: now + 10 * 60000,
    }),
  ]);
  const digest = digestKeyFor([deliveryUid('e_nas', 'email'), deliveryUid('e_plex_ok', 'email')]);
  await fallback.insert([
    mail('e_nas', 'nas', 'firing', { digestKey: digest }),
    mail('e_plex_ok', 'plex', 'resolved', { digestKey: digest }),
  ]);
  const sent = [];
  const { outbox } = outboxOver(
    store,
    [
      {
        name: 'email',
        digest: { windowMs: 60000, maxFactor: 3 },
        async send(message) {
          sent.push(message.events.map(event => `${event.service}:${event.kind}`).join());
          return accepted({ status: 250 });
        },
      },
    ],
    clock
  );
  for (let i = 0; i < 9; i++) {
    await clock.advance(60000);
    await outbox.pump();
    await settle();
  }
  assert.deepEqual(sent, [], 'the digest waits for plex’s firing');
  for (let i = 0; i < 3; i++) {
    await clock.advance(60000);
    await outbox.pump();
    await settle();
  }
  assert.deepEqual(sent, ['plex:firing', 'nas:firing,plex:resolved']);
});
