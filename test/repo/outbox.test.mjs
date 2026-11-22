// The control-database OutboxStore (lib/repo/outbox.mjs, delivery spec §4.1): the store
// contract row for row over a migrated control.sqlite, the same random operations as the memory
// store (differential), the per-call bounds, and the failover store over it when control.sqlite
// is full (PRAGMA max_page_count through Db#pragma).
import test from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { openControl, packageRelease } from '../../lib/db/control.mjs';
import { createControlOutboxStore, OUTBOX_UNIT_LIMITS } from '../../lib/repo/outbox.mjs';
import {
  createMemoryOutboxStore,
  createFailoverStore,
  isStorageError,
} from '../../lib/notify/memory-store.mjs';
import { createOutbox, deliveryUid, digestKeyFor } from '../../lib/notify/outbox.mjs';
import { accepted, retry, pause, failed, skipped } from '../../lib/notify/channel.mjs';
import {
  outboxStoreContract,
  outboxRow,
  seededRandom,
  deliveryOrderProperty,
} from '../notify/store-contract.mjs';
import { fakeClock, quietLogger, settle } from '../alerting/fake-clock.mjs';
import { temporary } from './helpers.mjs';

const T0 = 1_800_000_000_000;
const day = 24 * 3600 * 1000;

/** A migrated control.sqlite in a new directory; closed after the test. */
async function openMigrated(t) {
  const control = openControl(temporary(t, 'orbit-outbox-'), {
    release: packageRelease(),
    env: {},
  });
  t.after(() => control.close());
  await control.migrate();
  return control;
}

/** The control database's Db with every read and write unit counted. */
function counting(db) {
  const counts = { read: 0, write: 0 };
  return {
    counts,
    db: {
      dialect: db.dialect,
      read: (fn, options) => {
        counts.read++;
        return db.read(fn, options);
      },
      write: (fn, options) => {
        counts.write++;
        return db.write(fn, options);
      },
    },
  };
}

/**
 * Fills control.sqlite to its page limit (PRAGMA max_page_count through Db#pragma): large rows
 * until one does not fit, then small ones, so the pages are packed and every write that grows a
 * row or adds one fails with class `full`. (A page limit does not cap the WAL, so a write that
 * changes a row in place may still succeed: the test seam is a full database, not a full disk.)
 */
async function fill(control) {
  const pages = control.db.pragma('page_count')[0].page_count;
  control.db.pragma(`max_page_count=${pages}`);
  const store = createControlOutboxStore({ db: control.db });
  for (const [size, label] of [
    [3000, 'big'],
    [300, 'medium'],
    [1, 'small'],
  ])
    for (let n = 0; ; n++) {
      if (n > 10000) assert.fail('control.sqlite never became full');
      const error = await store
        .insert([
          outboxRow({
            eventUid: `filler-${label}-${n}`,
            event: { message: 'x'.repeat(size) },
            state: 'delivered',
          }),
        ])
        .then(
          () => null,
          caught => caught
        );
      if (!error) continue;
      assert.equal(error.class, 'full', String(error));
      break;
    }
}
const unlimited = control => control.db.pragma('max_page_count=1000000000');

outboxStoreContract(test, 'control database', async t =>
  createControlOutboxStore({ db: (await openMigrated(t)).db })
);

test('rows and channel status survive the store (a restart): another store reads them back', async t => {
  const control = await openMigrated(t);
  const first = createControlOutboxStore({ db: control.db, clock: () => T0 + 7 });
  const row = outboxRow({
    eventUid: 'e_survives',
    orderKey: 'plex\n__availability',
    severity: null,
    event: { service: 'plex', name: 'Plex', nested: { list: [1, 'two', null] } },
  });
  const { inserted } = await first.insert([row]);
  await first.setChannel('env-webhook', {
    state: 'paused',
    pausedReason: 'The receiver answered 404.',
    pausedSince: T0 - 5,
    consecutiveRefusals: 2,
    lastError: { time: T0, message: 'Not found' },
    nextSendAt: T0 + 900000,
  });
  const second = createControlOutboxStore({ db: control.db });
  assert.deepEqual(await second.find(row.uid), inserted[0]);
  assert.deepEqual(await second.channel('env-webhook'), {
    state: 'paused',
    pausedReason: 'The receiver answered 404.',
    nextSendAt: T0 + 900000,
    consecutiveFailures: 0,
    failedTotal: 0,
    deliveredTotal: 0,
    lastAttempt: null,
    lastSuccess: null,
    lastFailure: null,
    lastError: { time: T0, message: 'Not found' },
    pausedSince: T0 - 5,
    consecutiveRefusals: 2,
  });
  assert.deepEqual(await second.channelIds(), ['env-webhook']);
  // A status written again replaces it; fields left out take the column defaults.
  await second.setChannel('env-webhook', { state: 'ok', lastError: null });
  assert.deepEqual(
    [
      (await first.channel('env-webhook')).state,
      (await first.channel('env-webhook')).pausedSince,
      (await first.channel('env-webhook')).consecutiveRefusals,
    ],
    ['ok', null, 0]
  );
});

test('a duplicate within one insert, fractional times rounded up, and refused patches', async t => {
  const control = await openMigrated(t);
  const store = createControlOutboxStore({ db: control.db });
  const row = outboxRow({ eventUid: 'twice' });
  const result = await store.insert([row, { ...row, kind: 'resolved' }]);
  assert.equal(result.inserted.length, 1);
  assert.deepEqual(result.duplicates, [row.uid]);
  // Retry backoff times carry a random factor; an INTEGER column takes them rounded up.
  const [claimed] = await store.claim([result.inserted[0].id], {
    owner: 'o_a',
    epoch: 1,
    now: T0,
    leaseUntil: T0 + 60000.2,
  });
  assert.equal(claimed.leaseUntil, T0 + 60001);
  assert.equal(
    await store.complete([{ id: claimed.id, patch: { state: 'queued', nextAt: T0 + 31234.5 } }], {
      owner: 'o_a',
      epoch: 1,
    }),
    1
  );
  assert.equal((await store.find(row.uid)).nextAt, T0 + 31235);
  // A completion never changes a row's identity, and names only real fields.
  // Inherited names are no fields either: each is the documented TypeError, never reaching id().
  for (const patch of [
    { uid: 'd_other' },
    { channelId: 'email' },
    { nonsense: 1 },
    ...['constructor', 'toString', 'hasOwnProperty', '__proto__', 'valueOf'].map(field =>
      JSON.parse(`{"${field}": "x"}`)
    ),
  ])
    await assert.rejects(
      store.complete([{ id: claimed.id, patch }], { owner: 'o_a', epoch: 1 }),
      error => error instanceof TypeError && /An outbox completion cannot set/.test(error.message),
      JSON.stringify(Object.keys(patch))
    );
  await assert.rejects(store.insert([{ ...row, uid: '' }]), TypeError);
  await assert.rejects(store.candidates({}), TypeError);
  await assert.rejects(store.list({ beforeId: 'x' }), TypeError);
});

test('each call does a bounded amount of work per unit; an idle expire() writes nothing', async t => {
  const control = await openMigrated(t);
  const { db, counts } = counting(control.db);
  const store = createControlOutboxStore({ db });
  const reset = () => Object.assign(counts, { read: 0, write: 0 });
  // 450 rows: three insert units (200, 200, 50).
  const { inserted } = await store.insert(
    Array.from({ length: 450 }, (_, n) =>
      outboxRow({ eventUid: `bound-${n}`, expiresAt: T0 + (n < 260 ? 10 : day) })
    )
  );
  assert.equal(inserted.length, 450);
  assert.equal(counts.write, 3);
  // Nothing to expire: one indexed read, no write unit (delivery spec D21).
  reset();
  assert.equal(await store.expire(T0), 0);
  assert.deepEqual(counts, { read: 1, write: 0 });
  // 260 rows to expire: units of at most 500 rows, repeated until a unit changes fewer.
  reset();
  assert.equal(await store.expire(T0 + 10), 260);
  assert.deepEqual(counts, { read: 1, write: 1 });
  // Bulk changes repeat units of 500.
  reset();
  assert.equal(await store.hold('env-webhook', T0 + 20), 190);
  assert.equal(counts.write, 1);
  const more = await store.insert(
    Array.from({ length: 1100 }, (_, n) => outboxRow({ eventUid: `more-${n}` }))
  );
  reset();
  assert.equal(await store.hold('env-webhook', T0 + 30), 1100);
  assert.equal(counts.write, 3, '500 + 500 + 100');
  // Claims, completions and unclaims: 100 ids per unit.
  const some = more.inserted.slice(0, 250).map(row => row.id);
  await store.release('env-webhook', T0 + 40);
  reset();
  const lease = { owner: 'o_a', epoch: 1, now: T0 + 40, leaseUntil: T0 + 99999 };
  assert.equal((await store.claim(some, lease)).length, 250);
  assert.equal(counts.write, 3);
  reset();
  assert.equal(await store.unclaim(some, { owner: 'o_a', epoch: 1, now: T0 + 41 }), 250);
  assert.equal(counts.write, 3);
  await store.claim(some, lease);
  reset();
  assert.equal(
    await store.complete(
      some.map(rowId => ({ id: rowId, patch: { state: 'delivered' } })),
      { owner: 'o_a', epoch: 1 }
    ),
    250
  );
  assert.equal(counts.write, 3);
  // Reads are bounded too: candidates ≤ 200, list ≤ 100, activeKeys 200 keys per read unit.
  assert.equal((await store.candidates({ now: T0 + 50, limit: 5000 })).length, 200);
  assert.equal((await store.list({ limit: 5000 })).length, 100);
  reset();
  const keys = Array.from({ length: 450 }, (_, n) => ({ channelId: 'email', orderKey: `k${n}` }));
  assert.deepEqual(await store.activeKeys(keys), []);
  assert.deepEqual(counts, { read: 3, write: 0 });
  // prune: at most 1000 rows per call, whatever the caller asks.
  const rules = {
    now: T0 + 100 * day,
    finished: { maxAgeMs: day, maxRows: 50000 },
    dead: { maxAgeMs: day, maxRows: 5000 },
  };
  assert.equal(await store.prune({ ...rules, limit: 5000 }), 510);
  assert.ok(Object.isFrozen(OUTBOX_UNIT_LIMITS));
});

test("a batch read by state (the worker's whole-batch check) searches an index by state, never the whole table", async t => {
  const directory = temporary(t, 'orbit-outbox-');
  const control = openControl(directory, { release: packageRelease(), env: {} });
  t.after(() => control.close());
  await control.migrate();
  // The statements the store reads with, rendered as SQLite runs them.
  const statements = [];
  const watch = tx =>
    new Proxy(tx, {
      get(target, name) {
        if (name === 'all')
          return query => {
            statements.push(control.db.dialect.render(query));
            return target.all(query);
          };
        const value = target[name];
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
  const store = createControlOutboxStore({
    db: {
      dialect: control.db.dialect,
      write: (fn, options) => control.db.write(fn, options),
      read: (fn, options) => control.db.read(tx => fn(watch(tx)), options),
    },
  });
  await store.batch('g_x', { states: ['queued', 'sending', 'held'] });
  const [{ text, params }] = statements;
  const raw = new DatabaseSync(path.join(directory, 'control.sqlite'), { readOnly: true });
  t.after(() => raw.close());
  const plan = raw
    .prepare(`EXPLAIN QUERY PLAN ${text}`)
    .all(...params)
    .map(step => step.detail);
  assert.ok(
    plan.some(step =>
      /^SEARCH alerting_outbox USING INDEX alerting_outbox_\w+ \(state=\?\)/.test(step)
    ),
    plan.join('; ')
  );
  assert.ok(!plan.some(step => /^SCAN alerting_outbox\b/.test(step)), plan.join('; '));
});

test('store errors keep their class: a full control.sqlite is a storage error, a refused value is not', async t => {
  const control = await openMigrated(t);
  const store = createControlOutboxStore({ db: control.db });
  await fill(control);
  const error = await store
    .insert([outboxRow({ eventUid: 'no-room', event: { message: 'y'.repeat(3000) } })])
    .then(
      () => null,
      caught => caught
    );
  assert.ok(error, 'the insert failed');
  assert.equal(error.class, 'full');
  assert.equal(isStorageError(error), true);
  // Reads still work on a full database.
  assert.ok((await store.countActive()) >= 0);
  unlimited(control);
  await store.insert([outboxRow({ eventUid: 'room-again', event: { message: 'y'.repeat(3000) } })]);
  // A row the table refuses (a key too long for its column) is poison, not storage.
  const poison = await store.insert([outboxRow({ eventUid: 'e'.repeat(200) })]).catch(c => c);
  assert.equal(poison.class, 'poison');
  assert.equal(isStorageError(poison), false);
});

test('candidates, list, summary and the rest match the memory store over random operations (differential)', async t => {
  const control = await openMigrated(t);
  const stores = {
    memory: createMemoryOutboxStore(),
    control: createControlOutboxStore({ db: control.db }),
  };
  const { random, pick, int } = seededRandom(20261002);
  const channels = ['env-webhook', 'email', 'teams'],
    keys = ['plex\n__availability', 'plex\ncpu', 'nas\n__availability', 'nas2\nx', null],
    kinds = ['firing', 'resolved', 'reminder'];
  let now = T0,
    events = 0,
    epoch = 1;
  const uidsOf = rows => rows.map(row => row.uid);
  // Ids are compared by row: both stores number new rows the same way, but compare by uid anyway.
  const idMaps = { memory: new Map(), control: new Map() };
  const bothIds = uids => ({
    memory: uids.map(uid => idMaps.memory.get(uid)).filter(Boolean),
    control: uids.map(uid => idMaps.control.get(uid)).filter(Boolean),
  });
  const known = [];
  const operations = {
    async insert() {
      const rows = Array.from({ length: int(1, 4) }, () =>
        outboxRow({
          eventUid: `d-${++events}`,
          channelId: pick(channels),
          orderKey: pick(keys),
          kind: pick(kinds),
          createdAt: now - int(0, 5000),
          nextAt: now + (random() < 0.7 ? 0 : int(1, 60) * 1000),
          expiresAt: now + int(1, 120) * 60000,
          state: random() < 0.1 ? 'held' : 'queued',
        })
      );
      if (random() < 0.2 && known.length) rows.push(outboxRow({ eventUid: pick(known) }));
      for (const [name, store] of Object.entries(stores)) {
        const result = await store.insert(structuredClone(rows));
        for (const row of result.inserted) idMaps[name].set(row.uid, row.id);
      }
      known.push(...rows.map(row => row.eventUid));
    },
    async claim() {
      const found = await stores.memory.candidates({ now, limit: 50 });
      const chosen = found.filter(() => random() < 0.5).map(row => row.uid);
      const ids = bothIds(chosen);
      const lease = {
        owner: 'o_d',
        epoch,
        now,
        leaseUntil: now + int(1, 90) * 1000,
        digestKey: random() < 0.3 ? 'g_d' : null,
      };
      const a = await stores.memory.claim(ids.memory, lease),
        b = await stores.control.claim(ids.control, lease);
      assert.deepEqual(uidsOf(b), uidsOf(a));
    },
    async complete() {
      const sending = await stores.memory.sending();
      if (!sending.length) return;
      const row = pick(sending);
      const patch = pick([
        { state: 'delivered', sentAt: now, leaseOwner: null, leaseUntil: null, updatedAt: now },
        {
          state: 'queued',
          nextAt: now + int(1, 30) * 1000,
          leaseOwner: null,
          leaseUntil: null,
          lastError: 'retry',
        },
        {
          state: 'dead',
          deadReason: 'failed',
          lastError: 'refused',
          lastStatus: 410,
          updatedAt: now,
        },
        { state: 'held', nextAt: now, leaseOwner: null, updatedAt: now },
      ]);
      const lease = { owner: row.leaseOwner, epoch: random() < 0.9 ? row.epoch : row.epoch + 1 };
      const ids = bothIds([row.uid]);
      assert.equal(
        await stores.control.complete([{ id: ids.control[0], patch }], lease),
        await stores.memory.complete([{ id: ids.memory[0], patch }], lease)
      );
    },
    async unclaim() {
      const sending = await stores.memory.sending();
      if (!sending.length) return;
      const row = pick(sending),
        ids = bothIds([row.uid]),
        lease = { owner: row.leaseOwner, epoch: row.epoch, now };
      assert.equal(
        await stores.control.unclaim(ids.control, lease),
        await stores.memory.unclaim(ids.memory, lease)
      );
    },
    async channel() {
      const status = pick([
        { state: 'ok', nextSendAt: 0 },
        { state: 'paused', nextSendAt: 0, pausedReason: 'Paused.' },
        { state: 'circuit-open', nextSendAt: now + int(1, 60) * 1000 },
        { state: 'retrying', nextSendAt: now - 1 },
      ]);
      const channelId = pick(channels);
      for (const store of Object.values(stores)) await store.setChannel(channelId, status);
    },
    async bulk() {
      const channelId = pick(channels),
        key = pick(keys);
      const action = pick([
        'hold',
        'release',
        'expire',
        'supersede',
        'cancel',
        'requeue',
        'shift',
        'clamp',
      ]);
      // Drawn once, so both stores get the same call.
      const reason = random() < 0.5 ? 'replaced' : undefined,
        createdBefore = random() < 0.5 ? now - 2000 : undefined,
        expiresAt = random() < 0.5 ? now + day : undefined,
        by = int(1, 5) * 60000;
      const run = async (name, store) => {
        switch (action) {
          case 'hold':
            return store.hold(channelId, now);
          case 'release':
            return store.release(channelId, now);
          case 'expire':
            return store.expire(now);
          case 'supersede':
            return store.supersede({
              channelId,
              orderKey: key,
              kinds: ['reminder', 'firing'],
              now,
              reason,
              createdBefore,
            });
          case 'cancel':
            return store.cancel({
              orderKeyPrefix: key ? key.split('\n')[0] + '\n' : 'nas\n',
              now,
              reason: 'deleted',
            });
          case 'requeue': {
            const ids = bothIds(known.slice(-10).map(uid => outboxRow({ eventUid: uid }).uid));
            return store.requeue(ids[name], { now, expiresAt });
          }
          case 'shift':
            return store.shiftExpiry({ by, now });
          default:
            return store.clampTimes({
              now,
              nextAtMax: now + 900000,
              expiresAtMax: now + 3600000,
              leaseUntilMax: now + 60000,
            });
        }
      };
      assert.equal(
        await run('control', stores.control),
        await run('memory', stores.memory),
        action
      );
    },
    async advance() {
      now += int(1, 40) * 1000;
      if (random() < 0.05) epoch++;
    },
  };
  const weights = [
    'insert',
    'insert',
    'insert',
    'claim',
    'claim',
    'complete',
    'complete',
    'unclaim',
    'channel',
    'bulk',
    'bulk',
    'advance',
    'advance',
  ];
  const strip = row => ({ ...row, id: undefined });
  for (let step = 0; step < 2000; step++) {
    const name = pick(weights);
    await operations[name]();
    const options = {
      now,
      limit: int(1, 60),
      ...(random() < 0.3 ? { channels: [pick(channels)] } : {}),
    };
    const [a, b] = [
      await stores.memory.candidates(options),
      await stores.control.candidates(options),
    ];
    assert.deepEqual(b.map(strip), a.map(strip), `candidates after step ${step} (${name})`);
    if (step % 25 === 0) {
      const listOptions = {
        limit: 100,
        ...(random() < 0.5 ? { states: ['queued', 'held', 'dead'] } : {}),
      };
      assert.deepEqual(
        (await stores.control.list(listOptions)).map(strip),
        (await stores.memory.list(listOptions)).map(strip),
        `list after step ${step}`
      );
      const failedSince = { 'env-webhook': now - 60000 };
      assert.deepEqual(
        await stores.control.summary({ failedSince }),
        await stores.memory.summary({ failedSince })
      );
      assert.equal(await stores.control.countActive(), await stores.memory.countActive());
      assert.equal(await stores.control.nextDueAt(now), await stores.memory.nextDueAt(now));
      const someKeys = channels.flatMap(channelId =>
        keys.map(orderKey => ({ channelId, orderKey }))
      );
      assert.deepEqual(
        await stores.control.activeKeys(someKeys),
        await stores.memory.activeKeys(someKeys)
      );
      const counts = [await stores.control.counts(), await stores.memory.counts()];
      assert.deepEqual(counts[0], counts[1]);
    }
  }
  assert.ok(events > 500, `${events} rows were written`);
});

test('the outbox delivers through the control store, and its state outlives the outbox', async t => {
  const control = await openMigrated(t);
  const store = createControlOutboxStore({ db: control.db });
  const clock = fakeClock();
  const answers = [
    retry(null, 'The receiver answered 503.', { status: 503 }),
    accepted({ status: 200 }),
  ];
  const sent = [];
  const outbox = createOutbox({
    store,
    clock,
    logger: quietLogger(),
    // A random factor that makes the backoff fractional, as in production.
    rng: () => 0.731,
    owner: 'o_test',
    channels: [
      {
        name: 'env-webhook',
        async send(message) {
          sent.push(message.uid);
          return answers.shift() ?? accepted({ status: 200 });
        },
      },
    ],
  });
  t.after(() => outbox.stop({ timeoutMs: 0 }));
  const entry = (eventUid, kind) => ({
    eventUid,
    channelId: 'env-webhook',
    kind,
    orderKey: 'plex\n__availability',
    event: { service: 'plex', kind, message: 'Source is unavailable' },
  });
  assert.equal(
    (await outbox.enqueue([entry('e_f', 'firing'), entry('e_r', 'resolved')])).inserted,
    2
  );
  await outbox.pump();
  await clock.advance(0);
  // The firing failed once; the recovery waits behind it.
  const [firing, recovery] = (await store.list({ limit: 10 })).reverse();
  assert.deepEqual(
    [firing.state, firing.attempts, recovery.state, recovery.attempts],
    ['queued', 1, 'queued', 0]
  );
  assert.ok(Number.isInteger(firing.nextAt) && firing.nextAt > clock.wall());
  assert.equal((await store.channel('env-webhook')).state, 'retrying');
  await clock.advance(60000);
  await outbox.flush({ ignoreWindows: true, timeoutMs: 1000 });
  await clock.advance(0);
  await outbox.flush({ ignoreWindows: true, timeoutMs: 1000 });
  assert.equal(sent.length, 3);
  assert.deepEqual(sent.slice(1), [firing.uid, recovery.uid]);
  // Another store over the same database (a restart) sees the outcome and the channel's health.
  const again = createControlOutboxStore({ db: control.db });
  assert.deepEqual(
    (await again.list({ limit: 10 })).map(row => [row.kind, row.state]),
    [
      ['resolved', 'delivered'],
      ['firing', 'delivered'],
    ]
  );
  const health = await again.channel('env-webhook');
  assert.deepEqual([health.state, health.deliveredTotal, health.failedTotal], ['ok', 2, 1]);
});

test('A58: a row skipped just before a send keeps the attempts it had in control.sqlite', async t => {
  const control = await openMigrated(t);
  const store = createControlOutboxStore({ db: control.db });
  const clock = fakeClock();
  const answers = [retry(null, 'The receiver answered 500.', { status: 500 })];
  const skip = new Set();
  const outbox = createOutbox({
    store,
    clock,
    logger: quietLogger(),
    rng: () => 1,
    owner: 'o_test',
    recheck: row => (skip.has(row.eventUid) ? 'Not sent: the source was deleted.' : null),
    channels: [
      {
        name: 'env-webhook',
        async send(message) {
          if (message.events[0].service === 'unset')
            return skipped('GOBLIN_WEBHOOK_URL is not set.');
          return answers.shift() ?? accepted({ status: 200 });
        },
      },
    ],
  });
  t.after(() => outbox.stop({ timeoutMs: 0 }));
  const entry = (eventUid, service) => ({
    eventUid,
    channelId: 'env-webhook',
    kind: 'firing',
    orderKey: `${service}\n__availability`,
    event: { service, kind: 'firing', message: 'Source is unavailable' },
  });
  await outbox.enqueue([entry('e_tried', 'plex'), entry('e_unset', 'unset')]);
  await outbox.flush({ timeoutMs: 1000 });
  await clock.advance(0);
  await outbox.enqueue(entry('e_waiting', 'nas'));
  for (const uid of ['e_tried', 'e_waiting']) skip.add(uid);
  await clock.advance(3600 * 1000);
  await outbox.flush({ timeoutMs: 1000 });
  await clock.advance(0);
  // Read back by another store (a restart): what control.sqlite holds.
  const again = createControlOutboxStore({ db: control.db });
  assert.deepEqual(
    (await again.list({ limit: 10 })).map(row => [row.eventUid, row.state, row.attempts]),
    [
      ['e_waiting', 'skipped', 0],
      ['e_unset', 'skipped', 0],
      ['e_tried', 'skipped', 1],
    ]
  );
});

// --- The failover store over the control adapter (the degraded path, D15) ------------------

test('with control.sqlite full, new rows are kept in memory and still delivered; then saved again', async t => {
  const control = await openMigrated(t);
  const changes = [];
  const failover = createFailoverStore({
    primary: createControlOutboxStore({ db: control.db }),
    logger: quietLogger(),
    onChange: value => changes.push(value),
  });
  await fill(control);
  const { inserted } = await failover.insert([
    outboxRow({ eventUid: 'kept', event: { message: 'z'.repeat(3000) } }),
  ]);
  assert.match(String(inserted[0].id), /^m:\d+$/);
  assert.equal(failover.degraded, true);
  assert.equal(changes[0], true);
  const [candidate] = await failover.candidates({ now: T0, limit: 10 });
  assert.equal(candidate.eventUid, 'kept');
  const [claimed] = await failover.claim([candidate.id], {
    owner: 'o_a',
    epoch: 1,
    now: T0,
    leaseUntil: T0 + 60000,
  });
  assert.equal(
    await failover.complete([{ id: claimed.id, patch: { state: 'delivered', sentAt: T0 } }], {
      owner: 'o_a',
      epoch: 1,
    }),
    1
  );
  unlimited(control);
  const saved = await failover.insert([outboxRow({ eventUid: 'saved-again' })]);
  assert.equal(typeof saved.inserted[0].id, 'number');
  assert.equal(failover.degraded, false);
});

// The failover store's own changes in the delivery milestone (deferred completions, probe(),
// order across stores, read errors that propagate) are lane D's (delivery spec §5.2). These run
// over the control adapter once that failover store is in the tree.
const laneD =
  typeof createFailoverStore({ primary: createMemoryOutboxStore() }).probe === 'function';
const needsLaneD = laneD ? {} : { skip: "needs the delivery milestone's failover store (lane D)" };

test(
  'failover over control: a completion control.sqlite cannot record is deferred, never resent, and applied once space returns',
  needsLaneD,
  async t => {
    const control = await openMigrated(t);
    const primary = createControlOutboxStore({ db: control.db });
    const failover = createFailoverStore({ primary, logger: quietLogger() });
    // A channel status for probe() to write back.
    await failover.setChannel('env-webhook', { state: 'ok', nextSendAt: 0 });
    const [row] = (await failover.insert([outboxRow({ eventUid: 'deferred' })])).inserted;
    const lease = { owner: 'o_a', epoch: 1, now: T0, leaseUntil: T0 + 60000 };
    await failover.claim([row.id], lease);
    await fill(control);
    // An outcome that grows the row (its error text) needs a page the database cannot have.
    const patch = {
      state: 'dead',
      deadReason: 'failed',
      lastError: 'r'.repeat(300),
      externalRef: 'x'.repeat(200),
      leaseOwner: null,
      leaseUntil: null,
    };
    assert.equal(await failover.complete([{ id: row.id, patch }], { owner: 'o_a', epoch: 1 }), 1);
    assert.equal(failover.degraded, true);
    // Neither recover() (through sending()) nor the worker (candidates()) sees it again.
    assert.deepEqual(
      (await failover.sending()).map(r => r.uid),
      []
    );
    assert.deepEqual(await failover.candidates({ now: T0 + 120000, limit: 10 }), []);
    unlimited(control);
    assert.equal(await failover.probe(), true);
    assert.equal(failover.degraded, false);
    const stored = await primary.find(row.uid);
    assert.deepEqual(
      [stored.state, stored.lastError, stored.leaseOwner],
      ['dead', 'r'.repeat(300), null]
    );
  }
);

test(
  'failover over control: a completion failing with class retry once is deferred, never resent',
  needsLaneD,
  async t => {
    const control = await openMigrated(t);
    const inner = createControlOutboxStore({ db: control.db });
    let busy = 1;
    const primary = {
      ...inner,
      async complete(...args) {
        if (busy-- > 0) throw Object.assign(new Error('database is locked'), { class: 'retry' });
        return inner.complete(...args);
      },
    };
    const failover = createFailoverStore({ primary, logger: quietLogger() });
    const [row] = (await failover.insert([outboxRow({ eventUid: 'busy' })])).inserted;
    await failover.claim([row.id], { owner: 'o_a', epoch: 1, now: T0, leaseUntil: T0 + 60000 });
    const patch = { state: 'delivered', sentAt: T0, leaseOwner: null, leaseUntil: null };
    assert.equal(await failover.complete([{ id: row.id, patch }], { owner: 'o_a', epoch: 1 }), 1);
    assert.equal(failover.degraded, false, 'busy is not a storage error');
    assert.deepEqual(await failover.sending(), []);
    // The next primary operation applies it.
    await failover.insert([outboxRow({ eventUid: 'next' })]);
    assert.equal((await inner.find(row.uid)).state, 'delivered');
  }
);

test(
  'failover over control: re-enqueueing a row control.sqlite already holds adds nothing to memory',
  needsLaneD,
  async t => {
    const control = await openMigrated(t);
    const failover = createFailoverStore({
      primary: createControlOutboxStore({ db: control.db }),
      logger: quietLogger(),
    });
    const row = outboxRow({ eventUid: 'held-already', event: { message: 'w'.repeat(3000) } });
    await failover.insert([row]);
    await fill(control);
    const again = await failover.insert([row]);
    assert.deepEqual(again.inserted, []);
    assert.equal(
      (await failover.list({ limit: 100 })).filter(item => item.uid === row.uid).length,
      1
    );
    assert.equal((await failover.summary({ failedSince: {} }))['env-webhook'].waiting, 1);
  }
);

test(
  'failover over control: a primary read error makes summary() and list() reject',
  needsLaneD,
  async t => {
    const control = await openMigrated(t);
    const inner = createControlOutboxStore({ db: control.db });
    const unavailable = () => Object.assign(new Error('disk I/O error'), { class: 'unavailable' });
    const primary = {
      ...inner,
      summary: async () => {
        throw unavailable();
      },
      list: async () => {
        throw unavailable();
      },
    };
    const failover = createFailoverStore({ primary, logger: quietLogger() });
    await assert.rejects(failover.summary({ failedSince: {} }), { class: 'unavailable' });
    await assert.rejects(failover.list({ limit: 10 }), { class: 'unavailable' });
  }
);

test(
  'failover over control: the delivery order property holds while control.sqlite fills and frees',
  needsLaneD,
  async t => {
    const control = await openMigrated(t);
    const failover = createFailoverStore({
      primary: createControlOutboxStore({ db: control.db }),
      logger: quietLogger(),
    });
    await deliveryOrderProperty(failover, {
      seed: 7,
      steps: 200,
      between: async step => {
        if (step === 50) await fill(control);
        if (step === 130) unlimited(control);
      },
    });
  }
);

test(
  'failover over control: held rows are never stranded by a resume or a probe that control.sqlite refuses, or by a restart between them',
  needsLaneD,
  async t => {
    // control.sqlite as T8's double failure leaves it: reads work, every write unit fails.
    for (const how of ['resume', 'probe', 'restart']) {
      const control = await openMigrated(t);
      let refusing = false;
      const fullError = () =>
        Object.assign(new Error('database or disk is full'), {
          class: 'full',
          code: 'ERR_SQLITE_ERROR',
          errcode: 13,
        });
      const db = {
        dialect: control.db.dialect,
        read: (fn, options) => control.db.read(fn, options),
        write: (fn, options) =>
          refusing ? Promise.reject(fullError()) : control.db.write(fn, options),
      };
      const clock = fakeClock();
      let answer = 404;
      const sent = [];
      const channel = {
        name: 'env-webhook',
        async send(message) {
          sent.push(message.events[0].rule);
          return answer === 404
            ? pause('The webhook answered 404.', { status: 404, transient: true })
            : accepted({ status: 200 });
        },
      };
      const start = () => {
        const store = createFailoverStore({
          primary: createControlOutboxStore({ db, clock: () => clock.wall() }),
          logger: quietLogger(),
          now: () => clock.wall(),
        });
        const logger = quietLogger();
        const outbox = createOutbox({ store, channels: [channel], clock, logger, rng: () => 0 });
        t.after(() => outbox.stop({ timeoutMs: 0 }));
        return { store, outbox, logger };
      };
      let { store, outbox, logger } = start();
      const pass = async () => {
        await outbox.pump();
        await settle();
      };
      const entry = (uid, rule) => ({
        eventUid: uid,
        channelId: 'env-webhook',
        kind: 'firing',
        orderKey: `nas\n${rule}`,
        event: { service: 'nas', kind: 'firing', rule },
      });
      const rows = async () =>
        (await store.list({ limit: 10 })).map(row => `${row.event.rule}:${row.state}`).reverse();
      await outbox.enqueue(entry('e_1', 'cpu'));
      await pass();
      await outbox.enqueue(entry('e_2', 'disk'));
      await pass();
      assert.deepEqual(await rows(), ['cpu:held', 'disk:held'], how);
      answer = 200;
      if (how === 'restart') {
        // A resume whose release could not be written, then a restart once space is back: the
        // stored status says the channel works, and its rows are still held.
        await createControlOutboxStore({ db: control.db }).setChannel('env-webhook', {
          ...(await store.channel('env-webhook')),
          state: 'ok',
          pausedReason: null,
          pausedSince: null,
          nextSendAt: 0,
        });
        await outbox.stop({ timeoutMs: 0 });
        ({ store, outbox, logger } = start());
      } else {
        refusing = true;
        if (how === 'resume') {
          assert.equal(await outbox.resume('env-webhook'), 0, how);
          assert.equal((await store.channel('env-webhook')).state, 'ok', 'the resume stands');
        } else {
          await clock.advance(15 * 60 * 1000 + 1000);
          await pass();
          const health = await store.channel('env-webhook');
          assert.equal(health.state, 'paused', 'a probe that could not release stays due');
          assert.ok(health.nextSendAt <= clock.wall(), how);
        }
        for (let i = 0; i < 6; i++) {
          await clock.advance(10 * 60 * 1000);
          await pass();
        }
        assert.deepEqual(await rows(), ['cpu:held', 'disk:held'], how);
        assert.deepEqual(sent, ['cpu'], how);
        refusing = false;
        // The service's probe (every 10 s while not saving) writes the status kept in memory.
        assert.equal(await store.probe(), true, how);
      }
      for (let i = 0; i < 3; i++) await pass();
      assert.deepEqual(await rows(), ['cpu:delivered', 'disk:delivered'], how);
      assert.deepEqual(sent, ['cpu', 'cpu', 'disk'], how);
      assert.equal((await store.channel('env-webhook')).state, 'ok', how);
      if (how !== 'restart')
        assert.match(logger.lines.error.join('\n'), /Held notifications could not be released yet/);
    }
  }
);

/**
 * The failover store over this control.sqlite as T8's double failure leaves it while `state.
 * refusing` is true: reads work and every write unit fails as a full disk makes it fail.
 */
function refusingControl(control, clock) {
  const state = { refusing: false };
  const fullError = () =>
    Object.assign(new Error('database or disk is full'), {
      class: 'full',
      code: 'ERR_SQLITE_ERROR',
      errcode: 13,
    });
  const db = {
    dialect: control.db.dialect,
    read: (fn, options) => control.db.read(fn, options),
    write: (fn, options) =>
      state.refusing ? Promise.reject(fullError()) : control.db.write(fn, options),
  };
  const primary = createControlOutboxStore({ db, clock: () => clock.wall() });
  const store = createFailoverStore({ primary, logger: quietLogger(), now: () => clock.wall() });
  return { state, primary, store };
}

test(
  'failover over control: an email digest across control.sqlite and memory goes out whole or waits, and a recovery never overtakes its alert',
  needsLaneD,
  async t => {
    // An email-like digest channel; each message's content is "service:kind", sorted.
    const contentOf = message =>
      message.events
        .map(event => `${event.service}:${event.kind}`)
        .sort()
        .join();
    const mail = (uid, service, kind = 'firing') => ({
      eventUid: uid,
      channelId: 'email',
      kind,
      orderKey: `${service}\n__availability`,
      event: { service, kind },
    });
    for (const how of ['resume', 'retry']) {
      const control = await openMigrated(t);
      const clock = fakeClock();
      const { state, store } = refusingControl(control, clock);
      const sent = [],
        answers =
          how === 'resume'
            ? [pause('The mail server refused the sign-in (535).', { status: 535 })]
            : [
                retry(null, 'The mail server asked Uptime Goblin to try later (451).', {
                  status: 451,
                }),
              ];
      const email = {
        name: 'email',
        digest: { windowMs: 60000, maxFactor: 3 },
        async send(message) {
          sent.push(message);
          return answers.length ? answers.shift() : accepted({ status: 250 });
        },
      };
      const outbox = createOutbox({
        store,
        channels: [email],
        clock,
        logger: quietLogger(),
        rng: () => 1,
      });
      t.after(() => outbox.stop({ timeoutMs: 0 }));
      const passes = async (count, ms) => {
        for (let i = 0; i < count; i++) {
          await clock.advance(ms);
          await outbox.pump();
          await settle();
        }
      };
      // control.sqlite is full when Plex fails, so its alert is kept in memory (D15); space is
      // back when Sonarr fails, so that one is saved. Both wait in one quiet window: one digest.
      state.refusing = true;
      await outbox.enqueue(mail('e_plex', 'plex'));
      state.refusing = false;
      await clock.advance(5000);
      await outbox.enqueue(mail('e_sonarr', 'sonarr'));
      await passes(1, 61000);
      assert.deepEqual(sent.map(contentOf), ['plex:firing,sonarr:firing'], how);
      if (how === 'resume') {
        // The sign-in failed: email is paused and both rows are held. Plex recovers; its row
        // goes to memory behind its alert (D23). The disk fills again, and the admin saves a new app
        // password: the rows kept in memory are released, control.sqlite's cannot be (A20).
        await clock.advance(30000);
        const late = await outbox.enqueue(mail('e_plex_ok', 'plex', 'resolved'));
        assert.equal(late.memoryUids.length, 1, how);
        state.refusing = true;
        await outbox.channelChanged('email');
        await passes(4, 61000);
        // Before, Plex's recovery went out alone, first.
        assert.equal(sent.length, 1, `${how}: nothing goes while the digest waits for its half`);
        state.refusing = false;
        // The service probes every 10 s while not saving: the resume is saved, Sonarr released.
        assert.equal(await store.probe(), true, how);
        await passes(4, 61000);
        assert.deepEqual(
          sent.map(contentOf),
          ['plex:firing,sonarr:firing', 'plex:firing,sonarr:firing', 'plex:resolved'],
          how
        );
      } else {
        // The mail server asked to try later. The disk fills before the retry: the claim gets the
        // row kept in memory and not control.sqlite's. Before, Plex's alert went out alone under
        // the digest's Message-ID, and Sonarr's later under the same Message-ID.
        state.refusing = true;
        await passes(3, 60000);
        assert.equal(sent.length, 1, `${how}: no part of the digest goes alone`);
        state.refusing = false;
        await passes(3, 60000);
        assert.deepEqual(
          sent.map(contentOf),
          ['plex:firing,sonarr:firing', 'plex:firing,sonarr:firing'],
          how
        );
        // A claim given back does not count as an attempt.
        const rows = await store.list({ channelId: 'email', limit: 10 });
        assert.deepEqual(
          rows.map(row => [row.state, row.attempts]),
          [
            ['delivered', 2],
            ['delivered', 2],
          ],
          how
        );
      }
      assert.equal(sent[1].uid, sent[0].uid, `${how}: the retried digest keeps its Message-ID`);
      // One content per Message-ID.
      const byId = new Map();
      for (const message of sent)
        byId.set(message.uid, new Set([...(byId.get(message.uid) ?? []), contentOf(message)]));
      for (const [uid, contents] of byId)
        assert.equal(contents.size, 1, `${how}: ${uid} carried ${[...contents].join(' and ')}`);
    }
  }
);

test(
  'failover over control: after the clock steps back, a row kept in memory still comes after its alert’s saved rows (Retry, and a digest across the two stores)',
  needsLaneD,
  async t => {
    const hour = 3600 * 1000,
      minute = 60 * 1000;
    const event = (eventUid, channelId, service, kind) => ({
      eventUid,
      channelId,
      kind,
      orderKey: `${service}\n__availability`,
      event: { service, kind, message: kind },
    });
    const contentOf = message => message.events.map(item => `${item.service}:${item.kind}`).join();
    // The webhook refuses plex's firing (400). Five minutes later control.sqlite is full and NTP
    // steps the clock back an hour: plex's recovery is kept in memory, created "before" its
    // firing by the wall clock, and delivered. Before, Retry ordered the two by those times: it
    // accepted the firing, which reached the receiver after the recovery, so plex showed as down
    // for good.
    {
      const control = await openMigrated(t);
      const clock = fakeClock();
      const { state, store } = refusingControl(control, clock);
      const sent = [],
        answers = [failed('The webhook answered 400.', { status: 400 })];
      const outbox = createOutbox({
        store,
        clock,
        logger: quietLogger(),
        rng: () => 1,
        channels: [
          {
            name: 'env-webhook',
            async send(message) {
              sent.push(contentOf(message));
              return answers.shift() ?? accepted({ status: 200 });
            },
          },
        ],
      });
      t.after(() => outbox.stop({ timeoutMs: 0 }));
      await outbox.enqueue(event('e_fire', 'env-webhook', 'plex', 'firing'));
      await outbox.flush({ timeoutMs: 1000 });
      await clock.advance(5 * minute);
      state.refusing = true;
      clock.step(-hour);
      const kept = await outbox.enqueue(event('e_ok', 'env-webhook', 'plex', 'resolved'));
      assert.equal(kept.memoryUids.length, 1);
      await outbox.flush({ timeoutMs: 1000 });
      assert.deepEqual(sent, ['plex:firing', 'plex:resolved']);
      const firing = deliveryUid('e_fire', 'env-webhook');
      assert.equal(await outbox.retryable(await store.find(firing)), false);
      assert.equal((await outbox.retry(firing)).refused, 'outdated', 'kept in memory');
      // Space is back: the recovery is saved, with an id above the firing's.
      state.refusing = false;
      assert.equal(await store.probe(), true);
      assert.equal(store.unsaved, 0);
      assert.equal((await outbox.retry(firing)).refused, 'outdated', 'saved');
      await outbox.flush({ timeoutMs: 1000 });
      assert.deepEqual(sent, ['plex:firing', 'plex:resolved']);
    }
    // Email refuses plex's firing (554). The clock steps back an hour; plex's recovery is kept in
    // memory and, with space back, nas's alert saved: one digest of both, which the mail server
    // asks to try later (451). The admin presses Retry on plex's firing once the digest is due again:
    // the digest's recovery waits behind the firing (D23), so the firing goes, then the digest.
    // Before, the firing was held back behind the recovery (by creation time) while the digest
    // waited for that recovery: neither went, nor any later email of plex or nas, until the rows
    // expired 24 hours on.
    {
      const control = await openMigrated(t);
      const clock = fakeClock();
      const { state, store } = refusingControl(control, clock);
      const sent = [],
        answers = [
          failed('The mail server refused the message (554).', { status: 554 }),
          retry(null, 'The mail server asked Uptime Goblin to try later (451).', { status: 451 }),
        ];
      const email = {
        name: 'email',
        digest: { windowMs: minute, maxFactor: 3 },
        async send(message) {
          sent.push(message);
          return answers.shift() ?? accepted({ status: 250 });
        },
      };
      const outbox = createOutbox({
        store,
        clock,
        logger: quietLogger(),
        rng: () => 1,
        channels: [email],
      });
      t.after(() => outbox.stop({ timeoutMs: 0 }));
      const passes = async (count, ms) => {
        for (let i = 0; i < count; i++) {
          await clock.advance(ms);
          await outbox.pump();
          await settle();
        }
      };
      await outbox.enqueue(event('e_plex', 'email', 'plex', 'firing'));
      await passes(2, minute);
      await clock.advance(5 * minute);
      clock.step(-hour);
      await passes(1, 0);
      state.refusing = true;
      const kept = await outbox.enqueue(event('e_plex_ok', 'email', 'plex', 'resolved'));
      assert.equal(kept.memoryUids.length, 1);
      state.refusing = false;
      assert.equal(await store.probe(), true);
      await outbox.enqueue(event('e_nas', 'email', 'nas', 'firing'));
      await passes(1, minute);
      assert.deepEqual(sent.map(contentOf), ['plex:firing', 'nas:firing,plex:resolved']);
      await clock.advance(minute);
      assert.equal((await outbox.retry(deliveryUid('e_plex', 'email'))).retried, 1);
      await passes(4, minute);
      await outbox.enqueue(event('e_nas_ok', 'email', 'nas', 'resolved'));
      await passes(4, minute);
      assert.deepEqual(sent.map(contentOf), [
        'plex:firing',
        'nas:firing,plex:resolved',
        'plex:firing',
        'nas:firing,plex:resolved',
        'nas:resolved',
      ]);
      assert.equal(sent[3].uid, sent[1].uid, 'the digest keeps its Message-ID');
      assert.deepEqual(
        (await store.list({ limit: 10 })).map(row => row.state),
        ['delivered', 'delivered', 'delivered', 'delivered']
      );
    }
  }
);

test(
  'failover over control: three email digests tried before that interleave past the 200-row candidate window go whole, then a newer alert',
  needsLaneD,
  async t => {
    // Production sizes (200 candidates a pass, 100 rows a message). Each digest was tried once
    // (451) and is due again; their rows interleave a0 b0 c0 a1 b1 c1 …, so the window holds a
    // third of each past it. Before, no pass sent anything, the newer alert of another source
    // included, until the rows expired.
    const control = await openMigrated(t);
    const clock = fakeClock();
    const { store } = refusingControl(control, clock);
    const now = clock.wall(),
      rows = [],
      uids = { a: [], b: [], c: [] };
    for (let i = 0; i < 100; i++)
      for (const group of ['a', 'b', 'c']) {
        const row = outboxRow({
          eventUid: `e_${group}${i}`,
          channelId: 'email',
          kind: i % 2 ? 'resolved' : 'firing',
          orderKey: `${group}${i >> 1}\n__availability`,
          event: { service: `${group}${i >> 1}`, kind: i % 2 ? 'resolved' : 'firing' },
          attempts: 1,
          digestKey: group,
          lastStatus: 451,
          createdAt: now - 600000,
          nextAt: now - 1000,
        });
        uids[group].push(row.uid);
        rows.push(row);
      }
    for (const row of rows) row.digestKey = digestKeyFor(uids[row.digestKey]);
    await store.insert(rows);
    const sent = [];
    const outbox = createOutbox({
      store,
      clock,
      logger: quietLogger(),
      channels: [
        {
          name: 'email',
          digest: { windowMs: 60000, maxFactor: 3 },
          async send(message) {
            sent.push([message.uid, message.events.length]);
            return accepted({ status: 250 });
          },
        },
      ],
    });
    t.after(() => outbox.stop({ timeoutMs: 0 }));
    await outbox.enqueue({
      eventUid: 'e_new',
      channelId: 'email',
      kind: 'firing',
      orderKey: 'z\n__availability',
      event: { service: 'z', kind: 'firing' },
    });
    for (let i = 0; i < 12; i++) {
      await clock.advance(30000);
      await outbox.pump();
      await settle();
    }
    assert.deepEqual(sent, [
      [digestKeyFor(uids.a), 100],
      [digestKeyFor(uids.b), 100],
      [digestKeyFor(uids.c), 100],
      [digestKeyFor([deliveryUid('e_new', 'email')]), 1],
    ]);
    assert.deepEqual((await store.counts()).total, { delivered: 301 });
  }
);

test(
  'failover over control: a clock step that meets a control.sqlite refusing writes is applied once it takes them (D25)',
  needsLaneD,
  async t => {
    const hour = 3600 * 1000,
      minute = 60 * 1000;
    for (const direction of ['forward', 'back']) {
      const control = await openMigrated(t);
      const clock = fakeClock();
      const { state, primary, store } = refusingControl(control, clock);
      // A webhook whose receiver is down: every send is retried.
      const sends = [];
      const hook = {
        name: 'env-webhook',
        async send() {
          sends.push(clock.wall());
          return retry(null, 'The webhook answered 503.', { status: 503 });
        },
      };
      const outbox = createOutbox({
        store,
        channels: [hook],
        clock,
        logger: quietLogger(),
        rng: () => 0.5,
      });
      t.after(() => outbox.stop({ timeoutMs: 0 }));
      const pass = async () => {
        await outbox.pump();
        await settle();
      };
      await outbox.enqueue({
        eventUid: 'e_1',
        channelId: 'env-webhook',
        kind: 'firing',
        orderKey: 'nas\n__availability',
        event: { service: 'nas', kind: 'firing' },
      });
      await pass();
      const row = async () => (await primary.list({ limit: 1 }))[0];
      if (direction === 'forward') {
        // 20 hours of retries: 4 hours of life left. Then NTP steps the clock forward by 6 hours
        // while control.sqlite refuses writes.
        for (let i = 0; i < 80; i++) {
          await clock.advance(15 * minute);
          await pass();
        }
        assert.equal(Math.round(((await row()).expiresAt - clock.wall()) / hour), 4);
        state.refusing = true;
        clock.step(6 * hour);
        await pass();
        state.refusing = false;
        await clock.advance(1000);
        await pass();
        // Before, the step was answered as adjusted but never written: the row expired unsent.
        const after = await row();
        assert.notEqual(after.state, 'dead', direction);
        assert.equal(Math.round((after.expiresAt - clock.wall()) / hour), 4, direction);
      } else {
        // A few minutes of retries: the next attempt is minutes away. Then the clock steps back
        // 6 hours while control.sqlite refuses writes.
        for (let i = 0; i < 6; i++) {
          await clock.advance(minute);
          await pass();
        }
        state.refusing = true;
        clock.step(-6 * hour);
        await pass();
        state.refusing = false;
        await clock.advance(1000);
        await pass();
        // Before, the wait was never capped: the next attempt came 5.5 hours later.
        const after = await row();
        assert.ok(after.nextAt - clock.wall() <= 15 * minute, direction);
        const before = sends.length;
        for (let i = 0; i < 30; i++) {
          await clock.advance(minute);
          await pass();
        }
        assert.ok(sends.length > before, `${direction}: retries go on within 30 minutes`);
      }
    }
  }
);

test('a row whose saved event does not decode, or is not an object, is set dead and never stops the rows after it', async t => {
  const control = await openMigrated(t);
  const store = createControlOutboxStore({ db: control.db });
  const { inserted } = await store.insert(
    [1, 2, 3, 4].map(n => outboxRow({ eventUid: `row-${n}` }))
  );
  const ids = inserted.map(row => row.id);
  // Written past the json_valid CHECK, as a damaged page or a hand edit could.
  const raw = new DatabaseSync(control.file);
  raw.exec('PRAGMA ignore_check_constraints=ON');
  const event = raw.prepare('UPDATE alerting_outbox SET event = ? WHERE id = ?');
  event.run('not json {SYNTH-OUTBOX-CANARY', ids[0]);
  event.run('null', ids[1]);
  event.run('[1]', ids[2]);
  raw.close();
  const warnings = t.mock.method(console, 'warn', () => {});
  const due = await store.candidates({ now: T0 + 1 });
  assert.deepEqual(
    due.map(row => row.id),
    [ids[3]],
    'the readable row is still due'
  );
  const logged = warnings.mock.calls.map(call => call.arguments.join(' ')).join('\n');
  assert.equal(
    logged,
    `Notification rows ${ids.slice(0, 3).join(', ')} could not be read from control.sqlite; they are not sent.`
  );
  for (const rowId of ids.slice(0, 3)) {
    const [row] = (await store.list({ limit: 100 })).filter(item => item.id === rowId);
    assert.equal(row.state, 'dead', String(rowId));
    assert.equal(row.deadReason, 'unreadable');
    assert.equal(row.event, null, 'shown without its alert');
  }
  // Set dead once: the next pass reads only the readable row and says nothing.
  assert.deepEqual(
    (await store.candidates({ now: T0 + 2 })).map(row => row.id),
    [ids[3]]
  );
  assert.equal(warnings.mock.callCount(), 1);
});
