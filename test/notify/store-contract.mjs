// The OutboxStore contract (lib/notify/outbox.mjs), as tests any adapter must pass (not a test
// file itself). test/notify/memory-store.test.mjs runs it against the memory store and the
// failover store; wave 2 runs it against the control-database adapter, row for row:
//
//   import { outboxStoreContract } from './store-contract.mjs';
//   outboxStoreContract(test, 'control database', async t => openedAdapter);
//
// `makeStore(t)` returns a fresh, empty store (and may register cleanup with t.after).
import assert from 'node:assert/strict';
import { deliveryUid } from '../../lib/notify/outbox.mjs';
import { isStorageError } from '../../lib/notify/memory-store.mjs';

const T0 = 1_800_000_000_000;
let sequence = 0;

/**
 * A queued row as createOutbox writes it (see newRow in outbox.mjs): its uid always derives from
 * (eventUid, channelId, target), so an adapter may enforce uniqueness on either.
 */
export function outboxRow(overrides = {}) {
  sequence++;
  const createdAt = overrides.createdAt ?? T0,
    eventUid = overrides.eventUid ?? `ev-${sequence}`,
    channelId = overrides.channelId ?? 'env-webhook',
    target = overrides.target ?? '';
  return {
    uid: deliveryUid(eventUid, channelId, target),
    eventUid,
    channelId,
    target,
    kind: 'firing',
    severity: 'critical',
    orderKey: null,
    event: { service: 'plex', kind: 'firing', message: 'Source is unavailable', time: createdAt },
    state: 'queued',
    attempts: 0,
    unknowns: 0,
    nextAt: createdAt,
    createdAt,
    expiresAt: createdAt + 24 * 3600 * 1000,
    digestKey: null,
    leaseOwner: null,
    leaseUntil: null,
    epoch: 0,
    sentAt: null,
    lastStatus: null,
    lastError: null,
    deadReason: null,
    externalRef: null,
    updatedAt: createdAt,
    ...overrides,
  };
}

const lease = (overrides = {}) => ({
  owner: 'o_a',
  epoch: 1,
  now: T0,
  leaseUntil: T0 + 60000,
  digestKey: null,
  ...overrides,
});
const ids = rows => rows.map(row => row.id);

export function outboxStoreContract(test, name, makeStore) {
  const prefix = `OutboxStore contract (${name}):`;

  test(`${prefix} insert keeps (eventUid, channelId, target) unique and returns copies`, async t => {
    const store = await makeStore(t);
    const a = outboxRow({ eventUid: 'e1' }),
      b = outboxRow({ eventUid: 'e1', channelId: 'email' }),
      c = outboxRow({ eventUid: 'e1', target: 'ops@example.test' });
    const first = await store.insert([a, b, c]);
    assert.equal(first.inserted.length, 3);
    assert.deepEqual(first.duplicates, []);
    const [row] = first.inserted;
    assert.ok(row.id !== undefined && row.id !== null);
    assert.deepEqual({ ...row, id: undefined }, { ...a, id: undefined });
    // Same event, channel and target again: a duplicate, whatever its other fields.
    const again = await store.insert([outboxRow({ eventUid: 'e1', kind: 'resolved' })]);
    assert.deepEqual(again, { inserted: [], duplicates: [a.uid] });
    // Rows handed out are copies.
    row.event.message = 'changed by the caller';
    const [listed] = await store.list({ channelId: 'env-webhook', limit: 10 });
    assert.equal(listed.event.message, 'Source is unavailable');
    assert.equal(await store.countActive(), 3);
  });

  test(`${prefix} candidates are due, queued rows in id order, on channels able to send`, async t => {
    const store = await makeStore(t);
    const { inserted } = await store.insert([
      outboxRow({ eventUid: 'due-1' }),
      outboxRow({ eventUid: 'later', nextAt: T0 + 1000 }),
      outboxRow({ eventUid: 'expired', expiresAt: T0 }),
      outboxRow({ eventUid: 'held', state: 'held' }),
      outboxRow({ eventUid: 'mail', channelId: 'email' }),
      outboxRow({ eventUid: 'paused', channelId: 'slack' }),
      outboxRow({ eventUid: 'backoff', channelId: 'teams' }),
      outboxRow({ eventUid: 'due-2' }),
    ]);
    await store.setChannel('slack', { state: 'paused', nextSendAt: 0 });
    await store.setChannel('teams', { state: 'circuit-open', nextSendAt: T0 + 1 });
    const due = await store.candidates({ now: T0, limit: 10 });
    assert.deepEqual(
      due.map(row => row.eventUid),
      ['due-1', 'mail', 'due-2']
    );
    assert.deepEqual(ids(due), [inserted[0].id, inserted[4].id, inserted[7].id]);
    assert.deepEqual(
      (await store.candidates({ now: T0, limit: 2 })).map(row => row.eventUid),
      ['due-1', 'mail']
    );
    assert.deepEqual(
      (await store.candidates({ now: T0, limit: 10, channels: ['email'] })).map(r => r.eventUid),
      ['mail']
    );
    assert.deepEqual(await store.candidates({ now: T0, limit: 10, channels: [] }), []);
    // The back-off ends: the channel's rows are candidates again.
    assert.ok(
      (await store.candidates({ now: T0 + 1, limit: 10 })).some(row => row.eventUid === 'backoff')
    );
  });

  test(`${prefix} a row never overtakes an earlier active row of its (channel, orderKey)`, async t => {
    const store = await makeStore(t);
    const key = 'plex\n__availability';
    const { inserted } = await store.insert([
      outboxRow({ eventUid: 'f1', orderKey: key, kind: 'firing' }),
      outboxRow({ eventUid: 'r1', orderKey: key, kind: 'resolved' }),
      outboxRow({ eventUid: 'other', orderKey: 'nas\n__availability' }),
      outboxRow({ eventUid: 'f1-mail', orderKey: key, channelId: 'email' }),
    ]);
    // A run of due rows of one key is returned together (a digest sends them as one message).
    assert.deepEqual(
      (await store.candidates({ now: T0, limit: 10 })).map(row => row.eventUid),
      ['f1', 'r1', 'other', 'f1-mail']
    );
    // Once the firing is sending (or waits for a retry), the recovery waits behind it; the
    // same key on another channel, and other keys, do not.
    await store.claim([inserted[0].id], lease());
    assert.deepEqual(
      (await store.candidates({ now: T0, limit: 10 })).map(row => row.eventUid),
      ['other', 'f1-mail']
    );
    await store.complete([{ id: inserted[0].id, patch: { state: 'queued', nextAt: T0 + 30000 } }], {
      owner: 'o_a',
      epoch: 1,
    });
    assert.deepEqual(
      (await store.candidates({ now: T0, limit: 10 })).map(row => row.eventUid),
      ['other', 'f1-mail']
    );
    // Delivered: the recovery may go.
    await store.claim([inserted[0].id], lease({ now: T0 + 30000 }));
    await store.complete([{ id: inserted[0].id, patch: { state: 'delivered' } }], {
      owner: 'o_a',
      epoch: 1,
    });
    assert.deepEqual(
      (await store.candidates({ now: T0 + 30000, limit: 10 })).map(row => row.eventUid),
      ['r1', 'other', 'f1-mail']
    );
  });

  test(`${prefix} claim leases queued rows once; complete needs the same owner and epoch`, async t => {
    const store = await makeStore(t);
    const { inserted } = await store.insert([outboxRow(), outboxRow()]);
    const claimed = await store.claim(ids(inserted), lease({ digestKey: 'g_batch' }));
    assert.equal(claimed.length, 2);
    for (const row of claimed) {
      assert.equal(row.state, 'sending');
      assert.equal(row.leaseOwner, 'o_a');
      assert.equal(row.leaseUntil, T0 + 60000);
      assert.equal(row.epoch, 1);
      assert.equal(row.attempts, 1);
      assert.equal(row.digestKey, 'g_batch');
    }
    // Already sending: a second claim gets nothing.
    assert.deepEqual(await store.claim(ids(inserted), lease({ owner: 'o_b' })), []);
    assert.equal((await store.sending()).length, 2);
    // A stale epoch or another owner changes nothing.
    const patch = { state: 'delivered', leaseOwner: null, leaseUntil: null, sentAt: T0 };
    assert.equal(
      await store.complete([{ id: inserted[0].id, patch }], { owner: 'o_a', epoch: 2 }),
      0
    );
    assert.equal(
      await store.complete([{ id: inserted[0].id, patch }], { owner: 'o_b', epoch: 1 }),
      0
    );
    assert.equal(
      await store.complete(
        ids(inserted).map(id => ({ id, patch })),
        { owner: 'o_a', epoch: 1 }
      ),
      2
    );
    // Completed rows cannot be completed again.
    assert.equal(
      await store.complete([{ id: inserted[0].id, patch }], { owner: 'o_a', epoch: 1 }),
      0
    );
    assert.deepEqual(await store.sending(), []);
    // A retry keeps the batch's digest key when claimed again with none.
    const [row] = (await store.insert([outboxRow()])).inserted;
    await store.claim([row.id], lease({ digestKey: 'g_keep' }));
    await store.complete([{ id: row.id, patch: { state: 'queued', leaseOwner: null } }], {
      owner: 'o_a',
      epoch: 1,
    });
    const [again] = await store.claim([row.id], lease({ digestKey: null }));
    assert.equal(again.digestKey, 'g_keep');
    assert.equal(again.attempts, 2);
  });

  test(`${prefix} expire, hold, release and supersede move only the rows they name`, async t => {
    const store = await makeStore(t);
    const key = 'plex\n__availability';
    const { inserted } = await store.insert([
      outboxRow({ eventUid: 'old', expiresAt: T0 + 10 }),
      outboxRow({ eventUid: 'old-held', expiresAt: T0 + 10, state: 'held' }),
      outboxRow({ eventUid: 'fresh' }),
      outboxRow({ eventUid: 'retrying', nextAt: T0 + 5000 }),
      outboxRow({ eventUid: 'mail', channelId: 'email' }),
      outboxRow({ eventUid: 'firing', orderKey: key, kind: 'firing' }),
      outboxRow({ eventUid: 'reminder', orderKey: key, kind: 'reminder' }),
      outboxRow({ eventUid: 'ack', orderKey: key, kind: 'acknowledged', state: 'held' }),
    ]);
    assert.equal(await store.expire(T0 + 10), 2);
    const dead = await store.list({ state: 'dead', limit: 10 });
    assert.deepEqual(dead.map(row => row.eventUid).sort(), ['old', 'old-held']);
    for (const row of dead) {
      assert.equal(row.deadReason, 'expired');
      assert.ok(row.lastError);
    }
    // Hold: only queued rows of that channel.
    assert.equal(await store.hold('env-webhook', T0 + 20), 4);
    assert.equal((await store.list({ state: 'held', channelId: 'email', limit: 10 })).length, 0);
    // Release: held rows are queued again and rows waiting to retry become due, at once.
    assert.equal(await store.release('env-webhook', T0 + 30), 5);
    const queued = await store.list({ state: 'queued', channelId: 'env-webhook', limit: 10 });
    assert.equal(queued.length, 5);
    for (const row of queued) assert.equal(row.nextAt, T0 + 30);
    // Supersede: named kinds of that channel and key, while queued or held; never a firing.
    assert.equal(
      await store.supersede({
        channelId: 'env-webhook',
        orderKey: key,
        kinds: ['reminder', 'escalated', 'acknowledged'],
        now: T0 + 40,
      }),
      2
    );
    const superseded = await store.list({ state: 'superseded', limit: 10 });
    assert.deepEqual(superseded.map(row => row.eventUid).sort(), ['ack', 'reminder']);
    assert.equal(
      (await store.list({ channelId: 'env-webhook', limit: 20 })).find(r => r.eventUid === 'firing')
        .state,
      'queued'
    );
    assert.equal(inserted.length, 8);
  });

  test(`${prefix} channel status, counts and the next due time`, async t => {
    const store = await makeStore(t);
    assert.equal(await store.channel('email'), null);
    const status = { state: 'retrying', nextSendAt: 0, consecutiveFailures: 1, lastError: null };
    await store.setChannel('email', status);
    status.state = 'changed by the caller';
    assert.equal((await store.channel('email')).state, 'retrying');
    assert.ok((await store.channelIds()).includes('email'));
    const { inserted } = await store.insert([
      outboxRow({ eventUid: 'a', createdAt: T0 - 5000, nextAt: T0 + 9000 }),
      outboxRow({ eventUid: 'b', channelId: 'email', createdAt: T0 - 1000 }),
      outboxRow({ eventUid: 'c', state: 'delivered' }),
    ]);
    const counts = await store.counts();
    assert.deepEqual(counts.total, { queued: 2, delivered: 1 });
    assert.deepEqual(counts.byChannel, {
      'env-webhook': { queued: 1, delivered: 1 },
      email: { queued: 1 },
    });
    assert.equal(counts.oldestQueuedAt, T0 - 5000);
    assert.equal(await store.countActive(), 2);
    // The next moment something becomes due, never `now` or earlier.
    assert.equal(await store.nextDueAt(T0), T0 + 9000);
    await store.claim([inserted[1].id], lease({ leaseUntil: T0 + 4000 }));
    assert.equal(await store.nextDueAt(T0), T0 + 4000);
    assert.equal(await store.nextDueAt(T0 + 9000), null);
  });

  test(`${prefix} prune removes finished and dead rows by age and count, oldest first`, async t => {
    const store = await makeStore(t);
    const day = 24 * 3600 * 1000;
    await store.insert([
      outboxRow({ eventUid: 'd-old', state: 'delivered', updatedAt: T0 - 8 * day }),
      outboxRow({ eventUid: 'd-new', state: 'delivered', updatedAt: T0 - day }),
      outboxRow({ eventUid: 's-old', state: 'superseded', updatedAt: T0 - 9 * day }),
      outboxRow({ eventUid: 'dead-1', state: 'dead', updatedAt: T0 - 3 * day }),
      outboxRow({ eventUid: 'dead-2', state: 'dead', updatedAt: T0 - 2 * day }),
      outboxRow({ eventUid: 'dead-3', state: 'dead', updatedAt: T0 - day }),
      outboxRow({ eventUid: 'active', updatedAt: T0 - 90 * day }),
    ]);
    const rules = {
      now: T0,
      finished: { maxAgeMs: 7 * day, maxRows: 50000 },
      dead: { maxAgeMs: 30 * day, maxRows: 2 },
    };
    // `limit` bounds one call, so a large prune runs in chunks.
    assert.equal(await store.prune({ ...rules, limit: 1 }), 1);
    assert.equal(await store.prune({ ...rules, limit: 100 }), 2);
    assert.equal(await store.prune({ ...rules, limit: 100 }), 0);
    const left = (await store.list({ limit: 20 })).map(row => row.eventUid).sort();
    assert.deepEqual(left, ['active', 'd-new', 'dead-2', 'dead-3']);
    // A pruned row's uniqueness is gone with it.
    const again = await store.insert([outboxRow({ eventUid: 'd-old' })]);
    assert.equal(again.inserted.length, 1);
  });

  // --- Delivery spec §5.2 additions (frozen with the rest of the contract) -----------------

  test(`${prefix} find and batch read rows by delivery id and by digest key`, async t => {
    const store = await makeStore(t);
    const { inserted } = await store.insert([
      outboxRow({ eventUid: 'b1', channelId: 'email' }),
      outboxRow({ eventUid: 'b2', channelId: 'email' }),
      outboxRow({ eventUid: 'alone' }),
    ]);
    const found = await store.find(inserted[2].uid);
    assert.deepEqual(found, inserted[2]);
    found.event.message = 'changed by the caller';
    assert.equal((await store.find(inserted[2].uid)).event.message, 'Source is unavailable');
    assert.equal(await store.find('d_nothingnothingnothingnothi'), null);
    await store.claim(ids(inserted.slice(0, 2)), lease({ digestKey: 'g_batch' }));
    const batch = await store.batch('g_batch');
    assert.deepEqual(
      batch.map(row => row.uid),
      [inserted[0].uid, inserted[1].uid]
    );
    assert.ok(batch.every(row => row.state === 'sending' && row.digestKey === 'g_batch'));
    assert.deepEqual(await store.batch('g_other'), []);
    // With `states`, only the batch's rows in those states (the worker's whole-batch check).
    await store.complete(
      [
        { id: inserted[0].id, patch: { state: 'dead', deadReason: 'expired' } },
        { id: inserted[1].id, patch: { state: 'queued', nextAt: T0 + 30000 } },
      ],
      { owner: 'o_a', epoch: 1 }
    );
    const active = ['queued', 'sending', 'held'];
    assert.deepEqual(
      (await store.batch('g_batch', { states: active })).map(row => [row.uid, row.state]),
      [[inserted[1].uid, 'queued']]
    );
    assert.equal((await store.batch('g_batch')).length, 2);
    assert.deepEqual(await store.batch('g_batch', { states: [] }), []);
  });

  test(`${prefix} list is newest first, filtered, paged by id and bounded`, async t => {
    const store = await makeStore(t);
    const key = 'plex\n__availability';
    const { inserted } = await store.insert([
      outboxRow({ eventUid: 'l1', orderKey: key }),
      outboxRow({ eventUid: 'l2', channelId: 'email', state: 'delivered' }),
      outboxRow({ eventUid: 'l3', orderKey: key, state: 'dead' }),
      outboxRow({ eventUid: 'l4', state: 'held' }),
      outboxRow({ eventUid: 'l5', channelId: 'email' }),
    ]);
    const uids = rows => rows.map(row => row.eventUid);
    assert.deepEqual(uids(await store.list({ limit: 10 })), ['l5', 'l4', 'l3', 'l2', 'l1']);
    assert.deepEqual(uids(await store.list({ limit: 2 })), ['l5', 'l4']);
    assert.deepEqual(uids(await store.list({ states: ['queued', 'held'], limit: 10 })), [
      'l5',
      'l4',
      'l1',
    ]);
    // `state` stays an alias of `states: [state]`.
    assert.deepEqual(uids(await store.list({ state: 'dead', limit: 10 })), ['l3']);
    assert.deepEqual(uids(await store.list({ channelId: 'email', limit: 10 })), ['l5', 'l2']);
    assert.deepEqual(uids(await store.list({ orderKey: key, limit: 10 })), ['l3', 'l1']);
    // Keyset paging: below an id (the next page), above one (newer rows).
    assert.deepEqual(uids(await store.list({ beforeId: inserted[2].id, limit: 10 })), ['l2', 'l1']);
    assert.deepEqual(uids(await store.list({ afterId: inserted[2].id, limit: 10 })), ['l5', 'l4']);
    assert.deepEqual(
      uids(await store.list({ beforeId: inserted[4].id, afterId: inserted[1].id, limit: 10 })),
      ['l4', 'l3']
    );
    // At most 100 rows, whatever the caller asks for.
    await store.insert(Array.from({ length: 120 }, (_, n) => outboxRow({ eventUid: `bulk-${n}` })));
    assert.equal((await store.list({ limit: 1000 })).length, 100);
  });

  test(`${prefix} list with excludeWaiting leaves out queued rows not tried yet, so a page of problems is full`, async t => {
    const store = await makeStore(t);
    // The oldest rows retry, are held or failed; 120 newer rows wait for their first attempt
    // (a backlog behind an open circuit).
    await store.insert([
      outboxRow({ eventUid: 'retrying', attempts: 2 }),
      outboxRow({ eventUid: 'held', state: 'held', attempts: 1 }),
      outboxRow({ eventUid: 'dead', state: 'dead', attempts: 3 }),
      outboxRow({ eventUid: 'held-untried', state: 'held' }),
      ...Array.from({ length: 120 }, (_, n) => outboxRow({ eventUid: `waiting-${n}` })),
    ]);
    const problems = { states: ['queued', 'held', 'dead'], excludeWaiting: true };
    const uids = rows => rows.map(row => row.eventUid);
    assert.deepEqual(uids(await store.list({ ...problems, limit: 100 })), [
      'held-untried',
      'dead',
      'held',
      'retrying',
    ]);
    // Paged by id as before: the next page starts below the last row shown.
    const first = await store.list({ ...problems, limit: 2 });
    assert.deepEqual(uids(first), ['held-untried', 'dead']);
    const second = await store.list({ ...problems, beforeId: first[1].id, limit: 2 });
    assert.deepEqual(uids(second), ['held', 'retrying']);
    assert.deepEqual(await store.list({ ...problems, beforeId: second[1].id, limit: 2 }), []);
    // With a channel; and without states, every row but the untried queued ones.
    assert.deepEqual(uids(await store.list({ ...problems, channelId: 'email', limit: 10 })), []);
    assert.equal((await store.list({ excludeWaiting: true, limit: 100 })).length, 4);
    // Without it, unchanged: the newest rows, all waiting.
    assert.ok(
      (await store.list({ states: problems.states, limit: 100 })).every(row =>
        row.eventUid.startsWith('waiting-')
      )
    );
  });

  test(`${prefix} requeue makes failed and retrying rows due now; other states are left alone`, async t => {
    const store = await makeStore(t);
    const later = T0 + 3600000;
    const { inserted } = await store.insert([
      outboxRow({
        eventUid: 'dead',
        state: 'dead',
        deadReason: 'failed',
        unknowns: 1,
        attempts: 3,
        lastError: 'refused',
        expiresAt: T0 + 10,
      }),
      outboxRow({ eventUid: 'retrying', attempts: 2, nextAt: T0 + 90000, unknowns: 1 }),
      outboxRow({ eventUid: 'delivered', state: 'delivered' }),
      outboxRow({ eventUid: 'held', state: 'held' }),
    ]);
    const [sending] = (await store.insert([outboxRow({ eventUid: 'sending' })])).inserted;
    await store.claim([sending.id], lease());
    const all = [...ids(inserted), sending.id];
    assert.equal(await store.requeue(all, { now: later, expiresAt: later + 86400000 }), 2);
    const byUid = Object.fromEntries(
      (await store.list({ limit: 10 })).map(row => [row.eventUid, row])
    );
    // A dead row gets a fresh age budget and its unknown count back to 0; attempts are kept.
    assert.deepEqual(
      [
        byUid.dead.state,
        byUid.dead.nextAt,
        byUid.dead.expiresAt,
        byUid.dead.deadReason,
        byUid.dead.unknowns,
        byUid.dead.attempts,
        byUid.dead.leaseOwner,
      ],
      ['queued', later, later + 86400000, null, 0, 3, null]
    );
    // A retrying row is due now and keeps its expiry and unknown count.
    assert.deepEqual(
      [byUid.retrying.state, byUid.retrying.nextAt, byUid.retrying.unknowns],
      ['queued', later, 1]
    );
    assert.equal(byUid.retrying.expiresAt, T0 + 24 * 3600 * 1000);
    for (const name of ['delivered', 'held', 'sending'])
      assert.notEqual(byUid[name].nextAt, later, name);
    assert.equal(byUid.sending.state, 'sending');
    // Without expiresAt a dead row keeps its expiry.
    const [old] = (
      await store.insert([outboxRow({ eventUid: 'dead-2', state: 'dead', expiresAt: T0 + 5 })])
    ).inserted;
    assert.equal(await store.requeue([old.id], { now: later }), 1);
    assert.equal((await store.find(old.uid)).expiresAt, T0 + 5);
  });

  test(`${prefix} stale and cancel end waiting rows with a reason, never sent`, async t => {
    const store = await makeStore(t);
    const { inserted } = await store.insert([
      outboxRow({ eventUid: 's1', orderKey: 'plex\n__availability' }),
      outboxRow({ eventUid: 's2', orderKey: 'plex\ncpu', state: 'held' }),
      outboxRow({ eventUid: 's3', orderKey: 'plex2\n__availability' }),
      outboxRow({ eventUid: 's4', orderKey: 'plex\ncpu', state: 'delivered' }),
      outboxRow({ eventUid: 's5', orderKey: null }),
      outboxRow({ eventUid: 's6', orderKey: 'plex\nmem', channelId: 'email' }),
    ]);
    await store.claim([inserted[5].id], lease());
    // cancel: queued and held rows whose order key starts with the prefix; not the sending one.
    const reason = 'Not sent: the source was deleted.';
    assert.equal(await store.cancel({ orderKeyPrefix: 'plex\n', now: T0 + 1, reason }), 2);
    const state = async () =>
      Object.fromEntries(
        (await store.list({ limit: 10 })).map(row => [row.eventUid, [row.state, row.lastError]])
      );
    assert.deepEqual(await state(), {
      s1: ['cancelled', reason],
      s2: ['cancelled', reason],
      s3: ['queued', null],
      s4: ['delivered', null],
      s5: ['queued', null],
      s6: ['sending', null],
    });
    await assert.rejects(store.cancel({ orderKeyPrefix: '', now: T0, reason }), TypeError);
    // stale: queued, held and sending rows, lease cleared.
    const staleReason = 'Not sent: restored.';
    assert.equal(await store.stale({ now: T0 + 2, reason: staleReason }), 3);
    assert.deepEqual(await state(), {
      s1: ['cancelled', reason],
      s2: ['cancelled', reason],
      s3: ['stale', staleReason],
      s4: ['delivered', null],
      s5: ['stale', staleReason],
      s6: ['stale', staleReason],
    });
    assert.deepEqual(await store.sending(), []);
    assert.equal(await store.countActive(), 0);
  });

  test(`${prefix} unclaim gives rows back without counting the attempt`, async t => {
    const store = await makeStore(t);
    const { inserted } = await store.insert([
      outboxRow({ eventUid: 'u1', nextAt: T0 - 5 }),
      outboxRow({ eventUid: 'u2' }),
    ]);
    await store.claim(ids(inserted), lease({ digestKey: 'g_u' }));
    // Another owner or epoch changes nothing.
    assert.equal(await store.unclaim(ids(inserted), { owner: 'o_b', epoch: 1, now: T0 + 1 }), 0);
    assert.equal(await store.unclaim(ids(inserted), { owner: 'o_a', epoch: 2, now: T0 + 1 }), 0);
    assert.equal(await store.unclaim(ids(inserted), { owner: 'o_a', epoch: 1, now: T0 + 1 }), 2);
    const [first] = await store
      .list({ orderKey: null, limit: 10, state: 'queued' })
      .then(rows => rows.filter(row => row.eventUid === 'u1'));
    assert.deepEqual(
      [
        first.state,
        first.attempts,
        first.leaseOwner,
        first.leaseUntil,
        first.nextAt,
        first.digestKey,
        first.updatedAt,
      ],
      ['queued', 0, null, null, T0 - 5, 'g_u', T0 + 1]
    );
    // Rows not sending are left alone.
    assert.equal(await store.unclaim(ids(inserted), { owner: 'o_a', epoch: 1, now: T0 + 2 }), 0);
    assert.equal((await store.candidates({ now: T0, limit: 10 })).length, 2);
  });

  test(`${prefix} supersede takes a reason and only rows created before a time`, async t => {
    const store = await makeStore(t);
    const key = 'plex\n__availability';
    await store.insert([
      outboxRow({ eventUid: 'f-old', orderKey: key, createdAt: T0 - 1000 }),
      outboxRow({ eventUid: 'r-old', orderKey: key, kind: 'resolved', createdAt: T0 - 500 }),
      outboxRow({ eventUid: 'f-new', orderKey: key, createdAt: T0 + 1000, state: 'held' }),
      outboxRow({ eventUid: 'other', orderKey: 'nas\n__availability', createdAt: T0 - 1000 }),
    ]);
    const reason = 'Not sent: Orbit 1.4.x handled a later change of this alert.';
    assert.equal(
      await store.supersede({
        channelId: 'env-webhook',
        orderKey: key,
        kinds: ['firing', 'resolved'],
        now: T0 + 2000,
        reason,
        createdBefore: T0,
      }),
      2
    );
    const rows = Object.fromEntries(
      (await store.list({ limit: 10 })).map(row => [row.eventUid, row])
    );
    assert.deepEqual(
      [rows['f-old'].state, rows['f-old'].lastError, rows['f-old'].updatedAt],
      ['superseded', reason, T0 + 2000]
    );
    assert.equal(rows['r-old'].state, 'superseded');
    assert.equal(rows['f-new'].state, 'held');
    assert.equal(rows.other.state, 'queued');
  });

  test(`${prefix} activeKeys names the keys with a queued, sending or held row, in input order`, async t => {
    const store = await makeStore(t);
    const { inserted } = await store.insert([
      outboxRow({ eventUid: 'k1', orderKey: 'a\nx' }),
      outboxRow({ eventUid: 'k2', orderKey: 'b\nx', state: 'held' }),
      outboxRow({ eventUid: 'k3', orderKey: 'c\nx', state: 'delivered' }),
      outboxRow({ eventUid: 'k4', orderKey: 'd\nx' }),
      outboxRow({ eventUid: 'k5', orderKey: 'a\nx', channelId: 'email', state: 'dead' }),
    ]);
    await store.claim([inserted[3].id], lease());
    const keys = [
      { channelId: 'env-webhook', orderKey: 'd\nx' },
      { channelId: 'email', orderKey: 'a\nx' },
      { channelId: 'env-webhook', orderKey: 'c\nx' },
      { channelId: 'env-webhook', orderKey: 'b\nx' },
      { channelId: 'env-webhook', orderKey: 'a\nx' },
      { channelId: 'env-webhook', orderKey: 'z\nx' },
    ];
    assert.deepEqual(await store.activeKeys(keys), [
      { channelId: 'env-webhook', orderKey: 'd\nx' },
      { channelId: 'env-webhook', orderKey: 'b\nx' },
      { channelId: 'env-webhook', orderKey: 'a\nx' },
    ]);
    assert.deepEqual(await store.activeKeys([]), []);
  });

  test(`${prefix} shiftExpiry and clampTimes adjust active rows after a clock step`, async t => {
    const store = await makeStore(t);
    const day = 24 * 3600 * 1000;
    const { inserted } = await store.insert([
      outboxRow({ eventUid: 'q', nextAt: T0 + 3 * day, expiresAt: T0 + 4 * day }),
      outboxRow({ eventUid: 'h', state: 'held', expiresAt: T0 + 4 * day }),
      outboxRow({ eventUid: 'd', state: 'delivered', expiresAt: T0 + 4 * day }),
      outboxRow({ eventUid: 's', expiresAt: T0 + 4 * day }),
      outboxRow({ eventUid: 'near', nextAt: T0 + 60000, expiresAt: T0 + 3600000 }),
    ]);
    await store.claim([inserted[3].id], lease({ leaseUntil: T0 + 2 * day }));
    const get = async () =>
      Object.fromEntries((await store.list({ limit: 10 })).map(row => [row.eventUid, row]));
    // Forward: every active row's expiry moves on; finished rows are left alone.
    assert.equal(await store.shiftExpiry({ by: day, now: T0 + 1 }), 4);
    let rows = await get();
    assert.deepEqual(
      ['q', 'h', 'd', 's', 'near'].map(name => rows[name].expiresAt),
      [T0 + 5 * day, T0 + 5 * day, T0 + 4 * day, T0 + 5 * day, T0 + day + 3600000]
    );
    assert.equal(await store.shiftExpiry({ by: 0, now: T0 + 1 }), 0);
    // Backward: queued nextAt, active expiresAt and sending leaseUntil are lowered to the caps.
    const changed = await store.clampTimes({
      now: T0 + 2,
      nextAtMax: T0 + 900000,
      expiresAtMax: T0 + day,
      leaseUntilMax: T0 + 60000,
    });
    assert.equal(changed, 4);
    rows = await get();
    assert.deepEqual(
      [rows.q.nextAt, rows.q.expiresAt, rows.h.expiresAt, rows.s.expiresAt, rows.s.leaseUntil],
      [T0 + 900000, T0 + day, T0 + day, T0 + day, T0 + 60000]
    );
    assert.equal(rows.d.expiresAt, T0 + 4 * day);
    assert.deepEqual([rows.near.nextAt, rows.near.expiresAt], [T0 + 60000, T0 + day]);
    // Already within the caps: nothing changes.
    assert.equal(
      await store.clampTimes({
        now: T0 + 3,
        nextAtMax: T0 + 900000,
        expiresAtMax: T0 + day,
        leaseUntilMax: T0 + 60000,
      }),
      0
    );
  });

  test(`${prefix} summary counts each channel's waiting, retrying, sending, held and recent failures`, async t => {
    const store = await makeStore(t);
    assert.deepEqual(await store.summary({ failedSince: {} }), {});
    const { inserted } = await store.insert([
      outboxRow({ eventUid: 'w1', createdAt: T0 - 300 }),
      outboxRow({ eventUid: 'w2', createdAt: T0 - 100 }),
      outboxRow({ eventUid: 'r1', attempts: 2, createdAt: T0 - 50 }),
      outboxRow({ eventUid: 'h1', state: 'held', createdAt: T0 - 900 }),
      outboxRow({ eventUid: 's1' }),
      outboxRow({ eventUid: 'f-old', state: 'dead', updatedAt: T0 - 5000 }),
      outboxRow({ eventUid: 'f-new', state: 'dead', updatedAt: T0 - 10 }),
      outboxRow({ eventUid: 'ok', state: 'delivered' }),
      outboxRow({ eventUid: 'm-dead', channelId: 'email', state: 'dead', updatedAt: T0 - 5000 }),
      outboxRow({ eventUid: 'm-done', channelId: 'email', state: 'delivered' }),
      outboxRow({ eventUid: 't-done', channelId: 'teams', state: 'delivered' }),
    ]);
    await store.claim([inserted[4].id], lease());
    assert.deepEqual(await store.summary({ failedSince: { 'env-webhook': T0 - 1000 } }), {
      'env-webhook': {
        waiting: 2,
        retrying: 1,
        sending: 1,
        held: 1,
        failed: 1,
        oldestWaitingAt: T0 - 900,
      },
      // No failedSince for email: every dead row counts.
      email: {
        waiting: 0,
        retrying: 0,
        sending: 0,
        held: 0,
        failed: 1,
        oldestWaitingAt: null,
      },
    });
    // Failures before the channel's failedSince do not count, and a channel left with nothing
    // is absent.
    assert.deepEqual(
      (await store.summary({ failedSince: { 'env-webhook': T0, email: T0 } })).email,
      undefined
    );
    assert.equal(
      (await store.summary({ failedSince: { 'env-webhook': T0 } }))['env-webhook'].failed,
      0
    );
  });

  test(`${prefix} delivery order property: each (channel, orderKey) is delivered in insertion order`, async t => {
    for (const seed of [1, 2, 3]) {
      const store = await makeStore(t);
      await deliveryOrderProperty(store, { seed, steps: 250 });
    }
  });
}

/** A small deterministic generator (a failing sequence can be replayed from its seed). */
export function seededRandom(seed = 1) {
  let state = seed >>> 0 || 1;
  const random = () => {
    state = (Math.imul(state, 1103515245) + 12345) >>> 0;
    return state / 2 ** 32;
  };
  return {
    random,
    pick: list => list[Math.floor(random() * list.length)],
    int: (low, high) => low + Math.floor(random() * (high - low + 1)),
  };
}

/**
 * The contract's property test (delivery spec §5.2), exported so other suites run it over other
 * stores (the failover store with a failing primary): random interleavings of inserts (each
 * key's rows in event order), claims of what candidates() returns, and completions (accepted,
 * retry, pause, unknown, unclaim). A worker that claims only candidates must deliver each
 * (channel, orderKey)'s rows in insertion order, every row once, and claim no row again except
 * after retry, unknown, unclaim or a pause and its release. Resolves with what happened.
 * `between(step)` runs after every step (a test can break and mend the store there).
 */
export async function deliveryOrderProperty(
  store,
  { seed = 1, steps = 250, between = async () => {}, owner = 'o_prop' } = {}
) {
  const { random, pick, int } = seededRandom(seed);
  const channels = ['env-webhook', 'email'],
    keys = ['plex\n__availability', 'plex\ncpu', 'nas\n__availability', null];
  let now = T0,
    epoch = 1,
    eventNumber = 0;
  const inserted = new Map(), // `${channel}\n${key}` -> eventUids in insertion order
    delivered = new Map(), // same -> eventUids in delivery order
    claimable = new Map(), // row id -> may be claimed now
    inFlight = new Map(), // row id -> {row, epoch}
    reclaims = { retry: 0, unknown: 0, unclaim: 0, pause: 0 };
  const keyOf = row => `${row.channelId}\n${row.orderKey}`;
  const record = (map, row) => {
    if (!map.has(keyOf(row))) map.set(keyOf(row), []);
    map.get(keyOf(row)).push(row.eventUid);
  };
  const finish = async (id, patch) => {
    const { epoch: leased } = inFlight.get(id);
    inFlight.delete(id);
    return store.complete(
      [{ id, patch: { leaseOwner: null, leaseUntil: null, updatedAt: now, ...patch } }],
      {
        owner,
        epoch: leased,
      }
    );
  };
  const step = async kind => {
    if (kind === 'insert') {
      const channelId = pick(channels),
        orderKey = pick(keys),
        count = int(1, 3),
        rows = [];
      for (let n = 0; n < count; n++)
        rows.push(
          outboxRow({
            eventUid: `p${seed}-${++eventNumber}`,
            channelId,
            orderKey,
            kind: n % 2 ? 'resolved' : 'firing',
            createdAt: now,
          })
        );
      const result = await store.insert(rows);
      assert.equal(result.inserted.length, count);
      for (const row of result.inserted) {
        record(inserted, row);
        claimable.set(row.id, true);
      }
    } else if (kind === 'claim') {
      const candidates = await store.candidates({ now, limit: int(1, 20) });
      // Like the outbox for a non-digest channel: the first candidate of each key only.
      const seen = new Set(),
        chosen = [];
      for (const row of candidates) {
        if (row.orderKey !== null) {
          if (seen.has(keyOf(row))) continue;
          seen.add(keyOf(row));
        }
        if (random() < 0.7) chosen.push(row);
      }
      if (!chosen.length) return;
      const claimed = await store.claim(
        chosen.map(row => row.id),
        { owner, epoch, now, leaseUntil: now + 60000, digestKey: null }
      );
      for (const row of claimed) {
        assert.equal(claimable.get(row.id), true, `row ${row.eventUid} was claimed again too soon`);
        claimable.set(row.id, false);
        inFlight.set(row.id, { row, epoch });
      }
    } else if (kind === 'complete' && inFlight.size) {
      const id = pick([...inFlight.keys()]),
        { row } = inFlight.get(id),
        outcome = pick([
          'accepted',
          'accepted',
          'accepted',
          'retry',
          'unknown',
          'pause',
          'unclaim',
        ]);
      if (outcome === 'accepted') {
        assert.equal(await finish(id, { state: 'delivered', sentAt: now }), 1);
        record(delivered, row);
      } else if (outcome === 'retry' || outcome === 'unknown') {
        const patch = { state: 'queued', nextAt: now + int(0, 30) * 1000 };
        if (outcome === 'unknown') patch.unknowns = (row.unknowns ?? 0) + 1;
        assert.equal(await finish(id, patch), 1);
        claimable.set(id, true);
        reclaims[outcome]++;
      } else if (outcome === 'pause') {
        assert.equal(await finish(id, { state: 'held', nextAt: now }), 1);
        await store.hold(row.channelId, now);
        claimable.set(id, true);
        reclaims.pause++;
      } else {
        const { epoch: leased } = inFlight.get(id);
        inFlight.delete(id);
        assert.equal(await store.unclaim([id], { owner, epoch: leased, now }), 1);
        claimable.set(id, true);
        reclaims.unclaim++;
      }
    } else if (kind === 'release')
      // A store that cannot write now refuses the release (the failover store over a full
      // primary): the rows stay held, and the drain below releases them once it can.
      await store.release(pick(channels), now).catch(error => {
        if (!isStorageError(error)) throw error;
      });
    else if (kind === 'advance') {
      now += int(1, 20) * 1000;
      if (random() < 0.1) epoch++;
    }
  };
  for (let n = 0; n < steps; n++) {
    await step(
      pick(['insert', 'insert', 'claim', 'claim', 'complete', 'complete', 'release', 'advance'])
    );
    await between(n);
  }
  // Drain: release everything, then deliver whatever is due until nothing is active.
  for (let round = 0; round < 1000 && (inFlight.size || (await store.countActive())); round++) {
    for (const id of [...inFlight.keys()]) {
      const { row } = inFlight.get(id);
      assert.equal(await finish(id, { state: 'delivered', sentAt: now }), 1);
      record(delivered, row);
    }
    for (const channelId of channels) await store.release(channelId, now);
    now += 31000;
    await step('claim');
  }
  assert.equal(await store.countActive(), 0, 'everything was delivered');
  for (const [key, order] of inserted)
    if (key.endsWith('\nnull'))
      // Rows without an order key may go in any order, but each exactly once.
      assert.deepEqual([...(delivered.get(key) ?? [])].sort(), [...order].sort(), key);
    else
      assert.deepEqual(delivered.get(key) ?? [], order, `delivery order of ${JSON.stringify(key)}`);
  return { inserted: eventNumber, reclaims };
}
