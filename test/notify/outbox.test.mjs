// The outbox: its pure state machine, and the delivery worker over the memory store with a fake
// clock and scripted channels (no network).
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createOutbox,
  deliveryUid,
  digestKeyFor,
  supersededKinds,
  rowAfterOutcome,
  channelAfterOutcome,
  initialChannelStatus,
  planDigest,
  SNAPSHOT_LIMIT,
} from '../../lib/notify/outbox.mjs';
import { createMemoryOutboxStore } from '../../lib/notify/memory-store.mjs';
import { accepted, retry, failed, unknown, pause, skipped } from '../../lib/notify/channel.mjs';
import { createJobRunner, createLocalLeader } from '../../lib/jobs.mjs';
import * as notify from '../../lib/notify/index.mjs';
import { outboxRow } from './store-contract.mjs';
import { fakeClock, quietLogger, settle } from '../alerting/fake-clock.mjs';

const second = 1000,
  minute = 60 * second,
  hour = 60 * minute;

// A channel whose answers follow `script` (outcomes, or functions of (message, {signal})), then
// `accepted`. Every message it was given is recorded.
function scripted(name, script = [], options = {}) {
  const sent = [],
    queue = [...script];
  const channel = {
    name,
    ...options,
    async send(message, context) {
      sent.push(structuredClone(message));
      const next = queue.length ? queue.shift() : accepted({ status: 200 });
      return typeof next === 'function' ? next(message, context) : next;
    },
  };
  return { channel, sent, queue };
}

// A send that never answers until it is cancelled; it then reports whether anything was sent.
const hang =
  (outcome = retry(null, 'Cancelled before sending.')) =>
  (message, { signal }) =>
    new Promise(resolve =>
      signal.addEventListener('abort', () => resolve(outcome), { once: true })
    );

function setup(t, { channels = [], ...options } = {}) {
  const clock = options.clock ?? fakeClock(),
    logger = quietLogger(),
    store = options.store ?? createMemoryOutboxStore();
  const outbox = createOutbox({
    store,
    clock,
    logger,
    rng: () => 1,
    channels,
    owner: 'o_test',
    ...options,
  });
  t.after(() => outbox.stop({ timeoutMs: 0 }));
  return { outbox, store, clock, logger };
}

let events = 0;
const entry = (overrides = {}) => ({
  eventUid: `ev-${++events}`,
  channelId: 'env-webhook',
  kind: 'firing',
  event: { service: 'plex', kind: overrides.kind ?? 'firing', message: 'Source is unavailable' },
  ...overrides,
});
// In insertion (id) order: the store lists newest first (delivery spec §5.2).
const rowsOf = async (store, filter = {}) =>
  (await store.list({ limit: 100, ...filter })).sort((a, b) => a.id - b.id);
const rowFor = async (store, eventUid) =>
  (await rowsOf(store)).find(row => row.eventUid === eventUid);
// Runs pumps until nothing more starts now (windows respected), letting sends finish.
async function drain(outbox) {
  for (let i = 0; i < 50; i++) {
    const { started } = await outbox.pump();
    await settle();
    if (!started && !outbox.inFlight) return;
  }
  throw new Error('the outbox did not settle');
}

// ---------------------------------------------------------------------------------------------
// Pure parts

test('delivery ids are stable per (event, channel, target); digest keys ignore order', () => {
  const a = deliveryUid('ev-1', 'env-webhook');
  assert.match(a, /^d_[a-z2-7]{26}$/);
  assert.equal(a, deliveryUid('ev-1', 'env-webhook', ''));
  assert.notEqual(a, deliveryUid('ev-1', 'email'));
  assert.notEqual(a, deliveryUid('ev-1', 'env-webhook', 'ops@example.test'));
  assert.notEqual(a, deliveryUid('ev-2', 'env-webhook'));
  const g = digestKeyFor(['d_b', 'd_a']);
  assert.match(g, /^g_[a-z2-7]{26}$/);
  assert.equal(g, digestKeyFor(['d_a', 'd_b']));
  assert.notEqual(g, digestKeyFor(['d_a']));
});

test('a recovery supersedes waiting reminders, escalations and acks, never a firing', () => {
  assert.deepEqual(supersededKinds('resolved'), ['reminder', 'escalated', 'acknowledged']);
  assert.deepEqual(supersededKinds('cleared'), ['reminder', 'escalated', 'acknowledged']);
  assert.deepEqual(supersededKinds('reminder'), ['reminder']);
  for (const kind of ['firing', 'acknowledged', 'escalated', 'system', 'test'])
    assert.deepEqual(supersededKinds(kind), []);
});

test('rowAfterOutcome: each outcome moves a claimed row to its next state', () => {
  const now = 1_000_000;
  const row = {
    id: 1,
    state: 'sending',
    attempts: 2,
    unknowns: 0,
    expiresAt: now + hour,
    externalRef: null,
  };
  const at = (outcome, channel = {}) =>
    rowAfterOutcome(row, outcome, { now, rng: () => 1, channel });
  assert.deepEqual(at(accepted({ status: 201, externalRef: 'INC001' })), {
    leaseOwner: null,
    leaseUntil: null,
    updatedAt: now,
    lastStatus: 201,
    state: 'delivered',
    sentAt: now,
    lastError: null,
    externalRef: 'INC001',
  });
  // Attempt 2 failed: 30 s × 2 = 60 s (rng 1 is the top of the jitter range).
  assert.deepEqual(at(retry(null, 'busy', { status: 503 })), {
    leaseOwner: null,
    leaseUntil: null,
    updatedAt: now,
    lastStatus: 503,
    state: 'queued',
    nextAt: now + 60 * second,
    lastError: 'busy',
  });
  // Retry-After wins when it asks for longer; a wait past expiry is a dead letter now.
  assert.equal(at(retry(10 * minute, 'slow down')).nextAt, now + 10 * minute);
  assert.equal(at(retry(10 * second, 'soon')).nextAt, now + 60 * second);
  assert.deepEqual(
    [at(retry(2 * hour, 'much later')).state, at(retry(2 * hour, 'x')).deadReason],
    ['dead', 'expired']
  );
  assert.deepEqual(
    [at(failed('bad payload')).state, at(failed('bad payload')).deadReason],
    ['dead', 'failed']
  );
  assert.equal(at(skipped('email is off')).state, 'skipped');
  // A skip sends nothing: the claim's attempt (attempts 2 = 1 sent + this claim) is taken back.
  assert.equal(at(skipped('email is off')).attempts, 1);
  assert.deepEqual(
    [at(pause('401')).state, at(pause('401')).nextAt, at(pause('401')).lastError],
    ['held', now, '401']
  );
  // Unknown: resent per the channel's rule, counted, then a dead letter.
  const resend = { unknown: { resendAfterMs: 5 * minute, maxResends: 1 } };
  assert.deepEqual(
    [at(unknown('timeout'), resend).state, at(unknown('timeout'), resend).nextAt],
    ['queued', now + 5 * minute]
  );
  assert.equal(at(unknown('timeout'), resend).unknowns, 1);
  const again = rowAfterOutcome({ ...row, unknowns: 1 }, unknown('timeout'), {
    now,
    channel: resend,
  });
  assert.deepEqual([again.state, again.deadReason], ['dead', 'unknown']);
  // Without a rule: the backoff, at most three resends.
  assert.equal(at(unknown('timeout')).nextAt, now + 60 * second);
  assert.equal(
    rowAfterOutcome({ ...row, unknowns: 3 }, unknown('timeout'), { now }).deadReason,
    'unknown'
  );
});

test('channelAfterOutcome keeps health: the circuit opens after 5 failures in a row', () => {
  let status = initialChannelStatus();
  const now = 5000;
  for (let n = 1; n <= 4; n++) {
    status = channelAfterOutcome(status, retry(null, `failure ${n}`), { now });
    assert.equal(status.state, 'retrying');
    assert.equal(status.nextSendAt, 0);
  }
  status = channelAfterOutcome(status, unknown('timeout'), { now });
  assert.deepEqual(
    [status.state, status.nextSendAt, status.consecutiveFailures, status.failedTotal],
    ['circuit-open', now + minute, 5, 5]
  );
  status = channelAfterOutcome(status, retry(null, 'probe failed'), { now });
  assert.equal(status.nextSendAt, now + 2 * minute);
  assert.deepEqual(status.lastError, { time: now, message: 'probe failed' });
  // A refused message says nothing about the endpoint's health.
  const refused = channelAfterOutcome(status, failed('400'), { now });
  assert.deepEqual([refused.state, refused.consecutiveFailures], ['ok', 0]);
  const ok = channelAfterOutcome(status, accepted(), { now: now + 1 });
  assert.deepEqual(
    [ok.state, ok.consecutiveFailures, ok.nextSendAt, ok.deliveredTotal, ok.lastSuccess],
    ['ok', 0, 0, 1, now + 1]
  );
  const paused = channelAfterOutcome(ok, pause('401: check the URL'), { now });
  assert.deepEqual([paused.state, paused.pausedReason], ['paused', '401: check the URL']);
  // A pause that needs a change waits for it (nextSendAt 0); a transient one probes again after
  // circuitCapMs (D10). The pause keeps the time it began through later pauses (probes).
  assert.deepEqual([paused.pausedSince, paused.nextSendAt], [now, 0]);
  const transient = channelAfterOutcome(
    ok,
    pause('The webhook answered 404.', { transient: true }),
    {
      now,
    }
  );
  assert.deepEqual([transient.pausedSince, transient.nextSendAt], [now, now + 15 * minute]);
  const again = channelAfterOutcome(transient, pause('404 again', { transient: true }), {
    now: now + 15 * minute,
  });
  assert.deepEqual([again.pausedSince, again.nextSendAt], [now, now + 30 * minute]);
  // A refusal ends a pause and counts toward "refusing" (D29); an acceptance clears both.
  assert.deepEqual([refused.consecutiveRefusals, refused.pausedSince], [1, null]);
  const afterPause = channelAfterOutcome(again, failed('422'), { now });
  assert.deepEqual(
    [afterPause.state, afterPause.pausedSince, afterPause.pausedReason],
    ['ok', null, null]
  );
  const thrice = [failed('a'), failed('b'), failed('c')].reduce(
    (status, outcome) => channelAfterOutcome(status, outcome, { now }),
    ok
  );
  assert.equal(thrice.consecutiveRefusals, 3);
  assert.equal(channelAfterOutcome(thrice, accepted(), { now }).consecutiveRefusals, 0);
  // Nothing was attempted: health is unchanged.
  assert.deepEqual(channelAfterOutcome(ok, skipped('off'), { now: 9 }), ok);
});

test('429 and 503 with Retry-After hold the whole channel, up to an hour (D29)', () => {
  const now = 5000;
  const busy = channelAfterOutcome(
    initialChannelStatus(),
    retry(10 * minute, 'The webhook answered 429.', { status: 429 }),
    { now }
  );
  assert.deepEqual([busy.state, busy.nextSendAt], ['retrying', now + 10 * minute]);
  const capped = channelAfterOutcome(
    initialChannelStatus(),
    retry(5 * hour, 'The webhook answered 503.', { status: 503 }),
    { now }
  );
  assert.equal(capped.nextSendAt, now + hour);
  // Other answers keep Retry-After for the row only; no Retry-After keeps the channel open.
  for (const outcome of [
    retry(10 * minute, 'The webhook answered 500.', { status: 500 }),
    retry(null, 'The webhook answered 429.', { status: 429 }),
  ])
    assert.equal(channelAfterOutcome(initialChannelStatus(), outcome, { now }).nextSendAt, 0);
});

test('planDigest follows 1.4.2: 60 s without a new alert, or 180 s after the first', () => {
  const window = { windowMs: minute, maxFactor: 3 };
  const rows = times => times.map((createdAt, i) => ({ id: i + 1, uid: `d_${i}`, createdAt }));
  // Quiet for a minute: due.
  assert.deepEqual(planDigest(rows([0, 10 * second]), { now: 69 * second, ...window }), {
    batches: [],
    wakeAt: 70 * second,
  });
  assert.equal(
    planDigest(rows([0, 10 * second]), { now: 70 * second, ...window }).batches.length,
    1
  );
  // A steady stream still goes out 180 s after its first row.
  const stream = rows([0, 50, 100, 150, 175].map(s => s * second));
  assert.equal(planDigest(stream, { now: 179 * second, ...window }).wakeAt, 180 * second);
  assert.deepEqual(
    planDigest(stream, { now: 180 * second, ...window }).batches.map(batch => batch.length),
    [5]
  );
  // A batch already sent goes out again as it was; ignoreWindows sends at once; big windows split.
  const retried = [
    { id: 1, uid: 'a', createdAt: 0, digestKey: 'g_1' },
    { id: 2, uid: 'b', createdAt: 0, digestKey: 'g_1' },
    { id: 3, uid: 'c', createdAt: 100 * second },
  ];
  const plan = planDigest(retried, { now: 101 * second, ...window });
  assert.deepEqual(
    plan.batches.map(batch => batch.map(row => row.uid)),
    [['a', 'b']]
  );
  assert.equal(plan.wakeAt, 160 * second);
  assert.equal(
    planDigest(retried, { now: 101 * second, ...window, ignoreWindows: true }).batches.length,
    2
  );
  assert.deepEqual(
    planDigest(rows(Array(250).fill(0)), { now: minute, ...window }).batches.map(b => b.length),
    [100, 100, 50]
  );
  // A row created later than now was queued before the clock stepped back (D25): it counts as
  // having waited the whole cap, so the window does not stay open until the clock catches up.
  assert.equal(
    planDigest(rows([10 * hour, 10 * hour + 1]), { now: minute, ...window }).batches.length,
    1
  );
});

// ---------------------------------------------------------------------------------------------
// The worker

test('enqueue writes each (event, channel, target) once and validates entries', async t => {
  const webhook = scripted('env-webhook');
  const { outbox, store, clock } = setup(t, { channels: [webhook.channel] });
  const first = await outbox.enqueue([entry({ eventUid: 'ev-a' }), entry({ eventUid: 'ev-b' })]);
  assert.equal(first.inserted, 2);
  assert.deepEqual(first.uids, [
    deliveryUid('ev-a', 'env-webhook'),
    deliveryUid('ev-b', 'env-webhook'),
  ]);
  // The relay may run again after a crash: nothing is written twice.
  const again = await outbox.enqueue(entry({ eventUid: 'ev-a' }));
  assert.deepEqual([again.inserted, again.duplicates], [0, 1]);
  const row = await rowFor(store, 'ev-a');
  assert.equal(row.state, 'queued');
  assert.equal(row.createdAt, clock.wall());
  assert.equal(row.expiresAt, clock.wall() + 24 * hour);
  assert.equal(row.severity, null);
  // Per-entry maximum age and creation time (the event's own time when relayed later).
  await outbox.enqueue(
    entry({ eventUid: 'ev-old', createdAt: clock.wall() - hour, maxAgeMs: 2 * hour })
  );
  assert.equal((await rowFor(store, 'ev-old')).expiresAt, clock.wall() + hour);
  for (const bad of [
    { eventUid: '' },
    { channelId: 'Not Valid' },
    { kind: 'Firing!' },
    { event: null },
    { event: ['list'] },
    { event: { message: 'é'.repeat(SNAPSHOT_LIMIT / 2) } },
  ])
    await assert.rejects(outbox.enqueue(entry(bad)), TypeError, JSON.stringify(bad).slice(0, 60));
  // Nothing of a refused batch is written.
  assert.equal((await rowsOf(store)).length, 3);
});

test('a due row is sent once, with its stable delivery id, and recorded as delivered', async t => {
  const webhook = scripted('env-webhook');
  const { outbox, store } = setup(t, { channels: [webhook.channel] });
  await outbox.enqueue(entry({ eventUid: 'ev-sent', severity: 'critical' }));
  await drain(outbox);
  assert.equal(webhook.sent.length, 1);
  assert.deepEqual(webhook.sent[0], {
    uid: deliveryUid('ev-sent', 'env-webhook'),
    channelId: 'env-webhook',
    target: '',
    kind: 'firing',
    attempt: 1,
    digest: false,
    events: [{ service: 'plex', kind: 'firing', message: 'Source is unavailable' }],
  });
  const row = await rowFor(store, 'ev-sent');
  assert.deepEqual(
    [row.state, row.attempts, row.lastStatus, row.leaseOwner],
    ['delivered', 1, 200, null]
  );
  const status = await outbox.status();
  assert.equal(status.counts.delivered, 1);
  assert.equal(status.channels['env-webhook'].deliveredTotal, 1);
  assert.equal(status.channels['env-webhook'].known, true);
  // Nothing more to do.
  await drain(outbox);
  assert.equal(webhook.sent.length, 1);
});

test('500, 500, 200: retried with backoff and delivered on the third attempt', async t => {
  const webhook = scripted('env-webhook', [
    retry(null, 'The webhook answered 500.', { status: 500 }),
    retry(null, 'The webhook answered 500.', { status: 500 }),
  ]);
  const { outbox, store, clock } = setup(t, { channels: [webhook.channel] });
  await outbox.enqueue(entry({ eventUid: 'ev-retry' }));
  await drain(outbox);
  let row = await rowFor(store, 'ev-retry');
  assert.deepEqual(
    [row.state, row.attempts, row.lastError],
    ['queued', 1, 'The webhook answered 500.']
  );
  assert.equal(row.nextAt, clock.wall() + 30 * second);
  const status = await outbox.status();
  assert.equal(status.channels['env-webhook'].state, 'retrying');
  assert.equal((await outbox.pump()).wakeAt, row.nextAt);
  await clock.advance(30 * second - 1);
  await drain(outbox);
  assert.equal(webhook.sent.length, 1);
  await clock.advance(1);
  await drain(outbox);
  row = await rowFor(store, 'ev-retry');
  assert.equal(row.nextAt, clock.wall() + 60 * second);
  await clock.advance(60 * second);
  await drain(outbox);
  row = await rowFor(store, 'ev-retry');
  assert.deepEqual([row.state, row.attempts, row.lastError], ['delivered', 3, null]);
  assert.deepEqual(
    webhook.sent.map(message => [message.uid, message.attempt]),
    [1, 2, 3].map(n => [deliveryUid('ev-retry', 'env-webhook'), n])
  );
  assert.equal((await outbox.status()).channels['env-webhook'].state, 'ok');
});

test('a recovery never overtakes its firing; other alerts are not held up', async t => {
  const webhook = scripted('env-webhook', [retry(null, 'down')]);
  const { outbox, store, clock } = setup(t, { channels: [webhook.channel] });
  const key = 'plex\n__availability';
  await outbox.enqueue(entry({ eventUid: 'fire', orderKey: key }));
  await drain(outbox);
  await outbox.enqueue([
    entry({ eventUid: 'recover', orderKey: key, kind: 'resolved' }),
    entry({ eventUid: 'nas', orderKey: 'nas\n__availability' }),
  ]);
  await drain(outbox);
  // The firing waits for its retry; its recovery waits behind it; the other alert went out.
  assert.deepEqual(
    webhook.sent.map(message => message.uid),
    [deliveryUid('fire', 'env-webhook'), deliveryUid('nas', 'env-webhook')]
  );
  assert.equal((await rowFor(store, 'recover')).state, 'queued');
  await clock.advance(30 * second);
  await drain(outbox);
  assert.deepEqual(
    webhook.sent.slice(2).map(message => message.uid),
    [deliveryUid('fire', 'env-webhook'), deliveryUid('recover', 'env-webhook')]
  );
});

test('one send per channel and four in all; channels do not wait for each other', async t => {
  const releases = [];
  const block = () => new Promise(resolve => releases.push(() => resolve(accepted())));
  const channels = ['a', 'b', 'c', 'd', 'e'].map(name =>
    scripted(`ch-${name}`, [block, block], name === 'a' ? { concurrency: 2 } : {})
  );
  const { outbox } = setup(t, { channels: channels.map(c => c.channel) });
  for (const c of channels)
    await outbox.enqueue([
      entry({ channelId: c.channel.name }),
      entry({ channelId: c.channel.name }),
    ]);
  await outbox.pump();
  await settle();
  // ch-a may send two at once; the others one each; four in all.
  assert.deepEqual(
    channels.map(c => c.sent.length),
    [2, 1, 1, 0, 0]
  );
  assert.equal(outbox.inFlight, 4);
  releases.shift()();
  await settle();
  await outbox.pump();
  await settle();
  assert.equal(outbox.inFlight, 4);
  assert.deepEqual(
    channels.map(c => c.sent.length),
    [2, 1, 1, 1, 0]
  );
  while (releases.length) {
    releases.shift()();
    await settle();
    await outbox.pump();
    await settle();
  }
  await drain(outbox);
  assert.deepEqual(
    channels.map(c => c.sent.length),
    [2, 2, 2, 2, 2]
  );
});

test('rows that cannot be sent before they expire become dead letters', async t => {
  const webhook = scripted('env-webhook', [retry(null, 'down'), retry(null, 'down')]);
  const { outbox, store, clock } = setup(t, {
    channels: [{ ...webhook.channel, maxAgeMs: 45 * second }],
  });
  await outbox.enqueue(entry({ eventUid: 'short-lived' }));
  await drain(outbox);
  await clock.advance(30 * second);
  await drain(outbox);
  // The next retry (60 s) would come after the row expires: dead now, not later.
  let row = await rowFor(store, 'short-lived');
  assert.deepEqual([row.state, row.deadReason, row.lastError], ['dead', 'expired', 'down']);
  // A row that waits (here: held by a paused channel) expires on its own.
  await outbox.pause('env-webhook', 'Paused while the receiver is replaced.');
  await outbox.enqueue(entry({ eventUid: 'waiting' }));
  assert.equal((await rowFor(store, 'waiting')).state, 'held');
  await clock.advance(45 * second);
  assert.equal((await outbox.pump()).expired, 1);
  row = await rowFor(store, 'waiting');
  assert.deepEqual([row.state, row.deadReason], ['dead', 'expired']);
  assert.equal(webhook.sent.length, 2);
});

test('a pause outcome holds the channel until it is resumed, then everything goes', async t => {
  const webhook = scripted('env-webhook', [pause('The webhook answered 401.', { status: 401 })]);
  const email = scripted('email');
  const { outbox, store } = setup(t, { channels: [webhook.channel, email.channel] });
  await outbox.enqueue([entry({ eventUid: 'w1' }), entry({ eventUid: 'w2' })]);
  await drain(outbox);
  assert.equal(webhook.sent.length, 1);
  assert.deepEqual(
    (await rowsOf(store)).map(row => row.state),
    ['held', 'held']
  );
  let status = await outbox.status();
  assert.deepEqual(
    [status.channels['env-webhook'].state, status.channels['env-webhook'].pausedReason],
    ['paused', 'The webhook answered 401.']
  );
  // New rows for a paused channel wait too; other channels carry on.
  await outbox.enqueue([entry({ eventUid: 'w3' }), entry({ eventUid: 'm1', channelId: 'email' })]);
  await drain(outbox);
  assert.equal((await rowFor(store, 'w3')).state, 'held');
  assert.equal(email.sent.length, 1);
  assert.equal(webhook.sent.length, 1);
  // Resume: held rows go out at once, in order.
  assert.equal(await outbox.resume('env-webhook'), 3);
  await drain(outbox);
  assert.deepEqual(
    webhook.sent.slice(1).map(message => message.uid),
    ['w1', 'w2', 'w3'].map(uid => deliveryUid(uid, 'env-webhook'))
  );
  status = await outbox.status();
  assert.equal(status.channels['env-webhook'].state, 'ok');
  assert.equal(status.counts.delivered, 4);
});

test('a settings change cancels the send in flight and sends again with the new settings', async t => {
  const settings = { password: 'old' };
  const used = [];
  const email = scripted('email', [
    // The first attempt hangs until cancelled; nothing was sent.
    hang(),
  ]);
  const channel = {
    ...email.channel,
    async send(message, context) {
      used.push(settings.password);
      return email.channel.send(message, context);
    },
  };
  const { outbox, store, clock } = setup(t, { channels: [channel] });
  await outbox.enqueue(entry({ eventUid: 'm1', channelId: 'email' }));
  await outbox.pump();
  await settle();
  assert.equal(outbox.inFlight, 1);
  settings.password = 'new';
  assert.equal(await outbox.channelChanged('email'), 1);
  assert.equal(outbox.inFlight, 0);
  // The cancelled attempt was a retry, and the change made it due at once.
  const row = await rowFor(store, 'm1');
  assert.deepEqual([row.state, row.nextAt], ['queued', clock.wall()]);
  await drain(outbox);
  assert.deepEqual(used, ['old', 'new']);
  assert.equal((await rowFor(store, 'm1')).state, 'delivered');
});

test('after 5 failures in a row the circuit opens, then lets a single probe through', async t => {
  const down = () => retry(null, 'Uptime Goblin could not connect.');
  const webhook = scripted('env-webhook', Array(6).fill(down), { concurrency: 2 });
  const { outbox, clock } = setup(t, { channels: [webhook.channel] });
  await outbox.enqueue(Array.from({ length: 8 }, () => entry()));
  for (let i = 0; i < 3; i++) {
    await outbox.pump();
    await settle();
  }
  // Two sends at a time until five failed in a row (the sixth was already in flight).
  assert.equal(webhook.sent.length, 6);
  let health = (await outbox.status()).channels['env-webhook'];
  assert.equal(health.state, 'circuit-open');
  const reopensAt = health.nextSendAt;
  assert.equal(reopensAt, clock.wall() + 2 * minute);
  await clock.advance(reopensAt - clock.wall() - 1);
  await drain(outbox);
  assert.equal(webhook.sent.length, 6);
  await clock.advance(1);
  // One probe, although the channel may send two at a time.
  await outbox.pump();
  assert.equal(outbox.inFlight, 1);
  await settle();
  health = (await outbox.status()).channels['env-webhook'];
  assert.equal(health.state, 'ok');
  await drain(outbox);
  // The probe and the seven other rows (all due by now).
  assert.equal(webhook.sent.length, 6 + 1 + 7);
});

test('acceptance unknown: resent per the channel rule, then a dead letter', async t => {
  const webhook = scripted('env-webhook', [
    unknown('The request timed out. The webhook may have received the alert.'),
    unknown('again'),
  ]);
  const { outbox, store, clock } = setup(t, {
    channels: [{ ...webhook.channel, unknown: { resendAfterMs: 30 * second, maxResends: 1 } }],
  });
  await outbox.enqueue(entry({ eventUid: 'maybe' }));
  await drain(outbox);
  let row = await rowFor(store, 'maybe');
  assert.deepEqual(
    [row.state, row.unknowns, row.nextAt],
    ['queued', 1, clock.wall() + 30 * second]
  );
  await clock.advance(30 * second);
  await drain(outbox);
  row = await rowFor(store, 'maybe');
  assert.deepEqual([row.state, row.deadReason, row.lastError], ['dead', 'unknown', 'again']);
  // Both sends carried the same delivery id, so a receiver can drop the duplicate.
  assert.deepEqual(new Set(webhook.sent.map(message => message.uid)).size, 1);
});

test('failed and skipped outcomes end the row; a throwing or invalid channel is a retry', async t => {
  const webhook = scripted('env-webhook', [
    failed('The webhook refused the alert (400).', { status: 400 }),
    skipped('GOBLIN_WEBHOOK_URL is not set.'),
    () => {
      throw new Error('bug in https://hooks.example.test/secret-path');
    },
    { type: 'maybe' },
  ]);
  const { outbox, store, logger } = setup(t, { channels: [webhook.channel] });
  await outbox.enqueue([
    entry({ eventUid: 'refused' }),
    entry({ eventUid: 'nothing' }),
    entry({ eventUid: 'throws' }),
    entry({ eventUid: 'invalid' }),
  ]);
  await drain(outbox);
  const states = Object.fromEntries(
    (await rowsOf(store)).map(row => [row.eventUid, [row.state, row.deadReason, row.lastError]])
  );
  assert.deepEqual(states, {
    refused: ['dead', 'failed', 'The webhook refused the alert (400).'],
    nothing: ['skipped', null, 'GOBLIN_WEBHOOK_URL is not set.'],
    throws: ['queued', null, 'The env-webhook channel failed unexpectedly.'],
    invalid: ['queued', null, 'The channel returned an invalid result.'],
  });
  const status = await outbox.status();
  assert.match(status.lastError.message, /env-webhook channel threw: bug in \[url\]/);
  assert.ok(!JSON.stringify(logger.lines).includes('secret-path'));
});

test('a recovery replaces the reminders still waiting for its alert', async t => {
  const webhook = scripted('env-webhook', [retry(null, 'down')]);
  const { outbox, store } = setup(t, { channels: [webhook.channel] });
  const key = 'plex\n__availability';
  await outbox.enqueue(entry({ eventUid: 'fire', orderKey: key }));
  await drain(outbox);
  await outbox.enqueue([
    entry({ eventUid: 'rem:1', orderKey: key, kind: 'reminder' }),
    entry({ eventUid: 'rem:2', orderKey: key, kind: 'reminder' }),
  ]);
  assert.equal((await rowFor(store, 'rem:1')).state, 'superseded');
  const result = await outbox.enqueue(entry({ eventUid: 'ok', orderKey: key, kind: 'resolved' }));
  assert.equal(result.superseded, 1);
  assert.deepEqual(
    (await rowsOf(store)).map(row => [row.eventUid, row.state]),
    [
      ['fire', 'queued'],
      ['rem:1', 'superseded'],
      ['rem:2', 'superseded'],
      ['ok', 'queued'],
    ]
  );
});

test('email digests: one message per quiet window, retried as the same batch', async t => {
  const email = scripted('email', [retry(null, 'The mail server did not respond in time.')], {
    digest: { windowMs: minute, maxFactor: 3 },
  });
  const { outbox, store, clock } = setup(t, { channels: [email.channel] });
  const mail = (uid, kind = 'firing') =>
    entry({ eventUid: uid, channelId: 'email', kind, orderKey: `${uid.split('-')[0]}\nrule` });
  await outbox.enqueue(mail('plex-fire'));
  await clock.advance(20 * second);
  await outbox.enqueue(mail('nas-fire'));
  await clock.advance(20 * second);
  await outbox.enqueue(mail('plex-ok', 'resolved'));
  // Not yet: 60 s without a new alert.
  assert.equal((await outbox.pump()).wakeAt, clock.wall() + minute);
  await clock.advance(minute - 1);
  await drain(outbox);
  assert.equal(email.sent.length, 0);
  await clock.advance(1);
  await drain(outbox);
  assert.equal(email.sent.length, 1);
  const [first] = email.sent;
  assert.equal(first.kind, 'digest');
  assert.equal(first.digest, true);
  assert.equal(first.events.length, 3);
  // The retry sends the very same batch (same id), even though another alert came meanwhile.
  await outbox.enqueue(mail('dns-fire'));
  await clock.advance(30 * second);
  await drain(outbox);
  assert.equal(email.sent.length, 2);
  assert.equal(email.sent[1].uid, first.uid);
  assert.equal(email.sent[1].events.length, 3);
  assert.equal(email.sent[1].attempt, 2);
  // The newer alert waits for its own window, then goes alone.
  await clock.advance(minute);
  await drain(outbox);
  assert.equal(email.sent.length, 3);
  assert.equal(email.sent[2].kind, 'firing');
  assert.equal(email.sent[2].digest, false);
  assert.equal((await rowsOf(store, { state: 'delivered' })).length, 4);
});

test('flush() sends digest windows at once and waits; retries are not waited for', async t => {
  const email = scripted('email', [], { digest: { windowMs: minute } });
  const webhook = scripted('env-webhook', [retry(null, 'down')]);
  const { outbox } = setup(t, { channels: [email.channel, webhook.channel] });
  await outbox.enqueue([
    entry({ channelId: 'email' }),
    entry({ channelId: 'email' }),
    entry({ channelId: 'env-webhook' }),
  ]);
  assert.equal(await outbox.flush(), true);
  assert.equal(email.sent.length, 1);
  assert.equal(email.sent[0].events.length, 2);
  assert.equal(webhook.sent.length, 1);
  assert.equal(outbox.inFlight, 0);
});

test('the backlog cap refuses new rows except on digest channels, and says so', async t => {
  const email = scripted('email', [], { digest: { windowMs: minute } });
  const webhook = scripted('env-webhook');
  const { outbox, store, logger } = setup(t, {
    channels: [email.channel, webhook.channel],
    maxActive: 3,
  });
  const result = await outbox.enqueue([
    entry({ eventUid: 'w1' }),
    entry({ eventUid: 'w2' }),
    entry({ eventUid: 'w3' }),
    entry({ eventUid: 'w4' }),
    entry({ eventUid: 'm1', channelId: 'email' }),
  ]);
  assert.deepEqual([result.inserted, result.dropped], [4, 1]);
  assert.deepEqual(
    (await rowsOf(store)).map(row => row.eventUid),
    ['w1', 'w2', 'w3', 'm1']
  );
  assert.equal((await outbox.status()).dropped, 1);
  assert.match(logger.lines.error[0], /backlog is full \(3 waiting\); 1 notification/);
});

test('the backlog cap counts each channel’s own rows: an email backlog never refuses webhook rows', async t => {
  // Email paused (its sign-in failed) keeps every row for a day, and digest rows are never
  // refused. Counted together, its backlog alone filled the cap, and the webhook, working all
  // along, then dropped every new alert.
  const email = scripted('email', [pause('Email sign-in failed.')], {
    digest: { windowMs: minute },
  });
  const webhook = scripted('env-webhook');
  const { outbox, store, clock, logger } = setup(t, {
    channels: [email.channel, webhook.channel],
    maxActive: 3,
  });
  await outbox.enqueue(entry({ eventUid: 'm0', channelId: 'email' }));
  await clock.advance(minute);
  await drain(outbox);
  for (let i = 1; i <= 5; i++)
    await outbox.enqueue(entry({ eventUid: `m${i}`, channelId: 'email' }));
  assert.equal((await store.summary()).email.held, 6, 'over the cap, all held');
  const result = await outbox.enqueue([
    entry({ eventUid: 'm6', channelId: 'email' }),
    entry({ eventUid: 'w1', orderKey: 'nas\n__availability' }),
  ]);
  assert.deepEqual([result.inserted, result.dropped], [2, 0]);
  await drain(outbox);
  assert.deepEqual(
    webhook.sent.map(message => message.uid),
    [deliveryUid('w1', 'env-webhook')]
  );
  assert.equal(logger.lines.error.length, 0);
  // The webhook's own backlog is still capped: paused, it holds three, and the fourth is refused.
  webhook.queue.push(pause('The webhook answered 404.', { transient: true }));
  await outbox.enqueue(entry({ eventUid: 'w2' }));
  await drain(outbox);
  await outbox.enqueue([entry({ eventUid: 'w3' }), entry({ eventUid: 'w4' })]);
  const full = await outbox.enqueue([
    entry({ eventUid: 'w5' }),
    entry({ eventUid: 'm7', channelId: 'email' }),
  ]);
  assert.deepEqual([full.inserted, full.dropped], [1, 1]);
  assert.equal(await rowFor(store, 'w5'), undefined);
  assert.equal((await rowFor(store, 'm7')).state, 'held');
  assert.match(
    logger.lines.error[0],
    /^The env-webhook notification backlog is full \(3 waiting\); 1 notification/
  );
  assert.equal(outbox.dropped, 1);

  // When the per-channel counts cannot be read, the total counts for every channel (as one
  // shared cap): more is refused, never less.
  const inner = createMemoryOutboxStore();
  const unreadable = {
    ...inner,
    summary: async () => {
      throw new Error('disk I/O error');
    },
  };
  const other = setup(t, {
    channels: [
      scripted('email', [], { digest: { windowMs: minute } }).channel,
      scripted('env-webhook').channel,
    ],
    maxActive: 3,
    store: unreadable,
  });
  await other.outbox.enqueue([1, 2, 3].map(i => entry({ eventUid: `x${i}`, channelId: 'email' })));
  const shared = await other.outbox.enqueue(entry({ eventUid: 'y1' }));
  assert.deepEqual([shared.inserted, shared.dropped], [0, 1]);
  assert.match(
    other.logger.lines.error.join('\n'),
    /could not be counted per channel: disk I\/O error/
  );
});

test('the backlog-cap line comes at most once a minute per channel and counts every refusal; each channel keeps its count and time (A46, A47)', async t => {
  const email = scripted('email', [], { digest: { windowMs: minute } });
  const webhook = scripted('env-webhook');
  const { outbox, clock, logger } = setup(t, {
    channels: [email.channel, webhook.channel],
    maxActive: 3,
  });
  const line = (count, more = false) =>
    `The env-webhook notification backlog is full (3 waiting); ${count} ${more ? 'more ' : ''}notification(s) were not queued.`;
  for (let i = 1; i <= 3; i++) await outbox.enqueue(entry({ eventUid: `w${i}` }));
  // A flood against the full backlog: one line, not one per alert.
  for (let i = 0; i < 100; i++) await outbox.enqueue(entry({ eventUid: `x${i}` }));
  assert.deepEqual(logger.lines.error, [line(1)]);
  assert.equal(outbox.dropped, 100);
  assert.deepEqual(outbox.notQueued('env-webhook'), { count: 100, lastAt: clock.wall() });
  // Email rows are never refused, and email has nothing to say.
  await outbox.enqueue(entry({ eventUid: 'm1', channelId: 'email' }));
  assert.deepEqual(outbox.notQueued('email'), { count: 0, lastAt: null });
  // A minute on, the next refusal is logged with those held back, in one line.
  await clock.advance(minute);
  await outbox.enqueue(entry({ eventUid: 'y1' }));
  assert.deepEqual(logger.lines.error, [line(1), line(100, true)]);
  assert.deepEqual(outbox.notQueued('env-webhook'), { count: 101, lastAt: clock.wall() });
  // Held back again, and no further alert comes: the first pass after the minute logs them.
  for (let i = 0; i < 5; i++) await outbox.enqueue(entry({ eventUid: `z${i}` }));
  await clock.advance(30 * 1000);
  await outbox.pump();
  assert.equal(logger.lines.error.length, 2, 'not before the minute is over');
  await clock.advance(30 * 1000);
  await outbox.pump();
  assert.deepEqual(logger.lines.error, [line(1), line(100, true), line(5, true)]);
  // The backlog empties and fills again after a quiet minute: a new line, without "more".
  await drain(outbox);
  await clock.advance(minute);
  for (let i = 4; i <= 7; i++) await outbox.enqueue(entry({ eventUid: `w${i}` }));
  assert.deepEqual(logger.lines.error, [line(1), line(100, true), line(5, true), line(1)]);
  assert.equal(outbox.dropped, 107);
  const other = setup(t, { channels: [scripted('env-webhook').channel], maxActive: 1 });
  await other.outbox.enqueue(entry({ eventUid: 'a1' }));
  for (let i = 0; i < 3; i++) await other.outbox.enqueue(entry({ eventUid: `b${i}` }));
  assert.deepEqual(other.logger.lines.error, [
    'The env-webhook notification backlog is full (1 waiting); 1 notification(s) were not queued.',
  ]);
  // stop() logs what the log has not said yet, before the process may end.
  await other.outbox.stop({ timeoutMs: 0 });
  assert.deepEqual(other.logger.lines.error, [
    'The env-webhook notification backlog is full (1 waiting); 1 notification(s) were not queued.',
    'The env-webhook notification backlog is full (1 waiting); 2 more notification(s) were not queued.',
  ]);
});

test('rows of a channel this release does not know are kept and never crowd out others', async t => {
  const webhook = scripted('env-webhook');
  const { outbox, store, clock } = setup(t, { channels: [webhook.channel], candidateLimit: 5 });
  // Written by a newer release (a channel type 1.5 does not have), ahead of a known row.
  await store.insert(
    Array.from({ length: 20 }, (_, i) =>
      outboxRow({ eventUid: `future-${i}`, channelId: 'matrix', createdAt: clock.wall() })
    )
  );
  await outbox.enqueue(entry({ eventUid: 'known' }));
  await drain(outbox);
  assert.equal(webhook.sent.length, 1);
  assert.equal((await rowsOf(store, { channelId: 'matrix', state: 'queued' })).length, 20);
  const status = await outbox.status();
  assert.equal(status.channels.matrix.known, false);
  assert.equal(status.channels.matrix.counts.queued, 20);
});

test('a stale completion changes nothing: another worker owns the rows now', async t => {
  let release;
  const webhook = scripted('env-webhook', [
    () => new Promise(resolve => (release = () => resolve(accepted()))),
  ]);
  const { outbox, store, logger, clock } = setup(t, { channels: [webhook.channel] });
  await outbox.enqueue(entry({ eventUid: 'contested' }));
  await outbox.pump({ epoch: 1 });
  await settle();
  // Meanwhile another worker (a new leader) took the row over.
  const [row] = await store.sending();
  await store.complete(
    [{ id: row.id, patch: { state: 'queued', leaseOwner: null, leaseUntil: null } }],
    { owner: 'o_test', epoch: 1 }
  );
  await store.claim([row.id], {
    owner: 'o_other',
    epoch: 2,
    now: clock.wall(),
    leaseUntil: clock.wall() + minute,
  });
  release();
  await settle();
  const after = await rowFor(store, 'contested');
  assert.deepEqual([after.state, after.leaseOwner, after.epoch], ['sending', 'o_other', 2]);
  assert.match(logger.lines.warn[0], /not recorded: another worker owns those rows/);
  // The channel's health was not touched by a result that was not recorded.
  assert.equal((await outbox.status()).channels['env-webhook'].deliveredTotal, 0);
});

test('restart continuity: queued, retrying, windowed and in-flight rows are delivered by the next process', async t => {
  const clock = fakeClock(),
    store = createMemoryOutboxStore();
  // The first process: a webhook row retrying, an email row in its window, and a webhook send
  // that never finishes because the process is killed.
  const before = {
    webhook: scripted('env-webhook', [
      retry(null, 'down'),
      hang(unknown('Uptime Goblin stopped.')),
    ]),
    email: scripted('email', [], { digest: { windowMs: minute } }),
  };
  const first = setup(t, {
    clock,
    store,
    owner: 'o_first',
    channels: [before.webhook.channel, before.email.channel],
  });
  await first.outbox.enqueue([
    entry({ eventUid: 'retrying' }),
    entry({ eventUid: 'windowed', channelId: 'email' }),
  ]);
  await first.outbox.pump();
  await settle();
  await first.outbox.enqueue(entry({ eventUid: 'in-flight', orderKey: 'k' }));
  await first.outbox.pump();
  await settle();
  assert.equal(before.webhook.sent.length, 2);
  // SIGKILL: the process is gone without stop(); its send never completes.
  const states = Object.fromEntries((await rowsOf(store)).map(row => [row.eventUid, row.state]));
  assert.deepEqual(states, { retrying: 'queued', windowed: 'queued', 'in-flight': 'sending' });

  // The next process (another owner) starts its delivery worker on the same store.
  const after = {
    webhook: scripted('env-webhook'),
    email: scripted('email', [], { digest: { windowMs: minute } }),
  };
  const second = setup(t, {
    clock,
    store,
    owner: 'o_second',
    channels: [
      { ...after.webhook.channel, unknown: { resendAfterMs: 0, maxResends: 3 } },
      after.email.channel,
    ],
  });
  const controller = new AbortController();
  const running = second.outbox.run({ signal: controller.signal, epoch: 1 });
  await clock.advance(2 * minute);
  controller.abort();
  await running;
  assert.deepEqual(
    (await rowsOf(store)).map(row => [row.eventUid, row.state]),
    [
      ['retrying', 'delivered'],
      ['windowed', 'delivered'],
      ['in-flight', 'delivered'],
    ]
  );
  // The interrupted send counted as "acceptance unknown" and was sent again, with the same id.
  const resent = after.webhook.sent.find(m => m.uid === deliveryUid('in-flight', 'env-webhook'));
  assert.equal(resent.attempt, 2);
  assert.equal(after.email.sent.length, 1);
});

test('stop() lets sends finish, then cancels them; nothing is claimed afterwards', async t => {
  let release;
  const webhook = scripted('env-webhook', [
    () => new Promise(resolve => (release = () => resolve(accepted()))),
    hang(unknown('Cancelled mid-request.')),
  ]);
  const { outbox, store, clock } = setup(t, { channels: [webhook.channel] });
  await outbox.enqueue(entry({ eventUid: 'finishes' }));
  await outbox.pump();
  await settle();
  const stopping = outbox.stop({ timeoutMs: 8000 });
  await settle();
  release();
  assert.deepEqual(await stopping, { cancelled: 0, unsettled: 0 });
  assert.equal((await rowFor(store, 'finishes')).state, 'delivered');
  await outbox.enqueue(entry({ eventUid: 'after-stop' }));
  assert.equal((await outbox.pump()).started, 0);
  assert.equal((await rowFor(store, 'after-stop')).state, 'queued');

  // A send still running when the time is up is cancelled; mid-request it is "unknown".
  const other = setup(t, {
    channels: [scripted('env-webhook', [hang(unknown('Cancelled mid-request.'))]).channel],
    clock,
  });
  await other.outbox.enqueue(entry({ eventUid: 'cancelled' }));
  await other.outbox.pump();
  await settle();
  const stopped = other.outbox.stop({ timeoutMs: 8000 });
  await clock.advance(8000);
  assert.deepEqual(await stopped, { cancelled: 1, unsettled: 0 });
  const row = await rowFor(other.store, 'cancelled');
  assert.deepEqual([row.state, row.unknowns], ['queued', 1]);
});

test('the delivery worker as a leader task: sends while leading, stops sending on demotion', async t => {
  const clock = fakeClock(),
    leader = createLocalLeader();
  const jobs = createJobRunner({ clock, leader, logger: quietLogger() });
  t.after(() => jobs.stop({ timeoutMs: 0 }));
  let inFlight = null;
  const webhook = scripted('env-webhook', [
    accepted(),
    (message, { signal }) =>
      new Promise(resolve => {
        inFlight = signal;
        signal.addEventListener('abort', () => resolve(retry(null, 'Cancelled.')), { once: true });
      }),
  ]);
  const { outbox, store } = setup(t, { clock, channels: [webhook.channel] });
  jobs.leaderTask('notify.delivery', ctx => outbox.run(ctx));
  await clock.advance(0);
  await outbox.enqueue(entry({ eventUid: 'first' }));
  await clock.advance(10);
  assert.equal((await rowFor(store, 'first')).state, 'delivered');
  await outbox.enqueue(entry({ eventUid: 'second' }));
  await clock.advance(10);
  assert.ok(inFlight && !inFlight.aborted);
  // Demoted (HA): the send in flight is cancelled and nothing new is claimed.
  leader.demote();
  await clock.advance(10);
  assert.equal(inFlight.aborted, true);
  assert.equal((await rowFor(store, 'second')).state, 'queued');
  await outbox.enqueue(entry({ eventUid: 'third' }));
  await clock.advance(5 * minute);
  assert.equal(webhook.sent.length, 2);
  // Leading again (a new epoch): delivery resumes.
  leader.promote();
  await clock.advance(minute);
  assert.equal((await rowFor(store, 'second')).state, 'delivered');
  assert.equal((await rowFor(store, 'third')).state, 'delivered');
  const [job] = jobs.status();
  assert.equal(job.name, 'notify.delivery');
  assert.equal(job.kind, 'continuous');
});

test('retention: finished rows 7 days (50,000), dead rows 30 days (5,000)', async t => {
  const store = createMemoryOutboxStore();
  let seen;
  const spy = {
    ...store,
    prune: async options => {
      seen = options;
      return store.prune(options);
    },
  };
  const { outbox, clock } = setup(t, { store: spy });
  await outbox.prune({ limit: 250 });
  assert.deepEqual(seen, {
    now: clock.wall(),
    finished: { maxAgeMs: 7 * 24 * hour, maxRows: 50000 },
    dead: { maxAgeMs: 30 * 24 * hour, maxRows: 5000 },
    limit: 250,
  });
});

test('lib/notify/index.mjs exports the whole delivery surface', () => {
  for (const name of [
    'createOutbox',
    'createMemoryOutboxStore',
    'createFailoverStore',
    'createEnvWebhookChannel',
    'createEmailChannel',
    'defineChannel',
    'signWebhook',
    'signWebhookAll',
    'verifyWebhookSignature',
    'newEventUid',
    'classifyWebhookResponse',
    'classifyMailError',
    'post',
    'retryDelayMs',
  ])
    assert.equal(typeof notify[name], 'function', name);
  assert.match(notify.newEventUid(), /^e_[a-z2-7]{26}$/);
  assert.notEqual(notify.newEventUid(), notify.newEventUid());
  assert.deepEqual(notify.ENV_WEBHOOK_UNKNOWN, { resendAfterMs: 120000, maxResends: 1 });
});

test('a store failing on every pass is logged once a minute, and the worker keeps going', async t => {
  const store = createMemoryOutboxStore();
  let failing = true;
  const flaky = {
    ...store,
    candidates: async options => {
      if (failing) throw Object.assign(new Error('database is locked'), { code: 'SQLITE_BUSY' });
      return store.candidates(options);
    },
  };
  const webhook = scripted('env-webhook');
  const { outbox, clock, logger } = setup(t, { store: flaky, channels: [webhook.channel] });
  await outbox.enqueue(entry({ eventUid: 'waits' }));
  const controller = new AbortController();
  const running = outbox.run({ signal: controller.signal });
  await clock.advance(150 * second);
  assert.equal(logger.lines.error.length, 3);
  assert.match(logger.lines.error[0], /could not read its queue: database is locked/);
  assert.equal((await outbox.status()).lastError.message, logger.lines.error[0]);
  failing = false;
  await clock.advance(second);
  assert.equal(webhook.sent.length, 1);
  controller.abort();
  await running;
  await assert.rejects(outbox.enqueue(entry({ maxAgeMs: -1 })), /maxAgeMs/);
});

// ---------------------------------------------------------------------------------------------
// Delivery spec §5.6: probes, rechecks, stopping during a claim, Retry now, test emails, clock
// steps

const orderKey = 'plex\n__availability';
const statusOf = async (outbox, id = 'env-webhook') => (await outbox.status()).channels[id];

test('onChannel sees every committed channel-status change, before and after', async t => {
  const changes = [];
  const webhook = scripted('env-webhook', [pause('The webhook answered 401.', { status: 401 })]);
  const { outbox } = setup(t, {
    channels: [webhook.channel],
    onChannel: change => changes.push(change),
  });
  await outbox.enqueue(entry({ eventUid: 'p1' }));
  await drain(outbox);
  assert.equal(changes.length, 1);
  assert.equal(changes[0].channelId, 'env-webhook');
  assert.equal(changes[0].previous.pausedSince, null);
  assert.equal(changes[0].next.state, 'paused');
  assert.equal(typeof changes[0].next.pausedSince, 'number');
  await outbox.resume('env-webhook');
  assert.equal(changes.at(-1).previous.state, 'paused');
  assert.equal(changes.at(-1).next.pausedSince, null);
  // A listener that throws is logged, never fatal.
  const failing = setup(t, {
    channels: [scripted('env-webhook').channel],
    onChannel: () => {
      throw new Error('listener bug');
    },
  });
  await failing.outbox.enqueue(entry());
  await drain(failing.outbox);
  assert.match(failing.logger.lines.error[0], /channel status listener failed: listener bug/);
});

test('a transient pause probes one held row every 15 minutes; an answer resumes the channel', async t => {
  const notFound = () => pause('The webhook answered 404.', { status: 404, transient: true });
  const webhook = scripted('env-webhook', [notFound, notFound]);
  const { outbox, store, clock } = setup(t, { channels: [webhook.channel] });
  await outbox.enqueue([
    entry({ eventUid: 'f1', orderKey }),
    entry({ eventUid: 'r1', orderKey, kind: 'resolved' }),
    entry({ eventUid: 'nas', orderKey: 'nas\n__availability' }),
  ]);
  await drain(outbox);
  assert.equal(webhook.sent.length, 1);
  let health = await statusOf(outbox);
  const since = health.pausedSince;
  assert.deepEqual([health.state, health.nextSendAt], ['paused', clock.wall() + 15 * minute]);
  assert.equal((await outbox.pump()).wakeAt, health.nextSendAt);
  // Nothing before the probe is due.
  await clock.advance(15 * minute - 1);
  await drain(outbox);
  assert.equal(webhook.sent.length, 1);
  // The probe: exactly one send, the oldest held row; answered 404 again, so held again.
  await clock.advance(1);
  await drain(outbox);
  assert.equal(webhook.sent.length, 2);
  assert.equal(webhook.sent[1].uid, deliveryUid('f1', 'env-webhook'));
  health = await statusOf(outbox);
  assert.equal(health.state, 'paused');
  assert.equal(health.pausedSince, since, 'kept through probes');
  assert.deepEqual(
    (await rowsOf(store)).map(row => row.state),
    ['held', 'held', 'held']
  );
  // The receiver is fixed: the next probe is accepted, the channel resumes and every held row
  // goes once, in order.
  await clock.advance(15 * minute);
  await drain(outbox);
  assert.deepEqual(
    webhook.sent.slice(2).map(message => message.uid),
    ['f1', 'r1', 'nas'].map(uid => deliveryUid(uid, 'env-webhook'))
  );
  health = await statusOf(outbox);
  assert.deepEqual([health.state, health.pausedSince, health.pausedReason], ['ok', null, null]);
});

test('a pause that needs a change never probes by time, but probes once when a start asks', async t => {
  const signIn = () => pause('Email sign-in failed.');
  const email = scripted('email', [signIn, signIn], { digest: { windowMs: minute } });
  const { outbox, store, clock } = setup(t, { channels: [email.channel] });
  await outbox.enqueue([entry({ channelId: 'email' }), entry({ channelId: 'email' })]);
  await clock.advance(minute);
  await drain(outbox);
  assert.equal(email.sent.length, 1);
  assert.deepEqual([(await statusOf(outbox, 'email')).nextSendAt], [0]);
  for (let i = 0; i < 8; i++) {
    await clock.advance(15 * minute);
    await drain(outbox);
  }
  assert.equal(email.sent.length, 1, 'no probe by time');
  // A start lets each paused channel probe once (the delivery service sets nextSendAt).
  await outbox.updateChannel('email', status => ({ ...status, nextSendAt: clock.wall() }));
  await drain(outbox);
  assert.equal(email.sent.length, 2);
  // The probe is the whole digest (one message, the same batch) and was refused again.
  assert.equal(email.sent[1].uid, email.sent[0].uid);
  assert.equal(email.sent[1].events.length, 2);
  assert.equal((await statusOf(outbox, 'email')).nextSendAt, 0);
  assert.deepEqual(
    (await rowsOf(store)).map(row => row.state),
    ['held', 'held']
  );
  await clock.advance(5 * hour);
  await drain(outbox);
  assert.equal(email.sent.length, 2);
});

test('the send-time recheck skips a row unsent without touching the channel health', async t => {
  const reasons = new Map([['gone', 'Not sent: the source was deleted.']]);
  const webhook = scripted('env-webhook');
  const { outbox, store } = setup(t, {
    channels: [webhook.channel],
    recheck: row => reasons.get(row.event.service) ?? null,
  });
  await outbox.enqueue([
    entry({ eventUid: 'a', event: { service: 'gone', kind: 'firing' }, orderKey: 'gone\nx' }),
    entry({ eventUid: 'b', event: { service: 'gone', kind: 'resolved' }, orderKey: 'gone\nx' }),
    entry({ eventUid: 'c', event: { service: 'here', kind: 'firing' } }),
  ]);
  await drain(outbox);
  assert.deepEqual(
    webhook.sent.map(message => message.uid),
    [deliveryUid('c', 'env-webhook')]
  );
  const rows = await rowsOf(store);
  assert.deepEqual(
    rows.map(row => [row.state, row.lastError]),
    [
      ['skipped', 'Not sent: the source was deleted.'],
      ['skipped', 'Not sent: the source was deleted.'],
      ['delivered', null],
    ]
  );
  const health = await statusOf(outbox);
  assert.deepEqual([health.deliveredTotal, health.failedTotal], [1, 0]);
  // A recheck that throws sends the row (the check is a safeguard, not a gate).
  const throwing = setup(t, {
    channels: [scripted('env-webhook').channel],
    recheck: () => {
      throw new Error('config unreadable');
    },
  });
  await throwing.outbox.enqueue(entry({ eventUid: 'd' }));
  await drain(throwing.outbox);
  assert.equal((await rowFor(throwing.store, 'd')).state, 'delivered');
  assert.match(throwing.logger.lines.error[0], /send-time check failed: config unreadable/);
});

test('A58: a notification skipped just before a send counts no attempt for it', async t => {
  // The send-time recheck (D24): a waiting row skipped before its first try keeps 0 attempts,
  // and one that was sent once, then switched off while it waited to retry, keeps 1.
  const reasons = new Map();
  const webhook = scripted('env-webhook', [retry(null, 'The receiver answered 500.')]);
  const { outbox, store, clock } = setup(t, {
    channels: [webhook.channel],
    recheck: row => reasons.get(row.event.service) ?? null,
  });
  await outbox.enqueue(entry({ eventUid: 'tried', event: { service: 'nas', kind: 'firing' } }));
  await drain(outbox);
  assert.equal((await rowFor(store, 'tried')).attempts, 1);
  await outbox.enqueue(entry({ eventUid: 'waiting', event: { service: 'gone', kind: 'firing' } }));
  reasons.set('nas', 'Not sent: alerts of this kind were switched off after it was queued.');
  reasons.set('gone', 'Not sent: the source was deleted.');
  await clock.advance(hour);
  await drain(outbox);
  assert.equal(webhook.sent.length, 1);
  assert.deepEqual(
    (await rowsOf(store)).map(row => [row.eventUid, row.state, row.attempts]),
    [
      ['tried', 'skipped', 1],
      ['waiting', 'skipped', 0],
    ]
  );
  // A channel that skips what it is given (GOBLIN_WEBHOOK_URL removed, email switched off: A45),
  // a digest of two included: every row keeps the attempts it had.
  const unset = scripted('env-webhook', [skipped('GOBLIN_WEBHOOK_URL is not set.')]);
  const off = scripted('email', [skipped('Email alerts are switched off.')], {
    digest: { windowMs: minute, maxFactor: 3 },
  });
  const other = setup(t, { channels: [unset.channel, off.channel] });
  await other.outbox.enqueue([
    entry({ eventUid: 'hook' }),
    entry({ eventUid: 'mail-1', channelId: 'email' }),
    entry({ eventUid: 'mail-2', channelId: 'email' }),
  ]);
  await other.outbox.flush({ ignoreWindows: true, timeoutMs: 1000 });
  assert.equal(off.sent.length, 1);
  assert.equal(off.sent[0].events.length, 2);
  assert.deepEqual(
    (await rowsOf(other.store)).map(row => [row.eventUid, row.state, row.attempts]),
    [
      ['hook', 'skipped', 0],
      ['mail-1', 'skipped', 0],
      ['mail-2', 'skipped', 0],
    ]
  );
});

test('P3: a claim that resolves after stop() starts no send; the row is queued as before', async t => {
  const inner = createMemoryOutboxStore();
  let release;
  const slow = {
    ...inner,
    claim: async (...args) => {
      await new Promise(resolve => (release = resolve));
      return inner.claim(...args);
    },
  };
  const webhook = scripted('env-webhook');
  const { outbox } = setup(t, { store: slow, channels: [webhook.channel] });
  await outbox.enqueue(entry({ eventUid: 'late' }));
  const pumping = outbox.pump();
  await settle();
  assert.equal(typeof release, 'function', 'the pass is claiming');
  const stopping = outbox.stop({ timeoutMs: 8000 });
  await settle();
  release();
  assert.deepEqual(await stopping, { cancelled: 0, unsettled: 0 });
  assert.equal((await pumping).started, 0);
  assert.equal(webhook.sent.length, 0);
  const row = await rowFor(inner, 'late');
  assert.deepEqual([row.state, row.attempts, row.leaseOwner], ['queued', 0, null]);
  // A run cancelled while claiming does the same.
  const other = createMemoryOutboxStore();
  let go;
  const held = {
    ...other,
    claim: async (...args) => {
      await new Promise(resolve => (go = resolve));
      return other.claim(...args);
    },
  };
  const second = setup(t, { store: held, channels: [scripted('env-webhook').channel] });
  await second.outbox.enqueue(entry({ eventUid: 'aborted' }));
  const controller = new AbortController();
  const pass = second.outbox.pump({ signal: controller.signal });
  await settle();
  controller.abort();
  go();
  assert.equal((await pass).started, 0);
  assert.deepEqual(
    [(await rowFor(other, 'aborted')).state, (await rowFor(other, 'aborted')).attempts],
    ['queued', 0]
  );
});

test('Retry now: failed rows get a fresh budget, retrying rows go now, everything else is refused', async t => {
  const answers = {
    dead: failed('The webhook refused the alert (422).', { status: 422 }),
    late: retry(null, 'The webhook answered 500.', { status: 500 }),
  };
  const webhook = scripted('env-webhook', [
    message => answers[message.events[0].message] ?? accepted({ status: 200 }),
  ]);
  const channel = {
    ...webhook.channel,
    async send(message, context) {
      webhook.sent.push(structuredClone(message));
      return answers[message.events[0].message] ?? accepted({ status: 200 });
    },
  };
  const { outbox, store, clock } = setup(t, { channels: [channel] });
  const ev = (eventUid, message, extra = {}) =>
    entry({ eventUid, event: { service: 'plex', kind: 'firing', message }, ...extra });
  await outbox.enqueue([
    ev('dead', 'dead', { orderKey: 'a\nr' }),
    ev('late', 'late', { orderKey: 'b\nr' }),
    ev('ok', 'ok', { orderKey: 'c\nr' }),
  ]);
  await drain(outbox);
  const uid = name => deliveryUid(name, 'env-webhook');
  // Refusals.
  assert.deepEqual(await outbox.retry('d_nothingherexxxxxxxxxxxxxxxx'), { refused: 'not_found' });
  assert.equal((await outbox.retry(uid('ok'))).refused, 'finished');
  await outbox.enqueue(ev('fresh', 'fresh', { orderKey: 'd\nr', createdAt: clock.wall() + 1 }));
  assert.equal((await outbox.retry(uid('fresh'))).refused, 'waiting');
  // A failed row: requeued with a fresh 24 h budget, due now, the channel may send at once.
  await clock.advance(10 * hour);
  const before = await rowFor(store, 'dead');
  assert.deepEqual([before.state, before.deadReason], ['dead', 'failed']);
  const result = await outbox.retry(uid('dead'));
  assert.equal(result.retried, 1);
  const after = await rowFor(store, 'dead');
  assert.deepEqual(
    [after.state, after.nextAt, after.expiresAt, after.deadReason, after.attempts],
    ['queued', clock.wall(), clock.wall() + 24 * hour, null, 1]
  );
  // A retrying row: due now.
  const retrying = await rowFor(store, 'late');
  assert.ok(retrying.nextAt <= clock.wall() || retrying.state === 'dead');
  // Paused channel: refused with its reason.
  await outbox.pause('env-webhook', 'The webhook answered 401.');
  const paused = await outbox.retry(uid('dead'));
  assert.deepEqual(paused, {
    refused: 'paused',
    channelId: 'env-webhook',
    reason: 'The webhook answered 401.',
  });
  await outbox.resume('env-webhook');
  // Being sent right now: refused.
  let releaseSend;
  const blocking = scripted('env-webhook', [
    () => new Promise(resolve => (releaseSend = () => resolve(accepted()))),
  ]);
  const second = setup(t, { channels: [blocking.channel], clock });
  await second.outbox.enqueue(ev('busy', 'busy'));
  await second.outbox.pump();
  await settle();
  assert.equal((await second.outbox.retry(uid('busy'))).refused, 'sending');
  releaseSend();
  await settle();
});

test('Retry now refuses a failed row whose alert already has a later delivered or sending row', async t => {
  const webhook = scripted('env-webhook', [failed('The webhook refused the alert (400).')]);
  const { outbox, store } = setup(t, { channels: [webhook.channel] });
  await outbox.enqueue(entry({ eventUid: 'f', orderKey }));
  await drain(outbox);
  assert.equal((await rowFor(store, 'f')).state, 'dead');
  // Nothing later yet: retryable.
  assert.equal(await outbox.retryable(await rowFor(store, 'f')), true);
  // A later notification of the same alert is being sent: sending this one would be out of order.
  let releaseSend;
  webhook.queue.push(() => new Promise(resolve => (releaseSend = () => resolve(accepted()))));
  await outbox.enqueue(entry({ eventUid: 'r', orderKey, kind: 'resolved' }));
  await outbox.pump();
  await settle();
  assert.equal((await outbox.retry(deliveryUid('f', 'env-webhook'))).refused, 'outdated');
  releaseSend();
  await settle();
  // Delivered: still outdated. A later row that is only queued does not refuse.
  assert.equal((await outbox.retry(deliveryUid('f', 'env-webhook'))).refused, 'outdated');
  assert.equal(await outbox.retryable(await rowFor(store, 'f')), false);
  const other = setup(t, { channels: [scripted('env-webhook', [failed('400')]).channel] });
  await other.outbox.enqueue(entry({ eventUid: 'f2', orderKey }));
  await drain(other.outbox);
  await other.outbox.pause('env-webhook', 'hold the next one');
  await other.outbox.enqueue(entry({ eventUid: 'r2', orderKey, kind: 'resolved' }));
  await other.outbox.resume('env-webhook');
  assert.equal((await rowFor(other.store, 'r2')).state, 'queued');
  assert.equal((await other.outbox.retry(deliveryUid('f2', 'env-webhook'))).retried, 1);
});

test('Retry now retries a digest as a whole, with its batch id, or refuses it as a whole', async t => {
  const email = scripted('email', [failed('The mail server refused the message (554).')], {
    digest: { windowMs: minute },
  });
  const { outbox, store, clock } = setup(t, { channels: [email.channel] });
  await outbox.enqueue([
    entry({ eventUid: 'm1', channelId: 'email', orderKey: 'a\nr' }),
    entry({ eventUid: 'm2', channelId: 'email', orderKey: 'b\nr' }),
  ]);
  await clock.advance(minute);
  await drain(outbox);
  const [first] = email.sent;
  assert.deepEqual(
    (await rowsOf(store)).map(row => row.state),
    ['dead', 'dead']
  );
  // One row of the batch already has a later delivered row: the batch is refused as a whole.
  const blocked = setup(t, {
    channels: [scripted('email', [failed('554')], { digest: { windowMs: minute } }).channel],
    clock,
  });
  await blocked.outbox.enqueue([
    entry({ eventUid: 'x1', channelId: 'email', orderKey: 'a\nr' }),
    entry({ eventUid: 'x2', channelId: 'email', orderKey: 'b\nr' }),
  ]);
  await clock.advance(minute);
  await drain(blocked.outbox);
  await blocked.outbox.enqueue(entry({ eventUid: 'x3', channelId: 'email', orderKey: 'b\nr' }));
  await clock.advance(minute);
  await drain(blocked.outbox);
  assert.equal((await rowFor(blocked.store, 'x3')).state, 'delivered');
  assert.equal(
    (await blocked.outbox.retry(deliveryUid('x1', 'email'))).refused,
    'outdated',
    'x2 of the same batch is outdated'
  );
  // The first batch: retried whole, sent as the same message.
  const result = await outbox.retry(deliveryUid('m2', 'email'));
  assert.equal(result.retried, 2);
  await drain(outbox);
  assert.equal(email.sent.length, 2);
  assert.equal(email.sent[1].uid, first.uid);
  assert.equal(email.sent[1].events.length, 2);
});

test('recordTest records a test email without pausing; an accepted one resumes the channel', async t => {
  const email = scripted('email', [pause('Email sign-in failed.')], {
    digest: { windowMs: minute },
  });
  const { outbox, store, clock } = setup(t, { channels: [email.channel] });
  await outbox.recordTest('email', {
    accepted: false,
    message: 'Email sign-in failed. https://x.test/secret',
  });
  let health = await statusOf(outbox, 'email');
  assert.deepEqual(
    [
      health.state,
      health.lastAttempt,
      health.lastFailure,
      health.failedTotal,
      health.consecutiveFailures,
    ],
    ['ok', clock.wall(), clock.wall(), 1, 0]
  );
  assert.equal(health.lastError.message, 'Email sign-in failed. [url]');
  await outbox.enqueue(entry({ channelId: 'email' }));
  await clock.advance(minute);
  await drain(outbox);
  health = await statusOf(outbox, 'email');
  assert.equal(health.state, 'paused');
  // A failed test changes no pause; an accepted test resumes it and releases the held row.
  await outbox.recordTest('email', { accepted: false, message: 'still wrong' });
  assert.equal((await statusOf(outbox, 'email')).state, 'paused');
  await clock.advance(1000);
  await outbox.recordTest('email', { accepted: true });
  health = await statusOf(outbox, 'email');
  assert.deepEqual(
    [health.state, health.pausedSince, health.lastSuccess],
    ['ok', null, clock.wall()]
  );
  await drain(outbox);
  assert.deepEqual(
    (await rowsOf(store)).map(row => row.state),
    ['delivered']
  );
});

test('channelChanged clears the last error and both streaks; resume clears the pause', async t => {
  const webhook = scripted('env-webhook', [failed('a'), failed('b'), failed('c')]);
  const { outbox } = setup(t, { channels: [webhook.channel] });
  await outbox.enqueue([entry(), entry(), entry()]);
  await drain(outbox);
  let health = await statusOf(outbox);
  assert.deepEqual([health.consecutiveRefusals, health.lastError?.message], [3, 'c']);
  await outbox.channelChanged('env-webhook');
  health = await statusOf(outbox);
  assert.deepEqual(
    [health.consecutiveRefusals, health.consecutiveFailures, health.lastError, health.failedTotal],
    [0, 0, null, 3]
  );
});

test('cancelSource and markStale end waiting rows unsent, with their reasons', async t => {
  const webhook = scripted('env-webhook', [pause('401')]);
  const { outbox, store } = setup(t, { channels: [webhook.channel] });
  await outbox.enqueue([
    entry({ eventUid: 'plex-1', orderKey: 'plex\n__availability' }),
    entry({ eventUid: 'plex-2', orderKey: 'plex\ncpu' }),
    entry({ eventUid: 'plexus', orderKey: 'plexus\n__availability' }),
  ]);
  await drain(outbox);
  assert.equal(await outbox.cancelSource('plex', 'Not sent: the source was deleted.'), 2);
  assert.deepEqual(
    (await rowsOf(store)).map(row => [row.eventUid, row.state]),
    [
      ['plex-1', 'cancelled'],
      ['plex-2', 'cancelled'],
      ['plexus', 'held'],
    ]
  );
  assert.equal(await outbox.markStale('Not sent: restored.'), 1);
  assert.deepEqual(
    [(await rowFor(store, 'plexus')).state, (await rowFor(store, 'plexus')).lastError],
    ['stale', 'Not sent: restored.']
  );
  await outbox.resume('env-webhook');
  await drain(outbox);
  assert.equal(webhook.sent.length, 1);
});

test('clock steps: +3 days expires nothing unsent in that pass; −3 days caps every wait', async t => {
  // Forward: a row waiting to retry would be past its expiry on the stepped clock.
  const webhook = scripted('env-webhook', [retry(null, 'down')]);
  const { outbox, store, clock, logger } = setup(t, { channels: [webhook.channel] });
  await outbox.enqueue(entry({ eventUid: 'w', orderKey }));
  await drain(outbox);
  const before = await rowFor(store, 'w');
  clock.step(3 * 24 * hour);
  const pass = await outbox.pump();
  assert.equal(pass.expired, 0);
  // It keeps the life it had left (here: almost a day), never more than 24 h from now.
  const shifted = await rowFor(store, 'w');
  assert.equal(shifted.expiresAt, before.expiresAt + 3 * day());
  assert.ok(shifted.expiresAt <= clock.wall() + 24 * hour);
  assert.match(
    logger.lines.warn[0],
    /clock jumped forward by 3 days; notification times were adjusted/
  );
  await settle();
  await drain(outbox);
  assert.equal((await rowFor(store, 'w')).state, 'delivered');
  // A bogus jump of ten years cannot keep a row alive for ten years.
  await outbox.enqueue(entry({ eventUid: 'y' }));
  webhook.queue.push(retry(null, 'down'));
  await drain(outbox);
  clock.step(3650 * 24 * hour);
  await outbox.pump();
  assert.ok((await rowFor(store, 'y')).expiresAt <= clock.wall() + 24 * hour);

  // Backward: retries, the circuit and the email digest would otherwise wait three days.
  const down = () => retry(null, 'down');
  const hook = scripted('env-webhook', Array(5).fill(down));
  const email = scripted('email', [], { digest: { windowMs: minute } });
  const second = setup(t, { channels: [hook.channel, email.channel] });
  await second.outbox.enqueue(Array.from({ length: 5 }, () => entry()));
  for (let i = 0; i < 5; i++) {
    await drain(second.outbox);
    await second.clock.advance(15 * minute);
  }
  await second.outbox.enqueue([entry({ channelId: 'email' }), entry({ channelId: 'email' })]);
  second.clock.step(-3 * 24 * hour);
  const now = second.clock.wall();
  await second.outbox.pump();
  await settle();
  assert.match(second.logger.lines.warn.at(-1), /clock jumped back by 3 days/);
  for (const row of await rowsOf(second.store)) {
    if (row.state === 'queued') assert.ok(row.nextAt <= now + 15 * minute, 'retry within 15 min');
    if (['queued', 'held', 'sending'].includes(row.state))
      assert.ok(row.expiresAt <= now + 24 * hour);
  }
  assert.ok((await statusOf(second.outbox)).nextSendAt <= now + 15 * minute);
  // Alert changes stamped before the step but queued after it: created at now, so their digest
  // goes within three windows of the stepped clock, not three days later.
  await second.outbox.enqueue([
    entry({ channelId: 'email', createdAt: now + 2 * day() }),
    entry({ channelId: 'email', createdAt: now + 3 * day() }),
  ]);
  await second.clock.advance(3 * minute);
  await drain(second.outbox);
  assert.deepEqual(
    email.sent.map(message => message.events.length),
    [2]
  );
  // The rows queued before the step wait at most the 15-minute cap, then go too; so do the
  // webhook's retries.
  await second.clock.advance(15 * minute);
  await drain(second.outbox);
  assert.deepEqual(
    email.sent.map(message => message.events.length),
    [2, 2]
  );
  assert.ok(hook.sent.length > 5);
  // A row stamped later than now (an event from before the step) is created at now.
  await second.outbox.enqueue(
    entry({ eventUid: 'future', createdAt: second.clock.wall() + day() })
  );
  assert.equal((await rowFor(second.store, 'future')).createdAt, second.clock.wall());
});
const day = () => 24 * hour;

test('a forward clock step while a send is in flight keeps each row’s remaining life (D25)', async t => {
  // The answer (retry, unknown) arrives after the step. Judged against the expiry the row had
  // when it was claimed, the row expired unsent, while a waiting row kept the life it had left.
  for (const { ageHours, stepHours, answer, detectedFirst } of [
    { ageHours: 0, stepHours: 25, answer: () => retry(null, 'The webhook answered 500.') },
    { ageHours: 20, stepHours: 5, answer: () => unknown('The request timed out.') },
    // A pass sees the step while the send is still out (it moves the stored expiry).
    { ageHours: 22, stepHours: 3, answer: () => retry(null, 'down'), detectedFirst: true },
  ]) {
    let answerNow;
    const webhook = scripted('env-webhook', [
      () => new Promise(resolve => (answerNow = () => resolve(answer()))),
    ]);
    const { outbox, store, clock, logger } = setup(t, { channels: [webhook.channel] });
    await outbox.enqueue(entry({ eventUid: 'w', createdAt: clock.wall() - ageHours * hour }));
    await outbox.pump();
    assert.equal((await rowFor(store, 'w')).state, 'sending');
    clock.step(stepHours * hour);
    if (detectedFirst) await outbox.pump();
    answerNow();
    await settle();
    await outbox.pump();
    const row = await rowFor(store, 'w');
    const label = `${ageHours} h old, +${stepHours} h${detectedFirst ? ', seen first' : ''}`;
    assert.deepEqual([row.state, row.deadReason], ['queued', null], label);
    assert.equal(row.expiresAt - clock.wall(), (24 - ageHours) * hour, label);
    assert.match(logger.lines.warn.join('\n'), /clock jumped forward/, label);
    // And it is delivered once the receiver works.
    await clock.advance(15 * minute);
    await drain(outbox);
    assert.equal((await rowFor(store, 'w')).state, 'delivered', label);
  }
  // A digest in flight: the whole batch keeps its life, and is retried together.
  let answerNow;
  const email = scripted(
    'email',
    [() => new Promise(resolve => (answerNow = () => resolve(retry(null, 'SMTP 421'))))],
    { digest: { windowMs: minute } }
  );
  const { outbox, store, clock } = setup(t, { channels: [email.channel] });
  await outbox.enqueue([
    entry({ eventUid: 'm1', channelId: 'email' }),
    entry({ eventUid: 'm2', channelId: 'email' }),
  ]);
  await clock.advance(minute);
  await outbox.pump();
  clock.step(25 * hour);
  answerNow();
  await settle();
  await outbox.pump();
  const rows = await rowsOf(store);
  assert.deepEqual(
    rows.map(row => [row.state, row.expiresAt - clock.wall()]),
    [
      ['queued', 24 * hour - minute],
      ['queued', 24 * hour - minute],
    ]
  );
  await clock.advance(15 * minute);
  await drain(outbox);
  assert.deepEqual(
    email.sent.map(message => [message.uid, message.events.length]),
    [
      [email.sent[0].uid, 2],
      [email.sent[0].uid, 2],
    ]
  );
});

test('a source flapping 50 times in 10 minutes: one row per change and channel, sent in order', async t => {
  const webhook = scripted('env-webhook');
  const email = scripted('email', [], { digest: { windowMs: minute, maxFactor: 3 } });
  const { outbox, store, clock } = setup(t, { channels: [webhook.channel, email.channel] });
  const changes = [];
  for (let n = 0; n < 50; n++) {
    const kind = n % 2 ? 'resolved' : 'firing',
      eventUid = `flap-${n}`;
    changes.push(eventUid);
    // The relay may enqueue the same change twice (a crash before its mark): written once.
    for (let copy = 0; copy < 2; copy++)
      await outbox.enqueue(
        ['env-webhook', 'email'].map(channelId =>
          entry({ eventUid, channelId, kind, orderKey, createdAt: clock.wall() })
        )
      );
    await clock.advance(12 * second);
    await drain(outbox);
  }
  await clock.advance(10 * minute);
  await drain(outbox);
  assert.equal(await store.countActive(), 0);
  // Exactly one row per change and channel.
  assert.equal((await store.counts()).total.delivered, 100);
  // The webhook got each change once, in order.
  assert.deepEqual(
    webhook.sent.map(message => message.uid),
    changes.map(uid => deliveryUid(uid, 'env-webhook'))
  );
  // Email: one digest per 180 s cap while the flapping lasts (the 60 s quiet never comes).
  assert.deepEqual(
    email.sent.map(message => message.events.length),
    [15, 15, 15, 5]
  );
  assert.deepEqual(
    email.sent.flatMap(message => message.events.map(event => event.kind)),
    changes.map((_, n) => (n % 2 ? 'resolved' : 'firing'))
  );
});

test('enqueue reports rows kept in memory; sending() and dropped describe the worker', async t => {
  const releases = [];
  const webhook = scripted('env-webhook', [
    () => new Promise(resolve => releases.push(() => resolve(accepted()))),
  ]);
  const { outbox } = setup(t, { channels: [webhook.channel], maxActive: 1 });
  const first = await outbox.enqueue(entry());
  assert.deepEqual(first.memoryUids, []);
  assert.equal(outbox.sending('env-webhook'), false);
  await outbox.pump();
  await settle();
  assert.equal(outbox.sending('env-webhook'), true);
  assert.equal(outbox.sending('email'), false);
  await outbox.enqueue(entry());
  assert.equal(outbox.dropped, 1);
  releases[0]();
  await settle();
  assert.equal(outbox.sending('env-webhook'), false);
});

test('Retry now follows §6.4 for every state; a retrying row becomes due now and may probe', async t => {
  const store = createMemoryOutboxStore();
  const webhook = scripted(
    'env-webhook',
    Array(6).fill(() => retry(null, 'The webhook answered 500.', { status: 500 }))
  );
  const { outbox, clock } = setup(t, { store, channels: [webhook.channel] });
  const uid = name => deliveryUid(name, 'env-webhook');
  // One row in each finished state, written as they would be.
  const finished = ['delivered', 'skipped', 'superseded', 'stale', 'cancelled', 'archived'];
  await store.insert(
    finished.map(state => outboxRow({ eventUid: `x-${state}`, state, createdAt: clock.wall() }))
  );
  for (const state of finished)
    assert.deepEqual(
      await outbox.retry(uid(`x-${state}`)),
      {
        refused: 'finished',
        channelId: 'env-webhook',
        reason: null,
      },
      state
    );
  // A held row (its channel paused) is refused as paused. It is cancelled before the passes
  // below: held on a channel that is not paused, the next pass would release it (the upkeep).
  await store.insert([
    outboxRow({
      eventUid: 'x-held',
      state: 'held',
      orderKey: 'gone\n__availability',
      createdAt: clock.wall(),
    }),
  ]);
  assert.equal((await outbox.retry(uid('x-held'))).refused, 'paused');
  assert.equal(await outbox.cancelSource('gone', 'Not sent: the source was deleted.'), 1);
  // Five failures open the circuit; Retry now makes the row due now and lets one probe go.
  await outbox.enqueue(entry({ eventUid: 'r' }));
  for (let n = 0; n < 5; n++) {
    if (n) await clock.advance(16 * minute);
    await drain(outbox);
  }
  let health = await statusOf(outbox);
  assert.deepEqual([health.state, health.nextSendAt], ['circuit-open', clock.wall() + minute]);
  const before = await rowFor(store, 'r');
  assert.equal(before.nextAt, clock.wall() + 8 * minute);
  const result = await outbox.retry(uid('r'));
  assert.equal(result.retried, 1);
  const after = await rowFor(store, 'r');
  assert.deepEqual(
    [after.state, after.nextAt, after.expiresAt],
    ['queued', clock.wall(), before.expiresAt]
  );
  health = await statusOf(outbox);
  assert.deepEqual(
    [health.nextSendAt, health.consecutiveFailures],
    [0, 5],
    'the circuit count is kept'
  );
  const sent = webhook.sent.length;
  await outbox.pump();
  await settle();
  assert.equal(webhook.sent.length, sent + 1, 'one probe at once');
});

test('candidates are read per channel: a backlog on one never delays a due row of the other', async t => {
  const webhook = scripted('env-webhook');
  const email = scripted('email', [], { digest: { windowMs: minute, maxFactor: 3 } });
  const { outbox, clock } = setup(t, { channels: [webhook.channel, email.channel] });
  // More due webhook rows than one candidate read returns (200), written before the email.
  await outbox.enqueue(
    Array.from({ length: 250 }, (_, i) => entry({ eventUid: `w-${i}`, orderKey: `s${i}\nrule` }))
  );
  await outbox.enqueue(entry({ eventUid: 'mail', channelId: 'email', orderKey: 'm\nrule' }));
  // The email's quiet window is open: the first pass already says when it closes.
  const first = await outbox.pump();
  await settle();
  assert.equal(first.wakeAt, clock.wall() + minute);
  await clock.advance(minute);
  // The window closed: the next pass sends the email, the backlog notwithstanding.
  await outbox.pump();
  await settle();
  assert.equal(email.sent.length, 1);
  assert.equal(webhook.sent.length, 2, 'one webhook send per pass, as before');
});

// The events of a message, as "service:kind" joined by commas.
const contentOf = message => message.events.map(event => `${event.service}:${event.kind}`).join();
// Each Message-ID (a digest's uid) with every content it was sent with.
function contentsById(sent) {
  const byId = new Map();
  for (const message of sent)
    byId.set(message.uid, new Set([...(byId.get(message.uid) ?? []), contentOf(message)]));
  return byId;
}

test('a digest tried before goes out whole: a row of it held back makes it wait, so one Message-ID never carries two contents', async t => {
  const mail = (eventUid, service, kind = 'firing') =>
    entry({
      eventUid,
      channelId: 'email',
      kind,
      orderKey: `${service}\nrule`,
      event: { service, kind, message: kind },
    });
  const tryLater = () =>
    retry(null, 'The mail server asked Uptime Goblin to try later (421).', { status: 421 });
  // Retry now on an older row of an alert whose newer row is in a digest waiting to retry: the
  // older row is active again, so the newer one is held back behind it.
  {
    const email = scripted(
      'email',
      [
        failed('The mail server refused the message (552).', { status: 552 }),
        tryLater(),
        tryLater(),
      ],
      { digest: { windowMs: second, maxFactor: 3 } }
    );
    const { outbox, clock } = setup(t, { channels: [email.channel] });
    // a fires; the server refuses that message for good.
    await outbox.enqueue(mail('a1', 'a'));
    await clock.advance(1500);
    await drain(outbox);
    // a recovers and k fires: one digest of both, which the server asks to try later (30 s).
    await outbox.enqueue([mail('a2', 'a', 'resolved'), mail('k1', 'k')]);
    await clock.advance(1500);
    await drain(outbox);
    // Retry now on a's failed firing (allowed: its recovery is only waiting to retry). It goes at
    // once, is asked to try later again, and now waits 60 s: longer than the digest.
    assert.equal((await outbox.retry(deliveryUid('a1', 'email'))).retried, 1);
    await drain(outbox);
    // The digest's time comes first, with a's recovery held back behind a's firing: it waits.
    await clock.advance(30 * second);
    await drain(outbox);
    assert.equal(email.sent.length, 3, 'nothing at the digest time');
    // a's firing is accepted, then the digest goes, whole.
    for (let i = 0; i < 4; i++) {
      await clock.advance(30 * second);
      await drain(outbox);
    }
    assert.deepEqual(email.sent.map(contentOf), [
      'a:firing',
      'a:resolved,k:firing',
      'a:firing',
      'a:firing',
      'a:resolved,k:firing',
    ]);
    for (const [uid, contents] of contentsById(email.sent))
      assert.equal(contents.size, 1, `${uid} was sent with ${[...contents].join(' and ')}`);
  }
  // A digest cut off by the candidate limit, behind a row that became due before it.
  {
    const email = scripted('email', [tryLater(), tryLater()], {
      digest: { windowMs: second, maxFactor: 3 },
    });
    const { outbox, clock } = setup(t, { channels: [email.channel], candidateLimit: 2 });
    // q fires; the server asks to try later, so q's recovery waits behind it, unbatched, while x
    // and y form a digest, which the server also asks to try later.
    await outbox.enqueue(mail('q1', 'q'));
    await clock.advance(1500);
    await drain(outbox);
    await outbox.enqueue([mail('q2', 'q', 'resolved'), mail('x1', 'x'), mail('y1', 'y')]);
    await clock.advance(1500);
    await drain(outbox);
    // Both are due again: q's firing goes, then q's recovery and the digest, which comes after
    // it in id order and does not fit in one candidate read with it.
    for (let i = 0; i < 3; i++) {
      await clock.advance(30 * second);
      await drain(outbox);
    }
    assert.deepEqual(email.sent.map(contentOf), [
      'q:firing',
      'x:firing,y:firing',
      'q:firing',
      'q:resolved',
      'x:firing,y:firing',
    ]);
    for (const [uid, contents] of contentsById(email.sent))
      assert.equal(contents.size, 1, `${uid} was sent with ${[...contents].join(' and ')}`);
  }
});

test('a digest tried before whose whole-batch check meets a busy database waits a pass instead of going out in part', async t => {
  const memory = createMemoryOutboxStore();
  let busy = false;
  // SQLITE_BUSY past its retries, as the control store classifies it (class retry).
  const store = {
    ...memory,
    async batch(...args) {
      if (busy)
        throw Object.assign(new Error('database is locked'), {
          code: 'SQLITE_BUSY',
          class: 'retry',
        });
      return memory.batch(...args);
    },
  };
  const mail = (eventUid, service, kind = 'firing') =>
    entry({
      eventUid,
      channelId: 'email',
      kind,
      orderKey: `${service}\nrule`,
      event: { service, kind, message: kind },
    });
  const tryLater = () =>
    retry(null, 'The mail server asked Uptime Goblin to try later (421).', { status: 421 });
  const email = scripted(
    'email',
    [failed('The mail server refused the message (552).', { status: 552 }), tryLater(), tryLater()],
    { digest: { windowMs: second, maxFactor: 3 } }
  );
  const { outbox, clock, logger } = setup(t, { channels: [email.channel], store });
  // As in the test above: a's recovery waits in a retrying digest behind a's firing, which Retry
  // now made active again; at the digest's time its check meets a busy database.
  await outbox.enqueue(mail('a1', 'a'));
  await clock.advance(1500);
  await drain(outbox);
  await outbox.enqueue([mail('a2', 'a', 'resolved'), mail('k1', 'k')]);
  await clock.advance(1500);
  await drain(outbox);
  assert.equal((await outbox.retry(deliveryUid('a1', 'email'))).retried, 1);
  await drain(outbox);
  busy = true;
  await clock.advance(30 * second);
  await drain(outbox);
  // Before, a batch that could not be read was sent as it was: k's alert alone, under the
  // digest's Message-ID, and a's recovery later under the same one.
  assert.equal(email.sent.length, 3, 'nothing at the digest time');
  assert.match(logger.lines.error.join('\n'), /A digest batch could not be checked before sending/);
  busy = false;
  for (let i = 0; i < 4; i++) {
    await clock.advance(30 * second);
    await drain(outbox);
  }
  assert.deepEqual(email.sent.map(contentOf), [
    'a:firing',
    'a:resolved,k:firing',
    'a:firing',
    'a:firing',
    'a:resolved,k:firing',
  ]);
  for (const [uid, contents] of contentsById(email.sent))
    assert.equal(contents.size, 1, `${uid} was sent with ${[...contents].join(' and ')}`);
});

test('a later row of an alert waits while a digest holding its earlier row waits to go out whole (D23 within a pass)', async t => {
  const mail = (eventUid, service, kind = 'firing') =>
    entry({
      eventUid,
      channelId: 'email',
      kind,
      orderKey: `${service}\nrule`,
      event: { service, kind, message: kind },
    });
  const tryLater = () =>
    retry(null, 'The mail server asked Uptime Goblin to try later (421).', { status: 421 });
  const email = scripted(
    'email',
    [failed('The mail server refused the message (552).', { status: 552 }), tryLater(), tryLater()],
    { digest: { windowMs: second, maxFactor: 3 } }
  );
  const { outbox, clock } = setup(t, { channels: [email.channel] });
  // a's recovery and k's alert wait in a retrying digest; a's recovery is held back behind a's
  // firing, which Retry now made active again, so the digest waits whole (A5).
  await outbox.enqueue(mail('a1', 'a'));
  await clock.advance(1500);
  await drain(outbox);
  await outbox.enqueue([mail('a2', 'a', 'resolved'), mail('k1', 'k')]);
  await clock.advance(1500);
  await drain(outbox);
  assert.equal((await outbox.retry(deliveryUid('a1', 'email'))).retried, 1);
  await drain(outbox);
  // k recovers. Its recovery is due in the same pass as the waiting digest that holds k's alert:
  // before, it went out alone, first.
  await outbox.enqueue(mail('k2', 'k', 'resolved'));
  await clock.advance(30 * second);
  await drain(outbox);
  assert.equal(email.sent.length, 3, 'k’s recovery waits with the digest holding its alert');
  for (let i = 0; i < 4; i++) {
    await clock.advance(30 * second);
    await drain(outbox);
  }
  assert.deepEqual(email.sent.map(contentOf), [
    'a:firing',
    'a:resolved,k:firing',
    'a:firing',
    'a:firing',
    'a:resolved,k:firing',
    'k:resolved',
  ]);
});

// Digests tried before (one attempt each, due again) stored as `layout` lists them, in id order:
// each item is [digest, service, kind]. Every row of one digest shares its digest key.
async function triedDigests(store, layout, now) {
  const rows = layout.map(([digest, service, kind], index) => {
    const eventUid = `${digest}-${service}-${kind}-${index}`;
    return outboxRow({
      eventUid,
      channelId: 'email',
      kind,
      orderKey: `${service}\nrule`,
      event: { service, kind, message: kind },
      attempts: 1,
      digestKey: digest,
      lastStatus: 451,
      lastError: 'The mail server asked Uptime Goblin to try later (451).',
      createdAt: now - 10 * minute,
      nextAt: now - second,
      expiresAt: now + 20 * hour,
      updatedAt: now - minute,
    });
  });
  const keys = new Map();
  for (const row of rows) keys.set(row.digestKey, [...(keys.get(row.digestKey) ?? []), row.uid]);
  for (const row of rows) row.digestKey = digestKeyFor(keys.get(row.digestKey));
  await store.insert(rows);
  return Object.fromEntries([...keys].map(([digest, uids]) => [digest, digestKeyFor(uids)]));
}
// A digest's content (contentOf) as first sent: its rows of `layout` in id order.
const contentIn = (layout, digest) =>
  layout
    .filter(([d]) => d === digest)
    .map(([, service, kind]) => `${service}:${kind}`)
    .join();

test('digests tried before whose rows lie past the candidate window go whole, never before an earlier row of one of their alerts', async t => {
  // Two digests whose rows interleave by id share alert k, and the four rows of the candidate
  // window hold neither whole, so each waits for rows the pass did not read. Before, every pass
  // held both back (and every row behind them) and sent nothing until the rows expired. Now the
  // one holding k's earlier row goes first, whole, read from the store, then the other.
  const pastTheWindow = [
    ['A', 'a1', 'firing'],
    ['B', 'b1', 'firing'],
    ['A', 'a2', 'firing'],
    ['B', 'b2', 'firing'],
    ['B', 'k', 'firing'],
    ['A', 'k', 'resolved'],
  ];
  const cases = [
    // k's rows lie past the window: the store is read to find B's firing before A's recovery.
    { name: 'past the window', layout: pastTheWindow },
    // k's rows are both in the window: B's firing is among the candidates.
    {
      name: 'in the window',
      layout: [
        ['A', 'a1', 'firing'],
        ['B', 'k', 'firing'],
        ['A', 'k', 'resolved'],
        ['B', 'b1', 'firing'],
        ['A', 'a2', 'firing'],
        ['B', 'b2', 'firing'],
      ],
    },
    // k's alerts were switched off meanwhile: B's row past the window is checked as a candidate
    // is (D24), skipped unsent, and B goes without it.
    {
      name: 'a row past the window switched off',
      layout: pastTheWindow,
      recheck: row => (row.event.service === 'k' ? 'Alerts of this kind are switched off.' : null),
      contents: { B: 'b1:firing,b2:firing', A: 'a1:firing,a2:firing' },
      skipped: ['k:firing', 'k:resolved'],
    },
  ];
  for (const { name, layout, recheck, contents = {}, skipped: unsent = [] } of cases) {
    const email = scripted('email', [], { digest: { windowMs: second, maxFactor: 3 } });
    const { outbox, store, clock } = setup(t, {
      channels: [email.channel],
      candidateLimit: 4,
      ...(recheck ? { recheck } : {}),
    });
    const keys = await triedDigests(store, layout, clock.wall());
    // A newer alert of another source, queued after them.
    await outbox.enqueue(
      entry({
        eventUid: 'z1',
        channelId: 'email',
        orderKey: 'z\nrule',
        event: { service: 'z', kind: 'firing', message: 'firing' },
      })
    );
    for (let i = 0; i < 4; i++) {
      await clock.advance(2 * second);
      await drain(outbox);
    }
    assert.deepEqual(
      email.sent.map(message => [message.uid, contentOf(message)]),
      [
        [keys.B, contents.B ?? contentIn(layout, 'B')],
        [keys.A, contents.A ?? contentIn(layout, 'A')],
        [digestKeyFor([deliveryUid('z1', 'email')]), 'z:firing'],
      ],
      name
    );
    assert.deepEqual(
      (await rowsOf(store))
        .filter(row => row.state !== 'delivered')
        .map(row => `${row.event.service}:${row.kind}:${row.state}`),
      unsent.map(item => `${item}:skipped`),
      `${name}: every other row delivered`
    );
  }
});

test('a digest whose alerts cannot be read from the store waits a pass, logged, and the pass goes on', async t => {
  // As the first case above (A holds k's firing, B its recovery), but the store is busy
  // (SQLITE_BUSY past its retries) when A's alert k is read: A waits, the check is logged, and
  // the pass goes on to B, which waits for A. The next pass sends A, then B.
  const memory = createMemoryOutboxStore();
  let busy = 1;
  const store = {
    ...memory,
    async list(filter = {}) {
      if (filter.orderKey === 'k\nrule' && busy-- > 0)
        throw Object.assign(new Error('database is locked'), {
          code: 'SQLITE_BUSY',
          class: 'retry',
        });
      return memory.list(filter);
    },
  };
  const layout = [
    ['A', 'a1', 'firing'],
    ['B', 'b1', 'firing'],
    ['A', 'a2', 'firing'],
    ['B', 'b2', 'firing'],
    ['A', 'k', 'firing'],
    ['B', 'k', 'resolved'],
  ];
  const email = scripted('email', [], { digest: { windowMs: second, maxFactor: 3 } });
  const { outbox, clock, logger } = setup(t, {
    channels: [email.channel],
    candidateLimit: 4,
    store,
  });
  const keys = await triedDigests(store, layout, clock.wall());
  await outbox.pump();
  await settle();
  assert.equal(busy, -1, 'A’s read of k failed, and B’s was made');
  assert.match(logger.lines.error.join('\n'), /A digest batch could not be checked before sending/);
  assert.deepEqual(
    email.sent.map(message => message.uid),
    [],
    'B holds k’s recovery, which waits for A'
  );
  for (let i = 0; i < 3; i++) {
    await clock.advance(2 * second);
    await drain(outbox);
  }
  assert.deepEqual(
    email.sent.map(message => [message.uid, contentOf(message)]),
    [
      [keys.A, contentIn(layout, 'A')],
      [keys.B, contentIn(layout, 'B')],
    ]
  );
});

test('three digests tried before that interleave past the 200-row candidate window keep email going, and a newer alert goes after them', async t => {
  // Production sizes: 200 candidates a pass, 100 rows a message. Three digests of 100 rows,
  // each tried once and due again, interleave a0 b0 c0 a1 b1 c1 …, so each has a third of its
  // rows past the window. Before, no pass sent anything: no email went for an hour, a newer
  // alert of another source included, until the rows started to expire 24 hours on.
  const email = scripted('email', [], { digest: { windowMs: minute, maxFactor: 3 } });
  const { outbox, store, clock } = setup(t, { channels: [email.channel] });
  const layout = [];
  for (let i = 0; i < 100; i++)
    for (const digest of ['a', 'b', 'c'])
      layout.push([digest, `${digest}${i >> 1}`, i % 2 ? 'resolved' : 'firing']);
  const keys = await triedDigests(store, layout, clock.wall());
  await outbox.enqueue(
    entry({
      eventUid: 'z1',
      channelId: 'email',
      orderKey: 'z\nrule',
      event: { service: 'z', kind: 'firing', message: 'firing' },
    })
  );
  for (let i = 0; i < 12; i++) {
    await clock.advance(30 * second);
    await drain(outbox);
  }
  assert.deepEqual(
    email.sent.map(message => [message.uid, message.events.length]),
    [
      [keys.a, 100],
      [keys.b, 100],
      [keys.c, 100],
      [digestKeyFor([deliveryUid('z1', 'email')]), 1],
    ]
  );
  // Each message holds its digest's rows in id order, as first sent.
  for (const [index, digest] of ['a', 'b', 'c'].entries())
    assert.equal(contentOf(email.sent[index]), contentIn(layout, digest));
  assert.deepEqual((await store.counts()).total, { delivered: 301 });
});

test('security D04: conditional Resume preserves a newer pause and its held rows', async t => {
  const { outbox, store } = setup(t, { channels: [scripted('env-webhook').channel] });
  await outbox.enqueue([entry({ eventUid: 'conditional-resume' })]);
  await outbox.pause('env-webhook', 'Signing authority held');
  const observed = await store.channel('env-webhook');
  const version = outbox.channelVersion('env-webhook');
  await outbox.pause('env-webhook', 'Receiver credentials changed');
  const before = await store.channel('env-webhook');
  let checked = false;
  assert.equal(
    await outbox.resume('env-webhook', {
      ifStatus: observed,
      ifVersion: version,
      beforeRelease: () => {
        checked = true;
      },
    }),
    null
  );
  assert.equal(checked, false);
  assert.deepEqual(await store.channel('env-webhook'), before);
  assert.equal((await rowsOf(store))[0].state, 'held');
  // A fresh observation can release it; a current signing hold still cannot.
  assert.equal(
    await outbox.resume('env-webhook', { ifStatus: before, canResume: () => false }),
    null
  );
  assert.equal((await rowsOf(store))[0].state, 'held');
  assert.equal(await outbox.resume('env-webhook', { ifStatus: before }), 1);
});

test('security D04: pause and Resume serialize their row changes with channel status', async t => {
  const { outbox, store } = setup(t, { channels: [scripted('env-webhook').channel] });
  await outbox.enqueue([entry({ eventUid: 'serial-resume' })]);
  await outbox.pause('env-webhook', 'Signing authority held');
  const observed = await store.channel('env-webhook');
  const version = outbox.channelVersion('env-webhook');
  let entered, release;
  const inside = new Promise(resolve => {
    entered = resolve;
  });
  const barrier = new Promise(resolve => {
    release = resolve;
  });
  const resuming = outbox.resume('env-webhook', {
    ifStatus: observed,
    ifVersion: version,
    beforeRelease: async () => {
      entered();
      await barrier;
    },
  });
  await inside;
  const pausing = outbox.pause('env-webhook', 'New receiver refusal');
  release();
  assert.equal(await resuming, 1);
  await pausing;
  assert.equal((await store.channel('env-webhook')).pausedReason, 'New receiver refusal');
  assert.equal((await rowsOf(store))[0].state, 'held');
  // Even an identical repeated pause invalidates an observation by version.
  const same = await store.channel('env-webhook'),
    old = outbox.channelVersion('env-webhook');
  await outbox.pause('env-webhook', 'New receiver refusal');
  assert.equal(await outbox.resume('env-webhook', { ifStatus: same, ifVersion: old }), null);
  assert.equal((await rowsOf(store))[0].state, 'held');
});

test(
  'security R2-01: completion holds rows before a competing Resume can release them',
  { timeout: 5000 },
  async t => {
    const webhook = scripted('env-webhook', [pause('Receiver refused delivery')]);
    const { outbox, store } = setup(t, { channels: [webhook.channel] });
    const entered = Promise.withResolvers(),
      gate = Promise.withResolvers();
    const hold = store.hold;
    store.hold = async (...args) => {
      entered.resolve();
      await gate.promise;
      return hold(...args);
    };
    t.after(() => gate.resolve());
    await outbox.enqueue(entry({ eventUid: 'completion-race' }));
    await outbox.pump();
    await entered.promise;
    const resuming = outbox.resume('env-webhook');
    await settle();
    gate.resolve();
    await resuming;
    await settle();
    const status = await statusOf(outbox);
    assert.deepEqual([status.state, status.pausedReason], ['ok', null]);
    assert.equal((await rowFor(store, 'completion-race')).state, 'queued');
  }
);

test(
  'security R2-01: an accepted test does not resume a newer email pause',
  { timeout: 5000 },
  async t => {
    const { outbox, store, clock } = setup(t, { channels: [scripted('email').channel] });
    await outbox.pause('email', 'Original email refusal');
    await outbox.enqueue(entry({ eventUid: 'test-race', channelId: 'email' }));
    const entered = Promise.withResolvers(),
      gate = Promise.withResolvers();
    const setChannel = store.setChannel,
      release = store.release;
    let armed = true,
      releases = 0;
    store.setChannel = async (id, status) => {
      const result = await setChannel(id, status);
      if (armed && id === 'email' && status.lastSuccess === clock.wall()) {
        armed = false;
        entered.resolve();
        await gate.promise;
      }
      return result;
    };
    store.release = (...args) => {
      releases++;
      return release(...args);
    };
    t.after(() => gate.resolve());
    const recording = outbox.recordTest('email', { accepted: true });
    await entered.promise;
    const pausing = outbox.pause('email', 'New email credentials required');
    gate.resolve();
    await Promise.all([recording, pausing]);
    const status = await statusOf(outbox, 'email');
    assert.deepEqual(
      [status.state, status.pausedReason],
      ['paused', 'New email credentials required']
    );
    assert.equal((await rowFor(store, 'test-race')).state, 'held');
    assert.equal(releases, 0);
  }
);

test(
  'security R2-01: a settings change does not resume a pause queued during cancellation',
  { timeout: 5000 },
  async t => {
    const email = scripted('email', [hang()]);
    const { outbox, store } = setup(t, { channels: [email.channel] });
    const entered = Promise.withResolvers(),
      gate = Promise.withResolvers();
    const setChannel = store.setChannel,
      release = store.release;
    let armed = true,
      releases = 0;
    store.setChannel = async (id, status) => {
      const result = await setChannel(id, status);
      if (armed && id === 'email' && status.state === 'retrying') {
        armed = false;
        entered.resolve();
        await gate.promise;
      }
      return result;
    };
    store.release = (...args) => {
      releases++;
      return release(...args);
    };
    t.after(() => gate.resolve());
    await outbox.enqueue(entry({ eventUid: 'settings-race', channelId: 'email' }));
    await outbox.pump();
    await settle();
    assert.equal(outbox.inFlight, 1);
    const changing = outbox.channelChanged('email');
    await entered.promise;
    const pausing = outbox.pause('email', 'New settings were refused');
    gate.resolve();
    await Promise.all([changing, pausing]);
    const status = await statusOf(outbox, 'email');
    assert.deepEqual([status.state, status.pausedReason], ['paused', 'New settings were refused']);
    assert.equal((await rowFor(store, 'settings-race')).state, 'held');
    assert.equal(releases, 0);
  }
);
