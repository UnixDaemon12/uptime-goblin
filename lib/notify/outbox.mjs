// The outbox (alerting design §2.7; roadmap #15): every notification is a row written before
// anything is sent, so delivery survives restarts, retries with backoff and ends in a known
// state. This module holds the pure state machine and the worker that drives it; storage is an
// injected OutboxStore (memory-store.mjs, and lib/repo/outbox.mjs over control.sqlite).
//
// Row states:
//   queued ──claim──▶ sending ──accepted──▶ delivered
//     ▲  ▲               │──retry / unknown (resend allowed, before expiry)──▶ queued (later)
//     │  │               │──failed, or unknown with no resend left──▶ dead
//     │  │               │──retry past expiry──▶ dead (expired)
//     │  │               │──pause──▶ held (and the channel's other queued rows too)
//     │  │               └──skipped──▶ skipped
//     │  └─resume / probe── held ──expiry──▶ dead (expired)
//     ├── Retry now: dead (a fresh age budget) or retrying ──▶ queued, due now
//     └── (a new row) ── supersede ──▶ superseded · source deleted ──▶ cancelled ·
//         restored data ──▶ stale · send-time recheck ──▶ skipped (unsent)
// "unknown" is an outcome, not a resting state: a lease that ran out (a crash while sending) is
// resolved like a timeout, by the channel's resend rule.
//
// Pauses (delivery spec D10): a channel that pauses holds its rows. One that may recover by itself
// (a transient pause: a 404 while a proxy restarts) lets one probe through every circuitCapMs (15
// minutes); every start probes each paused channel once (the delivery service sets nextSendAt);
// Resume, a settings change or an accepted probe resumes it. A channel that is not paused keeps no
// held rows: each pass releases any it finds (a resume whose release a full store refused).
//
// Clock steps (D25): each pass compares wall-clock and monotonic time since the previous pass. A
// forward step of more than a minute moves active rows' expiry forward by the step (each keeps
// the life it had left, never more than its maximum age from now) instead of expiring them
// unsent; a backward step caps waits that would otherwise last until the clock caught up.
//
// Ordering: at most `concurrency` sends per channel (1 by default) and `maxInFlight` (4) in all.
// A row waits while an earlier row with the same (channel, orderKey) is still active, so a
// "resolved" never overtakes its "firing". Digest channels (email) send every row of their
// quiet window as one message, and retry that same batch, whole (it keeps its Message-ID), or
// not at all; a batch a pass holds back holds back the later rows of its alerts in that pass,
// and one that waits only for its rows past the pass's candidates is sent whole from the store
// when nothing else can start. Candidates are read per channel, so one channel's backlog never
// delays another's due rows.
//
// OutboxStore (all async; rows are copies; test/notify/store-contract.mjs is its executable
// specification, which the control-database adapter of wave 2 must pass as well):
//   insert(rows) -> {inserted: rows with ids, duplicates: uids}   UNIQUE (eventUid, channelId, target)
//   candidates({now, limit, channels}) -> queued rows due now (nextAt <= now < expiresAt), in id
//     order, at most `limit`, only on `channels` (ids; all when omitted) that are neither paused
//     nor in back-off (status.nextSendAt > now). A row is left out while an earlier row of the
//     same (channelId, orderKey) is active and not itself returned: a run of due rows of one
//     key is returned together (a digest sends them as one message; other channels take the
//     first), but nothing is returned behind a row that is sending, held or waiting to retry.
//   claim(ids, {owner, epoch, now, leaseUntil, digestKey}) -> rows moved queued -> sending
//     (attempts + 1; digestKey kept when null); rows no longer queued are skipped
//   complete([{id, patch}], {owner, epoch}) -> rows changed (only 'sending' rows with that lease)
//   sending() -> every 'sending' row · expire(now) -> queued or held rows at or past expiresAt
//     become dead ('expired') · hold(channelId, now) -> queued rows become held ·
//     release(channelId, now) -> held rows become queued, due now (one it cannot write rejects;
//     it never answers as if they were released)
//   supersede({channelId, orderKey, kinds, now, reason?, createdBefore?}) -> queued or held rows
//     of those kinds become superseded · channel(id) -> status | null · setChannel(id, status) ·
//     channelIds() · countActive() · counts() -> {total, byChannel, oldestQueuedAt} ·
//     nextDueAt(now) -> the earliest nextAt of a queued row or leaseUntil of a sending row after
//     `now`, or null · list({states, channelId, orderKey, beforeId, afterId, excludeWaiting,
//     limit}) newest first (excludeWaiting: no queued row with attempts 0) ·
//     prune({now, finished, dead, limit}) -> rows removed
//   and the delivery spec §5.2 additions: find(uid), batch(digestKey, {states}) (only rows in
//     `states` when given), requeue(ids, {now, expiresAt}), stale({now, reason}), unclaim(ids,
//     {owner, epoch, now}), cancel({orderKeyPrefix, now, reason}), activeKeys(keys),
//     shiftExpiry({by, now}), clampTimes({now, nextAtMax, expiresAtMax, leaseUntilMax}),
//     summary({failedSince})
import { createHash, randomBytes } from 'node:crypto';
import { systemClock, safeErrorText } from '../jobs.mjs';
import { DELIVERY_POLICY, retryDelayMs, circuitDelayMs } from './retry.mjs';
import {
  defineChannel,
  normaliseOutcome,
  retry,
  unknown,
  skipped,
  safeReason,
} from './channel.mjs';
import { SNAPSHOT_LIMIT, OUTBOX_LIMITS } from './limits.mjs';

export const ACTIVE_STATES = Object.freeze(['queued', 'sending', 'held']);
export const TERMINAL_STATES = Object.freeze([
  'delivered',
  'dead',
  'superseded',
  'cancelled',
  'stale',
  'skipped',
]);
export const STATES = Object.freeze([...ACTIVE_STATES, ...TERMINAL_STATES]);
export { SNAPSHOT_LIMIT, OUTBOX_LIMITS };

const BASE32 = 'abcdefghijklmnopqrstuvwxyz234567';
function base32(bytes) {
  let bits = 0,
    value = 0,
    out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
    value &= (1 << bits) - 1;
  }
  if (bits) out += BASE32[(value << (5 - bits)) & 31];
  return out;
}
const hashId = (prefix, text) =>
  prefix + base32(createHash('sha256').update(text).digest()).slice(0, 26);

/** The delivery id (X-Goblin-Delivery): the same event, channel and target always give it. */
export const deliveryUid = (eventUid, channelId, target = '') =>
  hashId('d_', `${eventUid}\n${channelId}\n${target}`);
/** The id of a digest batch, kept by its rows so a retry sends the same batch. */
export const digestKeyFor = uids => hashId('g_', [...uids].sort().join('\n'));
/**
 * A new alert event's uid (history `events.uid`): random, so an event id that SQLite reuses
 * after a source is deleted (V1) can never name the wrong event.
 */
export const newEventUid = () => 'e_' + base32(randomBytes(16)).slice(0, 26);

/** Kinds that a new row of `kind` replaces while they are still waiting (design §2.7). */
export function supersededKinds(kind) {
  if (kind === 'reminder') return ['reminder'];
  if (kind === 'resolved' || kind === 'cleared') return ['reminder', 'escalated', 'acknowledged'];
  return [];
}

/** Pure: the fields a claimed row takes after a send outcome. */
export function rowAfterOutcome(
  row,
  outcome,
  { now, rng = Math.random, policy = DELIVERY_POLICY, channel = {} } = {}
) {
  const base = {
    leaseOwner: null,
    leaseUntil: null,
    updatedAt: now,
    lastStatus: outcome.status ?? null,
  };
  const dead = (deadReason, lastError) => ({ ...base, state: 'dead', deadReason, lastError });
  switch (outcome.type) {
    case 'accepted':
      return {
        ...base,
        state: 'delivered',
        sentAt: now,
        lastError: null,
        externalRef: outcome.externalRef ?? row.externalRef ?? null,
      };
    case 'skipped':
      // Nothing was sent (the send-time recheck, or a channel that is not set up or is switched
      // off): the claim's attempt is not counted, as unclaim() does not count it (amendment A58).
      return {
        ...base,
        state: 'skipped',
        attempts: Math.max(0, (row.attempts ?? 1) - 1),
        lastError: outcome.reason,
      };
    case 'failed':
      return dead('failed', outcome.reason);
    case 'pause':
      return { ...base, state: 'held', nextAt: now, lastError: outcome.reason };
    case 'unknown': {
      const resends = row.unknowns ?? 0;
      if (resends >= (channel.unknown?.maxResends ?? 3)) return dead('unknown', outcome.reason);
      const nextAt =
        now +
        (channel.unknown?.resendAfterMs ?? retryDelayMs({ attempt: row.attempts, rng, policy }));
      if (nextAt >= row.expiresAt) return dead('expired', outcome.reason);
      return { ...base, state: 'queued', nextAt, unknowns: resends + 1, lastError: outcome.reason };
    }
    default: {
      const nextAt =
        now + retryDelayMs({ attempt: row.attempts, afterMs: outcome.afterMs, rng, policy });
      // No attempt could happen before the row expires: it is a dead letter now.
      if (nextAt >= row.expiresAt) return dead('expired', outcome.reason);
      return { ...base, state: 'queued', nextAt, lastError: outcome.reason };
    }
  }
}

export const initialChannelStatus = () => ({
  state: 'ok', // ok | retrying | circuit-open | paused
  pausedReason: null,
  nextSendAt: 0,
  consecutiveFailures: 0,
  failedTotal: 0,
  deliveredTotal: 0,
  lastAttempt: null,
  lastSuccess: null,
  lastFailure: null,
  lastError: null,
  pausedSince: null, // when the current pause began, kept through probes
  consecutiveRefusals: 0, // `failed` outcomes in a row: three mean "refusing"
});

/**
 * Pure: a channel's health after a send outcome (the circuit breaker lives here).
 * - accepted, failed: the endpoint answered, so a pause (and a probe) ends; three `failed` in a
 *   row mark the channel as refusing (consecutiveRefusals, D29), one accepted clears it.
 * - pause: pausedSince is kept from the pause's start (through probes); a transient pause may
 *   probe again after circuitCapMs, any other only after Resume, a settings change or a start.
 * - retry, unknown: the circuit opens after 5 in a row; a 429 or 503 with Retry-After holds the
 *   whole channel (the receiver asked the endpoint to slow down, not one row).
 */
export function channelAfterOutcome(status, outcome, { now, policy = DELIVERY_POLICY } = {}) {
  const p = { ...DELIVERY_POLICY, ...policy };
  const s = { ...initialChannelStatus(), ...status };
  if (outcome.type === 'skipped') return s;
  s.lastAttempt = now;
  const failure = () => ({
    failedTotal: s.failedTotal + 1,
    lastFailure: now,
    lastError: { time: now, message: outcome.reason },
  });
  switch (outcome.type) {
    case 'accepted':
      return {
        ...s,
        state: 'ok',
        pausedReason: null,
        pausedSince: null,
        consecutiveFailures: 0,
        consecutiveRefusals: 0,
        nextSendAt: 0,
        deliveredTotal: s.deliveredTotal + 1,
        lastSuccess: now,
      };
    case 'failed':
      // The endpoint answered: the message was bad, not the channel.
      return {
        ...s,
        ...failure(),
        state: 'ok',
        pausedReason: null,
        pausedSince: null,
        consecutiveFailures: 0,
        consecutiveRefusals: s.consecutiveRefusals + 1,
        nextSendAt: 0,
      };
    case 'pause':
      return {
        ...s,
        ...failure(),
        state: 'paused',
        pausedReason: outcome.reason,
        pausedSince: s.pausedSince ?? now,
        nextSendAt: outcome.transient ? now + p.circuitCapMs : 0,
      };
    default: {
      const consecutiveFailures = s.consecutiveFailures + 1,
        open = circuitDelayMs(consecutiveFailures, p);
      let nextSendAt = open ? now + open : 0;
      if (
        outcome.type === 'retry' &&
        Number.isFinite(outcome.afterMs) &&
        (outcome.status === 429 || outcome.status === 503)
      )
        nextSendAt = Math.max(nextSendAt, now + Math.min(outcome.afterMs, p.retryAfterCapMs));
      return {
        ...s,
        ...failure(),
        consecutiveFailures,
        state: open ? 'circuit-open' : 'retrying',
        nextSendAt,
      };
    }
  }
}

// Paused: the channel's own state, or a pause no accepted or refused answer has ended yet (a
// probe in progress). Retry is refused for such a channel's rows.
const isPausedStatus = status => status?.state === 'paused' || status?.pausedSince != null;

/**
 * Pure: which rows of a digest channel go out now. Rows already sent as a batch (digestKey)
 * go out again together; new rows form one window, due once the newest is `windowMs` old or
 * the oldest is `maxFactor × windowMs` old (1.4.2's email batching, computed from timestamps so
 * it survives a restart). `ignoreWindows` sends at once (shutdown, flushNotifications).
 */
export function planDigest(
  rows,
  { now, windowMs, maxFactor = 3, ignoreWindows = false, maxBatch = 100 }
) {
  const batches = [],
    earlier = new Map(),
    fresh = [];
  for (const row of rows) {
    if (row.digestKey) {
      if (!earlier.has(row.digestKey)) earlier.set(row.digestKey, []);
      earlier.get(row.digestKey).push(row);
    } else fresh.push(row);
  }
  batches.push(...earlier.values());
  let wakeAt = null;
  if (fresh.length) {
    // A row created later than now was queued before the clock stepped back (D25; a new row is
    // never created later than now). Its wait cannot be measured on this clock, so it counts as
    // having waited the whole cap: a window cannot stay open until the clock catches up.
    const created = fresh.map(row =>
      row.createdAt <= now ? row.createdAt : now - windowMs * maxFactor
    );
    const dueAt = Math.min(
      Math.max(...created) + windowMs,
      Math.min(...created) + windowMs * maxFactor
    );
    if (ignoreWindows || dueAt <= now)
      for (let i = 0; i < fresh.length; i += maxBatch) batches.push(fresh.slice(i, i + maxBatch));
    else wakeAt = dueAt;
  }
  return { batches, wakeAt };
}

const CHANNEL_ID = /^[a-z0-9][a-z0-9_-]{0,39}$/;
const within = (value, max) => typeof value === 'string' && value.length <= max;

function validEntry(entry) {
  if (!within(entry?.eventUid, OUTBOX_LIMITS.eventUid) || !entry.eventUid)
    throw new TypeError(
      `An outbox entry needs an eventUid of 1-${OUTBOX_LIMITS.eventUid} characters`
    );
  if (!CHANNEL_ID.test(entry.channelId ?? ''))
    throw new TypeError('An outbox entry needs a valid channelId');
  if (typeof entry.kind !== 'string' || !/^[a-z_]{1,40}$/.test(entry.kind))
    throw new TypeError('An outbox entry needs a kind');
  if (entry.target != null && !within(String(entry.target), OUTBOX_LIMITS.target))
    throw new TypeError(`An outbox target is at most ${OUTBOX_LIMITS.target} characters`);
  if (entry.orderKey != null && !within(String(entry.orderKey), OUTBOX_LIMITS.orderKey))
    throw new TypeError(`An outbox orderKey is at most ${OUTBOX_LIMITS.orderKey} characters`);
  if (entry.severity != null && !/^[a-z]{1,16}$/.test(entry.severity))
    throw new TypeError('An outbox severity is a lower-case word');
  if (entry.maxAgeMs !== undefined && !(Number.isFinite(entry.maxAgeMs) && entry.maxAgeMs > 0))
    throw new TypeError('An outbox maxAgeMs must be above 0');
  if (!entry.event || typeof entry.event !== 'object' || Array.isArray(entry.event))
    throw new TypeError('An outbox entry needs an event snapshot object');
  if (Buffer.byteLength(JSON.stringify(entry.event)) > SNAPSHOT_LIMIT)
    throw new TypeError(`An event snapshot must be at most ${SNAPSHOT_LIMIT} bytes of JSON`);
}

const day = 24 * 60 * 60 * 1000;
const duration = ms => {
  const abs = Math.abs(ms);
  if (abs >= 2 * day) return `${Math.round(abs / day)} days`;
  if (abs >= 2 * 3600 * 1000) return `${Math.round(abs / 3600000)} hours`;
  return `${Math.round(abs / 60000)} minutes`;
};
const numericPart = id => Number(String(id).replace(/^m:/, ''));
const inMemory = id => String(id).startsWith('m:');
// Whether `other` was written after `row`: ids within one store. Across the memory and the
// control store (degraded, D15) the row kept in memory is the later one, as the failover store's
// D23 rules make it: a new row whose alert has a row in memory goes to memory too, a row saved
// from memory gets a new id above every saved row of its alert, and a row Retry makes active
// again was older to begin with. Never the creation time: it is wall-clock time, which a backward
// clock step (D25) puts out of order, so a recovery kept in memory sorted before its firing and
// Retry sent the firing after it, or two digests waited for each other until they expired.
const isLater = (other, row) =>
  inMemory(other.id) === inMemory(row.id)
    ? numericPart(other.id) > numericPart(row.id)
    : inMemory(other.id);
// Store order (the order of each alert's rows, D23): for sort().
const byStoreOrder = (a, b) => (isLater(a, b) ? 1 : isLater(b, a) ? -1 : 0);

const stopReason = () =>
  Object.assign(new Error('Uptime Goblin is stopping.'), { name: 'AbortError', code: 'ABORT_ERR' });
const settingsChangedReason = () =>
  Object.assign(new Error('The channel settings changed.'), {
    name: 'AbortError',
    code: 'ABORT_ERR',
  });

/**
 * createOutbox({store, channels, clock, rng, owner, policy, logger, maxInFlight, candidateLimit,
 * pollMs, maxActive, singleProcess, recheck, onChannel}) returns
 *   enqueue(entries), run(ctx), pump({epoch, ignoreWindows, signal}), flush({ignoreWindows,
 *   timeoutMs}), recover({foreign}), pause(channelId, reason, {transient}), resume(channelId),
 *   channelChanged(channelId), retry(uid, {now, ready, check}),
 *   retryable(row, {status, cache, ready}), recordTest(channelId, {accepted, message}),
 *   cancelSource(serviceId, reason), updateChannel(channelId, change), markStale(reason),
 *   probe(), sending(channelId), status(), prune(options), stop({timeoutMs}),
 *   notQueued(channelId), and the getters inFlight and dropped.
 * `recheck(row)` -> null | reason is asked before a row is sent: a reason skips it unsent (the
 * delivery service's D24 checks), and Retry refuses a row it gives a reason for.
 * `onChannel({channelId, previous, next})` is called after every committed change of a
 * channel's status (the pause notices of D28).
 * An entry is {eventUid, channelId, target?, kind, severity?, orderKey?, event, createdAt?,
 * maxAgeMs?}; `event` is the snapshot the channel renders at send time (at most 4 KiB).
 * `run(ctx)` is the body of a continuous leader task (lib/jobs.mjs leaderTask); at shutdown stop
 * the job runner first (which ends run()), then call stop() to let sends in flight finish.
 */
export function createOutbox({
  store,
  channels = [],
  clock = systemClock,
  rng = Math.random,
  owner = `o_${randomBytes(6).toString('hex')}`,
  policy: overrides = {},
  logger = console,
  maxInFlight = 4,
  candidateLimit = 200,
  pollMs = 1000,
  maxActive = 10000,
  // SQLite mode: one process sends, so rows another process left 'sending' are resolved at once.
  singleProcess = true,
  recheck = () => null,
  onChannel = () => {},
} = {}) {
  if (!store) throw new TypeError('createOutbox needs a store');
  const policy = { ...DELIVERY_POLICY, ...overrides };
  const registry = new Map();
  for (const channel of channels instanceof Map ? channels.values() : channels) {
    const defined = defineChannel(channel);
    if (registry.has(defined.name)) throw new TypeError(`Channel ${defined.name} is listed twice`);
    registry.set(defined.name, defined);
  }
  const inFlight = new Map(),
    inFlightRows = new Set(),
    perChannel = new Map();
  let stopping = false,
    dropped = 0,
    lastError = null,
    dirty = false,
    wakeWaiter = null,
    // Wall and monotonic time at the start of the previous pass (clock steps, D25).
    lastPass = null;
  // Passes in progress, so stop() can wait for one that is still claiming.
  const pumps = new Set();

  const wake = () => {
    dirty = true;
    wakeWaiter?.();
  };
  // Rows the backlog cap refused, per channel, since this outbox was made: how many and when the
  // last was, for the Status (amendment A46: the page and a banner say so, since a refused alert
  // has no row to list), and what the log has not said yet (A47).
  const capRefusals = new Map();
  /**
   * The backlog-cap log line, per channel and at most once a minute (§6.7): a flood of alerts
   * against a full backlog gave one identical line per alert. The first refusal is logged at
   * once; those within the minute after a line are added up and logged in one line ("n more")
   * once the minute is over, by the next refusal, the next pass or stop() (`all`), so no refusal
   * goes unlogged. Measured on the monotonic clock, which a clock step does not move.
   */
  function logCapRefusals({ all = false } = {}) {
    const mono = clock.now();
    for (const [channelId, entry] of capRefusals) {
      if (!entry.unlogged) continue;
      if (!all && entry.loggedAt !== null && mono - entry.loggedAt < 60 * 1000) {
        entry.held = true;
        continue;
      }
      logger.error?.(
        `The ${channelId} notification backlog is full (${maxActive} waiting); ${entry.unlogged} ${entry.held ? 'more ' : ''}notification(s) were not queued.`
      );
      Object.assign(entry, { unlogged: 0, held: false, loggedAt: mono });
    }
  }
  function capRefused(channelId, count, now) {
    dropped += count;
    const entry = capRefusals.get(channelId) ?? {
      count: 0,
      lastAt: null,
      unlogged: 0,
      held: false,
      loggedAt: null,
    };
    entry.count += count;
    entry.lastAt = now;
    entry.unlogged += count;
    capRefusals.set(channelId, entry);
    logCapRefusals();
  }

  // A problem that repeats (a store failing on every pass) is logged once a minute, not each time.
  const note = (message, error) => {
    const text = `${message}: ${safeErrorText(error)}`,
      time = clock.wall();
    const repeat = lastError?.message === text && time - lastError.loggedAt < 60 * 1000;
    lastError = { time, message: text, loggedAt: repeat ? lastError.loggedAt : time };
    if (!repeat) logger.error?.(text);
  };

  function newRow(entry, now) {
    validEntry(entry);
    // Never later than now: an event stamped by a clock that has since stepped back (D25).
    const createdAt = Math.min(Number.isFinite(entry.createdAt) ? entry.createdAt : now, now),
      target = String(entry.target ?? ''),
      age = entry.maxAgeMs ?? registry.get(entry.channelId)?.maxAgeMs ?? policy.maxAgeMs;
    return {
      uid: deliveryUid(entry.eventUid, entry.channelId, target),
      eventUid: entry.eventUid,
      channelId: entry.channelId,
      target,
      kind: entry.kind,
      severity: entry.severity ?? null,
      orderKey:
        entry.orderKey === undefined || entry.orderKey === null ? null : String(entry.orderKey),
      event: structuredClone(entry.event),
      state: 'queued',
      attempts: 0,
      unknowns: 0,
      nextAt: createdAt,
      createdAt,
      expiresAt: createdAt + age,
      digestKey: null,
      leaseOwner: null,
      leaseUntil: null,
      epoch: 0,
      sentAt: null,
      lastStatus: null,
      lastError: null,
      deadReason: null,
      externalRef: null,
      updatedAt: now,
    };
  }

  // Channel status is read, changed and written back; one chain per channel keeps two
  // completions (or a completion and a pause) from overwriting each other's counts.
  const statusChains = new Map();
  const channelVersions = new Map();
  const channelVersion = channelId => channelVersions.get(channelId) ?? 0;
  function updateChannel(channelId, change, after = () => {}) {
    const previous = statusChains.get(channelId) ?? Promise.resolve();
    const next = previous
      .catch(() => {})
      .then(async () => {
        const current = { ...initialChannelStatus(), ...(await store.channel(channelId)) };
        const changed = await change(current);
        if (changed === null) return;
        await store.setChannel(channelId, changed);
        channelVersions.set(channelId, channelVersion(channelId) + 1);
        try {
          onChannel({ channelId, previous: current, next: { ...changed } });
        } catch (error) {
          note('A channel status listener failed', error);
        }
        return after();
      });
    statusChains.set(channelId, next);
    void next
      .catch(() => {})
      .finally(() => {
        if (statusChains.get(channelId) === next) statusChains.delete(channelId);
      });
    return next;
  }

  // Each channel's active rows (queued, sending, held), from the store's per-channel summary.
  // When that cannot be read, every channel counts the total `active`: one shared cap, as before,
  // which refuses more rows than the per-channel rule, never fewer.
  async function activeByChannel(active) {
    try {
      const summary = await store.summary();
      return channelId => {
        const part = summary?.[channelId];
        return part ? part.waiting + part.retrying + part.sending + part.held : 0;
      };
    } catch (error) {
      note('The notification backlog could not be counted per channel', error);
      return () => active;
    }
  }

  /** Writes rows for new notifications; the same (event, channel, target) is written once. */
  async function enqueue(entries) {
    const list = Array.isArray(entries) ? entries : [entries],
      now = clock.wall();
    const rows = list.map(entry => newRow(entry, now));
    // Backlog cap, per channel: digest channels absorb any number of rows into one message;
    // another channel stops taking new rows while its own backlog is full (counted and logged,
    // never silent). Counted per channel because email's rows are never refused: with email
    // paused for a day its backlog alone filled a shared count, and the working webhook then
    // dropped every new alert. The total is read first, so the per-channel counts are read only
    // when the cap could apply.
    let accepted = rows;
    const active = await store.countActive();
    if (active + rows.length > maxActive) {
      const activeOf = await activeByChannel(active);
      const room = new Map(),
        lost = new Map();
      accepted = rows.filter(row => {
        if (registry.get(row.channelId)?.digest) return true;
        const left = room.get(row.channelId) ?? Math.max(0, maxActive - activeOf(row.channelId));
        room.set(row.channelId, left - 1);
        if (left <= 0) lost.set(row.channelId, (lost.get(row.channelId) ?? 0) + 1);
        return left > 0;
      });
      for (const [channelId, count] of lost) capRefused(channelId, count, now);
    }
    // Only a row that is queued replaces what it supersedes: rows already stored, and earlier
    // rows of this same batch.
    let superseded = 0;
    for (const [index, row] of accepted.entries()) {
      const kinds = supersededKinds(row.kind);
      if (!kinds.length || row.orderKey === null) continue;
      superseded += await store.supersede({
        channelId: row.channelId,
        orderKey: row.orderKey,
        kinds,
        now,
      });
      for (const earlier of accepted.slice(0, index))
        if (
          earlier.state === 'queued' &&
          earlier.channelId === row.channelId &&
          earlier.orderKey === row.orderKey &&
          kinds.includes(earlier.kind)
        ) {
          earlier.state = 'superseded';
          superseded++;
        }
    }
    const health = new Map();
    for (const row of accepted) {
      if (!health.has(row.channelId)) health.set(row.channelId, await store.channel(row.channelId));
      if (row.state === 'queued' && health.get(row.channelId)?.state === 'paused')
        row.state = 'held';
    }
    const result = await store.insert(accepted);
    wake();
    return {
      inserted: result.inserted.length,
      duplicates: result.duplicates.length,
      superseded,
      dropped: rows.length - accepted.length,
      uids: result.inserted.map(row => row.uid),
      // Kept in memory (the control database could not be written, D15): the relay marks their
      // event only once these rows are final, so a restart sends them again.
      memoryUids: result.inserted.filter(row => inMemory(row.id)).map(row => row.uid),
    };
  }

  // The longest age a row may have: no clock-step adjustment ever lets a row live longer from now.
  const longestAge = () =>
    Math.max(policy.maxAgeMs, ...[...registry.values()].map(channel => channel.maxAgeMs ?? 0));

  // `claimedAt` is the wall and monotonic time of the pass that claimed the rows (startSend).
  async function complete(channel, rows, outcome, epoch, claimedAt = null) {
    const now = clock.wall(),
      u = rng(),
      // One draw per batch, so the rows of a digest stay together when retried.
      same = () => u;
    // D25: the wall clock jumped forward while this send was in flight. The claimed copies carry
    // the expiry from before the jump (a pass moves only the stored rows' expiry), so the same
    // move is applied to them before the outcome is judged against it; otherwise a retry or
    // "unknown" answer arriving after an NTP step expired the row (or a whole digest), where a
    // waiting row keeps the life it had left. Only the judgement uses it: the stored expiry is
    // the pass's to move (once), so the patch leaves it alone.
    const step = claimedAt ? now - claimedAt.wall - (clock.now() - claimedAt.mono) : 0;
    let judged = rows;
    if (step > 60000) {
      const latest = now + longestAge();
      judged = rows.map(row => ({
        ...row,
        expiresAt: Math.max(row.expiresAt, Math.min(row.expiresAt + step, latest)),
      }));
    }
    const patches = judged.map(row => ({
      id: row.id,
      patch: rowAfterOutcome(row, outcome, { now, rng: same, policy, channel }),
    }));
    const changed = await store.complete(patches, { owner, epoch });
    if (!changed) {
      logger.warn?.(
        `A ${channel.name} delivery result was not recorded: another worker owns those rows now.`
      );
      return;
    }
    await updateChannel(
      channel.name,
      status => channelAfterOutcome(status, outcome, { now, policy }),
      () => (outcome.type === 'pause' ? store.hold(channel.name, now) : undefined)
    );
  }

  // `claimedAt`: the wall and monotonic time of the pass that claimed the rows.
  function startSend(channel, rows, epoch, digestKey, claimedAt) {
    const controller = new AbortController(),
      key = Symbol(channel.name),
      first = rows[0];
    perChannel.set(channel.name, (perChannel.get(channel.name) ?? 0) + 1);
    for (const row of rows) inFlightRows.add(row.id);
    const message = {
      uid: digestKey ?? first.uid,
      channelId: channel.name,
      target: first.target,
      kind: rows.length > 1 ? 'digest' : first.kind,
      attempt: first.attempts,
      digest: rows.length > 1,
      events: rows.map(row => row.event),
    };
    const promise = (async () => {
      let outcome;
      try {
        outcome = normaliseOutcome(await channel.send(message, { signal: controller.signal }));
      } catch (error) {
        outcome = retry(null, `The ${channel.name} channel failed unexpectedly.`);
        note(`The ${channel.name} channel threw`, error);
      }
      await complete(channel, rows, outcome, epoch, claimedAt);
    })()
      .catch(error => note(`Could not record a ${channel.name} delivery result`, error))
      .finally(() => {
        inFlight.delete(key);
        for (const row of rows) inFlightRows.delete(row.id);
        perChannel.set(channel.name, perChannel.get(channel.name) - 1);
        wake();
      });
    inFlight.set(key, { promise, controller, channelId: channel.name });
  }

  /**
   * Resolves rows stuck in 'sending': those whose lease ran out, and with `foreign` (SQLite mode,
   * at start) every row another process left behind. They count as "acceptance unknown".
   */
  async function recover({ foreign = false, now = clock.wall() } = {}) {
    const outcome = unknown('Uptime Goblin stopped while sending; acceptance is unknown.');
    const groups = new Map();
    for (const row of await store.sending()) {
      if (inFlightRows.has(row.id)) continue;
      if (!(row.leaseUntil <= now || (foreign && row.leaseOwner !== owner))) continue;
      const group = `${row.leaseOwner}\n${row.epoch}\n${row.digestKey ?? row.id}`;
      if (!groups.has(group)) groups.set(group, []);
      groups.get(group).push(row);
    }
    let recovered = 0;
    for (const rows of groups.values()) {
      const channel = registry.get(rows[0].channelId) ?? {},
        u = rng();
      const patches = rows.map(row => ({
        id: row.id,
        patch: rowAfterOutcome(row, outcome, { now, rng: () => u, policy, channel }),
      }));
      recovered += await store.complete(patches, {
        owner: rows[0].leaseOwner,
        epoch: rows[0].epoch,
      });
    }
    return recovered;
  }

  // Clock steps (D25): compares this pass with the previous one and adjusts stored times.
  // Resolves true when this pass must not expire anything (a forward step).
  async function adjustForClockSteps(now) {
    const mono = clock.now(),
      base = lastPass;
    lastPass = { wall: now, mono };
    if (!base) return false;
    const step = now - base.wall - (mono - base.mono);
    if (Math.abs(step) <= 60000) return false;
    const maxAge = longestAge();
    try {
      if (step > 0) {
        // Forward: the time jumped, not the rows; each keeps the life it had left, and none
        // more than its maximum age from now (so a bogus jump of years cannot keep rows alive).
        await store.shiftExpiry({ by: step, now });
        await store.clampTimes({
          now,
          nextAtMax: Number.MAX_SAFE_INTEGER,
          expiresAtMax: now + maxAge,
          leaseUntilMax: Number.MAX_SAFE_INTEGER,
        });
      } else {
        await store.clampTimes({
          now,
          nextAtMax: now + policy.capMs,
          expiresAtMax: now + maxAge,
          leaseUntilMax: now + policy.leaseMs,
        });
        for (const channelId of registry.keys()) {
          const health = await store.channel(channelId);
          if (health && health.nextSendAt > now + policy.circuitCapMs)
            await updateChannel(channelId, status =>
              status.nextSendAt > now + policy.circuitCapMs
                ? { ...status, nextSendAt: now + policy.circuitCapMs }
                : status
            );
        }
      }
    } catch (error) {
      // Not adjusted: the next pass sees the same step again.
      lastPass = base;
      throw error;
    }
    logger.warn?.(
      `The system clock jumped ${step > 0 ? 'forward' : 'back'} by ${duration(step)}; notification times were adjusted.`
    );
    return step > 0;
  }

  // A release that could not be written (or a check for held rows that could not be read). One
  // text for every channel and both paths, so a store refusing every write logs it once a
  // minute, not on every pass.
  const heldNotReleased = error => note('Held notifications could not be released yet', error);

  // Each pass, for every channel this release knows:
  // - Probes (D10): a paused channel whose next probe is due, with nothing in flight, lets one
  //   send through: its held rows are queued again, then the open circuit admits a single one.
  //   The release comes first. A probe whose release cannot be written (a full control database)
  //   leaves the channel paused and due, so the next pass tries again; an open circuit with
  //   every row still held was never probed again (probes look only at paused channels).
  // - Upkeep: a channel that is not paused keeps no held rows. A resume whose release could not
  //   be written, a stop between a resume's two writes, or a row inserted held just as its
  //   channel resumed would otherwise wait until it expired: Resume and Retry see a working
  //   channel, and nothing else releases them. One indexed read per channel when none are held.
  async function probeChannels(now, later) {
    for (const channelId of registry.keys()) {
      const health = await store.channel(channelId);
      // A send in flight may be pausing the channel right now (complete() holds after it saves
      // the pause): its rows are left alone until it has finished.
      const busy = (perChannel.get(channelId) ?? 0) > 0;
      if (health?.state !== 'paused') {
        if (!busy) await releaseStranded(channelId, now);
        continue;
      }
      if (!(health.nextSendAt > 0)) continue;
      if (health.nextSendAt > now) {
        later(health.nextSendAt);
        continue;
      }
      if (busy) continue;
      try {
        await store.release(channelId, now);
      } catch (error) {
        heldNotReleased(error);
        continue;
      }
      await updateChannel(channelId, status =>
        status.state !== 'paused' || !(status.nextSendAt > 0) || status.nextSendAt > now
          ? status
          : { ...status, state: 'circuit-open', nextSendAt: now }
      );
    }
  }

  // The upkeep's release of a channel that is not paused (above).
  async function releaseStranded(channelId, now) {
    try {
      const [held] = await store.list({ states: ['held'], channelId, limit: 1 });
      if (held) await store.release(channelId, now);
    } catch (error) {
      heldNotReleased(error);
    }
  }

  // Completes a row the send-time recheck refused, unsent and without a channel-status change.
  // The claim adds an attempt; the skipped outcome takes it back (rowAfterOutcome).
  async function skipRow(row, reason, epoch, now) {
    const [claimed] = await store.claim([row.id], {
      owner,
      epoch,
      now,
      leaseUntil: now + policy.leaseMs,
      digestKey: null,
    });
    if (!claimed) return;
    await store.complete(
      [{ id: claimed.id, patch: rowAfterOutcome(claimed, skipped(reason), { now, policy }) }],
      { owner, epoch }
    );
  }

  // A digest batch that was tried before keeps its Message-ID, so it goes out whole or waits. A
  // row of it that this pass did not get (held back behind an older row of its alert that Retry
  // now made active again, past the candidate limit, or held in control.sqlite while a resume
  // released its rows kept in memory) would otherwise go later on its own under the same
  // Message-ID, and mail providers drop a second message whose Message-ID they already hold.
  // Resolves {rest}: the batch's active rows that are not among `rows` (none: it is whole), or
  // {error} when the batch cannot be read. Rows of the batch that ended meanwhile (cancelled,
  // skipped, expired) are not active, so they are not waited for.
  async function restOfBatch(digestKey, rows) {
    try {
      const active = await store.batch(digestKey, { states: ACTIVE_STATES });
      const here = new Set(rows.map(row => row.id));
      return { rest: active.filter(row => !here.has(row.id)) };
    } catch (error) {
      note('A digest batch could not be checked before sending', error);
      return { error };
    }
  }

  // Claims a batch's rows. Rows the claim does not get ended meanwhile, or are in a store that
  // refused the write (the failover store claims the rows kept in memory when control.sqlite is
  // full, and none of control.sqlite's). A digest tried before is sent only when every row of it
  // still active was claimed; otherwise its claimed rows go back, the attempt not counted, and
  // this resolves null: its claimed half sent alone would carry its Message-ID, and the other
  // half sent later the same Message-ID again, which mail providers drop as a duplicate while
  // Uptime Goblin marks it delivered.
  async function claimBatch(batch, { digestKey, triedBefore, epoch, now }) {
    const claimed = await store.claim(
      batch.map(row => row.id),
      { owner, epoch, now, leaseUntil: now + policy.leaseMs, digestKey }
    );
    if (triedBefore && claimed.length && claimed.length < batch.length) {
      const { rest } = await restOfBatch(digestKey, claimed);
      if (!rest || rest.length) {
        await store.unclaim(
          claimed.map(row => row.id),
          { owner, epoch, now: clock.wall() }
        );
        return null;
      }
    }
    return claimed;
  }

  // Whether `rows` (a digest about to go whole) hold the earliest active rows of each of their
  // alerts on the channel: no active row of one of those alerts that is not among them comes
  // before one that is (D23). `candidates` are this pass's: an alert whose rows here all came
  // from them is checked against them (the store returns a due row only with every earlier active
  // row of its alert, and those have lower ids, so they are among the candidates too). Any other
  // is read from the store: its active rows before the latest of them here. A page of 100 is
  // never all ours (a digest holds at most 100 rows, the latest not on the page), so a full page
  // fails and a shorter one is complete.
  async function earliestOfTheirAlerts(rows, candidates) {
    const here = new Set(rows.map(row => row.id)),
      fromCandidates = new Set(candidates.map(row => row.id));
    const latest = new Map();
    for (const row of rows) {
      if (row.orderKey === null) continue;
      const seen = latest.get(row.orderKey);
      latest.set(row.orderKey, {
        row: !seen || isLater(row, seen.row) ? row : seen.row,
        read: Boolean(seen?.read) || !fromCandidates.has(row.id),
      });
    }
    const foreign = list => list.some(other => !here.has(other.id));
    // Checked without a read first: an alert held back by a row among the candidates fails here.
    for (const [orderKey, { row, read }] of latest)
      if (
        !read &&
        candidates.some(
          other => other.orderKey === orderKey && !here.has(other.id) && isLater(row, other)
        )
      )
        return false;
    for (const { row, read } of latest.values()) {
      if (!read) continue;
      const filter = {
        channelId: row.channelId,
        orderKey: row.orderKey,
        states: ACTIVE_STATES,
        limit: 100,
      };
      // A row kept in memory (the failover store, D15) comes after every saved row of its alert:
      // those are all earlier, with the memory rows below it. A saved row comes before every
      // memory row of its alert, so its saved rows below it are all that can be earlier.
      const pages = inMemory(row.id)
        ? [
            await store.list({ ...filter, part: 'memory', beforeId: row.id }),
            await store.list({ ...filter, part: 'saved' }),
          ]
        : [await store.list({ ...filter, beforeId: row.id })];
      if (pages.some(page => page.length >= filter.limit || foreign(page))) return false;
    }
    return true;
  }

  // A digest tried before that this pass held back as not whole (`notWhole`: each batch with its
  // active rows the candidates did not bring), to be sent whole from the store's read of it when
  // nothing else could start. Candidates are the channel's due rows with the lowest ids, at most
  // `candidateLimit`; tried digests whose rows interleave by id can each have rows past that
  // window, so every pass held all of them back, and the rows behind them, and started nothing;
  // the window never moved, so no later email (another alert's too) went until rows expired. The
  // first batch (lowest ids first) whose missing rows are all queued and due, and whose rows are
  // the earliest active rows of their alerts, goes: the missing rows are checked as the
  // candidates' were (D24) and the batch is returned whole, in store order (the order it was
  // first sent in). A batch waiting for a row that is held, sending or waiting to retry, or for
  // an earlier row of one of its alerts, still waits (A5, A35). Null when none can go.
  async function wholeFromStore(notWhole, candidates, epoch, now) {
    const due = row => row.state === 'queued' && row.nextAt <= now && row.expiresAt > now;
    for (const [batch, rest] of notWhole) {
      if (!rest?.length || !rest.every(due)) continue;
      const rows = [...batch, ...rest].sort(byStoreOrder);
      // A read that fails tells nothing: the batch waits, as it did, and the pass goes on.
      let first = false;
      try {
        first = await earliestOfTheirAlerts(rows, candidates);
      } catch (error) {
        note('A digest batch could not be checked before sending', error);
      }
      if (!first) continue;
      const missing = new Set(rest.map(row => row.id)),
        whole = [];
      for (const row of rows) {
        let reason = null;
        if (missing.has(row.id))
          try {
            reason = await recheck(row);
          } catch (error) {
            note('The send-time check failed', error);
          }
        if (reason) await skipRow(row, safeReason(reason), epoch, now);
        else whole.push(row);
      }
      if (whole.length) return whole;
    }
    return null;
  }

  /** One pass: expire, recover, then claim and start what is due. Sends run in the background. */
  function pump(options = {}) {
    const run = pass(options);
    pumps.add(run);
    const done = () => pumps.delete(run);
    run.then(done, done);
    return run;
  }

  async function pass({ epoch = 1, ignoreWindows = false, signal } = {}) {
    // Backlog-cap refusals held back from the log are logged once their minute is over, also
    // when no further alert comes to log them (A47).
    logCapRefusals();
    const now = clock.wall(),
      // The rows this pass claims carry the expiry as of now: a step after it is measured from
      // here when their send completes (complete()).
      startedAt = { wall: now, mono: clock.now() };
    const forward = await adjustForClockSteps(now);
    const expired = forward ? 0 : await store.expire(now);
    const recovered = await recover({ now });
    let wakeAt = await store.nextDueAt(now),
      started = 0;
    const later = at => {
      if (Number.isFinite(at) && at > now && (wakeAt === null || at < wakeAt)) wakeAt = at;
    };
    const halted = () => stopping || Boolean(signal?.aborted);
    if (!halted()) await probeChannels(now, later);
    // Candidates are read per channel, and only for a channel that could start a send now. One
    // read across channels, in id order, gave an idle channel with a backlog (a thousand webhook
    // rows released by Resume) every slot of the limit, so a due email, and the end of its
    // digest window, waited until that backlog was under the limit. Rows of a busy channel, or of
    // a channel this release does not know (kept, never deleted), are not read at all.
    for (const channel of registry.values()) {
      if (halted() || inFlight.size >= maxInFlight) break;
      const channelId = channel.name;
      if ((perChannel.get(channelId) ?? 0) >= channel.concurrency) continue;
      const candidates = await store.candidates({
        now,
        limit: candidateLimit,
        channels: [channelId],
      });
      if (!candidates.length) continue;
      const health = await store.channel(channelId);
      if (health?.state === 'paused') continue;
      if (health?.nextSendAt > now) {
        later(health.nextSendAt);
        continue;
      }
      // D24: a row whose source is gone, or whose alerts were switched off, is skipped unsent.
      const rows = [];
      for (const row of candidates) {
        let reason = null;
        try {
          reason = await recheck(row);
        } catch (error) {
          note('The send-time check failed', error);
        }
        if (reason) await skipRow(row, safeReason(reason), epoch, now);
        else rows.push(row);
      }
      if (!rows.length) continue;
      let free = Math.min(
        channel.concurrency - (perChannel.get(channelId) ?? 0),
        maxInFlight - inFlight.size
      );
      // An open circuit lets a single probe through.
      if (health?.state === 'circuit-open')
        free = Math.min(free, 1 - (perChannel.get(channelId) ?? 0));
      if (free <= 0) continue;
      let batches;
      if (channel.digest) {
        const plan = planDigest(rows, { now, ...channel.digest, ignoreWindows });
        batches = plan.batches;
        later(plan.wakeAt);
      } else {
        const seen = new Set();
        batches = [];
        for (const row of rows) {
          if (row.orderKey !== null) {
            if (seen.has(row.orderKey)) continue;
            seen.add(row.orderKey);
          }
          batches.push([row]);
        }
      }
      // D23 within a pass. Candidates return a run of due rows of one alert together, on the
      // assumption that they go out together or in order; a batch held back in this pass breaks
      // that. So every row a batch holds back waits here, by order key, and a later row of the
      // same alert waits with it: a fresh digest leaves that row for its next window, and a
      // digest tried before waits whole (A5). Without this, a resume that control.sqlite could
      // not write (A20) left a digest's control.sqlite half held while its memory half was due,
      // and the recovery kept in memory behind its alert went out first, on its own.
      const waiting = new Map();
      const holdBack = list => {
        for (const row of list) {
          if (row.orderKey === null) continue;
          if (!waiting.has(row.orderKey)) waiting.set(row.orderKey, []);
          waiting.get(row.orderKey).push(row);
        }
      };
      const behind = row =>
        row.orderKey !== null &&
        (waiting.get(row.orderKey) ?? []).some(other => isLater(row, other));
      // Whether each digest tried before is whole is read before anything is claimed: a batch
      // earlier in the list may hold a later row of an alert whose earlier row waits in a batch
      // after it. A batch that cannot be read is sent as it is: an unreadable store holds
      // nothing back (A5; its claim must still come back whole, below). A read that met a busy
      // database (class `retry`, SQLITE_BUSY past its retries) is only late, and a claim, a
      // write, would meet the same lock: that batch waits for the next pass instead of going
      // out without the rows this pass did not get. Each batch that is not whole is kept with
      // its active rows the candidates did not bring (none when the read failed).
      const notWhole = new Map();
      if (channel.digest)
        for (const batch of batches) {
          if (!batch[0].digestKey) continue;
          const { rest, error } = await restOfBatch(batch[0].digestKey, batch);
          if (error ? error.class !== 'retry' : !rest.length) continue;
          notWhole.set(batch, rest);
          holdBack(batch);
          holdBack(rest ?? []);
        }
      // stop() (or demotion) came while a claim was awaited: no send may start now. The rows go
      // back to the queue, the attempt not counted.
      const giveBack = claimed =>
        store.unclaim(
          claimed.map(row => row.id),
          { owner, epoch, now: clock.wall() }
        );
      let startedHere = 0;
      for (const planned of batches) {
        if (halted() || free <= 0 || inFlight.size >= maxInFlight) break;
        const triedBefore = Boolean(channel.digest && planned[0].digestKey);
        let batch = planned;
        if (triedBefore) {
          if (notWhole.has(planned)) continue;
          if (planned.some(behind)) {
            holdBack(planned);
            continue;
          }
        } else {
          const waits = planned.filter(behind);
          holdBack(waits);
          batch = planned.filter(row => !waits.includes(row));
          if (!batch.length) continue;
        }
        const digestKey = channel.digest
          ? (batch[0].digestKey ?? digestKeyFor(batch.map(row => row.uid)))
          : null;
        // A digest tried before that the claim could not get whole waits whole (claimBatch).
        const claimed = await claimBatch(batch, { digestKey, triedBefore, epoch, now });
        if (!claimed) {
          holdBack(batch);
          continue;
        }
        if (claimed.length < batch.length) {
          const got = new Set(claimed.map(row => row.id));
          holdBack(batch.filter(row => !got.has(row.id)));
        }
        if (!claimed.length) continue;
        if (halted()) {
          await giveBack(claimed);
          return { started, expired, recovered, wakeAt };
        }
        startSend(channel, claimed, epoch, digestKey, startedAt);
        free--;
        started++;
        startedHere++;
      }
      // Nothing could start on this channel, while digests tried before wait for rows the
      // candidates did not bring: one of them that can go whole goes, read from the store
      // (wholeFromStore). Only then, so a pass that sends something keeps the order it had.
      if (notWhole.size && !startedHere && free > 0 && inFlight.size < maxInFlight && !halted()) {
        const whole = await wholeFromStore(notWhole, rows, epoch, now);
        if (!whole) continue;
        const digestKey = whole[0].digestKey;
        const claimed = await claimBatch(whole, { digestKey, triedBefore: true, epoch, now });
        if (!claimed?.length) continue;
        if (halted()) {
          await giveBack(claimed);
          return { started, expired, recovered, wakeAt };
        }
        startSend(channel, claimed, epoch, digestKey, startedAt);
        started++;
      }
    }
    return { started, expired, recovered, wakeAt };
  }

  // Resolves after `ms`, on wake() (a new row, a finished send, a resume) or on abort.
  function idle(ms, signal) {
    if (dirty || signal?.aborted) {
      dirty = false;
      return Promise.resolve();
    }
    return new Promise(resolve => {
      const done = () => {
        clock.clearTimeout(timer);
        signal?.removeEventListener('abort', done);
        if (wakeWaiter === done) wakeWaiter = null;
        dirty = false;
        resolve();
      };
      const timer = clock.setTimeout(done, ms);
      signal?.addEventListener('abort', done, { once: true });
      wakeWaiter = done;
    });
  }

  /** The delivery worker: a continuous leader task. */
  async function run(ctx = {}) {
    const { signal } = ctx,
      epoch = ctx.epoch ?? 1,
      wait = promise => (ctx.wait ? ctx.wait(promise) : promise);
    if (stopping) return;
    if (singleProcess) await recover({ foreign: true });
    while (!signal?.aborted && !stopping) {
      let wakeAt = null;
      try {
        ({ wakeAt } = await pump({ epoch, signal }));
      } catch (error) {
        note('Notification delivery could not read its queue', error);
      }
      const delay = wakeAt === null ? pollMs : Math.max(0, Math.min(pollMs, wakeAt - clock.wall()));
      await wait(idle(delay, signal));
    }
    // Demoted (HA): stop sending at once. A stop leaves in-flight sends to stop().
    if (signal?.aborted && signal.reason?.name === 'FencedError')
      for (const send of inFlight.values()) send.controller.abort(signal.reason);
  }

  async function settleInFlight(timeoutMs) {
    const pending = [...inFlight.values()].map(send => send.promise);
    if (!pending.length) return true;
    if (!Number.isFinite(timeoutMs)) {
      await Promise.allSettled(pending);
      return true;
    }
    let timer;
    const done = await Promise.race([
      Promise.allSettled(pending).then(() => true),
      new Promise(resolve => (timer = clock.setTimeout(() => resolve(false), timeoutMs))),
    ]);
    clock.clearTimeout(timer);
    return done;
  }

  /**
   * Sends everything due now, digest windows included (ignoreWindows), and waits for those sends.
   * Rows waiting for a retry are not waited for. Resolves true when nothing is left in flight.
   */
  async function flush({ ignoreWindows = true, epoch = 1, timeoutMs = Infinity } = {}) {
    const deadline = clock.now() + timeoutMs;
    for (let pass = 0; pass < 1000; pass++) {
      const { started } = await pump({ epoch, ignoreWindows });
      if (!started && !inFlight.size) return true;
      if (!(await settleInFlight(deadline - clock.now()))) return false;
    }
    return !inFlight.size;
  }

  /**
   * Stops claiming, lets sends in flight finish for up to timeoutMs, then cancels them (a
   * cancelled send ends as a retry when nothing was sent, or as "unknown" when it was). Resolves
   * {cancelled, unsettled}: sends cancelled, and sends that did not even answer the
   * cancellation (their rows stay 'sending' and are recovered at the next start).
   */
  async function stop({ timeoutMs = 8000 } = {}) {
    stopping = true;
    wake();
    // Refusals the log has not said yet are said now, before the process may end (A47).
    logCapRefusals({ all: true });
    const deadline = clock.now() + timeoutMs;
    // A pass still claiming gives its rows back instead of sending (see pass()): wait for it.
    if (pumps.size) {
      let timer;
      await Promise.race([
        Promise.allSettled([...pumps]),
        new Promise(
          resolve => (timer = clock.setTimeout(resolve, Math.max(0, deadline - clock.now())))
        ),
      ]);
      clock.clearTimeout(timer);
    }
    // A pass that was claiming when stop() was called may still start a send: wait for it too.
    while (inFlight.size && clock.now() < deadline)
      if (!(await settleInFlight(deadline - clock.now()))) break;
    if (!inFlight.size) return { cancelled: 0, unsettled: 0 };
    const cancelled = inFlight.size;
    for (const send of inFlight.values()) send.controller.abort(stopReason());
    // Channels answer a cancellation quickly; one that does not is recovered at the next start.
    await settleInFlight(2000);
    return { cancelled, unsettled: inFlight.size };
  }

  /**
   * Pauses a channel (an invalid GOBLIN_WEBHOOK_URL at start, or an administrator): its rows are
   * held. A transient pause may probe again after circuitCapMs; any other waits for Resume.
   */
  async function pause(
    channelId,
    reason = 'Paused by an administrator.',
    { transient = false, ifStatus, ifVersion, canPause = () => true } = {}
  ) {
    const now = clock.wall();
    return updateChannel(
      channelId,
      status => {
        if (ifVersion !== undefined && ifVersion !== channelVersion(channelId)) return null;
        if (
          ifStatus &&
          ['state', 'pausedReason', 'pausedSince', 'nextSendAt'].some(
            field => (status[field] ?? null) !== (ifStatus[field] ?? null)
          )
        )
          return null;
        if (!canPause(status)) return null;
        return {
          ...status,
          state: 'paused',
          pausedReason: safeReason(reason),
          pausedSince: status.pausedSince ?? now,
          nextSendAt: transient ? now + policy.circuitCapMs : 0,
        };
      },
      () => store.hold(channelId, now)
    );
  }

  // Held rows are released before the status says the channel works. A release that cannot be
  // written now (a full control database) does not undo the resume: the admin's decision stands (in
  // memory if need be, D15), and each pass's upkeep releases the rows once the store takes
  // writes again (probeChannels).
  async function resumeChannel(
    channelId,
    {
      clearError = false,
      ifStatus,
      ifVersion,
      beforeRelease = () => {},
      canResume = () => true,
    } = {}
  ) {
    let released = 0,
      resumed = false;
    await updateChannel(channelId, async status => {
      if (ifVersion !== undefined && ifVersion !== channelVersion(channelId)) return null;
      if (
        ifStatus &&
        ['state', 'pausedReason', 'pausedSince', 'nextSendAt'].some(
          field => (status[field] ?? null) !== (ifStatus[field] ?? null)
        )
      )
        return null;
      await beforeRelease();
      if (!canResume(status)) return null;
      try {
        released = await store.release(channelId, clock.wall());
      } catch (error) {
        heldNotReleased(error);
      }
      resumed = true;
      return {
        ...status,
        state: 'ok',
        pausedReason: null,
        pausedSince: null,
        consecutiveFailures: 0,
        consecutiveRefusals: 0,
        nextSendAt: 0,
        ...(clearError ? { lastError: null } : {}),
      };
    });
    if (resumed) wake();
    return resumed ? released : null;
  }

  /**
   * Resumes a channel: it leaves pause, its circuit closes, held rows are queued again and rows
   * waiting for a retry become due, all at once. Resolves with the number of rows released (rows
   * a full store could not release now are released by the next pass that can).
   */
  const resume = (channelId, options) => resumeChannel(channelId, options);

  /**
   * The channel's settings changed (for example PATCH /api/settings for email): a send in
   * flight is cancelled, so its rows are sent again with the new settings, and the channel
   * resumes as above. Replaces 1.4.2's email.reconfigure(), which dropped queued mail.
   */
  async function channelChanged(channelId, { settleMs = 2000 } = {}) {
    const version = channelVersion(channelId),
      cancelled = [];
    for (const send of inFlight.values())
      if (send.channelId === channelId) {
        send.controller.abort(settingsChangedReason());
        cancelled.push(send.promise);
      }
    // Their rows are back in the queue once the channel answers the cancellation.
    if (cancelled.length) {
      let timer;
      await Promise.race([
        Promise.allSettled(cancelled),
        new Promise(resolve => (timer = clock.setTimeout(resolve, settleMs))),
      ]);
      clock.clearTimeout(timer);
    }
    // As 1.4.x's reconfigure() did, saving the settings clears the last error (D12).
    return resumeChannel(channelId, {
      clearError: true,
      // Cancellation updates delivery counters too. It may clear those unpaused
      // results, but only the pause observed before cancellation is ours to clear.
      canResume: status => !isPausedStatus(status) || channelVersion(channelId) === version,
    });
  }

  // Of a row's later rows (same channel and order key), delivered or being sent: sending this one
  // now would arrive after a later change of its alert. `cache` keeps one read per key.
  async function laterSent(row, cache) {
    if (row.orderKey === null || row.orderKey === undefined) return false;
    const key = `${row.channelId}\n${row.orderKey}`;
    let rows = cache?.get(key);
    if (rows === undefined) {
      rows = await store.list({
        channelId: row.channelId,
        orderKey: row.orderKey,
        states: ['delivered', 'sending'],
        limit: 100,
      });
      cache?.set(key, rows);
    }
    return rows.some(other => other.id !== row.id && isLater(other, row));
  }

  // Why Retry now is refused for one row (delivery spec §6.4), or null.
  async function refusalOf(row, status, cache) {
    if (row.state === 'sending') return 'sending';
    if (isPausedStatus(status) || row.state === 'held') return 'paused';
    if (row.state === 'queued') return row.attempts > 0 ? null : 'waiting';
    if (row.state !== 'dead') return 'finished';
    return (await laterSent(row, cache)) ? 'outdated' : null;
  }

  // The send-time recheck's reason for a row (D24: its source was deleted, its kind of alert
  // switched off), or null. Retry refuses such a row as it refuses one of a channel that is not
  // set up (A45): it would only be skipped when sent, after Uptime Goblin had said it sends it again. A
  // recheck that throws refuses nothing, as at send time (a safeguard, not a gate).
  async function skippedWhenSent(row) {
    try {
      return (await recheck(row)) || null;
    } catch {
      return null;
    }
  }

  // The rows Retry now acts on for `row`: its whole digest batch (sent as one email, so retried
  // or refused as one), or the row alone. `cache` keeps one read per batch.
  async function retryRows(row, cache) {
    if (!row.digestKey) return [row];
    const key = `digest\n${row.digestKey}`;
    let batch = cache?.get(key);
    if (batch === undefined) {
      batch = await store.batch(row.digestKey);
      cache?.set(key, batch);
    }
    return (batch.length ? batch : [row]).toSorted(byStoreOrder);
  }

  // Why Retry now refuses `rows` (retryRows of `row`), or null: the first row that is not ready,
  // would be skipped when sent, or is refused (refusalOf), as {refused, channelId, reason,
  // other}. `row` itself is looked at first, so `other` (another notification of its email) is
  // named only when nothing is wrong with `row`.
  async function batchRefusal(row, rows, { status, cache, ready }) {
    for (const item of [row, ...rows.filter(item => item.id !== row.id)]) {
      // Named only when it is another notification of the row's email.
      const other = item.id !== row.id ? { other: true } : {};
      const refused = await refusalOf(item, status, cache);
      if ((refused === null || refused === 'paused') && !ready(item.channelId))
        return { refused: 'not_set_up', channelId: item.channelId, reason: null, ...other };
      const skipped = refused === null || refused === 'paused' ? await skippedWhenSent(item) : null;
      if (skipped)
        return { refused: 'not_sent', channelId: item.channelId, reason: skipped, ...other };
      if (refused)
        return {
          refused,
          channelId: item.channelId,
          reason: status?.pausedReason ?? null,
          ...other,
        };
    }
    return null;
  }

  /**
   * Whether Retry now would accept this row (the history list's Retry button): the same checks,
   * over the same rows, as retryNow(), so a digest member whose email holds a notification Retry
   * refuses (its source deleted, say) is not offered a Retry that could only fail.
   * `ready(channelId)`: whether the channel is set up and on (see retryNow()).
   */
  async function retryable(row, { status, cache, ready = () => true } = {}) {
    const health = status === undefined ? await store.channel(row.channelId) : status;
    const rows = await retryRows(row, cache);
    return (await batchRefusal(row, rows, { status: health, cache, ready })) === null;
  }

  /**
   * Retry now (§6.4, D18): a failed row gets a fresh age budget, a row waiting to retry becomes
   * due now, and the channel may send at once (one probe if its circuit is open). A digest batch
   * is retried as a whole, with the same Message-ID, or refused as a whole. Resolves
   * {retried, rows} or {refused, channelId, reason}. `ready(channelId)` says whether the
   * channel is set up and on: a row of one that is not (GOBLIN_WEBHOOK_URL removed at a restart,
   * email switched off) would only be skipped when sent, after Uptime Goblin had said it sends it again,
   * so it is refused ('not_set_up', amendment A45), also in place of 'paused', which Resume
   * could not end. A row the send-time recheck would skip is refused the same way ('not_sent',
   * with the recheck's reason; `other` when it is another notification of the row's email).
   * `check()` (the route's re-check of its session) runs right
   * before the rows are requeued, after every await: when it throws, nothing is requeued.
   */
  async function retryNow(uid, { now = clock.wall(), ready = () => true, check = () => {} } = {}) {
    const row = await store.find(uid);
    if (!row) return { refused: 'not_found' };
    const cache = new Map(),
      rows = await retryRows(row, cache);
    const status = await store.channel(row.channelId);
    const refusal = await batchRefusal(row, rows, { status, cache, ready });
    if (refusal) return refusal;
    check();
    const age = registry.get(row.channelId)?.maxAgeMs ?? policy.maxAgeMs;
    const retried = await store.requeue(
      rows.map(item => item.id),
      { now, expiresAt: now + age }
    );
    if (retried) {
      await updateChannel(row.channelId, health => ({ ...health, nextSendAt: 0 }));
      wake();
    }
    return { retried, rows };
  }

  /**
   * A test email's outcome in the channel's status (D13): when it was tried, and its success or
   * error. It never pauses the channel or counts in the circuit; an accepted test resumes a
   * paused channel, since it used the very settings the channel sends with.
   */
  async function recordTest(channelId, { accepted: ok = false, message = '' } = {}) {
    const now = clock.wall();
    let paused = false,
      observed,
      version;
    await updateChannel(
      channelId,
      status => {
        paused = isPausedStatus(status);
        observed = ok
          ? { ...status, lastAttempt: now, lastSuccess: now }
          : {
              ...status,
              lastAttempt: now,
              lastFailure: now,
              lastError: { time: now, message: safeReason(message) },
              failedTotal: status.failedTotal + 1,
            };
        return observed;
      },
      () => {
        version = channelVersion(channelId);
      }
    );
    if (ok && paused) await resume(channelId, { ifStatus: observed, ifVersion: version });
  }

  /** D24: a deleted source's queued and held rows are cancelled with `reason`. */
  async function cancelSource(serviceId, reason) {
    const cancelled = await store.cancel({
      orderKeyPrefix: `${serviceId}\n`,
      now: clock.wall(),
      reason: safeReason(reason),
    });
    if (cancelled) wake();
    return cancelled;
  }

  /** D16: every row still queued, held or sending becomes stale (not sent). */
  const markStale = reason => store.stale({ now: clock.wall(), reason: safeReason(reason) });

  /** Whether the store can be written now (the failover store's probe; D15). */
  const probe = async () => (typeof store.probe === 'function' ? store.probe() : !store.degraded);

  async function status() {
    const counts = await store.counts(),
      channels = {};
    for (const id of new Set([...registry.keys(), ...Object.keys(counts.byChannel)]))
      channels[id] = {
        ...initialChannelStatus(),
        ...(await store.channel(id)),
        known: registry.has(id),
        counts: counts.byChannel[id] ?? {},
      };
    return {
      owner,
      inFlight: inFlight.size,
      stopping,
      dropped,
      degraded: Boolean(store.degraded),
      lastError: lastError && { time: lastError.time, message: lastError.message },
      counts: counts.total,
      oldestQueuedAt: counts.oldestQueuedAt,
      channels,
    };
  }

  /** Retention (§3.7): finished rows 7 d / 50,000; dead rows 30 d / 5,000; `limit` per call. */
  const prune = ({ limit = 1000 } = {}) =>
    store.prune({
      now: clock.wall(),
      finished: { maxAgeMs: 7 * 24 * 3600 * 1000, maxRows: 50000 },
      dead: { maxAgeMs: 30 * 24 * 3600 * 1000, maxRows: 5000 },
      limit,
    });

  return {
    enqueue,
    run,
    pump,
    flush,
    recover,
    pause,
    resume,
    channelChanged,
    retry: retryNow,
    retryable,
    recordTest,
    cancelSource,
    updateChannel,
    channelVersion,
    markStale,
    probe,
    /** Whether `channelId` has a send in flight (the test email's "busy", D13). */
    sending: channelId => (perChannel.get(channelId) ?? 0) > 0,
    status,
    prune,
    stop,
    owner,
    channels: registry,
    get inFlight() {
      return inFlight.size;
    },
    /** Rows the backlog cap refused since this outbox was made. */
    get dropped() {
      return dropped;
    },
    /** `channelId`'s rows the backlog cap refused since this outbox was made: {count, lastAt}. */
    notQueued(channelId) {
      const entry = capRefusals.get(channelId);
      return { count: entry?.count ?? 0, lastAt: entry?.lastAt ?? null };
    },
  };
}
