// OutboxStore implementations kept in memory (see outbox.mjs for the interface):
// - createMemoryOutboxStore(): for tests, and the reference the control-database adapter
//   (wave 2) must match row for row;
// - createFailoverStore({primary, fallback}): the degraded path (design §2.7, T8; delivery spec
//   D15, D23). When the primary store cannot be written (disk full, database unavailable), new
//   rows go to memory and are still delivered, and `degraded` is true so the dashboard can say
//   "Notifications are not being saved". Rows already in memory stay there until they end; then
//   they are written to the primary as they are, once it takes writes again.
import { ACTIVE_STATES } from './outbox.mjs';

const ACTIVE = new Set(ACTIVE_STATES),
  FINISHED = new Set(['delivered', 'superseded', 'stale', 'skipped', 'cancelled']);
const uniqueKey = row => `${row.eventUid}\n${row.channelId}\n${row.target}`;
const copy = value => structuredClone(value);

export function createMemoryOutboxStore() {
  const rows = new Map(),
    keys = new Map(),
    channels = new Map();
  let nextId = 1;
  const each = function* (filter) {
    for (const row of rows.values()) if (filter(row)) yield row;
  };
  const update = (filter, patch) => {
    let changed = 0;
    for (const row of each(filter)) {
      Object.assign(row, typeof patch === 'function' ? patch(row) : patch);
      changed++;
    }
    return changed;
  };
  return {
    kind: 'memory',
    /** How many rows it holds (the failover store's "not saved" count). */
    get size() {
      return rows.size;
    },
    async insert(list) {
      const inserted = [],
        duplicates = [];
      for (const row of list) {
        if (keys.has(uniqueKey(row))) {
          duplicates.push(row.uid);
          continue;
        }
        const stored = { ...copy(row), id: nextId++ };
        rows.set(stored.id, stored);
        keys.set(uniqueKey(stored), stored.id);
        inserted.push(copy(stored));
      }
      return { inserted, duplicates };
    },
    async candidates({ now, limit = 200, channels: only = null }) {
      const wanted = only ? new Set(only) : null,
        blocked = new Set(),
        found = [];
      const channelWaits = id => {
        const status = channels.get(id);
        return status?.state === 'paused' || (status?.nextSendAt ?? 0) > now;
      };
      for (const row of rows.values()) {
        if (!ACTIVE.has(row.state) || (wanted && !wanted.has(row.channelId))) continue;
        const order = row.orderKey === null ? null : `${row.channelId}\n${row.orderKey}`;
        const due =
          row.state === 'queued' &&
          row.nextAt <= now &&
          row.expiresAt > now &&
          !channelWaits(row.channelId) &&
          !(order && blocked.has(order));
        if (!due) {
          if (order) blocked.add(order);
        } else if (found.length < limit) found.push(copy(row));
      }
      return found;
    },
    async claim(ids, { owner, epoch, now, leaseUntil, digestKey = null }) {
      const claimed = [];
      for (const id of ids) {
        const row = rows.get(id);
        if (!row || row.state !== 'queued') continue;
        Object.assign(row, {
          state: 'sending',
          leaseOwner: owner,
          leaseUntil,
          epoch,
          attempts: row.attempts + 1,
          digestKey: digestKey ?? row.digestKey,
          updatedAt: now,
        });
        claimed.push(copy(row));
      }
      return claimed;
    },
    async complete(patches, { owner, epoch }) {
      let changed = 0;
      for (const { id, patch } of patches) {
        const row = rows.get(id);
        if (!row || row.state !== 'sending' || row.leaseOwner !== owner || row.epoch !== epoch)
          continue;
        Object.assign(row, copy(patch));
        changed++;
      }
      return changed;
    },
    async sending() {
      return [...each(row => row.state === 'sending')].map(copy);
    },
    async expire(now) {
      return update(
        row => (row.state === 'queued' || row.state === 'held') && row.expiresAt <= now,
        row => ({
          state: 'dead',
          deadReason: 'expired',
          lastError: row.lastError ?? 'It could not be delivered before it expired.',
          updatedAt: now,
        })
      );
    },
    async hold(channelId, now) {
      return update(row => row.channelId === channelId && row.state === 'queued', {
        state: 'held',
        updatedAt: now,
      });
    },
    // Held rows are queued again, and rows waiting for a retry become due, at once.
    async release(channelId, now) {
      return update(
        row =>
          row.channelId === channelId &&
          (row.state === 'held' || (row.state === 'queued' && row.nextAt > now)),
        { state: 'queued', nextAt: now, updatedAt: now }
      );
    },
    // `reason` becomes the rows' last error; `createdBefore` limits it to older rows (D26).
    async supersede({ channelId, orderKey, kinds, now, reason, createdBefore }) {
      return update(
        row =>
          row.channelId === channelId &&
          row.orderKey === orderKey &&
          (row.state === 'queued' || row.state === 'held') &&
          kinds.includes(row.kind) &&
          (createdBefore === undefined || createdBefore === null || row.createdAt < createdBefore),
        {
          state: 'superseded',
          updatedAt: now,
          ...(reason === undefined || reason === null ? {} : { lastError: reason }),
        }
      );
    },
    async channel(id) {
      return channels.has(id) ? copy(channels.get(id)) : null;
    },
    async setChannel(id, status) {
      channels.set(id, copy(status));
    },
    async channelIds() {
      return [...channels.keys()];
    },
    async countActive() {
      return [...each(row => ACTIVE.has(row.state))].length;
    },
    async counts() {
      const total = {},
        byChannel = {};
      let oldestQueuedAt = null;
      for (const row of rows.values()) {
        total[row.state] = (total[row.state] ?? 0) + 1;
        byChannel[row.channelId] ??= {};
        byChannel[row.channelId][row.state] = (byChannel[row.channelId][row.state] ?? 0) + 1;
        if (
          (row.state === 'queued' || row.state === 'held') &&
          (oldestQueuedAt === null || row.createdAt < oldestQueuedAt)
        )
          oldestQueuedAt = row.createdAt;
      }
      return { total, byChannel, oldestQueuedAt };
    },
    // The next moment something becomes due: a retry, or a lease running out. Never `now` or
    // earlier, so a row that is due but must wait for an earlier one cannot cause a busy loop.
    async nextDueAt(now) {
      let next = null;
      for (const row of rows.values()) {
        const at =
          row.state === 'queued' ? row.nextAt : row.state === 'sending' ? row.leaseUntil : null;
        if (at !== null && at > now && (next === null || at < next)) next = at;
      }
      return next;
    },
    // Newest first (id descending), at most `limit` (≤ 100); `state` is an alias of [state].
    // `excludeWaiting`: no queued row that has not been tried yet (the Problems filter).
    async list({
      states,
      state,
      channelId,
      orderKey,
      beforeId,
      afterId,
      excludeWaiting = false,
      limit = 100,
    } = {}) {
      const wanted = states ?? (state ? [state] : null),
        most = Math.max(1, Math.min(Math.floor(limit) || 1, 100)),
        found = [];
      for (const row of [...rows.values()].reverse()) {
        if (wanted && !wanted.includes(row.state)) continue;
        if (excludeWaiting && row.state === 'queued' && !(row.attempts > 0)) continue;
        if (channelId && row.channelId !== channelId) continue;
        if (orderKey !== undefined && row.orderKey !== orderKey) continue;
        if (beforeId !== undefined && beforeId !== null && !(row.id < beforeId)) continue;
        if (afterId !== undefined && afterId !== null && !(row.id > afterId)) continue;
        found.push(copy(row));
        if (found.length >= most) break;
      }
      return found;
    },
    // --- Delivery spec §5.2 additions ---
    async find(uid) {
      for (const row of rows.values()) if (row.uid === uid) return copy(row);
      return null;
    },
    // With `states`, only the batch's rows in those states (the worker's "is it whole" check).
    async batch(digestKey, { states } = {}) {
      return [
        ...each(row => row.digestKey === digestKey && (!states || states.includes(row.state))),
      ]
        .slice(0, 100)
        .map(copy);
    },
    // Retry now: dead and queued rows are due now; a dead row gets a fresh expiry.
    async requeue(ids, { now, expiresAt } = {}) {
      let changed = 0;
      for (const id of ids) {
        const row = rows.get(id);
        if (!row || (row.state !== 'dead' && row.state !== 'queued')) continue;
        const dead = row.state === 'dead';
        Object.assign(row, {
          state: 'queued',
          nextAt: now,
          leaseOwner: null,
          leaseUntil: null,
          deadReason: null,
          updatedAt: now,
          ...(dead ? { unknowns: 0 } : {}),
          ...(dead && expiresAt !== undefined && expiresAt !== null ? { expiresAt } : {}),
        });
        changed++;
      }
      return changed;
    },
    async stale({ now, reason } = {}) {
      return update(row => ACTIVE.has(row.state), {
        state: 'stale',
        lastError: reason ?? null,
        leaseOwner: null,
        leaseUntil: null,
        updatedAt: now,
      });
    },
    // A pass that met stop() gives its claimed rows back, the attempt not counted.
    async unclaim(ids, { owner, epoch, now } = {}) {
      let changed = 0;
      for (const id of ids) {
        const row = rows.get(id);
        if (!row || row.state !== 'sending' || row.leaseOwner !== owner || row.epoch !== epoch)
          continue;
        Object.assign(row, {
          state: 'queued',
          attempts: row.attempts - 1,
          leaseOwner: null,
          leaseUntil: null,
          updatedAt: now,
        });
        changed++;
      }
      return changed;
    },
    async cancel({ orderKeyPrefix, now, reason } = {}) {
      if (typeof orderKeyPrefix !== 'string' || !orderKeyPrefix)
        throw new TypeError('cancel() needs an order key prefix');
      return update(
        row =>
          (row.state === 'queued' || row.state === 'held') &&
          typeof row.orderKey === 'string' &&
          row.orderKey.startsWith(orderKeyPrefix),
        { state: 'cancelled', lastError: reason ?? null, updatedAt: now }
      );
    },
    async activeKeys(keys) {
      return (keys ?? [])
        .filter(key =>
          [...rows.values()].some(
            row =>
              ACTIVE.has(row.state) &&
              row.channelId === key.channelId &&
              row.orderKey === (key.orderKey ?? null)
          )
        )
        .map(key => ({ channelId: key.channelId, orderKey: key.orderKey }));
    },
    async shiftExpiry({ by, now } = {}) {
      if (!by) return 0;
      return update(
        row => ACTIVE.has(row.state),
        row => ({ expiresAt: row.expiresAt + by, updatedAt: now })
      );
    },
    async clampTimes({ now, nextAtMax, expiresAtMax, leaseUntilMax } = {}) {
      const set = value => value !== undefined && value !== null;
      return update(
        row =>
          (set(nextAtMax) && row.state === 'queued' && row.nextAt > nextAtMax) ||
          (set(expiresAtMax) && ACTIVE.has(row.state) && row.expiresAt > expiresAtMax) ||
          (set(leaseUntilMax) && row.state === 'sending' && row.leaseUntil > leaseUntilMax),
        row => ({
          ...(set(nextAtMax) && row.state === 'queued' && row.nextAt > nextAtMax
            ? { nextAt: nextAtMax }
            : {}),
          ...(set(expiresAtMax) && row.expiresAt > expiresAtMax ? { expiresAt: expiresAtMax } : {}),
          ...(set(leaseUntilMax) && row.state === 'sending' && row.leaseUntil > leaseUntilMax
            ? { leaseUntil: leaseUntilMax }
            : {}),
          updatedAt: now,
        })
      );
    },
    async summary({ failedSince = {} } = {}) {
      const out = {};
      const entry = channelId =>
        (out[channelId] ??= {
          waiting: 0,
          retrying: 0,
          sending: 0,
          held: 0,
          failed: 0,
          oldestWaitingAt: null,
        });
      for (const row of rows.values()) {
        if (row.state === 'queued')
          entry(row.channelId)[row.attempts > 0 ? 'retrying' : 'waiting']++;
        else if (row.state === 'sending' || row.state === 'held') entry(row.channelId)[row.state]++;
        else if (row.state === 'dead') {
          const since = Number.isFinite(failedSince?.[row.channelId])
            ? failedSince[row.channelId]
            : 0;
          if (row.updatedAt > since) entry(row.channelId).failed++;
        }
        if (row.state === 'queued' || row.state === 'held') {
          const item = entry(row.channelId);
          if (item.oldestWaitingAt === null || row.createdAt < item.oldestWaitingAt)
            item.oldestWaitingAt = row.createdAt;
        }
      }
      return out;
    },
    async prune({ now, finished, dead, limit = 1000 }) {
      let removed = 0;
      for (const [states, rule] of [
        [FINISHED, finished],
        [new Set(['dead']), dead],
      ]) {
        const list = [...each(row => states.has(row.state))].sort(
          (a, b) => a.updatedAt - b.updatedAt || a.id - b.id
        );
        const excess = Math.max(0, list.length - rule.maxRows);
        for (const [index, row] of list.entries()) {
          if (removed >= limit) return removed;
          if (index >= excess && row.updatedAt > now - rule.maxAgeMs) break;
          rows.delete(row.id);
          keys.delete(uniqueKey(row));
          removed++;
        }
      }
      return removed;
    },
    // --- For the failover store (not OutboxStore operations) ---
    /**
     * Rows that are no longer active (delivered, dead, replaced …), in id order, at most `limit`,
     * leaving out a row while an earlier row of its (channel, order key) is still active: saved
     * in this order, the rows of each key keep their order in the store they are saved to.
     */
    async finishedRows(limit = 200) {
      const busy = new Set(),
        found = [];
      for (const row of rows.values()) {
        const order = row.orderKey === null ? null : `${row.channelId}\n${row.orderKey}`;
        if (ACTIVE.has(row.state)) {
          if (order) busy.add(order);
        } else if (!(order && busy.has(order))) found.push(copy(row));
        if (found.length >= limit) break;
      }
      return found;
    },
    /** Of [{channelId, orderKey}], those with any row here, active or not, in input order. */
    async heldKeys(keys) {
      const held = new Set();
      for (const row of rows.values()) held.add(`${row.channelId}\n${row.orderKey}`);
      return (keys ?? [])
        .filter(key => held.has(`${key.channelId}\n${key.orderKey ?? null}`))
        .map(key => ({ channelId: key.channelId, orderKey: key.orderKey }));
    },
    /** Removes these rows, each only while it is still not active. Returns the rows removed. */
    async removeFinished(ids) {
      let removed = 0;
      for (const id of ids) {
        const row = rows.get(id);
        if (!row || ACTIVE.has(row.state)) continue;
        rows.delete(id);
        keys.delete(uniqueKey(row));
        removed++;
      }
      return removed;
    },
  };
}

/**
 * A storage failure worth falling back for: dialect.classify's 'full' or 'unavailable' class,
 * or node:sqlite's SQLITE_FULL, IOERR, READONLY, CANTOPEN, CORRUPT or NOTADB.
 */
export function isStorageError(error) {
  if (['full', 'unavailable'].includes(error?.class)) return true;
  const primary = Number(error?.errcode) & 0xff;
  if ([13, 10, 8, 14, 11, 26].includes(primary)) return true;
  return /\bSQLITE_(FULL|IOERR|READONLY|CANTOPEN|CORRUPT|NOTADB)\b|database or disk is full/i.test(
    `${error?.code ?? ''} ${error?.errstr ?? ''} ${error?.message ?? ''}`
  );
}

const FALLBACK = 'm:';
const isFallbackId = id => typeof id === 'string' && id.startsWith(FALLBACK);
const toFallback = row => ({ ...row, id: FALLBACK + row.id });
const orderOf = row => `${row.channelId}\n${row.orderKey}`;
const keysOf = rows => {
  const seen = new Map();
  for (const row of rows)
    if (row.orderKey !== null && row.orderKey !== undefined && !seen.has(orderOf(row)))
      seen.set(orderOf(row), { channelId: row.channelId, orderKey: row.orderKey });
  return [...seen.values()];
};
const errorText = error =>
  String(error?.code ?? error?.errstr ?? error?.message ?? 'error')
    .replace(/[\p{Cc}\p{Zl}\p{Zp}]/gu, ' ')
    .slice(0, 200);

/**
 * createFailoverStore({primary, fallback, storageError, logger, onChange, now}): an OutboxStore
 * over `primary` (control.sqlite) that keeps delivering from memory while the primary cannot be
 * written.
 * - Order across the two stores (D23): a new row whose (channel, order key) has a row in memory
 *   (active, or ended but not saved yet) goes to memory as well, and a memory row waits while the
 *   primary holds an active row of its key, so a recovery never overtakes its alert because the
 *   two went to different stores.
 * - A completion the primary cannot write (for any reason except fencing) is kept and applied
 *   later; until then its row is neither a candidate nor recovered, so it is never sent again
 *   while Uptime Goblin runs. An unclaim (a pass that met stop()) is kept the same way. A channel status
 *   the primary cannot write is served from memory (dirty). A row whose kept result ends it
 *   (delivered, failed …) holds no key back, and the history and summary show it with that
 *   result: it was sent, only the write waits.
 * - A clock-step adjustment (shiftExpiry, clampTimes; D25) the primary cannot write is kept too,
 *   and written after the kept completions; meanwhile the primary's rows are not expired. The
 *   outbox sees each step once, so an adjustment answered as done but not written would let a
 *   forward step expire rows that had life left, or a backward one stall retries for its size.
 * - Rows that ended in memory are written to the primary as they are (new ids) once it takes
 *   writes again: before every insert, at a successful probe(), and at a candidates read while
 *   saving; a row only once no earlier row of its key is active in memory. With the rule above,
 *   the primary's id order stays each alert's order (Retry's "outdated" check and D23 read it).
 *   So the history of a full-disk episode survives a restart, and once saving resumes only rows
 *   still in progress are "kept in memory" (`unsaved`) and listed first.
 * - Reads that report status (summary, list, batch, find) let a primary read error through, so
 *   the page says "unavailable" instead of showing zeros. So does release(), after releasing the
 *   rows in memory: held rows the primary keeps must be released again later, and only the
 *   caller (the outbox) knows when.
 * - onChange(degraded, error) is called when it starts and stops keeping rows in memory;
 *   probe() tries a primary write and ends the degraded state when it succeeds.
 */
export function createFailoverStore({
  primary,
  fallback = createMemoryOutboxStore(),
  storageError = isStorageError,
  logger = console,
  onChange = () => {},
  now = Date.now,
} = {}) {
  let degraded = false,
    reason = null,
    degradedSince = null,
    applying = null;
  // Writes the primary could not take for rows it holds: primary id -> {patch, lease} for a
  // completion, {unclaim: true, lease} for an unclaim.
  const deferred = new Map(),
    // Channels whose status the primary could not write: memory has the current one.
    dirty = new Set(),
    logged = new Map();
  // The result a kept completion will write when it ends the row (delivered, dead, skipped …);
  // null for a retry, an "unknown", a pause or an unclaim, which leave the row active.
  const finalPatch = id => {
    const entry = deferred.get(id);
    return entry && !entry.unclaim && entry.patch && !ACTIVE.has(entry.patch.state)
      ? entry.patch
      : null;
  };
  const anyFinalPatch = () => [...deferred.keys()].some(id => finalPatch(id) !== null);
  // A primary row as it will be once its kept result is written (what the page shows).
  const pendingView = row => {
    const patch = finalPatch(row.id);
    return patch ? { ...row, ...structuredClone(patch) } : row;
  };
  const logOnce = (key, text) => {
    const at = now(),
      last = logged.get(key);
    if (last !== undefined && at - last < 60000) return;
    logged.set(key, at);
    logger.error?.(text);
  };
  const set = (value, error) => {
    if (degraded === value) return;
    degraded = value;
    reason = value ? errorText(error) : null;
    degradedSince = value ? now() : null;
    if (value)
      logger.error?.(
        `Notifications are not being saved (${reason}); they are kept in memory until the database can be written again.`
      );
    else logger.info?.('Notifications are being saved again.');
    onChange(degraded, value ? error : null);
  };

  // A clock-step adjustment (D25) the primary could not write yet, or null. The outbox makes one
  // per step it sees, and moves on: a step it saw is not seen again. So the primary's share is
  // kept here and written once the primary takes writes; until then its rows keep the times from
  // before the step, and none of them is expired (expire() below). Steps compose into one record
  // however many there are: an active row's expiry x becomes min(x + by, expiresAtMax), a queued
  // row's nextAt at most nextAtMax and a sending row's leaseUntil at most leaseUntilMax (Infinity:
  // no cap).
  let clockPending = null;
  const capOf = value =>
    value === undefined || value === null || value >= Number.MAX_SAFE_INTEGER ? Infinity : value;
  const clockStep = ({ by = 0, now: at, nextAtMax, expiresAtMax, leaseUntilMax } = {}) => ({
    by,
    now: at,
    nextAtMax: capOf(nextAtMax),
    expiresAtMax: capOf(expiresAtMax),
    leaseUntilMax: capOf(leaseUntilMax),
  });
  // `first` then `then`, as one adjustment: min(min(x + a, E1) + b, E2) = min(x + a + b,
  // E1 + b, E2); the caps of nextAt and leaseUntil take the lower.
  const composeClock = (first, then) =>
    !first
      ? then
      : !then
        ? first
        : {
            by: first.by + then.by,
            now: then.now,
            nextAtMax: Math.min(first.nextAtMax, then.nextAtMax),
            expiresAtMax: Math.min(first.expiresAtMax + then.by, then.expiresAtMax),
            leaseUntilMax: Math.min(first.leaseUntilMax, then.leaseUntilMax),
          };
  const finite = value => (Number.isFinite(value) ? value : undefined);
  // Writes the kept adjustment: the shift, then the caps. Never throws: what fails stays (a
  // shift that was written is not kept again; its caps are).
  async function applyClock() {
    let left = clockPending;
    if (!left) return;
    clockPending = null;
    try {
      if (left.by) {
        await primary.shiftExpiry({ by: left.by, now: left.now });
        left = { ...left, by: 0 };
      }
      const caps = {
        nextAtMax: finite(left.nextAtMax),
        expiresAtMax: finite(left.expiresAtMax),
        leaseUntilMax: finite(left.leaseUntilMax),
      };
      if (Object.values(caps).some(value => value !== undefined))
        await primary.clampTimes({ now: left.now, ...caps });
    } catch (error) {
      // Before any step that came meanwhile.
      clockPending = composeClock(left, clockPending);
      if (storageError(error)) set(true, error);
      else
        logOnce(
          'clock',
          `A clock-step adjustment of notification times could not be saved yet (${errorText(error)}); Uptime Goblin keeps it and saves it later.`
        );
    }
  }

  // Applies up to 100 deferred writes, grouped by kind and lease, then a kept clock-step
  // adjustment once no deferred write is left: a completion kept from before a backward step
  // carries a retry time from before it, which the step's cap must still reach. Never throws:
  // what fails stays.
  function applyDeferred() {
    // One in progress is waited for even when nothing is left to start: a kept adjustment being
    // written is no longer `clockPending`, and a step that came meanwhile must not reach the
    // primary before it.
    if (applying) return applying;
    if (!deferred.size && !clockPending) return Promise.resolve();
    applying = (async () => {
      const groups = new Map();
      for (const [id, entry] of [...deferred].slice(0, 100)) {
        const { lease } = entry,
          key = `${entry.unclaim ? 'u' : 'c'}\n${lease.owner}\n${lease.epoch}\n${lease.now}`;
        if (!groups.has(key))
          groups.set(key, { unclaim: Boolean(entry.unclaim), lease, items: [] });
        groups.get(key).items.push({ id, patch: entry.patch });
      }
      for (const { unclaim, lease, items } of groups.values()) {
        try {
          if (unclaim)
            await primary.unclaim(
              items.map(item => item.id),
              lease
            );
          else await primary.complete(items, { owner: lease.owner, epoch: lease.epoch });
        } catch (error) {
          // A fenced lease can never apply: another leader owns the rows now.
          if (error?.class !== 'fenced') {
            if (storageError(error)) set(true, error);
            return;
          }
        }
        for (const { id } of items) deferred.delete(id);
      }
      if (!deferred.size) await applyClock();
    })().finally(() => (applying = null));
    return applying;
  }
  // The primary's share of a clock-step adjustment: written now, or kept (above) when the primary
  // cannot take it now or an earlier one still waits, so the steps reach its rows in order. Any
  // other error is not hidden: the outbox then sees the same step again at its next pass.
  async function adjustPrimary(operation, step) {
    await applyDeferred();
    if (clockPending || deferred.size) {
      clockPending = composeClock(clockPending, step);
      return 0;
    }
    try {
      return await operation();
    } catch (error) {
      if (!storageError(error)) throw error;
      set(true, error);
      clockPending = composeClock(clockPending, step);
      return 0;
    }
  }
  // Keeps a primary write for later (see above); a storage error also marks the store degraded.
  function deferWrite(ids, entry, error, what) {
    for (const id of ids) deferred.set(id, { ...entry });
    if (storageError(error)) set(true, error);
    else
      logOnce(
        what,
        `A delivery ${what} could not be saved yet (${errorText(error)}); Uptime Goblin keeps it and saves it later.`
      );
  }
  // Runs a primary operation (after any deferred completions); a storage failure marks the store
  // degraded and yields `otherwise`. Any other error is never hidden.
  const tryPrimary = async (operation, otherwise) => {
    await applyDeferred();
    try {
      return await operation();
    } catch (error) {
      if (!storageError(error)) throw error;
      set(true, error);
      return otherwise;
    }
  };
  // A read whose answer the page shows: a primary error goes to the caller.
  const readPrimary = async operation => {
    await applyDeferred();
    return operation();
  };
  const split = ids => ({
    main: ids.filter(id => !isFallbackId(id)),
    memory: ids.filter(isFallbackId).map(id => Number(id.slice(FALLBACK.length))),
  });
  const sum = async (a, b) => (await a) + (await b);

  async function insertInMemory(rows) {
    if (!rows.length) return { inserted: [], duplicates: [] };
    const result = await fallback.insert(rows);
    return { inserted: result.inserted.map(toFallback), duplicates: result.duplicates };
  }
  // Of `keys`, those with any row in memory (a fallback without heldKeys: its active ones).
  const heldInMemory = keys =>
    typeof fallback.heldKeys === 'function' ? fallback.heldKeys(keys) : fallback.activeKeys(keys);

  // Of `keys`, those the primary holds active (D23), not counting a row whose kept result ends
  // it: that row was sent and only its write waits, so a recovery kept in memory behind it would
  // otherwise wait for disk space, and expire unsent while the disk stays full.
  async function primaryActiveKeys(keys) {
    const active = await primary.activeKeys(keys);
    if (!active.length || !anyFinalPatch()) return active;
    const held = [];
    for (const key of active) {
      const rows = await primary.list({
        channelId: key.channelId,
        orderKey: key.orderKey ?? null,
        states: ACTIVE_STATES,
        limit: 100,
      });
      if (rows.length >= 100 || rows.some(row => finalPatch(row.id) === null)) held.push(key);
    }
    return held;
  }

  // Writes the rows that ended in memory to the primary, as they are (they get new ids), and
  // drops them from memory: the history of a full-disk episode then survives a restart, and
  // nothing reads "kept in memory" once saving resumes but rows still in progress. A delivery id
  // the primary already holds keeps the primary's row. Never throws: what cannot be written now
  // stays in memory for the next try.
  let persisting = null;
  function persistFinished() {
    if (typeof fallback.finishedRows !== 'function' || !(fallback.size > 0))
      return Promise.resolve();
    persisting ??= (async () => {
      try {
        for (;;) {
          const rows = await fallback.finishedRows(200);
          if (!rows.length) return;
          // insert() gives every row its own id (the memory ids are not kept).
          await primary.insert(rows);
          const removed = await fallback.removeFinished(rows.map(row => row.id));
          if (rows.length < 200 || !removed) return;
        }
      } catch (error) {
        if (storageError(error)) set(true, error);
        else
          logOnce(
            'persist',
            `Notifications kept in memory could not be saved yet (${errorText(error)}); Uptime Goblin tries again later.`
          );
      }
    })().finally(() => (persisting = null));
    return persisting;
  }

  return {
    kind: 'failover',
    get degraded() {
      return degraded;
    },
    get reason() {
      return reason;
    },
    /** When the store started keeping rows in memory (null while saving). */
    get degradedSince() {
      return degradedSince;
    },
    /** How many rows are kept in memory (shown as not saved). */
    get unsaved() {
      return fallback.size ?? 0;
    },
    async insert(rows) {
      // Rows that ended in memory are saved first (when the primary takes writes), so the new
      // rows come after them in the primary's id order, which is each alert's order (D23).
      if (rows.length) {
        await applyDeferred();
        await persistFinished();
      }
      // A key with a row still in memory (in progress, or ended but not saved yet) keeps its
      // next rows in memory too (D23): a row saved later gets a later id than every row of its
      // key the primary already holds.
      const keys = keysOf(rows);
      const busy = new Set(keys.length ? (await heldInMemory(keys)).map(key => orderOf(key)) : []);
      const toMemory = rows.filter(row => row.orderKey != null && busy.has(orderOf(row)));
      const toPrimary = rows.filter(row => !toMemory.includes(row));
      const inserted = [],
        duplicates = [];
      if (toPrimary.length) {
        try {
          const result = await primary.insert(toPrimary);
          set(false);
          inserted.push(...result.inserted);
          duplicates.push(...result.duplicates);
        } catch (error) {
          if (!storageError(error)) throw error;
          set(true, error);
          // Rows the primary already holds (a sweep relaying an event again after a restart)
          // are not copied into memory; reads usually still work on a full disk.
          let keep = toPrimary;
          try {
            const held = new Set();
            for (const row of toPrimary) if (await primary.find(row.uid)) held.add(row.uid);
            keep = toPrimary.filter(row => !held.has(row.uid));
            duplicates.push(...held);
          } catch {
            keep = toPrimary;
          }
          toMemory.push(...keep);
        }
      }
      const kept = await insertInMemory(toMemory);
      inserted.push(...kept.inserted);
      duplicates.push(...kept.duplicates);
      return { inserted, duplicates };
    },
    async candidates(options) {
      // Saving again: rows that ended in memory meanwhile are written now (cheap when none).
      if (!degraded) await persistFinished();
      const main = (await tryPrimary(() => primary.candidates(options), [])).filter(
        row => !deferred.has(row.id)
      );
      let memory = await fallback.candidates(options);
      const keys = keysOf(memory);
      if (keys.length) {
        try {
          // A memory row waits while the primary still holds an active row of its key (D23).
          const active = new Set(
            (await readPrimary(() => primaryActiveKeys(keys))).map(key => orderOf(key))
          );
          memory = memory.filter(row => row.orderKey == null || !active.has(orderOf(row)));
        } catch (error) {
          if (!storageError(error)) throw error;
          // Delivery goes on: an unreadable primary cannot hold anything back.
          logOnce(
            'active-keys',
            `Notification order across memory and the database could not be checked (${errorText(error)}); rows kept in memory are sent as they are.`
          );
        }
      }
      return [...main, ...memory.map(toFallback)];
    },
    async claim(ids, lease) {
      const { main, memory } = split(ids);
      return [
        ...(main.length ? await tryPrimary(() => primary.claim(main, lease), []) : []),
        ...(memory.length ? (await fallback.claim(memory, lease)).map(toFallback) : []),
      ];
    },
    async complete(patches, lease) {
      const main = patches.filter(p => !isFallbackId(p.id)),
        memory = patches
          .filter(p => isFallbackId(p.id))
          .map(p => ({ ...p, id: Number(p.id.slice(FALLBACK.length)) }));
      let changed = 0;
      if (main.length) {
        await applyDeferred();
        try {
          changed += await primary.complete(main, lease);
        } catch (error) {
          // Fenced: another leader owns these rows; the result is not recorded.
          if (error?.class !== 'fenced') {
            for (const { id, patch } of main)
              deferWrite(
                [id],
                { patch, lease: { owner: lease.owner, epoch: lease.epoch } },
                error,
                'result'
              );
            changed += main.length;
          }
        }
      }
      if (memory.length) changed += await fallback.complete(memory, lease);
      return changed;
    },
    async sending() {
      return [
        ...(await tryPrimary(() => primary.sending(), [])).filter(row => !deferred.has(row.id)),
        ...(await fallback.sending()).map(toFallback),
      ];
    },
    // A clock-step adjustment still kept for the primary (it could not be written above): its
    // rows keep the expiry from before a forward step, so none of them is expired yet.
    expire: now =>
      sum(
        tryPrimary(() => (clockPending ? 0 : primary.expire(now)), 0),
        fallback.expire(now)
      ),
    hold: (id, now) =>
      sum(
        tryPrimary(() => primary.hold(id, now), 0),
        fallback.hold(id, now)
      ),
    // Not swallowed: rows the primary could not release stay held, and the outbox must know (a
    // probe stays due and is tried again; a resume is completed by the worker's upkeep). Rows in
    // memory are released first, so they can go even while the primary takes no writes.
    async release(id, now) {
      const kept = await fallback.release(id, now);
      await applyDeferred();
      try {
        return kept + (await primary.release(id, now));
      } catch (error) {
        if (storageError(error)) set(true, error);
        throw error;
      }
    },
    supersede: options =>
      sum(
        tryPrimary(() => primary.supersede(options), 0),
        fallback.supersede(options)
      ),
    async channel(id) {
      if (dirty.has(id)) return fallback.channel(id);
      return (await tryPrimary(() => primary.channel(id), null)) ?? fallback.channel(id);
    },
    async setChannel(id, status) {
      await fallback.setChannel(id, status);
      await applyDeferred();
      try {
        await primary.setChannel(id, status);
        dirty.delete(id);
      } catch (error) {
        dirty.add(id);
        if (storageError(error)) set(true, error);
        else
          logOnce(
            'channel',
            `A channel status could not be saved yet (${errorText(error)}); Uptime Goblin keeps it in memory.`
          );
      }
    },
    async channelIds() {
      return [
        ...new Set([
          ...(await tryPrimary(() => primary.channelIds(), [])),
          ...(await fallback.channelIds()),
        ]),
      ];
    },
    countActive: () =>
      sum(
        tryPrimary(() => primary.countActive(), 0),
        fallback.countActive()
      ),
    async counts() {
      const a = await tryPrimary(() => primary.counts(), {
          total: {},
          byChannel: {},
          oldestQueuedAt: null,
        }),
        b = await fallback.counts();
      const total = { ...a.total },
        byChannel = structuredClone(a.byChannel);
      for (const [state, n] of Object.entries(b.total)) total[state] = (total[state] ?? 0) + n;
      for (const [channel, states] of Object.entries(b.byChannel))
        for (const [state, n] of Object.entries(states)) {
          byChannel[channel] ??= {};
          byChannel[channel][state] = (byChannel[channel][state] ?? 0) + n;
        }
      const oldest = [a.oldestQueuedAt, b.oldestQueuedAt].filter(value => value !== null);
      return { total, byChannel, oldestQueuedAt: oldest.length ? Math.min(...oldest) : null };
    },
    async nextDueAt(now) {
      const times = [
        await tryPrimary(() => primary.nextDueAt(now), null),
        await fallback.nextDueAt(now),
      ].filter(value => value !== null);
      return times.length ? Math.min(...times) : null;
    },
    // Without a cursor: the memory rows first (newest first, ids m:<n>), then the primary's. A
    // cursor (beforeId, afterId) names a primary row, so only the primary is read. A primary row
    // whose kept result ends it is shown with that result, where the state filter allows it.
    // `part` reads one side alone, so the history can page through both in turn (§6.4,
    // amendment A30): 'memory' the rows kept in memory, below `beforeId` when it is an m:<n> id;
    // 'saved' the primary's.
    async list(filter = {}) {
      const { part = null, ...rest } = filter;
      if (part === 'memory') {
        const { beforeId, afterId, ...memoryFilter } = rest;
        if (
          (beforeId !== undefined && beforeId !== null && !isFallbackId(beforeId)) ||
          (afterId !== undefined && afterId !== null)
        )
          throw new TypeError('list(): a memory page is read below an m:<n> id only');
        return (
          await fallback.list({
            ...memoryFilter,
            ...(isFallbackId(beforeId)
              ? { beforeId: Number(beforeId.slice(FALLBACK.length)) }
              : {}),
          })
        ).map(toFallback);
      }
      const cursor =
        (rest.beforeId !== undefined && rest.beforeId !== null) ||
        (rest.afterId !== undefined && rest.afterId !== null);
      const wanted = rest.states ?? (rest.state ? [rest.state] : null);
      const main = (await readPrimary(() => primary.list(rest))).map(row => {
        const shown = pendingView(row);
        return !wanted || wanted.includes(shown.state) ? shown : row;
      });
      if (cursor || part === 'saved') return main;
      return [...(await fallback.list(rest)).map(toFallback), ...main];
    },
    prune: options =>
      sum(
        tryPrimary(() => primary.prune(options), 0),
        fallback.prune(options)
      ),
    async find(uid) {
      const kept = await fallback.find(uid);
      if (kept) return toFallback(kept);
      return readPrimary(() => primary.find(uid));
    },
    async batch(digestKey, options = {}) {
      let main = await readPrimary(() => primary.batch(digestKey, options));
      // Asked for by state (the worker's whole-batch check): a row whose kept result ends it is
      // not active any more.
      if (options.states)
        main = main.map(pendingView).filter(row => options.states.includes(row.state));
      return [...main, ...(await fallback.batch(digestKey, options)).map(toFallback)];
    },
    async requeue(ids, options) {
      const { main, memory } = split(ids);
      const saved = main.length ? await tryPrimary(() => primary.requeue(main, options), 0) : 0;
      if (!memory.length) return saved;
      // A row being written to the primary (persistFinished) is retried there, not in memory:
      // wait, then requeue only what is still here (a moved row counts 0; Retry answers "try
      // again", and the next Retry finds it in the primary).
      while (persisting) await persisting;
      return saved + (await fallback.requeue(memory, options));
    },
    async stale(options) {
      const saved = await tryPrimary(() => primary.stale(options), 0);
      return saved + (await fallback.stale(options));
    },
    async unclaim(ids, lease) {
      const { main, memory } = split(ids);
      let saved = 0;
      if (main.length) {
        await applyDeferred();
        try {
          saved = await primary.unclaim(main, lease);
        } catch (error) {
          if (error?.class !== 'fenced') {
            deferWrite(main, { unclaim: true, lease: { ...lease } }, error, 'unclaim');
            saved = main.length;
          }
        }
      }
      return saved + (memory.length ? await fallback.unclaim(memory, lease) : 0);
    },
    async cancel(options) {
      const saved = await tryPrimary(() => primary.cancel(options), 0);
      return saved + (await fallback.cancel(options));
    },
    async activeKeys(keys) {
      const either = new Set(),
        mark = list => list.forEach(key => either.add(orderOf(key)));
      mark(await tryPrimary(() => primaryActiveKeys(keys), []));
      mark(await fallback.activeKeys(keys));
      return (keys ?? [])
        .filter(key => either.has(orderOf(key)))
        .map(key => ({ channelId: key.channelId, orderKey: key.orderKey }));
    },
    // D25: the primary's share is written now or kept until it can be (adjustPrimary), never
    // dropped; the rows in memory are adjusted at once.
    async shiftExpiry(options = {}) {
      if (!options.by) return 0;
      const saved = await adjustPrimary(
        () => primary.shiftExpiry(options),
        clockStep({ by: options.by, now: options.now })
      );
      return saved + (await fallback.shiftExpiry(options));
    },
    async clampTimes(options = {}) {
      const saved = await adjustPrimary(() => primary.clampTimes(options), clockStep(options));
      return saved + (await fallback.clampTimes(options));
    },
    async summary(options = {}) {
      const out = structuredClone(await readPrimary(() => primary.summary(options)));
      // A primary row whose kept result ends it is counted with that result, not as sending.
      if (anyFinalPatch()) {
        const failedSince = options.failedSince ?? {};
        for (const row of await readPrimary(() => primary.sending())) {
          const patch = finalPatch(row.id),
            item = out[row.channelId];
          if (!patch || !item) continue;
          item.sending = Math.max(0, item.sending - 1);
          const since = Number.isFinite(failedSince[row.channelId])
            ? failedSince[row.channelId]
            : 0;
          if (patch.state === 'dead' && patch.updatedAt > since) item.failed++;
          if (Object.values(item).every(value => value === 0 || value === null))
            delete out[row.channelId];
        }
      }
      for (const [channelId, figures] of Object.entries(await fallback.summary(options))) {
        const item = (out[channelId] ??= {
          waiting: 0,
          retrying: 0,
          sending: 0,
          held: 0,
          failed: 0,
          oldestWaitingAt: null,
        });
        for (const name of ['waiting', 'retrying', 'sending', 'held', 'failed'])
          item[name] += figures[name];
        if (
          figures.oldestWaitingAt !== null &&
          (item.oldestWaitingAt === null || figures.oldestWaitingAt < item.oldestWaitingAt)
        )
          item.oldestWaitingAt = figures.oldestWaitingAt;
      }
      return out;
    },
    /**
     * Whether the primary can be written now: a write of a channel status it should hold anyway
     * (the memory copy of a dirty one, else its own). Success ends the degraded state, writes
     * the other dirty statuses, applies deferred completions and saves the rows that ended in
     * memory.
     */
    async probe() {
      try {
        let ids = [...dirty, ...(await fallback.channelIds())];
        if (!ids.length) ids = await primary.channelIds();
        const id = ids[0];
        if (id === undefined) return !degraded;
        const status = dirty.has(id)
          ? await fallback.channel(id)
          : ((await primary.channel(id)) ?? (await fallback.channel(id)));
        if (!status) return !degraded;
        await primary.setChannel(id, status);
        dirty.delete(id);
        for (const other of [...dirty]) {
          await primary.setChannel(other, await fallback.channel(other));
          dirty.delete(other);
        }
        set(false);
        await applyDeferred();
        await persistFinished();
        // Either may have met a full disk again (and said so).
        return !degraded;
      } catch (error) {
        if (storageError(error)) set(true, error);
        return false;
      }
    },
  };
}
