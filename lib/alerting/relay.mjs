// The relay (delivery spec §5.3; roadmap #14, D1-D4, D15, D23): it copies alert changes from
// history into the outbox. The history `events` row, written in the same transaction as the alert
// state change, is the transactional outbox record (relayed = 0); the relay enqueues its rows in
// control.sqlite and only then marks it relayed, by uid. A crash in between relays it again, and
// the outbox's unique delivery id absorbs the copy. SQLite reuses the highest event id after a
// source is deleted (V1), so nothing here ever names an event by id: marks go by uid, and the
// sweep's cursor lives only within one pass.
//
// Order (D23): every operation (the fast path, the sweep, Uptime Goblin's own notices and source
// deletions) runs on one queue, one at a time, in call order. The fast path relays nothing until a
// sweep has read history to its end, and leaves to the sweep every event whose (service, rule)
// has an older event it could not enqueue; the sweep relays in id order and, within a pass, skips
// the later events of a key whose enqueue failed. So the rows of one alert enter the outbox in the
// order the alert changed, and the outbox keeps that order by row id.
//
// Degraded (D15): an event whose rows went to memory (control.sqlite could not be written) stays
// relayed = 0 until those rows are final, so a restart sends again what was not yet delivered
// instead of losing it.
//
// Held (the ntfy and Gotify settings not read): enqueue queues the other channels' rows and says
// `held`; the event stays relayed = 0, the later changes of its key wait behind it, and the rows
// it put in memory are kept with it, to be awaited (D15) once it is relayed. While enqueue still
// holds (`waiting()`), a sweep passes such an event, and the later changes of its key, without
// enqueueing or counting them, so any number of held events or of changes waiting behind them
// cannot use up a pass's maxPerSweep and starve newer ones.
import { systemClock, safeErrorText } from '../jobs.mjs';
import { legacyOrderKey } from './policy.mjs';

const MARK_CHUNK = 200;

/**
 * createRelay({history, enqueue, isFinal, cancelSource, nameOf, waiting, clock, logger,
 * pageSize, maxPerSweep, rememberMax}) returns {relay, sweep, direct, forget, started, idle,
 * pending}.
 *
 * - history: {unrelayedEvents({afterId, limit}), markRelayed(uids)} (lib/store.mjs).
 * - enqueue(event, eventUid, {exclude, notice}) -> {inserted, duplicates, dropped, memoryUids,
 *   held}: the service's legacy routing into the outbox (`notice` as direct() was given it);
 *   `held` when some channels' rows wait (the event is then relayed again later). A TypeError
 *   means the outbox refuses the entry; any other error leaves the event unrelayed.
 * - waiting() -> boolean: whether enqueue still holds those rows (a held event is not tried
 *   again while it does).
 * - isFinal(deliveryUid) -> boolean: the row is final, or gone.
 * - cancelSource(serviceId) -> rows cancelled.
 */
export function createRelay({
  history,
  enqueue,
  isFinal = async () => true,
  cancelSource = async () => 0,
  nameOf = () => undefined,
  waiting = () => false,
  clock = systemClock,
  logger = console,
  pageSize = 200,
  maxPerSweep = 2000,
  rememberMax = 10000,
}) {
  if (typeof history?.unrelayedEvents !== 'function' || typeof history?.markRelayed !== 'function')
    throw new TypeError('createRelay needs history.unrelayedEvents and history.markRelayed');
  if (typeof enqueue !== 'function') throw new TypeError('createRelay needs enqueue');

  let chain = Promise.resolve(),
    queued = 0,
    begun = false,
    // True once a sweep read every unrelayed event: from then on, every event older than the
    // ones the fast path gets is in the outbox (or its key is in `held`).
    caughtUp = false;
  // Keys (service\nrule) with an older event the relay could not enqueue: their newer events wait
  // for the sweep, so a recovery can never be enqueued before its firing.
  let held = new Set();
  // Event uids being enqueued, or enqueued and not yet marked (uid -> service).
  const inProgress = new Map(),
    // Of those, enqueued with every row in the outbox: waiting only for their mark.
    unmarked = new Set(),
    // Event uids whose rows went to memory (D15): uid -> {service, deliveries: [delivery uids]}.
    awaiting = new Map(),
    // Event uids that enqueue held, with the rows they put in memory meanwhile (the same shape).
    heldEvents = new Map();
  const notes = new Map();
  // A problem that repeats (history full, a store failing) is logged once a minute.
  function note(key, text) {
    const now = clock.now(),
      last = notes.get(key);
    if (last !== undefined && now - last < 60000) return;
    notes.set(key, now);
    logger.error?.(text);
  }

  // Runs `operation` after every operation queued before it, never beside one.
  function enqueueOperation(operation) {
    queued++;
    const run = chain.then(() => operation());
    chain = run.then(
      () => queued--,
      () => queued--
    );
    return run;
  }

  // Bounded memory: the oldest remembered uids are forgotten first. A forgotten uid is relayed
  // again by a later sweep, and the outbox's unique delivery id absorbs the copy.
  function remember(uid, service) {
    inProgress.set(uid, service);
    while (inProgress.size > rememberMax) {
      const oldest = inProgress.keys().next().value;
      inProgress.delete(oldest);
      unmarked.delete(oldest);
    }
  }
  function forgetUid(uid) {
    inProgress.delete(uid);
    unmarked.delete(uid);
  }

  /** Marks `uids` relayed (by uid, never by id), in chunks. Resolves the uids marked. */
  async function mark(uids) {
    const done = [];
    for (let i = 0; i < uids.length; i += MARK_CHUNK) {
      const chunk = uids.slice(i, i + MARK_CHUNK);
      try {
        await history.markRelayed(chunk);
        done.push(...chunk);
      } catch (error) {
        // The rows are in the outbox; only the mark is missing. They stay in progress (the
        // sweep skips them) and the mark is tried again at the next sweep.
        note('mark', `Alert changes could not be marked as relayed: ${safeErrorText(error)}`);
        break;
      }
    }
    for (const uid of done) forgetUid(uid);
    return done.length;
  }

  // Enqueues one event; resolves 'enqueued', 'memory' (rows kept in memory) or 'failed'.
  async function relayOne(event, uid, counts) {
    remember(uid, event.service);
    let result;
    try {
      result = await enqueue(event, uid, {});
    } catch (error) {
      if (error instanceof TypeError) {
        // An entry the outbox refuses would block its key for good: it is logged and marked.
        logger.error?.(`Alert change ${uid} cannot be queued and is skipped: ${error.message}`);
        unmarked.add(uid);
        return 'enqueued';
      }
      forgetUid(uid);
      note('enqueue', `Alert notifications could not be queued: ${safeErrorText(error)}`);
      return 'failed';
    }
    counts.enqueued += result?.inserted ?? 0;
    // Rows an earlier, held attempt put in memory count with this attempt's.
    const deliveries = [
      ...new Set([...(heldEvents.get(uid)?.deliveries ?? []), ...(result?.memoryUids ?? [])]),
    ];
    if (result?.held) {
      forgetUid(uid);
      heldEvents.set(uid, { service: event.service, deliveries });
      note(
        'held',
        'Alert notifications for ntfy and Gotify wait until their settings can be read; the other channels were queued.'
      );
      return 'held';
    }
    heldEvents.delete(uid);
    if (deliveries.length) {
      // D15: marked only once these rows are final (sweep), so a restart sends them again.
      inProgress.delete(uid);
      awaiting.set(uid, { service: event.service, deliveries });
      return 'memory';
    }
    unmarked.add(uid);
    return 'enqueued';
  }

  /** The fast path: the transitions store.evaluate() just wrote. */
  function relay(events) {
    const list = Array.isArray(events) ? events : [];
    return enqueueOperation(async () => {
      const counts = { enqueued: 0, marked: 0, deferred: 0 };
      if (!begun || !caughtUp) {
        counts.deferred = list.length;
        return counts;
      }
      const failed = new Set(),
        toMark = [];
      for (const event of list) {
        const uid = event?.uid,
          key = legacyOrderKey(event ?? {});
        if (typeof uid !== 'string' || !uid) {
          note('uid', 'An alert change without a uid cannot be relayed; it is not sent.');
          continue;
        }
        if (
          held.has(key) ||
          failed.has(key) ||
          inProgress.has(uid) ||
          awaiting.has(uid) ||
          heldEvents.has(uid)
        ) {
          counts.deferred++;
          continue;
        }
        const outcome = await relayOne(event, uid, counts);
        if (outcome === 'failed' || outcome === 'held') {
          held.add(key);
          failed.add(key);
          counts.deferred++;
        } else if (outcome === 'enqueued') toMark.push(uid);
      }
      counts.marked = await mark(toMark);
      return counts;
    });
  }

  /** Marks the events whose memory rows are all final (D15). Resolves how many it marked. */
  async function settle() {
    const ready = [];
    for (const [uid, entry] of awaiting) {
      let final = true;
      for (const delivery of entry.deliveries) {
        // A row that cannot be read now is not known to be final: it is checked again later.
        const done = await Promise.resolve()
          .then(() => isFinal(delivery))
          .catch(() => false);
        if (!done) {
          final = false;
          break;
        }
      }
      if (final) ready.push(uid);
    }
    for (const uid of ready) {
      const { service } = awaiting.get(uid);
      awaiting.delete(uid);
      remember(uid, service);
      unmarked.add(uid);
    }
    return ready.length ? mark(ready) : 0;
  }

  /**
   * The sweep: settles events kept in memory, retries marks that failed, then pages through
   * the unrelayed events in id order, enqueueing and marking each (at most maxPerSweep of them;
   * events already in progress, still held, or waiting behind a key held or failed in this pass
   * are skipped and not counted).
   */
  function sweep({ signal } = {}) {
    return enqueueOperation(async () => {
      const result = { relayed: 0, marked: 0, pending: 0, settled: 0 };
      // Marks that failed earlier (history full): the rows are in the outbox already.
      if (unmarked.size) result.marked += await mark([...unmarked]);
      result.settled = await settle();
      const failed = new Set(),
        counts = { enqueued: 0 };
      let afterId = 0,
        processed = 0,
        reachedEnd = false;
      try {
        pages: while (processed < maxPerSweep && !signal?.aborted) {
          const rows = await history.unrelayedEvents({ afterId, limit: pageSize });
          const toMark = [];
          let cutShort = false;
          for (const row of rows) {
            if (inProgress.has(row.uid) || awaiting.has(row.uid)) {
              afterId = row.id;
              continue;
            }
            // Still held: not enqueued or counted again, and its key's later changes wait.
            if (heldEvents.has(row.uid) && waiting()) {
              afterId = row.id;
              failed.add(legacyOrderKey(row));
              continue;
            }
            const key = legacyOrderKey(row);
            // A later change of a key that is held or whose enqueue failed in this pass waits for
            // the next one. Not counted either: it costs no enqueue, and any number of changes
            // waiting behind one held event must not use up maxPerSweep and starve newer keys.
            if (failed.has(key)) {
              afterId = row.id;
              continue;
            }
            if (processed >= maxPerSweep) {
              cutShort = true;
              break;
            }
            afterId = row.id;
            processed++;
            const event = {
              service: row.service,
              name: nameOf(row.service) ?? row.service,
              kind: row.kind,
              category: row.category ?? undefined,
              rule: row.rule ?? undefined,
              message: row.message,
              time: row.time,
            };
            const outcome = await relayOne(event, row.uid, counts);
            if (outcome === 'failed' || outcome === 'held') failed.add(key);
            else {
              result.relayed++;
              if (outcome === 'enqueued') toMark.push(row.uid);
            }
          }
          result.marked += await mark(toMark);
          if (cutShort) break pages;
          if (rows.length < pageSize) reachedEnd = true;
          if (reachedEnd) break pages;
        }
      } finally {
        // A pass that read every unrelayed event decides which keys are held; one cut short
        // (or failed) keeps the old ones and adds its own.
        if (reachedEnd) {
          held = failed;
          caughtUp = true;
        } else for (const key of failed) held.add(key);
      }
      result.pending = unmarked.size + awaiting.size;
      return result;
    });
  }

  /** Uptime Goblin's own notices (storage, fallback, pause, disk): no history row, nothing to mark. */
  function direct(event, uid, { exclude = [], notice = false } = {}) {
    return enqueueOperation(async () => {
      const result = await enqueue(event, uid, notice ? { exclude, notice } : { exclude });
      return { enqueued: result?.inserted ?? 0 };
    });
  }

  /** After store.forget(serviceId): cancels the source's waiting rows (D24). */
  function forget(serviceId) {
    return enqueueOperation(async () => {
      const cancelled = await cancelSource(serviceId);
      const prefix = `${serviceId}\n`;
      for (const key of [...held]) if (key.startsWith(prefix)) held.delete(key);
      for (const map of [awaiting, heldEvents])
        for (const [uid, entry] of [...map]) if (entry.service === serviceId) map.delete(uid);
      // Their history rows are gone with the source: there is nothing left to mark.
      for (const [uid, service] of [...inProgress]) if (service === serviceId) forgetUid(uid);
      return { cancelled };
    });
  }

  /** Resolves once every operation queued so far, and any queued meanwhile, has finished. */
  async function idle() {
    for (;;) {
      const current = chain;
      await current;
      if (current === chain && queued === 0) return;
    }
  }

  return {
    relay,
    sweep,
    direct,
    forget,
    /** The start sweep was queued: from here the fast path may relay once a sweep caught up. */
    started() {
      begun = true;
    },
    idle,
    /** Event uids enqueued but not yet marked relayed. */
    get pending() {
      return unmarked.size + awaiting.size;
    },
    get caughtUp() {
      return caughtUp;
    },
  };
}
