// Aggregated events (audit spec D9, §4.5): refused sign-ins, refused password changes, and legacy
// Basic failures and use. What an unauthenticated client can make Uptime Goblin write must not depend on
// how much it sends, so each action gets at most two rows a window, whatever the traffic: the
// first event of the window at once (an attack is visible from its first attempt), and one
// summary of every other event at the window's end. The window is the UTC hour, or the UTC day
// for auth.basic.used. The two anonymous actions write at most 96 rows a day; with the password
// changes refused before a credential signed in (Codex review A5), what clients nobody
// authenticated can make Uptime Goblin write is at most 144 rows a day.
//
// A login string is reduced to its class at once (admin, other, or null) and never kept: a
// password typed into the login field must not land in the log, nor be testable against it, so
// neither the string nor any hash of it is stored.
//
// count() is synchronous and never throws: the routes call it on their refusal paths. Writes go
// through the `write(event, kind)` the service gives (an own unit, best effort, resolving
// whether the row was written). While the disk is full nothing is written and every event is
// counted; counts that could not be written carry into the next summary, so none is lost while
// Uptime Goblin runs, and close() prints what is left. A timer is armed only while counted events wait.
import { AGG_CLIENTS_TRACKED, AGG_SAMPLE } from './actions.mjs';

/** The actions count() takes. */
export const AGGREGATED = Object.freeze([
  'session.login',
  'account.password.changed',
  'auth.basic.failed',
  'auth.basic.used',
  'auth.forbidden',
  'auth.step-up',
]);
const HOUR = 3600000,
  DAY = 86400000;
const windowSize = action => (action === 'auth.basic.used' ? DAY : HOUR);
/** The window `at` falls in: {start, end}. */
export const windowOf = (action, at) => {
  const size = windowSize(action),
    start = Math.floor(at / size) * size;
  return { start, end: start + size };
};
// Refusals of a client nobody has authenticated: their rows name no actor.
const anonymousActions = new Set(['session.login', 'auth.basic.failed']);
const anonymous = Object.freeze({
  type: 'anonymous',
  id: null,
  name: null,
  via: null,
  sessionId: null,
});
// The actor of a summary that counts events of `a` and of `b` (Codex review A5): the first one
// named, as before, except that a signed-in actor is never replaced by the anonymous one of a
// password change refused before anyone signed in. Only a signed-in session can make the
// refusals of the change's own checks (current_password_incorrect, …), so a summary mixing
// both names that session; its `codes` tell which refusals came before sign-in. Naming no one
// there would let a client nobody authenticated wipe a guessing session's id from the log by
// sending two refusals of its own in the same hour.
const sharedActor = (a, b) =>
  !a ? b : b && a.type === 'anonymous' && b.type !== 'anonymous' ? b : a;

/**
 * The class of a login string (D9): `admin` when its NFKC-normalised, trimmed, lower-cased form
 * is admin, `other` for any other non-empty string, null for none.
 */
export function loginClass(login) {
  if (typeof login !== 'string') return null;
  const normalised = login.normalize('NFKC').trim();
  if (!normalised) return null;
  return normalised.toLowerCase() === 'admin' ? 'admin' : 'other';
}

const text = (value, max) =>
  typeof value === 'string' && value ? Array.from(value).slice(0, max).join('') : null;

/**
 * The aggregator. Options: clock (ms), write(event, kind) → Promise<boolean> (kind `immediate`
 * or `summary`), full() (the storage guard is full), setTimer(fn, ms) / clearTimer(handle)
 * (unref'd timers; tests give their own).
 */
export function createAggregator({
  clock = Date.now,
  write,
  full = () => false,
  setTimer = (fn, ms) => {
    const handle = setTimeout(fn, Math.max(0, ms));
    handle.unref?.();
    return handle;
  },
  clearTimer = handle => clearTimeout(handle),
}) {
  // Per action: the current window and whether its immediate row was taken, and `waiting`, the
  // counted events not yet written (which carry across windows while they cannot be written).
  const state = new Map();
  let timer = null,
    timerAt = null;
  const inFlight = new Set();

  const track = promise => {
    inFlight.add(promise);
    promise.finally(() => inFlight.delete(promise));
    return promise;
  };
  const fresh = () => ({
    count: 0,
    codes: {},
    clients: new Set(),
    more: false,
    sample: [],
    from: null,
    to: null,
    failed: false,
    actor: null,
  });
  const entryOf = action => {
    let entry = state.get(action);
    if (!entry) {
      entry = { window: null, taken: false, waiting: fresh() };
      state.set(action, entry);
    }
    return entry;
  };
  // Counts one event into `waiting`: its code, its client (up to 1,000 distinct ones, then
  // `more`), the first 10 clients as a sample, the first and last time.
  const add = (waiting, event) => {
    waiting.count += 1;
    if (event.code) waiting.codes[event.code] = (waiting.codes[event.code] ?? 0) + 1;
    if (event.client) {
      if (waiting.clients.has(event.client)) {
        // Already counted.
      } else if (waiting.clients.size < AGG_CLIENTS_TRACKED) {
        waiting.clients.add(event.client);
        if (waiting.sample.length < AGG_SAMPLE) waiting.sample.push(event.client);
      } else waiting.more = true;
    }
    waiting.from = waiting.from === null ? event.at : Math.min(waiting.from, event.at);
    waiting.to = waiting.to === null ? event.at : Math.max(waiting.to, event.at);
    if (event.outcome === 'failed') waiting.failed = true;
    waiting.actor = sharedActor(waiting.actor, event.actor);
  };
  const merge = (into, from) => {
    into.count += from.count;
    for (const [code, n] of Object.entries(from.codes))
      into.codes[code] = (into.codes[code] ?? 0) + n;
    for (const client of from.clients) {
      if (into.clients.has(client)) continue;
      if (into.clients.size < AGG_CLIENTS_TRACKED) {
        into.clients.add(client);
        if (into.sample.length < AGG_SAMPLE) into.sample.push(client);
      } else into.more = true;
    }
    into.more ||= from.more;
    if (from.from !== null)
      into.from = into.from === null ? from.from : Math.min(into.from, from.from);
    if (from.to !== null) into.to = into.to === null ? from.to : Math.max(into.to, from.to);
    into.failed ||= from.failed;
    into.actor = sharedActor(into.actor, from.actor);
  };

  /** The summary event of `waiting` for `action`, at `at` (the window's end). */
  function summaryOf(action, waiting, at) {
    const named = anonymousActions.has(action);
    return {
      action,
      outcome: action === 'auth.basic.used' ? 'ok' : waiting.failed ? 'failed' : 'denied',
      at,
      actor: named ? anonymous : (waiting.actor ?? anonymous),
      target: { type: 'account', id: named ? null : 'u_admin', name: null },
      count: waiting.count,
      detail: {
        codes: { ...waiting.codes },
        clients: waiting.clients.size,
        more: waiting.more,
        sample: [...waiting.sample],
        from: waiting.from,
        to: waiting.to,
      },
    };
  }

  // Writes the waiting summary of `action` at `at`, unless the disk is full; a summary that
  // fails puts its counts back, so they go into the next one.
  function flushAction(action, entry, at) {
    if (!entry.waiting.count || full()) return null;
    const waiting = entry.waiting;
    entry.waiting = fresh();
    return track(
      Promise.resolve()
        .then(() => write(summaryOf(action, waiting, at), 'summary'))
        .catch(() => false)
        .then(written => {
          if (!written) merge(entry.waiting, waiting);
          arm();
        })
    );
  }

  // Writes the summary of every action whose window has ended (of all, at once, with `force`:
  // close()); its time is the window's end, or now for a window that has not ended.
  function flush({ force = false } = {}) {
    const now = clock(),
      writes = [];
    for (const [action, entry] of state) {
      if (!entry.window || !(force || entry.window.end <= now)) continue;
      const written = flushAction(action, entry, Math.min(entry.window.end, now));
      if (written) writes.push(written);
    }
    arm();
    return Promise.all(writes);
  }

  // A timer for the earliest window end among the actions with waiting counts; none otherwise.
  // Counts whose window ended unwritten (the disk was full, or the write failed) carry into the
  // window of now: its end is the next try, so a failing write is never retried in a loop.
  // Review round 2: so do counts whose window begins after now (the clock was stepped back): a
  // timer for that window's end would wait until the clock got there again, and one more than
  // 2^31 ms away fires at once (Node clamps it to 1 ms), so it fired, flushed nothing and was
  // armed again, every millisecond. The delay is also never more than a window.
  function arm() {
    const now = clock();
    let next = null;
    for (const [action, entry] of state) {
      if (!entry.waiting.count || !entry.window) continue;
      if (entry.window.end <= now || entry.window.start > now) {
        // No event arrived in the window of now (count() would have moved to it).
        entry.window = windowOf(action, now);
        entry.taken = false;
      }
      next = next === null ? entry.window.end : Math.min(next, entry.window.end);
    }
    if (next === timerAt) return;
    if (timer !== null) clearTimer(timer);
    timer = null;
    timerAt = next;
    if (next === null) return;
    timer = setTimer(
      () => {
        timer = null;
        timerAt = null;
        void flush();
      },
      Math.min(next - now, DAY)
    );
  }

  return {
    /** Counts one event (§4.5). Never throws, never awaits. */
    count(event) {
      try {
        const action = event?.action;
        if (!AGGREGATED.includes(action)) return;
        const at = Number.isSafeInteger(event.at) ? event.at : clock();
        const entry = entryOf(action);
        const window = windowOf(action, at);
        if (!entry.window || entry.window.start !== window.start) {
          // A new window: what the last one counted is written first, at its end, as its timer
          // would have (a late timer, or a clock that moved on); at once when the clock went
          // back before that end (review round 2), never dated after this event.
          if (entry.window) void flushAction(action, entry, Math.min(entry.window.end, at));
          entry.window = window;
          entry.taken = false;
        }
        const login = anonymousActions.has(action) ? loginClass(event.login) : null;
        const counted = {
          outcome: event.outcome,
          at,
          code: text(event.detail?.code, 64),
          client: text(event.client, 64),
          actor: anonymousActions.has(action) ? anonymous : (event.actor ?? null),
        };
        if (!entry.taken && !full()) {
          entry.taken = true;
          const detail = anonymousActions.has(action)
            ? { code: counted.code, login }
            : ['account.password.changed', 'auth.forbidden', 'auth.step-up'].includes(action)
              ? { code: counted.code }
              : null;
          const immediate = {
            action,
            outcome: event.outcome,
            at,
            actor: anonymousActions.has(action) ? anonymous : event.actor,
            client: counted.client,
            userAgent: typeof event.userAgent === 'string' ? event.userAgent : null,
            target: {
              type: 'account',
              id: anonymousActions.has(action) ? (login === 'admin' ? 'admin' : null) : 'u_admin',
              name: null,
            },
            detail,
          };
          track(
            Promise.resolve()
              .then(() => write(immediate, 'immediate'))
              .catch(() => false)
              .then(written => {
                if (written) return;
                add(entryOf(action).waiting, counted);
                arm();
              })
          );
          return;
        }
        add(entry.waiting, counted);
        arm();
      } catch {
        // count() never fails its caller (a refusal path).
      }
    },
    flush,
    /** The counts not written, per action: {action: {count, codes, from, to}} (close()). */
    pending() {
      const found = {};
      for (const [action, entry] of state)
        if (entry.waiting.count)
          found[action] = {
            count: entry.waiting.count,
            codes: { ...entry.waiting.codes },
            from: entry.waiting.from,
            to: entry.waiting.to,
          };
      return found;
    },
    /** Resolves when no aggregated write is in flight. */
    async idle() {
      while (inFlight.size) await Promise.allSettled([...inFlight]);
    },
    /** Whether a timer is armed (tests: an idle Uptime Goblin arms none). */
    get armed() {
      return timer !== null;
    },
    /** Stops the timer (close()). */
    stop() {
      if (timer !== null) clearTimer(timer);
      timer = null;
      timerAt = null;
    },
  };
}
