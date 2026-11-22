// Idempotency-Key handling (roadmap §2.4 step 13), extracted from server.mjs 1.4.3 with the same
// rules, behind a storage adapter so wave 2 can keep keys in the control database:
//
// - A key is 8-128 letters, digits, hyphens or underscores (anything else is a 400).
// - The outcome of a keyed write is kept for 10 minutes. The same key and body again is answered
//   from it ("replayed"); the same key with another body is a 422 ("conflict"); a retry arriving
//   while the first attempt still runs waits for it and is then answered from it.
// - Refusals that applied nothing (401, 403, 429, 503: sessions spec D22, as server.mjs) are not
//   kept, so a retry may succeed: after signing in again it runs or joins, never replays a
//   refusal. Neither are answers over 64 KiB.
// - A write applied as its session ended (a sign-out, a revocation, a password change) is
//   answered 401, but the key keeps the outcome its handler recorded with the pipeline's
//   committed() (`res.orbitCommitted`), so the retry signed in again is answered from it and the
//   write runs once (delivery spec A62, as server.mjs). The request whose session ended gets only
//   the 401, and the ended session's own retry is refused by the check below before it is
//   answered from anything.
// - Bodies are compared by an HMAC with a process secret, so storage never holds a plain hash
//   of a request body.
// - The scope is chosen by the caller: the pipeline passes [principal and its epoch (D22),
//   method, path], which a sign-out, a revocation and a password change made in Uptime Goblin keep, and
//   the key is appended.
// - Before a request runs, and before it is answered from a kept or awaited outcome, the
//   caller's credential is rechecked (1.4.x maintenance): the body or an earlier attempt may have
//   held the retry across a password change, which must stop it like any other request. The
//   last check comes after the last await, as server.mjs keeps it in one synchronous section
//   with the replay or run: a busy store (the SQLite adapter backs off on SQLITE_BUSY) is such a
//   wait too.
// - A store that cannot be read or written (a full disk, a database that is unavailable) never
//   fails a request: that request is handled with an in-memory store, exactly as 1.4.3 did.
//
// A store adapter is {begin, takeOver, finish, abandon, prune} (all async, below). The memory
// adapter reproduces 1.4.3's limits: at most 1,000 entries and 4 MiB of kept answers, oldest
// finished answers dropped first, and an entry still running never dropped.
// createIdempotencyHandler() adapts all this to the request pipeline's `idempotency` option.
import { createHmac, randomBytes } from 'node:crypto';
import { InputError } from '../config.mjs';
import { json, replay } from './body.mjs';

export const IDEMPOTENCY_KEY_PATTERN = /^[\w-]{8,128}$/;
export const INVALID_KEY_MESSAGE =
  'Idempotency-Key must be 8-128 letters, digits, hyphens or underscores';
export const CONFLICT_MESSAGE = 'This Idempotency-Key was already used for a different request.';

/** An unusable Idempotency-Key header: an InputError, so the pipeline answers 400 with it. */
export class IdempotencyKeyError extends InputError {
  constructor() {
    super(INVALID_KEY_MESSAGE);
    this.name = 'IdempotencyKeyError';
    this.status = 400;
  }
}

export const validIdempotencyKey = key =>
  typeof key === 'string' && IDEMPOTENCY_KEY_PATTERN.test(key);

const copyResponse = ({ status, body, headers = {} }) => ({
  status,
  body: String(body),
  headers: { ...headers },
});

/**
 * In-memory adapter. Entries are {digest, response|null, expiresAt|null, leaseUntil}. `id` is
 * the scope and key joined by newlines; every call also receives `parts: {scope: [...], key}`,
 * which a database adapter may store as columns (the memory adapter ignores it).
 * - begin(id, {digest, leaseUntil, parts}) -> {entry: null} when a new pending entry was
 *   created for the caller, or {entry} (a copy of what is there) otherwise.
 * - takeOver(id, {digest, leaseUntil, now, parts}) -> true when a pending entry whose lease
 *   ended (its process died) now belongs to the caller.
 * - finish(id, {response, expiresAt, parts}); abandon(id, {parts}) forgets a pending entry;
 *   prune(now) -> number removed.
 * - peek(id) -> a copy of the entry, or null (memory adapter only; used for its fallback role).
 */
export function memoryIdempotencyStore({ maxEntries = 1000, maxBytes = 4 * 1024 * 1024 } = {}) {
  const entries = new Map();
  let bytes = 0;
  const copy = entry => ({
    digest: entry.digest,
    response: entry.response && copyResponse(entry.response),
    expiresAt: entry.expiresAt,
    leaseUntil: entry.leaseUntil,
  });
  return {
    kind: 'memory',
    async begin(scope, { digest, leaseUntil }) {
      const entry = entries.get(scope);
      if (entry) return { entry: copy(entry) };
      entries.set(scope, { digest, response: null, expiresAt: null, leaseUntil });
      return { entry: null };
    },
    async takeOver(scope, { digest, leaseUntil, now }) {
      const entry = entries.get(scope);
      if (!entry || entry.response || entry.leaseUntil > now) return false;
      entry.digest = digest;
      entry.leaseUntil = leaseUntil;
      return true;
    },
    async finish(scope, { response, expiresAt }) {
      const entry = entries.get(scope);
      if (!entry || entry.response) return;
      entry.response = copyResponse(response);
      entry.expiresAt = expiresAt;
      bytes += entry.response.body.length;
    },
    async abandon(scope) {
      const entry = entries.get(scope);
      if (entry && !entry.response) entries.delete(scope);
    },
    // 1.4.3's forgetReplies(): oldest first, drop a finished answer when it expired or while
    // the store is over either limit.
    async prune(now) {
      let removed = 0;
      for (const [scope, entry] of entries) {
        if (!entry.response) continue;
        if (entry.expiresAt > now && entries.size <= maxEntries && bytes <= maxBytes) continue;
        entries.delete(scope);
        bytes -= entry.response.body.length;
        removed++;
      }
      return removed;
    },
    async peek(scope) {
      const entry = entries.get(scope);
      return entry ? copy(entry) : null;
    },
    stats: () => ({ entries: entries.size, bytes }),
  };
}

/**
 * createIdempotency({store, fallback, now, ttlMs, secret, ...}).run({key, scope, body, execute,
 * check}) resolves with one of
 * - {outcome: 'executed', response, kept}: execute() ran here; `response` is what it returned
 *   ({status, body, headers}, or null when it produced none);
 * - {outcome: 'replayed', response}: answer with this, plus `Idempotent-Replayed: true`;
 * - {outcome: 'conflict'}: answer 422 with CONFLICT_MESSAGE.
 * It rejects with IdempotencyKeyError for an invalid key, or with what execute() threw (the key
 * is then forgotten, so a retry runs again). `check()`, when given, runs before each look at the
 * key (first, and again after waiting for another attempt), and again after the store has
 * answered, with no await before the request is answered or execute() starts: what it throws
 * rejects the request before anything runs or is replayed, and a key it had claimed is released.
 *
 * `now` must suit the store: a monotonic clock for the memory store (as 1.4.3), wall-clock
 * milliseconds for a persistent one, whose `secret` must also survive restarts and be shared
 * by every process using the store. `fallback` (a memory store, used for a request whenever
 * `store` fails) defaults to one when `store` is not itself the memory store.
 */
export function createIdempotency({
  store = memoryIdempotencyStore(),
  fallback,
  now = () => performance.now(),
  ttlMs = 10 * 60 * 1000,
  secret = randomBytes(32),
  maxResponseBytes = 65536,
  // Refusals that applied nothing (D22). A committed outcome is the response execute() returns
  // (createIdempotencyHandler), so a 401 that followed it is never what is checked here.
  keep = response => ![401, 403, 429, 503].includes(response.status),
  // A pending entry of another process is taken over once its lease has ended (a crash).
  leaseMs = 60 * 1000,
  pollMs = 250,
  sleep = ms => new Promise(resolve => setTimeout(resolve, ms)),
} = {}) {
  if (fallback === undefined) fallback = store.kind === 'memory' ? null : memoryIdempotencyStore();
  // Attempts running in this process, by id: {digest, done}. A retry joins them directly.
  const running = new Map();
  let storeErrors = 0,
    lastStoreError = null,
    degradedRuns = 0;
  const digestOf = body =>
    createHmac('sha256', secret)
      .update(body ?? '')
      .digest('hex');
  const noteError = error => {
    storeErrors++;
    lastStoreError = error;
  };
  const pruneQuietly = async target => {
    try {
      await target?.prune(now());
    } catch (error) {
      noteError(error);
    }
  };
  // What an existing entry means for this request, or null when it is still running elsewhere.
  const answerFrom = (entry, digest) =>
    entry.digest !== digest
      ? { outcome: 'conflict' }
      : entry.response
        ? { outcome: 'replayed', response: entry.response }
        : null;

  async function run({ key, scope = [], body, execute, check = () => {} }) {
    if (!validIdempotencyKey(key)) throw new IdempotencyKeyError();
    const scopeParts = (Array.isArray(scope) ? scope : [scope]).map(String),
      id = [...scopeParts, key].join('\n'),
      parts = { scope: scopeParts, key },
      digest = digestOf(body);
    // An answer found after an await is returned only once the credential passes again: the
    // store (or the fallback) may have been slow long enough for a password change.
    const rechecked = answer => {
      check();
      return answer;
    };
    let owner = null;
    for (;;) {
      // Before anything touches the store, on every pass (after waiting for another attempt).
      check();
      const local = running.get(id);
      if (local) {
        // No await since the check above, so this answer needs no recheck.
        if (local.digest !== digest) return { outcome: 'conflict' };
        await local.done;
        continue;
      }
      // Answers kept in memory while the store was failing are still honoured.
      if (fallback && fallback !== store) {
        await pruneQuietly(fallback);
        const kept = await fallback.peek(id);
        const answer = kept && answerFrom(kept, digest);
        if (answer) return rechecked(answer);
      }
      let entry;
      try {
        await store.prune(now());
        ({ entry } = await store.begin(id, { digest, leaseUntil: now() + leaseMs, parts }));
      } catch (error) {
        if (!fallback) throw error;
        noteError(error);
        degradedRuns++;
        ({ entry } = await fallback.begin(id, { digest, leaseUntil: now() + leaseMs, parts }));
        if (entry) {
          const answer = answerFrom(entry, digest);
          if (answer) return rechecked(answer);
          continue;
        }
        owner = fallback;
        break;
      }
      if (!entry) {
        owner = store;
        break;
      }
      const answer = answerFrom(entry, digest);
      if (answer) return rechecked(answer);
      // Pending in another process: take it over once its lease ended, otherwise wait.
      let taken;
      try {
        taken = await store.takeOver(id, {
          digest,
          leaseUntil: now() + leaseMs,
          now: now(),
          parts,
        });
      } catch (error) {
        if (!fallback) throw error;
        noteError(error);
        degradedRuns++;
        ({ entry } = await fallback.begin(id, { digest, leaseUntil: now() + leaseMs, parts }));
        if (entry) {
          const answer = answerFrom(entry, digest);
          if (answer) return rechecked(answer);
          continue;
        }
        owner = fallback;
        break;
      }
      if (taken) {
        owner = store;
        break;
      }
      await sleep(pollMs);
    }
    let settle,
      response = null,
      kept = false;
    running.set(id, { digest, done: new Promise(resolve => (settle = resolve)) });
    try {
      // The last check, after the store's last await and just before execute(): a stale
      // credential runs nothing, and with no response the claimed key is abandoned below, so
      // a retry (or another process) is not left waiting on it until the lease ends.
      check();
      response = (await execute()) ?? null;
    } finally {
      // The request has been answered (or refused by check()) by now: a store failure only
      // means a retry runs again (as after a restart in 1.4.3), so it never fails the request
      // itself.
      try {
        if (response && keep(response) && String(response.body).length <= maxResponseBytes) {
          await owner.finish(id, { response, expiresAt: now() + ttlMs, parts });
          kept = true;
        } else await owner.abandon(id, { parts });
      } catch (error) {
        noteError(error);
      } finally {
        running.delete(id);
        settle();
      }
      await pruneQuietly(owner);
    }
    return { outcome: 'executed', response, kept };
  }

  return {
    run,
    digest: digestOf,
    prune: async () => {
      await pruneQuietly(fallback);
      return store.prune(now());
    },
    store,
    fallback,
    status: () => ({
      running: running.size,
      storeErrors,
      degradedRuns,
      lastStoreError: lastStoreError && String(lastStoreError.code ?? lastStoreError.name),
    }),
  };
}

/**
 * The request pipeline's `idempotency(req, res, {key, scope, body, access}, run)` option over
 * createIdempotency(), answering exactly as server.mjs's idempotent() does: 400 for an invalid
 * key (the pipeline answers the thrown InputError), 422 for a key reused with another body, a
 * replay with `Idempotent-Replayed: true`, and otherwise run(). What is kept is the outcome
 * run()'s handler recorded with committed() (res.orbitCommitted, delivery spec A62), when there
 * is one, and otherwise its JSON answer (res.orbitResponse, recorded by body.mjs json()), each
 * unless it is a refusal that applied nothing (see createIdempotency's `keep`). So a write
 * applied as its session ended is answered 401 but keeps its outcome under the key, and the
 * retry signed in again replays it. `fail(res, error)` answers what run() threw
 * (lib/http/pipeline.mjs fail). `assertCurrent(access)` (identity.assertCurrent) rechecks the
 * pipeline's `access` before the request runs or is answered from a kept reply, as server.mjs
 * does, so an ended session never receives a kept outcome; the AuthError it throws is answered
 * by the pipeline.
 */
export function createIdempotencyHandler(idempotency, { fail, assertCurrent = () => {} }) {
  if (typeof fail !== 'function') throw new TypeError('createIdempotencyHandler needs fail');
  return async function idempotent(req, res, { key, scope, body, access }, run) {
    const result = await idempotency.run({
      key: String(key),
      scope,
      body,
      check: () => assertCurrent(access),
      async execute() {
        try {
          await run();
        } catch (error) {
          fail(res, error);
        }
        // A write applied before its session ended (committed() recorded it, then its check
        // threw and fail() answered 401): the key keeps the applied outcome, not the 401, so
        // the retry signed in again replays it instead of applying the write twice (A62).
        return res.orbitCommitted ?? res.orbitResponse ?? null;
      },
    });
    // run() checked just before it resolved, but resuming here is a later microtask, and a
    // password change can land in between. A stored answer or a conflict reveals what an earlier
    // request did, so check once more before sending either. A request this call executed is
    // not re-checked: its effects already happened (a password change would refuse itself).
    if (result.outcome === 'conflict' || result.outcome === 'replayed') assertCurrent(access);
    if (result.outcome === 'conflict') json(res, 422, { error: CONFLICT_MESSAGE });
    else if (result.outcome === 'replayed') replay(res, result.response);
  };
}
