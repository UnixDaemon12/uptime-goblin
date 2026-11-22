// Configuration writes, one at a time (roadmap §2.4 step 16), each with its audit attempt row.

/** A configuration write that could not start in time: nothing was applied, so retry later. */
export class BusyError extends Error {}

/**
 * Configuration writes run one at a time. Several await history work (pruning, clearing a
 * source's rows), and another save interleaving there would make the If-Match check and the
 * before/after comparisons stale, silently overwriting that save.
 *
 * A queued write re-checks its credential when it starts (`assertCurrent(access)`): a password
 * change completed while it waited must stop it, as it stops any other request made with the
 * old password.
 *
 * The queue is bounded: at most `limit` writes wait, each for at most `startMs`. Beyond that,
 * or when the browser gave up before its turn (`abandoned()`), the write is skipped and nothing
 * is applied, so the browser can safely try again (BusyError, answered 503 busy).
 *
 * `admit()` runs when a write's turn comes, after the credential check and before the task: it
 * throws to refuse the write with nothing applied (the storage guard's StorageFullError while
 * the disk is full, delivery spec D14). It is checked at the turn, not when the write is
 * queued, because the disk can fill (or be freed) while the write waits. `onError(error)` sees
 * every error the task itself throws (a full disk refusing config.json, for example, so the
 * storage guard learns of it at once); the error is then rethrown unchanged.
 *
 * The audit (audit spec §5.4): `exclusive({access, abandoned, audit}, task, {action, target,
 * detail})` takes the request's recorder (`ctx.audit`) and the change it is. At the write's
 * turn, once admitted, it writes the attempt row (`audit.begin`, with the configuration's
 * revision): a write the full disk refuses writes none, and one whose attempt cannot be written
 * rejects AuditError with nothing applied (fail closed, D6). Then it checks again that the
 * browser is still there (one that left during the attempt's write ends `failed` with
 * client_closed, nothing applied: MEC-6) and that the credential still holds (a sign-out during
 * the write ends the change `denied` at settle). The task gets the Change to note what only it
 * knows (a new source's id, a history already deleted); in any case the change is noted with
 * the configuration before and after (`snapshot()`, the audit's configSnapshot of
 * config.value: its revision, public values and secret HMACs) and whether that applied anything,
 * still inside the turn, so the next queued write cannot be mixed into this one's diff. The
 * result row is written by the pipeline's settle(), with the answer's status.
 */
export function createExclusive({
  limit = 16,
  startMs = 20000,
  assertCurrent = () => {},
  admit = () => {},
  onError = () => {},
  snapshot = () => ({ revision: null }),
} = {}) {
  let writes = Promise.resolve(),
    waiting = 0;
  // A reporter that fails must not replace the task's own error with its own.
  const report = error => {
    try {
      onError(error);
    } catch {}
  };
  return function exclusive({ access, abandoned = () => false, audit }, task, recorded = {}) {
    // A configuration write always records (fail closed): one without the request's recorder is
    // a defect, refused before it is queued.
    if (!audit || typeof audit.begin !== 'function')
      return Promise.reject(new TypeError('exclusive() needs the request audit recorder'));
    if (waiting >= limit)
      return Promise.reject(
        new BusyError('Uptime Goblin is busy saving other changes. Nothing was changed; try again.')
      );
    waiting++;
    let expired = false,
      timer;
    const run = writes.then(async () => {
      clearTimeout(timer);
      if (expired) return;
      waiting--;
      if (abandoned()) return;
      assertCurrent(access);
      admit();
      const change = await audit.begin({
        action: recorded.action,
        target: recorded.target ?? null,
        detail: recorded.detail ?? null,
        configRevision: snapshot()?.revision ?? null,
      });
      // The attempt's write took time: nothing is applied behind a browser that left meanwhile,
      // nor for a session that ended.
      if (abandoned()) {
        change.note({ outcome: 'failed', detail: { code: 'client_closed' } });
        return;
      }
      assertCurrent(access);
      // Taken now, right before the task (audit spec §5.4 step 4): the change noted is the
      // task's own, whatever happened to the configuration while the attempt was written.
      const before = snapshot();
      try {
        return await task(change);
      } catch (error) {
        report(error);
        throw error;
      } finally {
        // A snapshot that cannot be taken must not replace the task's own outcome: the result
        // row then goes by the answer alone.
        let after = null;
        try {
          after = snapshot();
        } catch {}
        if (after)
          change.note({
            applied: after.revision !== before?.revision,
            configRevision: after.revision ?? null,
            before,
            after,
          });
      }
    });
    writes = run.catch(() => {});
    const deadline = new Promise((_, reject) => {
      timer = setTimeout(() => {
        expired = true;
        waiting--;
        reject(
          new BusyError(
            'Uptime Goblin was busy and could not start this change. Nothing was changed.'
          )
        );
      }, startMs);
      timer.unref?.();
    });
    return Promise.race([run, deadline]);
  };
}
