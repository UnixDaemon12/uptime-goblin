// Background jobs (roadmap §2.3, IR-17). One runner owns every periodic and leader-only task in
// the process, so pruning, relay, reconcile and delivery cannot starve request handling:
//
// - Work runs in slices of `budgetMs` (50 ms by default). A job checks `ctx.shouldYield()` inside
//   its synchronous loop (a SQLite transaction must finish synchronously), commits, then awaits
//   `ctx.yieldNow()` before the next chunk.
// - A global duty-cycle cap (25 % of wall time by default) is a token bucket shared by every job:
//   time spent in slices is charged to it, and a job waits before its next slice (or run) while
//   the bucket is empty. A job may also declare its own, lower `duty`.
// - Time a job spends awaiting I/O is not CPU time: wrap such awaits in `ctx.wait(promise)` (or
//   use `ctx.sleep(ms)`). Any other await counts as busy time, which throttles more, never less.
// - Leader-only work runs only while `leader.isLeader`. In SQLite mode the process that holds
//   `goblin.lock` is always the leader (createLocalLeader); from 1.9 a lease decides. `ctx.signal`
//   aborts on demotion or stop, and `ctx.fence(tx)` throws FencedError once this run's epoch is
//   no longer current, so a demoted leader's writes fail. A job writes its checkpoint in the same
//   database and transaction as its output.
//
// Nothing here touches a database: `statusSink` receives each job's status after a run, and the
// server points it at the control database's `jobs` table. With `statusMinIntervalMs` it receives
// a job's status only when the outcome changed or that interval passed, so a job that runs every
// 10 s (the notification relay) writes a row every 5 minutes, not 8,640 times a day.

/** Monotonic `now()` for scheduling and slices, `wall()` for reported times, unref'd timers. */
export const systemClock = Object.freeze({
  now: () => performance.now(),
  wall: () => Date.now(),
  setTimeout(fn, ms) {
    const handle = setTimeout(fn, Math.max(0, ms));
    handle.unref?.();
    return handle;
  },
  clearTimeout: handle => clearTimeout(handle),
});

/** A write attempted by a run whose leadership (epoch) has ended. dialect.classify: 'fenced'. */
export class FencedError extends Error {
  constructor(message = 'This process is no longer the leader, so the write was refused.') {
    super(message);
    this.name = 'FencedError';
    this.code = 'GOBLIN_FENCED';
    this.class = 'fenced';
  }
}

const stoppedReason = () =>
  Object.assign(new Error('Background jobs are stopping.'), {
    name: 'AbortError',
    code: 'ABORT_ERR',
  });

// Error text for logs and status: one line, bounded, and without URLs (which can carry secrets).
export function safeErrorText(error) {
  const text = String(error?.message ?? error ?? 'error');
  return (
    text
      .replace(/[\p{Cc}\p{Zl}\p{Zp}]/gu, ' ')
      .replace(/\b[a-z][a-z0-9+.-]*:\/\/\S+/gi, '[url]')
      .trim()
      .slice(0, 300)
      .toWellFormed() || 'error'
  );
}

/**
 * Leadership for a single process (SQLite mode): always the leader while `goblin.lock` is held.
 * `demote()` and `promote()` exist for shutdown and tests; promotion starts a new epoch, so a
 * run from the previous epoch can no longer pass `fence()`.
 */
export function createLocalLeader({ epoch = 1 } = {}) {
  let leading = true,
    current = epoch,
    controller = new AbortController();
  const listeners = new Set();
  const notify = () => {
    const state = { isLeader: leading, epoch: current };
    for (const listener of [...listeners])
      try {
        listener(state);
      } catch {}
  };
  return {
    mode: 'single-process',
    get isLeader() {
      return leading;
    },
    get epoch() {
      return current;
    },
    get signal() {
      return controller.signal;
    },
    onChange(listener) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    demote() {
      if (!leading) return;
      leading = false;
      controller.abort(new FencedError('This process stopped being the leader.'));
      notify();
    },
    promote() {
      if (leading) return;
      leading = true;
      current++;
      controller = new AbortController();
      notify();
    },
  };
}

function positive(value, name) {
  if (!Number.isFinite(value) || value <= 0) throw new TypeError(`${name} must be above 0`);
  return value;
}

/**
 * createJobRunner({clock, logger, leader, dutyCap, sliceMs, burstMs, statusSink,
 * statusMinIntervalMs}) returns {every, leaderTask, runNow, cancel, cancelAndWait, status, stop}.
 *
 * - every(name, intervalMs, fn, {duty, budgetMs, leader, initialDelayMs}): runs fn(ctx) again
 *   `intervalMs` after each run finishes (runs never overlap). `leader: true` skips it while
 *   this process is not the leader.
 * - leaderTask(name, fn, {restartMs, maxRestartMs}): a continuous task (such as the delivery
 *   worker) that runs while this process leads. It is aborted on demotion and started again on
 *   promotion; if it returns it restarts after `restartMs`, and after a failure with a backoff
 *   doubling up to `maxRestartMs`.
 * - leaderTask(name, {intervalMs, budgetMs, duty, initialDelayMs}, fn): the periodic leader-only
 *   form of §2.3, the same as every(name, intervalMs, fn, {leader: true, ...}).
 *
 * fn receives ctx = {name, signal, epoch, shouldYield(), yieldNow(), wait(promise), sleep(ms),
 * fence(tx)}.
 */
export function createJobRunner({
  clock = systemClock,
  logger = console,
  leader = createLocalLeader(),
  dutyCap = 0.25,
  sliceMs = 50,
  burstMs = 250,
  statusSink = null,
  // 0: every finished run is reported. Above 0: a run is reported when its outcome differs from
  // the last one given to the sink (recorded or not), or when this much monotonic time passed
  // since then.
  statusMinIntervalMs = 0,
} = {}) {
  positive(dutyCap, 'dutyCap');
  if (!Number.isFinite(statusMinIntervalMs) || statusMinIntervalMs < 0)
    throw new TypeError('statusMinIntervalMs must be 0 or more');
  if (dutyCap > 1) throw new TypeError('dutyCap must be at most 1');
  positive(sliceMs, 'sliceMs');
  positive(burstMs, 'burstMs');
  const jobs = new Map();
  let stopped = false;

  // Token buckets in milliseconds of slice time: they refill at `rate` ms per ms of wall time.
  const bucket = (rate, burst) => ({ rate, burst, tokens: burst, at: clock.now() });
  const refill = b => {
    const now = clock.now();
    b.tokens = Math.min(b.burst, b.tokens + (now - b.at) * b.rate);
    b.at = now;
  };
  const shortfall = b => {
    refill(b);
    return b.tokens >= 0 ? 0 : Math.ceil(-b.tokens / b.rate);
  };
  const shared = bucket(dutyCap, burstMs);

  function sleep(ms, signal) {
    return new Promise((resolve, reject) => {
      if (signal?.aborted) return reject(signal.reason);
      const abort = () => {
        clock.clearTimeout(timer);
        reject(signal.reason);
      };
      const timer = clock.setTimeout(() => {
        signal?.removeEventListener('abort', abort);
        resolve();
      }, ms);
      signal?.addEventListener('abort', abort, { once: true });
    });
  }

  // Waits until both the shared bucket and the job's own bucket allow another slice. Always
  // yields at least one timer turn, so a chunked job lets I/O and requests in between.
  async function admit(job, signal) {
    for (;;) {
      const wait = Math.max(shortfall(shared), job.duty ? shortfall(job.duty) : 0);
      await sleep(wait, signal);
      if (!shortfall(shared) && !(job.duty && shortfall(job.duty))) return;
    }
  }

  function openSlice(run) {
    run.sliceStart = clock.now();
  }
  function closeSlice(job, run) {
    if (run.sliceStart === null) return;
    const spent = Math.max(0, clock.now() - run.sliceStart);
    run.sliceStart = null;
    run.busy += spent;
    run.maxSlice = Math.max(run.maxSlice, spent);
    refill(shared);
    shared.tokens -= spent;
    if (job.duty) {
      refill(job.duty);
      job.duty.tokens -= spent;
    }
    if (spent > job.budgetMs * 4 && !run.warned) {
      run.warned = true;
      job.status.longSlices++;
      logger.warn?.(
        `Background job ${job.name} ran ${Math.round(spent)} ms without yielding (budget ${job.budgetMs} ms).`
      );
    }
  }

  function snapshot(job) {
    const s = job.status;
    return {
      name: job.name,
      kind: job.kind,
      leaderOnly: job.leaderOnly,
      intervalMs: job.intervalMs ?? null,
      running: Boolean(job.run),
      runs: s.runs,
      failures: s.failures,
      skipped: s.skipped,
      longSlices: s.longSlices,
      lastStarted: s.lastStarted,
      lastFinished: s.lastFinished,
      lastOk: s.lastOk,
      lastOutcome: s.lastOutcome,
      lastError: s.lastError && { ...s.lastError },
      durationMs: s.durationMs,
      busyMs: s.busyMs,
      maxSliceMs: s.maxSliceMs,
      nextAt: job.timer ? clock.wall() + Math.max(0, job.nextAt - clock.now()) : null,
    };
  }

  function report(job) {
    if (!statusSink) return;
    const value = snapshot(job);
    if (statusMinIntervalMs > 0) {
      const last = job.reported,
        now = clock.now();
      if (last && last.outcome === value.lastOutcome && now - last.at < statusMinIntervalMs) return;
      job.reported = { outcome: value.lastOutcome, at: now };
    }
    // A report the sink could not record keeps its mark: the next attempt comes, like the next
    // report, once the outcome changes or the interval has passed. Tried again at every run, a
    // control database that refuses writes (a full disk) met one write and one log line every
    // 10 s from the relay alone, 8,640 a day.
    Promise.resolve()
      .then(() => statusSink(value))
      .catch(error =>
        logger.error?.(`Could not record the status of job ${job.name}: ${safeErrorText(error)}`)
      );
  }

  function execute(job) {
    const controller = new AbortController(),
      epoch = leader.epoch,
      run = { sliceStart: null, busy: 0, maxSlice: 0, warned: false, controller };
    // A leader-only run ends with the leadership it started under.
    const leaderSignal = job.leaderOnly ? leader.signal : null,
      onDemote = () => controller.abort(leaderSignal.reason);
    if (leaderSignal?.aborted) controller.abort(leaderSignal.reason);
    else leaderSignal?.addEventListener('abort', onDemote, { once: true });
    const ctx = {
      name: job.name,
      signal: controller.signal,
      epoch,
      shouldYield: () => run.sliceStart !== null && clock.now() - run.sliceStart >= job.budgetMs,
      async yieldNow() {
        closeSlice(job, run);
        await admit(job, controller.signal);
        openSlice(run);
      },
      async wait(promise) {
        closeSlice(job, run);
        try {
          return await promise;
        } finally {
          openSlice(run);
        }
      },
      sleep: ms => ctx.wait(sleep(ms, controller.signal)),
      // SQLite mode: goblin.lock is the fence, so this checks leadership in memory. On a server
      // database (1.9) the lease row is read FOR SHARE inside `tx` as well.
      fence() {
        if (controller.signal.aborted) throw new FencedError();
        if (job.leaderOnly && (!leader.isLeader || leader.epoch !== epoch)) throw new FencedError();
      },
    };
    const status = job.status;
    const promise = (async () => {
      try {
        await admit(job, controller.signal);
      } catch {
        return; // stopped or demoted before it started: not a run
      }
      const started = clock.now();
      status.runs++;
      status.lastStarted = clock.wall();
      openSlice(run);
      try {
        await job.fn(ctx);
        closeSlice(job, run);
        status.lastOk = clock.wall();
        status.lastOutcome = 'ok';
      } catch (error) {
        closeSlice(job, run);
        // Aborted by stop(), cancel() or demotion: the job gave up as asked, not a failure.
        if (controller.signal.aborted) status.lastOutcome = 'aborted';
        else {
          status.failures++;
          status.lastOutcome = 'failed';
          status.lastError = { time: clock.wall(), message: safeErrorText(error) };
          logger.error?.(`Background job ${job.name} failed: ${status.lastError.message}`);
          throw error;
        }
      } finally {
        leaderSignal?.removeEventListener('abort', onDemote);
        status.lastFinished = clock.wall();
        status.durationMs = Math.round(clock.now() - started);
        status.busyMs = Math.round(run.busy);
        status.maxSliceMs = Math.round(run.maxSlice);
      }
    })();
    const settled = promise.then(
      () => true,
      () => false
    );
    job.run = { promise: settled, controller };
    void settled.then(() => {
      if (job.run?.controller === controller) job.run = null;
      report(job);
    });
    return settled;
  }

  function schedule(job, delayMs) {
    if (stopped || jobs.get(job.name) !== job) return;
    if (job.timer) clock.clearTimeout(job.timer);
    job.nextAt = clock.now() + delayMs;
    job.timer = clock.setTimeout(() => {
      job.timer = null;
      void fire(job);
    }, delayMs);
  }

  async function fire(job) {
    if (stopped || job.run) return;
    if (job.kind === 'continuous') return startContinuous(job);
    if (job.leaderOnly && !leader.isLeader) {
      job.status.skipped++;
      schedule(job, job.intervalMs);
      return;
    }
    await execute(job);
    // An earlier runNow() may have scheduled it already.
    if (!job.timer) schedule(job, job.intervalMs);
  }

  function startContinuous(job) {
    if (stopped || job.run || !leader.isLeader) return;
    if (job.timer) {
      clock.clearTimeout(job.timer);
      job.timer = null;
    }
    void execute(job).then(ok => {
      if (stopped || job.run || !leader.isLeader) return;
      if (ok) job.restartDelay = job.restartMs;
      const delay = job.restartDelay;
      if (!ok) job.restartDelay = Math.min(job.maxRestartMs, job.restartDelay * 2);
      schedule(job, delay);
    });
  }

  const unsubscribe = leader.onChange(state => {
    if (stopped || !state.isLeader) return; // demotion aborts runs through leader.signal
    for (const job of jobs.values()) if (job.kind === 'continuous') startContinuous(job);
  });

  function register(name, fields) {
    if (stopped) throw new Error('The job runner is stopped.');
    if (typeof name !== 'string' || !/^[a-z][a-z0-9._:-]{0,63}$/.test(name))
      throw new TypeError(`Invalid job name ${JSON.stringify(name)}`);
    if (jobs.has(name)) throw new Error(`Job ${name} is already registered.`);
    if (typeof fields.fn !== 'function') throw new TypeError(`Job ${name} needs a function`);
    const job = {
      name,
      timer: null,
      nextAt: null,
      run: null,
      reported: null, // {outcome, at}: the last status given to statusSink (statusMinIntervalMs)
      ...fields,
      status: {
        runs: 0,
        failures: 0,
        skipped: 0,
        longSlices: 0,
        lastStarted: null,
        lastFinished: null,
        lastOk: null,
        lastOutcome: null,
        lastError: null,
        durationMs: null,
        busyMs: null,
        maxSliceMs: null,
      },
    };
    jobs.set(name, job);
    return job;
  }

  function every(name, intervalMs, fn, options = {}) {
    positive(intervalMs, 'intervalMs');
    const { duty, budgetMs = sliceMs, leader: leaderOnly = false } = options;
    const initialDelayMs = options.initialDelayMs ?? intervalMs;
    if (duty !== undefined) positive(duty, 'duty');
    if (duty > 1) throw new TypeError('duty must be at most 1');
    if (!Number.isFinite(initialDelayMs) || initialDelayMs < 0)
      throw new TypeError('initialDelayMs must be 0 or more');
    const job = register(name, {
      kind: 'periodic',
      leaderOnly: Boolean(leaderOnly),
      intervalMs,
      fn,
      budgetMs: positive(budgetMs, 'budgetMs'),
      duty: duty === undefined ? null : bucket(duty, Math.min(burstMs, duty * 1000)),
    });
    schedule(job, initialDelayMs);
    return () => cancel(name);
  }

  function leaderTask(name, second, third) {
    if (typeof second === 'object' && second !== null && typeof third === 'function') {
      const { intervalMs, ...rest } = second;
      return every(name, intervalMs, third, { ...rest, leader: true });
    }
    const fn = second,
      { restartMs = 1000, maxRestartMs = 60000, budgetMs = sliceMs } = third ?? {};
    const job = register(name, {
      kind: 'continuous',
      leaderOnly: true,
      fn,
      budgetMs: positive(budgetMs, 'budgetMs'),
      duty: null,
      restartMs: positive(restartMs, 'restartMs'),
      maxRestartMs: positive(maxRestartMs, 'maxRestartMs'),
      restartDelay: restartMs,
    });
    startContinuous(job);
    return () => cancel(name);
  }

  // Removes a job; a run in progress is aborted.
  function cancel(name) {
    const job = jobs.get(name);
    if (!job) return false;
    jobs.delete(name);
    if (job.timer) clock.clearTimeout(job.timer);
    job.timer = null;
    job.run?.controller.abort(stoppedReason());
    return true;
  }

  /**
   * Removes a job like cancel() (aborting a run in progress) and waits up to `timeoutMs` for that
   * run to finish, so a caller can release what the run uses (the outbox at shutdown) knowing no
   * pass of it is still going. Resolves {cancelled, settled}: settled is false only when a run
   * was in progress and did not finish in time.
   */
  async function cancelAndWait(name, { timeoutMs = 2000 } = {}) {
    const run = jobs.get(name)?.run ?? null;
    const cancelled = cancel(name);
    if (!run) return { cancelled, settled: true };
    if (!Number.isFinite(timeoutMs)) {
      await run.promise;
      return { cancelled, settled: true };
    }
    let timer;
    const settled = await Promise.race([
      run.promise.then(() => true),
      new Promise(resolve => (timer = clock.setTimeout(() => resolve(false), timeoutMs))),
    ]);
    clock.clearTimeout(timer);
    return { cancelled, settled };
  }

  /** Runs a periodic job now (or joins the run in progress) and resolves with its status. */
  async function runNow(name) {
    const job = jobs.get(name);
    if (!job) throw new Error(`No job named ${name}`);
    if (stopped) throw new Error('The job runner is stopped.');
    if (job.kind === 'continuous') throw new Error(`${name} runs continuously`);
    if (job.run) await job.run.promise;
    else if (job.leaderOnly && !leader.isLeader) job.status.skipped++;
    else {
      if (job.timer) clock.clearTimeout(job.timer);
      job.timer = null;
      await execute(job);
      if (!job.timer && jobs.get(name) === job) schedule(job, job.intervalMs);
    }
    return snapshot(job);
  }

  /** Stops scheduling, aborts every run and waits up to `timeoutMs` for them to finish. */
  async function stop({ timeoutMs = 8000 } = {}) {
    if (!stopped) {
      stopped = true;
      unsubscribe();
      for (const job of jobs.values()) {
        if (job.timer) clock.clearTimeout(job.timer);
        job.timer = null;
        job.run?.controller.abort(stoppedReason());
      }
    }
    const running = [...jobs.values()].filter(job => job.run);
    let timer;
    const timedOut = await Promise.race([
      Promise.all(running.map(job => job.run?.promise)).then(() => false),
      new Promise(resolve => (timer = clock.setTimeout(() => resolve(true), timeoutMs))),
    ]);
    clock.clearTimeout(timer);
    return { timedOut: timedOut ? running.filter(job => job.run).map(job => job.name) : [] };
  }

  return {
    every,
    leaderTask,
    runNow,
    cancel,
    cancelAndWait,
    stop,
    status: () => [...jobs.values()].map(snapshot),
    get stopped() {
      return stopped;
    },
    get leader() {
      return leader;
    },
  };
}
