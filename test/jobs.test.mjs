import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createJobRunner,
  createLocalLeader,
  FencedError,
  safeErrorText,
  systemClock,
} from '../lib/jobs.mjs';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { openControl } from '../lib/db/control.mjs';
import { fakeClock, quietLogger, settle } from './alerting/fake-clock.mjs';

function runner(t, options = {}) {
  const clock = options.clock ?? fakeClock(),
    logger = options.logger ?? quietLogger();
  const jobs = createJobRunner({ clock, logger, ...options });
  t.after(() => jobs.stop({ timeoutMs: 0 }));
  return { jobs, clock, logger };
}

test('every() runs a job an interval after the previous run finished, never overlapping', async t => {
  const { jobs, clock } = runner(t);
  const starts = [];
  let release;
  jobs.every('sample.work', 1000, async ctx => {
    starts.push(clock.now());
    if (starts.length === 2) await ctx.wait(new Promise(resolve => (release = resolve)));
  });
  await clock.advance(999);
  assert.deepEqual(starts, []);
  await clock.advance(1);
  assert.deepEqual(starts, [2000]);
  await clock.advance(1000);
  assert.deepEqual(starts, [2000, 3000]);
  // The second run is still going: nothing starts while it runs, however long it takes.
  await clock.advance(5000);
  assert.equal(starts.length, 2);
  assert.equal(jobs.status()[0].running, true);
  release();
  await clock.advance(0);
  const finishedAt = clock.now();
  await clock.advance(1000);
  assert.deepEqual(starts.at(-1), finishedAt + 1000);
  const [status] = jobs.status();
  assert.equal(status.runs, 3);
  assert.equal(status.failures, 0);
  assert.equal(status.lastOutcome, 'ok');
  assert.equal(status.kind, 'periodic');
  assert.equal(typeof status.lastOk, 'number');
  assert.ok(status.nextAt > clock.wall());
});

test('a failing job is counted and logged without URLs, and keeps its schedule', async t => {
  const { jobs, clock, logger } = runner(t);
  let calls = 0;
  jobs.every('sample.fails', 100, () => {
    calls++;
    throw new Error('POST https://hooks.example.com/services/T0/B0/secret failed\nwith detail');
  });
  await clock.advance(350);
  assert.equal(calls, 3);
  const [status] = jobs.status();
  assert.equal(status.failures, 3);
  assert.equal(status.lastOutcome, 'failed');
  assert.equal(status.lastError.message, 'POST [url] failed with detail');
  assert.equal(logger.lines.error.length, 3);
  assert.ok(logger.lines.error.every(line => !line.includes('secret')));
  assert.equal(safeErrorText({ message: 'x'.repeat(400) }).length, 300);
  assert.equal(safeErrorText(null), 'error');
});

test('the duty cycle keeps chunked jobs to a quarter of wall time, shared by every job', async t => {
  const { jobs, clock } = runner(t, { dutyCap: 0.25, burstMs: 250 });
  const done = {};
  for (const name of ['sample.a', 'sample.b'])
    jobs.every(
      name,
      60000,
      async ctx => {
        for (let chunk = 0; chunk < 40; chunk++) {
          clock.burn(50); // 50 ms of synchronous work per chunk
          assert.equal(ctx.shouldYield(), true);
          await ctx.yieldNow();
        }
        done[name] = clock.now();
      },
      { initialDelayMs: 0 }
    );
  await clock.advance(60000);
  // 2 × 40 × 50 ms = 4,000 ms of work; at 25 % that needs at least (4,000 − burst) / 0.25.
  const elapsed = Math.max(done['sample.a'], done['sample.b']) - 1000;
  assert.ok(elapsed >= (4000 - 250) / 0.25, `finished after ${elapsed} ms`);
  assert.ok(elapsed <= 4000 / 0.25 + 1000, `finished after ${elapsed} ms`);
  for (const status of jobs.status()) {
    assert.equal(status.busyMs, 2000);
    assert.equal(status.maxSliceMs, 50);
  }
});

test('a job can declare a lower duty of its own', async t => {
  const { jobs, clock } = runner(t, { dutyCap: 0.5 });
  let finished = null;
  jobs.every(
    'sample.gentle',
    60000,
    async ctx => {
      for (let chunk = 0; chunk < 10; chunk++) {
        clock.burn(50);
        await ctx.yieldNow();
      }
      finished = clock.now();
    },
    { duty: 0.1, initialDelayMs: 0 }
  );
  await clock.advance(30000);
  // 500 ms of work at 10 % (the job's burst is 100 ms): at least 4 s.
  assert.ok(finished - 1000 >= (500 - 100) / 0.1, `finished after ${finished - 1000} ms`);
});

test('time awaited through ctx.wait() and ctx.sleep() is not charged as busy time', async t => {
  const { jobs, clock } = runner(t);
  jobs.every(
    'sample.io',
    60000,
    async ctx => {
      clock.burn(10);
      assert.equal(ctx.shouldYield(), false);
      await ctx.wait(new Promise(resolve => clock.setTimeout(resolve, 5000)));
      await ctx.sleep(5000);
      clock.burn(20);
    },
    { initialDelayMs: 0 }
  );
  await clock.advance(20000);
  const [status] = jobs.status();
  assert.equal(status.lastOutcome, 'ok');
  assert.equal(status.busyMs, 30);
  assert.ok(status.durationMs >= 10030);
});

test('a slice far over its budget is reported once per run', async t => {
  const { jobs, clock, logger } = runner(t);
  jobs.every('sample.hog', 60000, () => clock.burn(400), { initialDelayMs: 0 });
  await clock.advance(1);
  assert.equal(jobs.status()[0].longSlices, 1);
  assert.match(logger.lines.warn[0], /sample\.hog ran 400 ms without yielding \(budget 50 ms\)/);
});

test('leader-only jobs run only while leading; demotion aborts them and fences their writes', async t => {
  const leader = createLocalLeader();
  const { jobs, clock } = runner(t, { leader });
  let periodic = 0;
  jobs.leaderTask('sample.periodic', { intervalMs: 1000 }, () => periodic++);
  const runs = [];
  jobs.leaderTask('sample.worker', async ctx => {
    const run = { epoch: ctx.epoch, ctx, aborted: false };
    runs.push(run);
    ctx.fence();
    try {
      await ctx.sleep(1e9);
    } catch (error) {
      run.aborted = true;
      throw error;
    }
  });
  await clock.advance(1000);
  assert.equal(periodic, 1);
  assert.equal(runs.length, 1);
  assert.equal(runs[0].epoch, 1);

  leader.demote();
  await clock.advance(0);
  assert.equal(runs[0].aborted, true);
  assert.equal(runs[0].ctx.signal.aborted, true);
  assert.throws(() => runs[0].ctx.fence(), FencedError);
  assert.equal(new FencedError().class, 'fenced');
  await clock.advance(3000);
  assert.equal(periodic, 1, 'skipped while not leading');
  const byName = Object.fromEntries(jobs.status().map(s => [s.name, s]));
  assert.equal(byName['sample.periodic'].skipped, 3);
  assert.equal(byName['sample.worker'].lastOutcome, 'aborted');
  assert.equal(byName['sample.worker'].failures, 0);
  assert.equal(runs.length, 1, 'the worker does not restart while demoted');

  leader.promote();
  await clock.advance(1000);
  assert.equal(periodic, 2);
  assert.equal(runs.length, 2);
  assert.equal(runs[1].epoch, 2);
  // A run from the old epoch stays fenced even though this process leads again.
  assert.throws(() => runs[0].ctx.fence(), FencedError);
  assert.doesNotThrow(() => runs[1].ctx.fence());
});

test('fence() refuses a run whose epoch is no longer current, even before any abort', async t => {
  // A lease-based leader (1.9) can move to a new epoch before its signal reaches the run.
  const leader = {
    isLeader: true,
    epoch: 7,
    signal: new AbortController().signal,
    onChange: () => () => {},
  };
  const { jobs, clock } = runner(t, { leader });
  let context;
  jobs.leaderTask('sample.lease', async ctx => {
    context = ctx;
    await ctx.sleep(1e9);
  });
  await clock.advance(0);
  assert.equal(context.epoch, 7);
  assert.doesNotThrow(() => context.fence());
  leader.epoch = 8;
  assert.throws(() => context.fence(), FencedError);
  leader.epoch = 7;
  leader.isLeader = false;
  assert.throws(() => context.fence(), FencedError);
});

test('a continuous leader task restarts after returning, with a backoff after failures', async t => {
  const { jobs, clock } = runner(t);
  const starts = [];
  let failures = 3;
  jobs.leaderTask(
    'sample.continuous',
    () => {
      starts.push(clock.now());
      if (failures-- > 0) throw new Error('not yet');
    },
    { restartMs: 1000, maxRestartMs: 4000 }
  );
  await clock.advance(20000);
  const gaps = starts.slice(1).map((at, i) => at - starts[i]);
  // Failures back off 1 s, 2 s, 4 s; after a clean return it restarts every restartMs.
  assert.deepEqual(gaps.slice(0, 5), [1000, 2000, 4000, 1000, 1000]);
  const [status] = jobs.status();
  assert.equal(status.kind, 'continuous');
  assert.equal(status.failures, 3);
});

test('runNow() runs a job at once, or joins the run in progress', async t => {
  const { jobs, clock } = runner(t);
  let calls = 0,
    release;
  jobs.every('sample.now', 60000, async ctx => {
    calls++;
    await ctx.wait(new Promise(resolve => (release = resolve)));
  });
  const first = jobs.runNow('sample.now');
  const second = jobs.runNow('sample.now');
  await clock.advance(0);
  assert.equal(calls, 1);
  release();
  const [a, b] = await Promise.all([first, second]);
  assert.equal(calls, 1);
  assert.equal(a.runs, 1);
  assert.equal(b.runs, 1);
  // The next scheduled run counts from the end of this one.
  assert.ok(a.nextAt >= clock.wall() + 59000);
  await assert.rejects(jobs.runNow('sample.missing'), /No job named/);
});

test('stop() aborts every run, clears timers and reports a job that ignores the abort', async t => {
  const clock = fakeClock();
  const jobs = createJobRunner({ clock, logger: quietLogger() });
  let aborted = false;
  jobs.every(
    'sample.cooperative',
    1000,
    async ctx => {
      await ctx.sleep(1e9).catch(error => {
        aborted = true;
        throw error;
      });
    },
    { initialDelayMs: 0 }
  );
  jobs.every(
    'sample.stubborn',
    1000,
    async ctx => {
      await ctx.wait(new Promise(() => {}));
    },
    { initialDelayMs: 0 }
  );
  jobs.every('sample.idle', 1000, () => {});
  await clock.advance(1);
  const stopping = jobs.stop({ timeoutMs: 8000 });
  await clock.advance(8000);
  const result = await stopping;
  assert.equal(aborted, true);
  assert.deepEqual(result.timedOut, ['sample.stubborn']);
  assert.equal(clock.pending, 0);
  assert.equal(jobs.stopped, true);
  assert.throws(() => jobs.every('sample.late', 1000, () => {}), /stopped/);
  await assert.rejects(jobs.runNow('sample.idle'), /stopped/);
  const byName = Object.fromEntries(jobs.status().map(s => [s.name, s]));
  assert.equal(byName['sample.cooperative'].lastOutcome, 'aborted');
  assert.equal(byName['sample.cooperative'].failures, 0);
});

test('each finished run is passed to the status sink; a failing sink is only logged', async t => {
  const seen = [];
  let fail = false;
  const { jobs, clock, logger } = runner(t, {
    statusSink: status => {
      if (fail) throw new Error('disk full');
      seen.push(status);
    },
  });
  jobs.every('sample.sink', 1000, () => {});
  await clock.advance(1000);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].name, 'sample.sink');
  assert.equal(seen[0].runs, 1);
  fail = true;
  await clock.advance(1000);
  await settle();
  assert.match(
    logger.lines.error.at(-1),
    /Could not record the status of job sample\.sink: disk full/
  );
  assert.equal(jobs.status()[0].runs, 2);
});

test('statusMinIntervalMs reports a repeated outcome at most once per interval', async t => {
  const seen = [];
  let fail = false,
    sinkFails = false,
    attempts = 0;
  const { jobs, clock, logger } = runner(t, {
    statusMinIntervalMs: 300000,
    statusSink: status => {
      attempts++;
      if (sinkFails) throw new Error('disk full');
      seen.push([status.name, status.lastOutcome, status.runs]);
    },
  });
  jobs.every('notify.relay', 10000, () => {
    if (fail) throw new Error('database is locked');
  });
  // The first run is reported; the same outcome within 5 minutes is not.
  await clock.advance(10000);
  assert.deepEqual(seen, [['notify.relay', 'ok', 1]]);
  await clock.advance(10000 * 28);
  assert.equal(seen.length, 1);
  // A changed outcome is reported at once, and so is the change back.
  fail = true;
  await clock.advance(10000);
  assert.deepEqual(seen.at(-1), ['notify.relay', 'failed', 30]);
  fail = false;
  await clock.advance(10000);
  assert.deepEqual(seen.at(-1), ['notify.relay', 'ok', 31]);
  // The same outcome again once 5 minutes passed since the last report.
  await clock.advance(10000 * 29);
  assert.equal(seen.length, 3);
  await clock.advance(10000);
  assert.deepEqual(seen.at(-1), ['notify.relay', 'ok', 61]);
  // A sink that keeps failing (control.sqlite on a full disk) is not tried at every run: a report
  // it could not record counts like one it did, so the same outcome is tried again only once the
  // interval has passed. 10 minutes of runs every 10 s: two attempts and two log lines, not 60.
  fail = true;
  sinkFails = true;
  const attemptsBefore = attempts,
    errorsBefore = logger.lines.error.length;
  for (let i = 0; i < 60; i++) {
    await clock.advance(10000);
    await settle();
  }
  assert.equal(attempts - attemptsBefore, 2, 'one attempt per interval');
  const sinkErrors = logger.lines.error
    .slice(errorsBefore)
    .filter(line => /Could not record the status of job notify\.relay/.test(line));
  assert.equal(sinkErrors.length, 2, 'one log line per attempt');
  // A changed outcome is still tried at once, and once the sink works the status is recorded.
  sinkFails = false;
  fail = false;
  await clock.advance(10000);
  assert.deepEqual(seen.at(-1), ['notify.relay', 'ok', 122]);
  // Without the option every run is reported (unchanged behaviour).
  const every = [];
  const plain = runner(t, { statusSink: status => every.push(status.runs) });
  plain.jobs.every('sample.plain', 1000, () => {});
  await plain.clock.advance(3000);
  assert.deepEqual(every, [1, 2, 3]);
  assert.throws(() => createJobRunner({ statusMinIntervalMs: -1 }), /statusMinIntervalMs/);
});

test('cancelAndWait() aborts a run and waits for it; it gives up after its timeout', async t => {
  const { jobs, clock } = runner(t);
  const order = [];
  // A cooperative continuous task: it ends soon after the abort, with work still to finish.
  jobs.leaderTask('notify.delivery', async ctx => {
    await ctx.sleep(1e9).catch(() => {});
    await ctx.wait(new Promise(resolve => clock.setTimeout(resolve, 500)));
    order.push('run finished');
  });
  await clock.advance(1);
  const waiting = jobs.cancelAndWait('notify.delivery', { timeoutMs: 2000 }).then(result => {
    order.push('cancelAndWait resolved');
    return result;
  });
  await clock.advance(500);
  assert.deepEqual(await waiting, { cancelled: true, settled: true });
  assert.deepEqual(order, ['run finished', 'cancelAndWait resolved']);
  // Removed: not restarted, and not listed.
  await clock.advance(60000);
  assert.deepEqual(jobs.status(), []);
  // A run that ignores the abort: settled false once the timeout passed.
  jobs.every('sample.stubborn', 1000, ctx => ctx.wait(new Promise(() => {})), {
    initialDelayMs: 0,
  });
  await clock.advance(1);
  const stubborn = jobs.cancelAndWait('sample.stubborn', { timeoutMs: 2000 });
  await clock.advance(2000);
  assert.deepEqual(await stubborn, { cancelled: true, settled: false });
  // No run in progress, or no such job.
  jobs.every('sample.idle', 1000, () => {});
  assert.deepEqual(await jobs.cancelAndWait('sample.idle'), { cancelled: true, settled: true });
  assert.deepEqual(await jobs.cancelAndWait('sample.missing'), {
    cancelled: false,
    settled: true,
  });
  // cancel() is unchanged: synchronous, a boolean.
  jobs.every('sample.sync', 1000, () => {});
  assert.equal(jobs.cancel('sample.sync'), true);
  assert.equal(jobs.cancel('sample.sync'), false);
});

test('cancel() removes a job and aborts its run', async t => {
  const { jobs, clock } = runner(t);
  let calls = 0;
  const cancel = jobs.every('sample.cancel', 100, () => calls++);
  await clock.advance(100);
  assert.equal(calls, 1);
  assert.equal(cancel(), true);
  await clock.advance(1000);
  assert.equal(calls, 1);
  assert.deepEqual(jobs.status(), []);
  assert.equal(jobs.cancel('sample.cancel'), false);
});

test('registration is validated', t => {
  const { jobs } = runner(t);
  jobs.every('sample.valid', 1000, () => {});
  assert.throws(() => jobs.every('sample.valid', 1000, () => {}), /already registered/);
  for (const name of ['', 'Upper', 'has space', 'x'.repeat(65), 42])
    assert.throws(() => jobs.every(name, 1000, () => {}), /Invalid job name/);
  assert.throws(() => jobs.every('sample.zero', 0, () => {}), /intervalMs/);
  assert.throws(() => jobs.every('sample.fn', 1000, 'nope'), /needs a function/);
  assert.throws(() => jobs.every('sample.duty', 1000, () => {}, { duty: 2 }), /duty/);
  assert.throws(() => createJobRunner({ dutyCap: 0 }), /dutyCap/);
  assert.throws(() => createJobRunner({ dutyCap: 1.5 }), /dutyCap/);
});

test('the system clock is monotonic and its timers do not keep the process alive', async () => {
  const a = systemClock.now();
  await new Promise(resolve => systemClock.setTimeout(resolve, 5));
  assert.ok(systemClock.now() >= a);
  const timer = systemClock.setTimeout(() => {}, 60000);
  assert.equal(timer.hasRef(), false);
  systemClock.clearTimeout(timer);
  assert.ok(Math.abs(systemClock.wall() - Date.now()) < 1000);
});

test('statuses reach the control database through its jobs store (contracts C-JOB and C-DB)', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-jobs-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const clock = fakeClock();
  const control = openControl(directory, { release: '1.5.0', env: {}, clock: () => clock.wall() });
  t.after(() => control.close());
  await control.migrate();
  const { jobs } = runner(t, { clock, statusSink: status => control.jobs.record(status) });
  let fail = false;
  jobs.every('outbox.prune', 1000, () => {
    if (fail) throw new Error('POST https://hooks.example.test/secret failed');
  });
  await clock.advance(1000);
  fail = true;
  await clock.advance(1000);
  await settle();
  const [row] = await control.jobs.list();
  assert.equal(row.name, 'outbox.prune');
  assert.deepEqual([row.runs, row.failures], [2, 1]);
  assert.equal(row.last_error, 'POST [url] failed');
  assert.equal(row.last_ok, clock.wall() - 1000);
  assert.equal(row.last_started, clock.wall());
  assert.equal(typeof row.duration_ms, 'number');
});
