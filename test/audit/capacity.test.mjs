// The capacity measurement (audit spec §9.3, D33): 250,000 rows, generated through the writer's
// row builder and chained under a real keyring (a realistic mix: 5 % with diffs up to 16 KiB,
// aggregated summaries, attempts with and without results, operation rows), then measured: a
// route-style verification (gating: within 60 s, no unit of 1,000 rows over 250 ms), the first
// page of every filter and of every combination the Audit log page can send, outcome=unknown, an
// export of 50,000 rows, the row count, and a prune of 25,000 rows in one maintain() run.
//
// The gate is elapsed (wall) time, as §9.3 and §11 item 12 promise: Check integrity finishes within
// 60 s, and no synchronous read unit holds the event loop for more than 250 ms. A unit is timed in
// two ways, and each must be within 250 ms (see gatedVerification). First, as verifyAudit times it
// (onUnit), the measure this test has always gated: from just before the unit's read until
// verifyAudit has its result, so it counts the read and whatever runs synchronously once the read
// resolves, before the event loop gets a turn (and, for a unit SQLite runs again after SQLITE_BUSY,
// the waits between its attempts). Second, every attempt at a read unit on its own (see
// measuredReads): the first unit (the log's ends, head and checkpoints) included, which onUnit does
// not time, and each further attempt SQLite makes at a unit after SQLITE_BUSY. This thread's CPU
// time, the CPU time of the process's other threads and, on Linux, this thread's wait for a core
// (/proc/thread-self/schedstat) are printed beside the wall times as diagnostics only. Nothing is
// subtracted from the wall time: time a unit spends blocked (a lock, a disk read, a synchronous
// wait) or waiting for a core counts. A unit that blocks for 324 ms uses about 0.2 ms of CPU
// (an independent review of the CPU-time proposal B38, 2026-10-06), so a CPU-time gate passes it; this
// gate fails it, and the three "capacity gate" tests at the end, which run in every test run, hold
// the gate to that.
//
// Wall time also measures the machine, so the normative run (§9.3, §11 item 12) is this file
// alone, in the Node 24 container with fixed limits, on a quiet machine:
//
//   docker run --memory 4g --cpus 4 --pids-limit 1024 --memory-swap 4g \
//     --rm --pull=never --network none --user node -e HOME=/tmp \
//     --tmpfs /ktmp:rw,exec,size=1g,mode=1777 -e TMPDIR=/ktmp -e TEST_REQUIRE=capacity \
//     -v "$PWD":/src:ro -w /src node:24-bookworm-slim@sha256:<recorded digest> \
//     node --test --import ./test/setup.mjs test/audit/capacity.test.mjs
//
// Quiet: no other test run, build, scan, benchmark, load generator or injected pause on the
// machine (host and VM) from before the run until it ends. Just before the run starts, the
// 1-minute load average is at most a quarter of the logical CPUs, on the host and in its VM; this
// is checked before the run only, since the run's own load then raises it. Record the image
// digest, the machine and its load average first, and keep a monitor running outside the
// container for the whole run that logs, every 5 s, the host's load average, its busiest
// processes with their recent CPU use (not a lifetime average, which is what `ps` gives on Linux)
// and each container's CPU use. Each CPU reading records the interval it covers, with the reading
// itself: the change in a cumulative counter between two recorded times; another reading's
// interval is never borrowed. Each reading, start and stop names its workload lifetime, not just
// a pid or a name: a process by its pid namespace, pid and kernel start time, a container by its
// ID and StartedAt, checked at both reads of the counter. The monitor also records when each
// outside workload it sees started and stopped, where that is known, and from what: only a
// process's kernel start time, a time by which it had exited, and docker inspect's StartedAt and
// FinishedAt bound its activity, each only for readings of the same lifetime; its own log, or
// when a poller first or last saw it, never narrows a reading. Every time is written with its
// zone and names the clock it was read on. For each clock the monitor records its offset from
// the test's clock (the container's, so with Docker Desktop or OrbStack the VM's) and the most
// that offset may be wrong by, measured before and after the run from readings each taken to
// the millisecond, and widened by the resolution of each reading and of its times. The
// "capacity: machine" and "capacity: verify" lines add what the test saw: its limits, the load
// average, the verification's start and end ("from", "to", whole milliseconds read down), and
// the diagnostics. A run anywhere else (macOS, Node 26, or `npm test` and the gate's full runs,
// beside other test files) applies the same limits, and its result is kept as evidence: a
// failure there fails that run, but only the normative run decides §9.3. The full runs that set
// TEST_REQUIRE=capacity keep it, and this file stays mandatory in them, until a separately
// reviewed integration makes the normative capacity stage mandatory; nothing is removed from the
// full gates before then.
//
// Every run is kept, failed and invalid ones included: none is discarded, overwritten or replaced
// by a later run. A failed normative run may be rerun only when records made outside the test
// place contention from outside the run within the verification, between "from" and "to". A
// reading places its activity there only when its own interval, moved onto the test's clock by
// its clock's recorded offset and widened on both sides by the most that offset may be wrong by,
// then narrowed to the recorded start and stop of its workload lifetime (only that same
// lifetime's, from the sources above, each moved and widened the same way), lies within "from" to
// "to"; the window starts 1 ms after "from". Records that name more than one lifetime for its pid
// in its pid namespace or for its container ID, or two starts or two stops for its lifetime from
// those sources, are ambiguous and narrow nothing. A sample after "to", the first one included, is
// not such a record on its own, and neither is a reading whose interval reaches before "from" or
// after "to" (all of its activity could fall outside the verification), a reading with no recorded
// interval, a time without a zone, or a time on a clock with no recorded offset. Ambiguous, late or
// missing evidence leaves the failure standing. Contention is another container using a core or
// more; a host process using a core or more, other than the run's own (its container's processes,
// the docker client that started it and, with Docker Desktop or OrbStack, the VM process that
// carries its container); that VM process using a core or more above the run's container, both
// read over the same interval on one clock; or anything the quiet rule above excludes, other than
// the run itself and its monitor, placed within the verification in the same way. The run's own
// load never counts. Nor does the load average during the run: it includes the run's own load (one
// runnable thread lifts the 1-minute figure by about 0.6 in a minute), so a run that started
// within the bar could cross it on its own. That failed run is kept, marked invalid with the
// records, and the rerun follows the same procedure; after two invalid runs, the result goes to
// the maintainer instead of a third rerun. The test's own figures (its CPU and scheduler times and
// the load averages it prints) are never that record, and never turn a failure into a pass.
// Without such a record, the failure is the result.
// docs/engineering-quality.md (Capacity benchmark) gives the same procedure in full.
//
// It runs only with TEST_REQUIRE=capacity (test/setup.mjs), and prints its timings as lines that
// start with "capacity:" for the hand-off, with the machine it ran on.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import { performance } from 'node:perf_hooks';
import { auditOps } from '../../lib/repo/audit.mjs';
import { buildRow } from '../../lib/audit/writer.mjs';
import { GENESIS, rowHash } from '../../lib/audit/chain.mjs';
import { createAudit, parseAuditQuery } from '../../lib/audit/index.mjs';
import { verifyAudit } from '../../lib/audit/verify.mjs';
import { exportAudit } from '../../lib/audit/export.mjs';
import { MAX_ROWS } from '../../lib/audit/actions.mjs';
import { manualClock, migratedControl, openKeyring } from './helpers.mjs';

const required = (process.env.TEST_REQUIRE || '')
  .split(',')
  .map(name => name.trim())
  .includes('capacity');
const DAY = 86400000;
const report = (name, value) => console.log(`capacity: ${name} ${JSON.stringify(value)}`);
const tenths = ms => Math.round(ms * 10) / 10;
const timed = async fn => {
  const start = performance.now();
  const value = await fn();
  return { value, ms: tenths(performance.now() - start) };
};
// The gate (§9.3, §11 item 12), in wall time: no unit and no attempt at a read unit over UNIT_MS,
// and the whole verification under TOTAL_MS.
const UNIT_MS = 250,
  TOTAL_MS = 60000;
const linux = os.platform() === 'linux';
/** CPU time of this thread (user and system), in ms. */
const threadCpuMs = () => {
  const { user, system } = process.threadCpuUsage();
  return (user + system) / 1000;
};
/** CPU time of the whole process, every thread, in ms. */
const processCpuMs = () => {
  const { user, system } = process.cpuUsage();
  return (user + system) / 1000;
};
/**
 * Linux: this thread's wait for a core so far, in ms (the run-queue time of
 * /proc/thread-self/schedstat, "<run ns> <run-queue ns> <slices>", which includes CPU-limit
 * throttling); null elsewhere, or when it cannot be read. A diagnostic only.
 */
const queuedMs = () => {
  if (!linux) return null;
  try {
    return Number(fs.readFileSync('/proc/thread-self/schedstat', 'utf8').split(' ')[1]) / 1e6;
  } catch {
    return null;
  }
};
/** Linux: the limits of this process's cgroup (v2), for the record; null elsewhere. */
const cgroupLimits = () => {
  if (!linux) return null;
  const limit = name => {
    try {
      return fs.readFileSync(`/sys/fs/cgroup/${name}`, 'utf8').trim();
    } catch {
      return null;
    }
  };
  return { cpu: limit('cpu.max'), memory: limit('memory.max'), pids: limit('pids.max') };
};
const loadAverage = () => os.loadavg().map(load => Math.round(load * 100) / 100);
/**
 * A span of this thread's time, from start() to end(started): {wallMs, cpuMs, othersMs,
 * queuedMs}. wallMs (performance.now()) is what the gate judges. The others are diagnostics for a
 * reader, never subtracted from it: this thread's CPU time, the CPU time the process's other
 * threads (the thread pool, the garbage collector's helpers) had meanwhile, and on Linux this
 * thread's wait for a core (null elsewhere). They are read outside the clock readings.
 */
const span = {
  start: () => ({
    queued: queuedMs(),
    all: processCpuMs(),
    cpu: threadCpuMs(),
    at: performance.now(),
  }),
  end(started) {
    const at = performance.now(),
      cpu = threadCpuMs(),
      all = processCpuMs(),
      queued = queuedMs();
    const cpuMs = cpu - started.cpu;
    return {
      wallMs: at - started.at,
      cpuMs,
      othersMs: Math.max(0, all - started.all - cpuMs),
      queuedMs: queued === null || started.queued === null ? null : queued - started.queued,
    };
  },
};
/**
 * `db` for verifyAudit, which only calls read(fn): the span of each attempt at a read unit is
 * pushed to `attempts`. A SQLite read unit runs synchronously inside read() (lib/db/sqlite.mjs:
 * #run calls #unit before its first await), so the span of the call is the whole of its first
 * attempt, however long it holds the event loop. One that meets SQLITE_BUSY is run again later,
 * after read() returned: each later attempt is its own span, {retried: true}, from the start to
 * the end of fn (its BEGIN and COMMIT, which take no lock in a read, are left out). sinceRead()
 * is the span from the start of the latest read() call until now.
 */
const measuredReads = (db, attempts) => {
  let latest = null;
  return {
    read(fn, options) {
      let tries = 0;
      const started = (latest = span.start());
      const done = db.read(tx => {
        tries += 1;
        if (tries === 1) return fn(tx);
        const again = span.start();
        try {
          return fn(tx);
        } finally {
          attempts.push({ ...span.end(again), retried: true });
        }
      }, options);
      attempts.push(span.end(started));
      return done;
    },
    sinceRead: () => span.end(latest),
  };
};
/**
 * A route-style verification of `db` (verifyAudit with onUnit: units of `chunk` rows, the event
 * loop between them), timed for the gate: {verified, units, attempts, whole}. `units` holds
 * verifyAudit's own time for each unit after the first (onUnit's ms), with diagnostics for the
 * same stretch from the read() call; `attempts` the span of each attempt at a read unit
 * (measuredReads); `whole` the verification's span.
 */
async function gatedVerification(db, options) {
  const attempts = [],
    units = [];
  const reads = measuredReads(db, attempts);
  const started = span.start();
  const verified = await verifyAudit(reads, {
    ...options,
    // From just before the unit's read until verifyAudit has its result: the read, and what runs
    // synchronously once it resolves, before the event loop gets a turn.
    onUnit: ms => units.push({ ...reads.sinceRead(), wallMs: ms }),
  });
  const whole = span.end(started);
  return { verified, units, attempts, whole };
}
/** A span's times, in words, for a failure message. */
const described = ({ wallMs, cpuMs, othersMs, queuedMs }) =>
  `${tenths(wallMs)} ms of wall time (diagnostics: ${tenths(cpuMs)} ms CPU, ` +
  `${tenths(othersMs)} ms on Uptime Goblin's other threads` +
  (queuedMs === null ? ')' : `, ${tenths(queuedMs)} ms waiting for a core)`);
/** Whether a unit or an attempt took longer than UNIT_MS; a time that is not a number did. */
const tooLong = ({ wallMs }) => !(wallMs <= UNIT_MS);
/**
 * The gate: why a verification fails it, judged on wall time alone ([] when it passes). `units`:
 * verifyAudit's time for each unit (onUnit); `attempts`: the span of each attempt at a read unit;
 * `whole`: the verification's span, rounded to tenths of a ms before it is compared, as this test
 * has always compared it. A time that is not a number fails.
 */
const overLimits = ({ units = [], attempts = [], whole }) => [
  ...units
    .filter(tooLong)
    .map(unit => `a unit took ${described(unit)}, from its read until verifyAudit had its result`),
  ...attempts
    .filter(tooLong)
    .map(unit => `a${unit.retried ? ' retried' : 'n'} attempt at a unit took ${described(unit)}`),
  ...(tenths(whole.wallMs) < TOTAL_MS ? [] : [`the verification took ${described(whole)}`]),
];
const blocked = () => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 320);

const admin = { type: 'user', id: 'u_admin', name: 'admin', via: 'session', sessionId: 's_abc' };
const anonymous = { type: 'anonymous', id: null, name: null, via: null, sessionId: null };
const firefox = 'Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0';
const facts = n => ({
  actor: admin,
  client: `192.0.2.${n % 250}`,
  userAgent: firefox,
  requestId: `req-${n}`,
});
// A diff whose canonical JSON is close to `bytes` (the writer cuts it at 16 KiB).
const bigDiff = (n, bytes) =>
  Array.from({ length: Math.max(1, Math.floor(bytes / 230)) }, (_, i) => ({
    path: `services.s-${i}.name`,
    from: `${'a'.repeat(90)}${n}`,
    to: `${'b'.repeat(90)}${i}`,
  }));

// The events of the mix, in the order written: each entry gives one or two events (an attempt
// and its result share a `ref`, filled when written).
function* mix(total) {
  let n = 0;
  while (n < total) {
    const k = n % 100;
    if (k < 28)
      yield [
        {
          action: 'session.login',
          outcome: 'ok',
          ...facts(n),
          target: { type: 'session', id: `s_${n}`, name: null },
          detail: { persistent: k % 2 === 0, transport: 'https', ended: 0 },
        },
      ];
    else if (k < 36)
      yield [
        {
          action: 'session.login',
          outcome: 'failed',
          actor: anonymous,
          client: `198.51.100.${n % 200}`,
          userAgent: 'curl/8.5.0',
          target: { type: 'account', id: k % 2 ? 'admin' : null, name: null },
          detail: { code: 'invalid_credentials', login: 'other' },
        },
      ];
    else if (k < 37)
      yield [
        {
          action: 'session.login',
          outcome: 'failed',
          actor: anonymous,
          count: 250,
          target: { type: 'account', id: null, name: null },
          detail: {
            codes: { invalid_credentials: 240, locked: 10 },
            clients: 1000,
            more: true,
            sample: Array.from({ length: 10 }, (_, i) => `198.51.100.${i}`),
            from: 1,
            to: 2,
          },
        },
      ];
    else if (k < 45)
      yield [
        {
          action: 'session.logout',
          outcome: 'ok',
          ...facts(n),
          target: { type: 'session', id: `s_${n}`, name: null },
          detail: { cause: 'signout' },
        },
      ];
    else if (k < 48)
      yield [
        {
          action: 'session.revoked',
          outcome: 'ok',
          ...facts(n),
          target: { type: 'session', id: `s_${n}`, name: null },
          detail: { cause: 'by_user' },
        },
      ];
    else if (k < 58) {
      // 5 % of all rows: a configuration result with a diff of up to 16 KiB.
      const attempt = {
        action: 'settings.update',
        outcome: 'attempt',
        ...facts(n),
        target: { type: 'settings', id: 'workspace', name: null },
        configRevision: n,
        detail: { ifMatch: true },
      };
      const diff =
        k < 53 ? bigDiff(n, 1000 + (n % 16) * 1000) : [{ path: 'title', from: 'a', to: 'b' }];
      yield [
        attempt,
        {
          ...attempt,
          outcome: k === 57 ? 'conflict' : 'ok',
          status: k === 57 ? 409 : 200,
          configRevision: n + 1,
          detail: { ifMatch: true, diff },
        },
      ];
    } else if (k < 64) {
      const attempt = {
        action: 'source.update',
        outcome: 'attempt',
        ...facts(n),
        target: { type: 'source', id: `src-${n % 40}`, name: `Source ${n % 40}` },
        detail: { ifMatch: false },
      };
      yield [attempt, { ...attempt, outcome: 'ok', status: 200, detail: { ifMatch: false } }];
    } else if (k < 66)
      yield [
        {
          action: 'settings.update',
          outcome: 'attempt',
          ...facts(n),
          target: { type: 'settings', id: 'workspace', name: null },
          detail: { ifMatch: true },
        },
      ];
    else if (k < 74)
      yield [
        {
          action: 'source.test',
          outcome: k % 3 ? 'ok' : 'failed',
          status: 200,
          ...facts(n),
          target: { type: 'source', id: `src-${n % 40}`, name: `Source ${n % 40}` },
          detail: { type: 'plex', savedCredentials: true, result: k % 3 ? 'connected' : 'timeout' },
        },
      ];
    else if (k < 78)
      yield [
        {
          action: 'sources.refresh',
          outcome: 'ok',
          status: 202,
          ...facts(n),
          target: { type: 'sources', id: '*', name: null },
        },
      ];
    else if (k < 80)
      yield [
        {
          action: 'email.test',
          outcome: 'ok',
          status: 200,
          ...facts(n),
          target: { type: 'channel', id: 'email', name: null },
          detail: { accepted: true },
        },
      ];
    else if (k < 83) {
      const attempt = {
        action: 'delivery.retry',
        outcome: 'attempt',
        ...facts(n),
        target: { type: 'delivery', id: `d_${n}`, name: null },
      };
      yield [
        attempt,
        {
          ...attempt,
          outcome: k === 82 ? 'denied' : 'ok',
          status: k === 82 ? 409 : 200,
          detail: k === 82 ? { code: 'delivery_not_retryable' } : { retried: 1 },
        },
      ];
    } else if (k < 88)
      yield [
        {
          action: k % 2 ? 'system.stop' : 'channel.working',
          outcome: 'info',
          target: { type: k % 2 ? 'orbit' : 'channel', id: k % 2 ? null : 'email', name: null },
          detail: k % 2 ? { uptimeMs: n } : null,
        },
      ];
    else if (k < 90)
      yield [
        {
          action: 'auth.basic.used',
          outcome: 'ok',
          ...facts(n),
          actor: { ...admin, via: 'basic', sessionId: null },
          target: { type: 'account', id: 'u_admin', name: null },
        },
      ];
    else if (k < 91)
      yield [
        {
          action: 'account.password.changed',
          outcome: 'ok',
          ...facts(n),
          target: { type: 'account', id: 'u_admin', name: null },
          detail: { revokedOtherSessions: 1, newSessionId: `s_${n}` },
        },
      ];
    else if (k < 93)
      yield [
        {
          action: 'config.export',
          outcome: 'ok',
          status: 200,
          ...facts(n),
          target: { type: 'config', id: null, name: null },
          detail: { sources: 12, bytes: 4096 },
        },
      ];
    else if (k < 94)
      yield [
        {
          action: 'data.snapshot',
          outcome: 'info',
          target: { type: 'snapshot', id: `manual-${n}`, name: null },
          detail: { reason: 'manual', createdAt: n },
        },
      ];
    else if (k < 95)
      yield [
        {
          action: 'key.rotate',
          outcome: 'ok',
          actor: {
            type: 'cli',
            id: null,
            name: 'cli:dana (sudo as orbit)',
            via: 'cli',
            sessionId: null,
          },
          target: { type: 'keyring', id: null, name: null },
          detail: { purposes: ['seal'], retired: ['k1'], active: ['k2'] },
        },
      ];
    else if (k < 97)
      yield [
        {
          action: 'channel.paused',
          outcome: 'info',
          target: { type: 'channel', id: 'webhook', name: null },
          detail: { reason: 'the endpoint answered 500', transient: true },
        },
      ];
    else
      yield [
        {
          action: 'system.start',
          outcome: 'info',
          target: { type: 'orbit', id: null, name: null },
          configRevision: n,
          detail: {
            version: '1.5.0-dev.2',
            build: 'b',
            first: false,
            cleanStop: true,
            configRevision: n,
            security: {
              legacyBasic: false,
              insecureHttpSessions: false,
              trustProxy: null,
              allowedHosts: [],
              webhook: true,
              keySource: 'file',
            },
          },
        },
      ];
    n += 1;
  }
}

// Writes `total` rows through the writer's row builder, chained and signed, in units of 5,000,
// their times spread evenly over `days` before `end`.
async function generate(db, keyring, total, { end, days }) {
  const kid = keyring.activeKid('audit');
  const mac = data => keyring.hmac('audit', data, kid).mac;
  const step = Math.floor((days * DAY) / total);
  let seq = 0,
    prev = GENESIS,
    batch = [];
  const flush = async () => {
    const rows = batch;
    batch = [];
    await db.write(tx => {
      for (const row of rows) auditOps.insertRow(tx, row);
      const last = rows.at(-1);
      auditOps.setHead(tx, { seq: last.seq, hash: last.hash, key_id: kid, updated_at: end });
    });
  };
  const time = () => end - days * DAY + seq * step;
  for (const events of mix(total)) {
    let ref = null;
    for (const event of events) {
      if (seq >= total) break;
      seq += 1;
      const row = buildRow(
        { ...event, at: time(), ref: event.outcome === 'attempt' ? null : ref },
        time
      );
      if (event.outcome === 'attempt') ref = seq;
      Object.assign(row, { seq, key_id: kid, prev_hash: prev });
      row.hash = rowHash(mac, prev, row);
      prev = row.hash;
      batch.push(row);
    }
    if (batch.length >= 5000) await flush();
    if (seq >= total) break;
  }
  if (batch.length) await flush();
  return { kid, step };
}

// The query strings the Audit log page can send (§8.2): Period × Kind × Outcome × Who.
function pageQueries(now) {
  const periods = {
    '24h': now - DAY,
    '7d': now - 7 * DAY,
    '30d': now - 30 * DAY,
    '90d': now - 90 * DAY,
    all: null,
  };
  const kinds = {
    all: null,
    sessions: 'session.',
    account: 'account.,identity.',
    scripts: 'auth.basic.',
    settings: 'settings.update',
    sources: 'source.,sources.refresh',
    outside: 'config.changed-outside',
    email: 'email.test',
    notifications: 'delivery.,channel.,notifications.',
    signing: 'signing.',
    exports: 'config.export,audit.export',
    orbit: 'system.,data.',
    cli: 'key.',
    audit: 'audit.',
  };
  const outcomes = [null, 'ok', 'denied', 'failed', 'conflict', 'info', 'unknown'];
  const actors = [null, 'user', 'anonymous', 'system', 'cli'];
  const queries = [];
  for (const [period, from] of Object.entries(periods))
    for (const [kind, action] of Object.entries(kinds))
      for (const outcome of outcomes)
        for (const actor of actors) {
          const params = new URLSearchParams();
          if (from !== null) params.set('from', String(from));
          if (action) params.set('action', action);
          if (outcome) params.set('outcome', outcome);
          if (actor) params.set('actor', actor);
          queries.push({
            label: `${period}/${kind}/${outcome ?? 'any'}/${actor ?? 'anyone'}`,
            params,
          });
        }
  return queries;
}

test(
  'capacity: 250,000 rows verify within 60 s with no unit over 250 ms; pages, unknown, export, count and a 25,000-row prune measured',
  { skip: required ? false : 'needs TEST_REQUIRE=capacity', timeout: 30 * 60 * 1000 },
  async t => {
    report('machine', {
      cpu: os.cpus()[0]?.model,
      cores: os.cpus().length,
      memoryGiB: Math.round(os.totalmem() / 2 ** 30),
      node: process.version,
      platform: `${os.platform()} ${os.release()} ${os.arch()}`,
      limits: cgroupLimits(),
      loadAverage: loadAverage(),
    });
    const end = Date.UTC(2026, 9, 3, 12);
    const clock = manualClock(end);
    const { db, control } = await migratedControl(t, { clock });
    const keyring = await openKeyring(control, { clock });
    const generated = await timed(() => generate(db, keyring, MAX_ROWS, { end, days: 90 }));
    report('generate', { rows: MAX_ROWS, ms: generated.ms });
    const sizes = await db.read(tx => ({ first: auditOps.first(tx), last: auditOps.last(tx) }));
    assert.equal(sizes.last.seq, MAX_ROWS);

    // Gating: a route-style verification (units of 1,000 rows, the event loop between them), in
    // wall time: each unit as verifyAudit times it, and every attempt at a read unit, the first
    // unit (the log's ends, head and checkpoints) included (see the top of this file).
    if (!linux || !process.version.startsWith('v24.'))
      t.diagnostic(
        `capacity: gated on wall time; ${process.version} on ${os.platform()} is not the ` +
          'normative run (Node 24 in the Linux container, alone, on a quiet machine)'
      );
    const loadBefore = loadAverage(),
      startedAt = new Date().toISOString();
    const { verified, units, attempts, whole } = await gatedVerification(db, { keyring, clock });
    const endedAt = new Date().toISOString();
    const retried = attempts.filter(attempt => attempt.retried).length;
    const longest = (spans, key) => spans.reduce((a, b) => (b[key] > a[key] ? b : a));
    const median = (spans, key) =>
      spans.map(one => one[key]).sort((a, b) => a - b)[spans.length >> 1];
    const rounded = times =>
      Object.fromEntries(
        Object.entries(times).map(([k, v]) => [k, typeof v === 'number' ? tenths(v) : v])
      );
    const { wallMs, ...diagnostics } = whole;
    report('verify', {
      ms: tenths(wallMs),
      gatedOn: 'wall time',
      diagnostics: rounded(diagnostics),
      units: units.length,
      longestUnitMs: tenths(longest(units, 'wallMs').wallMs),
      longestUnit: rounded(longest(units, 'wallMs')),
      medianUnitMs: tenths(median(units, 'wallMs')),
      attempts: attempts.length,
      retried,
      longestAttemptMs: tenths(longest(attempts, 'wallMs').wallMs),
      longestAttempt: rounded(longest(attempts, 'wallMs')),
      mostCpuAttempt: rounded(longest(attempts, 'cpuMs')),
      medianAttemptMs: tenths(median(attempts, 'wallMs')),
      medianAttemptCpuMs: tenths(median(attempts, 'cpuMs')),
      from: startedAt,
      to: endedAt,
      loadAverage: { before: loadBefore, after: loadAverage() },
      result: verified.result,
    });
    assert.equal(verified.result, 'intact', JSON.stringify(verified.problem));
    assert.equal(verified.rows.checked, MAX_ROWS);
    // Every unit was timed: by onUnit, one per 1,000 rows (the last finds none); and every
    // attempt, the first read unit's included.
    assert.equal(units.length, MAX_ROWS / 1000 + 1);
    assert.equal(attempts.length - retried, units.length + 1);
    const failures = overLimits({ units, attempts, whole });
    assert.equal(
      failures.length,
      0,
      `${failures.join('; ')}; the median unit took ${tenths(median(units, 'wallMs'))} ms of wall time`
    );

    const audit = createAudit({
      db,
      clock,
      out() {},
      err() {},
      retention: { days: 90, maxRows: MAX_ROWS },
    });
    t.after(() => audit.close());
    await audit.attach({ keyring, instanceId: await control.meta.instanceId() });

    // The first page of every filter alone (the API's), and of every combination the page sends.
    const alone = {
      none: '',
      from: `from=${end - 7 * DAY}`,
      'from-to': `from=${end - 30 * DAY}&to=${end - 29 * DAY}`,
      'actor type': 'actor=user',
      'actor name': 'actor=admin',
      'actor cli name': 'actor=cli:dana (sudo as orbit)',
      action: 'action=session.logout',
      'action prefix': 'action=session.',
      'action list': 'action=source.,sources.refresh,delivery.',
      'target type': 'target=session',
      'target id': 'target=source:src-7',
      'outcome attempt': 'outcome=attempt',
      'outcome unknown': 'outcome=unknown',
      'outcome ok': 'outcome=ok',
      cursor: `cursor=${MAX_ROWS - 100000}`,
      'limit 500': 'limit=500',
    };
    const filters = {};
    for (const [name, text] of Object.entries(alone)) {
      const { ms, value } = await timed(() =>
        audit.list(parseAuditQuery(new URLSearchParams(text), 'list'))
      );
      filters[name] = { ms, entries: value.entries.length };
    }
    report('filters', filters);
    const combos = [];
    for (const { label, params } of pageQueries(end)) {
      const { ms, value } = await timed(() => audit.list(parseAuditQuery(params, 'list')));
      combos.push({ label, ms, entries: value.entries.length });
    }
    combos.sort((a, b) => b.ms - a.ms);
    const slow = combos.filter(combo => combo.ms > 250);
    report('page combinations', {
      count: combos.length,
      slowest: combos.slice(0, 10),
      over250ms: slow.map(combo => combo.label),
      medianMs: combos[Math.floor(combos.length / 2)].ms,
    });

    const unknown = await timed(() =>
      audit.list(parseAuditQuery(new URLSearchParams('outcome=unknown'), 'list'))
    );
    report('outcome=unknown', { ms: unknown.ms, entries: unknown.value.entries.length });
    // An export of 50,000 rows (the 16 MiB cap lifted, since these rows average more than the
    // 335 bytes that 50,000 rows in 16 MiB allow), and an export of everything with the caps.
    const exported = await timed(() =>
      exportAudit(db, { format: 'csv' }, { clock, instance: 'capacity', maxBytes: Infinity })
    );
    report('export of 50,000 rows', {
      ms: exported.ms,
      rows: exported.value.rows,
      more: exported.value.more,
      bytes: exported.value.body.length,
    });
    assert.equal(exported.value.rows, 50000);
    const capped = await timed(() =>
      exportAudit(db, { format: 'ndjson' }, { clock, instance: 'capacity' })
    );
    report('export with the caps', {
      ms: capped.ms,
      rows: capped.value.rows,
      more: capped.value.more,
      bytes: capped.value.body.length,
    });
    assert.ok(capped.value.body.length <= 16 * 1024 * 1024);
    const counted = await timed(() =>
      audit.list(parseAuditQuery(new URLSearchParams('limit=1'), 'list'))
    );
    report('row count', { ms: counted.ms, rows: counted.value.retention.rows });
    assert.equal(counted.value.retention.rows, MAX_ROWS);

    // A prune of at least 25,000 rows in one maintain() run: the rows span 90 days, so with an
    // 80-day window the oldest ninth (10 days, about 27,800 rows) is past it.
    const pruner = createAudit({
      db,
      clock,
      out() {},
      err() {},
      retention: { days: 80, maxRows: MAX_ROWS },
    });
    t.after(() => pruner.close());
    await pruner.attach({ keyring, instanceId: await control.meta.instanceId() });
    clock.set(end);
    const pruned = await timed(() => pruner.maintain({}));
    await pruner.idle();
    const after = await db.read(tx => auditOps.first(tx));
    report('prune', { ms: pruned.ms, deleted: after.seq - 1, firstSeq: after.seq });
    assert.ok(after.seq - 1 >= 25000, `deleted ${after.seq - 1}`);
    const again = await timed(() => verifyAudit(db, { keyring, clock }));
    report('verify after prune', {
      ms: again.ms,
      result: again.value.result,
      problem: again.value.problem?.code ?? null,
      checkpoints: again.value.checkpoints,
    });
    assert.equal(again.value.result, 'intact');
  }
);

// The gate itself, without the 250,000 rows: these three run in every test run. A unit that
// blocks the event loop without using the CPU must fail it as surely as one that computes, in its
// read or once its read has resolved, on its first attempt or a retry, and no diagnostic may make
// up for wall time.
test('capacity gate: wall time decides; CPU and scheduler times never offset it', () => {
  const times = (wallMs, more = {}) => ({ wallMs, cpuMs: 0, othersMs: 0, queuedMs: null, ...more });
  const gate = (attempts, units = [], whole = times(6000)) =>
    overLimits({ units, attempts, whole });
  assert.deepEqual(
    gate([times(30), times(UNIT_MS)], [times(40), times(UNIT_MS)], times(TOTAL_MS - 0.1)),
    []
  );
  // The independent reviewer's probe of the CPU-time proposal: 324.7 ms blocked, counted as 0.196 ms of CPU.
  assert.equal(gate([times(324.7, { cpuMs: 0.196 })]).length, 1);
  assert.equal(gate([times(300.1, { cpuMs: 300.06 })]).length, 1);
  assert.equal(gate([times(UNIT_MS + 0.1, { queuedMs: UNIT_MS, othersMs: 0 })]).length, 1);
  assert.equal(gate([times(260, { cpuMs: 1, retried: true })]).length, 1);
  // A unit whose read was quick but whose result reached verifyAudit 324.7 ms after the read
  // began (the event loop blocked once the read resolved) fails on verifyAudit's own time.
  assert.deepEqual(gate([times(30)], [times(324.7, { cpuMs: 0.196 })]), [
    'a unit took 324.7 ms of wall time (diagnostics: 0.2 ms CPU, 0 ms on ' +
      "Uptime Goblin's other threads), from its read until verifyAudit had its result",
  ]);
  assert.equal(gate([times(30)], [times(UNIT_MS + 0.1, { queuedMs: UNIT_MS })]).length, 1);
  assert.equal(gate([times(30)], [times(Number.NaN)]).length, 1);
  assert.equal(gate([times(30)], [], times(TOTAL_MS, { cpuMs: 8000, queuedMs: 52000 })).length, 1);
  // The whole is rounded to tenths of a ms before it is compared, as this test always did.
  assert.equal(gate([times(30)], [], times(TOTAL_MS - 0.04)).length, 1);
  assert.equal(gate([times(Number.NaN)]).length, 1);
  assert.equal(gate([times(30)], [], times(undefined)).length, 1);
  assert.match(
    gate([times(324.7, { cpuMs: 0.196, retried: true })])[0],
    /^a retried attempt at a unit took 324\.7 ms of wall time \(diagnostics: 0\.2 ms CPU/
  );
});

test('capacity gate: a read unit that blocks 320 ms or computes for 300 ms fails, first attempt or retry', async t => {
  const { db } = await migratedControl(t);
  const attempts = [];
  const reads = measuredReads(db, attempts);
  const computing = () => {
    for (const until = threadCpuMs() + 300; threadCpuMs() < until; );
  };
  let tries = 0;
  await reads.read(() => blocked());
  await reads.read(() => computing());
  await reads.read(() => {
    tries += 1;
    // A stand-in for SQLITE_BUSY: a unit that throws class `retry` is rolled back and run again.
    if (tries === 1) throw Object.assign(new Error('busy (a stand-in)'), { class: 'retry' });
    blocked();
  });
  assert.equal(tries, 2);
  // In order: the blocked unit, the computing unit, the first attempt at the retried unit (which
  // only threw), and its second attempt.
  assert.deepEqual(
    attempts.map(attempt => attempt.retried ?? false),
    [false, false, false, true]
  );
  for (const [i, attempt] of Object.entries(attempts))
    t.diagnostic(`attempt ${i}: ${described(attempt)}${attempt.retried ? ', retried' : ''}`);
  // Each fails on its own span, beside a whole verification that passes.
  const whole = { wallMs: 0, cpuMs: 0, othersMs: 0, queuedMs: null };
  assert.deepEqual(overLimits({ whole }), []);
  for (const i of [0, 1, 3]) {
    const reasons = overLimits({ attempts: [attempts[i]], whole });
    assert.equal(reasons.length, 1, `attempt ${i}: ${described(attempts[i])}`);
    assert.match(reasons[0], i === 3 ? /^a retried attempt at a unit took / : /^an attempt at /);
  }
});

test('capacity gate: a unit that blocks 320 ms once its read has resolved fails, though its read was quick', async t => {
  const end = Date.UTC(2026, 9, 3, 12);
  const clock = manualClock(end);
  const { db, control } = await migratedControl(t, { clock });
  const keyring = await openKeyring(control, { clock });
  await generate(db, keyring, 25, { end, days: 1 });
  // The third read (the second unit of 10 rows) resolves, then the main thread blocks 320 ms
  // before verifyAudit has its result, with no event-loop turn between: outside every attempt at
  // the read unit, as a block in verifyAudit after its read would be.
  let reads = 0;
  const slow = {
    read(fn, options) {
      const done = db.read(fn, options);
      reads += 1;
      return reads === 3 ? done.then(value => (blocked(), value)) : done;
    },
  };
  const { verified, units, attempts, whole } = await gatedVerification(slow, {
    keyring,
    clock,
    chunk: 10,
  });
  assert.equal(verified.result, 'intact', JSON.stringify(verified.problem));
  assert.equal(verified.rows.checked, 25);
  // Units of rows 1-10, 11-20 and 21-25; their reads follow the first read unit's.
  assert.equal(units.length, 3);
  assert.equal(attempts.length, 4);
  for (const [i, unit] of Object.entries(units)) t.diagnostic(`unit ${i}: ${described(unit)}`);
  // The blocked unit fails on its own, beside a whole verification that passes, and so does the
  // verification.
  const passing = { wallMs: 0, cpuMs: 0, othersMs: 0, queuedMs: null };
  const reasons = overLimits({ units: [units[1]], whole: passing });
  assert.equal(reasons.length, 1, `unit 1: ${described(units[1])}`);
  assert.match(reasons[0], /^a unit took .*, from its read until verifyAudit had its result$/);
  assert.ok(
    overLimits({ units, attempts, whole }).some(reason => reason.startsWith('a unit took ')),
    'the verification passed the gate'
  );
});
