import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  MemoryBudget,
  BudgetConfigError,
  BudgetTimeoutError,
  cgroupMemoryLimit,
  defaultBudgetBytes,
} from '../../lib/budget.mjs';
import { fakeClock, settle } from './fake-clock.mjs';

const MiB = 1024 * 1024;
const GiB = 1024 * MiB;

// Every call here names the cgroup limit and total memory itself. Passing `undefined` (or
// leaving either out) makes the default parameter read the machine running the test, so a
// memory-limited container (the Node 24 gate runs under --memory=4g) would change the answer.
// The defaults themselves are covered by the tests after it.
test('the default budget is 25 % of the cgroup limit or of total memory', () => {
  // The reference host: a 1 GiB LXC whose cgroup limit is below the machine's memory.
  assert.deepEqual(defaultBudgetBytes({ env: {}, constrained: GiB, total: 16 * GiB }), {
    bytes: 256 * MiB,
    source: 'cgroup',
  });
  // No cgroup limit: Node reports 0, or a value at or above total memory (libuv turns cgroup
  // v2's "max" into 2^64 - 1, which Node returns as 2^64).
  for (const constrained of [0, 2 ** 62, 2 ** 64, 8 * GiB])
    assert.deepEqual(defaultBudgetBytes({ env: {}, constrained, total: 8 * GiB }), {
      bytes: 2 * GiB,
      source: 'total',
    });
  assert.equal(
    defaultBudgetBytes({ env: {}, constrained: 0, total: 32 * MiB }).bytes,
    16 * MiB,
    'never below 16 MiB'
  );
  assert.deepEqual(
    defaultBudgetBytes({
      env: { GOBLIN_COLLECTION_MEMORY_MB: '384' },
      constrained: GiB,
      total: 16 * GiB,
    }),
    { bytes: 384 * MiB, source: 'GOBLIN_COLLECTION_MEMORY_MB' }
  );
  // Set but empty counts as not set.
  assert.deepEqual(
    defaultBudgetBytes({
      env: { GOBLIN_COLLECTION_MEMORY_MB: '' },
      constrained: GiB,
      total: 16 * GiB,
    }),
    { bytes: 256 * MiB, source: 'cgroup' }
  );
  for (const bad of ['15', '1048577', '1.5', '-1', 'lots', '0x40', ' '])
    assert.throws(
      () =>
        defaultBudgetBytes({
          env: { GOBLIN_COLLECTION_MEMORY_MB: bad },
          constrained: GiB,
          total: 16 * GiB,
        }),
      error => error instanceof BudgetConfigError && error.refusal === true,
      bad
    );
});

// A cgroup tree of files, as the kernel shows one, under a new directory: {proc, mount} for
// cgroupMemoryLimit() and defaultBudgetBytes({cgroupFiles}). `own` is /proc/self/cgroup's
// content; `files` maps a path below the mount to its content.
function cgroupTree(t, own, files = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'orbit-cgroup-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const proc = path.join(directory, 'proc-self-cgroup'),
    mount = path.join(directory, 'sys-fs-cgroup');
  if (own !== null) fs.writeFileSync(proc, own);
  fs.mkdirSync(mount);
  for (const [file, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(mount, file)), { recursive: true });
    fs.writeFileSync(path.join(mount, file), content);
  }
  return { proc, mount };
}

test('the cgroup limit is the lowest of the own cgroup and every parent', t => {
  const v1Unlimited = '9223372036854771712\n';
  // Uptime Goblin's systemd unit in a 1 GiB LXC or container (cgroup v2, its own namespace): the unit's
  // cgroup and its slice say "max"; the limit is on the namespace root. libuv, which reads only
  // the unit's own cgroup, sees no limit here.
  const unit = {
    'memory.max': `${GiB}\n`,
    'memory.high': 'max\n',
    'system.slice/memory.max': 'max\n',
    'system.slice/memory.high': 'max\n',
    'system.slice/uptime-goblin.service/memory.max': 'max\n',
    'system.slice/uptime-goblin.service/memory.high': 'max\n',
  };
  const nested = cgroupTree(t, '0::/system.slice/uptime-goblin.service\n', unit);
  assert.equal(cgroupMemoryLimit(nested), GiB);
  // A lower memory.high on the way up wins, and so does the own cgroup's limit.
  assert.equal(
    cgroupMemoryLimit(
      cgroupTree(t, '0::/system.slice/uptime-goblin.service\n', {
        ...unit,
        'system.slice/memory.high': `${512 * MiB}\n`,
      })
    ),
    512 * MiB
  );
  assert.equal(
    cgroupMemoryLimit(cgroupTree(t, '0::/\n', { 'memory.max': `${4 * GiB}\n` })),
    4 * GiB,
    'docker run --memory=4g: the container is the root of its namespace'
  );
  // No limit anywhere: "max" everywhere, and a host's real root has no limit files at all.
  assert.equal(
    cgroupMemoryLimit(
      cgroupTree(t, '0::/user.slice/session.scope\n', {
        'user.slice/memory.max': 'max\n',
        'user.slice/session.scope/memory.max': 'max\n',
      })
    ),
    0
  );
  // cgroup v1 (also hybrid, where memory stays on v1): Docker shows the container's own cgroup
  // at the mount's root, not under the path /proc/self/cgroup names.
  const v1 = cgroupTree(t, '12:memory:/docker/0123abcd\n4:cpu,cpuacct:/docker/0123abcd\n0::/\n', {
    'memory/memory.limit_in_bytes': `${GiB}\n`,
    'memory/memory.soft_limit_in_bytes': v1Unlimited,
    'memory.max': `${64 * GiB}\n`,
  });
  assert.equal(cgroupMemoryLimit(v1), GiB);
  assert.equal(
    cgroupMemoryLimit(
      cgroupTree(t, '5:memory:/\n', {
        'memory/memory.limit_in_bytes': v1Unlimited,
        'memory/memory.soft_limit_in_bytes': v1Unlimited,
      })
    ),
    0
  );
  // Nothing to read, or nothing that names a visible cgroup: no limit from here.
  assert.equal(cgroupMemoryLimit(cgroupTree(t, null, { 'memory.max': `${GiB}\n` })), 0);
  assert.equal(
    cgroupMemoryLimit(cgroupTree(t, '0::/../../other\n', { 'memory.max': `${GiB}\n` })),
    0
  );
  assert.equal(cgroupMemoryLimit(cgroupTree(t, '3:cpu:/x\n', { 'memory.max': `${GiB}\n` })), 0);
  assert.equal(cgroupMemoryLimit(cgroupTree(t, '0::/\n', { 'memory.max': '1g\n' })), 0);
});

// The default parameters, deterministically. Both sources of the limit are replaced: Node's
// process.constrainedMemory() (libuv reads memory.max and memory.high of the process's own
// cgroup, or cgroup v1's limits) by a stub, and the cgroup files by a tree of the test's own;
// so is os.totalmem(). The cases a real machine shows (a 4 GiB or 1 GiB limit, no limit, no
// cgroup at all, a limit only on a parent) are all checked wherever the suite runs, whatever
// limit that machine has.
test('the default takes the lowest of process.constrainedMemory() and the cgroup files', t => {
  const total = t.mock.method(os, 'totalmem', () => 16 * GiB);
  const constrained = t.mock.method(process, 'constrainedMemory', () => 0);
  const none = cgroupTree(t, null);
  const cases = [
    // [what process.constrainedMemory() returns, the budget]
    [4 * GiB, { bytes: GiB, source: 'cgroup' }], // docker run --memory=4g
    [GiB, { bytes: 256 * MiB, source: 'cgroup' }], // a 1 GiB LXC or --memory=1g
    [2 ** 64, { bytes: 4 * GiB, source: 'total' }], // cgroup v2 memory.max "max"
    [64 * GiB, { bytes: 4 * GiB, source: 'total' }], // a limit above the machine's memory
    [0, { bytes: 4 * GiB, source: 'total' }], // no cgroup (macOS), or none known
    [undefined, { bytes: 4 * GiB, source: 'total' }],
  ];
  for (const [limit, expected] of cases) {
    constrained.mock.mockImplementation(() => limit);
    assert.deepEqual(defaultBudgetBytes({ env: {}, cgroupFiles: none }), expected, String(limit));
  }
  assert.equal(constrained.mock.callCount(), cases.length);
  assert.equal(total.mock.callCount(), cases.length);
  // The unit of a 1 GiB LXC: libuv sees "max" (2^64) in its own cgroup, the files show the
  // limit on the namespace root. Before 1.5's fix this was 25 % of the machine's memory.
  constrained.mock.mockImplementation(() => 2 ** 64);
  const unit = cgroupTree(t, '0::/system.slice/uptime-goblin.service\n', {
    'memory.max': `${GiB}\n`,
    'system.slice/uptime-goblin.service/memory.max': 'max\n',
  });
  assert.deepEqual(defaultBudgetBytes({ env: {}, cgroupFiles: unit }), {
    bytes: 256 * MiB,
    source: 'cgroup',
  });
  // Whichever is lower wins: Node's figure (it also counts RLIMIT_AS) or the files'.
  constrained.mock.mockImplementation(() => 512 * MiB);
  assert.deepEqual(defaultBudgetBytes({ env: {}, cgroupFiles: unit }), {
    bytes: 128 * MiB,
    source: 'cgroup',
  });
  // A Node without process.constrainedMemory: the files and total memory decide.
  const saved = process.constrainedMemory;
  process.constrainedMemory = undefined;
  try {
    assert.deepEqual(defaultBudgetBytes({ env: {}, cgroupFiles: none }), {
      bytes: 4 * GiB,
      source: 'total',
    });
    assert.deepEqual(defaultBudgetBytes({ env: {}, cgroupFiles: unit }), {
      bytes: 256 * MiB,
      source: 'cgroup',
    });
  } finally {
    process.constrainedMemory = saved;
  }
  // With no argument at all (process.env, which test/setup.mjs clears of GOBLIN_ variables, and
  // this machine's own cgroup files), MemoryBudget takes the same default.
  t.mock.restoreAll();
  const machine = defaultBudgetBytes();
  assert.ok(['cgroup', 'total'].includes(machine.source));
  assert.equal(new MemoryBudget().totalBytes, machine.bytes);
});

test('reservations wait while the budget is spent and are admitted in arrival order', async () => {
  const budget = new MemoryBudget({ totalBytes: 256 * MiB });
  const collection = await budget.reserve(64 * MiB, { label: 'collection' });
  const scrypt = await budget.reserve(128 * MiB, { label: 'backup' });
  const tiny = await budget.reserve(8 * MiB, { label: 'collection' });
  assert.equal(budget.availableBytes, 56 * MiB);
  const order = [];
  const big = budget.reserve(128 * MiB, { label: 'export' }).then(lease => {
    order.push('export');
    return lease;
  });
  // Fits in what is left, but must not overtake the larger reservation that came first.
  const small = budget.reserve(32 * MiB, { label: 'collection' }).then(lease => {
    order.push('small');
    return lease;
  });
  assert.equal(budget.tryReserve(1 * MiB), null, 'tryReserve never jumps the queue');
  await settle();
  assert.deepEqual(order, []);
  assert.equal(budget.status().waiting, 2);
  // 64 MiB free now: enough for the small one, but the export came first and does not fit.
  tiny.release();
  await settle();
  assert.deepEqual(order, []);
  collection.release();
  const exported = await big;
  await settle();
  // 128 MiB free was enough for the export; the small one now waits for its turn's memory.
  assert.deepEqual(order, ['export']);
  scrypt.release();
  const smallLease = await small;
  assert.deepEqual(order, ['export', 'small']);
  assert.deepEqual(budget.status().byLabel, { export: 128 * MiB, collection: 32 * MiB });
  exported.release();
  exported.release(); // releasing twice is harmless
  smallLease[Symbol.dispose]();
  assert.equal(budget.usedBytes, 0);
  const status = budget.status();
  assert.equal(status.admitted, 5);
  assert.equal(status.waited, 2);
  assert.equal(status.peakBytes, 256 * MiB);
});

test('a reservation larger than the budget is clamped and runs alone', async () => {
  const budget = new MemoryBudget({ totalBytes: 100 });
  const huge = await budget.reserve(1000, { label: 'restore' });
  assert.equal(huge.bytes, 100);
  assert.equal(budget.tryReserve(1), null);
  huge.release();
  assert.ok(budget.tryReserve(1));
  assert.equal(budget.status().clamped, 1);
  const nothing = await budget.reserve(0);
  assert.equal(nothing.bytes, 0);
  assert.throws(() => budget.tryReserve(-1), /0 or more bytes/);
  assert.throws(() => budget.tryReserve(NaN), /0 or more bytes/);
  assert.throws(() => new MemoryBudget({ totalBytes: 0 }), /positive/);
});

test('reservations sharing a serial key run one at a time without blocking others', async () => {
  const budget = new MemoryBudget({ totalBytes: 512 * MiB });
  const first = await budget.reserve(128 * MiB, { label: 'backup', serial: 'scrypt' });
  let second = null;
  const pending = budget
    .reserve(128 * MiB, { label: 'backup', serial: 'scrypt' })
    .then(lease => (second = lease));
  // A collection behind the waiting scrypt is not held up by it: memory is free.
  const collection = await budget.reserve(64 * MiB, { label: 'collection' });
  assert.ok(collection);
  assert.ok(budget.tryReserve(8 * MiB));
  await settle();
  assert.equal(second, null);
  first.release();
  await pending;
  assert.equal(second.serial, 'scrypt');
});

test('a wait can time out or be cancelled, and the queue moves on', async () => {
  const clock = fakeClock();
  const budget = new MemoryBudget({ totalBytes: 100, clock });
  const held = budget.tryReserve(90);
  const timed = budget.reserve(50, { label: 'export', timeoutMs: 30000 });
  const controller = new AbortController();
  const cancelled = budget.reserve(60, { signal: controller.signal });
  const behind = budget.reserve(5);
  let admitted = false;
  void behind.then(() => (admitted = true));
  const timedOut = assert.rejects(timed, error => {
    assert.ok(error instanceof BudgetTimeoutError);
    assert.match(error.message, /Waited 30 s for 1 MiB of working memory \(export\)/);
    return true;
  });
  controller.abort();
  await assert.rejects(cancelled, { name: 'AbortError' });
  await clock.advance(30000);
  await timedOut;
  // With both departed, the small request behind them fits in what is free.
  await settle();
  assert.equal(admitted, true);
  const status = budget.status();
  assert.equal(status.timedOut, 1);
  assert.equal(status.cancelled, 1);
  assert.equal(status.waiting, 0);
  held.release();
  const aborted = new AbortController();
  aborted.abort();
  await assert.rejects(budget.reserve(1, { signal: aborted.signal }), { name: 'AbortError' });
  assert.equal(clock.pending, 0, 'no timer is left behind');
});

test('resize() changes the budget and admits waiters that now fit', async () => {
  const budget = new MemoryBudget({ totalBytes: 100 });
  const held = budget.tryReserve(80);
  let lease = null;
  const waiting = budget.reserve(50).then(value => (lease = value));
  await settle();
  assert.equal(lease, null);
  budget.resize(200);
  await waiting;
  assert.equal(lease.bytes, 50);
  assert.equal(budget.usedBytes, 130);
  // Shrinking below what is in use only makes newcomers wait.
  budget.resize(60);
  assert.equal(budget.tryReserve(1), null);
  held.release();
  lease.release();
  assert.ok(budget.tryReserve(60));
});
